//! Ethereum JSON-RPC as the operator commands use it. The RPC URL often carries an API key, so no message here
//! repeats it: a provider's error text is redacted, a body that is not JSON-RPC is never echoed, and a request that
//! gets no answer says only that.
//!
//! Metered RPCs, such as Alchemy's compute units per second, are read through `Paced`, which spaces requests and
//! retries rate-limited ones.
use std::fmt;
use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde_json::{json, Value};

use crate::esplora::TIMEOUT_SECS;

/// Why a request failed, as far as retrying is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Retrying the request as it was would not help.
    Failed,
    /// The provider limits the request rate; it may have said after how many milliseconds to retry.
    RateLimited { retry_after_ms: Option<u64> },
    /// Still rate-limited after every retry `Paced` allows.
    Exhausted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcError {
    /// Safe to print: never the URL or a credential in it.
    pub message: String,
    /// The JSON-RPC error code, if the reply had one.
    pub code: Option<i64>,
    pub kind: Kind,
}

impl RpcError {
    pub fn failed(message: impl Into<String>) -> RpcError {
        RpcError {
            message: message.into(),
            code: None,
            kind: Kind::Failed,
        }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// The execution RPC URL: `--rpc` if given, else SEPOLIA_EXECUTION_RPC, which keeps a URL carrying an API key out
/// of the process list. Never echoed.
pub fn rpc_url(flag: Option<&str>, env: Option<String>) -> Result<String, String> {
    match flag.map(str::to_owned).or(env) {
        Some(url) if !url.is_empty() => Ok(url),
        _ => Err("set SEPOLIA_EXECUTION_RPC or pass --rpc".into()),
    }
}

// Alchemy: HTTP 429, error code 429, "Your app has exceeded its compute units per second capacity". Other
// providers say "rate limit", "request rate" or "too many requests". A block-range limit is none of these.
static RATE_LIMITED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)compute units|rate.?limit|request rate|too many requests|throughput|capacity")
        .expect("a valid pattern")
});

/// Whether an error message says the provider limits the request rate.
pub fn says_rate_limited(message: &str) -> bool {
    RATE_LIMITED.is_match(message)
}

/// The parts of a URL that may carry a credential: its user info, its path and its query.
struct Endpoint<'a> {
    username: &'a str,
    password: &'a str,
    path: &'a str,
    query: &'a str,
}

fn endpoint(url: &str) -> Option<Endpoint<'_>> {
    let (_, rest) = url.split_once("://")?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let end = rest
        .find(|c: char| c == '/' || c == '?')
        .unwrap_or(rest.len());
    let (authority, rest) = rest.split_at(end);
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let userinfo = authority
        .rsplit_once('@')
        .map_or("", |(userinfo, _)| userinfo);
    let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    Some(Endpoint {
        username,
        password,
        path,
        query,
    })
}

/// A query value as form decoding reads it: `+` is a space and `%XX` a byte.
fn form_decoded(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = bytes
            .get(i + 1..i + 3)
            .filter(|_| bytes[i] == b'%')
            .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok());
        match (bytes[i], escaped) {
            (_, Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b'+', None) => {
                out.push(b' ');
                i += 1;
            }
            (b, None) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `message` with the RPC URL and the credentials in it masked: the URL itself, API key path segments (any of at
/// least 12 characters, wherever the provider puts its key, as in `/v2/<key>` or `/<token>/`), query values and user
/// info (each if at least 8).
pub fn redact(message: &str, url: &str) -> String {
    // Some providers put the credential-bearing endpoint in their error message.
    let mut message = if url.is_empty() {
        message.to_owned()
    } else {
        message.replace(url, "[RPC URL]")
    };
    let Some(endpoint) = endpoint(url) else {
        return message;
    };
    let mut credentials: Vec<String> = endpoint
        .path
        .split('/')
        .filter(|segment| segment.len() >= 12)
        .map(str::to_owned)
        .collect();
    for pair in endpoint.query.split('&') {
        let value = pair.split_once('=').map_or("", |(_, v)| v);
        credentials.extend(
            [value.to_owned(), form_decoded(value)]
                .into_iter()
                .filter(|v| v.len() >= 8),
        );
    }
    for value in [endpoint.username, endpoint.password] {
        if value.len() >= 8 {
            credentials.push(value.to_owned());
        }
    }
    for credential in credentials {
        message = message.replace(&credential, "[RPC credential]");
    }
    message
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Seconds since the Unix epoch of an HTTP date in its preferred form, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
fn http_date(text: &str) -> Option<u64> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [_, day, month, year, time, "GMT"] = parts.as_slice() else {
        return None;
    };
    let day: u64 = day.parse().ok()?;
    let month = MONTHS.iter().position(|m| m == month)? as u64 + 1;
    let year: u64 = year.parse().ok()?;
    let hms: Vec<u64> = time
        .split(':')
        .map(|x| x.parse().ok())
        .collect::<Option<_>>()?;
    let [hour, minute, second] = hms.as_slice() else {
        return None;
    };
    if !(1..=31).contains(&day) || year < 1970 || *hour > 23 || *minute > 59 || *second > 60 {
        return None;
    }
    // Days from 1970-01-01 to the date, by Howard Hinnant's days_from_civil, with March as the year's first month.
    let y = if month <= 2 { year - 1 } else { year };
    let (era, year_of_era) = (y / 400, y % 400);
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = (era * 146_097 + day_of_era).checked_sub(719_468)?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// A Retry-After header in ms, as delta-seconds or an HTTP date relative to `now`; `None` if unreadable.
pub fn retry_after_ms(header: &str, now: SystemTime) -> Option<u64> {
    let header = header.trim();
    if !header.is_empty() && header.bytes().all(|c| c.is_ascii_digit()) {
        return Some(
            header
                .parse::<u64>()
                .map_or(u64::MAX, |s| s.saturating_mul(1000)),
        );
    }
    let at = Duration::from_secs(http_date(header)?);
    let now = now.duration_since(UNIX_EPOCH).ok()?;
    Some(u64::try_from(at.saturating_sub(now).as_millis()).unwrap_or(u64::MAX))
}

/// One JSON-RPC request. A reply without a JSON body, with an error or with an HTTP status other than 2xx fails;
/// HTTP 429, error code 429 and a rate limit in the error's words fail as `Kind::RateLimited`.
pub fn call(url: &str, method: &str, params: &Value) -> Result<Value, RpcError> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let response = minreq::post(url)
        .with_header("content-type", "application/json")
        .with_body(body)
        .with_timeout(TIMEOUT_SECS)
        .send()
        .map_err(|_| RpcError::failed("the Ethereum RPC is unreachable (URL not shown)"))?;
    let status = response.status_code;
    // A gateway's HTML or text page is not parsed, and its body is never echoed.
    let reply: Option<Value> = serde_json::from_slice(response.as_bytes()).ok();
    let has_body = reply.is_some();
    let error = reply
        .as_ref()
        .and_then(|r| r.get("error"))
        .filter(|e| !e.is_null())
        .cloned();
    if let (Some(mut reply), None) = (reply, &error) {
        if (200..300).contains(&status) {
            return Ok(reply
                .get_mut("result")
                .map(Value::take)
                .unwrap_or(Value::Null));
        }
    }

    let message = match &error {
        Some(e) => redact(
            &match e.get("message") {
                Some(Value::String(s)) => s.clone(),
                None | Some(Value::Null) => "RPC error".to_owned(),
                Some(other) => other.to_string(),
            },
            url,
        ),
        None if !has_body => format!("HTTP {status} without a JSON-RPC body"),
        None => format!("HTTP {status}"),
    };
    let code = error
        .as_ref()
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64);
    let kind = if status == 429 || code == Some(429) || says_rate_limited(&message) {
        let retry_after_ms = response
            .headers
            .get("retry-after")
            .and_then(|h| retry_after_ms(h, SystemTime::now()));
        Kind::RateLimited { retry_after_ms }
    } else {
        Kind::Failed
    };
    Err(RpcError {
        message: format!("{method} failed: {message}"),
        code,
        kind,
    })
}

/// The time `Paced` waits on: the system's, or a test's.
pub trait Clock {
    /// Milliseconds since some fixed start.
    fn now_ms(&self) -> u64;
    fn sleep_ms(&self, ms: u64);
}

pub struct SystemClock(Instant);

impl SystemClock {
    pub fn new() -> SystemClock {
        SystemClock(Instant::now())
    }
}

impl Default for SystemClock {
    fn default() -> SystemClock {
        SystemClock::new()
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sleep_ms(&self, ms: u64) {
        thread::sleep(Duration::from_millis(ms));
    }
}

/// The longest wait before a retry, and the longest pace a rate limit can set.
const WAIT_MAX_MS: u64 = 30_000;
const PACE_MAX_MS: u64 = 5_000;

/// Requests paced for a long run against a metered RPC: they start at least `pace` ms apart, and a rate-limited
/// request is retried up to `retries` times, first after `backoff` ms and then after twice the previous wait (or the
/// RPC's Retry-After if longer), at most 30 s. Each rate limit also doubles the pace, up to 5 s, so the rest of the
/// run stays under the limit it found. A request still rate-limited after its retries fails as `Kind::Exhausted`;
/// any other failure passes through at once.
///
/// `call` makes one request: method and params.
pub struct Paced<'a, F> {
    call: F,
    clock: &'a dyn Clock,
    log: &'a dyn Fn(&str),
    pace: u64,
    retries: u32,
    backoff: u64,
    last: Option<u64>,
}

impl<'a, F> Paced<'a, F>
where
    F: FnMut(&str, &Value) -> Result<Value, RpcError>,
{
    pub fn new(
        call: F,
        clock: &'a dyn Clock,
        log: &'a dyn Fn(&str),
        pace: u64,
        retries: u32,
        backoff: u64,
    ) -> Paced<'a, F> {
        Paced {
            call,
            clock,
            log,
            pace,
            retries,
            backoff,
            last: None,
        }
    }

    /// `method` with `params`, named `what` in messages.
    pub fn call(&mut self, method: &str, params: &Value, what: &str) -> Result<Value, RpcError> {
        let mut waited = 0u64;
        for attempt in 0..=self.retries {
            if let Some(next) = self.last.map(|last| last.saturating_add(self.pace)) {
                let now = self.clock.now_ms();
                if next > now {
                    self.clock.sleep_ms(next - now);
                }
            }
            self.last = Some(self.clock.now_ms());
            let error = match (self.call)(method, params) {
                Ok(result) => return Ok(result),
                Err(e) => e,
            };
            let Kind::RateLimited { retry_after_ms } = error.kind else {
                return Err(error);
            };
            if attempt == self.retries {
                return Err(RpcError {
                    message: format!(
                        "{what} was still rate-limited after {} attempts and {} s of backoff ({})",
                        attempt + 1,
                        (waited + 500) / 1000,
                        error.message
                    ),
                    code: error.code,
                    kind: Kind::Exhausted,
                });
            }
            let doubled = self.backoff.saturating_mul(1u64 << attempt.min(63));
            let ms = WAIT_MAX_MS.min(doubled.max(retry_after_ms.unwrap_or(0)));
            self.pace = self
                .pace
                .max(PACE_MAX_MS.min(self.pace.saturating_mul(2).max(100)));
            (self.log)(&format!(
                "{what} was rate-limited; retry {} of {} in {ms} ms, then at most one request per {} ms",
                attempt + 1,
                self.retries,
                self.pace
            ));
            waited = waited.saturating_add(ms);
            self.clock.sleep_ms(ms);
        }
        unreachable!("the last attempt returns")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates() {
        assert_eq!(
            http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(http_date("Sun, 06 Nov 1994 08:49:37 UTC"), None);
        assert_eq!(http_date("06 Nov 1994"), None);
    }

    #[test]
    fn endpoints() {
        let e = endpoint("https://u:p@host:8545/v2/key?a=1&b=2#f").unwrap();
        assert_eq!(
            (e.username, e.password, e.path, e.query),
            ("u", "p", "/v2/key", "a=1&b=2")
        );
        let e = endpoint("http://host?k=v").unwrap();
        assert_eq!((e.username, e.path, e.query), ("", "", "k=v"));
        assert!(endpoint("not a url").is_none());
        assert_eq!(form_decoded("a%2Bb+c%zz"), "a+b c%zz");
    }
}
