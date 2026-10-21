//! The escrow's Deposit events, as `assemble.py claim --deposits` takes them, read over eth_getLogs from RPCs that
//! limit both the block range of a request and the request rate.
use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::abi::word;
use crate::bridge::{deposit_topic, Address, Deposit};
use crate::hex;
use crate::rpc::{Kind, RpcError};

// eth_getLogs refusals that a smaller block range answers. Alchemy's free tier: "Under the Free tier plan, you can
// make eth_getLogs requests with up to a 10 block range. Based on your parameters, this block range should work:
// [0x..., 0x...]"; its paid tiers: "Log response size exceeded. ... up to a 2K block range ..."; Infura: "query
// returned more than 10000 results. Try with this block range [0x..., 0x...]"; others: "block range too large",
// "exceed maximum block range", "too many blocks".
static RANGE_LIMITED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)block range|range.*(large|wide|limit)|too many blocks|exceed.*blocks|response size|more than [0-9]+ results",
    )
    .expect("a valid pattern")
});
static SUGGESTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\[\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*\]").expect("a valid pattern")
});
static STATED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)up to (?:a )?([0-9]+)(k?) block range").expect("a valid pattern")
});

/// EIP-1474's "Limit exceeded". Providers send it for range limits and rate limits alike, so a rate limit is told
/// apart by its words first (`rpc::call`), and only then is the code read as a range limit.
const LIMIT_EXCEEDED: i64 = -32005;

/// Whether a failed eth_getLogs asks for fewer blocks. A rate limit never does: `Paced` retries it as it was.
pub fn range_limited(error: &RpcError) -> bool {
    error.kind == Kind::Failed
        && (error.code == Some(LIMIT_EXCEEDED) || RANGE_LIMITED.is_match(&error.message))
}

/// How many blocks to ask for after an eth_getLogs of `width` blocks was refused with `message`: the size of the
/// range the RPC suggests, else its "up to N block range", else half of `width`. Always at least 1 and less than
/// `width`, which must be at least 2, so every refusal shrinks the scan's ranges and the refusals end.
pub fn narrowed_width(message: &str, width: u64) -> u64 {
    let suggested = SUGGESTED.captures(message).and_then(|c| {
        let a = u128::from_str_radix(&c[1][2..], 16).ok()?;
        let b = u128::from_str_radix(&c[2][2..], 16).ok()?;
        b.checked_sub(a)?.checked_add(1)
    });
    let stated = STATED.captures(message).and_then(|c| {
        let n: u128 = c[1].parse().ok()?;
        n.checked_mul(if c[2].is_empty() { 1 } else { 1000 })
    });
    [suggested, stated]
        .into_iter()
        .flatten()
        .find(|&allowed| allowed >= 1 && allowed < u128::from(width))
        // In range: below `width`.
        .map_or(width.div_ceil(2), |allowed| {
            u64::try_from(allowed).expect("below a u64")
        })
}

/// Whether a reorg removed the log: its `removed` is the boolean true, and nothing else counts.
fn removed(log: &Value) -> bool {
    log.get("removed") == Some(&Value::Bool(true))
}

/// A log's identity: its block hash, its index in that block and whether it was removed, else all of it.
fn log_key(log: &Value) -> String {
    let field = |name: &str| log.get(name).and_then(Value::as_str);
    match (field("blockHash"), field("logIndex")) {
        (Some(hash), Some(index)) => format!(
            "{}:{}:{}",
            hash.to_lowercase(),
            index.to_lowercase(),
            removed(log)
        ),
        _ => log.to_string(),
    }
}

fn read_so_far(from: u64, next: u64, to: u64) -> String {
    if next == from {
        format!("no block up to {to} was read")
    } else {
        format!(
            "blocks {from}-{} were read, but the list needs every block up to {to}",
            next - 1
        )
    }
}

/// The blocks a scan reads.
pub struct Scan {
    pub escrow: Address,
    pub from: u64,
    pub to: u64,
    /// The most blocks one eth_getLogs asks for.
    pub step: u64,
    /// Report progress every so many ranges.
    pub progress_every: u64,
}

/// A request named for messages: method, params and what to call it.
pub type NamedCall<'a> = dyn FnMut(&str, &Value, &str) -> Result<Value, RpcError> + 'a;

/// The escrow's Deposit logs over blocks `scan.from..=scan.to`, read through `call` (normally `Paced`) in
/// consecutive ranges of at most `scan.step` blocks, each block in exactly one range that was read. A log the RPC
/// returns more than once is kept once.
///
/// A range the RPC refuses as too large (`range_limited`) is asked again from its first block with fewer blocks
/// (`narrowed_width`), and that smaller width is kept to the end: the ranges already read are kept, and as the width
/// only shrinks there are at most `step - 1` such refusals. A rate-limited range is retried as it was, inside
/// `call`. Every `scan.progress_every` ranges read, `log` says how far the scan got.
///
/// Fails, returning nothing, if a range cannot be read: on a refusal of a single block, on any other error, and on
/// a rate limit that outlasts `call`'s retries. The first and last also say how far the scan got.
pub fn deposit_logs(
    call: &mut NamedCall,
    scan: &Scan,
    log: &dyn Fn(&str),
) -> Result<Vec<Value>, RpcError> {
    let (from, to) = (scan.from, scan.to);
    let topic = deposit_topic();
    let mut logs = Vec::new();
    let mut seen = HashSet::new();
    let mut width = scan.step.max(1);
    let mut ranges = 0u64;
    let mut a = from;
    while a <= to {
        let end = to.min(a.saturating_add(width - 1));
        let what = format!("eth_getLogs of blocks {a}-{end}");
        let filter = json!({
            "address": scan.escrow.to_string(),
            "topics": [topic],
            "fromBlock": format!("0x{a:x}"),
            "toBlock": format!("0x{end:x}"),
        });
        let result = match call("eth_getLogs", &json!([filter]), &what) {
            Ok(result) => result,
            Err(error) if error.kind == Kind::Exhausted => {
                return Err(RpcError {
                    message: format!("{}; {}", error.message, read_so_far(from, a, to)),
                    ..error
                })
            }
            Err(error) if !range_limited(&error) => return Err(error),
            Err(error) if end == a => {
                return Err(RpcError::failed(format!(
                    "{}; the RPC refuses eth_getLogs even for block {a} alone; {}",
                    error.message,
                    read_so_far(from, a, to)
                )))
            }
            Err(error) => {
                // Alchemy's free tier, among others, limits eth_getLogs by block range. Retrying only the
                // refused range keeps every preceding result and never produces a partial deposit list.
                width = narrowed_width(&error.message, end - a + 1);
                log(&format!(
                    "eth_getLogs permits at most {width} blocks per request; continuing from block {a}, {} requests to go",
                    (to - a + 1).div_ceil(width)
                ));
                continue;
            }
        };

        let Value::Array(list) = result else {
            return Err(RpcError::failed(format!(
                "{what} returned something other than a list of logs (details not shown)"
            )));
        };
        for entry in list {
            if seen.insert(log_key(&entry)) {
                logs.push(entry);
            }
        }
        ranges += 1;
        if end == to {
            break;
        }
        a = end + 1;
        if ranges % scan.progress_every.max(1) == 0 {
            log(&format!(
                "eth_getLogs read blocks {from}-{end} of {from}-{to} in {ranges} ranges; {} logs so far",
                logs.len()
            ));
        }
    }
    Ok(logs)
}

/// `assemble.py claim --deposits` from the escrow's Deposit logs: (units, scriptPubKey hex) in index order, skipping
/// removed logs. Refuses a gap, a repeat, or a count other than the escrow's depositCount() at the logs' last block,
/// so a log range an RPC silently dropped is caught here and not later as an accumulator the claim cannot reproduce.
pub fn deposit_list(
    logs: &[Value],
    escrow: &Address,
    count: u64,
) -> Result<Vec<(u64, String)>, String> {
    let mut events = Vec::new();
    for log in logs {
        if removed(log) {
            continue;
        }
        match Deposit::from_log(log, escrow) {
            Ok(Some(deposit)) => events.push(deposit),
            Ok(None) => {}
            Err(_) => {
                return Err(
                    "the Ethereum RPC returned an invalid Deposit log (details not shown)".into(),
                )
            }
        }
    }
    events.sort_by(|a, b| a.index.cmp(&b.index));
    for (i, event) in events.iter().enumerate() {
        if event.index != word(i as u64) {
            return Err(format!(
                "deposit #{i} is missing or repeated in the logs; retry with a smaller --step"
            ));
        }
    }
    if events.len() as u64 != count {
        return Err(format!(
            "the logs hold {} deposits, but the escrow counted {count} at that block",
            events.len()
        ));
    }
    Ok(events
        .into_iter()
        .map(|e| (e.units, hex::encode(&e.script)))
        .collect())
}
