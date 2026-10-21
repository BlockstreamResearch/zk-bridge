//! The deposit scan against RPCs that bound eth_getLogs and meter requests: the deposit list it builds from the logs,
//! how it narrows, paces and retries its ranges, and the messages it fails with.
mod common;

use std::cell::{Cell, RefCell};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{json, Value};

use bridge_operator::bridge::Address;
use bridge_operator::deposits::{deposit_list, deposit_logs, narrowed_width, Scan};
use bridge_operator::rpc::{redact, retry_after_ms, rpc_url, Clock, Kind, Paced, RpcError};
use common::*;

fn escrow() -> Address {
    Address::parse(ESCROW).unwrap()
}

fn list(logs: &[Value], count: u64) -> Result<Vec<(u64, String)>, String> {
    deposit_list(logs, &escrow(), count)
}

fn pairs(expected: &[(u64, &str)]) -> Vec<(u64, String)> {
    expected.iter().map(|&(u, s)| (u, s.to_owned())).collect()
}

#[test]
fn the_deposit_list_is_in_index_order_whatever_order_the_logs_came_in() {
    let logs = [
        deposit_log(1, 250_000, P2WPKH),
        deposit_log(0, 100_000, P2TR),
    ];
    assert_eq!(
        list(&logs, 2).unwrap(),
        pairs(&[(100_000, P2TR), (250_000, P2WPKH)])
    );
}

#[test]
fn logs_of_another_contract_and_removed_logs_are_not_deposits() {
    let mut other = deposit_log(1, 100_000, P2TR);
    other["address"] = json!(format!("0x{}", "43".repeat(20)));
    let mut removed = deposit_log(1, 100_000, P2TR);
    removed["removed"] = json!(true);
    let logs = [deposit_log(0, 100_000, P2TR), other, removed];
    assert_eq!(list(&logs, 1).unwrap(), pairs(&[(100_000, P2TR)]));
}

#[test]
fn only_a_removed_of_boolean_true_removes_a_log() {
    for not_removed in [
        json!(false),
        json!(null),
        json!("true"),
        json!("false"),
        json!(1),
        json!([]),
    ] {
        let mut log = deposit_log(0, 100_000, P2TR);
        log["removed"] = not_removed.clone();
        assert_eq!(
            list(&[log], 1).unwrap(),
            pairs(&[(100_000, P2TR)]),
            "removed: {not_removed}"
        );
    }
}

#[test]
fn a_missing_or_repeated_deposit_or_a_count_other_than_the_escrows_is_refused() {
    let gap = [deposit_log(0, 100_000, P2TR), deposit_log(2, 100_000, P2TR)];
    assert!(list(&gap, 3)
        .unwrap_err()
        .starts_with("deposit #1 is missing or repeated"));
    let repeat = [deposit_log(0, 100_000, P2TR), deposit_log(0, 100_000, P2TR)];
    assert!(list(&repeat, 2)
        .unwrap_err()
        .starts_with("deposit #1 is missing or repeated"));
    assert_eq!(
        list(&[deposit_log(0, 100_000, P2TR)], 2).unwrap_err(),
        "the logs hold 1 deposits, but the escrow counted 2 at that block"
    );
}

#[test]
fn a_malformed_deposit_log_cannot_echo_its_contents() {
    let mut malformed = deposit_log(0, 100_000, P2TR);
    malformed["topics"][1] = json!("secret-from-provider-123456");
    let mut truncated = deposit_log(0, 100_000, P2TR);
    let data = truncated["data"].as_str().unwrap().to_owned();
    truncated["data"] = json!(data[..data.len() - 64]);
    for log in [malformed, truncated, json!(7)] {
        let e = list(&[log], 1).unwrap_err();
        assert_eq!(
            e,
            "the Ethereum RPC returned an invalid Deposit log (details not shown)"
        );
    }
}

#[test]
fn the_rpc_url_is_the_flag_else_the_environment_and_its_absence_names_only_the_variable() {
    let env = || Some("http://env".to_owned());
    assert_eq!(rpc_url(Some("http://flag"), env()).unwrap(), "http://flag");
    assert_eq!(rpc_url(None, env()).unwrap(), "http://env");
    assert_eq!(
        rpc_url(None, None).unwrap_err(),
        "set SEPOLIA_EXECUTION_RPC or pass --rpc"
    );
    assert!(rpc_url(Some(""), None).is_err());
    assert!(
        rpc_url(Some(""), env()).is_err(),
        "an empty --rpc is not replaced"
    );
    assert!(rpc_url(None, Some(String::new())).is_err());
}

#[test]
fn rpc_diagnostics_mask_the_url_an_api_key_path_segment_query_values_and_user_info() {
    let url = "https://opsuser01:pass-secret-99@eth-sepolia.g.alchemy.com/v2/alchemy-key-0123456789?apiKey=query-secret-123";
    let message =
        format!("at {url}: key alchemy-key-0123456789, query-secret-123, opsuser01:pass-secret-99");
    assert_eq!(
        redact(&message, url),
        "at [RPC URL]: key [RPC credential], [RPC credential], [RPC credential]:[RPC credential]"
    );
    // A token anywhere in the path, as in QuickNode's `/<token>/`, is masked too.
    let url = "https://x.ethereum-sepolia.quiknode.pro/0123456789abcdef0123/";
    assert_eq!(
        redact("token 0123456789abcdef0123 refused", url),
        "token [RPC credential] refused"
    );
    // A form-encoded key is masked in both forms; short values and the host are not credentials.
    let url = "https://rpc.example/v1?key=abc%2Fdef%2Bghi&x=1";
    assert_eq!(
        redact("abc%2Fdef%2Bghi or abc/def+ghi at rpc.example, x=1", url),
        "[RPC credential] or [RPC credential] at rpc.example, x=1"
    );
}

#[test]
fn retry_after_is_seconds_or_an_http_date() {
    let now = UNIX_EPOCH + Duration::from_secs(784_111_777);
    assert_eq!(retry_after_ms("3", now), Some(3000));
    assert_eq!(retry_after_ms(" 0 ", now), Some(0));
    assert_eq!(
        retry_after_ms("Sun, 06 Nov 1994 08:49:40 GMT", now),
        Some(3000)
    );
    assert_eq!(
        retry_after_ms("Sun, 06 Nov 1994 08:49:30 GMT", now),
        Some(0),
        "in the past"
    );
    assert_eq!(retry_after_ms("soon", now), None);
    assert_eq!(retry_after_ms("-1", now), None);
}

/// A clock that `Paced` waits on without real time passing; `waits` records each wait.
#[derive(Default)]
struct FakeClock {
    t: Cell<u64>,
    waits: RefCell<Vec<u64>>,
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.t.get()
    }

    fn sleep_ms(&self, ms: u64) {
        self.waits.borrow_mut().push(ms);
        self.t.set(self.t.get() + ms);
    }
}

fn throttled(retry_after_ms: Option<u64>) -> RpcError {
    RpcError {
        message: "eth_getLogs failed: Your app has exceeded its compute units per second capacity."
            .into(),
        code: Some(429),
        kind: Kind::RateLimited { retry_after_ms },
    }
}

#[test]
fn paced_calls_start_the_pace_apart_back_off_on_a_rate_limit_and_slow_the_pace_after_one() {
    let c = FakeClock::default();
    let lines = RefCell::new(Vec::new());
    let log = |l: &str| lines.borrow_mut().push(l.to_owned());
    let mut replies = vec![
        None,
        Some(throttled(None)),
        Some(throttled(Some(3000))),
        None,
        None,
    ]
    .into_iter();
    let mut paced = Paced::new(
        |_: &str, _: &Value| -> Result<Value, RpcError> {
            match replies.next().flatten() {
                Some(e) => Err(e),
                None => Ok(json!(c.now_ms())),
            }
        },
        &c,
        &log,
        100,
        3,
        1000,
    );
    assert_eq!(
        paced.call("eth_getLogs", &json!([]), "first").unwrap(),
        json!(0)
    );
    // 100 of pace; 1000 of backoff; the Retry-After's 3000, being over the doubled 2000; then the doubled pace, twice.
    assert_eq!(
        paced.call("eth_getLogs", &json!([]), "second").unwrap(),
        json!(4100)
    );
    assert_eq!(
        paced.call("eth_getLogs", &json!([]), "third").unwrap(),
        json!(4500)
    );
    assert_eq!(*c.waits.borrow(), vec![100, 1000, 3000, 400]);
    assert_eq!(
        *lines.borrow(),
        vec![
            "second was rate-limited; retry 1 of 3 in 1000 ms, then at most one request per 200 ms",
            "second was rate-limited; retry 2 of 3 in 3000 ms, then at most one request per 400 ms",
        ]
    );
}

#[test]
fn a_request_rate_limited_on_every_attempt_fails_after_the_retries_with_waits_capped_at_30_s() {
    let c = FakeClock::default();
    let calls = Cell::new(0);
    let quiet = |_: &str| {};
    let mut paced = Paced::new(
        |_: &str, _: &Value| -> Result<Value, RpcError> {
            calls.set(calls.get() + 1);
            Err(throttled(None))
        },
        &c,
        &quiet,
        0,
        3,
        20_000,
    );
    let e = paced
        .call("eth_getLogs", &json!([]), "eth_getLogs of blocks 0-9")
        .unwrap_err();
    assert_eq!(e.kind, Kind::Exhausted);
    assert!(e.message.starts_with(
        "eth_getLogs of blocks 0-9 was still rate-limited after 4 attempts and 80 s of backoff (eth_getLogs failed: Your app has exceeded"
    ));
    assert_eq!(calls.get(), 4);
    assert_eq!(*c.waits.borrow(), vec![20_000, 30_000, 30_000]);

    // Any other failure is not retried.
    let calls = Cell::new(0);
    let mut other = Paced::new(
        |_: &str, _: &Value| -> Result<Value, RpcError> {
            calls.set(calls.get() + 1);
            Err(RpcError::failed("eth_call failed: execution reverted"))
        },
        &c,
        &quiet,
        250,
        6,
        1000,
    );
    let e = other.call("eth_call", &json!([]), "eth_call").unwrap_err();
    assert_eq!(
        (e.message.as_str(), e.kind),
        ("eth_call failed: execution reverted", Kind::Failed)
    );
    assert_eq!(calls.get(), 1);
}

/// A paced scan of blocks 0-25 in ranges of 10 that rate-limits blocks 10-19 `times` times: the ranges asked, and
/// the result.
fn rate_limited_scan(times: u32) -> (Vec<(u64, u64)>, Result<Vec<Value>, RpcError>) {
    let c = FakeClock::default();
    let seen = RefCell::new(Vec::new());
    let left = Cell::new(times);
    let quiet = |_: &str| {};
    let mut paced = Paced::new(
        |_: &str, params: &Value| -> Result<Value, RpcError> {
            let (a, b) = log_range(params);
            seen.borrow_mut().push((a, b));
            if a == 10 && left.get() > 0 {
                left.set(left.get() - 1);
                return Err(throttled(None));
            }
            Ok(json!([{ "a": a }]))
        },
        &c,
        &quiet,
        0,
        2,
        10,
    );
    let scan = Scan {
        escrow: escrow(),
        from: 0,
        to: 25,
        step: 10,
        progress_every: 100,
    };
    let logs = deposit_logs(
        &mut |m: &str, p: &Value, w: &str| paced.call(m, p, w),
        &scan,
        &quiet,
    );
    drop(paced);
    (seen.into_inner(), logs)
}

#[test]
fn a_rate_limited_range_is_retried_alone_keeping_the_ranges_before_it() {
    let (seen, logs) = rate_limited_scan(2);
    assert_eq!(
        logs.unwrap(),
        vec![json!({ "a": 0 }), json!({ "a": 10 }), json!({ "a": 20 })]
    );
    assert_eq!(seen, vec![(0, 9), (10, 19), (10, 19), (10, 19), (20, 25)]);
}

#[test]
fn a_range_still_rate_limited_after_its_retries_ends_the_scan_with_how_far_it_got() {
    let (seen, logs) = rate_limited_scan(u32::MAX);
    let e = logs.unwrap_err();
    assert_eq!(e.kind, Kind::Exhausted);
    assert!(e
        .message
        .starts_with("eth_getLogs of blocks 10-19 was still rate-limited after 3 attempts "));
    assert!(e
        .message
        .ends_with("; blocks 0-9 were read, but the list needs every block up to 25"));
    assert_eq!(seen, vec![(0, 9), (10, 19), (10, 19), (10, 19)]);
}

/// The error `rpc::call` returns for a JSON-RPC error body that is no rate limit.
fn rpc_error(code: i64, message: &str) -> RpcError {
    RpcError {
        message: format!("eth_getLogs failed: {message}"),
        code: Some(code),
        kind: Kind::Failed,
    }
}

/// An unpaced eth_getLogs over `answer(a, b)` from blocks `from..=to` in ranges of `step`: the ranges asked, the
/// progress lines and the result.
fn provider(
    from: u64,
    to: u64,
    step: u64,
    progress_every: u64,
    answer: impl Fn(u64, u64) -> Result<Value, RpcError>,
) -> (Vec<(u64, u64)>, Vec<String>, Result<Vec<Value>, RpcError>) {
    let mut seen = Vec::new();
    let lines = RefCell::new(Vec::new());
    let scan = Scan {
        escrow: escrow(),
        from,
        to,
        step,
        progress_every,
    };
    let logs = deposit_logs(
        &mut |method: &str, params: &Value, _: &str| {
            assert_eq!(method, "eth_getLogs");
            let (a, b) = log_range(params);
            seen.push((a, b));
            answer(a, b)
        },
        &scan,
        &|l: &str| lines.borrow_mut().push(l.to_owned()),
    );
    (seen, lines.into_inner(), logs)
}

#[test]
fn a_bare_limit_exceeded_halves_the_range_until_the_rpc_answers_and_the_scan_keeps_that_width() {
    let (seen, lines, logs) = provider(100, 199, 64, 100, |a, b| {
        if b - a + 1 > 10 {
            return Err(rpc_error(-32005, "limit exceeded"));
        }
        Ok(json!(in_range(a, b)))
    });
    assert_eq!(seen[..4], [(100, 163), (100, 131), (100, 115), (100, 107)]);
    assert_covers(&seen[3..], 100, 199, 8);
    assert_eq!(seen.len(), 3 + 13);
    assert_eq!(
        list(&logs.unwrap(), 3).unwrap(),
        pairs(&[(100_000, P2TR), (250_000, P2WPKH), (300_000, P2TR)])
    );
    assert_eq!(
        lines,
        vec![
            "eth_getLogs permits at most 32 blocks per request; continuing from block 100, 4 requests to go",
            "eth_getLogs permits at most 16 blocks per request; continuing from block 100, 7 requests to go",
            "eth_getLogs permits at most 8 blocks per request; continuing from block 100, 13 requests to go",
        ]
    );
}

#[test]
fn a_limit_that_appears_mid_scan_narrows_from_the_refused_range_keeping_the_ranges_before_it() {
    // A response-size limit: the dense blocks from 500 on answer at most 100 blocks at a time.
    let (seen, _, logs) = provider(100, 1234, 300, 100, |a, b| {
        if b >= 500 && b - a + 1 > 100 {
            return Err(rpc_error(-32602, &format!("Log response size exceeded. You can make eth_getLogs requests with up to a 2K block range and no limit on the response size, or you can request any block range with a cap of 10K logs in the response. Based on your parameters, this block range should work: [0x{a:x}, 0x{:x}]", a + 99)));
        }
        Ok(json!(in_range(a, b)))
    });
    assert_eq!(seen[..3], [(100, 399), (400, 699), (400, 499)]);
    let mut read = vec![seen[0]];
    read.extend(&seen[2..]);
    assert_covers(&read, 100, 1234, 300);
    assert!(seen[2..].iter().all(|&(a, b)| b - a < 100));
    assert_eq!(list(&logs.unwrap(), 5).unwrap().len(), 5);
}

#[test]
fn the_refusals_end_a_single_refused_block_is_an_explicit_error_that_says_how_far_the_scan_got() {
    let (seen, _, logs) = provider(100, 199, 20, 100, |a, b| {
        if a >= 120 {
            return Err(rpc_error(-32005, "limit exceeded"));
        }
        Ok(json!(in_range(a, b)))
    });
    let e = logs.unwrap_err();
    assert_eq!(e.message, "eth_getLogs failed: limit exceeded; the RPC refuses eth_getLogs even for block 120 alone; blocks 100-119 were read, but the list needs every block up to 199");
    assert_eq!(e.kind, Kind::Failed);
    assert_eq!(
        seen,
        vec![
            (100, 119),
            (120, 139),
            (120, 129),
            (120, 124),
            (120, 122),
            (120, 121),
            (120, 120)
        ]
    );
}

#[test]
fn an_error_that_is_not_a_range_limit_ends_the_scan_at_once() {
    let (seen, _, logs) = provider(100, 199, 10, 100, |_, _| {
        Err(rpc_error(
            -32602,
            "invalid argument 0: hex string has leading zero digits",
        ))
    });
    assert_eq!(
        logs.unwrap_err().message,
        "eth_getLogs failed: invalid argument 0: hex string has leading zero digits"
    );
    assert_eq!(seen, vec![(100, 109)]);

    let (_, _, logs) = provider(100, 199, 10, 100, |_, _| Ok(json!({ "logs": [] })));
    assert_eq!(
        logs.unwrap_err().message,
        "eth_getLogs of blocks 100-109 returned something other than a list of logs (details not shown)"
    );

    // A rate limit that reached the scan unpaced is not a range limit either.
    let (seen, _, logs) = provider(100, 199, 10, 100, |_, _| Err(throttled(None)));
    assert!(matches!(logs.unwrap_err().kind, Kind::RateLimited { .. }));
    assert_eq!(seen, vec![(100, 109)]);
}

#[test]
fn a_log_returned_twice_is_kept_once_but_a_removed_log_and_its_replacement_are_both_kept() {
    let mut removed = deposit_log_at(1, 109, 250_000, P2WPKH);
    removed["removed"] = json!(true);
    let (_, _, logs) = provider(100, 1234, 10, 100, |a, b| {
        let mut answer = in_range(a, b);
        answer.extend(in_range(a - 1, b));
        if a == 100 {
            answer.push(removed.clone());
        }
        Ok(json!(answer))
    });
    let logs = logs.unwrap();
    assert_eq!(logs.len(), sample_deposits().len() + 1);
    assert_eq!(
        logs.iter().filter(|l| l["removed"] == json!(true)).count(),
        1
    );
    assert_eq!(list(&logs, 5).unwrap().len(), 5);
}

#[test]
fn a_log_whose_removed_is_not_boolean_true_is_the_same_log_as_one_without_it() {
    let (_, _, logs) = provider(100, 119, 10, 100, |a, b| {
        let mut answer = in_range(a, b);
        if a == 110 {
            // Deposit #1, at block 109, again in the next range, its `removed` neither absent nor true.
            for not_removed in [json!(false), json!("true"), json!(1)] {
                let mut again = deposit_log_at(1, 109, 250_000, P2WPKH);
                again["removed"] = not_removed;
                answer.push(again);
            }
        }
        Ok(json!(answer))
    });
    let logs = logs.unwrap();
    assert_eq!(logs.len(), 3);
    assert_eq!(
        list(&logs, 3).unwrap(),
        pairs(&[(100_000, P2TR), (250_000, P2WPKH), (300_000, P2TR)])
    );
}

#[test]
fn progress_is_reported_every_so_many_ranges_but_not_after_the_last() {
    let (_, lines, _) = provider(100, 159, 10, 2, |a, b| Ok(json!(in_range(a, b))));
    assert_eq!(
        lines,
        vec![
            "eth_getLogs read blocks 100-119 of 100-159 in 2 ranges; 3 logs so far",
            "eth_getLogs read blocks 100-139 of 100-159 in 4 ranges; 3 logs so far",
        ]
    );
}

#[test]
fn the_narrowed_width_is_the_rpcs_suggestion_if_smaller_else_half_and_always_shrinks() {
    let alchemy =
        "Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range.";
    assert_eq!(narrowed_width(alchemy, 2000), 10);
    assert_eq!(
        narrowed_width(
            &format!("{alchemy} Based on your parameters, this block range should work: [0x8d1b20, 0x8d1b29]."),
            2000
        ),
        10
    );
    assert_eq!(
        narrowed_width(
            "query returned more than 10000 results. Try with this block range [0x0, 0x2b5].",
            2000
        ),
        694
    );
    assert_eq!(
        narrowed_width(
            "You can make eth_getLogs requests with up to a 2K block range",
            5000
        ),
        2000
    );

    // A suggestion no smaller than the refused range, or backwards, is not one.
    assert_eq!(narrowed_width(alchemy, 10), 5);
    assert_eq!(
        narrowed_width("this block range should work: [0x10, 0x1]", 7),
        4
    );
    assert_eq!(narrowed_width("block range too large", 3), 2);
    assert_eq!(narrowed_width("block range too large", 2), 1);
}
