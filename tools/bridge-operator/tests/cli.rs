//! The built `bridge-operator` against local Esplora and JSON-RPC stubs: each command's output, and the deposit
//! scan's behaviour end to end past range limits, rate limits and repeated logs. The RPC URLs carry stand-in
//! credentials that must appear in no output.
mod common;

use std::fs;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use bridge_operator::bridge::{
    batch_ref, burn_proof, redeem_calldata, relay_batch, submit_headers_calldata, Address, Batch,
    REDEEM, REDEEM_TO,
};
use bridge_operator::elements::display_hex;
use bridge_operator::hash::keccak256;
use bridge_operator::hex;
use common::*;

const SECRET: &str = "fake-secret-123456";
const QUERY_SECRET: &str = "query-secret-123456";

fn assert_no_secret(run: &Run) {
    for secret in [SECRET, QUERY_SECRET] {
        assert!(
            !run.stdout.contains(secret) && !run.stderr.contains(secret),
            "{}{}",
            run.stdout,
            run.stderr
        );
    }
}

/// What a JSON-RPC stub saw: each eth_getLogs range, or another method's name.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Logs(u64, u64),
    Method(String),
}

/// A JSON-RPC stub: finalized block `finalized`, depositCount() the logs of `deposits` up to the block asked,
/// and eth_getLogs answered by `get_logs(a, b, deposits in a..=b)`. Returns its base URL and what it saw.
fn rpc_stub(
    finalized: u64,
    deposits: Vec<(u64, Value)>,
    mut get_logs: impl FnMut(u64, u64, Vec<Value>) -> Reply + Send + 'static,
) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let base = serve(move |r| {
        let body = r.json();
        let method = body["method"].as_str().unwrap();
        let params = &body["params"];
        let between = |a: u64, b: u64| -> Vec<Value> {
            deposits
                .iter()
                .filter(|(at, _)| (a..=b).contains(at))
                .map(|(_, l)| l.clone())
                .collect()
        };
        if method == "eth_getLogs" {
            let (a, b) = log_range(params);
            log.lock().unwrap().push(Seen::Logs(a, b));
            return get_logs(a, b, between(a, b));
        }
        log.lock().unwrap().push(Seen::Method(method.to_owned()));
        if method == "eth_call" {
            assert_eq!(params[0]["to"], ESCROW);
            let count = between(0, block_number(&params[1])).len() as u64;
            return Reply::rpc(json!(format!("0x{}", word_hex(count))));
        }
        assert_eq!(method, "eth_getBlockByNumber");
        Reply::rpc(json!({ "number": format!("0x{finalized:x}") }))
    });
    (base, seen)
}

fn ranges(seen: &[Seen]) -> Vec<(u64, u64)> {
    seen.iter()
        .filter_map(|s| match s {
            Seen::Logs(a, b) => Some((*a, *b)),
            Seen::Method(_) => None,
        })
        .collect()
}

fn read(path: &std::path::Path) -> String {
    fs::read_to_string(path).unwrap()
}

/// The file `deposits` writes for these (units, script) pairs: compact JSON and a newline.
fn deposit_file(pairs: &[(u64, &str)]) -> String {
    let items: Vec<String> = pairs
        .iter()
        .map(|(u, s)| format!("[{u},\"{s}\"]"))
        .collect();
    format!("[{}]\n", items.join(","))
}

#[test]
fn deposits_reads_every_block_once_past_alchemys_free_tier_keeping_each_log_once() {
    let samples: Vec<(u64, Value)> = sample_deposits()
        .into_iter()
        .map(|l| (block_number(&l["blockNumber"]), l))
        .collect();
    let all = samples.clone();
    let (base, seen) = rpc_stub(1234, samples, move |a, b, mut found| {
        if b - a + 1 > 10 {
            return Reply::rpc_error(
                400,
                json!({
                    "code": -32005,
                    "message": format!("Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range. Based on your parameters, this block range should work: [0x{a:x}, 0x{:x}]. Upgrade to PAYG for expanded block range.", a + 9),
                }),
            );
        }
        // A provider glitch: deposit #3 twice in one answer, and #1 again in the range after its own.
        if (a..=b).contains(&555) {
            found.push(all[3].1.clone());
        }
        if a == 110 {
            found.push(all[1].1.clone());
        }
        Reply::rpc(json!(found))
    });
    let dir = scratch("free-tier");
    let out = dir.join("deposits.json");
    let url = format!("{base}/v2/{SECRET}");
    let run = operator(
        &[
            "deposits",
            "--escrow",
            ESCROW,
            "--from",
            "100",
            "--out",
            out.to_str().unwrap(),
            "--pace",
            "0",
        ],
        &[("SEPOLIA_EXECUTION_RPC", url.as_str())],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);

    // One refusal of the default 2000 blocks, then the suggested 10 blocks per request through the finalized block.
    let read_ranges = ranges(&seen.lock().unwrap());
    assert_eq!(read_ranges[0], (100, 1234));
    assert_eq!(read_ranges.len(), 1 + 114);
    assert_covers(&read_ranges[1..], 100, 1234, 10);

    assert_eq!(
        read(&out),
        deposit_file(&[
            (100_000, P2TR),
            (250_000, P2WPKH),
            (300_000, P2TR),
            (400_000, P2WPKH),
            (500_000, P2TR)
        ])
    );
    let report = run.json();
    assert_eq!(
        (report["to_block"].clone(), report["deposits"].clone()),
        (json!(1234), json!(5))
    );
    assert_eq!(report["out"], out.to_str().unwrap());
    assert_eq!(
        run.stderr_lines(),
        vec![
            "eth_getLogs permits at most 10 blocks per request; continuing from block 100, 114 requests to go",
            "eth_getLogs read blocks 100-1099 of 100-1234 in 100 ranges; 4 logs so far",
        ]
    );
    assert_no_secret(&run);
}

#[test]
fn a_limit_exceeded_that_is_a_rate_limit_in_its_words_is_retried_as_it_was_never_split() {
    let samples: Vec<(u64, Value)> = sample_deposits()
        .into_iter()
        .map(|l| (block_number(&l["blockNumber"]), l))
        .collect();
    let mut limits = 2;
    let (base, seen) = rpc_stub(1234, samples, move |a, _, found| {
        if a == 110 && limits > 0 {
            limits -= 1;
            return Reply::rpc_error(
                200,
                json!({ "code": -32005, "message": "daily request count exceeded, request rate limited" }),
            );
        }
        Reply::rpc(json!(found))
    });
    let dir = scratch("rate-words");
    let out = dir.join("deposits.json");
    let url = format!("{base}/v2/{SECRET}");
    let run = operator(
        &[
            "deposits",
            "--escrow",
            ESCROW,
            "--from",
            "100",
            "--to",
            "139",
            "--out",
            out.to_str().unwrap(),
            "--step",
            "10",
            "--pace",
            "0",
            "--backoff",
            "1",
        ],
        &[("SEPOLIA_EXECUTION_RPC", url.as_str())],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(
        ranges(&seen.lock().unwrap()),
        vec![
            (100, 109),
            (110, 119),
            (110, 119),
            (110, 119),
            (120, 129),
            (130, 139)
        ]
    );
    assert_eq!(
        read(&out),
        deposit_file(&[(100_000, P2TR), (250_000, P2WPKH), (300_000, P2TR)])
    );
    assert!(!run.stderr.contains("permits at most"));
}

/// Two deposits, at blocks 16 and 38, and finalized block 38.
fn two_deposits() -> Vec<(u64, Value)> {
    vec![
        (16, deposit_log(0, 100_000, P2TR)),
        (38, deposit_log(1, 250_000, P2WPKH)),
    ]
}

#[test]
fn deposits_reads_the_rpc_url_from_the_environment_without_it_in_its_output() {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let p = paths.clone();
    let base = serve(move |r| {
        p.lock().unwrap().push(r.path.clone());
        let body = r.json();
        match body["method"].as_str().unwrap() {
            "eth_getBlockByNumber" => Reply::rpc(json!({ "number": "0x10" })),
            "eth_getLogs" => Reply::rpc(json!([deposit_log(0, 100_000, P2WPKH)])),
            _ => Reply::rpc(json!(format!("0x{}", word_hex(1)))),
        }
    });
    let secret_path = "/v3/not-a-real-key-0123456789";
    let url = format!("{base}{secret_path}");
    let dir = scratch("environment");
    let out = dir.join("deposits.json");
    let args = [
        "deposits",
        "--escrow",
        ESCROW,
        "--from",
        "0",
        "--out",
        out.to_str().unwrap(),
    ];

    let run = operator(&args, &[("SEPOLIA_EXECUTION_RPC", url.as_str())]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(read(&out), deposit_file(&[(100_000, P2WPKH)]));
    assert_eq!(run.json()["to_block"], 16);
    assert!(!run.stdout.contains(secret_path) && !run.stderr.contains(secret_path));
    assert_eq!(*paths.lock().unwrap(), vec![secret_path; 3]);

    let unset = operator(&args, &[]);
    assert_eq!(unset.code, Some(2));
    assert_eq!(
        unset.stderr.trim(),
        "set SEPOLIA_EXECUTION_RPC or pass --rpc"
    );

    // --rpc works on its own, and wins over the environment.
    paths.lock().unwrap().clear();
    let mut with_flag = args.to_vec();
    with_flag.extend(["--rpc", url.as_str()]);
    let run = operator(
        &with_flag,
        &[("SEPOLIA_EXECUTION_RPC", "http://127.0.0.1:9/unused")],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(paths.lock().unwrap().len(), 3);
}

#[test]
fn deposits_adapts_to_a_10_block_limit_without_losing_ranges_or_exposing_the_rpc_url() {
    let url = Arc::new(Mutex::new(String::new()));
    let endpoint = url.clone();
    let (base, seen) = rpc_stub(38, two_deposits(), move |a, b, found| {
        if b - a + 1 > 10 {
            // No error code: the limit is in the words, and so is the endpoint with its credentials.
            let message = format!(
                "Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range. Endpoint: {}; token {QUERY_SECRET}; key {SECRET}",
                endpoint.lock().unwrap()
            );
            return Reply::rpc_error(200, json!({ "message": message }));
        }
        Reply::rpc(json!(found))
    });
    let rpc = format!("{base}/v2/{SECRET}?apiKey={QUERY_SECRET}");
    *url.lock().unwrap() = rpc.clone();
    let dir = scratch("ten-blocks");
    let out = dir.join("deposits.json");
    let run = operator(
        &[
            "deposits",
            "--escrow",
            ESCROW,
            "--from",
            "16",
            "--out",
            out.to_str().unwrap(),
        ],
        &[("SEPOLIA_EXECUTION_RPC", rpc.as_str())],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(
        ranges(&seen.lock().unwrap()),
        vec![(16, 38), (16, 25), (26, 35), (36, 38)]
    );
    assert_eq!(
        read(&out),
        deposit_file(&[(100_000, P2TR), (250_000, P2WPKH)])
    );
    assert!(run.stderr.contains("at most 10 blocks per request"));
    assert_no_secret(&run);
}

#[test]
fn deposits_paces_its_requests_and_rides_out_compute_unit_429s_without_exposing_the_rpc_url() {
    let mut limits = 2;
    let (base, seen) = rpc_stub(38, two_deposits(), move |a, _, found| {
        if a == 26 && limits > 0 {
            limits -= 1;
            return Reply::rpc_error(
                429,
                json!({
                    "code": 429,
                    "message": format!("Your app has exceeded its compute units per second capacity (app {SECRET}, key {QUERY_SECRET})."),
                }),
            );
        }
        Reply::rpc(json!(found))
    });
    let dir = scratch("compute-units");
    let out = dir.join("deposits.json");
    let rpc = format!("{base}/v2/{SECRET}?apiKey={QUERY_SECRET}");
    let run = operator(
        &[
            "deposits",
            "--escrow",
            ESCROW,
            "--from",
            "16",
            "--out",
            out.to_str().unwrap(),
            "--step",
            "10",
            "--pace",
            "50",
            "--backoff",
            "5",
        ],
        &[("SEPOLIA_EXECUTION_RPC", rpc.as_str())],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let method = |m: &str| Seen::Method(m.to_owned());
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            method("eth_getBlockByNumber"),
            Seen::Logs(16, 25),
            Seen::Logs(26, 35),
            Seen::Logs(26, 35),
            Seen::Logs(26, 35),
            Seen::Logs(36, 38),
            method("eth_call"),
        ]
    );
    assert_eq!(
        read(&out),
        deposit_file(&[(100_000, P2TR), (250_000, P2WPKH)])
    );
    assert_eq!(
        run.stderr_lines(),
        vec![
            "eth_getLogs of blocks 26-35 was rate-limited; retry 1 of 6 in 5 ms, then at most one request per 100 ms",
            "eth_getLogs of blocks 26-35 was rate-limited; retry 2 of 6 in 10 ms, then at most one request per 200 ms",
        ]
    );
    assert_no_secret(&run);
}

#[test]
fn deposits_that_stay_rate_limited_fail_redacted_and_leave_the_previous_file_as_it_was() {
    let url = Arc::new(Mutex::new(String::new()));
    let endpoint = url.clone();
    let (base, seen) = rpc_stub(38, two_deposits(), move |a, _, found| {
        if a == 26 {
            // A gateway's plain-text 429, here carrying the key; its body is never echoed.
            return Reply::text(
                429,
                format!("Too Many Requests for {}", endpoint.lock().unwrap()),
            );
        }
        Reply::rpc(json!(found))
    });
    let rpc = format!("{base}/v2/{SECRET}?apiKey={QUERY_SECRET}");
    *url.lock().unwrap() = rpc.clone();
    let dir = scratch("exhausted");
    let out = dir.join("deposits.json");
    fs::write(&out, "previous\n").unwrap();
    let out_text = out.to_str().unwrap();
    let run = operator(
        &[
            "deposits",
            "--escrow",
            ESCROW,
            "--from",
            "16",
            "--out",
            out_text,
            "--step",
            "10",
            "--pace",
            "1",
            "--retries",
            "2",
            "--backoff",
            "5",
        ],
        &[("SEPOLIA_EXECUTION_RPC", rpc.as_str())],
    );
    assert_eq!(run.code, Some(2));
    assert_eq!(run.stdout, "");
    let lines = run.stderr_lines();
    assert_eq!(lines.len(), 3, "{}", run.stderr);
    assert!(
        lines[0].starts_with("eth_getLogs of blocks 26-35 was rate-limited; retry 1 of 2 in 5 ms")
    );
    assert!(
        lines[1].starts_with("eth_getLogs of blocks 26-35 was rate-limited; retry 2 of 2 in 10 ms")
    );
    assert_eq!(
        lines[2],
        format!(
            "eth_getLogs of blocks 26-35 was still rate-limited after 3 attempts and 0 s of backoff (eth_getLogs failed: HTTP 429 without a JSON-RPC body); blocks 16-25 were read, but the list needs every block up to 38. Nothing was written to {out_text}; rerun once the provider's limit has reset, or with a larger --pace"
        )
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            Seen::Method("eth_getBlockByNumber".into()),
            Seen::Logs(16, 25),
            Seen::Logs(26, 35),
            Seen::Logs(26, 35),
            Seen::Logs(26, 35),
        ]
    );
    assert_eq!(read(&out), "previous\n");
    let names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, vec!["deposits.json"]);
    assert_no_secret(&run);
}

#[test]
fn deposits_waits_as_long_as_a_retry_after_header_asks() {
    let mut limits = 1;
    let (base, _) = rpc_stub(38, two_deposits(), move |a, _, found| {
        if a == 26 && limits > 0 {
            limits -= 1;
            return Reply::rpc_error(429, json!({ "code": 429, "message": "Too many requests" }))
                .with_retry_after("1");
        }
        Reply::rpc(json!(found))
    });
    let out = scratch("retry-after").join("deposits.json");
    let rpc = format!("{base}/v2/{SECRET}");
    let run = operator(
        &[
            "deposits",
            "--escrow",
            ESCROW,
            "--from",
            "16",
            "--out",
            out.to_str().unwrap(),
            "--step",
            "10",
            "--pace",
            "0",
            "--backoff",
            "0",
        ],
        &[("SEPOLIA_EXECUTION_RPC", rpc.as_str())],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(
        run.stderr_lines(),
        vec!["eth_getLogs of blocks 26-35 was rate-limited; retry 1 of 6 in 1000 ms, then at most one request per 100 ms"]
    );
    assert_eq!(
        read(&out),
        deposit_file(&[(100_000, P2TR), (250_000, P2WPKH)])
    );
}

#[test]
fn a_gateway_page_is_reported_by_its_status_never_echoed() {
    let (base, seen) = rpc_stub(38, two_deposits(), |_, _, _| {
        Reply::html(502, format!("<html>Bad gateway for /v2/{SECRET}</html>"))
    });
    let out = scratch("gateway").join("deposits.json");
    let rpc = format!("{base}/v2/{SECRET}");
    let run = operator(
        &[
            "deposits",
            "--escrow",
            ESCROW,
            "--from",
            "16",
            "--to",
            "38",
            "--out",
            out.to_str().unwrap(),
            "--pace",
            "0",
        ],
        &[("SEPOLIA_EXECUTION_RPC", rpc.as_str())],
    );
    assert_eq!(
        (run.code, run.stderr.trim()),
        (
            Some(2),
            "eth_getLogs failed: HTTP 502 without a JSON-RPC body"
        )
    );
    assert_eq!(
        ranges(&seen.lock().unwrap()),
        vec![(16, 38)],
        "neither retried nor split"
    );
    assert!(!out.exists());
    assert_no_secret(&run);
}

#[test]
fn deposits_from_past_the_finalized_block_reads_nothing_and_says_why() {
    let (base, seen) = rpc_stub(38, two_deposits(), |_, _, found| Reply::rpc(json!(found)));
    let out = scratch("not-final").join("deposits.json");
    let rpc = format!("{base}/v2/{SECRET}");
    let run = operator(
        &[
            "deposits",
            "--escrow",
            ESCROW,
            "--from",
            "50",
            "--out",
            out.to_str().unwrap(),
        ],
        &[("SEPOLIA_EXECUTION_RPC", rpc.as_str())],
    );
    assert_eq!(
        (run.code, run.stderr.trim()),
        (
            Some(2),
            "the finalized block is 38, before --from 50: no block to read yet"
        )
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![Seen::Method("eth_getBlockByNumber".into())]
    );
    assert!(!out.exists());
}

#[test]
fn an_esplora_that_is_unreachable_or_fails_is_reported_without_its_url_or_token() {
    let esplora = "http://127.0.0.1:9/api/0123456789abcdef0123?key=esplora-secret-123456";
    let run = operator(&["federation", "--esplora", esplora], &[]);
    assert_eq!(
        (run.code, run.stderr.trim()),
        (
            Some(2),
            "Liquid API /blocks/tip/hash: no answer (details not shown)"
        )
    );

    // A private Esplora with a token in its path: an error page repeating the token is named by its status, and
    // a block hash that is not one is refused without being echoed.
    let token = "esplora-token-0123456789abcdef";
    let base = serve(move |r| match r.path.strip_suffix("/blocks/tip/hash") {
        Some(_) if r.path.contains("broken") => {
            Reply::html(503, format!("<html>no backend for /{token}/</html>"))
        }
        Some(_) => Reply::text(200, format!("{token}{token}")),
        None => Reply::text(404, "not found"),
    });
    for (api, message) in [
        (
            format!("{base}/broken/{token}/api"),
            "Liquid API /blocks/tip/hash: HTTP 503",
        ),
        (
            format!("{base}/{token}/api"),
            "Liquid API returned an invalid block hash",
        ),
    ] {
        let run = operator(&["federation", "--esplora", api.as_str()], &[]);
        assert_eq!((run.code, run.stderr.trim()), (Some(2), message));
        assert!(!run.stdout.contains(token) && !run.stderr.contains(token));
    }
}

#[test]
fn deposits_refuses_bad_options_before_any_request() {
    let out = scratch("options").join("deposits.json");
    let out = out.to_str().unwrap();
    let rpc = [("SEPOLIA_EXECUTION_RPC", "http://127.0.0.1:9/never")];
    for (args, message) in [
        (vec!["--from", "0", "--out", out], "missing --escrow"),
        (
            vec!["--escrow", ESCROW, "--from", "x", "--out", out],
            "bad --from, --to or --step",
        ),
        (
            vec!["--escrow", ESCROW, "--from", "9", "--to", "8", "--out", out],
            "bad --from, --to or --step",
        ),
        (
            vec![
                "--escrow", ESCROW, "--from", "0", "--step", "0", "--out", out,
            ],
            "bad --from, --to or --step",
        ),
        (
            vec![
                "--escrow",
                ESCROW,
                "--from",
                "0",
                "--retries",
                "21",
                "--out",
                out,
            ],
            "bad --pace, --retries or --backoff",
        ),
        (
            vec![
                "--escrow", ESCROW, "--from", "0", "--pace", "-1", "--out", out,
            ],
            "bad --pace, --retries or --backoff",
        ),
        (
            vec![
                "--escrow", ESCROW, "--from", "0", "--out", out, "--setp", "10",
            ],
            "unknown option --setp",
        ),
        (
            vec!["--escrow", ESCROW, "--from"],
            "bad option --from: options are --name value pairs",
        ),
        (
            vec![
                "--escrow", ESCROW, "--escrow", ESCROW, "--from", "0", "--out", out,
            ],
            "--escrow is given twice",
        ),
    ] {
        let mut command = vec!["deposits"];
        command.extend(&args);
        let run = operator(&command, &rpc);
        assert_eq!(
            (run.code, run.stderr.trim()),
            (Some(2), message),
            "{args:?}"
        );
    }
}

#[test]
fn an_rpc_url_out_of_place_on_the_command_line_is_never_echoed() {
    let url =
        format!("https://opsuser01:{SECRET}@eth-sepolia.example/v2/{SECRET}?apiKey={QUERY_SECRET}");
    let rpc_flag = format!("--rpc={url}");
    let bad = "bad option (not shown, as it may be an RPC URL): options are --name value pairs";
    let unknown = "unknown option (not shown, as it may be an RPC URL)";
    for (args, message) in [
        // Positional, in place of --rpc <url>.
        (
            vec!["deposits", url.as_str(), "--escrow", ESCROW, "--from", "0"],
            bad,
        ),
        // After complete options.
        (
            vec!["deposits", "--escrow", ESCROW, "--from", "0", url.as_str()],
            bad,
        ),
        // Shifted by a missing value: --escrow takes --rpc, leaving the URL where a --name belongs.
        (vec!["deposits", "--escrow", "--rpc", url.as_str()], bad),
        // As --rpc=<url>, which is no option of the command.
        (
            vec!["deposits", rpc_flag.as_str(), "--escrow", ESCROW],
            unknown,
        ),
        // Every command parses its options the same way.
        (
            vec!["relay", url.as_str(), "--escrow", ESCROW, "--target", "1"],
            bad,
        ),
    ] {
        let run = operator(&args, &[]);
        assert_eq!(
            (run.code, run.stderr.trim()),
            (Some(2), message),
            "{args:?}"
        );
        assert_no_secret(&run);
    }
}

#[test]
fn burn_script_prints_the_shared_vectors() {
    let vectors = fixture("vectors/protocol.json");
    for case in vectors["burn_script"].as_array().unwrap() {
        let chain = case["chain_id"].as_u64().unwrap().to_string();
        let run = operator(
            &[
                "burn-script",
                chain.as_str(),
                case["escrow"].as_str().unwrap(),
                case["recipient"].as_str().unwrap(),
            ],
            &[],
        );
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        let out = run.json();
        assert_eq!(
            format!("0x{}", out["scriptPubKey"].as_str().unwrap()),
            case["script"].as_str().unwrap()
        );
        assert_eq!(out["chain_id"], chain);
        assert_eq!(out["escrow"], case["escrow"]);
        assert_eq!(out["recipient"], case["recipient"]);
    }
    let run = operator(&["burn-script", "11155111", ESCROW], &[]);
    assert_eq!(
        (run.code, run.stderr.trim()),
        (Some(2), "burn-script <chain id> <escrow> <recipient>")
    );
}

fn assert_real_federation(out: &Value) {
    assert_eq!(out["height"], 2_664_000);
    assert_eq!(
        out["block_hash_display"],
        "1a195d11b63038c91100a09efdb1489ae16e6f6f64cdc20a227015bc4ba77eb7"
    );
    assert_eq!(out["witness_script"], format!("0x{REAL_SCRIPT}"));
    assert_eq!(out["threshold"], 1);
    assert_eq!(out["keys"], json!([&REAL_SCRIPT[4..70]]));
    assert_eq!(out["key_y"], json!([REAL_KEY_Y]));
    let keys: Vec<&str> = out
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "height",
            "block_hash_display",
            "block_hash_internal",
            "signblockscript",
            "signblockscript_keccak",
            "witness_script",
            "threshold",
            "keys",
            "key_y"
        ]
    );
}

#[test]
fn federation_reads_a_header_given_in_a_file_or_from_esplora() {
    let signed = real_signed();
    let run = operator(&["federation", signed.as_str()], &[]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_real_federation(&run.json());

    let file = scratch("federation").join("header.hex");
    fs::write(&file, format!("{signed}\n")).unwrap();
    let at_file = format!("@{}", file.display());
    let run = operator(&["federation", at_file.as_str()], &[]);
    assert_real_federation(&run.json());

    let id = "1a195d11b63038c91100a09efdb1489ae16e6f6f64cdc20a227015bc4ba77eb7";
    let routes = [
        ("/blocks/tip/hash".to_owned(), id.to_owned()),
        (format!("/block/{id}/header"), real_signed()),
    ];
    let base = chain_stub(routes.into_iter().collect(), Escrow::new(vec![], 0));
    let esplora = format!("{base}/esplora");
    let run = operator(&["federation", "--esplora", esplora.as_str()], &[]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_real_federation(&run.json());

    let unsigned = operator(&["federation", REAL_HASH_FORM], &[]);
    assert_eq!(unsigned.code, Some(2));
    assert!(unsigned.stderr.contains("no signblock witness"));
}

#[test]
fn checkpoint_names_the_last_completed_epoch_and_the_next_epochs_keys() {
    let chain = chain(1991, 2150, |h| [h as u8; 32]);
    let mut routes = esplora_routes(&chain);
    routes.insert("/blocks/tip/height".into(), "2010".into());
    let base = chain_stub(routes, Escrow::new(vec![], 0));
    let esplora = format!("{base}/esplora");
    let run = operator(
        &[
            "checkpoint",
            "--esplora",
            esplora.as_str(),
            "--epoch-length",
            "1000",
        ],
        &[],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let out = run.json();
    let checkpoint = &chain[1999 - 1991].2;
    assert_eq!(out["epochLength"], 1000);
    assert_eq!(out["height"], 1999);
    assert_eq!(out["hash"], hex::prefixed(&checkpoint.hash));
    assert_eq!(
        out["checkpoint_hash_display"],
        display_hex(&checkpoint.hash)
    );
    assert_eq!(out["witnessScript"], hex::prefixed(&witness_script()));
    assert_eq!(out["keyY"], json!([format!("0x{G_Y}")]));
    assert_eq!(out["next_epoch_threshold"], 1);

    let early = operator(
        &[
            "checkpoint",
            "--esplora",
            esplora.as_str(),
            "--epoch-length",
            "3000",
        ],
        &[],
    );
    assert_eq!(
        (early.code, early.stderr.trim()),
        (Some(2), "no completed epoch yet")
    );
}

#[test]
fn relay_prints_the_next_batch_and_stops_at_the_target() {
    let chain = chain(1991, 2150, |h| [h as u8; 32]);
    let escrow = Escrow::new(vec![], 1990);
    let base = chain_stub(esplora_routes(&chain), escrow.clone());
    let rpc = format!("{base}/rpc/v2/{SECRET}");
    let esplora = format!("{base}/esplora");
    let args = [
        "relay",
        "--esplora",
        esplora.as_str(),
        "--escrow",
        ESCROW,
        "--target",
        "2150",
    ];
    let env = [("SEPOLIA_EXECUTION_RPC", rpc.as_str())];

    let run = operator(&args, &env);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let out = run.json();
    let hexes: Vec<String> = chain[..9]
        .iter()
        .map(|(_, raw, _)| hex::encode(raw))
        .collect();
    let spk_hash = keccak256(&p2wsh(&witness_script()));
    let expected = submit_headers_calldata(&relay_batch(&hexes, &spk_hash).unwrap());
    assert_eq!(out["first_height"], 1991);
    assert_eq!(out["count"], 9);
    assert_eq!(out["carries_new_keys"], false);
    assert_eq!(out["calldata"], expected);
    assert_no_secret(&run);

    // With the flag instead of the environment, and the light client under another signing script.
    *escrow.signblockscript_hash.lock().unwrap() = [0; 32];
    let mut with_flag = args.to_vec();
    with_flag.extend(["--rpc", rpc.as_str()]);
    let changed = operator(&with_flag, &[]).json();
    assert_eq!(changed["carries_new_keys"], true);
    assert_eq!(
        changed["calldata"],
        submit_headers_calldata(&relay_batch(&hexes, &[0; 32]).unwrap())
    );

    escrow.set_tip(2150);
    let done = operator(&args, &env);
    assert_eq!(
        done.stdout,
        "{\"relayed\":true,\"note\":\"the light client already covers the target\"}\n"
    );
}

#[test]
fn redeem_prints_redeem_or_redeem_to_arguments_once_the_burn_is_relayed() {
    let recipient = Address::parse(&format!("0x{}", "ab".repeat(20))).unwrap();
    let script = bridge_operator::bridge::burn_script(
        11_155_111,
        &Address::parse(ESCROW).unwrap(),
        &recipient,
    );
    let burn = BurnChain::new(&script);
    let root = batch_root(&burn.roots);
    let escrow = Escrow::new(vec![(5000, 3, root)], 5000);
    let base = chain_stub(burn.routes(true), escrow.clone());
    let rpc = format!("{base}/rpc/v2/{SECRET}");
    let esplora = format!("{base}/esplora");
    let recipient_text = recipient.to_string();
    let args = [
        "redeem",
        "--esplora",
        esplora.as_str(),
        "--escrow",
        ESCROW,
        "--txid",
        burn.txid.as_str(),
        "--vout",
        "0",
        "--recipient",
        recipient_text.as_str(),
    ];
    let env = [("SEPOLIA_EXECUTION_RPC", rpc.as_str())];

    let waiting = operator(&args, &env);
    assert_eq!(waiting.code, Some(0), "{}", waiting.stderr);
    assert_eq!(
        waiting.json(),
        json!({ "state": "awaiting-relay", "height": 5000, "tip": 5000, "needed": 5001 })
    );

    escrow.set_tip(5002);
    let run = operator(&args, &env);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let out = run.json();
    let txids = [display_hex(&burn.other), burn.txid.clone()];
    let proof = burn_proof(
        &burn.txid,
        &hex::encode(&burn.tx),
        0,
        &txids,
        &hex::encode(&burn.chain[0].1),
    )
    .unwrap();
    let batch = Batch {
        index: 0,
        first_height: 5000,
        count: 3,
        root,
    };
    let block_ref = batch_ref(&batch, &burn.roots, 5000).unwrap();
    assert_eq!(out["height"], 5000);
    assert_eq!(out["light_client_tip"], 5002);
    assert_eq!(out["recipient"], recipient_text);
    assert_eq!(out["pay_to"], recipient_text);
    assert_eq!(
        out["burn"],
        json!({
            "transaction": hex::prefixed(&burn.tx),
            "vout": 0,
            "branch": [hex::prefixed(&burn.other)],
            "position": 1,
        })
    );
    assert_eq!(out["ref"]["batch"], 0);
    assert_eq!(out["ref"]["index"], 0);
    assert_eq!(out["ref"]["path"].as_array().unwrap().len(), 2);
    assert_eq!(
        out["calldata"],
        redeem_calldata(REDEEM, &recipient, &proof.burn, &block_ref)
    );
    assert!(out.get("note").is_none());
    assert_no_secret(&run);

    let payee = Address::parse(&format!("0x{}", "cd".repeat(20))).unwrap();
    let mut to = args.to_vec();
    let payee_text = payee.to_string();
    to.extend(["--to", payee_text.as_str()]);
    let out = operator(&to, &env).json();
    assert_eq!(out["pay_to"], payee_text);
    assert_eq!(
        out["calldata"],
        redeem_calldata(REDEEM_TO, &payee, &proof.burn, &block_ref)
    );
    assert!(out["note"]
        .as_str()
        .unwrap()
        .starts_with("redeemTo: send this from the recipient account itself"));

    let unconfirmed = chain_stub(burn.routes(false), escrow);
    let esplora = format!("{unconfirmed}/esplora");
    let rpc = format!("{unconfirmed}/rpc");
    let mut args = args.to_vec();
    args[2] = esplora.as_str();
    let out = operator(&args, &[("SEPOLIA_EXECUTION_RPC", rpc.as_str())]).json();
    assert_eq!(out, json!({ "state": "unconfirmed" }));
}

#[test]
fn usage_and_unknown_commands() {
    let none = operator(&[], &[]);
    assert_eq!(none.code, Some(2));
    assert!(none.stderr.starts_with(
        "usage: bridge-operator federation|checkpoint|burn-script|relay|redeem|deposits"
    ));
    assert_eq!(operator(&["node"], &[]).code, Some(2));
    let help = operator(&["help"], &[]);
    assert_eq!(help.code, Some(0));
    for command in [
        "federation",
        "checkpoint",
        "burn-script",
        "relay",
        "redeem",
        "deposits",
    ] {
        assert!(
            help.stdout.contains(&format!("bridge-operator {command}")),
            "{command}"
        );
    }
    let relay = operator(
        &[
            "relay",
            "--esplora",
            "http://127.0.0.1:9",
            "--escrow",
            ESCROW,
        ],
        &[],
    );
    assert_eq!(
        (relay.code, relay.stderr.trim()),
        (Some(2), "missing --target")
    );
    let relay = operator(
        &[
            "relay",
            "--esplora",
            "http://127.0.0.1:9",
            "--escrow",
            ESCROW,
            "--target",
            "1",
        ],
        &[],
    );
    assert_eq!(
        (relay.code, relay.stderr.trim()),
        (Some(2), "set SEPOLIA_EXECUTION_RPC or pass --rpc")
    );
}
