//! Shared by the test files: synthetic signed DynaFed headers, Deposit logs as an RPC returns them, a local HTTP
//! stub, and a runner for the built binary.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::{fs, thread};

use serde_json::{json, Value};

use bridge_operator::abi::word;
use bridge_operator::bridge::{batch_at, deposit_topic, view};
use bridge_operator::elements::{display_hex, Header, Transaction};
use bridge_operator::esplora::Esplora;
use bridge_operator::hash::{keccak256, sha256, sha256d};
use bridge_operator::hex;

/// The repository root, for the fixtures other implementations share.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn fixture(path: &str) -> Value {
    let text = fs::read_to_string(repo().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The secp256k1 generator, whose x makes a compressed key and whose y is known.
pub const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
pub const G_Y: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

/// `OP_1 <G> OP_1 OP_CHECKMULTISIG`, the 1-of-1 shape Liquid testnet's signers use.
pub fn witness_script() -> Vec<u8> {
    let mut script = vec![0x51, 0x21];
    script.extend(hex::decode(&format!("02{G_X}")).unwrap());
    script.extend([0x51, 0xae]);
    script
}

pub fn p2wsh(script: &[u8]) -> Vec<u8> {
    let mut spk = vec![0x00, 0x20];
    spk.extend(sha256(script));
    spk
}

/// A made-up DER signature with SIGHASH_ALL: r = 11.., s = 2b...
pub fn made_up_sig() -> Vec<u8> {
    hex::decode(&format!(
        "30440220{}0220{}01",
        "11".repeat(32),
        "2b".repeat(32)
    ))
    .unwrap()
}

/// A strict-DER signature, as Elements requires in a block.
pub fn der_sig() -> Vec<u8> {
    hex::decode("3044022035cf30cbcf4d20c66a0fc5dd605238ffa322809af75f9e43a6fc0b55b5dc8c7e02202b864286584a4ff823f07b1bd50ac7deac49709ba0e81bc87db459d57b941dc501").unwrap()
}

/// A DynaFed header with compact current params paying to `witness_script()`, null proposed params, and its
/// signblock witness [empty, sig, witness script], built as the JavaScript tests build theirs.
pub fn signed_header(prev: [u8; 32], merkle_root: [u8; 32], height: u32, sig: &[u8]) -> Vec<u8> {
    let script = witness_script();
    let spk = p2wsh(&script);
    let mut h = Vec::new();
    h.extend(0xa000_0000u32.to_le_bytes());
    h.extend(prev);
    h.extend(merkle_root);
    h.extend(1_760_000_000u32.to_le_bytes());
    h.extend(height.to_le_bytes());
    h.extend([0x01, spk.len() as u8]);
    h.extend(&spk);
    h.extend(150u32.to_le_bytes());
    h.extend([0; 32]);
    h.push(0x00);
    h.extend([0x03, 0x00, sig.len() as u8]);
    h.extend(sig);
    h.push(script.len() as u8);
    h.extend(&script);
    h
}

/// A chain of signed headers from `first` to `last`, each with Merkle root `root(height)`: (height, raw, header).
pub fn chain(first: u32, last: u32, root: impl Fn(u32) -> [u8; 32]) -> Vec<(u32, Vec<u8>, Header)> {
    let mut prev = [0; 32];
    (first..=last)
        .map(|h| {
            let raw = signed_header(prev, root(h), h, &der_sig());
            let header = Header::parse(&raw).unwrap();
            prev = header.hash;
            (h, raw, header)
        })
        .collect()
}

/// Esplora's answers for a chain, by path: each height's page of block summaries (ten, descending, as
/// /blocks/:height serves them) and each block's raw header.
pub fn esplora_routes(chain: &[(u32, Vec<u8>, Header)]) -> HashMap<String, String> {
    let mut routes = HashMap::new();
    for (i, (height, raw, header)) in chain.iter().enumerate() {
        let id = display_hex(&header.hash);
        routes.insert(format!("/block/{id}/header"), hex::encode(raw));
        let page: Vec<Value> = chain[..=i]
            .iter()
            .rev()
            .take(10)
            .map(|(h, _, b)| {
                json!({ "height": h, "id": display_hex(&b.hash), "merkle_root": display_hex(&b.merkle_root) })
            })
            .collect();
        routes.insert(format!("/blocks/{height}"), json!(page).to_string());
    }
    routes
}

/// An Esplora answering `routes` by path, and 404 to anything else, as for an unknown txid.
pub fn canned_esplora(routes: HashMap<String, String>) -> Esplora {
    Esplora::with_fetch(
        "https://esplora.test/api/",
        Box::new(move |url: &str| {
            let path = url
                .strip_prefix("https://esplora.test/api")
                .expect("the base");
            Ok(routes
                .get(path)
                .map_or((404, "not found".to_owned()), |body| (200, body.clone())))
        }),
    )
}

/// The burn transaction of bridge.test.js: one input, a burn of 250,000 units of a made-up asset to `script`, and
/// an explicit fee.
pub fn burn_tx(script: &[u8]) -> Vec<u8> {
    let mut tx = hex::decode(&format!(
        "020000000001{}0000000000ffffffff02",
        "cc".repeat(32)
    ))
    .unwrap();
    tx.push(0x01);
    tx.extend([0xa5; 32]);
    tx.push(0x01);
    tx.extend(250_000u64.to_be_bytes());
    tx.extend([0x00, script.len() as u8]);
    tx.extend(script);
    tx.push(0x01);
    tx.extend([0x49; 32]);
    tx.push(0x01);
    tx.extend(300u64.to_be_bytes());
    tx.extend([0x00, 0x00]);
    tx.extend(0u32.to_le_bytes());
    tx
}

/// LiquidLightClient's batch root over `merkle_roots`, computed here on its own: keccak leaves, zero-padded to a
/// power of two, keccak parents.
pub fn batch_root(merkle_roots: &[[u8; 32]]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = merkle_roots.iter().map(|r| keccak256(r)).collect();
    level.resize(merkle_roots.len().next_power_of_two(), [0; 32]);
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|p| keccak256(&[p[0], p[1]].concat()))
            .collect();
    }
    level[0]
}

/// A burn of 250,000 units in block 5000 of a three-block chain, as the escrow and Esplora would serve it.
pub struct BurnChain {
    pub tx: Vec<u8>,
    pub txid: String,
    pub other: [u8; 32],
    pub chain: Vec<(u32, Vec<u8>, Header)>,
    pub roots: Vec<[u8; 32]>,
}

impl BurnChain {
    pub fn new(script: &[u8]) -> BurnChain {
        let tx = burn_tx(script);
        let parsed = Transaction::parse(&tx).unwrap();
        let other = sha256(&[7]);
        let burn_root = sha256d(&[other, parsed.txid].concat());
        let chain = chain(5000, 5002, |h| {
            if h == 5000 {
                burn_root
            } else {
                [(h - 5000) as u8; 32]
            }
        });
        let roots = chain.iter().map(|(_, _, h)| h.merkle_root).collect();
        BurnChain {
            tx,
            txid: display_hex(&parsed.txid),
            other,
            chain,
            roots,
        }
    }

    /// Esplora's answers about the burn, `confirmed` or not.
    pub fn routes(&self, confirmed: bool) -> HashMap<String, String> {
        let mut routes = esplora_routes(&self.chain);
        let block = display_hex(&self.chain[0].2.hash);
        let status = if confirmed {
            json!({ "confirmed": true, "block_height": 5000, "block_hash": block })
        } else {
            json!({ "confirmed": false })
        };
        routes.insert(format!("/tx/{}/status", self.txid), status.to_string());
        routes.insert(format!("/tx/{}/hex", self.txid), hex::encode(&self.tx));
        routes.insert(
            format!("/block/{block}/txids"),
            json!([display_hex(&self.other), self.txid]).to_string(),
        );
        routes
    }
}

/// An escrow stand-in: its light client's batches (first height, count, root), tip, minimum confirmations and
/// signing script hash, answering eth_call of its views.
pub struct Escrow {
    pub batches: Mutex<Vec<(u64, u64, [u8; 32])>>,
    pub tip: AtomicU64,
    pub min_confirmations: u64,
    pub signblockscript_hash: Mutex<[u8; 32]>,
}

impl Escrow {
    pub fn new(batches: Vec<(u64, u64, [u8; 32])>, tip: u64) -> Arc<Escrow> {
        Arc::new(Escrow {
            batches: Mutex::new(batches),
            tip: AtomicU64::new(tip),
            min_confirmations: 2,
            signblockscript_hash: Mutex::new(keccak256(&p2wsh(&witness_script()))),
        })
    }

    pub fn set_tip(&self, tip: u64) {
        self.tip.store(tip, Ordering::SeqCst);
    }

    pub fn call(&self, data: &str) -> Result<Vec<u8>, String> {
        let answer = |n: u64| Ok(word(n).to_vec());
        match data {
            d if d == view("batchCount()") => answer(self.batches.lock().unwrap().len() as u64),
            d if d == view("lcTipHeight()") => answer(self.tip.load(Ordering::SeqCst)),
            d if d == view("EPOCH_LENGTH()") => answer(1000),
            d if d == view("MIN_CONFIRMATIONS()") => answer(self.min_confirmations),
            d if d == view("signblockscriptHash()") => {
                Ok(self.signblockscript_hash.lock().unwrap().to_vec())
            }
            d => self
                .batches
                .lock()
                .unwrap()
                .iter()
                .enumerate()
                .find(|(i, _)| d == batch_at(*i as u64))
                .map(|(_, &(first, count, root))| [word(first), word(count), root].concat())
                .ok_or_else(|| format!("unexpected call {}", &d[..10])),
        }
    }
}

/// One server for both sides: Esplora's `routes` under /esplora, and the escrow's eth_call under /rpc.
pub fn chain_stub(routes: HashMap<String, String>, escrow: Arc<Escrow>) -> String {
    serve(move |r| {
        if r.path.starts_with("/rpc") {
            let body = r.json();
            assert_eq!(body["method"], "eth_call");
            assert_eq!(body["params"][0]["to"], ESCROW);
            return match escrow.call(body["params"][0]["data"].as_str().unwrap()) {
                Ok(data) => Reply::rpc(json!(hex::prefixed(&data))),
                Err(e) => Reply::rpc_error(200, json!({ "code": 3, "message": e })),
            };
        }
        let path = r.path.strip_prefix("/esplora").unwrap_or(&r.path);
        match routes.get(path) {
            Some(body) => Reply::text(200, body.clone()),
            None => Reply::text(404, "not found"),
        }
    })
}

// Public Liquid testnet block 2,664,000, the first block of an epoch, so its current params are in full form. Its
// signed form appends the signblock witness [empty, DER(r, s) || SIGHASH_ALL, witness script]: the 323-byte header
// Esplora serves (bridge-core/test/elements.test.js).
pub const REAL_HASH_FORM: &str = "000000a04054cb0dd4c42b4725aac4b85b1cb0d86738b09bc06789ade85088fc382c2e61e56e1c9fefbc09a6343654e694071b79bada50986eea3fba469f489439a4e1c3c9c1d26a40a6280002220020e9e4117540f7f23b3edd7c2cad660a17fb33c7959b8c37cf61d92b189133929a9600000017a91472c44f957fc011d97e3406667dca5b1c930c4026870151014202fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f02fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f00";
pub const REAL_SCRIPT: &str =
    "51210217e403ddb181872c32a0cd468c710040b2f53d8cac69f18dad07985ee37e9a7151ae";
pub const REAL_R: &str = "4b36a7485d57747c837f3d481966a896ac5ab610f9c99acce7cd1ef452d9e3db";
pub const REAL_S: &str = "71d9ccd8f1598bb17f348f198168b82627da564fc1e79a7cf15d8f99cb33f8e5";
pub const REAL_KEY_Y: &str = "0x6b3e7c7a50a5a173b577290cb7ee976809b87df20db40875ee7acdd79b81b642";

pub fn real_signed() -> String {
    format!("{REAL_HASH_FORM}03004730440220{REAL_R}0220{REAL_S}0125{REAL_SCRIPT}")
}

pub const ESCROW: &str = "0x4242424242424242424242424242424242424242";
pub const P2TR: &str = "51207878787878787878787878787878787878787878787878787878787878787878";
pub const P2WPKH: &str = "00141111111111111111111111111111111111111111";

pub fn word_hex(n: u64) -> String {
    format!("{n:064x}")
}

/// Deposit #index of `units` to `script` as BridgeDeposits emits it: index indexed; units, recipient, leaf,
/// accumulator, scriptPubKey.
pub fn deposit_log(index: u64, units: u64, script: &str) -> Value {
    let padded = format!("{script:0<width$}", width = script.len().div_ceil(64) * 64);
    let data = format!(
        "0x{}{}{}{}{}{}{padded}",
        word_hex(units),
        "ab".repeat(32),
        "cd".repeat(32),
        "ef".repeat(32),
        word_hex(160),
        word_hex(script.len() as u64 / 2)
    );
    json!({
        "address": ESCROW,
        "topics": [deposit_topic(), format!("0x{}", word_hex(index))],
        "data": data,
        "removed": false,
    })
}

/// The same deposit as the first log of block `block`.
pub fn deposit_log_at(index: u64, block: u64, units: u64, script: &str) -> Value {
    let mut log = deposit_log(index, units, script);
    log["blockNumber"] = json!(format!("0x{block:x}"));
    log["blockHash"] = json!(format!("0x{}", word_hex(block + 0xb10c)));
    log["logIndex"] = json!("0x0");
    log
}

/// A block number in a JSON-RPC filter.
pub fn block_number(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

/// The blocks of an eth_getLogs filter.
pub fn log_range(params: &Value) -> (u64, u64) {
    (
        block_number(&params[0]["fromBlock"]),
        block_number(&params[0]["toBlock"]),
    )
}

/// Deposits at a scan's first and last blocks, on both sides of a 10-block boundary, and in between.
pub fn sample_deposits() -> Vec<Value> {
    vec![
        deposit_log_at(0, 100, 100_000, P2TR),
        deposit_log_at(1, 109, 250_000, P2WPKH),
        deposit_log_at(2, 110, 300_000, P2TR),
        deposit_log_at(3, 555, 400_000, P2WPKH),
        deposit_log_at(4, 1234, 500_000, P2TR),
    ]
}

/// The sample deposits in blocks a..=b.
pub fn in_range(a: u64, b: u64) -> Vec<Value> {
    sample_deposits()
        .into_iter()
        .filter(|l| (a..=b).contains(&block_number(&l["blockNumber"])))
        .collect()
}

/// Checks that `ranges` are consecutive, each at most `max` blocks, and together exactly blocks from..=to.
pub fn assert_covers(ranges: &[(u64, u64)], from: u64, to: u64, max: u64) {
    assert_eq!(ranges.first().unwrap().0, from);
    assert_eq!(ranges.last().unwrap().1, to);
    for (i, &(a, b)) in ranges.iter().enumerate() {
        assert!(
            a <= b && b - a < max,
            "range {a}-{b} is not 1 to {max} blocks"
        );
        if i > 0 {
            assert_eq!(
                a,
                ranges[i - 1].1 + 1,
                "range {a}-{b} does not follow {}",
                ranges[i - 1].1
            );
        }
    }
}

/// An HTTP request the stub received.
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: String,
}

impl Request {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

/// What the stub answers.
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
    pub retry_after: Option<&'static str>,
}

impl Reply {
    pub fn json(status: u16, body: Value) -> Reply {
        Reply {
            status,
            content_type: "application/json",
            body: body.to_string(),
            retry_after: None,
        }
    }

    pub fn rpc(result: Value) -> Reply {
        Reply::json(200, json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
    }

    pub fn rpc_error(status: u16, error: Value) -> Reply {
        Reply::json(status, json!({ "jsonrpc": "2.0", "id": 1, "error": error }))
    }

    pub fn text(status: u16, body: impl Into<String>) -> Reply {
        Reply {
            status,
            content_type: "text/plain",
            body: body.into(),
            retry_after: None,
        }
    }

    pub fn html(status: u16, body: impl Into<String>) -> Reply {
        Reply {
            content_type: "text/html",
            ..Reply::text(status, body)
        }
    }

    pub fn with_retry_after(self, retry_after: &'static str) -> Reply {
        Reply {
            retry_after: Some(retry_after),
            ..self
        }
    }
}

fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut length = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().ok()?;
            }
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some(Request {
        method,
        path,
        body: String::from_utf8(body).ok()?,
    })
}

/// An HTTP server on 127.0.0.1 answering each request with `handler`, one connection at a time; its base URL.
pub fn serve(mut handler: impl FnMut(&Request) -> Reply + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Some(request) = read_request(&stream) else {
                continue;
            };
            let reply = handler(&request);
            let retry_after = reply
                .retry_after
                .map_or(String::new(), |r| format!("Retry-After: {r}\r\n"));
            let head = format!(
                "HTTP/1.1 {} Stub\r\ncontent-type: {}\r\ncontent-length: {}\r\n{retry_after}connection: close\r\n\r\n",
                reply.status,
                reply.content_type,
                reply.body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(reply.body.as_bytes());
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// A run of the binary: its exit code and output.
pub struct Run {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("{e}: {}{}", self.stdout, self.stderr))
    }

    pub fn stderr_lines(&self) -> Vec<&str> {
        self.stderr.trim_end().lines().collect()
    }
}

/// Runs `bridge-operator args` with SEPOLIA_EXECUTION_RPC empty unless `env` sets it.
pub fn operator(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bridge-operator"));
    command.args(args).env("SEPOLIA_EXECUTION_RPC", "");
    for (name, value) in env {
        command.env(name, value);
    }
    let out = command.output().expect("the binary runs");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// A fresh empty directory for one test.
pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bridge-operator-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}
