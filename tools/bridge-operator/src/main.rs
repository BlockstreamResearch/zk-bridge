//! bridge-operator: read-only operator commands for a deployed BridgeEscrow. Nothing here signs or sends: send the
//! printed calldata with your own wallet tooling, e.g. `cast send <escrow> <calldata>`. See USAGE.
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::process;

use serde_json::{json, Value};

use bridge_operator::abi;
use bridge_operator::bridge::{
    self, burn_script, lift_y, redeem_calldata, submit_headers_calldata, view, Address, Federation,
    REDEEM, REDEEM_TO,
};
use bridge_operator::deposits::{deposit_list, deposit_logs, Scan};
use bridge_operator::elements::{block_signatures, display_hex, Header};
use bridge_operator::esplora::Esplora;
use bridge_operator::hash::keccak256;
use bridge_operator::hex;
use bridge_operator::light_client::{next_relay_batch, redemption, Redemption};
use bridge_operator::rpc::{self, rpc_url, Clock, Kind, Paced, RpcError, SystemClock};

const USAGE: &str = "\
bridge-operator: read-only operator commands for a deployed BridgeEscrow. Nothing here signs or sends.

An RPC URL is read from --rpc, or else from SEPOLIA_EXECUTION_RPC, which keeps a URL carrying an API key out of the
process list. It is never printed or stored.

  bridge-operator federation <header hex | @file | --esplora <api>>
      the witness script, threshold and key y coordinates of a signed DynaFed header (default: the tip)
  bridge-operator checkpoint --esplora <api> --epoch-length <L>
      BridgeEscrow's Checkpoint for the last completed Liquid epoch: (L, height, hash, witnessScript, keyY)
  bridge-operator burn-script <chain id> <escrow> <recipient>
      the bare OP_RETURN scriptPubKey (BridgeEscrow.burnScriptPubKey) that redeems to <recipient> at <escrow>
  bridge-operator relay --esplora <api> [--rpc <url>] --escrow <0x...> --target <height>
      calldata of the next submitHeaders batch towards <target>; send it, wait, and run again
  bridge-operator redeem --esplora <api> [--rpc <url>] --escrow <0x...> --txid <burn txid> --vout <n> --recipient <0x...> [--to <0x...>]
      redeem() arguments and calldata, or how far the light client still has to be relayed; with --to,
      redeemTo() calldata paying <to>, which only <recipient> itself can send
  bridge-operator deposits [--rpc <url>] --escrow <0x...> --from <block> --out <deposits.json> [--to <block>] [--step <n>]
                           [--pace <ms>] [--retries <n>] [--backoff <ms>]
      the escrow's Deposit events up to the finalized block (or <to>), in index order, written as
      `assemble.py claim --deposits` takes them: [units, \"scriptPubKey hex\"]. <from> is the instance's
      ESCROW_DEPLOY_BLOCK; --step bounds each eth_getLogs range (default 2000). If the RPC refuses a range as
      too large (JSON-RPC error -32005, or a block-range or response-size limit in its words, such as
      Alchemy's free-tier 10 blocks), the reader asks again from the refused range's first block for as
      many blocks as the RPC suggests, or half as many, and keeps that smaller range to the end.
      Requests start at least --pace ms apart (default 250). A request the RPC rate-limits (HTTP 429, or
      Alchemy's compute-units-per-second error) is retried up to --retries times (default 6, at most 20) after
      --backoff ms (default 1000), doubling up to 30 s, and every rate limit doubles the pace up to 5 s.
      The file is written only once every range is read; if the retries run out, it is left untouched.

Errors go to standard error, with exit status 2.
";

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Some("help" | "--help" | "-h") = args.first().map(String::as_str) {
        print!("{USAGE}");
        return;
    }
    if let Err(message) = run(&args) {
        eprintln!("{message}");
        process::exit(2);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let (command, rest) = args.split_first().ok_or_else(usage)?;
    match command.as_str() {
        "federation" => federation(rest),
        "checkpoint" => checkpoint(rest),
        "burn-script" => burn_script_command(rest),
        "relay" => relay(rest),
        "redeem" => redeem(rest),
        "deposits" => deposits(rest),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: bridge-operator federation|checkpoint|burn-script|relay|redeem|deposits ... (bridge-operator help says more)"
        .into()
}

fn print_pretty(value: &Value) {
    // Infallible: a Value has only string keys.
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("a JSON value serializes")
    );
}

/// An argument found where an option's `--name` belongs, as an error shows it: a plain `--name`, else nothing of it,
/// since a positional or shifted argument, or `--rpc=<url>`, may be an RPC URL carrying an API key.
fn shown_flag(arg: &str) -> String {
    let plain = |name: &str| {
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    match arg.strip_prefix("--") {
        Some(name) if plain(name) => arg.to_owned(),
        _ => "(not shown, as it may be an RPC URL)".into(),
    }
}

/// `--name value` pairs, each name one the command takes.
struct Options(HashMap<String, String>);

impl Options {
    fn parse(args: &[String], known: &[&str], required: &[&str]) -> Result<Options, String> {
        let mut options = HashMap::new();
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            let (Some(name), Some(value)) = (flag.strip_prefix("--"), args.next()) else {
                return Err(format!(
                    "bad option {}: options are --name value pairs",
                    shown_flag(flag)
                ));
            };
            if !known.contains(&name) {
                return Err(format!("unknown option {}", shown_flag(flag)));
            }
            if options.insert(name.to_owned(), value.clone()).is_some() {
                return Err(format!("--{name} is given twice"));
            }
        }
        if let Some(name) = required
            .iter()
            .find(|n| options.get(**n).is_none_or(String::is_empty))
        {
            return Err(format!("missing --{name}"));
        }
        Ok(Options(options))
    }

    /// The value as given, possibly empty.
    fn raw(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// A required option's value; `parse` checked that it is there.
    fn value(&self, name: &str) -> &str {
        self.raw(name).expect("a required option")
    }

    /// A decimal integer option, if given.
    fn integer(&self, name: &str) -> Result<Option<u64>, String> {
        self.raw(name)
            .map(|v| v.parse().map_err(|_| format!("bad --{name}")))
            .transpose()
    }
}

/// The RPC URL of an Ethereum command.
fn execution_rpc(options: &Options) -> Result<String, String> {
    rpc_url(options.raw("rpc"), env::var("SEPOLIA_EXECUTION_RPC").ok())
}

/// eth_call of escrow calldata at the latest block, through `url`.
fn eth_call<'a>(
    url: &'a str,
    escrow: &'a Address,
) -> impl FnMut(&str) -> Result<Vec<u8>, String> + 'a {
    move |data: &str| {
        let params = json!([{ "to": escrow.to_string(), "data": data }, "latest"]);
        let result = rpc::call(url, "eth_call", &params).map_err(|e| e.message)?;
        result
            .as_str()
            .and_then(|r| hex::decode(r).ok())
            .ok_or_else(|| {
                "eth_call returned something other than hex data (details not shown)".into()
            })
    }
}

/// A signed header's federation, checked as LiquidLightClient checks it.
struct FederationReport {
    header: Header,
    witness_script: Vec<u8>,
    federation: Federation,
    key_y: Vec<[u8; 32]>,
}

impl FederationReport {
    fn of(header_hex: &str) -> Result<FederationReport, String> {
        let header = Header::parse(&hex::decode(header_hex)?)?;
        let (witness_script, signatures) = block_signatures(&header)?;
        let federation = bridge::federation(&witness_script)?;
        if signatures.len() != federation.threshold {
            return Err(format!(
                "header has {} signatures for a {}-of-{} script",
                signatures.len(),
                federation.threshold,
                federation.keys.len()
            ));
        }
        let key_y = federation
            .keys
            .iter()
            .map(lift_y)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FederationReport {
            header,
            witness_script,
            federation,
            key_y,
        })
    }

    fn key_y(&self) -> Vec<String> {
        self.key_y.iter().map(|y| hex::prefixed(y)).collect()
    }

    fn json(&self) -> Value {
        let h = &self.header;
        json!({
            "height": h.height,
            "block_hash_display": display_hex(&h.hash),
            "block_hash_internal": hex::prefixed(&h.hash),
            "signblockscript": hex::encode(&h.signblockscript),
            "signblockscript_keccak": hex::prefixed(&keccak256(&h.signblockscript)),
            "witness_script": hex::prefixed(&self.witness_script),
            "threshold": self.federation.threshold,
            "keys": self.federation.keys.iter().map(|k| hex::encode(k)).collect::<Vec<_>>(),
            "key_y": self.key_y(),
        })
    }
}

fn federation(args: &[String]) -> Result<(), String> {
    let header = match args {
        [flag, api] if flag == "--esplora" => Esplora::new(api).tip_header()?,
        [file] if file.starts_with('@') => {
            let path = &file[1..];
            fs::read_to_string(path)
                .map_err(|e| format!("cannot read {path}: {e}"))?
                .trim()
                .to_owned()
        }
        [header] if !header.starts_with("--") => header.clone(),
        _ => return Err("federation <header hex | @file | --esplora <api>>".into()),
    };
    print_pretty(&FederationReport::of(&header)?.json());
    Ok(())
}

fn checkpoint(args: &[String]) -> Result<(), String> {
    let o = Options::parse(
        args,
        &["esplora", "epoch-length"],
        &["esplora", "epoch-length"],
    )?;
    let length = o
        .integer("epoch-length")?
        .filter(|&l| l > 0)
        .ok_or("bad --epoch-length")?;
    let esplora = Esplora::new(o.value("esplora"));
    let tip = esplora.tip_height()?;
    // The last epoch boundary whose successor block exists, so the next epoch's signing script is read from a
    // header actually signed in that epoch rather than predicted.
    let height = (tip / length * length)
        .checked_sub(1)
        .ok_or("no completed epoch yet")?;
    let headers = esplora.headers(height, height + 1)?;
    // Two headers: `headers` returns one per height or fails.
    let checkpoint = Header::parse(&hex::decode(&headers[0])?)?;
    let next = FederationReport::of(&headers[1])?;
    print_pretty(&json!({
        "note": "BridgeEscrow(bridgeAsset, minConfirmations, maxRelayLag, admission, (epochLength, height, hash, witnessScript, keyY)); hash is internal byte order",
        "epochLength": length,
        "height": height,
        "hash": hex::prefixed(&checkpoint.hash),
        "witnessScript": hex::prefixed(&next.witness_script),
        "keyY": next.key_y(),
        "checkpoint_hash_display": display_hex(&checkpoint.hash),
        "next_epoch_threshold": next.federation.threshold,
    }));
    Ok(())
}

/// A chain id, decimal or `0x` hex.
fn chain_id(text: &str) -> Result<u64, String> {
    let text = text.trim();
    match text.strip_prefix("0x") {
        Some(digits) => u64::from_str_radix(digits, 16),
        None => text.parse(),
    }
    .map_err(|_| "a chain id is an integer below 2^64".into())
}

fn burn_script_command(args: &[String]) -> Result<(), String> {
    let [chain, escrow, recipient] = args else {
        return Err("burn-script <chain id> <escrow> <recipient>".into());
    };
    let chain = chain_id(chain)?;
    let escrow = Address::parse(escrow)?;
    let recipient = Address::parse(recipient)?;
    print_pretty(&json!({
        "scriptPubKey": hex::encode(&burn_script(chain, &escrow, &recipient)),
        "chain_id": chain.to_string(),
        "escrow": escrow.to_string(),
        "recipient": recipient.to_string(),
        "note": "burn with one explicit output of the bridge asset paying exactly this script; compare it with the escrow's burnScriptPubKey(recipient)",
    }));
    Ok(())
}

fn relay(args: &[String]) -> Result<(), String> {
    let o = Options::parse(
        args,
        &["esplora", "rpc", "escrow", "target"],
        &["esplora", "escrow", "target"],
    )?;
    let url = execution_rpc(&o)?;
    let escrow = Address::parse(o.value("escrow"))?;
    let target = o.integer("target")?.expect("a required option");
    let mut call = eth_call(&url, &escrow);
    match next_relay_batch(&Esplora::new(o.value("esplora")), &mut call, target)? {
        None => println!(
            "{}",
            json!({ "relayed": true, "note": "the light client already covers the target" })
        ),
        Some(batch) => print_pretty(&json!({
            "first_height": batch.first_height,
            "count": batch.headers.len(),
            "carries_new_keys": !batch.witness_script.is_empty(),
            "calldata": submit_headers_calldata(&batch),
            "note": "send this, wait for it to confirm, then run relay again",
        })),
    }
    Ok(())
}

fn hashes(hs: &[[u8; 32]]) -> Vec<String> {
    hs.iter().map(|h| hex::prefixed(h)).collect()
}

fn redeem(args: &[String]) -> Result<(), String> {
    let o = Options::parse(
        args,
        &[
            "esplora",
            "rpc",
            "escrow",
            "txid",
            "vout",
            "recipient",
            "to",
        ],
        &["esplora", "escrow", "txid", "vout", "recipient"],
    )?;
    let url = execution_rpc(&o)?;
    let escrow = Address::parse(o.value("escrow"))?;
    let recipient = Address::parse(o.value("recipient"))?;
    let payee = o
        .raw("to")
        .filter(|to| !to.is_empty())
        .map(Address::parse)
        .transpose()?;
    let txid = o.value("txid").to_ascii_lowercase();
    if txid.len() != 64 || !txid.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("a txid is 64 hex characters".into());
    }
    let vout = o
        .integer("vout")?
        .and_then(|v| u32::try_from(v).ok())
        .ok_or("bad --vout")?;

    let mut call = eth_call(&url, &escrow);
    let report = match redemption(&Esplora::new(o.value("esplora")), &mut call, &txid, vout)? {
        Redemption::Unconfirmed => json!({ "state": "unconfirmed" }),
        Redemption::AwaitingRelay {
            height,
            tip,
            needed,
        } => json!({ "state": "awaiting-relay", "height": height, "tip": tip, "needed": needed }),
        Redemption::Ready {
            height,
            tip,
            burn,
            block,
        } => {
            let calldata = match &payee {
                Some(to) => redeem_calldata(REDEEM_TO, to, &burn, &block),
                None => redeem_calldata(REDEEM, &recipient, &burn, &block),
            };
            let mut report = json!({
                "height": height,
                "light_client_tip": tip,
                "recipient": recipient.to_string(),
                "pay_to": payee.unwrap_or(recipient).to_string(),
                "burn": {
                    "transaction": hex::prefixed(&burn.transaction),
                    "vout": burn.vout,
                    "branch": hashes(&burn.branch),
                    "position": burn.position,
                },
                "ref": { "batch": block.batch, "index": block.index, "path": hashes(&block.path) },
                "calldata": calldata,
            });
            if payee.is_some() {
                report["note"] = json!("redeemTo: send this from the recipient account itself; from any other sender it reverts WrongBurnScript");
            }
            report
        }
    };
    print_pretty(&report);
    Ok(())
}

/// The escrow's deposits through block `to`, or the finalized block: its number and the deposit list.
fn read_deposits<F>(
    paced: &mut Paced<F>,
    escrow: &Address,
    (from, to, step): (u64, Option<u64>, u64),
    log: &dyn Fn(&str),
) -> Result<(u64, Vec<(u64, String)>), RpcError>
where
    F: FnMut(&str, &Value) -> Result<Value, RpcError>,
{
    // Claims cover only proven deposits, and a proof covers only finalized blocks: by default stop at finality.
    let to = match to {
        Some(to) => to,
        None => {
            let block = paced.call(
                "eth_getBlockByNumber",
                &json!(["finalized", false]),
                "the finalized block",
            )?;
            block
                .get("number")
                .and_then(Value::as_str)
                .and_then(|n| n.strip_prefix("0x"))
                .filter(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_hexdigit()))
                .and_then(|n| u64::from_str_radix(n, 16).ok())
                .ok_or_else(|| {
                    RpcError::failed(
                        "the Ethereum RPC returned an invalid finalized block number (details not shown)",
                    )
                })?
        }
    };
    // An explicit --to was checked against --from already.
    if from > to {
        return Err(RpcError::failed(format!(
            "the finalized block is {to}, before --from {from}: no block to read yet"
        )));
    }
    let scan = Scan {
        escrow: *escrow,
        from,
        to,
        step,
        progress_every: 100,
    };
    let logs = deposit_logs(
        &mut |method: &str, params: &Value, what: &str| paced.call(method, params, what),
        &scan,
        log,
    )?;
    let params =
        json!([{ "to": escrow.to_string(), "data": view("depositCount()") }, format!("0x{to:x}")]);
    let count = paced
        .call("eth_call", &params, "depositCount()")?
        .as_str()
        .and_then(|c| hex::decode(c).ok())
        .and_then(|data| abi::uint(&data).ok())
        .ok_or_else(|| {
            RpcError::failed(
                "depositCount() returned something other than a count (details not shown)",
            )
        })?;
    let list = deposit_list(&logs, escrow, count).map_err(RpcError::failed)?;
    Ok((to, list))
}

/// Writes `contents` to `path` whole or not at all: through a temporary file beside it, renamed over it.
fn write_atomically(path: &str, contents: &str) -> Result<(), String> {
    let tmp = format!("{path}.{}.tmp", process::id());
    File::create(&tmp)
        .and_then(|mut f| {
            f.write_all(contents.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path))
        .map_err(|e| {
            // Best effort: the error below is what matters.
            let _ = fs::remove_file(&tmp);
            format!("cannot write {path}: {e}")
        })
}

fn deposits(args: &[String]) -> Result<(), String> {
    let o = Options::parse(
        args,
        &[
            "rpc", "escrow", "from", "out", "to", "step", "pace", "retries", "backoff",
        ],
        &["escrow", "from", "out"],
    )?;
    let url = execution_rpc(&o)?;
    let escrow = Address::parse(o.value("escrow"))?;
    let out = o.value("out");

    let pacing = |name, default| match o.integer(name) {
        Ok(value) => Ok(value.unwrap_or(default)),
        Err(_) => Err("bad --pace, --retries or --backoff".to_owned()),
    };
    let pace = pacing("pace", 250)?;
    let backoff = pacing("backoff", 1000)?;
    let retries = u32::try_from(pacing("retries", 6)?)
        .ok()
        .filter(|&r| r <= 20)
        .ok_or("bad --pace, --retries or --backoff")?;
    let range = |name| {
        o.integer(name)
            .map_err(|_| "bad --from, --to or --step".to_owned())
    };
    let from = range("from")?.expect("a required option");
    let to = range("to")?;
    let step = range("step")?.unwrap_or(2000);
    if step == 0 || to.is_some_and(|to| from > to) {
        return Err("bad --from, --to or --step".into());
    }

    let clock = SystemClock::new();
    let log = |line: &str| eprintln!("{line}");
    let transport = |method: &str, params: &Value| rpc::call(&url, method, params);
    let mut paced = Paced::new(
        transport,
        &clock as &dyn Clock,
        &log,
        pace,
        retries,
        backoff,
    );
    let (to, list) = read_deposits(&mut paced, &escrow, (from, to, step), &log).map_err(|e| match e.kind {
        Kind::Exhausted => format!(
            "{}. Nothing was written to {out}; rerun once the provider's limit has reset, or with a larger --pace",
            e.message
        ),
        _ => e.message,
    })?;

    // A whole list or none: a crash mid-write leaves the temporary file, never a truncated list.
    // Infallible: integers and strings serialize.
    let text = serde_json::to_string(&list).expect("a list serializes") + "\n";
    write_atomically(out, &text)?;
    print_pretty(&json!({
        "to_block": to,
        "deposits": list.len(),
        "out": out,
        "note": "assemble.py claim pays one of these not yet claimed, and refuses the list unless its proven prefix gives the state's accumulator",
    }));
    Ok(())
}
