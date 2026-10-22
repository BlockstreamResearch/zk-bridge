//! sg16-testnet-claim: the claim leaf (compiled by the zk-bridge crate, `claim::source`) as the sibling of the
//! sg16 update leaf in the testnet state tree P2TR(NUMS, {{update leaf, claim leaf}, state leaf}).
//!
//!   sg16-testnet-claim cmr <manifest.json>
//!       the claim leaf's CMR for the manifest's bridge parameters (entropy, public token blindings, escrow
//!       DOMAIN), with the token commitments and asset it compiles in, for comparison with the update leaf
//!   sg16-testnet-claim deposits <manifest.json> <state.json> <deposits.json>
//!       the deposits the state's accumulator proves, each with its units, script and whether the state's claimed
//!       tree has paid it; `unclaimed` lists the indices `claim --deposit` accepts, in deposit order
//!   sg16-testnet-claim claim <manifest.json> <state.json> <deposits.json> <state tx.hex> <state vout>
//!                            <fee tx.hex> <fee vout> <out.hex> --deposit <index> [--local-test]
//!       mint deposit <index> of the escrow accumulator committed in the state, any proven deposit the state has not
//!       paid, in any order: inputs [state, fee], outputs [successor (slot <index> of the claimed tree set),
//!       explicit mint to the deposit's script, explicit fee].  There is no default deposit.  Input 0 is satisfied
//!       against the real transaction, encoded, decoded and executed; input 1 (fee) is left unsigned.  The report's
//!       `successor_state` is the record of output 0, in the form of the given record.
//!
//!   deposits.json lists the Deposit events in escrow order: [[units, "scriptPubKey hex"], ...], each paid at that
//!   script, whose SHA-256 the deposit committed.  It may run past the block the state proved: the prefix that
//!   reproduces the state's accumulator is used.  state.json is a state record (`load_state`), with or without the
//!   light-client store behind its lc, whose `claimed` lists the paid deposit indices strictly ascending and whose
//!   `claimed_root` is their claimed tree's root.
//!   sg16-testnet-claim synthetic-prevs <manifest.json> <state.json> <phase> <fee value> <state out.hex> <fee out.hex>
//!       SYNTHETIC previous transactions (fictional inputs) holding a state UTXO and an explicit fee output, so
//!       the claim path can be exercised locally; never valid on any chain
//!
//! The update leaf is not compiled here: its CMR comes from the manifest, and the claim leaf takes its hash as
//! SIBLING, authenticated on chain by the control block.  Failed gates print {"ok": false, ...} and exit 3.

use serde_json::{json, Value as Json};
use simplicity::elements::{
    self,
    confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor},
    encode::{deserialize, serialize, serialize_hex},
    hashes::Hash,
    secp256k1_zkp::{
        Generator, Secp256k1, SecretKey, SurjectionProof, Tweak, XOnlyPublicKey, ZERO_TWEAK,
    },
    taproot::{TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    AssetId, AssetIssuance, BlockHash, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, Txid,
};
use simplicity::jet::{
    elements::{ElementsEnv, ElementsUtxo},
    Elements,
};
use simplicity::{BitIter, BitMachine, RedeemNode};
use simplicityhl::{
    ast::ElementsJetHinter, Arguments, CompiledProgram, TemplateProgramWitness, Value as HlValue,
    WitnessNameToValueMap, WitnessValues,
};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};
use zk_bridge::claim::{
    self as leaf, check_params, complete_root, path_value, source, state_hash, u256, u64_value,
    ClaimedTree, DepositTree, Params, State, NUMS, TREE_DEPTH,
};
use zk_bridge::crypto::sha;

const SCHEMA: &str = "liquid-bridge-poc/manifest";
/// Domain tag of the light-client commitment, as sg16-bridge-core's LC_TAG.
const LC_TAG: &[u8] = b"liquid-bridge-poc/lc";

// Display (reversed) hex, as tools/sg16/bridge-guest/testnet/tx and pins.py pin them.
const TESTNET_GENESIS: &str = "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1";
const TESTNET_LBTC: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

const STANDARD_WEIGHT: usize = 400_000;
const MIN_RELAY_SAT_PER_KVB: u64 = 100;
const MIN_UNITS: u64 = 100_000;
const MAX_UNITS: u64 = 2_100_000_000_000_000;
const USAGE: &str = "usage: sg16-testnet-claim cmr|deposits|claim|synthetic-prevs ... \
    (claim needs --deposit <index>; see the source header)";

#[derive(Default)]
struct Gates {
    passed: Vec<String>,
}

impl Gates {
    fn need(&mut self, ok: bool, name: &str) -> Result<(), String> {
        if ok {
            self.passed.push(name.to_string());
            Ok(())
        } else {
            Err(name.to_string())
        }
    }
}

type Report = Result<Json, String>;

fn secp() -> Secp256k1<elements::secp256k1_zkp::All> {
    Secp256k1::new()
}

fn nums() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&hex::decode(NUMS).unwrap()).unwrap()
}

fn read_json(path: &str) -> Result<Json, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {}", path, e))
}

fn word(j: &Json, what: &str) -> Result<[u8; 32], String> {
    let s = j.as_str().ok_or_else(|| format!("{} missing", what))?;
    let v =
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| format!("{}: {}", what, e))?;
    v.try_into().map_err(|_| format!("{}: not 32 bytes", what))
}

fn num(j: &Json, what: &str) -> Result<u64, String> {
    j.as_u64().ok_or_else(|| format!("{} missing", what))
}

fn parse<T: std::str::FromStr>(s: &str, what: &str) -> Result<T, String> {
    s.parse()
        .map_err(|_| format!("{}: cannot parse {:?}", what, s))
}

fn fee_floor(weight: usize) -> u64 {
    ((weight as u64 + 3) / 4 * MIN_RELAY_SAT_PER_KVB + 999) / 1000
}

/// Internal byte order of a displayed 32-byte hash constant of this file.
fn internal(display: &str) -> [u8; 32] {
    let mut b: [u8; 32] = hex::decode(display)
        .ok()
        .and_then(|v| v.try_into().ok())
        .expect("a 64-digit hex constant of this file");
    b.reverse();
    b
}

/// The bridge parameters of the manifest in the claim crate's form.
fn params_of(m: &Json) -> Result<Params, String> {
    let hc = &m["harness_config"];
    let p = Params {
        liquid_genesis: word(&hc["genesis"], "harness_config.genesis")?,
        entropy: word(&hc["entropy"], "harness_config.entropy")?,
        fee_asset: AssetId::from_byte_array(word(&hc["fee_asset"], "harness_config.fee_asset")?),
        deposit_domain: word(&m["sepolia"]["deposit_domain"], "sepolia.deposit_domain")?,
        token_blinding: [
            word(&hc["abf_a"], "harness_config.abf_a")?,
            word(&hc["abf_b"], "harness_config.abf_b")?,
        ],
    };
    check_params(&p).map_err(str::to_owned)?;
    Ok(p)
}

fn compile_claim(p: &Params) -> Result<(String, CompiledProgram), String> {
    let src = source(p);
    let program = CompiledProgram::new(
        src.clone(),
        Arguments::default(),
        false,
        Box::new(ElementsJetHinter::new()),
    )
    .map_err(|e| e.to_string())?;
    Ok((src, program))
}

/// The deposits a state has paid: the claimed set, and its tree, whose root the state commits.
#[derive(Clone, Debug)]
struct Claimed {
    indices: BTreeSet<u64>,
    tree: ClaimedTree,
}

impl Claimed {
    fn with(&self, index: u64) -> Claimed {
        let mut indices = self.indices.clone();
        indices.insert(index);
        Claimed {
            indices,
            tree: self.tree.with(index),
        }
    }

    fn list(&self) -> Vec<u64> {
        self.indices.iter().copied().collect()
    }
}

/// The claimed set of a state record: `claimed`, the paid deposit indices, strictly ascending and below 2^32, and
/// `claimed_root`, which must be their tree's root. Other shapes are refused.
fn claimed_of(j: &Json) -> Result<Claimed, String> {
    let list = j["claimed"]
        .as_array()
        .ok_or("state.claimed: a list of deposit indices")?;
    let mut indices = Vec::with_capacity(list.len());
    for i in list {
        let i = i
            .as_u64()
            .ok_or("state.claimed: each index is an integer")?;
        if i >> TREE_DEPTH != 0 {
            return Err(format!("state.claimed: {} is outside the claimed tree", i));
        }
        indices.push(i);
    }
    if indices.windows(2).any(|w| w[0] >= w[1]) {
        return Err("state.claimed: indices strictly ascending, each listed once".into());
    }
    let tree = indices.iter().fold(ClaimedTree::new(), |t, &i| t.with(i));
    if word(&j["claimed_root"], "state.claimed_root")? != tree.root() {
        return Err("state.claimed_root is not the claimed tree's root of state.claimed".into());
    }
    Ok(Claimed {
        indices: indices.into_iter().collect(),
        tree,
    })
}

/// lc = SHA256(SHA256(LC_TAG) || be64(head) || header || committee) of a record that has the store (from
/// `assemble.py update`); a record without it gives lc itself (`assemble.py recover`: Liquid carries the lc, not
/// its preimage, and a claim needs only the lc).  Either way the spent output must be this state's, which `claim`
/// checks.  Also the claimed tree (`claimed_of`) and the record itself, for the successor's.
fn load_state(path: &str) -> Result<(State, Claimed, Json), String> {
    state_from_json(&read_json(path)?)
}

fn state_from_json(j: &Json) -> Result<(State, Claimed, Json), String> {
    let lc = if j.get("header").is_none() && j.get("committee").is_none() {
        word(&j["lc"], "state.lc")?
    } else {
        let head = num(&j["head"], "state.head")?;
        let (header, committee) = (
            word(&j["header"], "state.header")?,
            word(&j["committee"], "state.committee")?,
        );
        let lc = sha(&[
            &sha(LC_TAG)[..],
            &head.to_be_bytes()[..],
            &header[..],
            &committee[..],
        ]
        .concat());
        if j.get("lc").is_some() && word(&j["lc"], "state.lc")? != lc {
            return Err("state.lc is not lc(head, header, committee)".into());
        }
        lc
    };
    let claimed = claimed_of(&j)?;
    let state = State {
        lc,
        acc: word(&j["acc"], "state.acc")?,
        claimed_root: claimed.tree.root(),
    };
    Ok((state, claimed, j.clone()))
}

/// P2TR(NUMS, {{update, claim}, state}) with the sg16 update leaf.
fn state_info(update_cmr: &[u8; 32], claim_cmr: &[u8; 32], s: &State) -> TaprootSpendInfo {
    let script = |b: &[u8]| Script::from(b.to_vec());
    TaprootBuilder::new()
        .add_leaf_with_ver(2, script(&update_cmr[..]), leaf::leaf_version())
        .unwrap()
        .add_leaf_with_ver(2, script(&claim_cmr[..]), leaf::leaf_version())
        .unwrap()
        .add_leaf_with_ver(1, script(&state_hash(s)[..]), leaf::leaf_version())
        .unwrap()
        .finalize(&secp(), nums())
        .unwrap()
}

fn explicit(asset: AssetId, value: u64, script: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: script,
        witness: Default::default(),
    }
}

fn token_domain(p: &Params, phase: usize) -> (Generator, elements::secp256k1_zkp::Tag, Tweak) {
    (
        p.token_asset(phase).commitment().unwrap(),
        p.token().into_tag(),
        Tweak::from_slice(&p.token_blinding[phase]).unwrap(),
    )
}

fn explicit_domain(asset: AssetId) -> (Generator, elements::secp256k1_zkp::Tag, Tweak) {
    (
        Generator::new_unblinded(&secp(), asset.into_tag()),
        asset.into_tag(),
        ZERO_TWEAK,
    )
}

/// The successor token output with the other phase's public blinding, as the claim crate's `Bridge::successor`.
fn successor(
    p: &Params,
    spk: Script,
    next_phase: usize,
    domain: &[(Generator, elements::secp256k1_zkp::Tag, Tweak)],
) -> TxOut {
    let bf = p.token_blinding[next_phase];
    let mut out = TxOut {
        asset: p.token_asset(next_phase),
        value: p.token_value(),
        nonce: Nonce::Null,
        script_pubkey: spk,
        witness: Default::default(),
    };
    let mut rng = elements::secp256k1_zkp::rand::thread_rng();
    out.witness.surjection_proof = Some(Box::new(
        SurjectionProof::new(
            &secp(),
            &mut rng,
            p.token().into_tag(),
            Tweak::from_slice(&bf).unwrap(),
            domain,
        )
        .unwrap(),
    ));
    let vbf = ValueBlindingFactor::from_slice(
        &SecretKey::from_slice(&bf).unwrap().negate().secret_bytes(),
    )
    .unwrap();
    let msg = elements::RangeProofMessage {
        asset: p.token(),
        bf: AssetBlindingFactor::from_slice(&bf).unwrap(),
    };
    let (value, range) = Value::Explicit(1)
        .blind_with_shared_secret(
            &secp(),
            vbf,
            SecretKey::from_slice(&[9; 32]).unwrap(),
            &out.script_pubkey,
            &msg,
        )
        .unwrap();
    assert_eq!(value, out.value, "constant token value commitment");
    out.witness.rangeproof = Some(Box::new(range));
    out
}

fn parts(ser: &[u8]) -> Json {
    json!({"bit": ser[0] & 1, "x": hex::encode(&ser[1..])})
}

fn cmr_cmd(a: &[String], g: &mut Gates) -> Report {
    let m = read_json(&a[0])?;
    g.need(m["schema"] == SCHEMA, "manifest schema")?;
    let p = params_of(&m)?;
    let (src, program) = compile_claim(&p)?;
    g.need(
        true,
        "claim leaf compiles (SimplicityHL 0.7.2, stock Elements jets)",
    )?;
    let cmr = program.commit().cmr();
    Ok(json!({
        "cmr": hex::encode(cmr.as_ref().to_vec()), "source_sha256": hex::encode(sha(src.as_bytes())),
        "token_a": parts(&serialize(&p.token_asset(0))), "token_b": parts(&serialize(&p.token_asset(1))),
        "token_value": parts(&serialize(&p.token_value())),
        "asset": hex::encode(&serialize(&Asset::Explicit(p.asset()))[1..]),
        "token": hex::encode(&serialize(&Asset::Explicit(p.token()))[1..]),
        "entropy": hex::encode(p.entropy), "deposit_domain": hex::encode(p.deposit_domain),
    }))
}

/// The bridge parameters and leaves of a manifest the claim commands accept.
struct Deployment {
    params: Params,
    program: CompiledProgram,
    cmr: simplicity::Cmr,
    claim_cmr: [u8; 32],
    update_cmr: [u8; 32],
    deployable: bool,
}

fn deployment(m: &Json, local_test: bool, g: &mut Gates) -> Result<Deployment, String> {
    g.need(
        m["schema"] == SCHEMA && m["liquid"]["network"] == "liquidtestnet",
        "manifest schema and Liquid testnet network",
    )?;
    g.need(
        m["deployable"] == true || local_test,
        "manifest is deployable (real bootstrap outpoint, real-key update leaf, all gates passed)",
    )?;
    let p = params_of(m)?;
    g.need(
        p.liquid_genesis == internal(TESTNET_GENESIS),
        "genesis = Liquid testnet genesis block",
    )?;
    g.need(
        p.fee_asset == AssetId::from_byte_array(internal(TESTNET_LBTC)),
        "fee asset = Liquid testnet L-BTC",
    )?;
    let (_, program) = compile_claim(&p)?;
    let cmr = program.commit().cmr();
    let claim_cmr = word(&m["claim_leaf"]["cmr"], "claim_leaf.cmr")?;
    let update_cmr = word(&m["update_leaf"]["cmr"], "update_leaf.cmr")?;
    g.need(
        cmr.as_ref().to_vec() == claim_cmr.to_vec(),
        "compiled claim leaf CMR = manifest claim CMR",
    )?;
    Ok(Deployment {
        params: p,
        program,
        cmr,
        claim_cmr,
        update_cmr,
        deployable: m["deployable"] == true,
    })
}

/// The deposits a state proves: the tree of the prefix of the event list that reproduces its accumulator, and each
/// deposit's output script.
struct Proven {
    tree: DepositTree,
    scripts: Vec<Script>,
    listed: usize,
}

fn proven(
    p: &Params,
    old: &State,
    claimed: &Claimed,
    deposits: &str,
    g: &mut Gates,
) -> Result<Proven, String> {
    proven_from_json(p, old, claimed, &read_json(deposits)?, g)
}

fn proven_from_json(
    p: &Params,
    old: &State,
    claimed: &Claimed,
    deposits: &Json,
    g: &mut Gates,
) -> Result<Proven, String> {
    // Each event: units, the committed recipient and the output script the claim pays it with.
    let mut events: Vec<(u64, [u8; 32], Script)> = Vec::new();
    for d in deposits
        .as_array()
        .ok_or("deposits.json: a list of [units, recipient]")?
    {
        let units = num(&d[0], "deposit units")?;
        // The event's scriptPubKey; the committed recipient is its SHA-256.
        let s = d[1].as_str().ok_or("deposit scriptPubKey missing")?;
        let script = hex::decode(s.strip_prefix("0x").unwrap_or(s))
            .map_err(|e| format!("deposit scriptPubKey: {}", e))?;
        g.need(
            leaf::is_standard_recipient(&script),
            "deposit scripts are BridgeDeposits recipients (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)",
        )?;
        events.push((units, sha(&script), Script::from(script)));
    }
    // The escrow rejects any other amount, so an event outside the bounds means the list is not its events.
    g.need(
        events
            .iter()
            .all(|(u, _, _)| (MIN_UNITS..=MAX_UNITS).contains(u)),
        "deposit units within the escrow's bounds",
    )?;
    // Deposits after the block the state proved extend the list; the accumulator commits to its count, so at
    // most one prefix reproduces it.
    let mut prefix = DepositTree::new(p.deposit_domain);
    let mut tree = (prefix.accumulator() == old.acc).then(|| prefix.clone());
    for (units, recipient, _) in &events {
        prefix.push(*units, *recipient);
        if prefix.accumulator() == old.acc {
            tree = Some(prefix.clone());
        }
    }
    g.need(
        tree.is_some(),
        "a prefix of the deposit list reproduces the state's proven accumulator",
    )?;
    let tree = tree.unwrap_or_else(|| DepositTree::new(p.deposit_domain));
    // The leaf sets only slots below the proven count, and the accumulator only grows, so a state that claims a
    // deposit the accumulator does not prove is not a state of this chain.
    g.need(
        claimed.indices.iter().all(|&i| i < tree.count()),
        "every claimed index is a deposit the state's accumulator proves",
    )?;
    let scripts = events[..tree.count() as usize]
        .iter()
        .map(|(_, _, s)| s.clone())
        .collect();
    Ok(Proven {
        tree,
        scripts,
        listed: events.len(),
    })
}

fn deposits_cmd(a: &[String], g: &mut Gates) -> Report {
    let m = read_json(&a[0])?;
    g.need(m["schema"] == SCHEMA, "manifest schema")?;
    let p = params_of(&m)?;
    let (old, claimed, _) = load_state(&a[1])?;
    let pr = proven(&p, &old, &claimed, &a[2], g)?;
    let count = pr.tree.count();
    let deposits: Vec<Json> = (0..count)
        .map(|i| {
            let (units, recipient) = pr.tree.deposits[i as usize];
            json!({
                "index": i, "units": units, "recipient": hex::encode(recipient),
                "script_pubkey": hex::encode(pr.scripts[i as usize].as_bytes()), "claimed": claimed.indices.contains(&i),
            })
        })
        .collect();
    let unclaimed: Vec<u64> = (0..count)
        .filter(|i| !claimed.indices.contains(i))
        .collect();
    Ok(json!({
        "proven": count, "listed": pr.listed, "claimed": claimed.list(),
        "claimed_root": hex::encode(old.claimed_root), "unclaimed": unclaimed,
        "complete": old.claimed_root == complete_root(count), "deposits": deposits,
    }))
}

/// One claim spend of `index`, built and run the way a node would.  The membership gates are the caller's: given a
/// claimed index, the leaf itself must refuse the spend.
struct Built {
    tx: Transaction,
    new: State,
    weight: usize,
    cost: String,
    program_bytes: usize,
    witness_bytes: usize,
    cells: usize,
}

#[allow(clippy::too_many_arguments)]
fn spend(
    d: &Deployment,
    old: &State,
    claimed: &Claimed,
    tree: &DepositTree,
    index: u64,
    pay_to: Script,
    state_in: (OutPoint, TxOut),
    fee_in: (OutPoint, TxOut, u64),
    phase: usize,
    g: &mut Gates,
) -> Result<Built, String> {
    let p = &d.params;
    let (units, recipient) = tree.deposits[index as usize];
    let new = State {
        claimed_root: claimed.tree.with(index).root(),
        ..*old
    };
    let info = state_info(&d.update_cmr, &d.claim_cmr, old);
    let new_info = state_info(&d.update_cmr, &d.claim_cmr, &new);
    let mut input0 = TxIn {
        previous_output: state_in.0,
        ..TxIn::default()
    };
    // reissuance: the nonce is the spent token's public blinding factor
    input0.asset_issuance = AssetIssuance {
        asset_blinding_nonce: Tweak::from_slice(&p.token_blinding[phase]).unwrap(),
        asset_entropy: p.entropy,
        amount: Value::Explicit(units),
        inflation_keys: Value::Null,
    };
    let input1 = TxIn {
        previous_output: fee_in.0,
        ..TxIn::default()
    };
    let domain = [
        token_domain(p, phase),
        explicit_domain(p.asset()),
        explicit_domain(p.fee_asset),
    ];
    let fee = fee_in.2;
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input0, input1],
        output: vec![
            successor(
                p,
                Script::new_v1_p2tr_tweaked(new_info.output_key()),
                1 - phase,
                &domain,
            ),
            explicit(p.asset(), units, pay_to),
            explicit(p.fee_asset, fee, Script::new()),
        ],
    };
    let spent = vec![state_in.1.clone(), fee_in.1];
    tx.verify_tx_amt_proofs(&secp(), &spent)
        .map_err(|e| format!("Elements amount proofs: {:?}", e))?;
    g.need(
        true,
        "Elements amount, surjection and range proofs verify (rust-elements)",
    )?;
    let control = info
        .control_block(&(Script::from(d.claim_cmr.to_vec()), leaf::leaf_version()))
        .expect("claim control block");
    let key = XOnlyPublicKey::from_slice(&state_in.1.script_pubkey.as_bytes()[2..])
        .map_err(|_| "state output key".to_string())?;
    g.need(
        control.verify_taproot_commitment(
            &secp(),
            &elements::schnorr::TweakedPublicKey::new(key),
            &Script::from(d.claim_cmr.to_vec()),
        ),
        "claim control block commits to the state output key",
    )?;
    let sibling =
        TapLeafHash::from_script(&Script::from(d.update_cmr.to_vec()), leaf::leaf_version())
            .to_byte_array();
    let mut witness: HashMap<&'static str, HlValue> = HashMap::new();
    witness.insert("LC", u256(old.lc));
    witness.insert("ACC", u256(old.acc));
    witness.insert("CLAIMED_ROOT", u256(old.claimed_root));
    witness.insert("SIBLING", u256(sibling));
    witness.insert("TREE_ROOT", u256(tree.root()));
    witness.insert("COUNT", u64_value(tree.count()));
    witness.insert("INDEX", u64_value(index));
    witness.insert("RECIPIENT", u256(recipient));
    witness.insert("PATH", path_value(&tree.branch(index)));
    witness.insert("CLAIMED_PATH", path_value(&claimed.tree.branch(index)));
    let env = ElementsEnv::new(
        Arc::new(tx.clone()),
        spent.iter().cloned().map(ElementsUtxo::from).collect(),
        0,
        d.cmr,
        control.clone(),
        None,
        BlockHash::from_byte_array(p.liquid_genesis),
    );
    let map = witness
        .iter()
        .map(|(k, v)| (TemplateProgramWitness::witness_from_str(*k), v.clone()))
        .collect();
    let satisfied = d
        .program
        .satisfy_with_env(WitnessValues::from_map(map), Some(&env))
        .map_err(|e| format!("claim leaf rejected the spend: {}", e))?;
    let (code, wit) = satisfied.redeem().to_vec_with_witness();
    let decoded = RedeemNode::decode::<_, _, Elements>(
        BitIter::from(code.as_slice()),
        BitIter::from(wit.as_slice()),
    )
    .map_err(|e| e.to_string())?;
    g.need(decoded.cmr() == d.cmr, "CMR unchanged by encoding")?;
    BitMachine::for_program(&decoded)
        .map_err(|e| e.to_string())?
        .exec(&decoded, &env)
        .map_err(|e| format!("claim leaf execution: {}", e))?;
    g.need(
        true,
        "claim leaf satisfied, encoded, decoded and executed (vendored simplicity-lang 0.8)",
    )?;
    let stack = vec![
        wit.clone(),
        code.clone(),
        d.cmr.as_ref().to_vec(),
        control.serialize(),
    ];
    let bounds = decoded.bounds();
    g.need(
        bounds.cost.is_budget_valid(&stack),
        "cost within the input's witness budget",
    )?;
    tx.input[0].witness.script_witness = stack;
    let mut est = tx.clone();
    est.input[1].witness.script_witness = vec![vec![0; 72], vec![0; 33]];
    Ok(Built {
        weight: est.weight(),
        tx,
        new,
        cost: bounds.cost.to_string(),
        program_bytes: code.len(),
        witness_bytes: wit.len(),
        cells: bounds.extra_cells,
    })
}

fn claim(a: &[String], index: u64, local_test: bool, g: &mut Gates) -> Report {
    let input = json!({
        "manifest": read_json(&a[0])?, "state": read_json(&a[1])?,
        "deposits": read_json(&a[2])?, "index": index,
        "state_tx_hex": std::fs::read_to_string(&a[3]).map_err(|e| e.to_string())?,
        "state_vout": parse::<u32>(&a[4], "state vout")?,
        "fee_tx_hex": std::fs::read_to_string(&a[5]).map_err(|e| e.to_string())?,
        "fee_vout": parse::<u32>(&a[6], "fee vout")?,
    });
    let mut report = claim_from_json(&input, local_test, g)?;
    std::fs::write(
        &a[7],
        report["raw_tx"]
            .as_str()
            .ok_or("builder raw transaction missing")?,
    )
    .map_err(|e| e.to_string())?;
    report.as_object_mut().unwrap().remove("raw_tx");
    report["path"] = json!(a[7]);
    Ok(report)
}

fn claim_from_json(input: &Json, local_test: bool, g: &mut Gates) -> Report {
    let d = deployment(&input["manifest"], local_test, g)?;
    let p = d.params.clone();
    let (old, claimed, record) = state_from_json(&input["state"])?;
    let pr = proven_from_json(&p, &old, &claimed, &input["deposits"], g)?;
    let index = num(&input["index"], "deposit index")?;
    g.need(
        index < pr.tree.count(),
        &format!(
            "deposit {} is proven: below the {} deposits the state's accumulator commits",
            index,
            pr.tree.count()
        ),
    )?;
    g.need(
        !claimed.indices.contains(&index),
        &format!("deposit {} is unclaimed in the state's claimed tree", index),
    )?;
    let (units, recipient) = pr.tree.deposits[index as usize];
    let pay_to = pr.scripts[index as usize].clone();
    let state_tx = transaction_field(input, "state_tx_hex")?;
    let state_vout = index_field(input, "state_vout")?;
    let fee_tx = transaction_field(input, "fee_tx_hex")?;
    let fee_vout = index_field(input, "fee_vout")?;
    let state_utxo = state_tx
        .output
        .get(state_vout as usize)
        .cloned()
        .ok_or("state vout does not exist")?;
    let fee_utxo = fee_tx
        .output
        .get(fee_vout as usize)
        .cloned()
        .ok_or("fee vout does not exist")?;
    g.need(
        fee_utxo.script_pubkey.is_v0_p2wpkh(),
        "fee input must be P2WPKH",
    )?;
    // The spent output commits lc, acc and claimed_root, so this also binds the record's claimed set to Liquid.
    let info = state_info(&d.update_cmr, &d.claim_cmr, &old);
    g.need(
        state_utxo.script_pubkey == Script::new_v1_p2tr_tweaked(info.output_key()),
        "spent output = state UTXO of the given state (lc, accumulator, claimed root) under the manifest's leaves",
    )?;
    let phase = (0..2)
        .find(|&i| state_utxo.asset == p.token_asset(i))
        .ok_or("spent output does not hold the bridge token under blinding A or B")?;
    g.need(
        state_utxo.value == p.token_value(),
        "spent token value commitment = 1 * H(token)",
    )?;
    let fee = match (&fee_utxo.asset, &fee_utxo.value) {
        (Asset::Explicit(x), Value::Explicit(v)) if *x == p.fee_asset => *v,
        _ => return Err("fee input must be explicit Liquid testnet L-BTC".into()),
    };
    let b = spend(
        &d,
        &old,
        &claimed,
        &pr.tree,
        index,
        pay_to.clone(),
        (OutPoint::new(state_tx.txid(), state_vout), state_utxo),
        (OutPoint::new(fee_tx.txid(), fee_vout), fee_utxo, fee),
        phase,
        g,
    )?;
    g.need(
        b.weight < STANDARD_WEIGHT,
        "standard weight with a P2WPKH fee signature",
    )?;
    g.need(fee >= fee_floor(b.weight), "fee covers 0.1 sat/vB")?;
    // The leaf fixes the outputs, so the whole fee input is paid as fee: refuse one far above the floor.
    g.need(
        fee <= (100 * fee_floor(b.weight)).max(50_000),
        "fee input at most 100x the relay floor (split a larger UTXO first)",
    )?;

    let next = claimed.with(index);
    let mut successor_state = record.clone();
    successor_state["claimed"] = json!(next.list());
    successor_state["claimed_root"] = json!(hex::encode(b.new.claimed_root));
    successor_state["state_hash"] = json!(hex::encode(state_hash(&b.new)));
    Ok(json!({
        "local_test_only": local_test || !d.deployable,
        "txid": b.tx.txid().to_string(), "successor_outpoint": format!("{}:0", b.tx.txid()), "token_phase": 1 - phase,
        "deposit": {
            "index": index, "units": units, "recipient": hex::encode(recipient),
            "script_pubkey": hex::encode(pay_to.as_bytes()),
        },
        "claimed": next.list(), "claimed_root": hex::encode(b.new.claimed_root),
        "successor_state_hash": hex::encode(state_hash(&b.new)), "successor_state": successor_state,
        "unclaimed": (0..pr.tree.count()).filter(|i| !next.indices.contains(i)).collect::<Vec<_>>(),
        "cmr": d.cmr.to_string(), "cost_mwu": b.cost,
        "program_bytes": b.program_bytes, "witness_bytes": b.witness_bytes, "cells": b.cells,
        "weight_unsigned": b.tx.weight(), "weight_estimate": b.weight, "fee": fee, "unsigned_inputs": [1],
        "raw_tx": serialize_hex(&b.tx),
    }))
}

fn synthetic_prevs(a: &[String], g: &mut Gates) -> Report {
    let m = read_json(&a[0])?;
    let p = params_of(&m)?;
    let (s, _, _) = load_state(&a[1])?;
    let phase: usize = parse(&a[2], "phase")?;
    g.need(phase < 2, "phase is 0 (A) or 1 (B)")?;
    let fee_value: u64 = parse(&a[3], "fee value")?;
    let info = state_info(
        &word(&m["update_leaf"]["cmr"], "update_leaf.cmr")?,
        &word(&m["claim_leaf"]["cmr"], "claim_leaf.cmr")?,
        &s,
    );
    let fictional = |b: u8| TxIn {
        previous_output: OutPoint::new(Txid::from_byte_array([b; 32]), 0),
        ..TxIn::default()
    };
    let state_tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![fictional(0x5e)],
        output: vec![TxOut {
            asset: p.token_asset(phase),
            value: p.token_value(),
            nonce: Nonce::Null,
            script_pubkey: Script::new_v1_p2tr_tweaked(info.output_key()),
            witness: Default::default(),
        }],
    };
    let fee_tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![fictional(0x5d)],
        output: vec![explicit(
            p.fee_asset,
            fee_value,
            Script::from([&[0x00u8, 0x14][..], &[0x77u8; 20][..]].concat()),
        )],
    };
    std::fs::write(&a[4], serialize_hex(&state_tx)).map_err(|e| e.to_string())?;
    std::fs::write(&a[5], serialize_hex(&fee_tx)).map_err(|e| e.to_string())?;
    g.need(true, "synthetic previous transactions written")?;
    Ok(json!({
        "synthetic": "SYNTHETIC: fictional inputs, unbalanced; never valid on any chain; local tests only",
        "state_txid": state_tx.txid().to_string(), "fee_txid": fee_tx.txid().to_string(), "phase": phase,
    }))
}

/// The command line without its flags, `--local-test`, and the value of `--deposit`, a decimal deposit index
/// below 2^32.  Err on a repeated, valueless or malformed `--deposit`.
fn flags(all: Vec<String>) -> Result<(Vec<String>, bool, Option<u64>), String> {
    let (mut rest, mut local_test, mut deposit) = (Vec::new(), false, None);
    let mut it = all.into_iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "--local-test" => local_test = true,
            "--deposit" => {
                let v = it.next().ok_or("--deposit needs a deposit index")?;
                if deposit.is_some() {
                    return Err("--deposit given twice".into());
                }
                let i: u64 = v
                    .parse()
                    .ok()
                    .filter(|_| v.bytes().all(|b| b.is_ascii_digit()))
                    .ok_or_else(|| format!("--deposit {:?} is not a decimal deposit index", v))?;
                if i >> TREE_DEPTH != 0 {
                    return Err(format!("--deposit {} is outside the claimed tree", i));
                }
                deposit = Some(i);
            }
            _ => rest.push(x),
        }
    }
    Ok((rest, local_test, deposit))
}

pub fn cli_main() {
    let (a, local_test, deposit) = match flags(std::env::args().skip(1).collect()) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{}\n{}", e, USAGE);
            std::process::exit(2);
        }
    };
    let mut g = Gates::default();
    let result = match (a.first().map(String::as_str), deposit) {
        (Some("cmr"), None) if a.len() == 2 => cmr_cmd(&a[1..], &mut g),
        (Some("deposits"), None) if a.len() == 4 => deposits_cmd(&a[1..], &mut g),
        (Some("claim"), Some(index)) if a.len() == 9 => claim(&a[1..], index, local_test, &mut g),
        (Some("synthetic-prevs"), None) if a.len() == 7 => synthetic_prevs(&a[1..], &mut g),
        _ => {
            eprintln!("{}", USAGE);
            std::process::exit(2);
        }
    };
    match result {
        Ok(mut report) => {
            report["ok"] = json!(true);
            report["gates_passed"] = json!(g.passed);
            println!("{}", report);
        }
        Err(gate) => {
            println!(
                "{}",
                json!({"ok": false, "failed_gate": gate, "gates_passed": g.passed})
            );
            std::process::exit(3);
        }
    }
}

/// The manifest schema, LC_TAG and a state record's lc and claimed set against the shared protocol vectors
/// (vectors/protocol.json); malformed claimed records and `--deposit` flags; and claims built by `spend` in any
/// order, with the leaf refusing a claimed deposit when the tool's gates are bypassed.
#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../../vectors/protocol.json"
    );

    fn temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "sg16-testnet-claim-{}-{}.json",
            name,
            std::process::id()
        ))
    }

    #[test]
    fn tags_are_the_vectors() {
        let v = read_json(VECTORS).unwrap();
        assert_eq!(v["tags"]["manifest"].as_str(), Some(SCHEMA));
        assert_eq!(v["tags"]["lc"].as_str().map(str::as_bytes), Some(LC_TAG));
    }

    /// `load_state` of a record with the store, written for each lc case, has the case's lc.
    #[test]
    fn state_lc_is_the_vectors() {
        let v = read_json(VECTORS).unwrap();
        let cases = v["lc"].as_array().unwrap();
        assert!(!cases.is_empty(), "vectors: no lc case");
        let path = temp("lc");
        for (i, c) in cases.iter().enumerate() {
            let want = word(&c["lc"], "lc").unwrap_or_else(|_| {
                panic!(
                    "lc[{i}].lc is not recorded: run node vectors/record.mjs and review the result"
                )
            });
            let record = json!({
                "head": c["slot"].clone(), "header": c["header"].clone(), "committee": c["committee"].clone(),
                "acc": format!("0x{}", "00".repeat(32)), "claimed": [],
                "claimed_root": hex::encode(ClaimedTree::new().root()),
            });
            std::fs::write(&path, record.to_string()).unwrap();
            assert_eq!(
                load_state(path.to_str().unwrap()).unwrap().0.lc,
                want,
                "lc[{i}]"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// An lc-only record of each state_hash case, its indices listed ascending, gives the case's state hash.
    #[test]
    fn state_hash_is_the_vectors() {
        let v = read_json(VECTORS).unwrap();
        let path = temp("state-hash");
        for (i, c) in v["state_hash"].as_array().unwrap().iter().enumerate() {
            let mut list: Vec<u64> = c["indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap())
                .collect();
            list.sort_unstable();
            let record = json!({"lc": c["lc"], "acc": c["acc"], "claimed": list, "claimed_root": c["claimed_root"]});
            std::fs::write(&path, record.to_string()).unwrap();
            let (s, claimed, _) = load_state(path.to_str().unwrap()).unwrap();
            assert_eq!(claimed.list(), list, "state_hash[{i}] indices");
            assert_eq!(
                state_hash(&s),
                word(&c["state_hash"], "state_hash").unwrap(),
                "state_hash[{i}]"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_claimed_records_are_refused() {
        let root = |set: &[u64]| {
            hex::encode(
                set.iter()
                    .fold(ClaimedTree::new(), |t, &i| t.with(i))
                    .root(),
            )
        };
        for (what, j, fragment) in [
            (
                "a non-list claimed field",
                json!({"claimed": 1, "claimed_root": root(&[0])}),
                "a list of deposit indices",
            ),
            (
                "indices out of order",
                json!({"claimed": [2, 0], "claimed_root": root(&[0, 2])}),
                "strictly ascending",
            ),
            (
                "a repeated index",
                json!({"claimed": [0, 0], "claimed_root": root(&[0])}),
                "strictly ascending",
            ),
            (
                "an index outside the tree",
                json!({"claimed": [1u64 << 32], "claimed_root": root(&[])}),
                "outside the claimed tree",
            ),
            (
                "a negative index",
                json!({"claimed": [-1], "claimed_root": root(&[])}),
                "integer",
            ),
            (
                "the root of another set",
                json!({"claimed": [0], "claimed_root": root(&[1])}),
                "not the claimed tree's root",
            ),
            (
                "the root of the set minus a claim (a replayed slot)",
                json!({"claimed": [0, 2], "claimed_root": root(&[0])}),
                "not the claimed tree's root",
            ),
            ("no root", json!({"claimed": [0]}), "claimed_root missing"),
            (
                "a root that is not hex",
                json!({"claimed": [0], "claimed_root": "zz".repeat(32)}),
                "claimed_root",
            ),
        ] {
            let e = claimed_of(&j).expect_err(what);
            assert!(e.contains(fragment), "{what}: {e}");
        }
    }

    #[test]
    fn deposit_flag() {
        let args = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            flags(args(&["claim", "m", "--deposit", "7", "--local-test"])).unwrap(),
            (args(&["claim", "m"]), true, Some(7))
        );
        assert_eq!(
            flags(args(&["claim", "m"])).unwrap(),
            (args(&["claim", "m"]), false, None)
        );
        for (bad, fragment) in [
            (&["claim", "--deposit"][..], "needs a deposit index"),
            (&["claim", "--deposit", "1", "--deposit", "2"][..], "twice"),
            (&["claim", "--deposit", "-1"][..], "not a decimal"),
            (&["claim", "--deposit", "+1"][..], "not a decimal"),
            (&["claim", "--deposit", "0x1"][..], "not a decimal"),
            (
                &["claim", "--deposit", "4294967296"][..],
                "outside the claimed tree",
            ),
        ] {
            let e = flags(args(bad)).expect_err(fragment);
            assert!(e.contains(fragment), "{bad:?}: {e}");
        }
    }

    fn test_deployment() -> Deployment {
        let params = leaf::test_params();
        let (_, program) = compile_claim(&params).unwrap();
        let cmr = program.commit().cmr();
        Deployment {
            claim_cmr: cmr.as_ref().try_into().unwrap(),
            params,
            program,
            cmr,
            update_cmr: sha(b"test-only stand-in for the update leaf CMR"),
            deployable: false,
        }
    }

    fn state_out(d: &Deployment, s: &State, phase: usize) -> TxOut {
        let info = state_info(&d.update_cmr, &d.claim_cmr, s);
        TxOut {
            asset: d.params.token_asset(phase),
            value: d.params.token_value(),
            nonce: Nonce::Null,
            script_pubkey: Script::new_v1_p2tr_tweaked(info.output_key()),
            witness: Default::default(),
        }
    }

    fn fee_in(d: &Deployment, k: u8) -> (OutPoint, TxOut, u64) {
        let spk = Script::from([&[0x00u8, 0x14][..], &[0x77u8; 20][..]].concat());
        (
            OutPoint::new(Txid::from_byte_array([k; 32]), 0),
            explicit(d.params.fee_asset, 2_000, spk),
            2_000,
        )
    }

    /// Three proven deposits, paid 2, 0, 1: each claim spends the previous successor, and the last state has every
    /// proven deposit paid.  Then the leaf, not only the tool's gate, refuses deposit 2 again.
    #[test]
    fn claims_in_any_order_then_a_duplicate_is_refused_by_the_leaf() {
        let d = test_deployment();
        let scripts = [
            Script::from([&[0x00u8, 0x14][..], &[0x33u8; 20][..]].concat()),
            Script::from([&[0xa9u8, 0x14][..], &[0x44u8; 20][..], &[0x87u8][..]].concat()),
            Script::from([&[0x00u8, 0x14][..], &[0x55u8; 20][..]].concat()),
        ];
        let mut tree = DepositTree::new(d.params.deposit_domain);
        for (k, s) in scripts.iter().enumerate() {
            tree.push(100_000 * (k as u64 + 1), sha(s.as_bytes()));
        }
        let mut claimed = Claimed {
            indices: BTreeSet::new(),
            tree: ClaimedTree::new(),
        };
        let mut old = State {
            lc: [1; 32],
            acc: tree.accumulator(),
            claimed_root: claimed.tree.root(),
        };
        let mut phase = 0;
        let mut prev = (
            OutPoint::new(Txid::from_byte_array([0x5e; 32]), 0),
            state_out(&d, &old, phase),
        );
        for (k, index) in [2u64, 0, 1].into_iter().enumerate() {
            let b = spend(
                &d,
                &old,
                &claimed,
                &tree,
                index,
                scripts[index as usize].clone(),
                prev.clone(),
                fee_in(&d, k as u8 + 1),
                phase,
                &mut Gates::default(),
            )
            .unwrap_or_else(|e| panic!("claim of deposit {index}: {e}"));
            claimed = claimed.with(index);
            assert_eq!(b.new.claimed_root, claimed.tree.root(), "deposit {index}");
            assert_eq!(
                b.tx.output[0].script_pubkey,
                state_out(&d, &b.new, 1 - phase).script_pubkey
            );
            phase = 1 - phase;
            prev = (OutPoint::new(b.tx.txid(), 0), b.tx.output[0].clone());
            old = b.new;
        }
        assert_eq!(old.claimed_root, complete_root(3));
        let e = spend(
            &d,
            &old,
            &claimed,
            &tree,
            2,
            scripts[2].clone(),
            prev,
            fee_in(&d, 9),
            phase,
            &mut Gates::default(),
        )
        .err()
        .expect("the leaf refuses a second claim of deposit 2");
        assert!(
            e.contains("rejected") || e.contains("execution"),
            "a claimed slot: {e}"
        );
    }
}

// These limits bound parsing and proof work before any caller-controlled program runs.
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_TX_HEX: usize = 8 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

fn index_field(input: &Json, name: &str) -> Result<u32, String> {
    u32::try_from(num(&input[name], name)?).map_err(|_| format!("{} exceeds u32", name))
}

fn transaction_field(input: &Json, name: &str) -> Result<Transaction, String> {
    let value = input[name]
        .as_str()
        .ok_or_else(|| format!("{} missing", name))?
        .trim();
    if value.len() > MAX_TX_HEX {
        return Err(format!("{} exceeds size limit", name));
    }
    let raw = hex::decode(value).map_err(|e| format!("{}: {}", name, e))?;
    deserialize(&raw).map_err(|e| format!("{}: not an Elements transaction: {}", name, e))
}

fn checked_input(text: &str) -> Result<Json, String> {
    if text.len() > MAX_INPUT_BYTES {
        return Err("builder input exceeds 64 MiB".into());
    }
    let input: Json = serde_json::from_str(text).map_err(|e| format!("builder JSON: {}", e))?;
    if !input.is_object() {
        return Err("builder input must be an object".into());
    }
    for (owner, field) in [
        (&input["state"], "claimed"),
        (&input["new_state"], "claimed"),
        (&input, "deposits"),
    ] {
        if owner[field]
            .as_array()
            .is_some_and(|v| v.len() > MAX_ENTRIES)
        {
            return Err(format!("{} exceeds 10,000 entries", field));
        }
    }
    Ok(input)
}

/// Build and execute the covenant locally. The returned fee input still needs a wallet signature.
/// Test-only manifests are never accepted by this API.
pub fn build_claim_json(text: &str) -> Result<String, String> {
    let input = checked_input(text)?;
    let mut gates = Gates::default();
    let mut report = claim_from_json(&input, false, &mut gates)?;
    let raw_tx = report
        .as_object_mut()
        .ok_or("builder report missing")?
        .remove("raw_tx")
        .ok_or("builder raw transaction missing")?;
    report["ok"] = json!(true);
    report["gates_passed"] = json!(gates.passed);
    Ok(json!({"raw_tx": raw_tx, "report": report}).to_string())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn build_claim(input_json: &str) -> Result<String, wasm_bindgen::JsError> {
    build_claim_json(input_json).map_err(|e| wasm_bindgen::JsError::new(&e))
}
