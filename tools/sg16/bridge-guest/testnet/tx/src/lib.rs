//! sg16-testnet: Liquid testnet transactions of the sg16 bridge state UTXO (tools/sg16/bridge-guest/testnet).
//!
//! State UTXO: P2TR(NUMS, {{update leaf, claim leaf}, tapleaf(state_hash(lc, acc, claimed_root))}), holding the bridge
//! asset's only reissuance token, blinded with public factor A or B, value commitment 1 * H(token)
//! (tools/sg16/bridge-guest/liquid.py, contracts/simplicity/src/claim.rs).  Every command checks named gates; the
//! first failure prints {"ok": false, "failed_gate": ...} and exits 3.  Nothing is signed (except the explicitly
//! synthetic local funding transaction, which spends a fictional outpoint), funded or broadcast.
//!
//! A state record (state.json) is {"head", "header", "committee", "acc", "claimed", "claimed_root", ...}: `claimed`
//! lists the deposit indices already paid, strictly ascending, and `claimed_root` is the root of the claimed tree of
//! that set (sg16_harness::bridge::claimed_root), which the state hash commits. Both must be present and agree.
//!
//!   sg16-testnet params <funding txid (display hex)> <vout> <contract hash> <entropy>
//!       rust-elements' asset entropy of the outpoint, compared through the reissuance token with `entropy`
//!       (computed independently by testnet/pins.py)
//!   sg16-testnet cmr <program .simpl>
//!       the commitment Merkle root of a generated program (the update leaf's taproot leaf script)
//!   sg16-testnet tree <manifest.json> <state.json>
//!       the state output for `state` under the manifest's two leaves: script, address, control blocks, from
//!       rust-elements' TaprootBuilder and the harness's tagged-hash code, which must agree
//!   sg16-testnet bootstrap <manifest.json> <state.json> <funding.hex> <vout> <fee> <change spk hex> <out.hex>
//!                          [--local-test]
//!       the issuance transaction: input 0 spends the funding output the entropy was derived from and issues one
//!       token and no asset; output 0 is the first state UTXO (token blinding A), output 1 the change (the funding
//!       value must exceed the fee, and the change script must be non-empty), output 2 the fee.  Input 0 is left
//!       unsigned.  This tool does not re-derive the leaves or the initial state; `assemble.py bootstrap` does,
//!       and is the command to use for a real outpoint.
//!   sg16-testnet check-bootstrap <manifest.json> <state.json> <bootstrap.hex>
//!       a public bootstrap transaction against the manifest: input 0 spends the funding outpoint as a new issuance
//!       of no asset and exactly one explicit token, output 0 is the manifest's state UTXO holding it at blinding A,
//!       every other output is explicit L-BTC, so the token can be nowhere else
//!   sg16-testnet update <manifest.json> <program .simpl> <witness.json> <state.json> <new_state.json>
//!                       <state tx.hex> <state vout> <fee tx.hex> <fee vout> <out.hex> [--local-test]
//!       the update transaction, laid out exactly as tools/sg16-harness `bridge::build` (which test_bridge_guest.py
//!       exercises) but over the real spent outputs: the update leaf is pruned, executed, encoded, decoded and
//!       executed again; input 1 (fee) is left unsigned
//!   sg16-testnet verify <tx.hex> <input index> <prev tx.hex>...
//!       node-like check of one Simplicity input of any transaction: control-block commitment, CMR, decode and
//!       execution under simplicity-lang 0.9, budget, and Elements amount proofs of the whole transaction
//!   sg16-testnet recover <manifest.json> <state.json> <state tx.hex> [<spend tx.hex>...]
//!       the state a chain of public spends leads to, from `state` (output 0 of `state tx`, usually the initial
//!       state and the bootstrap) and the update and claim transactions that spent each state output 0 in turn:
//!       lc, acc, the claimed set and head, read from the spends' witnesses and accepted only if each output 0 is
//!       the state UTXO they imply.  A claim may pay any unclaimed deposit: its index is the one 64-bit word of its
//!       witness, below 2^32 and not yet claimed, whose claimed tree makes output 0 (`claim_index`).  The
//!       light-client store behind an update's lc (header, committee) is not on Liquid; the report has it only
//!       while no update has been walked
//!   sg16-testnet synthetic-funding <value> <out.hex>
//!       a SYNTHETIC explicit L-BTC output spending a fictional outpoint, for local tests only
//!   sg16-testnet txid <tx.hex>
//!       the txid of a transaction file: one hex string, surrounding whitespace allowed, that rust-elements reads
//!       as exactly one transaction with no bytes left over
//!   sg16-testnet output <tx.hex> <vout>
//!       output `vout` (canonical decimal) of a transaction file read as by `txid`: its script, and its asset
//!       (display hex) and value (sats) where explicit, null where confidential; "explicit_lbtc" says whether
//!       both are explicit and the asset is Liquid testnet L-BTC.  A missing output fails as a gate
//!   sg16-testnet input <tx.hex> <vin>
//!       input `vin` (canonical decimal) of a transaction file read as by `txid`: the outpoint it spends
//!       ("txid:vout", flags removed), whether it is a peg-in and whether it issues.  A missing input fails as a gate
//!
//! A manifest that is not `deployable` (dry run, stand-in leaf) is refused by bootstrap and update unless
//! --local-test is given; their reports then carry "local_test_only": true.
//!
//! Malformed operator input (hex, JSON fields, manifest configuration, transactions) fails as a gate.  The
//! generated program and witness files are read with tools/sg16-harness loaders, which panic on malformed
//! content: they are assemble.py outputs, and a panic there exits nonzero without writing a transaction.
use serde_json::{json, Value as Json};
use sg16_harness::bridge::{
    self, asset_bytes, asset_of, conf_parts, issuance, out_witness, stack_bytes, tagged, tap,
    tapbranch, tapleaf_simplicity, token_asset, token_of, try_h32, unit_value, Config, Plan,
};
use sg16_harness::program::{environment, Program};
use sg16_harness::witness::{self, hex, parse_hex};
use simplicity::elements::confidential::{Asset, Nonce, Value};
use simplicity::elements::encode::{deserialize, serialize, serialize_hex};
use simplicity::elements::secp256k1_zkp::{
    self as secp, Generator, PedersenCommitment, RangeProof, Scalar, Secp256k1, SecretKey,
    SurjectionProof, Tag, Tweak, XOnlyPublicKey, ZERO_TWEAK,
};
use simplicity::elements::taproot::{ControlBlock, TaprootBuilder};
use simplicity::elements::{
    Address, AddressParams, AssetId, BlockHash, ContractHash, LockTime, OutPoint, Script, Sequence,
    Transaction, TxIn, TxInWitness, TxOut, TxOutWitness, Txid, Witness,
};
use simplicity::jet::Elements;
use simplicity::{BitIter, BitMachine, RedeemNode};
use std::collections::BTreeSet;
use std::str::FromStr;

const TESTNET_GENESIS: &str = "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1";
const TESTNET_LBTC: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
const SCHEMA: &str = "liquid-bridge-poc/manifest";
const STANDARD_WEIGHT: usize = 400_000;
const MIN_RELAY_SAT_PER_KVB: u64 = 100;
const USAGE: &str = "usage: sg16-testnet \
    params|cmr|tree|bootstrap|check-bootstrap|compile-update|update|update-compiled|verify|recover|synthetic-funding|txid|output|input ... \
    (see the source header)";

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

fn read_json(path: &str) -> Result<Json, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {}", path, e))
}

fn read_tx(path: &str) -> Result<Transaction, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
    let raw = parse_hex(text.trim()).map_err(|e| format!("{}: {}", path, e))?;
    deserialize(&raw).map_err(|e| format!("{}: not an Elements transaction: {:?}", path, e))
}

fn word(j: &Json, what: &str) -> Result<[u8; 32], String> {
    let s = j.as_str().ok_or_else(|| format!("{} missing", what))?;
    parse_hex(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|e| format!("{}: {}", what, e))?
        .try_into()
        .map_err(|_| format!("{}: not 32 bytes", what))
}

fn num(j: &Json, what: &str) -> Result<u64, String> {
    j.as_u64().ok_or_else(|| format!("{} missing", what))
}

fn parse<T: FromStr>(s: &str, what: &str) -> Result<T, String> {
    s.parse()
        .map_err(|_| format!("{}: cannot parse {:?}", what, s))
}

/// The deposits a state has paid: the claimed set and the root of its claimed tree, which the state hash commits.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Claimed {
    indices: BTreeSet<u64>,
    root: [u8; 32],
}

impl Claimed {
    /// Nothing paid: the initial state's.
    fn none() -> Claimed {
        Claimed::of(BTreeSet::new()).expect("the empty claimed tree")
    }

    fn of(indices: BTreeSet<u64>) -> Result<Claimed, String> {
        let root = bridge::claimed_root(&indices)?;
        Ok(Claimed { indices, root })
    }

    /// `claimed` and `claimed_root` of a state record: indices below 2^32, strictly ascending, whose claimed tree
    /// has exactly that root.
    fn load(j: &Json) -> Result<Claimed, String> {
        let list = j["claimed"]
            .as_array()
            .ok_or("state.claimed: a list of deposit indices")?;
        let mut indices = Vec::with_capacity(list.len());
        for i in list {
            indices.push(
                i.as_u64()
                    .ok_or("state.claimed: each index is an integer")?,
            );
        }
        if indices.windows(2).any(|w| w[0] >= w[1]) {
            return Err("state.claimed: indices strictly ascending, each listed once".into());
        }
        let c = Claimed::of(indices.into_iter().collect())
            .map_err(|e| format!("state.claimed: {}", e))?;
        if word(&j["claimed_root"], "state.claimed_root")? != c.root {
            return Err(
                "state.claimed_root is not the claimed tree's root of state.claimed".into(),
            );
        }
        Ok(c)
    }

    fn with(&self, index: u64) -> Result<Claimed, String> {
        let mut indices = self.indices.clone();
        indices.insert(index);
        Claimed::of(indices)
    }

    fn json_into(&self, j: &mut Json) {
        j["claimed"] = json!(self.indices.iter().collect::<Vec<_>>());
        j["claimed_root"] = json!(hex(&self.root));
    }
}

/// A bridge state: lc = SHA256(SHA256(LC_TAG) || be64(head) || header || committee), the escrow accumulator and
/// the deposits already minted.
#[derive(Clone)]
struct State {
    head: u64,
    header: [u8; 32],
    committee: [u8; 32],
    acc: [u8; 32],
    claimed: Claimed,
}

impl State {
    fn load(path: &str) -> Result<State, String> {
        Self::from_json(&read_json(path)?)
    }

    fn from_json(j: &Json) -> Result<State, String> {
        Ok(State {
            head: num(&j["head"], "state.head")?,
            header: word(&j["header"], "state.header")?,
            committee: word(&j["committee"], "state.committee")?,
            acc: word(&j["acc"], "state.acc")?,
            claimed: Claimed::load(&j)?,
        })
    }

    fn lc(&self) -> [u8; 32] {
        bridge::lc(self.head, &self.header, &self.committee)
    }

    fn hash(&self) -> [u8; 32] {
        bridge::state_hash(&self.lc(), &self.acc, &self.claimed.root)
    }

    fn json(&self) -> Json {
        let mut j = json!({"head": self.head, "header": hex(&self.header), "committee": hex(&self.committee),
                           "acc": hex(&self.acc), "lc": hex(&self.lc()), "state_hash": hex(&self.hash())});
        self.claimed.json_into(&mut j);
        j
    }
}

/// The manifest's bridge parameters, checked on load.
struct Deployment {
    cfg: Config,
    constants: Json,
    update_cmr: [u8; 32],
    claim_cmr: [u8; 32],
    funding: OutPoint,
    contract: [u8; 32],
    deployable: bool,
}

fn load(path: &str, g: &mut Gates) -> Result<Deployment, String> {
    deployment_from_json(&read_json(path)?, g)
}

fn deployment_from_json(m: &Json, g: &mut Gates) -> Result<Deployment, String> {
    g.need(m["schema"] == SCHEMA, "manifest schema")?;
    g.need(
        m["liquid"]["network"] == "liquidtestnet",
        "manifest network is Liquid testnet",
    )?;
    let cfg = Config::try_from_json(&m["harness_config"])
        .map_err(|e| format!("manifest harness_config: {}", e))?;
    g.need(
        cfg.genesis == BlockHash::from_str(TESTNET_GENESIS).unwrap(),
        "genesis = Liquid testnet genesis block",
    )?;
    g.need(
        cfg.fee_asset == AssetId::from_str(TESTNET_LBTC).unwrap(),
        "fee asset = Liquid testnet L-BTC",
    )?;
    g.need(
        cfg.constants() == m["constants"],
        "manifest constants = harness constants of its configuration",
    )?;
    g.need(
        cfg.abf.iter().all(|bf| SecretKey::from_slice(bf).is_ok()) && cfg.abf[0] != cfg.abf[1],
        "two distinct valid token blinding factors",
    )?;
    let b = &m["bootstrap"];
    let txid = Txid::from_str(
        b["funding_txid"]
            .as_str()
            .ok_or("bootstrap.funding_txid missing")?,
    )
    .map_err(|e| format!("bootstrap.funding_txid: {:?}", e))?;
    let funding = OutPoint::new(
        txid,
        u32::try_from(num(&b["funding_vout"], "bootstrap.funding_vout")?)
            .map_err(|_| "bootstrap.funding_vout exceeds u32")?,
    );
    let contract = word(&b["contract_hash"], "bootstrap.contract_hash")?;
    g.need(
        word(&b["entropy"], "bootstrap.entropy")? == cfg.entropy,
        "manifest entropy = configured entropy",
    )?;
    let derived = AssetId::generate_asset_entropy(funding, ContractHash::from_byte_array(contract));
    g.need(
        AssetId::reissuance_token_from_entropy(derived, false) == cfg.token(),
        "bridge token derives from the bootstrap outpoint (rust-elements)",
    )?;
    g.need(
        b["asset"] == hex(&asset_bytes(cfg.asset())).as_str()
            && b["token"] == hex(&asset_bytes(cfg.token())).as_str(),
        "manifest asset and token ids = configuration",
    )?;
    Ok(Deployment {
        cfg,
        constants: m["constants"].clone(),
        update_cmr: word(&m["update_leaf"]["cmr"], "update_leaf.cmr")?,
        claim_cmr: word(&m["claim_leaf"]["cmr"], "claim_leaf.cmr")?,
        funding,
        contract,
        deployable: m["deployable"] == true,
    })
}

fn require_deployable(d: &Deployment, local_test: bool, g: &mut Gates) -> Result<(), String> {
    g.need(
        d.deployable || local_test,
        "manifest is deployable (real bootstrap outpoint, real-key update leaf, all gates passed)",
    )
}

fn explicit_out(asset: AssetId, value: u64, spk: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: spk,
        witness: TxOutWitness::default(),
    }
}

fn explicit_of(o: &TxOut) -> Option<(AssetId, u64)> {
    match (&o.asset, &o.value) {
        (Asset::Explicit(a), Value::Explicit(v)) => Some((*a, *v)),
        _ => None,
    }
}

fn same_utxo(a: &TxOut, b: &TxOut) -> bool {
    a.asset == b.asset
        && a.value == b.value
        && a.nonce == b.nonce
        && a.script_pubkey == b.script_pubkey
}

/// 0 or 1 if the output holds the bridge token under public blinding factor A or B.
fn token_phase(d: &Deployment, o: &TxOut) -> Option<usize> {
    let token = d.cfg.token();
    (0..2).find(|&i| o.asset == token_asset(token, &d.cfg.abf[i]))
}

fn empty_accumulator() -> [u8; 32] {
    let mut z = [0u8; 32];
    for _ in 0..32 {
        z = bridge::sha(&[&z[..], &z[..]].concat());
    }
    bridge::sha(&[&z[..], &0u64.to_be_bytes()[..]].concat())
}

fn fee_floor(weight: usize) -> u64 {
    ((weight as u64 + 3) / 4 * MIN_RELAY_SAT_PER_KVB + 999) / 1000
}

/// The covenant leaves fix the outputs, so an update or claim pays its whole fee input as fee.  Refusing fee
/// inputs far above the relay floor keeps a mistyped outpoint from burning a large UTXO; split it first.
fn fee_ceiling(weight: usize) -> u64 {
    (100 * fee_floor(weight)).max(50_000)
}

/// Weight after `inputs` get a P2WPKH-sized signature (72-byte DER + sighash byte at most, 33-byte key).
fn weight_with_p2wpkh(tx: &Transaction, inputs: &[usize]) -> usize {
    let mut est = tx.clone();
    for &i in inputs {
        est.input[i].witness.script_witness = Witness::from_slice(&[vec![0u8; 72], vec![0u8; 33]]);
    }
    est.weight()
}

/// Surjection and range proofs of a token output with the public blinding factor `abf` and the constant value
/// commitment 1 * H(token), as tools/sg16-harness `bridge::build`.  `domain` is Elements' surjection domain in
/// input order: (asset, asset blinding factor; zero for explicit).
fn token_proofs(
    token: AssetId,
    abf: &[u8; 32],
    spk: &Script,
    domain: &[(AssetId, [u8; 32])],
) -> TxOutWitness {
    let secp = Secp256k1::new();
    let mut rng = secp::rand::thread_rng();
    let domain: Vec<(Generator, Tag, Tweak)> = domain
        .iter()
        .map(|(id, bf)| {
            let gen = if *bf == [0; 32] {
                Generator::new_unblinded(&secp, id.into_tag())
            } else {
                Generator::new_blinded(&secp, id.into_tag(), Tweak::from_slice(bf).unwrap())
            };
            (
                gen,
                id.into_tag(),
                if *bf == [0; 32] {
                    ZERO_TWEAK
                } else {
                    Tweak::from_slice(bf).unwrap()
                },
            )
        })
        .collect();
    let surjection = SurjectionProof::new(
        &secp,
        &mut rng,
        token.into_tag(),
        Tweak::from_slice(abf).unwrap(),
        &domain,
    )
    .expect("surjection proof");
    let blinded = Generator::new_blinded(&secp, token.into_tag(), Tweak::from_slice(abf).unwrap());
    let commitment = PedersenCommitment::new_unblinded(
        &secp,
        1,
        Generator::new_unblinded(&secp, token.into_tag()),
    );
    let vbf =
        Tweak::from_slice(&SecretKey::from_slice(abf).unwrap().negate().secret_bytes()).unwrap();
    let range = RangeProof::new(
        &secp,
        1,
        commitment,
        1,
        vbf,
        &[],
        spk.as_bytes(),
        SecretKey::from_slice(&[9; 32]).unwrap(),
        0,
        52,
        blinded,
    )
    .expect("range proof");
    out_witness(&surjection.serialize(), &range.serialize())
}

/// Recompute the output key from a control block and the leaf's CMR, as consensus does before running the
/// program.  Ok(internal key is NUMS).
fn control_commits(control: &[u8], cmr: &[u8; 32], spk: &Script) -> Result<bool, String> {
    if control.len() < 33 || (control.len() - 33) % 32 != 0 || control.len() > 33 + 32 * 128 {
        return Err("control block length".into());
    }
    if control[0] & 0xfe != 0xbe {
        return Err("control block leaf version is not Simplicity (0xbe)".into());
    }
    let internal: [u8; 32] = control[1..33].try_into().unwrap();
    let mut node = tapleaf_simplicity(cmr);
    for p in control[33..].chunks(32) {
        let p: [u8; 32] = p.try_into().unwrap();
        node = tapbranch(&node, &p);
    }
    let t = tagged("TapTweak/elements", &[&internal[..], &node[..]].concat());
    let key = XOnlyPublicKey::from_slice(&internal)
        .map_err(|e| format!("control block internal key: {:?}", e))?;
    let scalar = Scalar::from_be_bytes(t).map_err(|_| "taproot tweak out of range".to_string())?;
    let (q, parity) = key
        .add_tweak(&Secp256k1::verification_only(), &scalar)
        .map_err(|e| format!("taproot tweak: {:?}", e))?;
    if Script::from([&[0x51u8, 0x20][..], &q.serialize()[..]].concat()) != *spk {
        return Err("control block does not commit to the spent output key".into());
    }
    if parity.to_u8() != control[0] & 1 {
        return Err("control block output key parity".into());
    }
    Ok(hex(&internal) == bridge::NUMS)
}

struct Tree {
    spk: Script,
    address: String,
    output_key: [u8; 32],
    merkle_root: [u8; 32],
    update_control: ControlBlock,
    claim_control: ControlBlock,
}

/// P2TR(NUMS, {{update, claim}, state}) by two implementations, which must agree.
fn state_tree(d: &Deployment, state_hash: &[u8; 32], g: &mut Gates) -> Result<Tree, String> {
    let (lu, lc, ls) = (
        tapleaf_simplicity(&d.update_cmr),
        tapleaf_simplicity(&d.claim_cmr),
        tapleaf_simplicity(state_hash),
    );
    let via_update = tap(&d.update_cmr, &[lc, ls]);
    let via_claim = tap(&d.claim_cmr, &[lu, ls]);
    let ctx = Secp256k1::verification_only();
    let internal = XOnlyPublicKey::from_str(bridge::NUMS).expect("NUMS key");
    let leaf = |b: &[u8; 32]| Script::from(b.to_vec());
    let info = TaprootBuilder::new()
        .add_leaf_with_ver(2, leaf(&d.update_cmr), simplicity::leaf_version())
        .expect("update leaf")
        .add_leaf_with_ver(2, leaf(&d.claim_cmr), simplicity::leaf_version())
        .expect("claim leaf")
        .add_leaf_with_ver(1, leaf(state_hash), simplicity::leaf_version())
        .expect("state leaf")
        .finalize(&ctx, internal)
        .expect("taproot tree");
    let address = Address::p2tr(
        &ctx,
        internal,
        info.merkle_root(),
        None,
        &AddressParams::LIQUID_TESTNET,
    );
    let update_control = info
        .control_block(&(leaf(&d.update_cmr), simplicity::leaf_version()))
        .expect("update control block");
    let claim_control = info
        .control_block(&(leaf(&d.claim_cmr), simplicity::leaf_version()))
        .expect("claim control block");
    g.need(
        address.script_pubkey() == via_update.spk && via_update.spk == via_claim.spk,
        "state script: rust-elements TaprootBuilder = harness taproot code",
    )?;
    g.need(
        update_control.serialize() == via_update.control.serialize()
            && claim_control.serialize() == via_claim.control.serialize(),
        "control blocks: rust-elements TaprootBuilder = harness taproot code",
    )?;
    let nums = control_commits(&update_control.serialize(), &d.update_cmr, &via_update.spk)?
        && control_commits(&claim_control.serialize(), &d.claim_cmr, &via_update.spk)?;
    g.need(nums, "both control blocks commit to the state output key with the NUMS internal key (no key path)")?;
    Ok(Tree {
        spk: via_update.spk.clone(),
        address: address.to_string(),
        output_key: via_update.output_key,
        merkle_root: tapbranch(&tapbranch(&lu, &lc), &ls),
        update_control,
        claim_control,
    })
}

fn params(a: &[String], g: &mut Gates) -> Report {
    let txid = Txid::from_str(&a[0]).map_err(|e| format!("funding txid: {:?}", e))?;
    let vout: u32 = parse(&a[1], "vout")?;
    let contract = try_h32(&a[2]).map_err(|e| format!("contract hash: {}", e))?;
    let entropy = try_h32(&a[3]).map_err(|e| format!("entropy: {}", e))?;
    let derived = AssetId::generate_asset_entropy(
        OutPoint::new(txid, vout),
        ContractHash::from_byte_array(contract),
    );
    let (asset, token) = (asset_of(entropy), token_of(entropy));
    g.need(true, "parameters computed")?;
    Ok(json!({
        "outpoint": format!("{}:{}", txid, vout),
        "asset": hex(&asset_bytes(asset)), "token": hex(&asset_bytes(token)),
        "asset_display": asset.to_string(), "token_display": token.to_string(),
        "outpoint_token_matches": AssetId::reissuance_token_from_entropy(derived, false) == token,
    }))
}

fn cmr_cmd(a: &[String], g: &mut Gates) -> Report {
    let program = Program::load(&a[0]);
    let cmr = program.cmr();
    g.need(true, "program parsed (tools/sg16-harness Program::load)")?;
    Ok(json!({"cmr": hex(&cmr), "leaf": hex(&tapleaf_simplicity(&cmr)), "path": a[0]}))
}

fn tree_cmd(a: &[String], g: &mut Gates) -> Report {
    let d = load(&a[0], g)?;
    let s = State::load(&a[1])?;
    let t = state_tree(&d, &s.hash(), g)?;
    Ok(json!({
        "deployable": d.deployable, "state": s.json(), "state_hash": hex(&s.hash()),
        "script_pubkey": hex(t.spk.as_bytes()), "address": t.address,
        "output_key": hex(&t.output_key), "merkle_root": hex(&t.merkle_root),
        "update_leaf": hex(&tapleaf_simplicity(&d.update_cmr)), "claim_leaf": hex(&tapleaf_simplicity(&d.claim_cmr)),
        "update_control": hex(&t.update_control.serialize()), "claim_control": hex(&t.claim_control.serialize()),
    }))
}

fn bootstrap(a: &[String], local_test: bool, g: &mut Gates) -> Report {
    let d = load(&a[0], g)?;
    require_deployable(&d, local_test, g)?;
    let s = State::load(&a[1])?;
    g.need(
        s.claimed == Claimed::none() && s.acc == empty_accumulator(),
        "initial state: nothing claimed, the escrow's empty deposit accumulator",
    )?;
    let funding = read_tx(&a[2])?;
    let vout: u32 = parse(&a[3], "funding vout")?;
    let fee: u64 = parse(&a[4], "fee")?;
    let change_spk = if a[5] == "-" {
        None
    } else {
        Some(Script::from(
            parse_hex(&a[5]).map_err(|e| format!("change script: {}", e))?,
        ))
    };
    let outpoint = OutPoint::new(funding.txid(), vout);
    g.need(
        outpoint == d.funding,
        "funding outpoint = the outpoint the bridge asset entropy was derived from",
    )?;
    let utxo = funding
        .output
        .get(vout as usize)
        .cloned()
        .ok_or("funding vout does not exist")?;
    let (asset, value) = explicit_of(&utxo)
        .ok_or("funding output is confidential; an explicit L-BTC output is required")?;
    g.need(
        asset == d.cfg.fee_asset,
        "funding output is explicit Liquid testnet L-BTC",
    )?;
    g.need(value > fee, "funding value exceeds the fee")?;
    // value > fee, so there is always change, and it needs a real script: Elements counts an explicit output
    // with an empty script as a fee, so an empty "change" script would pay the change to the block signer.
    let change = value - fee;
    g.need(change_spk.is_some(), "change has a script")?;
    let change_spk = change_spk.unwrap_or_else(Script::new);
    g.need(
        !change_spk.is_empty(),
        "change script is not empty (an explicit empty-script output is a fee)",
    )?;
    let token = d.cfg.token();
    let derived =
        AssetId::generate_asset_entropy(outpoint, ContractHash::from_byte_array(d.contract));
    g.need(
        AssetId::reissuance_token_from_entropy(derived, false) == token,
        "issuance authority: this outpoint and contract hash create the bridge token",
    )?;
    let t = state_tree(&d, &s.hash(), g)?;
    let mut state_out = TxOut {
        asset: token_asset(token, &d.cfg.abf[0]),
        value: unit_value(token),
        nonce: Nonce::Null,
        script_pubkey: t.spk.clone(),
        witness: TxOutWitness::default(),
    };
    // Elements' surjection domain of input 0: the spent L-BTC, then the newly issued token (no asset amount).
    state_out.witness = token_proofs(
        token,
        &d.cfg.abf[0],
        &t.spk,
        &[(d.cfg.fee_asset, [0; 32]), (token, [0; 32])],
    );
    let outputs = vec![
        state_out,
        explicit_out(d.cfg.fee_asset, change, change_spk),
        TxOut::new_fee(fee, d.cfg.fee_asset),
    ];
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: issuance(&[0; 32], &d.contract, None, Some(1)),
            witness: TxInWitness::default(),
        }],
        output: outputs,
    };
    if let Err(e) = tx.verify_tx_amt_proofs(&Secp256k1::new(), &[utxo.clone()]) {
        return Err(format!("Elements amount proofs: {:?}", e));
    }
    g.need(
        true,
        "Elements amount, surjection and range proofs verify (rust-elements)",
    )?;
    g.need(
        conf_parts(&serialize(&tx.output[0].asset)) == d.constants["token_a"]
            && conf_parts(&serialize(&tx.output[0].value)) == d.constants["token_value"],
        "state output commitments = token constants compiled into both leaves (phase A)",
    )?;
    g.need(
        tx.output.iter().skip(1).all(|o| {
            explicit_of(o)
                .map(|(x, _)| x == d.cfg.fee_asset)
                .unwrap_or(false)
        }),
        "only output 0 can hold the token; the other outputs are explicit L-BTC",
    )?;
    let weight = weight_with_p2wpkh(&tx, &[0]);
    g.need(weight < STANDARD_WEIGHT, "standard weight")?;
    g.need(
        fee >= fee_floor(weight),
        "fee covers 0.1 sat/vB at the estimated signed weight",
    )?;
    std::fs::write(&a[6], serialize_hex(&tx)).map_err(|e| e.to_string())?;
    Ok(json!({
        "local_test_only": local_test || !d.deployable,
        "txid": tx.txid().to_string(), "state_outpoint": format!("{}:0", tx.txid()),
        "state_address": t.address, "state_script_pubkey": hex(t.spk.as_bytes()), "state": s.json(), "token_phase": 0,
        "funding_outpoint": format!("{}:{}", outpoint.txid, outpoint.vout), "funding_value": value,
        "fee": fee, "change": change,
        "weight_unsigned": tx.weight(), "weight_estimate": weight, "unsigned_inputs": [0],
        "signing": "input 0 spends the operator's funding output: sign it with that wallet (SIGHASH_ALL); \
                    the txid does not change",
        "path": a[6],
    }))
}

/// A public bootstrap transaction, checked against the manifest: the bridge asset's only reissuance token
/// went into the state UTXO of the manifest's leaves and initial state.  The escrow pins the asset id but
/// cannot see where its token went; this is that check, for anyone holding the manifest.
fn check_bootstrap(a: &[String], g: &mut Gates) -> Report {
    let d = load(&a[0], g)?;
    let s = State::load(&a[1])?;
    g.need(
        s.claimed == Claimed::none() && s.acc == empty_accumulator(),
        "initial state: nothing claimed, empty accumulator",
    )?;
    let tx = read_tx(&a[2])?;
    let t = state_tree(&d, &s.hash(), g)?;
    let token = d.cfg.token();
    g.need(
        !tx.input.is_empty() && tx.input[0].previous_output == d.funding,
        "input 0 spends the funding outpoint the bridge asset derives from",
    )?;
    // Zero blinding nonce: a new issuance; its entropy field is the contract hash; no asset; one explicit token.
    g.need(
        tx.input[0].asset_issuance == issuance(&[0; 32], &d.contract, None, Some(1)),
        "input 0 is a new issuance of no asset and exactly one explicit token under the manifest's contract hash",
    )?;
    let derived =
        AssetId::generate_asset_entropy(d.funding, ContractHash::from_byte_array(d.contract));
    g.need(
        AssetId::reissuance_token_from_entropy(derived, false) == token,
        "that issuance's reissuance token is the bridge token",
    )?;
    g.need(
        tx.input.iter().skip(1).all(|i| !i.has_issuance()),
        "no other input issues anything",
    )?;
    g.need(
        !tx.output.is_empty() && tx.output[0].script_pubkey == t.spk,
        "output 0 pays the state UTXO of the manifest's leaves and initial state",
    )?;
    g.need(
        tx.output[0].asset == token_asset(token, &d.cfg.abf[0])
            && tx.output[0].value == unit_value(token),
        "output 0 holds the token under public blinding A with value commitment 1 * H(token)",
    )?;
    // The token supply is exactly one, so with every other output explicit L-BTC it can only be in output 0.
    g.need(
        tx.output.iter().skip(1).all(|o| {
            explicit_of(o)
                .map(|(x, _)| x == d.cfg.fee_asset)
                .unwrap_or(false)
        }),
        "every other output is explicit L-BTC",
    )?;
    Ok(json!({
        "txid": tx.txid().to_string(), "state_outpoint": format!("{}:0", tx.txid()), "state_address": t.address,
        "bridge_asset_internal": hex(&asset_bytes(d.cfg.asset())), "bridge_asset_display": d.cfg.asset().to_string(),
        "funding_outpoint": format!("{}:{}", d.funding.txid, d.funding.vout), "deployable": d.deployable,
        "note": "also confirm the transaction is in Liquid's chain, \
                 and BridgeEscrow.BRIDGE_ASSET() = bridge_asset_internal",
    }))
}

/// Compile a proof witness without transaction inputs, outputs, fee data or wallet access.
fn compile_update(a: &[String], g: &mut Gates) -> Report {
    let text = std::fs::read_to_string(&a[0]).map_err(|e| e.to_string())?;
    let wmap = witness::try_map(&read_json(&a[1])?)?;
    let program = Program::from_str(&text)?;
    let cmr = program.try_cmr()?;
    let (code, witness) = program.compile(&wmap)?;
    let decoded = Program::from_encoded(&code, &witness)?;
    g.need(
        decoded.try_cmr()? == cmr,
        "compiled program CMR survives canonical encoding",
    )?;
    let compiled =
        json!({"program_hex": hex(&code), "witness_hex": hex(&witness), "cmr": hex(&cmr)});
    std::fs::write(&a[2], compiled.to_string()).map_err(|e| e.to_string())?;
    Ok(
        json!({"cmr": hex(&cmr), "program_bytes": code.len(), "witness_bytes": witness.len(), "path": a[2]}),
    )
}

fn update(a: &[String], local_test: bool, g: &mut Gates) -> Report {
    let input = json!({
        "manifest": read_json(&a[0])?,
        "program": std::fs::read_to_string(&a[1]).map_err(|e| e.to_string())?,
        "witness": read_json(&a[2])?, "state": read_json(&a[3])?,
        "new_state": read_json(&a[4])?,
        "state_tx_hex": std::fs::read_to_string(&a[5]).map_err(|e| e.to_string())?,
        "state_vout": parse::<u32>(&a[6], "state vout")?,
        "fee_tx_hex": std::fs::read_to_string(&a[7]).map_err(|e| e.to_string())?,
        "fee_vout": parse::<u32>(&a[8], "fee vout")?,
    });
    let mut report = update_from_json(&input, local_test, g)?;
    std::fs::write(
        &a[9],
        report["raw_tx"]
            .as_str()
            .ok_or("builder raw transaction missing")?,
    )
    .map_err(|e| e.to_string())?;
    report.as_object_mut().unwrap().remove("raw_tx");
    report["path"] = json!(a[9]);
    Ok(report)
}

fn update_compiled(a: &[String], local_test: bool, g: &mut Gates) -> Report {
    let input = json!({
        "manifest": read_json(&a[0])?, "compiled_program": read_json(&a[1])?,
        "state": read_json(&a[2])?, "new_state": read_json(&a[3])?,
        "state_tx_hex": std::fs::read_to_string(&a[4]).map_err(|e| e.to_string())?,
        "state_vout": parse::<u32>(&a[5], "state vout")?,
        "fee_tx_hex": std::fs::read_to_string(&a[6]).map_err(|e| e.to_string())?,
        "fee_vout": parse::<u32>(&a[7], "fee vout")?,
    });
    let mut report = update_from_json(&input, local_test, g)?;
    std::fs::write(
        &a[8],
        report["raw_tx"]
            .as_str()
            .ok_or("builder raw transaction missing")?,
    )
    .map_err(|e| e.to_string())?;
    report.as_object_mut().unwrap().remove("raw_tx");
    report["path"] = json!(a[8]);
    Ok(report)
}

fn update_from_json(input: &Json, local_test: bool, g: &mut Gates) -> Report {
    let d = deployment_from_json(&input["manifest"], g)?;
    require_deployable(&d, local_test, g)?;
    let (program, wmap) = if let Some(compiled) = input.get("compiled_program") {
        let bytes = |name: &str| {
            let value = compiled[name]
                .as_str()
                .ok_or_else(|| format!("compiled_program.{} missing", name))?;
            if value.len() > MAX_TX_HEX {
                return Err(format!("compiled_program.{} exceeds size limit", name));
            }
            parse_hex(value)
        };
        (
            Program::from_encoded(&bytes("program_hex")?, &bytes("witness_hex")?)?,
            Default::default(),
        )
    } else {
        (
            Program::from_str(input["program"].as_str().ok_or("program missing")?)?,
            witness::try_map(&input["witness"])?,
        )
    };
    let cmr = program.try_cmr()?;
    g.need(
        cmr == d.update_cmr,
        "program CMR = the update leaf CMR committed in the state tree",
    )?;
    let old = State::from_json(&input["state"])?;
    let new = State::from_json(&input["new_state"])?;
    g.need(
        new.claimed == old.claimed && new.head > old.head,
        "successor keeps the claimed set and root and advances the finalized head",
    )?;
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
    let t = state_tree(&d, &old.hash(), g)?;
    g.need(
        state_utxo.script_pubkey == t.spk,
        "spent output = state UTXO of the given old state under the manifest's leaves",
    )?;
    let token = d.cfg.token();
    let phase = token_phase(&d, &state_utxo)
        .ok_or("spent output does not hold the bridge token under blinding A or B")?;
    g.need(
        state_utxo.value == unit_value(token),
        "spent token value commitment = 1 * H(token)",
    )?;
    let (fee_asset, fee) = explicit_of(&fee_utxo).ok_or("fee input must be explicit")?;
    g.need(
        fee_asset == d.cfg.fee_asset,
        "fee input is explicit Liquid testnet L-BTC",
    )?;
    // The harness's update plan, over the real outpoints (internal byte order) and states.
    let plan = Plan::honest(
        &d.cfg,
        &json!({
            "state_txid": hex(&state_tx.txid().to_byte_array()), "state_vout": state_vout,
            "fee_txid": hex(&fee_tx.txid().to_byte_array()), "fee_vout": fee_vout, "fee_value": fee, "old_abf": phase,
            "sibling": hex(&tapleaf_simplicity(&d.claim_cmr)),
            "head": old.head, "header": hex(&old.header), "committee": hex(&old.committee),
            "acc": hex(&old.acc), "claimed_root": hex(&old.claimed.root),
            "new_head": new.head, "new_header": hex(&new.header), "sync": hex(&new.committee), "new_acc": hex(&new.acc),
        }),
    );
    let mut built = bridge::build(&d.cfg, &plan, &cmr);
    g.need(
        built.ix == 0 && built.tx.input.len() == 2 && built.tx.output.len() == 2,
        "update shape: inputs [state, fee], outputs [successor, fee]",
    )?;
    g.need(
        same_utxo(&built.utxos[0], &state_utxo),
        "planned state input = the real state UTXO",
    )?;
    // the real fee output replaces the harness's test key output; its signature is the relayer's
    built.utxos[1] = fee_utxo.clone();
    built.tx.input[1].witness = TxInWitness::default();
    g.need(
        built.genesis == d.cfg.genesis,
        "environment genesis = Liquid testnet",
    )?;
    g.need(
        built.control.serialize() == t.update_control.serialize(),
        "update control block = state tree",
    )?;
    let succ = state_tree(&d, &new.hash(), g)?;
    g.need(
        built.tx.output[0].script_pubkey == succ.spk,
        "output 0 = successor state UTXO (same leaves, proven store and accumulator)",
    )?;
    g.need(
        token_phase(&d, &built.tx.output[0]) == Some(1 - phase)
            && built.tx.output[0].value == unit_value(token),
        "successor token blinding alternates; value commitment stays 1 * H(token)",
    )?;
    g.need(
        explicit_of(&built.tx.output[1]) == Some((d.cfg.fee_asset, fee))
            && built.tx.output[1].script_pubkey.as_bytes().is_empty(),
        "output 1 = explicit L-BTC fee of the whole fee input",
    )?;
    if let Err(e) = built
        .tx
        .verify_tx_amt_proofs(&Secp256k1::new(), &built.utxos)
    {
        return Err(format!("Elements amount proofs: {:?}", e));
    }
    g.need(
        true,
        "Elements amount, surjection and range proofs verify (rust-elements)",
    )?;
    let env = environment(
        &built.tx,
        &built.utxos,
        0,
        &cmr,
        &built.control,
        built.genesis,
    );
    let r = program
        .execute(&env, &wmap)
        .map_err(|(stage, e)| format!("update leaf rejected the spend ({}): {}", stage, e))?;
    g.need(
        true,
        "update leaf pruned, executed, encoded, decoded and executed again (simplicity-lang 0.9)",
    )?;
    let items = vec![
        r.witness.clone(),
        r.program.clone(),
        cmr.to_vec(),
        built.control.serialize(),
    ];
    let budget = (stack_bytes(&items) as u64 + 50) * 1000;
    g.need(
        r.cost <= budget,
        "decoded cost within the input's witness budget",
    )?;
    built.tx.input[0].witness.script_witness = Witness::from_slice(&items);
    let weight = weight_with_p2wpkh(&built.tx, &[1]);
    g.need(
        weight < STANDARD_WEIGHT,
        "standard weight (< 400,000 WU) with a P2WPKH fee signature",
    )?;
    g.need(fee >= fee_floor(weight), "fee covers 0.1 sat/vB")?;
    g.need(
        fee <= fee_ceiling(weight),
        "fee input at most 100x the relay floor (the leaf spends it whole as fee; split a larger UTXO)",
    )?;

    Ok(json!({
        "local_test_only": local_test || !d.deployable,
        "txid": built.tx.txid().to_string(), "successor_outpoint": format!("{}:0", built.tx.txid()),
        "successor_address": succ.address, "successor_state": new.json(), "token_phase": 1 - phase,
        "cmr": hex(&cmr), "cost_mwu": r.cost, "budget_mwu": budget,
        "program_bytes": r.program.len(), "witness_bytes": r.witness.len(), "cells": r.cells, "frames": r.frames,
        "weight_unsigned": built.tx.weight(), "weight_estimate": weight, "fee": fee,
        "unsigned_inputs": [1], "raw_tx": serialize_hex(&built.tx),
    }))
}

fn verify(a: &[String], g: &mut Gates) -> Report {
    let tx = read_tx(&a[0])?;
    let ix: usize = parse(&a[1], "input index")?;
    g.need(ix < tx.input.len(), "input index")?;
    let prevs = a[2..]
        .iter()
        .map(|p| read_tx(p))
        .collect::<Result<Vec<_>, _>>()?;
    let mut utxos = Vec::new();
    for i in &tx.input {
        let p = prevs
            .iter()
            .find(|p| p.txid() == i.previous_output.txid)
            .ok_or_else(|| format!("previous transaction {} not given", i.previous_output.txid))?;
        utxos.push(
            p.output
                .get(i.previous_output.vout as usize)
                .cloned()
                .ok_or("previous output index")?,
        );
    }
    let items: Vec<Vec<u8>> = tx.input[ix]
        .witness
        .script_witness
        .iter()
        .map(|b| b.to_vec())
        .collect();
    g.need(
        items.len() == 4,
        "Simplicity witness stack: [witness, program, CMR, control block]",
    )?;
    let cmr: [u8; 32] = items[2]
        .as_slice()
        .try_into()
        .map_err(|_| "CMR is not 32 bytes".to_string())?;
    let nums = control_commits(&items[3], &cmr, &utxos[ix].script_pubkey)?;
    g.need(
        true,
        "control block commits to the spent output key (leaf version 0xbe)",
    )?;
    let control =
        ControlBlock::from_slice(&items[3]).map_err(|e| format!("control block: {:?}", e))?;
    let decoded = RedeemNode::decode::<_, _, Elements>(
        BitIter::from(items[1].iter().cloned()),
        BitIter::from(items[0].iter().cloned()),
    )
    .map_err(|e| format!("decode: {}", e))?;
    g.need(
        decoded.cmr().to_byte_array() == cmr,
        "decoded program CMR = the CMR in the witness stack",
    )?;
    let env = environment(
        &tx,
        &utxos,
        ix as u32,
        &cmr,
        &control,
        BlockHash::from_str(TESTNET_GENESIS).unwrap(),
    );
    BitMachine::for_program(&decoded)
        .map_err(|e| format!("bit machine: {}", e))?
        .exec(&decoded, &env)
        .map_err(|e| format!("execution: {}", e))?;
    g.need(
        true,
        "program executes against the transaction (simplicity-lang 0.9, Liquid testnet genesis)",
    )?;
    // Cost's Display is its milliweight as a decimal integer (the form update and claim reports carry).
    let cost: u64 = decoded
        .bounds()
        .cost
        .to_string()
        .parse()
        .map_err(|e| format!("decoded cost: {:?}", e))?;
    let budget = (stack_bytes(&items) as u64 + 50) * 1000;
    g.need(
        cost <= budget,
        "decoded cost within the input's witness budget",
    )?;
    if let Err(e) = tx.verify_tx_amt_proofs(&Secp256k1::new(), &utxos) {
        return Err(format!("Elements amount proofs: {:?}", e));
    }
    g.need(true, "Elements amount, surjection and range proofs verify")?;
    let unsigned: Vec<usize> = (0..tx.input.len())
        .filter(|&i| i != ix && tx.input[i].witness.script_witness.len() == 0)
        .collect();
    Ok(json!({
        "txid": tx.txid().to_string(), "input": ix, "cmr": hex(&cmr), "internal_key_is_nums": nums,
        "cost_mwu": cost, "budget_mwu": budget, "cells": decoded.bounds().extra_cells, "weight": tx.weight(),
        "inputs_without_witness": unsigned,
    }))
}

/// A state as the public spends show it.  lc commits to the light-client store (head, header, committee); an
/// update's witness carries the new lc and head but not header and committee, so `store` is known only from the
/// start record until the first update.  `exec` is the execution state root and block the accumulator was proven at.
#[derive(Clone)]
struct Recovered {
    lc: [u8; 32],
    acc: [u8; 32],
    claimed: Claimed,
    head: u64,
    store: Option<([u8; 32], [u8; 32])>,
    exec: Option<([u8; 32], u64)>,
}

impl Recovered {
    fn hash(&self) -> [u8; 32] {
        bridge::state_hash(&self.lc, &self.acc, &self.claimed.root)
    }

    fn json(&self) -> Json {
        let mut j = json!({
            "head": self.head, "lc": hex(&self.lc), "acc": hex(&self.acc), "state_hash": hex(&self.hash()),
        });
        self.claimed.json_into(&mut j);
        if let Some((header, committee)) = self.store {
            j["header"] = json!(hex(&header));
            j["committee"] = json!(hex(&committee));
        }
        if let Some((root, block)) = self.exec {
            j["exec_root"] = json!(hex(&root));
            j["exec_block"] = json!(block);
        }
        j
    }
}

/// The state script of `state_hash` under the manifest's leaves, by the harness's taproot code (`state_tree`
/// cross-checks it against TaprootBuilder).
fn state_spk(d: &Deployment, state_hash: &[u8; 32]) -> Script {
    tap(
        &d.update_cmr,
        &[
            tapleaf_simplicity(&d.claim_cmr),
            tapleaf_simplicity(state_hash),
        ],
    )
    .spk
}

/// The bits of a Simplicity witness in the order the bit machine reads them, most significant bit first.
fn witness_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect()
}

fn take<const N: usize>(bits: &[bool], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    for (byte, chunk) in out.iter_mut().zip(bits[at..at + 8 * N].chunks(8)) {
        *byte = chunk.iter().fold(0u8, |v, &b| (v << 1) | b as u8);
    }
    out
}

/// What an update leaf's witness opens after the spent state's fields (tools/sg16/bridge-guest/liquid.py FIELDS:
/// lc, acc, sibling, new_lc, new_acc, exec_root, claimed_root as 256-bit words, then exec_block, new_head as 64-bit
/// words, big-endian, one balanced product, so contiguous in the encoding).
struct UpdateFields {
    new_lc: [u8; 32],
    new_acc: [u8; 32],
    exec_root: [u8; 32],
    claimed_root: [u8; 32],
    exec_block: u64,
    new_head: u64,
}

const FIELD_BITS: usize = 7 * 256 + 2 * 64;

/// The update fields in a confirmed update's witness.  The leaf checks lc, acc and sibling against the spent output
/// (tappath_hash), so they are the spent state's lc and acc and the claim leaf's hash; those 768 bits locate the
/// fields, at their first occurrence.  The witness is the proof's values, then the fields, then padding blocks
/// (sg16/covenant.py BridgeVerifier) that the leaf hashes and drops: anyone who relays an update can rewrite the
/// padding, these 768 bits included, without changing its txid, but cannot make the proof's values hold them.  The
/// leaf also verified the proof of exactly these values, and output 0's script, checked by the caller, commits
/// new_lc and new_acc.
fn update_fields(
    witness: &[u8],
    old: &Recovered,
    sibling: &[u8; 32],
) -> Result<UpdateFields, String> {
    let bits = witness_bits(witness);
    let anchor = witness_bits(&[&old.lc[..], &old.acc[..], &sibling[..]].concat());
    let hit = (0..(bits.len() + 1).saturating_sub(FIELD_BITS))
        .find(|&o| bits[o..o + anchor.len()] == anchor[..])
        .ok_or("the witness does not hold the spent state's lc, acc and claim leaf hash")?;
    let o = hit + anchor.len();
    let u = |k: usize| u64::from_be_bytes(take(&bits, o + 4 * 256 + 64 * k));
    Ok(UpdateFields {
        new_lc: take(&bits, o),
        new_acc: take(&bits, o + 256),
        exec_root: take(&bits, o + 512),
        claimed_root: take(&bits, o + 768),
        exec_block: u(0),
        new_head: u(1),
    })
}

/// The deposit a confirmed claim paid, and the claimed set after it.  The claim leaf's witness holds the index as a
/// 64-bit big-endian word (INDEX, below 2^32 because the leaf folds 32 bits of it), so it is one of the witness's
/// 64-bit windows; which one depends on the compiled program's witness order, not read here.  Each window value below
/// 2^32 that is not yet claimed is a candidate, and `makes_output` says whether the successor with that set is output
/// 0.  Exactly one candidate must: two would be two claimed sets with one root, a SHA-256 collision.  The leaf, run
/// by the node, already checked that the index was unclaimed and below the proven count.
fn claim_index(
    witness: &[u8],
    claimed: &Claimed,
    makes_output: impl Fn(&Claimed) -> bool,
) -> Result<(u64, Claimed), String> {
    let bits = witness_bits(witness);
    let candidates: BTreeSet<u64> = (0..bits.len().saturating_sub(63))
        .map(|o| u64::from_be_bytes(take(&bits, o)))
        .filter(|&i| i >> bridge::CLAIMED_DEPTH == 0 && !claimed.indices.contains(&i))
        .collect();
    let mut hits = Vec::new();
    for i in candidates {
        let next = claimed.with(i)?;
        if makes_output(&next) {
            hits.push((i, next));
        }
    }
    match hits.len() {
        1 => Ok(hits.pop().expect("one hit")),
        n => Err(format!(
            "the witness names {} unclaimed deposits whose claimed tree makes output 0, not one",
            n
        )),
    }
}

/// The state that a chain of public spends leads to (see the source header).  Each spend must spend the previous
/// state output 0 at its input 0 with the update or the claim leaf, which its control block commits to the spent
/// output; output 0 must then be the state UTXO of what the spend reveals, holding the token at the other blinding.
/// That the transactions are confirmed, in this order, and that the last state output is unspent, is the caller's
/// check against Liquid.
fn recover(a: &[String], g: &mut Gates) -> Report {
    let d = load(&a[0], g)?;
    let start = State::load(&a[1])?;
    let start_tx = read_tx(&a[2])?;
    let token = d.cfg.token();
    let mut cur = Recovered {
        lc: start.lc(),
        acc: start.acc,
        claimed: start.claimed.clone(),
        head: start.head,
        store: Some((start.header, start.committee)),
        exec: None,
    };
    let mut utxo = start_tx
        .output
        .first()
        .cloned()
        .ok_or("the state transaction has no output 0")?;
    g.need(
        utxo.script_pubkey == state_spk(&d, &cur.hash()),
        "output 0 of the state transaction = the state UTXO of the given state",
    )?;
    let mut phase = token_phase(&d, &utxo).ok_or(
        "output 0 of the state transaction does not hold the bridge token under blinding A or B",
    )?;
    g.need(
        utxo.value == unit_value(token),
        "its token value commitment = 1 * H(token)",
    )?;
    let mut outpoint = OutPoint::new(start_tx.txid(), 0);
    let sibling = tapleaf_simplicity(&d.claim_cmr);
    let mut chain =
        vec![json!({"txid": start_tx.txid().to_string(), "kind": "start", "state": cur.json()})];
    for (k, path) in a[3..].iter().enumerate() {
        let tx = read_tx(path)?;
        let at = |what: &str| format!("spend {} ({}): {}", k + 1, tx.txid(), what);
        g.need(
            tx.input.first().map(|i| i.previous_output) == Some(outpoint),
            &at("input 0 spends the previous state output 0"),
        )?;
        let items: Vec<Vec<u8>> = tx.input[0]
            .witness
            .script_witness
            .iter()
            .map(|b| b.to_vec())
            .collect();
        g.need(
            items.len() == 4,
            &at("Simplicity witness stack: [witness, program, CMR, control block]"),
        )?;
        let cmr: [u8; 32] = items[2]
            .as_slice()
            .try_into()
            .map_err(|_| at("CMR is not 32 bytes"))?;
        control_commits(&items[3], &cmr, &utxo.script_pubkey).map_err(|e| at(e.as_str()))?;
        g.need(
            true,
            &at("control block commits its leaf to the spent state output"),
        )?;
        let out = tx
            .output
            .first()
            .cloned()
            .ok_or_else(|| at("no output 0"))?;
        let (kind, deposit, next) = if cmr == d.claim_cmr {
            let (index, claimed) = claim_index(&items[0], &cur.claimed, |c| {
                let next = Recovered {
                    claimed: c.clone(),
                    ..cur.clone()
                };
                out.script_pubkey == state_spk(&d, &next.hash())
            })
            .map_err(|e| at(e.as_str()))?;
            g.need(
                true,
                &at("claim of one unclaimed deposit: its index, from the witness, sets the slot output 0 commits"),
            )?;
            (
                "claim",
                Some(index),
                Recovered {
                    claimed,
                    ..cur.clone()
                },
            )
        } else if cmr == d.update_cmr {
            let f = update_fields(&items[0], &cur, &sibling).map_err(|e| at(e.as_str()))?;
            g.need(
                f.claimed_root == cur.claimed.root && f.new_head > cur.head,
                &at("update witness keeps the claimed root and advances the head"),
            )?;
            let next = Recovered {
                lc: f.new_lc,
                acc: f.new_acc,
                claimed: cur.claimed.clone(),
                head: f.new_head,
                store: None,
                exec: Some((f.exec_root, f.exec_block)),
            };
            ("update", None, next)
        } else {
            return Err(at(
                "input 0 runs neither the manifest's update leaf nor its claim leaf",
            ));
        };
        g.need(
            out.script_pubkey == state_spk(&d, &next.hash()),
            &at("output 0 = the state UTXO of the state the spend reveals"),
        )?;
        g.need(
            token_phase(&d, &out) == Some(1 - phase) && out.value == unit_value(token),
            &at("output 0 holds the token, its blinding alternated"),
        )?;
        let mut link = json!({"txid": tx.txid().to_string(), "kind": kind, "state": next.json()});
        if let Some(index) = deposit {
            link["deposit"] = json!(index);
        }
        chain.push(link);
        phase = 1 - phase;
        outpoint = OutPoint::new(tx.txid(), 0);
        utxo = out;
        cur = next;
    }
    let t = state_tree(&d, &cur.hash(), g)?;
    g.need(
        t.spk == utxo.script_pubkey,
        "the last state script, rebuilt by TaprootBuilder = the last state output",
    )?;
    Ok(json!({
        "chain": chain, "state": cur.json(), "store_known": cur.store.is_some(),
        "outpoint": format!("{}:0", outpoint.txid),
        "address": t.address, "script_pubkey": hex(utxo.script_pubkey.as_bytes()), "token_phase": phase,
        "note": "check on Liquid that every transaction is confirmed, each spending the previous one's output 0, \
                 and that the outpoint is unspent",
    }))
}

fn synthetic_funding(a: &[String], g: &mut Gates) -> Report {
    let value: u64 = parse(&a[0], "value")?;
    let (spk, _) = bridge::p2wpkh(&SecretKey::from_slice(&bridge::FEE_SECRET).unwrap());
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0x5f; 32]), 0),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: Default::default(),
            witness: TxInWitness::default(),
        }],
        output: vec![explicit_out(
            AssetId::from_str(TESTNET_LBTC).unwrap(),
            value,
            spk,
        )],
    };
    std::fs::write(&a[1], serialize_hex(&tx)).map_err(|e| e.to_string())?;
    g.need(true, "synthetic funding written")?;
    Ok(
        json!({"synthetic": "SYNTHETIC: spends a fictional outpoint; never valid on any chain; local tests only",
              "txid": tx.txid().to_string(), "vout": 0, "value": value, "path": a[1]}),
    )
}

/// An input or output index as an operator types it: canonical decimal, so neither "01" nor "+1" names index 1.
fn index(s: &str, what: &str) -> Result<u32, String> {
    let n: u32 = parse(s, what)?;
    if n.to_string() != s {
        return Err(format!(
            "{}: {:?} is not a canonical decimal index",
            what, s
        ));
    }
    Ok(n)
}

fn txid_cmd(a: &[String], g: &mut Gates) -> Report {
    let tx = read_tx(&a[0])?;
    g.need(true, "one Elements transaction, no bytes left over")?;
    Ok(json!({"txid": tx.txid().to_string(), "path": a[0]}))
}

fn output_cmd(a: &[String], g: &mut Gates) -> Report {
    let tx = read_tx(&a[0])?;
    g.need(true, "one Elements transaction, no bytes left over")?;
    let vout = index(&a[1], "vout")?;
    let o = tx.output.get(vout as usize).ok_or_else(|| {
        format!(
            "{}: no output {}; the transaction has {}",
            a[0],
            vout,
            tx.output.len()
        )
    })?;
    g.need(true, "the output exists")?;
    let asset = match o.asset {
        Asset::Explicit(asset) => Some(asset.to_string()),
        _ => None,
    };
    let value = match o.value {
        Value::Explicit(value) => Some(value),
        _ => None,
    };
    let lbtc = AssetId::from_str(TESTNET_LBTC).unwrap();
    Ok(json!({
        "txid": tx.txid().to_string(), "vout": vout, "outputs": tx.output.len(),
        "script_pubkey": hex(o.script_pubkey.as_bytes()), "asset": asset, "value": value,
        "explicit_lbtc": explicit_of(o).map(|(asset, _)| asset) == Some(lbtc),
        "path": a[0],
    }))
}

fn input_cmd(a: &[String], g: &mut Gates) -> Report {
    let tx = read_tx(&a[0])?;
    g.need(true, "one Elements transaction, no bytes left over")?;
    let vin = index(&a[1], "vin")?;
    let i = tx.input.get(vin as usize).ok_or_else(|| {
        format!(
            "{}: no input {}; the transaction has {}",
            a[0],
            vin,
            tx.input.len()
        )
    })?;
    g.need(true, "the input exists")?;
    let spent = i.previous_output;
    Ok(json!({
        "txid": tx.txid().to_string(), "vin": vin, "inputs": tx.input.len(),
        "previous_output": format!("{}:{}", spent.txid, spent.vout),
        "is_pegin": i.is_pegin, "has_issuance": i.has_issuance(),
        "path": a[0],
    }))
}

pub fn cli_main() {
    let all: Vec<String> = std::env::args().skip(1).collect();
    let local_test = all.iter().any(|x| x.as_str() == "--local-test");
    let a: Vec<String> = all
        .into_iter()
        .filter(|x| x.as_str() != "--local-test")
        .collect();
    let mut g = Gates::default();
    let result = match a.first().map(String::as_str) {
        Some("params") if a.len() == 5 => params(&a[1..], &mut g),
        Some("cmr") if a.len() == 2 => cmr_cmd(&a[1..], &mut g),
        Some("tree") if a.len() == 3 => tree_cmd(&a[1..], &mut g),
        Some("bootstrap") if a.len() == 8 => bootstrap(&a[1..], local_test, &mut g),
        Some("check-bootstrap") if a.len() == 4 => check_bootstrap(&a[1..], &mut g),
        Some("compile-update") if a.len() == 4 => compile_update(&a[1..], &mut g),
        Some("update-compiled") if a.len() == 10 => update_compiled(&a[1..], local_test, &mut g),
        Some("update") if a.len() == 11 => update(&a[1..], local_test, &mut g),
        Some("verify") if a.len() >= 4 => verify(&a[1..], &mut g),
        Some("recover") if a.len() >= 4 => recover(&a[1..], &mut g),
        Some("synthetic-funding") if a.len() == 3 => synthetic_funding(&a[1..], &mut g),
        Some("txid") if a.len() == 2 => txid_cmd(&a[1..], &mut g),
        Some("output") if a.len() == 3 => output_cmd(&a[1..], &mut g),
        Some("input") if a.len() == 3 => input_cmd(&a[1..], &mut g),
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

/// The manifest schema, a state's lc, claimed root and state hash against the shared protocol vectors
/// (vectors/protocol.json); malformed claimed sets; and the index a claim's witness names.
#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Json {
        read_json(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../../vectors/protocol.json"
        ))
        .unwrap()
    }

    fn claimed_json(indices: Json, root: [u8; 32]) -> Json {
        json!({"claimed": indices, "claimed_root": hex(&root)})
    }

    fn root_of(indices: &[u64]) -> [u8; 32] {
        bridge::claimed_root(&indices.iter().copied().collect()).unwrap()
    }

    #[test]
    fn schema_and_state_lc_are_the_vectors() {
        let v = vectors();
        assert_eq!(v["tags"]["manifest"].as_str(), Some(SCHEMA));
        let cases = v["lc"].as_array().unwrap();
        assert!(!cases.is_empty(), "vectors: no lc case");
        for (i, c) in cases.iter().enumerate() {
            let want = word(&c["lc"], "lc").unwrap_or_else(|_| {
                panic!(
                    "lc[{i}].lc is not recorded: run node vectors/record.mjs and review the result"
                )
            });
            let s = State {
                head: num(&c["slot"], "slot").unwrap(),
                header: word(&c["header"], "header").unwrap(),
                committee: word(&c["committee"], "committee").unwrap(),
                acc: [0; 32],
                claimed: Claimed::none(),
            };
            assert_eq!(s.lc(), want, "lc[{i}]");
        }
    }

    /// A record's claimed set, listed in ascending order, and its state hash are the vectors'.  The vectors list
    /// indices in claim order, which the root does not depend on.
    #[test]
    fn state_hash_is_the_vectors() {
        let v = vectors();
        let cases = v["state_hash"].as_array().unwrap();
        assert!(!cases.is_empty(), "vectors: no state_hash case");
        for (i, c) in cases.iter().enumerate() {
            let mut list: Vec<u64> = c["indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap())
                .collect();
            list.sort_unstable();
            let root = word(&c["claimed_root"], "claimed_root").unwrap();
            let claimed = Claimed::load(&claimed_json(json!(list), root)).unwrap();
            let lc = word(&c["lc"], "lc").unwrap();
            let acc = word(&c["acc"], "acc").unwrap();
            assert_eq!(
                bridge::state_hash(&lc, &acc, &claimed.root),
                word(&c["state_hash"], "state_hash").unwrap(),
                "state_hash[{i}]"
            );
        }
    }

    /// A malformed claimed set or root is refused: never read as some other set.
    #[test]
    fn malformed_claimed_records_are_refused() {
        let root = root_of(&[0, 2]);
        for (what, j, fragment) in [
            (
                "a non-list claimed field",
                json!({"claimed": 2, "claimed_root": hex(&root)}),
                "a list of deposit indices",
            ),
            (
                "indices out of order",
                claimed_json(json!([2, 0]), root),
                "strictly ascending",
            ),
            (
                "a repeated index",
                claimed_json(json!([0, 0, 2]), root),
                "strictly ascending",
            ),
            (
                "an index outside the tree",
                claimed_json(json!([1u64 << 32]), root_of(&[])),
                "outside the claimed tree",
            ),
            (
                "an index that is not an integer",
                claimed_json(json!(["0"]), root),
                "integer",
            ),
            (
                "a root of another set",
                claimed_json(json!([0, 1]), root),
                "not the claimed tree's root",
            ),
            (
                "no root",
                json!({"claimed": [0, 2]}),
                "claimed_root missing",
            ),
            (
                "a short root",
                json!({"claimed": [0, 2], "claimed_root": "00".repeat(31)}),
                "not 32 bytes",
            ),
        ] {
            let e = Claimed::load(&j).expect_err(what);
            assert!(e.contains(fragment), "{what}: {e}");
        }
        assert_eq!(
            Claimed::load(&claimed_json(json!([0, 2]), root))
                .unwrap()
                .indices,
            BTreeSet::from([0, 2])
        );
    }

    /// A witness carrying `index` as a 64-bit word at an unaligned bit offset, among other words.
    fn witness_with(index: u64, at_bit: usize) -> Vec<u8> {
        let mut bits: Vec<bool> = witness_bits(&[0xa5u8; 40]);
        let word = witness_bits(&index.to_be_bytes());
        bits.splice(at_bit..at_bit, word);
        bits.extend(witness_bits(&[0x5au8; 40]));
        bits.resize(bits.len().div_ceil(8) * 8, false);
        bits.chunks(8)
            .map(|c| c.iter().fold(0u8, |v, &b| (v << 1) | b as u8))
            .collect()
    }

    #[test]
    fn a_claim_names_the_one_unclaimed_index_that_makes_output_0() {
        let claimed = Claimed::of(BTreeSet::from([0, 2])).unwrap();
        let want = claimed.with(5).unwrap();
        let (index, next) =
            claim_index(&witness_with(5, 13), &claimed, |c| c.root == want.root).unwrap();
        assert_eq!((index, next.indices), (5, BTreeSet::from([0, 2, 5])));
        // A lower index than claimed ones is found the same way: claims come in any order.
        let want = claimed.with(1).unwrap();
        assert_eq!(
            claim_index(&witness_with(1, 7), &claimed, |c| c.root == want.root)
                .unwrap()
                .0,
            1
        );
    }

    #[test]
    fn a_claim_of_a_claimed_slot_or_of_no_slot_is_refused() {
        let claimed = Claimed::of(BTreeSet::from([0, 2])).unwrap();
        // The output commits the set unchanged: a claimed slot set again.
        let e = claim_index(&witness_with(2, 9), &claimed, |c| c.root == claimed.root).unwrap_err();
        assert!(e.contains("0 unclaimed deposits"), "{e}");
        // The output commits a slot the witness does not name.
        let other = claimed.with(7).unwrap();
        let e = claim_index(&witness_with(5, 9), &claimed, |c| c.root == other.root).unwrap_err();
        assert!(e.contains("0 unclaimed deposits"), "{e}");
        // An output that two candidates would make is refused, not resolved by order.
        let e = claim_index(&witness_with(5, 9), &claimed, |_| true).unwrap_err();
        assert!(e.contains("not one"), "{e}");
    }

    /// An update leaf's fields from `old`: lc, acc and `sibling`, then `new_lc`, made-up new_acc and exec_root, the
    /// claimed root carried, exec_block 9,000,000 and `new_head`.
    fn field_bytes(
        old: &Recovered,
        sibling: &[u8; 32],
        new_lc: [u8; 32],
        new_head: u64,
    ) -> Vec<u8> {
        [
            &old.lc[..],
            &old.acc[..],
            &sibling[..],
            &new_lc[..],
            &[0x44; 32][..],
            &[0x55; 32][..],
            &old.claimed.root[..],
            &9_000_000u64.to_be_bytes()[..],
            &new_head.to_be_bytes()[..],
        ]
        .concat()
    }

    /// An update leaf's whole witness around `fields`, as the leaf lays it out: made-up proof values, the fields,
    /// then three 512-byte padding blocks, the second of which holds `padded` from bit 4,099 on, off every byte
    /// boundary.
    fn padded_witness(fields: &[u8], padded: &[u8]) -> Vec<u8> {
        let mut pad = witness_bits(&[0x3c; 3 * 512]);
        let copy = witness_bits(padded);
        pad.splice(4099..4099 + copy.len(), copy);
        let mut bits = witness_bits(&[0xc3; 900]);
        bits.extend(witness_bits(fields));
        bits.extend(pad);
        bits.chunks(8)
            .map(|c| c.iter().fold(0u8, |v, &b| (v << 1) | b as u8))
            .collect()
    }

    /// The leaf accepts any padding and the txid does not commit to it, so a relay can repeat the spent state's
    /// fields there, with another successor: the fields read are still the ones before the padding.
    #[test]
    fn padding_that_repeats_the_spent_fields_does_not_move_the_fields_read() {
        let old = Recovered {
            lc: [0x11; 32],
            acc: [0x22; 32],
            claimed: Claimed::none(),
            head: 100,
            store: None,
            exec: None,
        };
        let sibling = [0x33; 32];
        let read = |w: &[u8], old: &Recovered| {
            update_fields(w, old, &sibling).map(|f| {
                (
                    f.new_lc,
                    f.new_acc,
                    f.exec_root,
                    f.claimed_root,
                    f.exec_block,
                    f.new_head,
                )
            })
        };
        let fields = field_bytes(&old, &sibling, [0x66; 32], 200);
        let want = (
            [0x66; 32],
            [0x44; 32],
            [0x55; 32],
            old.claimed.root,
            9_000_000,
            200,
        );
        assert_eq!(read(&fields, &old), Ok(want));
        assert_eq!(read(&padded_witness(&fields, &[]), &old), Ok(want));
        assert_eq!(read(&padded_witness(&fields, &fields), &old), Ok(want));
        let forged = field_bytes(&old, &sibling, [0x77; 32], 201);
        assert_eq!(read(&padded_witness(&fields, &forged), &old), Ok(want));

        let other = Recovered {
            acc: [0x99; 32],
            ..old.clone()
        };
        let e = read(&padded_witness(&fields, &[]), &other).unwrap_err();
        assert!(e.contains("does not hold"), "{e}");
        let e = read(&fields[..fields.len() - 1], &old).unwrap_err();
        assert!(e.contains("does not hold"), "{e}");
    }

    /// `text` in a fresh file named for the test case.
    fn tx_file(case: &str, text: &str) -> String {
        let path =
            std::env::temp_dir().join(format!("sg16-testnet-{}-{}.hex", std::process::id(), case));
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// Output 0 explicit L-BTC to a P2WPKH, output 1 confidential, output 2 explicit in another asset.
    fn three_outputs() -> Transaction {
        let secp = Secp256k1::new();
        let lbtc = AssetId::from_str(TESTNET_LBTC).unwrap();
        let other = AssetId::from_str(&"77".repeat(32)).unwrap();
        let (spk, _) = bridge::p2wpkh(&SecretKey::from_slice(&bridge::FEE_SECRET).unwrap());
        let tweak = |b: u8| Tweak::from_slice(&[b; 32]).unwrap();
        let generator = Generator::new_blinded(&secp, lbtc.into_tag(), tweak(1));
        let confidential = TxOut {
            asset: Asset::Confidential(generator),
            value: Value::Confidential(PedersenCommitment::new(&secp, 5_000, tweak(2), generator)),
            nonce: Nonce::Null,
            script_pubkey: spk.clone(),
            witness: TxOutWitness::default(),
        };
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0x5f; 32]), 1),
                is_pegin: false,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                asset_issuance: Default::default(),
                witness: TxInWitness::default(),
            }],
            output: vec![
                explicit_out(lbtc, 120_000, spk),
                confidential,
                explicit_out(other, 7, Script::new()),
            ],
        }
    }

    #[test]
    fn txid_and_outputs_are_rust_elements_reading_of_the_file() {
        let tx = three_outputs();
        let path = tx_file("three-outputs", &format!("\n{}\n", serialize_hex(&tx)));
        let report = txid_cmd(&args(&[&path]), &mut Gates::default()).unwrap();
        assert_eq!(report["txid"], json!(tx.txid().to_string()));

        let output = |vout: &str| output_cmd(&args(&[&path, vout]), &mut Gates::default());
        let lbtc = output("0").unwrap();
        assert_eq!(lbtc["txid"], report["txid"]);
        assert_eq!(lbtc["outputs"], json!(3));
        assert_eq!(lbtc["asset"], json!(TESTNET_LBTC));
        assert_eq!(lbtc["value"], json!(120_000));
        assert_eq!(
            lbtc["script_pubkey"],
            json!(hex(tx.output[0].script_pubkey.as_bytes()))
        );
        assert_eq!(lbtc["explicit_lbtc"], json!(true));

        let confidential = output("1").unwrap();
        assert_eq!(confidential["asset"], Json::Null);
        assert_eq!(confidential["value"], Json::Null);
        assert_eq!(confidential["explicit_lbtc"], json!(false));

        let other = output("2").unwrap();
        assert_eq!(other["asset"], json!("77".repeat(32)));
        assert_eq!(other["script_pubkey"], json!(""));
        assert_eq!(other["explicit_lbtc"], json!(false));

        let e = output("3").unwrap_err();
        assert!(e.contains("no output 3; the transaction has 3"), "{e}");

        let input = |vin: &str| input_cmd(&args(&[&path, vin]), &mut Gates::default());
        let spend = input("0").unwrap();
        assert_eq!(spend["txid"], report["txid"]);
        assert_eq!(spend["inputs"], json!(1));
        assert_eq!(
            spend["previous_output"],
            json!(format!("{}:1", "5f".repeat(32)))
        );
        assert_eq!(spend["is_pegin"], json!(false));
        assert_eq!(spend["has_issuance"], json!(false));
        let e = input("1").unwrap_err();
        assert!(e.contains("no input 1; the transaction has 1"), "{e}");
    }

    /// An index is never read as another one, and a file is one transaction or nothing.
    #[test]
    fn malformed_indices_and_files_are_refused() {
        let hex_tx = serialize_hex(&three_outputs());
        let path = tx_file("indices", &hex_tx);
        for (vout, fragment) in [
            ("01", "canonical"),
            ("+1", "canonical"),
            ("-1", "cannot parse"),
            ("", "cannot parse"),
            ("1 ", "cannot parse"),
            ("4294967296", "cannot parse"),
        ] {
            let e = output_cmd(&args(&[&path, vout]), &mut Gates::default()).unwrap_err();
            assert!(e.contains(fragment), "vout {vout:?}: {e}");
            let e = input_cmd(&args(&[&path, vout]), &mut Gates::default()).unwrap_err();
            assert!(e.contains(fragment), "vin {vout:?}: {e}");
        }
        let not_a_tx = "not an Elements transaction";
        for (case, text, fragment) in [
            ("empty", String::new(), not_a_tx),
            ("odd", format!("{}0", hex_tx), "hex"),
            ("not-hex", format!("{}zz", hex_tx), "hex"),
            (
                "split",
                format!("{} {}", &hex_tx[..20], &hex_tx[20..]),
                "hex",
            ),
            ("trailing-byte", format!("{}00", hex_tx), not_a_tx),
            (
                "truncated",
                hex_tx[..hex_tx.len() - 2].to_string(),
                not_a_tx,
            ),
        ] {
            let path = tx_file(case, &text);
            let e = txid_cmd(&args(&[&path]), &mut Gates::default()).unwrap_err();
            assert!(e.contains(fragment), "{case}: {e}");
            let e = output_cmd(&args(&[&path, "0"]), &mut Gates::default()).unwrap_err();
            assert!(e.contains(fragment), "{case}: {e}");
            let e = input_cmd(&args(&[&path, "0"]), &mut Gates::default()).unwrap_err();
            assert!(e.contains(fragment), "{case}: {e}");
        }
        let e = txid_cmd(&args(&["/nonexistent/tx.hex"]), &mut Gates::default()).unwrap_err();
        assert!(e.starts_with("/nonexistent/tx.hex: "), "{e}");
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
    let raw = parse_hex(value).map_err(|e| format!("{}: {}", name, e))?;
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
pub fn build_update_json(text: &str) -> Result<String, String> {
    let input = checked_input(text)?;
    let mut gates = Gates::default();
    let mut report = update_from_json(&input, false, &mut gates)?;
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
pub fn build_update(input_json: &str) -> Result<String, wasm_bindgen::JsError> {
    build_update_json(input_json).map_err(|e| wasm_bindgen::JsError::new(&e))
}
