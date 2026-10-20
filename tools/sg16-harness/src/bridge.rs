//! The transactions around the generated update leaf (tools/sg16/bridge-guest/liquid.py).
//!
//! A bridge state is a taproot output with internal key NUMS and the tree {{update leaf, claim leaf},
//! tapleaf(state_hash)}, so the update leaf's control-block path is [claim leaf, state leaf].  The
//! output holds the bridge asset's single reissuance token, blinded with one of two *public* asset
//! blinding factors (A, B) that alternate with every spend, and the constant value commitment
//! 1 * H_token (value blinding factor = -abf), so anyone can build the next spend and its surjection
//! and range proofs.  The leaves pin these constants; a relayer cannot freeze the token behind a
//! private blinding factor.
//!
//! Update: inputs [state, fee (explicit L-BTC)]; outputs [successor state, explicit fee]; no issuance.
//!
//! All 32-byte hash fields in JSON are in internal byte order (as serialized in transactions), not
//! the reversed display order of block explorers.
use crate::witness::{hex, parse_hex};
use serde_json::{json, Value as Json};
use simplicity::elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value};
use simplicity::elements::encode::{deserialize, serialize};
use simplicity::elements::hashes::{hash160, sha256};
use simplicity::elements::secp256k1_zkp::{
    self as secp, Generator, PedersenCommitment, PublicKey, RangeProof, Scalar, Secp256k1,
    SecretKey, SurjectionProof, Tag, Tweak, XOnlyPublicKey, ZERO_TWEAK,
};
use simplicity::elements::sighash::SighashCache;
use simplicity::elements::taproot::ControlBlock;
use simplicity::elements::{
    AssetId, AssetIssuance, BlockHash, ContractHash, EcdsaSighashType, LockTime, OutPoint, Script,
    Sequence, Transaction, TxIn, TxInWitness, TxOut, TxOutWitness, Txid, Witness,
};

/// BIP341's provably unspendable internal key (no key path).
pub const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
/// Domain tag of the light-client commitment `lc` (as sg16-bridge-core).
pub const LC_TAG: &[u8] = b"liquid-bridge-poc/lc";
/// Domain tag of the bridge state hash (as the claim crate, contracts/simplicity).
pub const STATE_TAG: &[u8] = b"liquid-bridge-poc/state";
/// Preimage of a set slot of the claimed tree (as the claim crate, contracts/simplicity).
pub const CLAIMED_TAG: &[u8] = b"liquid-bridge-poc/claimed";
/// Depth of the claimed tree, and of the escrow's deposit tree it is indexed like.
pub const CLAIMED_DEPTH: usize = 32;
/// test key of the separate fee input (P2WPKH); local scenarios only
pub const FEE_SECRET: [u8; 32] = [0x5a; 32];

/// Panics unless `s` is 64 hex digits: only for generator-written values (see `try_h32`).
pub fn h32(s: &str) -> [u8; 32] {
    try_h32(s).unwrap_or_else(|e| panic!("{}", e))
}

pub fn try_h32(s: &str) -> Result<[u8; 32], String> {
    parse_hex(s)?
        .try_into()
        .map_err(|b: Vec<u8>| format!("{} bytes where 32 are needed", b.len()))
}

pub fn sha(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

/// BIP340-style tagged hash
pub fn tagged(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = sha(tag.as_bytes());
    sha(&[&t[..], &t[..], msg].concat())
}

pub fn tapleaf_simplicity(cmr: &[u8; 32]) -> [u8; 32] {
    tagged("TapLeaf/elements", &[&[0xbe, 0x20][..], &cmr[..]].concat())
}

pub fn tapbranch(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (l, r) = if a < b { (a, b) } else { (b, a) };
    tagged("TapBranch/elements", &[&l[..], &r[..]].concat())
}

/// A taproot output with the program leaf at the bottom of `path` (sibling hashes, leaf upwards).
pub struct Tap {
    pub spk: Script,
    pub control: ControlBlock,
    pub output_key: [u8; 32],
}

pub fn tap(cmr: &[u8; 32], path: &[[u8; 32]]) -> Tap {
    let secp = Secp256k1::verification_only();
    let mut node = tapleaf_simplicity(cmr);
    for p in path {
        node = tapbranch(&node, p);
    }
    let internal_bytes = h32(NUMS);
    let internal = XOnlyPublicKey::from_slice(&internal_bytes).expect("NUMS key");
    let t = tagged(
        "TapTweak/elements",
        &[&internal_bytes[..], &node[..]].concat(),
    );
    let (q, parity) = internal
        .add_tweak(&secp, &Scalar::from_be_bytes(t).expect("tweak in range"))
        .expect("tweak");
    let mut cb = vec![0xbe | parity.to_u8()];
    cb.extend_from_slice(&internal_bytes);
    for p in path {
        cb.extend_from_slice(p);
    }
    let output_key = q.serialize();
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&output_key);
    Tap {
        spk: Script::from(spk),
        control: ControlBlock::from_slice(&cb).expect("control block"),
        output_key,
    }
}

fn compact_size(b: &mut Vec<u8>, n: usize) {
    match n {
        0..=252 => b.push(n as u8),
        253..=0xffff => {
            b.push(0xfd);
            b.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            b.push(0xfe);
            b.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
}

/// An AssetIssuance from its consensus encoding: blinding nonce (32), entropy (32), amount, inflation
/// keys (each null = 0x00 or explicit = 0x01 || u64 big-endian).  Decoding keeps this code independent
/// of the nonce and entropy newtypes of a particular rust-elements version.
pub fn issuance(
    nonce: &[u8; 32],
    entropy: &[u8; 32],
    amount: Option<u64>,
    inflation_keys: Option<u64>,
) -> AssetIssuance {
    let mut b = Vec::with_capacity(82);
    b.extend_from_slice(nonce);
    b.extend_from_slice(entropy);
    for v in [amount, inflation_keys] {
        match v {
            None => b.push(0),
            Some(x) => {
                b.push(1);
                b.extend_from_slice(&x.to_be_bytes());
            }
        }
    }
    deserialize(&b).expect("asset issuance encoding")
}

/// An output witness from its consensus encoding: surjection proof, then range proof, each with a
/// CompactSize length.
pub fn out_witness(surjection: &[u8], range: &[u8]) -> TxOutWitness {
    let mut b = Vec::new();
    compact_size(&mut b, surjection.len());
    b.extend_from_slice(surjection);
    compact_size(&mut b, range.len());
    b.extend_from_slice(range);
    deserialize(&b).expect("output witness encoding")
}

pub fn asset_of(entropy: [u8; 32]) -> AssetId {
    AssetId::from_entropy(issuance(&[0; 32], &entropy, None, None).asset_entropy)
}

/// the reissuance token of an issuance with an explicit amount (Elements' `confidential = false`)
pub fn token_of(entropy: [u8; 32]) -> AssetId {
    AssetId::reissuance_token_from_entropy(
        issuance(&[0; 32], &entropy, None, None).asset_entropy,
        false,
    )
}

/// internal bytes of an asset id: the 32 bytes after the 0x01 prefix of its explicit serialization
pub fn asset_bytes(id: AssetId) -> [u8; 32] {
    serialize(&Asset::Explicit(id))[1..33].try_into().unwrap()
}

pub fn asset_from_bytes(b: [u8; 32]) -> AssetId {
    let mut raw = vec![0x01];
    raw.extend_from_slice(&b);
    match simplicity::elements::encode::deserialize::<Asset>(&raw).expect("explicit asset") {
        Asset::Explicit(id) => id,
        _ => unreachable!(),
    }
}

fn abf(b: &[u8; 32]) -> AssetBlindingFactor {
    AssetBlindingFactor::from_slice(b).expect("asset blinding factor")
}

/// the token's constant value commitment: 1 * H_token, i.e. value 1 blinded with vbf = -abf
pub fn unit_value(token: AssetId) -> Value {
    let secp = Secp256k1::new();
    Value::Confidential(PedersenCommitment::new_unblinded(
        &secp,
        1,
        Generator::new_unblinded(&secp, token.into_tag()),
    ))
}

pub fn token_asset(token: AssetId, bf: &[u8; 32]) -> Asset {
    Asset::new_confidential(&Secp256k1::new(), token, abf(bf))
}

/// (prefix bit, x) of a 33-byte commitment as the Elements jets present it: bit = prefix & 1
pub fn conf_parts(ser: &[u8]) -> Json {
    assert_eq!(ser.len(), 33);
    json!({"bit": ser[0] & 1, "x": hex(&ser[1..])})
}

pub fn p2wpkh(sk: &SecretKey) -> (Script, PublicKey) {
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), sk);
    let pkh = hash160::Hash::hash(&pk.serialize()).to_byte_array();
    let mut spk = vec![0x00, 0x14];
    spk.extend_from_slice(&pkh);
    (Script::from(spk), pk)
}

/// Sign input `i` (P2WPKH of `sk`, spending `value`) with SIGHASH_ALL.
pub fn sign_p2wpkh(tx: &mut Transaction, i: usize, sk: &SecretKey, value: Value) {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, sk);
    let pkh = hash160::Hash::hash(&pk.serialize()).to_byte_array();
    let mut code = vec![0x76, 0xa9, 0x14];
    code.extend_from_slice(&pkh);
    code.extend_from_slice(&[0x88, 0xac]);
    let sighash = SighashCache::new(&*tx).segwitv0_sighash(
        i,
        &Script::from(code),
        value,
        EcdsaSighashType::All,
    );
    let sig = secp.sign_ecdsa(&secp::Message::from_digest(sighash.to_byte_array()), sk);
    let mut der = sig.serialize_der().to_vec();
    der.push(EcdsaSighashType::All as u8);
    tx.input[i].witness.script_witness = Witness::from_slice(&[der, pk.serialize().to_vec()]);
}

/// The bridge's fixed parameters, compiled into the leaves as constants.
#[derive(Clone)]
pub struct Config {
    pub genesis: BlockHash,
    pub entropy: [u8; 32],
    pub fee_asset: AssetId,
    pub abf: [[u8; 32]; 2],
    /// the escrow whose accumulator slot the update leaf binds, recorded with the constants
    pub escrow: Option<[u8; 20]>,
}

impl Config {
    /// Panics on a malformed configuration: for generator-written files (see `try_from_json`).
    pub fn from_json(j: &Json) -> Config {
        Config::try_from_json(j).unwrap_or_else(|e| panic!("{}", e))
    }

    /// The configuration of an operator-supplied manifest, or the first problem found. The token
    /// blinding factors must be valid scalars: `token_asset` and `constants` rely on that.
    pub fn try_from_json(j: &Json) -> Result<Config, String> {
        let s = |k: &str| {
            j[k].as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("config.{} missing", k))
        };
        let w = |k: &str| try_h32(&s(k)?).map_err(|e| format!("config.{}: {}", k, e));
        let abf = [w("abf_a")?, w("abf_b")?];
        if abf.iter().any(|bf| {
            AssetBlindingFactor::from_slice(bf).is_err() || SecretKey::from_slice(bf).is_err()
        }) {
            return Err("config.abf_a/abf_b: not a valid nonzero scalar".into());
        }
        let escrow: Option<[u8; 20]> = match j["escrow"].as_str() {
            None => None,
            Some(e) => Some(
                parse_hex(e)?
                    .try_into()
                    .map_err(|_| "config.escrow: not a 20-byte address".to_string())?,
            ),
        };
        Ok(Config {
            genesis: BlockHash::from_byte_array(w("genesis")?),
            entropy: w("entropy")?,
            fee_asset: asset_from_bytes(w("fee_asset")?),
            abf,
            escrow,
        })
    }

    pub fn asset(&self) -> AssetId {
        asset_of(self.entropy)
    }

    pub fn token(&self) -> AssetId {
        token_of(self.entropy)
    }

    /// The constants the generator compiles into the program.
    pub fn constants(&self) -> Json {
        let token = self.token();
        json!({
            "escrow": self.escrow.map(|e| hex(&e)),
            "asset": hex(&asset_bytes(self.asset())),
            "token": hex(&asset_bytes(token)),
            "fee_asset": hex(&asset_bytes(self.fee_asset)),
            "genesis": hex(&self.genesis.to_byte_array()),
            "token_a": conf_parts(&serialize(&token_asset(token, &self.abf[0]))),
            "token_b": conf_parts(&serialize(&token_asset(token, &self.abf[1]))),
            "token_value": conf_parts(&serialize(&unit_value(token))),
            "nums": NUMS,
        })
    }
}

/// SHA256(SHA256(LC_TAG) || be64(head) || header || committee): the light-client commitment of the bridge state
pub fn lc(head: u64, header: &[u8; 32], committee: &[u8; 32]) -> [u8; 32] {
    sha(&[&sha(LC_TAG)[..], &head.to_be_bytes(), header, committee].concat())
}

/// SHA256(SHA256(STATE_TAG) || lc || acc || claimed_root): the bridge state hash (contracts/simplicity/src/claim.rs)
pub fn state_hash(lc: &[u8; 32], acc: &[u8; 32], claimed_root: &[u8; 32]) -> [u8; 32] {
    sha(&[&sha(STATE_TAG)[..], lc, acc, claimed_root].concat())
}

/// The roots of empty subtrees of the claimed tree by height: 32 zero bytes, then SHA256(z || z).
pub fn claimed_empty_roots() -> [[u8; 32]; CLAIMED_DEPTH + 1] {
    let mut zero = [[0u8; 32]; CLAIMED_DEPTH + 1];
    for h in 0..CLAIMED_DEPTH {
        zero[h + 1] = sha(&[&zero[h][..], &zero[h][..]].concat());
    }
    zero
}

/// The root of the claimed tree (contracts/simplicity `ClaimedTree`): a depth-32 SHA-256 sparse Merkle tree whose
/// slot i is SHA256(CLAIMED_TAG) once deposit i is paid and 0 before.  It depends only on the set `claimed`.  Err if
/// an index is outside the tree, which holds indices below 2^32.
pub fn claimed_root(claimed: &std::collections::BTreeSet<u64>) -> Result<[u8; 32], String> {
    if let Some(i) = claimed.iter().find(|&&i| i >> CLAIMED_DEPTH != 0) {
        return Err(format!("claimed index {} is outside the claimed tree", i));
    }
    let zero = claimed_empty_roots();
    let set = sha(CLAIMED_TAG);
    let mut level: std::collections::BTreeMap<u64, [u8; 32]> =
        claimed.iter().map(|&i| (i, set)).collect();
    for z in zero.iter().take(CLAIMED_DEPTH) {
        let node = |j: u64| *level.get(&j).unwrap_or(z);
        level = level
            .keys()
            .map(|&j| j >> 1)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|p| (p, sha(&[&node(2 * p)[..], &node(2 * p + 1)[..]].concat())))
            .collect();
    }
    Ok(*level.get(&0).unwrap_or(&zero[CLAIMED_DEPTH]))
}

/// The fields of one update: the spent state, the proven successor store (`new_head`, `sync`) and the
/// successor's fields, which start as the honest ones and are changed by mutations.
#[derive(Clone)]
pub struct UpdatePlan {
    /// the claim leaf's hash: the update leaf's sibling in the state tree
    pub sibling: [u8; 32],
    pub head: u64,
    pub header: [u8; 32],
    pub committee: [u8; 32],
    pub acc: [u8; 32],
    pub claimed_root: [u8; 32],
    pub new_head: u64,
    pub sync: [u8; 32],
    pub out_sibling: [u8; 32],
    pub out_header: [u8; 32],
    pub out_acc: [u8; 32],
    pub out_claimed_root: [u8; 32],
}

impl UpdatePlan {
    /// Panics on a missing or malformed field: the plan is a generator-written file, as for `Config::from_json`.
    fn from_json(t: &Json) -> UpdatePlan {
        let s = |k: &str| h32(t[k].as_str().unwrap_or_else(|| panic!("tx.{} missing", k)));
        let n = |k: &str| t[k].as_u64().unwrap_or_else(|| panic!("tx.{} missing", k));
        UpdatePlan {
            sibling: s("sibling"),
            head: n("head"),
            header: s("header"),
            committee: s("committee"),
            acc: s("acc"),
            claimed_root: s("claimed_root"),
            new_head: n("new_head"),
            sync: s("sync"),
            out_sibling: s("sibling"),
            out_header: s("new_header"),
            out_acc: s("new_acc"),
            out_claimed_root: s("claimed_root"),
        }
    }

    pub fn old_leaf(&self) -> [u8; 32] {
        tapleaf_simplicity(&state_hash(
            &lc(self.head, &self.header, &self.committee),
            &self.acc,
            &self.claimed_root,
        ))
    }

    pub fn new_leaf(&self) -> [u8; 32] {
        tapleaf_simplicity(&state_hash(
            &lc(self.new_head, &self.out_header, &self.sync),
            &self.out_acc,
            &self.out_claimed_root,
        ))
    }
}

/// Everything an update transaction is built from.  `honest` follows the protocol; mutations change
/// individual fields while the witness (proof and fields) stays the honest one.
#[derive(Clone)]
pub struct Plan {
    pub genesis: BlockHash,
    pub state_outpoint: OutPoint,
    pub fee_outpoint: OutPoint,
    pub fee_value: u64,
    /// control-block path of the spent state output (the honest one is [claim leaf, old state leaf])
    pub in_path: Vec<[u8; 32]>,
    /// entropy of the token the spent state output holds
    pub in_entropy: [u8; 32],
    pub in_abf: [u8; 32],
    /// a reissuance amount on input 0 (an honest update has none)
    pub reissue: Option<u64>,
    /// None: the leaf's successor for `update`
    pub successor_spk: Option<Script>,
    pub out_abf: [u8; 32],
    /// an explicit output before the fee (an honest update has none)
    pub mint: Option<(AssetId, u64, Script)>,
    pub fee_asset_out: AssetId,
    pub input1_issuance: bool,
    pub extra_input: bool,
    pub swap_inputs: bool,
    pub update: UpdatePlan,
}

pub fn attacker_spk() -> Script {
    p2wpkh(&SecretKey::from_slice(&[0x66; 32]).unwrap()).0
}

impl Plan {
    /// Panics on a missing or malformed field of `t`: the plan is a generator-written file, as for
    /// `Config::from_json`.  Operator input reaches the testnet tools through their fallible loaders instead.
    pub fn honest(cfg: &Config, t: &Json) -> Plan {
        let s = |k: &str| {
            t[k].as_str()
                .unwrap_or_else(|| panic!("tx.{} missing", k))
                .to_string()
        };
        let n = |k: &str| t[k].as_u64().unwrap_or_else(|| panic!("tx.{} missing", k));
        let old_abf = n("old_abf") as usize;
        assert!(old_abf < 2);
        let update = UpdatePlan::from_json(t);
        Plan {
            genesis: cfg.genesis,
            state_outpoint: OutPoint::new(
                Txid::from_byte_array(h32(&s("state_txid"))),
                n("state_vout") as u32,
            ),
            fee_outpoint: OutPoint::new(
                Txid::from_byte_array(h32(&s("fee_txid"))),
                n("fee_vout") as u32,
            ),
            fee_value: n("fee_value"),
            in_path: vec![update.sibling, update.old_leaf()],
            in_entropy: cfg.entropy,
            in_abf: cfg.abf[old_abf],
            reissue: None,
            successor_spk: None,
            out_abf: cfg.abf[1 - old_abf],
            mint: None,
            fee_asset_out: cfg.fee_asset,
            input1_issuance: false,
            extra_input: false,
            swap_inputs: false,
            update,
        }
    }

    /// Apply a named mutation.  Mutations marked "balanced" keep the transaction valid under Elements'
    /// amount, surjection and range-proof rules, so only the leaf can reject them.  Panics on an
    /// unknown name: the names come from the test drivers.
    pub fn mutate(&mut self, name: &str) {
        let other = [0xee; 32];
        match name {
            // balanced: the successor commits to another accumulator than the proof
            "successor_state_other" => self.update.out_acc = other,
            // balanced: the successor commits another claimed root than the spent state, as an update that marked a
            // deposit claimed, or cleared a claimed slot, would
            "claimed_changed" => {
                self.update.out_claimed_root =
                    sha(&[&self.update.claimed_root[..], CLAIMED_TAG].concat())
            }
            // balanced: the successor replaces the claim leaf (a covenant escape)
            "sibling_other" => self.update.out_sibling = [0xdd; 32],
            // balanced: the successor commits to another beacon header than the proof
            "header_other" => self.update.out_header = [0xcc; 32],
            // balanced: the token leaves the covenant
            "successor_to_attacker" => self.successor_spk = Some(attacker_spk()),
            // balanced: the token-freeze attack, a successor blinded with a private factor
            "token_private_abf" => self.out_abf = [0x77; 32],
            // balanced: a third input, its value added to the fee
            "third_input" => self.extra_input = true,
            // balanced: the state input is input 1
            "state_input_second" => self.swap_inputs = true,
            // balanced: a state output whose commitment differs from the proven old state
            "stale_old_state" => self.in_path = vec![self.update.sibling, other],
            // balanced: a state output with a deeper leaf
            "path_extra" => self.in_path.push(other),
            // balanced: an update that also mints
            "update_mints" => {
                self.reissue = Some(5000);
                self.mint = Some((asset_of(self.in_entropy), 5000, attacker_spk()));
            }
            // unbalanced: a new issuance on the fee input
            "input1_issuance" => self.input1_issuance = true,
            // unbalanced: the fee in another asset
            "fee_asset_other" => self.fee_asset_out = asset_of([0x31; 32]),
            m => panic!("unknown mutation {}", m),
        }
    }
}

pub struct Built {
    pub tx: Transaction,
    pub utxos: Vec<TxOut>,
    pub ix: u32,
    pub control: ControlBlock,
    pub genesis: BlockHash,
}

fn txin(outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        asset_issuance: AssetIssuance::default(),
        witness: TxInWitness::default(),
    }
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

/// Build the transaction of a plan for the program `cmr`, with Elements proofs for the successor and
/// signed fee inputs.  The state input's Simplicity witness stack is added by the caller.
pub fn build(cfg: &Config, plan: &Plan, cmr: &[u8; 32]) -> Built {
    let secp = Secp256k1::new();
    let mut rng = secp::rand::thread_rng();
    let in_tap = tap(cmr, &plan.in_path);
    let token = token_of(plan.in_entropy);
    let spent_state = TxOut {
        asset: token_asset(token, &plan.in_abf),
        value: unit_value(token),
        nonce: Nonce::Null,
        script_pubkey: in_tap.spk.clone(),
        witness: TxOutWitness::default(),
    };
    let fee_sk = SecretKey::from_slice(&FEE_SECRET).unwrap();
    let (fee_spk, _) = p2wpkh(&fee_sk);
    let spent_fee = explicit_out(cfg.fee_asset, plan.fee_value, fee_spk);

    // Inputs in protocol order, each with the (asset, blinding factor) of what it brings in, in the
    // order Elements builds the surjection domain: prevout asset, issued asset, issued token.
    let mut in0 = txin(plan.state_outpoint);
    let mut dom0: Vec<(AssetId, [u8; 32])> = vec![(token, plan.in_abf)];
    if let Some(amount) = plan.reissue {
        // reissuance: the nonce is the spent token's asset blinding factor
        in0.asset_issuance = issuance(&plan.in_abf, &plan.in_entropy, Some(amount), None);
        dom0.push((asset_of(plan.in_entropy), [0; 32]));
    }
    let mut in1 = txin(plan.fee_outpoint);
    let mut dom1: Vec<(AssetId, [u8; 32])> = vec![(cfg.fee_asset, [0; 32])];
    if plan.input1_issuance {
        // a new issuance (zero nonce, zero contract hash) of one token and no asset
        in1.asset_issuance = issuance(&[0; 32], &[0; 32], None, Some(1));
        let e = AssetId::generate_asset_entropy(
            plan.fee_outpoint,
            ContractHash::from_byte_array([0; 32]),
        );
        dom1.push((AssetId::reissuance_token_from_entropy(e, false), [0; 32]));
    }
    let mut ins = vec![(in0, spent_state, dom0), (in1, spent_fee.clone(), dom1)];
    let mut fee_total = plan.fee_value;
    if plan.extra_input {
        let mut extra = spent_fee.clone();
        extra.value = Value::Explicit(plan.fee_value);
        ins.push((
            txin(OutPoint::new(Txid::from_byte_array([0x17; 32]), 3)),
            extra,
            vec![(cfg.fee_asset, [0; 32])],
        ));
        fee_total += plan.fee_value;
    }
    let mut ix = 0u32;
    if plan.swap_inputs {
        ins.swap(0, 1);
        ix = 1;
    }

    let successor_spk = plan
        .successor_spk
        .clone()
        .unwrap_or_else(|| tap(cmr, &[plan.update.out_sibling, plan.update.new_leaf()]).spk);
    let mut outputs = vec![TxOut {
        asset: token_asset(token, &plan.out_abf),
        value: unit_value(token),
        nonce: Nonce::Null,
        script_pubkey: successor_spk.clone(),
        witness: TxOutWitness::default(),
    }];
    if let Some((asset, amount, spk)) = &plan.mint {
        outputs.push(explicit_out(*asset, *amount, spk.clone()));
    }
    outputs.push(TxOut::new_fee(fee_total, plan.fee_asset_out));

    // successor proofs: surjection over every input asset, range proof with the public vbf = -abf
    let domain: Vec<(Generator, Tag, Tweak)> = ins
        .iter()
        .flat_map(|(_, _, d)| d.iter())
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
        Tweak::from_slice(&plan.out_abf).unwrap(),
        &domain,
    )
    .expect("surjection proof");
    // Value 1 under the blinded generator H + abf G with vbf = -abf: the commitment is the constant
    // H_token (unit_value).  Elements' wallet parameters: minimum value 1, exponent 0, 52 bits; the
    // scriptPubKey is the extra commitment, as Elements verifies it.
    let blinded = Generator::new_blinded(
        &secp,
        token.into_tag(),
        Tweak::from_slice(&plan.out_abf).unwrap(),
    );
    let commitment = PedersenCommitment::new_unblinded(
        &secp,
        1,
        Generator::new_unblinded(&secp, token.into_tag()),
    );
    let vbf = Tweak::from_slice(
        &SecretKey::from_slice(&plan.out_abf)
            .unwrap()
            .negate()
            .secret_bytes(),
    )
    .unwrap();
    assert_eq!(
        Value::Confidential(commitment.clone()),
        outputs[0].value,
        "the value commitment is the constant 1 * H_token"
    );
    let range = RangeProof::new(
        &secp,
        1,
        commitment,
        1,
        vbf,
        &[],
        successor_spk.as_bytes(),
        SecretKey::from_slice(&[9; 32]).unwrap(),
        0,
        52,
        blinded,
    )
    .expect("range proof");
    outputs[0].witness = out_witness(&surjection.serialize(), &range.serialize());

    let utxos: Vec<TxOut> = ins.iter().map(|(_, u, _)| u.clone()).collect();
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: ins.into_iter().map(|(i, _, _)| i).collect(),
        output: outputs,
    };
    for i in 0..tx.input.len() {
        if i as u32 != ix {
            sign_p2wpkh(&mut tx, i, &fee_sk, utxos[i].value);
        }
    }
    Built {
        tx,
        utxos,
        ix,
        control: in_tap.control,
        genesis: plan.genesis,
    }
}

/// Bytes of a witness stack as serialized: CompactSize count, then each item with its length.
pub fn stack_bytes(items: &[Vec<u8>]) -> usize {
    fn cs(n: usize) -> usize {
        match n {
            0..=252 => 1,
            253..=0xffff => 3,
            0x10000..=0xffff_ffff => 5,
            _ => 9,
        }
    }
    cs(items.len()) + items.iter().map(|i| cs(i.len()) + i.len()).sum::<usize>()
}
