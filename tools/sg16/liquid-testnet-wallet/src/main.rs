//! Minimal wallet for the project's public Liquid testnet transactions: one key, used as a P2WPKH address for
//! L-BTC and as the untweaked P2TR output key (`recipient`).  A bridge claim pays whichever script its deposit
//! committed, so either one can hold the bridge asset.
//!
//! Secrets are generated into a mode-0600 file and never accepted on the command line or printed.
//! `sign`, `split` and `fund` sign only a matching, explicit Liquid testnet L-BTC UTXO; `fund` pays only an
//! unconfidential P2WPKH address, a fee input for another wallet's `burn`.  `burn` spends an explicit
//! bridge-asset UTXO paid to this key's P2TR script or P2WPKH address into the Sepolia escrow's bare 72-byte
//! OP_RETURN burn script (contracts/solidity/contracts/BridgeEscrow.sol).  Nothing here broadcasts.
use serde_json::json;
use simplicity::elements::bitcoin;
use simplicity::elements::confidential::{Asset, Nonce, Value};
use simplicity::elements::encode::{deserialize, serialize_hex};
use simplicity::elements::secp256k1_zkp::{self as secp, Secp256k1, SecretKey};
use simplicity::elements::sighash::{Prevouts, SchnorrSighashType, SighashCache};
use simplicity::elements::{
    Address, AddressParams, AssetId, BlockHash, EcdsaSighashType, LockTime, OutPoint, Script,
    Sequence, Transaction, TxIn, TxInWitness, TxOut, TxOutWitness, Witness,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::str::FromStr;

const TESTNET_LBTC: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
const TESTNET_GENESIS: &str = "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1";
const BURN_TAG: &[u8; 22] = b"liquid-bridge-poc/burn";
const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
const MIN_RELAY_SAT_PER_KVB: u64 = 100;

fn key(path: &str) -> Result<SecretKey, String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err("key file must have mode 0600".into());
    }
    SecretKey::from_str(fs::read_to_string(path).map_err(|e| e.to_string())?.trim())
        .map_err(|_| "invalid key file".into())
}

fn identity(sk: &SecretKey) -> (bitcoin::PublicKey, Address) {
    let ctx = Secp256k1::new();
    let pk = bitcoin::PublicKey::new(secp::PublicKey::from_secret_key(&ctx, sk));
    let address = Address::p2wpkh(&pk, None, &AddressParams::LIQUID_TESTNET);
    (pk, address)
}

fn new(path: &str) -> Result<serde_json::Value, String> {
    let sk = SecretKey::new(&mut secp::rand::thread_rng());
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create key file: {e}"))?;
    writeln!(f, "{}", hex(&sk.secret_bytes())).map_err(|e| e.to_string())?;
    let (_, address) = identity(&sk);
    Ok(
        json!({"ok": true, "network": "liquidtestnet", "address": address.to_string(),
        "script_pubkey": hex(address.script_pubkey().as_bytes()), "key_file": path}),
    )
}

fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex".into()))
        .collect()
}

fn sign(
    kpath: &str,
    tx_path: &str,
    ix: usize,
    prev_path: &str,
    vout: usize,
    out_path: &str,
) -> Result<serde_json::Value, String> {
    let sk = key(kpath)?;
    let (pk, addr) = identity(&sk);
    let mut tx: Transaction = deserialize(&unhex(
        &fs::read_to_string(tx_path).map_err(|e| e.to_string())?,
    )?)
    .map_err(|e| format!("transaction decode: {e:?}"))?;
    let prev: Transaction = deserialize(&unhex(
        &fs::read_to_string(prev_path).map_err(|e| e.to_string())?,
    )?)
    .map_err(|e| format!("previous transaction decode: {e:?}"))?;
    let input = tx.input.get(ix).ok_or("input index out of range")?;
    if input.previous_output.txid != prev.txid() || input.previous_output.vout as usize != vout {
        return Err("input outpoint does not match previous transaction".into());
    }
    if !input.witness.script_witness.is_empty() {
        return Err("input already has a script witness".into());
    }
    let utxo = prev
        .output
        .get(vout)
        .ok_or("previous output index out of range")?;
    if utxo.script_pubkey != addr.script_pubkey() {
        return Err("previous output does not pay this key".into());
    }
    let asset = match utxo.asset {
        Asset::Explicit(a) => a,
        _ => return Err("funding asset is confidential".into()),
    };
    if asset != AssetId::from_str(TESTNET_LBTC).map_err(|e| e.to_string())? {
        return Err("funding asset is not Liquid testnet L-BTC".into());
    }
    let value = match utxo.value {
        Value::Explicit(v) => v,
        _ => return Err("funding value is confidential".into()),
    };
    let script_code = Script::new_p2pkh(&pk.pubkey_hash());
    let sighash = SighashCache::new(&tx).segwitv0_sighash(
        ix,
        &script_code,
        Value::Explicit(value),
        EcdsaSighashType::All,
    );
    let msg = secp::Message::from_digest(sighash.to_byte_array());
    let ctx = Secp256k1::new();
    let sig = ctx.sign_ecdsa(&msg, &sk);
    ctx.verify_ecdsa(&msg, &sig, &pk.inner)
        .map_err(|e| format!("local signature verification: {e}"))?;
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    tx.input[ix].witness.script_witness = Witness::from_slice(&[sig_bytes, pk.to_bytes()]);
    if tx.weight() >= 400_000 {
        return Err("signed transaction exceeds 400,000 WU".into());
    }
    fs::write(out_path, serialize_hex(&tx)).map_err(|e| e.to_string())?;
    Ok(
        json!({"ok": true, "network": "liquidtestnet", "txid": tx.txid().to_string(),
        "signed_input": ix, "prev_txid": prev.txid().to_string(), "prev_vout": vout,
        "prev_value_sats": value, "weight": tx.weight(), "hex_file": out_path}),
    )
}

fn read_tx(path: &str, what: &str) -> Result<Transaction, String> {
    deserialize(&unhex(
        &fs::read_to_string(path).map_err(|e| format!("{what}: {e}"))?,
    )?)
    .map_err(|e| format!("{what} decode: {e:?}"))
}

fn explicit_of(o: &TxOut) -> Option<(AssetId, u64)> {
    match (&o.asset, &o.value) {
        (Asset::Explicit(a), Value::Explicit(v)) => Some((*a, *v)),
        _ => None,
    }
}

fn word20(s: &str, what: &str) -> Result<[u8; 20], String> {
    unhex(s.strip_prefix("0x").unwrap_or(s))?
        .try_into()
        .map_err(|_| format!("{what}: not 20 bytes"))
}

/// The escrow's burnScriptPubKey(recipient): OP_RETURN (0x6a), a direct push of 70 bytes (0x46), then
/// "liquid-bridge-poc/burn" (bytes22), the chain id as a big-endian uint64, the escrow and the recipient, as
/// abi.encodePacked lays out: 72 bytes. The caller supplies the escrow getter's answer separately; this offline
/// tool compares that value but does not query Sepolia.
fn burn_script(chain_id: u64, escrow: &[u8; 20], recipient: &[u8; 20]) -> Script {
    Script::from(
        [
            &[0x6a, 0x46][..],
            &BURN_TAG[..],
            &chain_id.to_be_bytes()[..],
            &escrow[..],
            &recipient[..],
        ]
        .concat(),
    )
}

/// Burn `units` of the bridge asset held by this key (a claim output) for `recipient` on Sepolia: outputs
/// [burn, bridge-asset change if any, L-BTC change, fee].  Input 0 is that bridge-asset UTXO.  Paid to the P2TR
/// script it is signed on the key path (BIP341 as Elements defines it, with the testnet genesis hash); paid to
/// the P2WPKH address, with SIGHASH_ALL as `sign` does.  Its change returns to the same script.  Input 1 is an
/// L-BTC P2WPKH UTXO of the same key for the fee.  Every output is explicit: the escrow reads the burn's
/// asset and amount, and a confidential burn could never be redeemed.
#[allow(clippy::too_many_arguments)]
fn burn(
    kpath: &str,
    asset_prev: &str,
    asset_vout: usize,
    fee_prev: &str,
    fee_vout: usize,
    bridge_asset: &str,
    units: u64,
    chain_id: u64,
    escrow: &str,
    recipient: &str,
    escrow_burn_spk: &str,
    miner_fee: u64,
    out_path: &str,
) -> Result<serde_json::Value, String> {
    let sk = key(kpath)?;
    let ctx = Secp256k1::new();
    let keypair = secp::Keypair::from_secret_key(&ctx, &sk);
    let (xonly, _) = keypair.x_only_public_key();
    let p2tr = Script::from([&[0x51, 0x20][..], &xonly.serialize()[..]].concat());
    let (_, address) = identity(&sk);
    let lbtc = AssetId::from_str(TESTNET_LBTC).map_err(|e| e.to_string())?;
    let asset = AssetId::from_str(bridge_asset)
        .map_err(|_| "bridge asset: display hex of a Liquid asset id")?;
    if asset == lbtc {
        return Err("the bridge asset cannot be L-BTC".into());
    }
    if chain_id != SEPOLIA_CHAIN_ID {
        return Err(format!("chain id must be Sepolia's, {SEPOLIA_CHAIN_ID}"));
    }
    let script = burn_script(
        chain_id,
        &word20(escrow, "escrow")?,
        &word20(recipient, "recipient")?,
    );
    let supplied = Script::from(unhex(
        escrow_burn_spk
            .strip_prefix("0x")
            .unwrap_or(escrow_burn_spk),
    )?);
    if supplied != script {
        return Err("burn script from (chain id, escrow, recipient) \
                    differs from the supplied burnScriptPubKey(recipient)"
            .into());
    }

    let aprev = read_tx(asset_prev, "bridge-asset previous transaction")?;
    let a_utxo = aprev
        .output
        .get(asset_vout)
        .cloned()
        .ok_or("bridge-asset output index out of range")?;
    let taproot = if a_utxo.script_pubkey == p2tr {
        true
    } else if a_utxo.script_pubkey == address.script_pubkey() {
        false
    } else {
        return Err(
            "bridge-asset output pays neither this key's P2TR script nor its P2WPKH address".into(),
        );
    };
    let (a_asset, a_value) = explicit_of(&a_utxo).ok_or("bridge-asset output is confidential")?;
    if a_asset != asset {
        return Err("previous output holds another asset than the bridge asset".into());
    }
    if units == 0 || units > a_value {
        return Err(format!(
            "units must be 1 .. {a_value}, the bridge-asset output's value"
        ));
    }
    let fprev = read_tx(fee_prev, "fee previous transaction")?;
    let f_utxo = fprev
        .output
        .get(fee_vout)
        .cloned()
        .ok_or("fee output index out of range")?;
    if f_utxo.script_pubkey != address.script_pubkey()
        || explicit_of(&f_utxo).map(|(x, _)| x) != Some(lbtc)
    {
        return Err("fee output is not explicit L-BTC paid to this key's P2WPKH address".into());
    }
    let (_, f_value) = explicit_of(&f_utxo).ok_or("fee output is confidential")?;
    let lbtc_change = f_value
        .checked_sub(miner_fee)
        .ok_or("miner fee exceeds the fee input")?;
    if miner_fee < 100 || lbtc_change < 546 {
        return Err("burn needs a >=100 sat miner fee and >=546 sat L-BTC change".into());
    }

    let explicit = |a: AssetId, n: u64, spk: Script| TxOut {
        asset: Asset::Explicit(a),
        value: Value::Explicit(n),
        nonce: Nonce::Null,
        script_pubkey: spk,
        witness: TxOutWitness::default(),
    };
    let mut output = vec![explicit(asset, units, script.clone())];
    if a_value > units {
        output.push(explicit(
            asset,
            a_value - units,
            a_utxo.script_pubkey.clone(),
        ));
    }
    output.push(explicit(lbtc, lbtc_change, address.script_pubkey()));
    output.push(TxOut::new_fee(miner_fee, lbtc));
    let input = |txid, vout| TxIn {
        previous_output: OutPoint { txid, vout },
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        asset_issuance: Default::default(),
        witness: TxInWitness::default(),
    };
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![
            input(aprev.txid(), asset_vout as u32),
            input(fprev.txid(), fee_vout as u32),
        ],
        output,
    };

    let spent = [a_utxo.clone(), f_utxo.clone()];
    if taproot {
        let genesis = BlockHash::from_str(TESTNET_GENESIS).map_err(|e| e.to_string())?;
        let tap = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&spent[..]),
                SchnorrSighashType::Default,
                genesis,
            )
            .map_err(|e| format!("taproot sighash: {e:?}"))?;
        let msg = secp::Message::from_digest(tap.to_byte_array());
        let sig = ctx.sign_schnorr_with_rng(&msg, &keypair, &mut secp::rand::thread_rng());
        ctx.verify_schnorr(&sig, &msg, &xonly)
            .map_err(|e| format!("local Schnorr verification: {e}"))?;
        // SIGHASH_DEFAULT: a bare 64-byte signature, no sighash byte.
        tx.input[0].witness.script_witness = Witness::from_slice(&[sig.serialize().to_vec()]);
    } else {
        sign_p2wpkh(&mut tx, 0, &sk, a_value)?;
    }
    sign_p2wpkh(&mut tx, 1, &sk, f_value)?;
    let weight = tx.weight();
    let floor = ((weight as u64 + 3) / 4 * MIN_RELAY_SAT_PER_KVB + 999) / 1000;
    if weight >= 400_000 || miner_fee < floor {
        return Err(format!(
            "weight {weight} WU needs a fee of at least {floor} sat at 0.1 sat/vB"
        ));
    }
    tx.verify_tx_amt_proofs(&ctx, &spent)
        .map_err(|e| format!("Elements amount check: {e:?}"))?;
    fs::write(out_path, serialize_hex(&tx)).map_err(|e| e.to_string())?;
    Ok(
        json!({"ok": true, "network": "liquidtestnet", "txid": tx.txid().to_string(), "burn_vout": 0, "units": units,
        "bridge_asset": asset.to_string(), "bridge_asset_input": if taproot { "p2tr" } else { "p2wpkh" },
        "burn_script_pubkey": hex(script.as_bytes()),
        "recipient": recipient, "escrow": escrow, "chain_id": chain_id,
        "weight": tx.weight(), "miner_fee_sats": miner_fee, "hex_file": out_path,
        "next": "broadcast after review; redeem once the block is relayed with MIN_CONFIRMATIONS"}),
    )
}

/// SIGHASH_ALL P2WPKH signature of input `ix`, which spends `value` sat of this key's address.
fn sign_p2wpkh(tx: &mut Transaction, ix: usize, sk: &SecretKey, value: u64) -> Result<(), String> {
    let (pk, _) = identity(sk);
    let script_code = Script::new_p2pkh(&pk.pubkey_hash());
    let sighash = SighashCache::new(&*tx).segwitv0_sighash(
        ix,
        &script_code,
        Value::Explicit(value),
        EcdsaSighashType::All,
    );
    let msg = secp::Message::from_digest(sighash.to_byte_array());
    let ctx = Secp256k1::new();
    let sig = ctx.sign_ecdsa(&msg, sk);
    ctx.verify_ecdsa(&msg, &sig, &pk.inner)
        .map_err(|e| format!("local signature verification: {e}"))?;
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    tx.input[ix].witness.script_witness = Witness::from_slice(&[sig_bytes, pk.to_bytes()]);
    Ok(())
}

/// Pay `amount` sat of explicit L-BTC from this key's P2WPKH address to another wallet's unconfidential P2WPKH
/// address, so that wallet has a fee input for `burn`: outputs [payment, change, fee], all explicit.  `burn` takes
/// its fee only from explicit L-BTC at its own key's P2WPKH address, so any other destination is refused, and so is
/// a payment smaller than the least fee input `burn` accepts (a 100-sat fee and 546 sats of change).
fn fund(
    kpath: &str,
    prev_path: &str,
    vout: usize,
    to: &str,
    amount: u64,
    miner_fee: u64,
    out_path: &str,
) -> Result<serde_json::Value, String> {
    let sk = key(kpath)?;
    let (_, address) = identity(&sk);
    let lbtc = AssetId::from_str(TESTNET_LBTC).map_err(|e| e.to_string())?;
    let dest = Address::from_str(to).map_err(|e| format!("destination address: {e}"))?;
    if dest.params != &AddressParams::LIQUID_TESTNET || dest.blinding_pubkey.is_some() {
        return Err("destination must be an unconfidential Liquid testnet address".into());
    }
    let dest_spk = dest.script_pubkey();
    if !dest_spk.is_v0_p2wpkh() {
        return Err(
            "destination must be a P2WPKH address, the only script `burn` takes a fee input from"
                .into(),
        );
    }
    if dest_spk == address.script_pubkey() {
        return Err("destination is this key's own address".into());
    }

    let prev = read_tx(prev_path, "previous transaction")?;
    let utxo = prev
        .output
        .get(vout)
        .cloned()
        .ok_or("previous output index out of range")?;
    if utxo.script_pubkey != address.script_pubkey()
        || explicit_of(&utxo).map(|(x, _)| x) != Some(lbtc)
    {
        return Err(
            "previous output is not explicit L-BTC paid to this key's P2WPKH address".into(),
        );
    }
    let (_, value) = explicit_of(&utxo).ok_or("previous output is confidential")?;
    let change = value
        .checked_sub(amount)
        .and_then(|x| x.checked_sub(miner_fee))
        .ok_or("payment and miner fee exceed the input value")?;
    if amount < 100 + 546 {
        return Err("payment must be at least 646 sats, the least fee input `burn` accepts".into());
    }
    if miner_fee < 100 {
        return Err("miner fee must be at least 100 sats".into());
    }
    if change < 546 {
        return Err("change must be at least 546 sats".into());
    }

    let explicit = |n: u64, spk: Script| TxOut {
        asset: Asset::Explicit(lbtc),
        value: Value::Explicit(n),
        nonce: Nonce::Null,
        script_pubkey: spk,
        witness: TxOutWitness::default(),
    };
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev.txid(),
                vout: vout as u32,
            },
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: Default::default(),
            witness: TxInWitness::default(),
        }],
        output: vec![
            explicit(amount, dest_spk.clone()),
            explicit(change, address.script_pubkey()),
            TxOut::new_fee(miner_fee, lbtc),
        ],
    };
    sign_p2wpkh(&mut tx, 0, &sk, value)?;
    let weight = tx.weight();
    let floor = ((weight as u64 + 3) / 4 * MIN_RELAY_SAT_PER_KVB + 999) / 1000;
    if weight >= 400_000 || miner_fee < floor {
        return Err(format!(
            "weight {weight} WU needs a fee of at least {floor} sat at 0.1 sat/vB"
        ));
    }
    tx.verify_tx_amt_proofs(&Secp256k1::new(), &[utxo])
        .map_err(|e| format!("Elements amount check: {e:?}"))?;
    fs::write(out_path, serialize_hex(&tx)).map_err(|e| e.to_string())?;
    Ok(
        json!({"ok": true, "network": "liquidtestnet", "txid": tx.txid().to_string(),
        "prev_txid": prev.txid().to_string(), "prev_vout": vout, "prev_value_sats": value,
        "to": dest.to_string(), "to_script_pubkey": hex(dest_spk.as_bytes()), "fund_vout": 0, "amount_sats": amount,
        "change_address": address.to_string(), "change_sats": change, "miner_fee_sats": miner_fee, "weight": weight,
        "hex_file": out_path,
        "next": "broadcast after review; then pass this transaction and vout 0 to `burn` as its fee input"}),
    )
}

fn split(
    kpath: &str,
    prev_path: &str,
    vout: usize,
    fee_slot: u64,
    miner_fee: u64,
    out_path: &str,
) -> Result<serde_json::Value, String> {
    let (_, address) = identity(&key(kpath)?);
    let prev: Transaction = deserialize(&unhex(
        &fs::read_to_string(prev_path).map_err(|e| e.to_string())?,
    )?)
    .map_err(|e| format!("previous transaction decode: {e:?}"))?;
    let utxo = prev
        .output
        .get(vout)
        .ok_or("previous output index out of range")?;
    if utxo.script_pubkey != address.script_pubkey() {
        return Err("previous output does not pay this key".into());
    }
    let asset = match utxo.asset {
        Asset::Explicit(a) => a,
        _ => return Err("split asset is confidential".into()),
    };
    if asset != AssetId::from_str(TESTNET_LBTC).map_err(|e| e.to_string())? {
        return Err("split asset is not Liquid testnet L-BTC".into());
    }
    let value = match utxo.value {
        Value::Explicit(v) => v,
        _ => return Err("split value is confidential".into()),
    };
    let change = value
        .checked_sub(fee_slot)
        .and_then(|x| x.checked_sub(miner_fee))
        .ok_or("split outputs exceed input value")?;
    if fee_slot < 1_000 || change < 546 || miner_fee < 100 {
        return Err(
            "split needs a >=1000 sat fee slot, >=546 sat change and >=100 sat miner fee".into(),
        );
    }
    let owned = |n| TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(n),
        nonce: Nonce::Null,
        script_pubkey: address.script_pubkey(),
        witness: TxOutWitness::default(),
    };
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev.txid(),
                vout: vout as u32,
            },
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: Default::default(),
            witness: TxInWitness::default(),
        }],
        output: vec![
            owned(fee_slot),
            owned(change),
            TxOut::new_fee(miner_fee, asset),
        ],
    };
    let unsigned_path = format!("{out_path}.unsigned");
    fs::write(&unsigned_path, serialize_hex(&tx)).map_err(|e| e.to_string())?;
    let mut r = sign(kpath, &unsigned_path, 0, prev_path, vout, out_path)?;
    let _ = fs::remove_file(unsigned_path);
    r["fee_slot_sats"] = json!(fee_slot);
    r["change_sats"] = json!(change);
    r["miner_fee_sats"] = json!(miner_fee);
    Ok(r)
}

fn run() -> Result<serde_json::Value, String> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["new", path] => new(path),
        ["address", path] => {
            let (_, a) = identity(&key(path)?);
            Ok(json!({"ok": true, "network": "liquidtestnet", "address": a.to_string(),
                "script_pubkey": hex(a.script_pubkey().as_bytes())}))
        }
        ["recipient", path] => {
            let ctx = Secp256k1::new();
            let kp = secp::Keypair::from_secret_key(&ctx, &key(path)?);
            let (xonly, _) = kp.x_only_public_key();
            Ok(json!({"ok": true, "recipient_key": xonly.to_string(),
                "claim_script_pubkey": format!("5120{xonly}")}))
        }
        ["sign", path, tx, ix, prev, vout, out] => sign(
            path,
            tx,
            ix.parse().map_err(|_| "invalid input index")?,
            prev,
            vout.parse().map_err(|_| "invalid output index")?,
            out,
        ),
        ["split", path, prev, vout, fee_slot, miner_fee, out] => split(
            path,
            prev,
            vout.parse().map_err(|_| "invalid output index")?,
            fee_slot.parse().map_err(|_| "invalid fee slot")?,
            miner_fee.parse().map_err(|_| "invalid miner fee")?,
            out,
        ),
        ["fund", path, prev, vout, to, amount, miner_fee, out] => fund(
            path,
            prev,
            vout.parse().map_err(|_| "invalid output index")?,
            to,
            amount.parse().map_err(|_| "invalid amount")?,
            miner_fee.parse().map_err(|_| "invalid miner fee")?,
            out,
        ),
        ["burn", path, aprev, avout, fprev, fvout, asset, units, chain, escrow, recipient, spk, miner_fee, out] => {
            burn(
                path,
                aprev,
                avout.parse().map_err(|_| "invalid bridge-asset output index")?,
                fprev,
                fvout.parse().map_err(|_| "invalid fee output index")?,
                asset,
                units.parse().map_err(|_| "invalid units")?,
                chain.parse().map_err(|_| "invalid chain id")?,
                escrow,
                recipient,
                spk,
                miner_fee.parse().map_err(|_| "invalid miner fee")?,
                out,
            )
        }
        _ => Err("usage: sg16-liquid-testnet-wallet \
             new <keyfile> \
             | address <keyfile> \
             | recipient <keyfile> \
             | sign <keyfile> <tx.hex> <input-index> <prev-tx.hex> <vout> <out.hex> \
             | split <keyfile> <prev-tx.hex> <vout> <fee-slot-sats> <miner-fee-sats> <out.hex> \
             | fund <keyfile> <prev-tx.hex> <vout> <to-address> <amount-sats> <miner-fee-sats> <out.hex> \
             | burn <keyfile> <asset-prev-tx.hex> <asset-vout> <fee-prev-tx.hex> <fee-vout> <bridge-asset-id> \
             <units> <chain-id> <escrow 0x..> <evm-recipient 0x..> <escrow burnScriptPubKey hex> <miner-fee-sats> \
             <out.hex>"
            .into()),
    }
}

fn main() {
    match run() {
        Ok(r) => println!("{r}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simplicity::elements::Txid;
    use std::path::{Path, PathBuf};

    const SEPOLIA: u64 = 11_155_111;

    // Synthetic escrow and recipient addresses, and the burn script they give, written out byte by byte:
    // OP_RETURN PUSH70, "liquid-bridge-poc/burn", be64 11155111, the escrow, the recipient.
    const ESCROW: &str = "0x1111111111111111111111111111111111111111";
    const RECIPIENT: &str = "0x2222222222222222222222222222222222222222";
    const ESCROW_BURN_SPK: &str = concat!(
        "6a46",
        "6c69717569642d6272696467652d706f632f6275726e",
        "0000000000aa36a7",
        "1111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222"
    );

    // A synthetic bridge asset id for the transactions the tests build.
    const BRIDGE_ASSET: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    /// A scratch directory under the system temporary directory, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("sg16-wallet-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
        fn path(&self, file: &str) -> String {
            self.0.join(file).to_str().unwrap().to_string()
        }
        /// A fresh key file made by `new`.
        fn key(&self, file: &str) -> (String, SecretKey) {
            let path = self.path(file);
            new(&path).unwrap();
            let sk = key(&path).unwrap();
            (path, sk)
        }
        /// Writes a transaction with one placeholder input and these outputs; returns its file.
        fn funding(&self, file: &str, output: Vec<TxOut>) -> String {
            let txid = Txid::from_str(&"11".repeat(32)).unwrap();
            let tx = Transaction {
                version: 2,
                lock_time: LockTime::ZERO,
                output,
                input: vec![TxIn {
                    previous_output: OutPoint { txid, vout: 0 },
                    is_pegin: false,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    asset_issuance: Default::default(),
                    witness: TxInWitness::default(),
                }],
            };
            let path = self.path(file);
            fs::write(&path, serialize_hex(&tx)).unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn asset(display: &str) -> AssetId {
        AssetId::from_str(display).unwrap()
    }

    fn out(a: AssetId, value: u64, spk: Script) -> TxOut {
        TxOut {
            asset: Asset::Explicit(a),
            value: Value::Explicit(value),
            nonce: Nonce::Null,
            script_pubkey: spk,
            witness: TxOutWitness::default(),
        }
    }

    fn p2tr_of(sk: &SecretKey) -> Script {
        let (xonly, _) = secp::Keypair::from_secret_key(&Secp256k1::new(), sk).x_only_public_key();
        Script::from([&[0x51, 0x20][..], &xonly.serialize()[..]].concat())
    }

    fn witness(tx: &Transaction, ix: usize) -> Vec<Vec<u8>> {
        tx.input[ix]
            .witness
            .script_witness
            .iter()
            .map(|w| w.to_vec())
            .collect()
    }

    /// Checks input `ix`'s P2WPKH witness, spending `value` sat explicit, against the segwit v0 sighash; returns its
    /// key.
    fn verify_p2wpkh(tx: &Transaction, ix: usize, value: u64) -> bitcoin::PublicKey {
        let w = witness(tx, ix);
        assert_eq!(w.len(), 2, "P2WPKH witness: signature and key");
        let pk = bitcoin::PublicKey::from_slice(&w[1]).unwrap();
        let (der, ty) = w[0].split_at(w[0].len() - 1);
        assert_eq!(ty, [EcdsaSighashType::All as u8].as_slice());
        let sighash = SighashCache::new(tx).segwitv0_sighash(
            ix,
            &Script::new_p2pkh(&pk.pubkey_hash()),
            Value::Explicit(value),
            EcdsaSighashType::All,
        );
        Secp256k1::new()
            .verify_ecdsa(
                &secp::Message::from_digest(sighash.to_byte_array()),
                &secp::ecdsa::Signature::from_der(der).unwrap(),
                &pk.inner,
            )
            .unwrap();
        pk
    }

    /// Checks input `ix`'s key-path witness against the SIGHASH_DEFAULT taproot sighash and the untweaked key `xonly`.
    fn verify_p2tr(tx: &Transaction, ix: usize, spent: &[TxOut], xonly: &[u8]) {
        let w = witness(tx, ix);
        assert_eq!(w.len(), 1, "key-path witness: one signature");
        assert_eq!(w[0].len(), 64, "SIGHASH_DEFAULT: no sighash byte");
        let genesis = BlockHash::from_str(TESTNET_GENESIS).unwrap();
        let tap = SighashCache::new(tx)
            .taproot_key_spend_signature_hash(
                ix,
                &Prevouts::All(spent),
                SchnorrSighashType::Default,
                genesis,
            )
            .unwrap();
        Secp256k1::new()
            .verify_schnorr(
                &secp::schnorr::Signature::from_slice(&w[0]).unwrap(),
                &secp::Message::from_digest(tap.to_byte_array()),
                &secp::XOnlyPublicKey::from_slice(xonly).unwrap(),
            )
            .unwrap();
    }

    fn burn_spk(recipient: &str) -> String {
        hex(burn_script(
            SEPOLIA,
            &word20(ESCROW, "escrow").unwrap(),
            &word20(recipient, "recipient").unwrap(),
        )
        .as_bytes())
    }

    #[test]
    fn burn_script_is_the_documented_layout() {
        assert_eq!(burn_spk(RECIPIENT), ESCROW_BURN_SPK);
        let script = Script::from(unhex(ESCROW_BURN_SPK).unwrap());
        assert_eq!(script.len(), 72);
        assert!(script.is_op_return());
    }

    /// Burns `units` of a 100,000-unit claim output paid to `holder(key)`, with a 2,000-sat fee input; returns the
    /// tool's report, the transaction and the spent outputs.
    fn burn_from(
        s: &Scratch,
        holder: fn(&SecretKey) -> Script,
        units: u64,
    ) -> (serde_json::Value, Transaction, [TxOut; 2]) {
        let (kpath, sk) = s.key("wallet.key");
        let (_, address) = identity(&sk);
        let claim = out(asset(BRIDGE_ASSET), 100_000, holder(&sk));
        let fee = out(asset(TESTNET_LBTC), 2_000, address.script_pubkey());
        let aprev = s.funding(
            "claim.hex",
            vec![out(asset(TESTNET_LBTC), 1, Script::new()), claim.clone()],
        );
        let fprev = s.funding("fee.hex", vec![fee.clone()]);
        let hex_file = s.path("burn.hex");
        let r = burn(
            &kpath,
            &aprev,
            1,
            &fprev,
            0,
            BRIDGE_ASSET,
            units,
            SEPOLIA,
            ESCROW,
            RECIPIENT,
            &burn_spk(RECIPIENT),
            300,
            &hex_file,
        )
        .unwrap();
        (r, read_tx(&hex_file, "burn").unwrap(), [claim, fee])
    }

    fn p2wpkh_of(sk: &SecretKey) -> Script {
        identity(sk).1.script_pubkey()
    }

    #[test]
    fn burns_a_claim_paid_to_the_p2wpkh_address() {
        let s = Scratch::new("p2wpkh");
        let (r, tx, spent) = burn_from(&s, p2wpkh_of, 100_000);
        assert_eq!(r["bridge_asset_input"], "p2wpkh");
        assert_eq!(r["txid"], tx.txid().to_string());
        assert_eq!(r["burn_script_pubkey"], ESCROW_BURN_SPK);
        let lbtc = asset(TESTNET_LBTC);
        assert_eq!(
            tx.output,
            vec![
                out(
                    asset(BRIDGE_ASSET),
                    100_000,
                    Script::from(unhex(ESCROW_BURN_SPK).unwrap())
                ),
                out(lbtc, 1_700, spent[1].script_pubkey.clone()),
                TxOut::new_fee(300, lbtc),
            ]
        );
        let pk = verify_p2wpkh(&tx, 0, 100_000);
        assert_eq!(verify_p2wpkh(&tx, 1, 2_000), pk);
        assert_eq!(
            Address::p2wpkh(&pk, None, &AddressParams::LIQUID_TESTNET).script_pubkey(),
            spent[0].script_pubkey
        );
        tx.verify_tx_amt_proofs(&Secp256k1::new(), &spent).unwrap();
    }

    #[test]
    fn a_partial_burn_returns_the_change_to_the_claims_script() {
        for holder in [p2wpkh_of as fn(&SecretKey) -> Script, p2tr_of] {
            let s = Scratch::new("partial");
            let (_, tx, spent) = burn_from(&s, holder, 40_000);
            assert_eq!(
                explicit_of(&tx.output[0]),
                Some((asset(BRIDGE_ASSET), 40_000))
            );
            assert_eq!(
                tx.output[1],
                out(asset(BRIDGE_ASSET), 60_000, spent[0].script_pubkey.clone())
            );
            assert_eq!(tx.output.len(), 4);
        }
    }

    #[test]
    fn burns_a_claim_paid_to_the_p2tr_key() {
        let s = Scratch::new("p2tr");
        let (r, tx, spent) = burn_from(&s, p2tr_of, 100_000);
        assert_eq!(r["bridge_asset_input"], "p2tr");
        assert_eq!(hex(tx.output[0].script_pubkey.as_bytes()), ESCROW_BURN_SPK);
        verify_p2tr(&tx, 0, &spent, &spent[0].script_pubkey.as_bytes()[2..]);
        verify_p2wpkh(&tx, 1, 2_000);
    }

    #[test]
    fn refuses_other_holders_assets_amounts_and_burn_scripts() {
        let s = Scratch::new("refusals");
        let (kpath, sk) = s.key("wallet.key");
        let (_, other) = s.key("other.key");
        let lbtc = asset(TESTNET_LBTC);
        let mine = p2wpkh_of(&sk);
        let fee_ok = out(lbtc, 2_000, mine.clone());
        let spk = burn_spk(RECIPIENT);
        let hex_file = s.path("burn.hex");
        let attempt = |claim: TxOut,
                       fee: TxOut,
                       bridge_asset: &str,
                       units: u64,
                       chain: u64,
                       spk: &str,
                       miner_fee: u64| {
            let aprev = s.funding("claim.hex", vec![claim]);
            let fprev = s.funding("fee.hex", vec![fee]);
            let e = burn(
                &kpath,
                &aprev,
                0,
                &fprev,
                0,
                bridge_asset,
                units,
                chain,
                ESCROW,
                RECIPIENT,
                spk,
                miner_fee,
                &hex_file,
            )
            .unwrap_err();
            assert!(
                !Path::new(&hex_file).exists(),
                "nothing is written when {e}"
            );
            e
        };
        let bridge = |spk: Script| out(asset(BRIDGE_ASSET), 100_000, spk);
        let refused = |claim: TxOut, units: u64, spk: &str| {
            attempt(
                claim,
                fee_ok.clone(),
                BRIDGE_ASSET,
                units,
                SEPOLIA,
                spk,
                300,
            )
        };
        let refused_fee = |fee: TxOut, miner_fee: u64| {
            attempt(
                bridge(mine.clone()),
                fee,
                BRIDGE_ASSET,
                100_000,
                SEPOLIA,
                &spk,
                miner_fee,
            )
        };

        // Holders, assets and amounts.
        assert!(refused(bridge(p2wpkh_of(&other)), 100_000, &spk).contains("pays neither"));
        assert!(refused(bridge(p2tr_of(&other)), 100_000, &spk).contains("pays neither"));
        assert!(refused(out(lbtc, 100_000, mine.clone()), 100_000, &spk).contains("another asset"));
        let mut hidden = bridge(mine.clone());
        hidden.asset = Asset::Null;
        assert!(refused(hidden, 100_000, &spk).contains("confidential"));
        assert!(refused(bridge(mine.clone()), 100_001, &spk).contains("units must be"));
        assert!(refused(bridge(mine.clone()), 0, &spk).contains("units must be"));
        assert!(attempt(
            bridge(mine.clone()),
            fee_ok.clone(),
            TESTNET_LBTC,
            100_000,
            SEPOLIA,
            &spk,
            300
        )
        .contains("cannot be L-BTC"));

        // Fee input and miner fee.
        assert!(refused_fee(out(lbtc, 2_000, p2wpkh_of(&other)), 300)
            .contains("fee output is not explicit L-BTC"));
        assert!(
            refused_fee(out(asset(BRIDGE_ASSET), 2_000, mine.clone()), 300)
                .contains("fee output is not explicit L-BTC")
        );
        assert!(refused_fee(fee_ok.clone(), 99).starts_with("burn needs a >=100 sat miner fee"));
        assert!(refused_fee(fee_ok.clone(), 2_000 - 545)
            .starts_with("burn needs a >=100 sat miner fee"));
        assert!(refused_fee(fee_ok.clone(), 2_001).contains("exceeds the fee input"));

        // A chain other than Sepolia, even with the script the escrow would answer there.
        let on_chain_1 = hex(burn_script(
            1,
            &word20(ESCROW, "escrow").unwrap(),
            &word20(RECIPIENT, "r").unwrap(),
        )
        .as_bytes());
        assert!(attempt(
            bridge(mine.clone()),
            fee_ok.clone(),
            BRIDGE_ASSET,
            100_000,
            1,
            &on_chain_1,
            300
        )
        .contains("Sepolia"));

        // Bare scripts for another recipient, escrow or chain.
        let other_escrow =
            hex(burn_script(SEPOLIA, &[0x44; 20], &word20(RECIPIENT, "r").unwrap()).as_bytes());
        for wrong in [
            burn_spk("0x3333333333333333333333333333333333333333"),
            other_escrow,
            on_chain_1,
        ] {
            assert!(refused(bridge(mine.clone()), 100_000, &wrong)
                .contains("differs from the supplied"));
        }
        // Unrelated bare OP_RETURNs: destroyamount's empty one, the same payload pushed with OP_PUSHDATA1, a trailing
        // byte, a truncated payload.
        let payload = &ESCROW_BURN_SPK[4..];
        for wrong in [
            "6a".to_string(),
            format!("6a4c46{payload}"),
            format!("{ESCROW_BURN_SPK}00"),
            ESCROW_BURN_SPK[..ESCROW_BURN_SPK.len() - 2].to_string(),
        ] {
            assert!(refused(bridge(mine.clone()), 100_000, &wrong)
                .contains("differs from the supplied"));
        }
    }

    /// The unconfidential Liquid testnet P2WPKH address of a fixed key, another wallet for `fund` to pay.
    fn destination() -> Address {
        identity(&SecretKey::from_slice(&[0x22; 32]).unwrap()).1
    }

    /// Funds `to` with `amount` sats from a fresh fee key's 23,700-sat output 1 (output 0 holds 2,000 sats);
    /// returns the report, the transaction and the spent output.
    fn fund_from(
        s: &Scratch,
        to: &str,
        amount: u64,
        miner_fee: u64,
    ) -> Result<(serde_json::Value, Transaction, TxOut), String> {
        let (kpath, sk) = s.key("fee.key");
        let lbtc = asset(TESTNET_LBTC);
        let source = out(lbtc, 23_700, p2wpkh_of(&sk));
        let prev = s.funding(
            "split.hex",
            vec![out(lbtc, 2_000, p2wpkh_of(&sk)), source.clone()],
        );
        let hex_file = s.path("fund.hex");
        let r = fund(&kpath, &prev, 1, to, amount, miner_fee, &hex_file)?;
        Ok((r, read_tx(&hex_file, "fund")?, source))
    }

    #[test]
    fn funds_another_wallet_with_two_thousand_explicit_sats() {
        let s = Scratch::new("fund");
        let dest = destination();
        let (r, tx, source) = fund_from(&s, &dest.to_string(), 2_000, 100).unwrap();
        let lbtc = asset(TESTNET_LBTC);
        assert_eq!(
            tx.output,
            vec![
                out(lbtc, 2_000, dest.script_pubkey()),
                out(lbtc, 21_600, source.script_pubkey.clone()),
                TxOut::new_fee(100, lbtc),
            ]
        );
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output.vout, 1);
        let pk = verify_p2wpkh(&tx, 0, 23_700);
        assert_eq!(
            Address::p2wpkh(&pk, None, &AddressParams::LIQUID_TESTNET).script_pubkey(),
            source.script_pubkey
        );
        tx.verify_tx_amt_proofs(&Secp256k1::new(), &[source])
            .unwrap();
        assert_eq!(r["txid"], tx.txid().to_string());
        assert_eq!(r["to_script_pubkey"], hex(dest.script_pubkey().as_bytes()));
        assert_eq!(
            (
                r["fund_vout"].clone(),
                r["amount_sats"].clone(),
                r["change_sats"].clone()
            ),
            (json!(0), json!(2_000), json!(21_600))
        );
        // 100 sats clears the 0.1 sat/vB relay floor of this one-input, three-output shape with room to spare.
        assert!(tx.weight() < 4_000, "weight {}", tx.weight());
    }

    #[test]
    fn the_funded_output_is_a_fee_input_burn_accepts() {
        let s = Scratch::new("fund-burn");
        let (claim_key, claim_sk) = s.key("claim.key");
        let claim_address = identity(&claim_sk).1.to_string();
        let (_, fund_tx, _) = fund_from(&s, &claim_address, 2_000, 100).unwrap();
        let claim = out(asset(BRIDGE_ASSET), 100_000, p2wpkh_of(&claim_sk));
        let aprev = s.funding(
            "claim.hex",
            vec![out(asset(TESTNET_LBTC), 1, Script::new()), claim.clone()],
        );
        let hex_file = s.path("burn.hex");
        let r = burn(
            &claim_key,
            &aprev,
            1,
            &s.path("fund.hex"),
            0,
            BRIDGE_ASSET,
            100_000,
            SEPOLIA,
            ESCROW,
            RECIPIENT,
            &burn_spk(RECIPIENT),
            300,
            &hex_file,
        )
        .unwrap();
        assert_eq!(r["bridge_asset_input"], "p2wpkh");
        let burn_tx = read_tx(&hex_file, "burn").unwrap();
        assert_eq!(
            burn_tx.input[1].previous_output,
            OutPoint {
                txid: fund_tx.txid(),
                vout: 0
            }
        );
        verify_p2wpkh(&burn_tx, 1, 2_000);
        burn_tx
            .verify_tx_amt_proofs(&Secp256k1::new(), &[claim, fund_tx.output[0].clone()])
            .unwrap();
    }

    #[test]
    fn fund_refuses_other_destinations_sources_and_amounts() {
        let s = Scratch::new("fund-refusals");
        let (_, other) = s.key("other.key");
        let (pk, _) = identity(&other);
        let blinder = Some(secp::PublicKey::from_secret_key(&Secp256k1::new(), &other));
        let dest = destination().to_string();
        let refused = |to: &str, amount: u64, fee: u64| {
            let e = fund_from(&s, to, amount, fee).unwrap_err();
            assert!(
                !Path::new(&s.path("fund.hex")).exists(),
                "nothing is written when {e}"
            );
            fs::remove_file(s.path("fee.key")).unwrap();
            e
        };
        let confidential =
            Address::p2wpkh(&pk, blinder, &AddressParams::LIQUID_TESTNET).to_string();
        let mainnet = Address::p2wpkh(&pk, None, &AddressParams::LIQUID).to_string();
        let p2wsh = Address::p2wsh(
            &Script::from(vec![0x51]),
            None,
            &AddressParams::LIQUID_TESTNET,
        )
        .to_string();
        assert!(refused(&confidential, 2_000, 100).contains("unconfidential Liquid testnet"));
        assert!(refused(&mainnet, 2_000, 100).contains("unconfidential Liquid testnet"));
        assert!(refused(&p2wsh, 2_000, 100).contains("P2WPKH"));
        assert!(refused("not-an-address", 2_000, 100).contains("destination address"));
        assert!(refused(&dest, 645, 100).contains("payment must be at least 646"));
        assert!(refused(&dest, 2_000, 99).contains("miner fee must be at least 100"));
        assert!(refused(&dest, 23_700 - 100 - 545, 100).contains("change must be at least 546"));
        assert!(refused(&dest, 23_700, 100).contains("exceed"));

        // A source not explicit L-BTC at the signing key's own address, and that address as the destination.
        let (kpath, sk) = s.key("fee.key");
        let hex_file = s.path("fund.hex");
        let lbtc = asset(TESTNET_LBTC);
        for (source, why) in [
            (out(lbtc, 23_700, p2wpkh_of(&other)), "not explicit L-BTC"),
            (
                out(asset(BRIDGE_ASSET), 23_700, p2wpkh_of(&sk)),
                "not explicit L-BTC",
            ),
        ] {
            let prev = s.funding("split.hex", vec![source]);
            assert!(fund(&kpath, &prev, 0, &dest, 2_000, 100, &hex_file)
                .unwrap_err()
                .contains(why));
        }
        let prev = s.funding("split.hex", vec![out(lbtc, 23_700, p2wpkh_of(&sk))]);
        let own = identity(&sk).1.to_string();
        assert!(fund(&kpath, &prev, 0, &own, 2_000, 100, &hex_file)
            .unwrap_err()
            .contains("own address"));
        assert!(fund(&kpath, &prev, 1, &dest, 2_000, 100, &hex_file)
            .unwrap_err()
            .contains("out of range"));
        assert!(!Path::new(&hex_file).exists());
    }
}

/// The burn tag and burn scripts against the shared protocol vectors (vectors/protocol.json).
#[cfg(test)]
mod vectors {
    use super::*;

    fn text<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
        v[key]
            .as_str()
            .unwrap_or_else(|| panic!("vectors: no {key}"))
    }

    #[test]
    fn burn_scripts_are_the_vectors() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vectors/protocol.json");
        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(&BURN_TAG[..], text(&v["tags"], "burn").as_bytes());
        let cases = v["burn_script"].as_array().unwrap();
        assert!(!cases.is_empty(), "vectors: no burn_script case");
        for (i, c) in cases.iter().enumerate() {
            let (escrow, recipient) = (
                word20(text(c, "escrow"), "escrow").unwrap(),
                word20(text(c, "recipient"), "recipient").unwrap(),
            );
            let script = burn_script(c["chain_id"].as_u64().unwrap(), &escrow, &recipient);
            assert_eq!(
                format!("0x{}", hex(script.as_bytes())),
                text(c, "script"),
                "burn_script[{i}]"
            );
        }
    }
}
