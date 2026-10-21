//! Elements (Liquid) consensus encodings, mirroring contracts/solidity/contracts/ElementsParser.sol and
//! bridge-core/lib/elements.js: the txid form of a transaction, the hash form and block signatures of a DynaFed
//! header, and a transaction's Merkle branch. Inputs are the full serializations nodes and Esplora serve.
use crate::hash::{sha256, sha256d};
use crate::hex;

/// A cursor over consensus-encoded bytes that fails on any read past the end.
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn is_done(&self) -> bool {
        self.pos == self.bytes.len()
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.bytes.len() - self.pos < n {
            return Err(format!("truncated at byte {}", self.pos));
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        // Infallible: `take` returned exactly N bytes.
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    pub fn u32_le(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Bitcoin CompactSize; non-minimal encodings are rejected, as Elements does.
    pub fn compact_size(&mut self) -> Result<u64, String> {
        let (value, min) = match self.u8()? {
            first @ 0..=0xfc => return Ok(u64::from(first)),
            0xfd => (u64::from(u16::from_le_bytes(self.array()?)), 0xfd),
            0xfe => (u64::from(u32::from_le_bytes(self.array()?)), 0x1_0000),
            0xff => (u64::from_le_bytes(self.array()?), 0x1_0000_0000),
        };
        if value < min {
            return Err("non-canonical CompactSize".into());
        }
        Ok(value)
    }

    pub fn var_bytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.compact_size()?;
        // A length beyond usize cannot be in memory, so it is truncated data.
        self.take(usize::try_from(n).unwrap_or(usize::MAX))
    }
}

const ISSUANCE_FLAG: u32 = 0x8000_0000;
const NULL_INDEX: u32 = 0xffff_ffff;

/// Skips a confidential commitment: null, explicit (`explicit_size` bytes with its prefix), or a 33-byte commitment
/// with prefix `a` or `b`.
fn skip_commitment(r: &mut Reader, explicit_size: usize, a: u8, b: u8) -> Result<(), String> {
    match r.u8()? {
        0x00 => Ok(()),
        0x01 => r.take(explicit_size - 1).map(drop),
        prefix if prefix == a || prefix == b => r.take(32).map(drop),
        prefix => Err(format!("bad commitment prefix 0x{prefix:x}")),
    }
}

/// A transaction as BridgeEscrow.redeem takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Version, flags byte 0, inputs, outputs and locktime: the bytes that SHA256d hashes to the txid.
    pub txid_form: Vec<u8>,
    /// The txid, internal byte order.
    pub txid: [u8; 32],
}

impl Transaction {
    /// Parses a transaction in either serialization. With flags 1 the witness follows the locktime; the txid
    /// does not commit to it, so it is not read.
    pub fn parse(raw: &[u8]) -> Result<Transaction, String> {
        let mut r = Reader::new(raw);
        r.u32_le()?; // version
        let flags = r.u8()?;
        if flags != 0 && flags != 1 {
            return Err("unknown transaction flags".into());
        }
        let inputs = r.compact_size()?;
        if inputs == 0 {
            return Err("transaction has no inputs".into());
        }
        for _ in 0..inputs {
            r.take(32)?; // previous txid
            let n = r.u32_le()?;
            r.var_bytes()?; // scriptSig
            r.u32_le()?; // sequence
            if n != NULL_INDEX && n & ISSUANCE_FLAG != 0 {
                r.take(64)?; // nonce, entropy
                skip_commitment(&mut r, 9, 0x08, 0x09)?; // amount
                skip_commitment(&mut r, 9, 0x08, 0x09)?; // inflation keys
            }
        }
        let outputs = r.compact_size()?;
        if outputs == 0 {
            return Err("transaction has no outputs".into());
        }
        for _ in 0..outputs {
            skip_commitment(&mut r, 33, 0x0a, 0x0b)?; // asset
            skip_commitment(&mut r, 9, 0x08, 0x09)?; // value
            skip_commitment(&mut r, 33, 0x02, 0x03)?; // nonce
            r.var_bytes()?; // scriptPubKey
        }
        r.u32_le()?; // locktime
        let end = r.position();
        if flags == 0 && !r.is_done() {
            return Err("trailing bytes after the transaction".into());
        }
        let mut txid_form = Vec::with_capacity(end);
        txid_form.extend_from_slice(&raw[..4]);
        txid_form.push(0);
        txid_form.extend_from_slice(&raw[5..end]);
        let txid = sha256d(&txid_form);
        Ok(Transaction { txid_form, txid })
    }
}

/// Reads DynaFed params, returning the signblockscript, or `None` for null params.
fn read_params<'a>(r: &mut Reader<'a>) -> Result<Option<&'a [u8]>, String> {
    let kind = r.u8()?;
    if kind == 0 {
        return Ok(None);
    }
    if kind != 1 && kind != 2 {
        return Err(format!("bad DynaFed params type {kind}"));
    }
    let signblockscript = r.var_bytes()?;
    r.u32_le()?; // signblock witness limit
    if kind == 1 {
        r.take(32)?; // elided root
    } else {
        r.var_bytes()?; // fedpeg program
        r.var_bytes()?; // fedpegscript
        for _ in 0..r.compact_size()? {
            r.var_bytes()?; // extension space
        }
    }
    Ok(Some(signblockscript))
}

/// A DynaFed header as /block/:hash/header serves it: the hash-form fields, then the signblock witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The bytes the block hash commits to: the header without its signblock witness.
    pub hash_form: Vec<u8>,
    /// The block hash, internal byte order.
    pub hash: [u8; 32],
    pub prev: [u8; 32],
    pub merkle_root: [u8; 32],
    pub height: u32,
    /// The current params' signblockscript.
    pub signblockscript: Vec<u8>,
    /// The signblock witness stack; empty for a header served without it.
    pub witness: Vec<Vec<u8>>,
}

impl Header {
    pub fn parse(raw: &[u8]) -> Result<Header, String> {
        let mut r = Reader::new(raw);
        let version = r.u32_le()?;
        if version & 0x8000_0000 == 0 {
            return Err("not a DynaFed header".into());
        }
        let prev = r.array()?;
        let merkle_root = r.array()?;
        r.u32_le()?; // time
        let height = r.u32_le()?;
        let signblockscript = read_params(&mut r)?
            .ok_or("header has null current params")?
            .to_vec();
        read_params(&mut r)?; // proposed
        let hash_form = raw[..r.position()].to_vec();
        let mut witness = Vec::new();
        if !r.is_done() {
            for _ in 0..r.compact_size()? {
                witness.push(r.var_bytes()?.to_vec());
            }
        }
        if !r.is_done() {
            return Err("trailing bytes after the header".into());
        }
        let hash = sha256d(&hash_form);
        Ok(Header {
            hash_form,
            hash,
            prev,
            merkle_root,
            height,
            signblockscript,
            witness,
        })
    }
}

/// An ECDSA signature as LiquidLightClient takes it: 32-byte big-endian (r, s).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// A DER ECDSA signature followed by its sighash byte, as in the signblock witness.
pub fn parse_der_signature(sig: &[u8]) -> Result<Signature, String> {
    if sig.len() < 9 {
        return Err("not a DER signature".into());
    }
    let der = &sig[..sig.len() - 1];
    if der[0] != 0x30 || usize::from(der[1]) != der.len() - 2 {
        return Err("not a DER signature".into());
    }
    let mut p = 2;
    let mut integer = || -> Result<[u8; 32], String> {
        if der.get(p) != Some(&0x02) {
            return Err("not a DER integer".into());
        }
        let len = usize::from(*der.get(p + 1).ok_or("bad DER integer length")?);
        if len == 0 || len > 33 || p + 2 + len > der.len() {
            return Err("bad DER integer length".into());
        }
        let mut v = &der[p + 2..p + 2 + len];
        p += 2 + len;
        while let [0, rest @ ..] = v {
            v = rest;
        }
        if v.len() > 32 {
            return Err("DER integer exceeds 32 bytes".into());
        }
        let mut out = [0; 32];
        out[32 - v.len()..].copy_from_slice(v);
        Ok(out)
    };
    let r = integer()?;
    let s = integer()?;
    if p != der.len() {
        return Err("trailing bytes in DER signature".into());
    }
    Ok(Signature { r, s })
}

/// The witness script and block signatures of a header, in witness order. The signblockscript must be the P2WSH
/// of the witness script, carried as the last witness item; OP_CHECKMULTISIG scripts carry an empty dummy first.
pub fn block_signatures(header: &Header) -> Result<(Vec<u8>, Vec<Signature>), String> {
    let (sigs, script) = match header.witness.as_slice() {
        [sigs @ .., script] if !sigs.is_empty() => (sigs, script),
        _ => {
            return Err("header has no signblock witness; fetch it with /block/:hash/header".into())
        }
    };
    let spk = &header.signblockscript;
    if spk.len() != 34 || spk[0] != 0x00 || spk[1] != 0x20 || spk[2..] != sha256(script) {
        return Err("signblockscript is not the P2WSH of the witness script".into());
    }
    let sigs = if script.last() == Some(&0xae) {
        if !sigs[0].is_empty() {
            return Err("missing OP_CHECKMULTISIG dummy".into());
        }
        &sigs[1..]
    } else {
        sigs
    };
    let signatures = sigs
        .iter()
        .map(|s| parse_der_signature(s))
        .collect::<Result<_, _>>()?;
    Ok((script.clone(), signatures))
}

/// The Bitcoin-style Merkle root of `leaves` and the branch of leaf `index`, internal byte order.
pub fn merkle_branch(
    leaves: &[[u8; 32]],
    index: usize,
) -> Result<([u8; 32], Vec<[u8; 32]>), String> {
    if index >= leaves.len() {
        return Err("index outside the block".into());
    }
    let mut level = leaves.to_vec();
    let mut branch = Vec::new();
    let mut i = index;
    while level.len() > 1 {
        branch.push(*level.get(i ^ 1).unwrap_or(&level[i]));
        level = level
            .chunks(2)
            .map(|pair| sha256d(&[pair[0], *pair.last().expect("chunks are not empty")].concat()))
            .collect();
        i >>= 1;
    }
    Ok((level[0], branch))
}

/// Internal-order txid or block-hash bytes from the display hex explorers show.
pub fn txid_from_display(display: &str) -> Result<[u8; 32], String> {
    if display.len() != 64 || display.starts_with("0x") {
        return Err("a txid is 64 hex characters".into());
    }
    let mut internal: [u8; 32] =
        hex::decode_array(display).map_err(|_| "a txid is 64 hex characters".to_owned())?;
    internal.reverse();
    Ok(internal)
}

/// Display hex of an internal-order hash.
pub fn display_hex(internal: &[u8; 32]) -> String {
    let mut display = *internal;
    display.reverse();
    hex::encode(&display)
}
