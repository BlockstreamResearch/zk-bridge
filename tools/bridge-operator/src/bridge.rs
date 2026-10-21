//! BridgeEscrow's rules as the operator commands need them, each mirroring the contract and
//! bridge-core/lib/bridge.js: addresses, the burn script, the federation's keys, relay batches, burn proofs, batch
//! references, calldata and the escrow's views.
use std::fmt;

use serde_json::Value;

use crate::abi::{self, word, Token, Word};
use crate::elements::{
    block_signatures, display_hex, merkle_branch, txid_from_display, Header, Signature, Transaction,
};
use crate::hash::keccak256;
use crate::hex;

/// BridgeEscrow.BURN_TAG, the first bytes of every burn payload.
pub const BURN_TAG: &[u8; 22] = b"liquid-bridge-poc/burn";

pub const SUBMIT_HEADERS: &str = "submitHeaders(bytes[],(bytes32,bytes32)[],bytes,uint256[])";
pub const REDEEM: &str =
    "redeem(address,(bytes,uint32,bytes32[],uint32),(uint256,uint256,bytes32[]))";
/// redeemTo(to, burn, ref): the burn's recipient, sending it, has the ETH paid to `to` instead.
pub const REDEEM_TO: &str =
    "redeemTo(address,(bytes,uint32,bytes32[],uint32),(uint256,uint256,bytes32[]))";
pub const DEPOSIT_EVENT: &str = "Deposit(uint64,uint64,bytes32,bytes32,bytes32,bytes)";

/// The most headers one submitHeaders batch carries.
pub const MAX_BATCH: u64 = 100;

/// An Ethereum address that can receive a redemption: never zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// `0x` and 40 hex digits; a mixed-case address must carry a correct EIP-55 checksum.
    pub fn parse(text: &str) -> Result<Address, String> {
        let s = text.trim();
        let digits = s
            .strip_prefix("0x")
            .filter(|d| d.len() == 40 && d.bytes().all(|c| c.is_ascii_hexdigit()))
            .ok_or("an Ethereum address is 0x followed by 40 hex characters")?;
        let lower = digits.to_ascii_lowercase();
        if digits != lower && digits != digits.to_ascii_uppercase() {
            let checksum = hex::encode(&keccak256(lower.as_bytes()));
            for (c, h) in digits.chars().zip(checksum.chars()) {
                // Checked hex digits above, and `checksum` is hex.
                let upper = h.to_digit(16).expect("hex digit") >= 8;
                if c.is_ascii_alphabetic() && c.is_ascii_uppercase() != upper {
                    return Err("address checksum is wrong".into());
                }
            }
        }
        let bytes = hex::decode_array(&lower)?;
        if bytes == [0; 20] {
            return Err("the zero address cannot receive a redemption".into());
        }
        Ok(Address(bytes))
    }
}

impl fmt::Display for Address {
    /// Lower case, `0x`-prefixed.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&hex::prefixed(&self.0))
    }
}

/// BridgeEscrow.burnScriptPubKey(recipient): OP_RETURN PUSH70 (BURN_TAG || be64 chain id || escrow || recipient), a
/// bare OP_RETURN output script of 72 bytes, with no address.
pub fn burn_script(chain_id: u64, escrow: &Address, recipient: &Address) -> Vec<u8> {
    let mut script = vec![0x6a, 0x46];
    script.extend_from_slice(BURN_TAG);
    script.extend_from_slice(&chain_id.to_be_bytes());
    script.extend_from_slice(&escrow.0);
    script.extend_from_slice(&recipient.0);
    script
}

/// The keys and threshold of a block-signing script LiquidLightClient accepts.
#[derive(Debug, PartialEq, Eq)]
pub struct Federation {
    pub threshold: usize,
    pub keys: Vec<[u8; 33]>,
}

fn key_at(script: &[u8], at: usize) -> [u8; 33] {
    // Infallible: callers have checked the script's length against its key count.
    script[at..at + 33].try_into().expect("33 bytes")
}

/// The number of keys of `OP_m <key>... OP_n OP_CHECKMULTISIG` the script's length allows: 1 to 16.
fn multisig_keys(script: &[u8]) -> Option<usize> {
    let rest = script.len().checked_sub(3)?;
    let n = rest / 34;
    (rest % 34 == 0 && (1..=16).contains(&n)).then_some(n)
}

/// The compressed keys of `<key> OP_CHECKSIG` or `OP_m <key>... OP_n OP_CHECKMULTISIG`, as a relay batch carries
/// them; the contract checks the rest of the script.
pub fn federation_keys(script: &[u8]) -> Result<Vec<[u8; 33]>, String> {
    if script.len() == 35 && script[0] == 0x21 && script[34] == 0xac {
        return Ok(vec![key_at(script, 1)]);
    }
    match multisig_keys(script) {
        Some(n) if script.last() == Some(&0xae) => {
            Ok((0..n).map(|i| key_at(script, 2 + 34 * i)).collect())
        }
        _ => Err("unsupported block-signing script".into()),
    }
}

/// The federation of a witness script, checked as LiquidLightClient checks it.
pub fn federation(script: &[u8]) -> Result<Federation, String> {
    if script.len() == 35 && script[0] == 0x21 && script[34] == 0xac {
        return Ok(Federation {
            threshold: 1,
            keys: federation_keys(script)?,
        });
    }
    let unsupported =
        || "the witness script is not a multisig LiquidLightClient supports".to_owned();
    let n = multisig_keys(script).ok_or_else(unsupported)?;
    let m = usize::from(script[0])
        .checked_sub(0x50)
        .filter(|m| (1..=n).contains(m))
        .ok_or_else(unsupported)?;
    if usize::from(script[script.len() - 2]) != 0x50 + n || script[script.len() - 1] != 0xae {
        return Err(unsupported());
    }
    if (0..n).any(|i| script[1 + 34 * i] != 0x21) {
        return Err("the witness script has a non-compressed key".into());
    }
    Ok(Federation {
        threshold: m,
        keys: federation_keys(script)?,
    })
}

/// The y coordinate, with the parity of a compressed key's prefix: BridgeEscrow's keyY argument.
pub fn lift_y(key: &[u8; 33]) -> Result<[u8; 32], String> {
    if key[0] != 0x02 && key[0] != 0x03 {
        return Err("not a compressed key".into());
    }
    let point =
        secp256k1::PublicKey::from_slice(key).map_err(|_| "key is not on secp256k1".to_owned())?;
    // Infallible: an uncompressed key is 0x04, x and y.
    Ok(point.serialize_uncompressed()[33..]
        .try_into()
        .expect("32 bytes"))
}

/// A submitHeaders batch: consecutive headers of one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayBatch {
    /// The headers' hash forms.
    pub headers: Vec<Vec<u8>>,
    /// The last header's block signatures.
    pub sigs: Vec<Signature>,
    /// The witness script of a new signblockscript, empty if the keys did not change.
    pub witness_script: Vec<u8>,
    /// The y coordinates of the new keys, empty if they did not change.
    pub key_y: Vec<[u8; 32]>,
    pub first_height: u64,
}

/// The batch of raw headers `header_hexes`, carrying the witness script and key y coordinates when the batch
/// starts under a signblockscript other than the light client's `current` one (a DynaFed key change).
pub fn relay_batch(header_hexes: &[String], current: &[u8; 32]) -> Result<RelayBatch, String> {
    let headers = header_hexes
        .iter()
        .map(|h| Header::parse(&hex::decode(h)?))
        .collect::<Result<Vec<_>, _>>()?;
    let (first, tip) = match (headers.first(), headers.last()) {
        (Some(first), Some(tip)) => (first, tip),
        _ => return Err("no headers to relay".into()),
    };
    for (i, pair) in headers.windows(2).enumerate() {
        if pair[1].prev != pair[0].hash
            || u64::from(pair[1].height) != u64::from(pair[0].height) + 1
        {
            return Err(format!("header {} is not the child of header {i}", i + 1));
        }
    }
    let (witness_script, sigs) = block_signatures(tip)?;
    let changed = keccak256(&first.signblockscript) != *current;
    let (witness_script, key_y) = if changed {
        let key_y = federation_keys(&witness_script)?
            .iter()
            .map(lift_y)
            .collect::<Result<Vec<_>, _>>()?;
        (witness_script, key_y)
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(RelayBatch {
        first_height: u64::from(first.height),
        headers: headers.into_iter().map(|h| h.hash_form).collect(),
        sigs,
        witness_script,
        key_y,
    })
}

pub fn submit_headers_calldata(batch: &RelayBatch) -> String {
    abi::call(
        SUBMIT_HEADERS,
        &[
            Token::Array(batch.headers.iter().cloned().map(Token::Bytes).collect()),
            Token::Array(
                batch
                    .sigs
                    .iter()
                    .map(|s| Token::Tuple(vec![Token::Bytes32(s.r), Token::Bytes32(s.s)]))
                    .collect(),
            ),
            Token::Bytes(batch.witness_script.clone()),
            Token::Array(batch.key_y.iter().copied().map(Token::Uint).collect()),
        ],
    )
}

/// BridgeEscrow's BurnProof: the burn's txid form, the output, and its Merkle branch and position in its block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnProof {
    pub transaction: Vec<u8>,
    pub vout: u32,
    pub branch: Vec<[u8; 32]>,
    pub position: u32,
}

/// A burn proof and the block it is in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenBurn {
    pub burn: BurnProof,
    pub height: u64,
    pub merkle_root: [u8; 32],
}

/// The BurnProof of output `vout` of the burn `tx_hex` (either serialization), after the checks BridgeEscrow makes
/// that need no chain state: its txid must be `txid_display`, and `txids_display`, the burn block's txids in block
/// order, must give the Merkle root of `header_hex`, the burn block's header.
pub fn burn_proof(
    txid_display: &str,
    tx_hex: &str,
    vout: u32,
    txids_display: &[String],
    header_hex: &str,
) -> Result<ProvenBurn, String> {
    let tx = Transaction::parse(&hex::decode(tx_hex)?)?;
    if display_hex(&tx.txid) != txid_display.to_ascii_lowercase() {
        return Err("transaction bytes do not match the txid".into());
    }
    let header = Header::parse(&hex::decode(header_hex)?)?;
    let leaves = txids_display
        .iter()
        .map(|t| txid_from_display(t))
        .collect::<Result<Vec<_>, _>>()?;
    let position = leaves
        .iter()
        .position(|t| *t == tx.txid)
        .ok_or("the transaction is not in that block")?;
    let (root, branch) = merkle_branch(&leaves, position)?;
    if root != header.merkle_root {
        return Err("txids do not reproduce the block's Merkle root".into());
    }
    Ok(ProvenBurn {
        burn: BurnProof {
            transaction: tx.txid_form,
            vout,
            branch,
            position: u32::try_from(position).map_err(|_| "the block has too many transactions")?,
        },
        height: u64::from(header.height),
        merkle_root: header.merkle_root,
    })
}

/// A batch of the light client, as batchAt(index) returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub index: u64,
    pub first_height: u64,
    pub count: u64,
    pub root: [u8; 32],
}

impl Batch {
    /// batchAt's return value: (uint32 firstHeight, uint32 count, bytes32 root).
    pub fn decode(data: &[u8], index: u64) -> Result<Batch, String> {
        if data.len() < 96 {
            return Err("batchAt returned too little data".into());
        }
        Ok(Batch {
            index,
            first_height: abi::word_u64(&abi::word_at(data, 0)?)?,
            count: abi::word_u64(&abi::word_at(data, 1)?)?,
            root: abi::word_at(data, 2)?,
        })
    }

    pub fn holds(&self, height: u64) -> bool {
        self.first_height <= height && height - self.first_height < self.count
    }
}

/// BridgeEscrow's BlockRef: a height's leaf in a batch, and its path to the batch root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRef {
    pub batch: u64,
    pub index: u64,
    pub path: Vec<[u8; 32]>,
}

/// The BlockRef of `height` in LiquidLightClient's batch tree: leaves keccak256(merkleRoot) for the batch's heights
/// in order, zero-padded to a power of two, parents keccak256(left || right). Checks the rebuilt root against the
/// stored one.
pub fn batch_ref(
    batch: &Batch,
    merkle_roots: &[[u8; 32]],
    height: u64,
) -> Result<BlockRef, String> {
    if merkle_roots.len() as u64 != batch.count {
        return Err("need one Merkle root per batch header".into());
    }
    if !batch.holds(height) {
        return Err("height outside the batch".into());
    }
    let index = height - batch.first_height;
    let size = merkle_roots.len().next_power_of_two();
    let mut level: Vec<[u8; 32]> = (0..size)
        .map(|i| merkle_roots.get(i).map_or([0; 32], |r| keccak256(r)))
        .collect();
    let mut path = Vec::new();
    // In range: index < count.
    let mut i = usize::try_from(index).expect("index below the batch's length");
    while level.len() > 1 {
        path.push(level[i ^ 1]);
        level = level
            .chunks(2)
            .map(|pair| keccak256(&[pair[0], pair[1]].concat()))
            .collect();
        i >>= 1;
    }
    if level[0] != batch.root {
        return Err("rebuilt batch root differs from the stored one".into());
    }
    Ok(BlockRef {
        batch: batch.index,
        index,
        path,
    })
}

/// redeem(recipient, burn, ref) with `REDEEM`, or redeemTo(to, burn, ref) with `REDEEM_TO`: the same layout.
pub fn redeem_calldata(
    signature: &str,
    payee: &Address,
    burn: &BurnProof,
    block: &BlockRef,
) -> String {
    let hashes = |hs: &[[u8; 32]]| Token::Array(hs.iter().copied().map(Token::Bytes32).collect());
    abi::call(
        signature,
        &[
            Token::Address(payee.0),
            Token::Tuple(vec![
                Token::Bytes(burn.transaction.clone()),
                Token::Uint(word(u64::from(burn.vout))),
                hashes(&burn.branch),
                Token::Uint(word(u64::from(burn.position))),
            ]),
            Token::Tuple(vec![
                Token::Uint(word(block.batch)),
                Token::Uint(word(block.index)),
                hashes(&block.path),
            ]),
        ],
    )
}

/// Calldata of an escrow view without arguments, e.g. `lcTipHeight()`.
pub fn view(signature: &str) -> String {
    abi::call(signature, &[])
}

/// Calldata of batchAt(index).
pub fn batch_at(index: u64) -> String {
    abi::call("batchAt(uint256)", &[Token::Uint(word(index))])
}

/// The Deposit event's topic, `0x`-prefixed lower-case hex as RPCs return topics.
pub fn deposit_topic() -> String {
    hex::prefixed(&keccak256(DEPOSIT_EVENT.as_bytes()))
}

/// A Deposit event: its index, its units and the recipient scriptPubKey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    /// The indexed deposit number, as its word.
    pub index: Word,
    pub units: u64,
    pub script: Vec<u8>,
}

impl Deposit {
    /// The Deposit event of an eth_getLogs entry: `Ok(None)` if the log is another contract's or another
    /// event's, an error if it is malformed. Its data is (units, recipient, leaf, accumulator, scriptPubKey).
    pub fn from_log(log: &Value, escrow: &Address) -> Result<Option<Deposit>, String> {
        let malformed = || "malformed Deposit log".to_owned();
        let address = log
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(malformed)?;
        let topics = log
            .get("topics")
            .and_then(Value::as_array)
            .ok_or_else(malformed)?;
        if !address.eq_ignore_ascii_case(&escrow.to_string())
            || topics.first().and_then(Value::as_str) != Some(deposit_topic().as_str())
        {
            return Ok(None);
        }
        let index = topics
            .get(1)
            .and_then(Value::as_str)
            .ok_or_else(malformed)?;
        let index = hex::decode(index.strip_prefix("0x").ok_or_else(malformed)?)?;
        if index.len() > 32 {
            return Err(malformed());
        }
        let mut word = [0; 32];
        word[32 - index.len()..].copy_from_slice(&index);

        let data = hex::decode(
            log.get("data")
                .and_then(Value::as_str)
                .ok_or_else(malformed)?,
        )?;
        let units = abi::word_u64(&abi::word_at(&data, 0)?)?;
        let at =
            usize::try_from(abi::word_u64(&abi::word_at(&data, 4)?)?).map_err(|_| malformed())?;
        let len = data
            .get(at..)
            .and_then(|tail| abi::word_at(tail, 0).ok())
            .and_then(|w| abi::word_u64(&w).ok())
            .and_then(|len| usize::try_from(len).ok())
            .ok_or_else(malformed)?;
        let script = at
            .checked_add(32)
            .and_then(|start| data.get(start..start.checked_add(len)?))
            .ok_or_else(malformed)?;
        Ok(Some(Deposit {
            index: word,
            units,
            script: script.to_vec(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55() {
        assert_eq!(
            Address::parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
                .unwrap()
                .to_string(),
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        );
        assert_eq!(
            Address::parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD").unwrap_err(),
            "address checksum is wrong"
        );
        assert!(Address::parse(&format!("0x{}", "AB".repeat(20))).is_ok());
        assert_eq!(
            Address::parse(&format!("0x{}", "00".repeat(20))).unwrap_err(),
            "the zero address cannot receive a redemption"
        );
        for bad in [
            "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            "0x5aae",
            "0X5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
        ] {
            assert_eq!(
                Address::parse(bad).unwrap_err(),
                "an Ethereum address is 0x followed by 40 hex characters"
            );
        }
    }
}
