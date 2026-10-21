//! The subset of the Solidity ABI the bridge's calls need, as bridge-core/lib/abi.js encodes it.
use crate::hash::selector;
use crate::hex;

/// A 32-byte ABI word.
pub type Word = [u8; 32];

/// A value to encode. Arrays and tuples hold their elements; an array is always dynamic, and a tuple is dynamic
/// when any member is.
#[derive(Clone, Debug)]
pub enum Token {
    Address([u8; 20]),
    /// Any uintN, as its big-endian word.
    Uint(Word),
    Bytes32([u8; 32]),
    Bytes(Vec<u8>),
    Array(Vec<Token>),
    Tuple(Vec<Token>),
}

/// The word of an unsigned integer.
pub fn word(n: u64) -> Word {
    let mut w = [0; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

impl Token {
    fn is_dynamic(&self) -> bool {
        match self {
            Token::Bytes(_) | Token::Array(_) => true,
            Token::Tuple(members) => members.iter().any(Token::is_dynamic),
            _ => false,
        }
    }

    /// The bytes a static value takes in place.
    fn static_size(&self) -> usize {
        match self {
            Token::Tuple(members) => members.iter().map(Token::static_size).sum(),
            _ => 32,
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            Token::Address(a) => {
                let mut out = vec![0; 12];
                out.extend_from_slice(a);
                out
            }
            Token::Uint(w) | Token::Bytes32(w) => w.to_vec(),
            Token::Bytes(b) => {
                let mut out = word(b.len() as u64).to_vec();
                out.extend_from_slice(b);
                out.resize(32 + b.len().div_ceil(32) * 32, 0);
                out
            }
            Token::Array(elements) => {
                let mut out = word(elements.len() as u64).to_vec();
                out.extend_from_slice(&encode_tuple(elements));
                out
            }
            Token::Tuple(members) => encode_tuple(members),
        }
    }
}

/// Heads in order, each dynamic member's head the offset of its tail, then the tails.
fn encode_tuple(members: &[Token]) -> Vec<u8> {
    let head_size: usize = members
        .iter()
        .map(|t| if t.is_dynamic() { 32 } else { t.static_size() })
        .sum();
    let mut head = Vec::with_capacity(head_size);
    let mut tail = Vec::new();
    for t in members {
        let encoded = t.encode();
        if t.is_dynamic() {
            head.extend_from_slice(&word((head_size + tail.len()) as u64));
            tail.extend_from_slice(&encoded);
        } else {
            head.extend_from_slice(&encoded);
        }
    }
    head.extend_from_slice(&tail);
    head
}

/// `0x`-prefixed calldata of `signature`, e.g. `batchAt(uint256)`, with `args` in order.
pub fn call(signature: &str, args: &[Token]) -> String {
    let mut data = selector(signature).to_vec();
    data.extend_from_slice(&encode_tuple(args));
    hex::prefixed(&data)
}

/// Word `i` of return data.
pub fn word_at(data: &[u8], i: usize) -> Result<Word, String> {
    data.get(32 * i..32 * (i + 1))
        .map(|w| w.try_into().expect("32 bytes"))
        .ok_or_else(|| "ABI data too short".to_owned())
}

/// A uint word as a u64; the bridge reads heights, counts and indices, none of which can exceed it.
pub fn word_u64(w: &Word) -> Result<u64, String> {
    if w[..24].iter().any(|&b| b != 0) {
        return Err("ABI value exceeds 64 bits".into());
    }
    Ok(u64::from_be_bytes(w[24..].try_into().expect("8 bytes")))
}

/// The first word of return data as a u64.
pub fn uint(data: &[u8]) -> Result<u64, String> {
    word_u64(&word_at(data, 0)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words() {
        assert_eq!(word(0x0102)[30..], [1, 2]);
        assert_eq!(uint(&word(7)).unwrap(), 7);
        assert!(uint(&[0; 31]).is_err());
        let mut big = word(1);
        big[0] = 1;
        assert!(uint(&big).is_err());
        assert_eq!(call("f()", &[]).len(), 10);
    }
}
