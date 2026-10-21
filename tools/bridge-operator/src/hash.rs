//! The bridge's hashes: SHA-256 and SHA256d on the Liquid side, Keccak-256 on the Ethereum side.
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-256 of SHA-256: Elements txids, block hashes and Merkle nodes.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0; 32];
    hasher.finalize(&mut out);
    out
}

/// The four-byte Solidity selector of a function signature.
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn known_digests() {
        assert_eq!(
            hex::encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex::encode(&keccak256(b"Transfer(address,address,uint256)")),
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
        assert_eq!(
            selector("transfer(address,uint256)"),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
    }
}
