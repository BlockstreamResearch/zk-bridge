//! The hashing and error helpers the claim harness shares.

use sha2::{Digest, Sha256};

/// A 32-byte hash or field element, in the byte order it is serialized.
pub type Root = [u8; 32];

/// A result whose error names the failed condition.
pub type Result<T> = std::result::Result<T, &'static str>;

/// `Ok(())` if `ok`, otherwise the error `why`.
pub fn require(ok: bool, why: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why)
    }
}

/// SHA-256 of `data`.
pub fn sha(data: &[u8]) -> Root {
    Sha256::digest(data).into()
}

/// SHA-256 of `a || b`: one node of the deposit tree.
pub fn pair(a: Root, b: Root) -> Root {
    sha(&[a.as_slice(), b.as_slice()].concat())
}
