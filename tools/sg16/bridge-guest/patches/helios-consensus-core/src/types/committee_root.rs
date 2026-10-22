//! sg16 bridge patch: the hash tree root of a sync committee, computed directly for `sync_committee_root`.
//! In the zkVM, tree_hash's derive spent 8,707,608 cycles per 512-key committee root (two roots: 17,415,215 in
//! target/guest-optimization/opus/runs/tracked/current.tracker.log), packing each key one byte at a time.

use sha2::digest::generic_array::GenericArray;

/// hash(merkle root of the key roots || root of the aggregate key), where a key's root is the hash of its two
/// 32-byte chunks, the second zero-padded. Every hash is of 64 bytes.
pub(crate) fn root<'a>(keys: impl Iterator<Item = &'a [u8]>, aggregate: &[u8]) -> [u8; 32] {
    let key_root = |key: &[u8]| {
        let mut chunks = [0u8; 64];
        chunks[..48].copy_from_slice(key);
        sha256_64(&chunks)
    };
    let node = |left: &[u8; 32], right: &[u8; 32]| {
        let mut children = [0u8; 64];
        children[..32].copy_from_slice(left);
        children[32..].copy_from_slice(right);
        sha256_64(&children)
    };
    let mut layer: Vec<[u8; 32]> = keys.map(key_root).collect();
    assert!(layer.len().is_power_of_two(), "sync committee size");
    let mut width = layer.len();
    while width > 1 {
        for i in 0..width / 2 {
            layer[i] = node(&layer[2 * i], &layer[2 * i + 1]);
        }
        width /= 2;
    }
    node(&layer[0], &key_root(aggregate))
}

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The second block of every 64-byte message: 0x80, zeros, and the bit length 512 as a big-endian u64.
const PADDING: [u8; 64] = {
    let mut block = [0u8; 64];
    block[0] = 0x80;
    block[62] = 0x02;
    block
};

/// SHA-256 of a 64-byte message: the compression function (the SP1-patched sha2 crate's, which uses the
/// precompiles in the zkVM) on the message block and the padding block, without sha2's buffering.
fn sha256_64(message: &[u8; 64]) -> [u8; 32] {
    let mut state = IV;
    sha2::compress256(
        &mut state,
        &[
            *GenericArray::from_slice(message),
            *GenericArray::from_slice(&PADDING),
        ],
    );
    let mut digest = [0u8; 32];
    for (bytes, word) in digest.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    digest
}
