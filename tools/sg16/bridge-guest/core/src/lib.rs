//! Public values of the sg16 bridge update guest (tools/sg16/bridge-guest/program).
//!
//! The guest commits exactly `UpdateOutputs::encode()`, 272 bytes, all big-endian:
//!
//!   offset size
//!        0   32  SHA256("liquid-bridge-poc/update")                          domain of these values
//!       32   32  config = SHA256(SHA256(CONFIG_TAG) || genesis_root || SHA256(cbor(forks)))   network binding
//!       64   32  12 zero bytes || escrow address                              the proven contract
//!       96   32  storage slot key                                             (0: the accumulator)
//!      128   32  prev_lc = lc(prev finalized slot, header root, sync-committee root)   the starting store
//!      160   32  new_lc  = lc(new finalized slot, header root, sync-committee root)    the successor store
//!      192   32  slot value                                                   the escrow accumulator
//!      224   32  finalized execution state root                               (informational)
//!      256    8  finalized execution block number                             (informational)
//!      264    8  new finalized slot                                           (informational; also in new_lc)
//!
//!   lc(slot, header, committee) = SHA256(SHA256("liquid-bridge-poc/lc") || be64(slot) || header || committee),
//!   the light-client commitment of the Liquid bridge state (tools/sg16/sg16/helios.py `lc`).
//!
//! SP1's Groth16 wrapper exposes SHA256(public values) with the top three bits cleared (sp1-contracts v6.1.0
//! `hashPublicValues`); the Liquid covenant recomputes that digest with its own constants (config, escrow,
//! slot key) and the state it spends (prev_lc), so a proof binds only the transition it was made for.

use sha2::{Digest, Sha256};

/// Domain tag of the guest's public values (word 0 is its SHA-256).
pub const UPDATE_TAG: &[u8] = b"liquid-bridge-poc/update";
/// Domain tag of the light-client commitment `lc`.
pub const LC_TAG: &[u8] = b"liquid-bridge-poc/lc";
/// Domain tag of the network binding `config`.
pub const CONFIG_TAG: &[u8] = b"liquid-bridge-poc/eth-config";
/// Length of the encoded public values.
pub const LEN: usize = 272;

pub const SEPOLIA_CHAIN_ID: u64 = 11_155_111;

/// Sepolia's genesis_validators_root (beacon API /eth/v1/beacon/genesis).  The host also compares it with the
/// helios network config and the consensus RPC, so a wrong constant fails loudly rather than silently.
pub const SEPOLIA_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61, 0x05, 0x2a,
    0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09, 0xed, 0x9b, 0x80, 0x78,
];

/// keccak256 of the empty string: the code hash of an account without code
pub const KECCAK_EMPTY: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The light-client commitment stored in the Liquid bridge state.
pub fn lc(slot: u64, header: &[u8; 32], committee: &[u8; 32]) -> [u8; 32] {
    let mut b = Vec::with_capacity(104);
    b.extend_from_slice(&sha256(LC_TAG));
    b.extend_from_slice(&slot.to_be_bytes());
    b.extend_from_slice(header);
    b.extend_from_slice(committee);
    sha256(&b)
}

/// The network the update was verified for: genesis validators root and the fork schedule as the guest
/// deserialized it (its canonical CBOR re-encoding), so the Liquid covenant can pin both.
pub fn config_hash(genesis_root: &[u8; 32], forks_encoding: &[u8]) -> [u8; 32] {
    let mut b = Vec::with_capacity(96);
    b.extend_from_slice(&sha256(CONFIG_TAG));
    b.extend_from_slice(genesis_root);
    b.extend_from_slice(&sha256(forks_encoding));
    sha256(&b)
}

/// SHA256(public values) with the top three bits cleared: the SP1 Groth16 public-values input.
pub fn public_input(public_values: &[u8]) -> [u8; 32] {
    let mut d = sha256(public_values);
    d[0] &= 0x1f;
    d
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateOutputs {
    pub config: [u8; 32],
    pub escrow: [u8; 20],
    pub slot_key: [u8; 32],
    pub prev_lc: [u8; 32],
    pub new_lc: [u8; 32],
    pub slot_value: [u8; 32],
    pub execution_state_root: [u8; 32],
    pub execution_block_number: u64,
    pub new_head: u64,
}

impl UpdateOutputs {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(LEN);
        b.extend_from_slice(&sha256(UPDATE_TAG));
        b.extend_from_slice(&self.config);
        b.extend_from_slice(&[0u8; 12]);
        b.extend_from_slice(&self.escrow);
        b.extend_from_slice(&self.slot_key);
        b.extend_from_slice(&self.prev_lc);
        b.extend_from_slice(&self.new_lc);
        b.extend_from_slice(&self.slot_value);
        b.extend_from_slice(&self.execution_state_root);
        b.extend_from_slice(&self.execution_block_number.to_be_bytes());
        b.extend_from_slice(&self.new_head.to_be_bytes());
        debug_assert_eq!(b.len(), LEN);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        if b.len() != LEN {
            return Err("public values: wrong length");
        }
        if b[..32] != sha256(UPDATE_TAG) {
            return Err("public values: wrong domain tag");
        }
        if b[64..76] != [0u8; 12] {
            return Err("public values: escrow word is not an address");
        }
        let w = |o: usize| -> [u8; 32] { b[o..o + 32].try_into().unwrap() };
        let u = |o: usize| -> u64 { u64::from_be_bytes(b[o..o + 8].try_into().unwrap()) };
        Ok(UpdateOutputs {
            config: w(32),
            escrow: b[76..96].try_into().unwrap(),
            slot_key: w(96),
            prev_lc: w(128),
            new_lc: w(160),
            slot_value: w(192),
            execution_state_root: w(224),
            execution_block_number: u(256),
            new_head: u(264),
        })
    }

    pub fn public_input(&self) -> [u8; 32] {
        public_input(&self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> UpdateOutputs {
        UpdateOutputs {
            config: [1; 32],
            escrow: [2; 20],
            slot_key: [0; 32],
            prev_lc: lc(8192 * 1000 + 64, &[3; 32], &[4; 32]),
            new_lc: lc(8192 * 1000 + 96, &[5; 32], &[6; 32]),
            slot_value: [7; 32],
            execution_state_root: [8; 32],
            execution_block_number: 9_100_000,
            new_head: 8192 * 1000 + 96,
        }
    }

    #[test]
    fn round_trip_and_layout() {
        let o = sample();
        let b = o.encode();
        assert_eq!(b.len(), LEN);
        assert_eq!(&b[64..76], &[0u8; 12]);
        assert_eq!(&b[76..96], &o.escrow);
        assert_eq!(&b[264..272], &o.new_head.to_be_bytes());
        assert_eq!(UpdateOutputs::decode(&b).unwrap(), o);
        assert_eq!(o.public_input()[0] & 0xe0, 0);
    }

    #[test]
    fn decode_rejects_malformed_values() {
        let b = sample().encode();
        assert!(UpdateOutputs::decode(&b[..LEN - 1]).is_err());
        let mut bad = b.clone();
        bad[0] ^= 1;
        assert!(UpdateOutputs::decode(&bad).is_err(), "domain tag");
        let mut bad = b.clone();
        bad[64] = 1;
        assert!(UpdateOutputs::decode(&bad).is_err(), "address padding");
    }

    #[test]
    fn commitments_separate_their_inputs() {
        assert_ne!(lc(1, &[0; 32], &[0; 32]), lc(2, &[0; 32], &[0; 32]));
        assert_ne!(lc(1, &[0; 32], &[1; 32]), lc(1, &[1; 32], &[0; 32]));
        assert_ne!(
            config_hash(&SEPOLIA_GENESIS_VALIDATORS_ROOT, b"a"),
            config_hash(&SEPOLIA_GENESIS_VALIDATORS_ROOT, b"b")
        );
        let mut o = sample();
        let d = o.public_input();
        o.slot_value[31] ^= 1;
        assert_ne!(o.public_input(), d);
    }
}
