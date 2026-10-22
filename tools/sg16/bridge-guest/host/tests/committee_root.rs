//! The patched helios `sync_committee_root` (../patches/helios-consensus-core), which the guest uses as
//! `TreeHash for SyncCommittee`, equals the stock derive. Off the zkVM, `SyncCommittee::tree_hash_root` is still
//! the derive, and a local struct derived the same way is a second, independent oracle. Checked on every committee
//! of the saved inputs and on arbitrary bytes; every key, the aggregate key and key order change the root.

use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec,
    types::{bls::PublicKey, sync_committee_root, SyncCommittee},
};
use sp1_helios_primitives::types::ProofInputs;
use ssz::{Decode, Encode};
use ssz_types::{typenum::U512, FixedVector};
use std::path::PathBuf;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

type Committee = SyncCommittee<MainnetConsensusSpec>;

const LEN: usize = 513 * 48;

/// SyncCommittee's fields under the stock derive.
#[derive(TreeHash)]
struct Derived {
    pubkeys: FixedVector<PublicKey, U512>,
    aggregate_pubkey: PublicKey,
}

fn check(c: &Committee, what: &str) {
    let direct = sync_committee_root(c);
    assert_eq!(direct, c.tree_hash_root(), "{what}: helios's derive");
    let derived = Derived {
        pubkeys: c.pubkeys.clone(),
        aggregate_pubkey: c.aggregate_pubkey.clone(),
    };
    assert_eq!(direct, derived.tree_hash_root(), "{what}: local derive");
}

/// Saved inputs: the tracked Sepolia period transition and sp1-helios's fixtures (tools/bootstrap-deps.py).
fn fixtures() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vendored = dir.join("../../../../vendor/sp1-helios/script/tests/fixtures");
    vec![
        dir.join("tests/fixtures/inputs-11385472-11388896.cbor"),
        vendored.join("proof_inputs.cbor"),
        vendored.join("gloas_current.cbor"),
        vendored.join("gloas_transition.cbor"),
    ]
}

fn xorshift_bytes(state: &mut u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as u8
        })
        .collect()
}

#[test]
fn equals_the_derive_on_saved_committees() {
    let mut seen = 0;
    for path in fixtures() {
        let cbor = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let inputs: ProofInputs = serde_cbor::from_slice(&cbor).unwrap();
        let mut committees = vec![inputs.store.current_sync_committee.clone()];
        committees.extend(inputs.store.next_sync_committee.clone());
        committees.extend(
            inputs
                .updates
                .iter()
                .map(|u| u.next_sync_committee().clone()),
        );
        for c in committees {
            check(&c, &path.display().to_string());
            seen += 1;
        }
    }
    assert!(
        seen >= 6,
        "the transition inputs bring next committees: {seen}"
    );
}

#[test]
fn equals_the_derive_on_arbitrary_bytes() {
    // SSZ does not check that keys are curve points, and neither root does.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for i in 0..8 {
        let bytes = xorshift_bytes(&mut state, LEN);
        let c = Committee::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(c.as_ssz_bytes(), bytes);
        check(&c, &format!("random {i}"));
    }
    check(&Committee::default(), "zero");
    check(&Committee::from_ssz_bytes(&[0xff; LEN]).unwrap(), "ones");
}

#[test]
fn every_key_and_the_aggregate_key_change_the_root() {
    let base = Committee::from_ssz_bytes(&[7u8; LEN]).unwrap();
    let root = sync_committee_root(&base);
    // Every byte of every key, including the aggregate key.
    for at in 0..LEN {
        let mut bytes = base.as_ssz_bytes();
        bytes[at] ^= 1;
        let changed = Committee::from_ssz_bytes(&bytes).unwrap();
        assert_ne!(sync_committee_root(&changed), root, "byte {at}");
        check(&changed, &format!("byte {at}"));
    }
    // Swapping two keys changes the root: positions are bound, not only the set of keys.
    let mut bytes = xorshift_bytes(&mut 1, LEN);
    let before = sync_committee_root(&Committee::from_ssz_bytes(&bytes).unwrap());
    bytes[..96].rotate_left(48);
    assert_ne!(
        sync_committee_root(&Committee::from_ssz_bytes(&bytes).unwrap()),
        before
    );
}
