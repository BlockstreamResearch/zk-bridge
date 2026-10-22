//! The guest's stdin carries exactly the saved inputs: decoding it gives the `ProofInputs` of inputs.cbor.

use helios_consensus_core::types::GenericUpdate;
use sg16_bridge_core::guest_input::{decode, guest_stdin};
use sp1_helios_primitives::types::ProofInputs;
use std::path::PathBuf;

/// Saved inputs (public beacon-chain data): the tracked Sepolia period transition, and sp1-helios's fixtures
/// (fetched by tools/bootstrap-deps.py), Gloas and earlier.
fn fixtures() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vendored = dir.join("../../../../vendor/sp1-helios/script/tests/fixtures");
    vec![
        dir.join("../host/tests/fixtures/inputs-11385472-11388896.cbor"),
        vendored.join("proof_inputs.cbor"),
        vendored.join("gloas_current.cbor"),
        vendored.join("gloas_transition.cbor"),
    ]
}

fn read(path: &PathBuf) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn stdin_decodes_to_the_saved_inputs() {
    for path in fixtures() {
        let cbor = read(&path);
        let saved: ProofInputs = serde_cbor::from_slice(&cbor).unwrap();
        // The one field not sent (src/guest_input.rs); the fixtures carry none.
        assert!(
            saved.store.best_valid_update.is_none(),
            "{}",
            path.display()
        );
        let stdin = guest_stdin(&cbor).unwrap();
        let decoded = decode(&stdin).unwrap();
        // ProofInputs has no PartialEq: compare canonical encodings, which cover every field.
        assert_eq!(
            serde_cbor::to_vec(&decoded).unwrap(),
            serde_cbor::to_vec(&saved).unwrap(),
            "{}",
            path.display()
        );
        assert!(
            stdin.len() < cbor.len(),
            "{}: keys as bytes, not hex",
            path.display()
        );
    }
}

#[test]
fn a_supplied_best_valid_update_is_not_sent() {
    let cbor = read(&fixtures()[0]);
    let mut inputs: ProofInputs = serde_cbor::from_slice(&cbor).unwrap();
    inputs.store.best_valid_update = Some(GenericUpdate::from(&inputs.updates[0]));
    let with = serde_cbor::to_vec(&inputs).unwrap();
    assert_eq!(guest_stdin(&with).unwrap(), guest_stdin(&cbor).unwrap());
    assert!(decode(&guest_stdin(&with).unwrap())
        .unwrap()
        .store
        .best_valid_update
        .is_none());
}

#[test]
fn the_two_encodings_refuse_each_other() {
    // The guest refuses inputs.cbor, and nothing reads its stdin as inputs.cbor.
    let cbor = read(&fixtures()[0]);
    assert!(decode(&cbor).is_err());
    let stdin = guest_stdin(&cbor).unwrap();
    assert!(serde_cbor::from_slice::<ProofInputs>(&stdin).is_err());
}

/// The stdin with the variant tag at `path` (map keys from the top) renamed from `from` to `to`.
fn retag(stdin: &[u8], path: &[&str], from: &str, to: &str) -> Vec<u8> {
    use serde_cbor::Value;
    let mut value: Value = serde_cbor::from_slice(stdin).unwrap();
    let mut at = &mut value;
    for key in path {
        let Value::Map(map) = at else {
            panic!("{key}: not a map")
        };
        at = map
            .get_mut(&Value::Text(key.to_string()))
            .unwrap_or_else(|| panic!("no {key}"));
    }
    let Value::Map(tagged) = at else {
        panic!("not a tagged variant")
    };
    let inner = tagged
        .remove(&Value::Text(from.into()))
        .unwrap_or_else(|| panic!("not {from}"));
    tagged.insert(Value::Text(to.into()), inner);
    serde_cbor::to_vec(&value).unwrap()
}

#[test]
fn a_variant_under_another_fork_tag_is_refused() {
    // The tracked fixture is Gloas throughout: its values do not decode as another fork's.
    let stdin = guest_stdin(&read(&fixtures()[0])).unwrap();
    for to in ["Base", "Electra"] {
        assert!(
            decode(&retag(&stdin, &["finality_update"], "Gloas", to)).is_err(),
            "finality {to}"
        );
    }
    for to in ["Bellatrix", "Capella", "Deneb", "Electra"] {
        let header = retag(&stdin, &["store", "finalized_header"], "Gloas", to);
        assert!(decode(&header).is_err(), "finalized header {to}");
    }
    assert!(
        decode(&retag(&stdin, &["finality_update"], "Gloas", "Fulu")).is_err(),
        "no such tag"
    );
    // Unchanged tags still decode, so the refusals above come from the tags.
    assert!(decode(&retag(&stdin, &["finality_update"], "Gloas", "Gloas")).is_ok());
}

#[test]
fn truncated_or_extended_stdin_is_refused() {
    let stdin = guest_stdin(&read(&fixtures()[0])).unwrap();
    assert!(decode(&stdin[..stdin.len() - 1]).is_err());
    let mut longer = stdin.clone();
    longer.push(0);
    assert!(decode(&longer).is_err());
}
