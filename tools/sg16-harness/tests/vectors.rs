//! The harness's tags, `lc`, `claimed_root` and `state_hash` against the shared protocol vectors
//! (vectors/protocol.json).

use serde_json::Value;
use sg16_harness::bridge::{
    claimed_root, lc, sha, state_hash, try_h32, CLAIMED_TAG, LC_TAG, STATE_TAG,
};
use std::collections::BTreeSet;

fn vectors() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/protocol.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("vectors/protocol.json"))
        .expect("vectors/protocol.json is JSON")
}

/// A 32-byte value of the file; an output not yet recorded fails, naming the recorder.
fn word(v: &Value, what: &str) -> [u8; 32] {
    let s = v.as_str().unwrap_or_else(|| {
        panic!("{what} is not recorded: run node vectors/record.mjs and review the result")
    });
    try_h32(s.strip_prefix("0x").expect("0x-prefixed hex")).expect("32 bytes of hex")
}

fn cases<'a>(v: &'a Value, section: &str) -> &'a Vec<Value> {
    let c = v[section]
        .as_array()
        .unwrap_or_else(|| panic!("vectors: no {section}"));
    assert!(!c.is_empty(), "vectors: no {section} case");
    c
}

/// The case's claimed indices as a set; the vectors list each at most once.
fn indices(c: &Value) -> BTreeSet<u64> {
    let list: Vec<u64> = c["indices"]
        .as_array()
        .expect("indices")
        .iter()
        .map(|i| i.as_u64().expect("index"))
        .collect();
    let set: BTreeSet<u64> = list.iter().copied().collect();
    assert_eq!(set.len(), list.len(), "vectors: a repeated index");
    set
}

#[test]
fn tags_are_the_vectors() {
    let v = vectors();
    for (name, tag) in [
        ("lc", LC_TAG),
        ("state", STATE_TAG),
        ("claimed", CLAIMED_TAG),
    ] {
        assert_eq!(
            Some(tag),
            v["tags"][name].as_str().map(str::as_bytes),
            "tags.{name}"
        );
        let hashed = cases(&v, "tag_sha256")
            .iter()
            .find(|c| c["tag"] == name)
            .expect("tag_sha256 case");
        assert_eq!(
            sha(tag),
            word(&hashed["sha256"], &format!("tag_sha256 {name}")),
            "SHA256(tags.{name})"
        );
    }
}

#[test]
fn lc_is_the_vectors() {
    let v = vectors();
    for (i, c) in cases(&v, "lc").iter().enumerate() {
        let got = lc(
            c["slot"].as_u64().expect("slot"),
            &word(&c["header"], "header"),
            &word(&c["committee"], "committee"),
        );
        assert_eq!(got, word(&c["lc"], &format!("lc[{i}].lc")), "lc[{i}]");
    }
}

#[test]
fn claimed_root_is_the_vectors() {
    let v = vectors();
    for (i, c) in cases(&v, "claimed_root").iter().enumerate() {
        assert_eq!(
            claimed_root(&indices(c)).unwrap(),
            word(&c["root"], &format!("claimed_root[{i}].root")),
            "claimed_root[{i}]"
        );
    }
    assert!(
        claimed_root(&BTreeSet::from([1u64 << 32])).is_err(),
        "an index outside the tree"
    );
}

#[test]
fn state_hash_is_the_vectors() {
    let v = vectors();
    for (i, c) in cases(&v, "state_hash").iter().enumerate() {
        let root = claimed_root(&indices(c)).unwrap();
        assert_eq!(
            root,
            word(&c["claimed_root"], &format!("state_hash[{i}].claimed_root")),
            "state_hash[{i}].claimed_root"
        );
        let got = state_hash(&word(&c["lc"], "lc"), &word(&c["acc"], "acc"), &root);
        assert_eq!(
            got,
            word(&c["state_hash"], &format!("state_hash[{i}].state_hash")),
            "state_hash[{i}]"
        );
    }
}
