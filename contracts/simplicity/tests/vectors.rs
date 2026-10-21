//! The claim crate's tags, state hash, claimed roots and token blinding factors against the shared protocol vectors
//! (vectors/protocol.json).

use zk_bridge::claim::{
    claimed_leaf, complete_root, state_hash, state_tag, token_blinding, ClaimedTree, State,
    CLAIMED_TAG, STATE_TAG, TOKEN_BLINDING_TAGS,
};
use zk_bridge::crypto::Root;

use serde_json::Value;

fn vectors() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/protocol.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("vectors/protocol.json"))
        .expect("vectors/protocol.json is JSON")
}

/// A 32-byte value of the file; an output not yet recorded fails, naming the recorder.
fn word(v: &Value, what: &str) -> Root {
    let s = v.as_str().unwrap_or_else(|| {
        panic!("{what} is not recorded: run node vectors/record.mjs and review the result")
    });
    hex::decode(s.strip_prefix("0x").expect("0x-prefixed hex"))
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

fn cases<'a>(v: &'a Value, section: &str) -> &'a Vec<Value> {
    let c = v[section]
        .as_array()
        .unwrap_or_else(|| panic!("vectors: no {section}"));
    assert!(!c.is_empty(), "vectors: no {section} case");
    c
}

fn tag<'a>(v: &'a Value, name: &str) -> &'a [u8] {
    v["tags"][name]
        .as_str()
        .unwrap_or_else(|| panic!("vectors: no tags.{name}"))
        .as_bytes()
}

#[test]
fn tags_are_the_vectors() {
    let v = vectors();
    assert_eq!(STATE_TAG, tag(&v, "state"));
    assert_eq!(CLAIMED_TAG, tag(&v, "claimed"));
    assert_eq!(
        TOKEN_BLINDING_TAGS,
        [tag(&v, "token_blinding_a"), tag(&v, "token_blinding_b")]
    );
    let hashed = |name: &str| {
        let c = cases(&v, "tag_sha256")
            .iter()
            .find(|c| c["tag"] == name)
            .unwrap_or_else(|| panic!("tag_sha256 of {name}"));
        word(&c["sha256"], &format!("tag_sha256 {name}"))
    };
    assert_eq!(state_tag(), hashed("state"));
    assert_eq!(claimed_leaf(), hashed("claimed"));
}

#[test]
fn state_hashes_are_the_vectors() {
    let v = vectors();
    for (i, c) in cases(&v, "state_hash").iter().enumerate() {
        let s = State {
            lc: word(&c["lc"], "lc"),
            acc: word(&c["acc"], "acc"),
            claimed_root: word(&c["claimed_root"], "claimed_root"),
        };
        assert_eq!(
            state_hash(&s),
            word(&c["state_hash"], &format!("state_hash[{i}].state_hash")),
            "state_hash[{i}]"
        );
    }
}

/// Each case sets the slots `indices`; a case whose indices are exactly 0..n is also the complete root of n.
#[test]
fn claimed_roots_are_the_vectors() {
    let v = vectors();
    for (i, c) in cases(&v, "claimed_root").iter().enumerate() {
        let indices: Vec<u64> = c["indices"]
            .as_array()
            .expect("indices")
            .iter()
            .map(|x| x.as_u64().expect("an index"))
            .collect();
        let tree = indices.iter().fold(ClaimedTree::new(), |t, &k| t.with(k));
        let root = word(&c["root"], &format!("claimed_root[{i}].root"));
        assert_eq!(tree.root(), root, "claimed_root[{i}]");
        let n = indices.len() as u64;
        if (0..n).all(|k| tree.contains(k)) {
            assert_eq!(
                complete_root(n),
                root,
                "claimed_root[{i}] as complete_root({n})"
            );
        }
    }
}

#[test]
fn token_blindings_are_the_vectors() {
    let v = vectors();
    for (i, c) in cases(&v, "token_blinding").iter().enumerate() {
        let entropy = word(&c["entropy"], "entropy");
        assert_eq!(
            token_blinding(entropy, 0),
            word(&c["a"], &format!("token_blinding[{i}].a")),
            "token_blinding[{i}] A"
        );
        assert_eq!(
            token_blinding(entropy, 1),
            word(&c["b"], &format!("token_blinding[{i}].b")),
            "token_blinding[{i}] B"
        );
    }
}
