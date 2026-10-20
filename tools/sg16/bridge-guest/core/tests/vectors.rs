//! The guest's tags and `lc` against the shared protocol vectors (vectors/protocol.json).
//!
//! serde_json is only behind the `cli` feature, so the few fields needed are found by string search. That relies on
//! the layout vectors/record.mjs writes (JSON.stringify, two-space indent): `"key": value`, and case objects
//! without nested objects or arrays.

use sg16_bridge_core::{lc, sha256, CONFIG_TAG, LC_TAG, UPDATE_TAG};

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../vectors/protocol.json"
));

/// The text between `"key": ` followed by `open`, and the first matching close after it.
fn section(key: &str, open: char) -> &'static str {
    let opening = format!("\"{key}\": {open}");
    let start = VECTORS
        .find(&opening)
        .unwrap_or_else(|| panic!("vectors: no {key}"))
        + opening.len();
    let close = if open == '[' { ']' } else { '}' };
    &VECTORS[start..start + VECTORS[start..].find(close).expect("closed")]
}

/// The objects of the array `key`.
fn cases(key: &str) -> Vec<&'static str> {
    let c: Vec<_> = section(key, '[')
        .split('}')
        .filter(|c| c.contains('{'))
        .collect();
    assert!(!c.is_empty(), "vectors: no {key} case");
    c
}

/// The value of field `name` in `obj`: a string without its quotes, or a bare number or null.
fn field<'a>(obj: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\": ");
    let at = obj
        .find(&key)
        .unwrap_or_else(|| panic!("vectors: no {name} in {obj}"))
        + key.len();
    obj[at..]
        .split([',', '\n'])
        .next()
        .unwrap()
        .trim()
        .trim_matches('"')
}

/// A 32-byte value; an output not yet recorded fails, naming the recorder.
fn word(v: &str, what: &str) -> [u8; 32] {
    assert_ne!(
        v, "null",
        "{what} is not recorded: run node vectors/record.mjs and review the result"
    );
    let h = v.strip_prefix("0x").expect("0x-prefixed hex");
    assert_eq!(h.len(), 64, "{what}: 32 bytes");
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

#[test]
fn tags_are_the_vectors() {
    let tags = section("tags", '{');
    let hashed = cases("tag_sha256");
    for (name, tag) in [
        ("lc", LC_TAG),
        ("update", UPDATE_TAG),
        ("eth_config", CONFIG_TAG),
    ] {
        assert_eq!(tag, field(tags, name).as_bytes(), "tags.{name}");
        let case = hashed
            .iter()
            .find(|c| field(c, "tag") == name)
            .unwrap_or_else(|| panic!("tag_sha256 of {name}"));
        assert_eq!(
            sha256(tag),
            word(field(case, "sha256"), &format!("tag_sha256 {name}")),
            "SHA256(tags.{name})"
        );
    }
}

#[test]
fn lc_is_the_vectors() {
    for (i, c) in cases("lc").iter().enumerate() {
        let slot: u64 = field(c, "slot").parse().expect("slot");
        let (header, committee) = (
            word(field(c, "header"), "header"),
            word(field(c, "committee"), "committee"),
        );
        assert_eq!(
            lc(slot, &header, &committee),
            word(field(c, "lc"), &format!("lc[{i}].lc")),
            "lc[{i}]"
        );
    }
}
