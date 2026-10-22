//! Witness files: JSON specs of Simplicity values, written by the Python generators.
//!
//! Adapted from simple-groth16 `tools/harness/src/witness.rs` (MIT, Copyright (c) 2026 Blockstream
//! Research), commit 4f787ea07b97e62bd0ba4fa3f9518d52621dcb68.  Same format:
//!   {"w": "<hex>"}              a word of 4 * len(hex) bits (a power of two)
//!   {"bit": 0|1}                a bit (the type 2)
//!   {"p": [VALUE, VALUE]}       a pair
//!   {"none": TYPE}              the left injection of unit into 1 + TYPE
//!   {"some": VALUE}             the right injection into 1 + type(VALUE)
//!   {"l": VALUE, "t": TYPE}     the left injection into type(VALUE) + TYPE
//!   {"r": VALUE, "t": TYPE}     the right injection into TYPE + type(VALUE)
//! and TYPE is {"w": bits}, {"p": [TYPE, TYPE]} or {"opt": TYPE}.
use simplicity::types::Final;
use simplicity::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Hex digits to bytes, or an error naming the problem. Use this for operator input (CLI arguments,
/// manifests, transaction files); `hex_to_bytes` is for values this crate or its generators wrote.
pub fn parse_hex(h: &str) -> Result<Vec<u8>, String> {
    if h.len() % 2 != 0 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "not an even-length hex string ({} characters)",
            h.len()
        ));
    }
    // Every character is an ASCII hex digit, so each two-byte slice is on a char boundary and parses.
    Ok((0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("ASCII hex digits"))
        .collect())
}

/// Panics on malformed hex: only for generator-written values (see `parse_hex`).
pub fn hex_to_bytes(h: &str) -> Vec<u8> {
    parse_hex(h).unwrap_or_else(|e| panic!("hex: {}", e))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// a word value from its hex digits: bytes paired up into a balanced tree
fn word(hex: &str) -> Value {
    let bits = hex.len() * 4;
    assert!(
        bits.is_power_of_two(),
        "word width must be a power of two: {} bits",
        bits
    );
    if bits < 8 {
        let v = u8::from_str_radix(hex, 16).unwrap();
        return match bits {
            1 => Value::u1(v),
            2 => Value::u2(v),
            4 => Value::u4(v),
            _ => unreachable!(),
        };
    }
    let mut vals: VecDeque<Value> = hex_to_bytes(hex).into_iter().map(Value::u8).collect();
    while vals.len() > 1 {
        let mut next = VecDeque::new();
        while let (Some(a), Some(b)) = (vals.pop_front(), vals.pop_front()) {
            next.push_back(Value::product(a, b));
        }
        vals = next;
    }
    vals.pop_front().unwrap()
}

fn ty(spec: &serde_json::Value) -> Arc<Final> {
    let o = spec.as_object().unwrap();
    if let Some(b) = o.get("w") {
        let bits = b.as_u64().unwrap() as usize;
        Final::two_two_n(bits.trailing_zeros() as usize).unwrap()
    } else if let Some(p) = o.get("p") {
        Final::product(ty(&p[0]), ty(&p[1]))
    } else if let Some(t) = o.get("opt") {
        Final::sum(Final::unit(), ty(t))
    } else {
        panic!("bad type spec {}", spec)
    }
}

pub fn value(spec: &serde_json::Value) -> Value {
    let o = spec.as_object().unwrap();
    if let Some(h) = o.get("w") {
        word(h.as_str().unwrap())
    } else if let Some(b) = o.get("bit") {
        Value::u1(b.as_u64().unwrap() as u8)
    } else if let Some(p) = o.get("p") {
        Value::product(value(&p[0]), value(&p[1]))
    } else if let Some(t) = o.get("none") {
        Value::none(ty(t))
    } else if let Some(v) = o.get("some") {
        Value::some(value(v))
    } else if let Some(v) = o.get("l") {
        Value::left(value(v), ty(o.get("t").expect("l needs t")))
    } else if let Some(v) = o.get("r") {
        Value::right(ty(o.get("t").expect("r needs t")), value(v))
    } else {
        panic!("bad value spec {}", spec)
    }
}

/// the witness map of a JSON object {"name": VALUE, ...}
pub fn map(spec: &serde_json::Value) -> HashMap<Arc<str>, Value> {
    spec.as_object()
        .expect("witness object")
        .iter()
        .map(|(k, v)| (Arc::from(k.as_str()), value(v)))
        .collect()
}

/// the witness map of a file
pub fn load(path: &str) -> HashMap<Arc<str>, Value> {
    map(&serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap())
}

/// Validate untrusted browser witness JSON before the trusted generator parser sees it.
/// Bounded nesting and word widths prevent pathological allocations and recursive stack growth.
pub fn try_map(spec: &serde_json::Value) -> Result<HashMap<Arc<str>, Value>, String> {
    fn check(spec: &serde_json::Value, depth: usize, is_type: bool) -> Result<(), String> {
        if depth > 64 {
            return Err("witness nesting exceeds 64".into());
        }
        let o = spec.as_object().ok_or("witness value must be an object")?;
        let child = |v, t| check(v, depth + 1, t);
        if let Some(w) = o.get("w") {
            if o.len() != 1 {
                return Err("ambiguous witness word".into());
            }
            if is_type {
                let bits = w.as_u64().ok_or("witness type width must be an integer")?;
                if bits == 0 || !bits.is_power_of_two() || bits > 4096 {
                    return Err("invalid witness type width".into());
                }
            } else {
                let h = w.as_str().ok_or("witness word must be hex")?;
                if h.is_empty()
                    || h.len() > 1024
                    || !h.len().is_power_of_two()
                    || !h.bytes().all(|c| c.is_ascii_hexdigit())
                {
                    return Err("invalid witness hex word".into());
                }
            }
        } else if let Some(p) = o.get("p") {
            let p = p.as_array().ok_or("witness pair must be an array")?;
            if o.len() != 1 || p.len() != 2 {
                return Err("witness pair needs two values".into());
            }
            child(&p[0], is_type)?;
            child(&p[1], is_type)?;
        } else if is_type {
            if o.len() != 1 {
                return Err("invalid witness type".into());
            }
            child(o.get("opt").ok_or("unknown witness type")?, true)?;
        } else if let Some(bit) = o.get("bit") {
            if o.len() != 1 || !matches!(bit.as_u64(), Some(0 | 1)) {
                return Err("witness bit must be 0 or 1".into());
            }
        } else {
            let tags: Vec<_> = ["none", "some", "l", "r"]
                .iter()
                .filter(|k| o.contains_key(**k))
                .collect();
            if tags.len() != 1 {
                return Err("unknown or ambiguous witness value".into());
            }
            let tag = *tags[0];
            let sum = tag == "l" || tag == "r";
            if o.len() != if sum { 2 } else { 1 } {
                return Err("invalid witness injection".into());
            }
            child(&o[tag], tag == "none")?;
            if sum {
                child(o.get("t").ok_or("witness injection needs type")?, true)?;
            }
        }
        Ok(())
    }
    let o = spec.as_object().ok_or("witness must be an object")?;
    if o.len() > 128 {
        return Err("too many witness names".into());
    }
    for v in o.values() {
        check(v, 0, false)?;
    }
    Ok(map(spec))
}

#[cfg(test)]
mod browser_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checked_witness_accepts_generator_shapes() {
        let spec = json!({"w_in": {"p": [
            {"w": "0f"},
            {"p": [{"bit": 1}, {"some": {"w": "f"}}]}
        ]}});
        assert_eq!(try_map(&spec).unwrap(), map(&spec));
        for value in [
            json!({"none": {"opt": {"w": 256}}}),
            json!({"l": {"bit": 0}, "t": {"p": [{"w": 8}, {"w": 16}]}}),
            json!({"r": {"bit": 1}, "t": {"w": 2}}),
        ] {
            assert!(try_map(&json!({"w_in": value})).is_ok());
        }
    }

    #[test]
    fn checked_witness_refuses_bad_shapes_without_panicking() {
        for value in [
            json!(null),
            json!({"w": ""}),
            json!({"w": "xyz"}),
            json!({"w": "fff"}),
            json!({"bit": 2}),
            json!({"bit": -1}),
            json!({"p": []}),
            json!({"p": [{"bit": 0}]}),
            json!({"none": {"w": 0}}),
            json!({"none": {"w": 3}}),
            json!({"l": {"bit": 1}}),
            json!({"w": "ff", "bit": 0}),
            json!({"some": {"bit": 1}, "none": {"w": 8}}),
        ] {
            assert!(try_map(&json!({"w_in": value})).is_err(), "{value}");
        }
        let mut deep = json!({"bit": 1});
        for _ in 0..66 {
            deep = json!({"some": deep});
        }
        assert!(try_map(&json!({"w_in": deep})).is_err());
    }
}
