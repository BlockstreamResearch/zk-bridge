//! The published instance records, shared by the tests that rebuild their claim leaf.

use zk_bridge::claim::Params;

/// The manifests of the published instance records, instances/<name>/manifest.json; none before the first
/// deployment.
pub fn published_manifests() -> Vec<(String, serde_json::Value)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../instances");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return vec![];
    };
    let mut out = vec![];
    for entry in entries {
        let path = entry.unwrap().path().join("manifest.json");
        if let Ok(text) = std::fs::read_to_string(&path) {
            out.push((
                path.display().to_string(),
                serde_json::from_str(&text).unwrap(),
            ));
        }
    }
    out
}

/// The claim leaf's parameters recorded in manifest `m`.
pub fn manifest_params(m: &serde_json::Value) -> Params {
    let word = |v: &serde_json::Value| -> [u8; 32] {
        let s = v.as_str().unwrap();
        hex::decode(s.strip_prefix("0x").unwrap_or(s))
            .unwrap()
            .try_into()
            .unwrap()
    };
    let hc = &m["harness_config"];
    Params {
        liquid_genesis: word(&hc["genesis"]),
        entropy: word(&hc["entropy"]),
        fee_asset: simplicity::elements::AssetId::from_byte_array(word(&hc["fee_asset"])),
        deposit_domain: word(&m["sepolia"]["deposit_domain"]),
        token_blinding: [word(&hc["abf_a"]), word(&hc["abf_b"])],
    }
}
