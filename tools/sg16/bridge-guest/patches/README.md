# Patched dependencies of the bridge guest

`helios-consensus-core/` is helios-consensus-core 0.12.0 from [a16z/helios](https://github.com/a16z/helios) tag
`0.12.0` (commit `2af9b41887e069144ee56cd710f3ddca195473f8`, MIT), the crate the workspace pinned before. It is
copied as `cargo vendor` writes it: `src/` and the normalized `Cargo.toml`. The `[[test]]` targets and
`[dev-dependencies]` are dropped, since their sources are not copied, and sha2's `compress` feature is added. The
workspace `Cargo.toml` substitutes the copy with `[patch."https://github.com/a16z/helios"]`, so the guest and the
host both build it. Every change is marked `sg16 bridge patch`.

## Upstream files

SHA-256 as `cargo vendor` recorded them for 2af9b41 (`.cargo-checksum.json`):

| File | Upstream SHA-256 | Here |
|---|---|---|
| `Cargo.toml` | `b7c2a7105a2e53308557d698f1270d1b92d5f6c6fa55c869994209323ed8464d` | changed: tests, dev-dependencies, sha2 `compress` |
| `src/lib.rs` | `a44c79794b6c43a0406e7964836a6689f0f3c8d132c606825eb44638a78419e8` | unchanged |
| `src/consensus_core.rs` | `b9ba3312f01a0caa54206e0f983158fd975beb2f136b0d07c4415049b1fa9685` | unchanged |
| `src/consensus_spec.rs` | `eba8ee4295cab91428d86deb4046b540b17e35cd74a91e8366159c775ff2d1fb` | unchanged |
| `src/errors.rs` | `b7eba17aad30fe663eda0228681561ee68a1e504e1587682dc7f03f5a30b7d8a` | unchanged |
| `src/proof.rs` | `df65279746846033cf6cc52f0c0179d48d825f5ef7efcb8ca1a571fd3f7dc09e` | unchanged |
| `src/utils.rs` | `5a43ec77858d0796b5dc8b3eeb62ce96913fe710781323030b428fd8a8bef045` | unchanged |
| `src/types/bls.rs` | `d44866e8c0cf2fb011cdf7a20194b7be5467452473bc91a3b63f3669ff5e44ed` | changed |
| `src/types/bytes.rs` | `2c07ca044b6459ccbd5b206cd319b26b647763c5c8b17a20eaf1f0a96341c3fb` | unchanged |
| `src/types/mod.rs` | `fec177a280919f5e1bef7975d494a499fa7c6f2552b10d3ac2d9c54bc48e00b9` | changed |
| `src/types/serde_utils.rs` | `8c53ffc43e4ea03a2f6524d3977b1ac2441b7678695f5fc8aa153adb7627c363` | unchanged |
| `src/types/committee_root.rs` | — | new |

`shasum -a 256 helios-consensus-core/src/{lib,consensus_core,consensus_spec,errors,proof,utils}.rs
helios-consensus-core/src/types/{bytes,serde_utils}.rs` must print the unchanged hashes above.

## Changes

| Change | Why | Evidence |
|---|---|---|
| `types/bls.rs`: `Signature::verify` no longer calls `subgroup_check_g2` (removed, with `hex_to_scalar`). | The helper multiplied the signature by `Scalar::from_raw(r)`, which reduces to zero, so it accepted every point. The subgroup check is `G2Affine::from_compressed`'s `is_torsion_free` in `Signature::point`, which stays. The helper cost 1,177,772 guest cycles per signature (stage profile; removing it measured −1,176,592). | `host/tests/signature_subgroup.rs`: a valid signature verifies; a point on the curve outside the subgroup, and a valid signature plus such a point, are refused; the helper's scalar is zero. The `host/src/main.rs` tests also refuse signatures at infinity, off the curve, with the flag cleared, with a bit flipped, and another update's. |
| `types/mod.rs`, `types/committee_root.rs`: `pub fn sync_committee_root`, the derived container root computed directly over 64-byte blocks with sha2's `compress256` (SP1's SHA precompiles in the zkVM). `PublicKey::as_bytes` is added. In the zkVM only, `TreeHash for SyncCommittee` is that function; elsewhere it stays the stock derive. | The derive packs each key one byte at a time: 8,707,608 guest cycles per committee root (two roots: 17,415,215), and the guest takes two roots per proof, three on a period transition (the third, in the next-committee branch check: 8,727,760). Off the zkVM the derive is kept, so the host's recomputation of new_lc stays an independent check of the guest's roots. | `host/tests/committee_root.rs`: equal to helios's derive and to a locally derived struct, on every committee of four saved inputs and on arbitrary bytes; every key byte, the aggregate key and key order change the root. In the zkVM the roots enter prev_lc and new_lc, which the stock-derive host recomputes, and a transition's next committee must also open the beacon state's branch. |

Cycle figures are SP1 6.8.1 execute counts on target/guest-optimization/baseline/current.cbor. They come from
target/guest-optimization/opus/runs: `tracked/current.tracker.log` (stage profile), `g2/current.profile.log`
(helper removed) and `tracked/transition.tracker.log` (third root).
