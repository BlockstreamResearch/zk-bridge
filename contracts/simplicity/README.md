# Simplicity contracts

The bridge's Liquid claim leaf, laid out as an [smplx](https://github.com/BlockstreamResearch/smplx) project:

| Path | Contents |
|---|---|
| `simf/claim.simf` | The claim leaf. It mints any unclaimed deposit of the escrow accumulator committed in the state to exactly the script the deposit named, requires an L-BTC fee, and moves the state token on with that deposit's slot set in the claimed tree |
| `src/claim.rs` | `parameters`: the literal of each `param::` name; `source`: the leaf's text with each replaced by its literal; `compile`; the domain tags; the deposit and claimed trees; and a local harness (`Bridge`) that builds claim and bootstrap transactions and runs input 0 the way a node would |
| `tests/claim.rs` | The leaf's rules and refusals, and, once an instance is published, its manifest's claim leaf rebuilt to the recorded CMR and source hash |
| `tests/smplx.rs` | The leaf compiled the way smplx 0.0.12 compiles it, with the SimplicityHL release smplx locks, to the same CMR, for the test parameters and each published manifest |
| `tests/vectors.rs` | The tags, state hash and claimed roots against `vectors/protocol.json` |
| `tests/common/` | The published manifests and the parameters they record, for both leaf-rebuilding tests |
| `Simplex.toml` | smplx configuration: `simplex build` writes Rust bindings for the leaf under the ignored `target/simplex/` |

The state UTXO is `P2TR(NUMS, {{update leaf, claim leaf}, state leaf})`, and the state leaf's hash is `SHA256(SHA256(state tag) ‖ lc ‖ acc ‖ claimed_root)`, 128 bytes. The update leaf is not here: it is a generated SP1 Groth16 verifier with the bridge-guest rules (`tools/sg16/bridge-guest/liquid.py`), built for the instance by `assemble.py manifest` and published as `instances/<name>/update_leaf.simpl`. It carries `claimed_root` from the old state to the successor unchanged.

## The claimed tree

`claimed_root` is the root of a depth-32 SHA-256 sparse Merkle tree with the deposit tree's shape and its empty-subtree hashes: slot `i` is `SHA256(claimed tag)` once deposit `i` is minted, and 0 before. The initial state's root is the empty tree's, the same as the escrow's empty deposit-tree root. A claim of deposit `index` (witness `INDEX`):

- opens the accumulator to `(TREE_ROOT, COUNT)` and requires `index < COUNT`;
- opens deposit `index` of `TREE_ROOT` with the leaf recomputed from the transaction, `SHA256(domain ‖ be64(index) ‖ be64(units) ‖ recipient)`, along `PATH`; folding all 32 bits of the index bounds it below 2^32;
- folds `CLAIMED_PATH` twice from slot `index`, once from 0 and once from the claimed value, and requires the first fold to give the old `claimed_root`; the second is the successor's root.

Hence:

- Any order. Nothing ties `index` to earlier claims, so lower indices can be skipped and claimed later.
- At most once. A second claim of a set slot needs an opening of that slot as 0 under a root that opens it as set. At fixed depth, two openings of one slot to one root differ at some level in a SHA-256 input, which is a collision.
- One slot per claim. Both folds share every sibling, so the successor differs from the old tree in slot `index` alone.
- Duplicate deposits stay distinct. Deposits with the same units and recipient have different leaves, because the leaf commits the index, and different slots.
- The payment is bound. The units are the reissued amount and the recipient is output 1's script hash, both inside the opened leaf.
- Completion. The root binds the set, and claims set only slots below the count, so a state whose accumulator opens to `count` deposits has nothing left to claim exactly when `claimed_root == complete_root(count)`. `src/claim.rs` computes that root in 32 steps without the tree. Whether a deposit is claimed is public: each claim's witness carries its `INDEX`, so the set is rebuilt from the chain of claim spends.

## Weight

A Simplicity program's cost is static, so one figure holds for every claim. `claims_in_any_order_form_one_token_chain` prints each report and requires `budget_valid_without_padding`: the cost must not exceed the input's own budget of (serialized witness stack + 50) WU, so no annex padding is needed. That assertion is the testable limit.

The witness is 18,048 bits (2,256 bytes): five words, two u64 and the two 32-word branches. Measured with the vendored toolchain, for claims of indices 2, 1 and 0: a cost of 3,541,884 to 3,551,868 mWU, and a pruned program of 1,884 to 1,932 bytes (pruning keeps only the branch each index bit takes). The stack is about 4.25 kB, so the budget is about 4.3M mWU and the margin about 0.75M. A claim transaction weighs about 10,270 WU. If the margin is ever short, `sha_pair` over `jet::sha_256_block` (an IV block, then the constant padding block) computes the same SHA-256 with far smaller intermediate types.

## Parameters and identity

The leaf's policy constants are SimplicityHL parameters (`param::STATE_TAG`, `param::ENTROPY`, …). `claim::source` replaces each with its literal from `claim::parameters`, and the vendored SimplicityHL compiles the result. An instance's manifest records the CMR and the SHA-256 of that substituted text (`claim_leaf.cmr`, `claim_leaf.source_sha256`), and its state tree commits the CMR, so any change to the file or to the tags in `src/claim.rs` gives another leaf, which needs a new instance.

| Tag | Preimage |
|---|---|
| state leaf, `SHA256(tag)` | `liquid-bridge-poc/state` |
| set slot of the claimed tree, `SHA256(tag)` | `liquid-bridge-poc/claimed` |
| token blinding factor A / B, `SHA256(tag ‖ entropy)` | `liquid-bridge-poc/token-blinding/A`, `liquid-bridge-poc/token-blinding/B` |

## Build and test

From the repository root, after `python3 tools/bootstrap-deps.py`:

```sh
cargo fmt --check --manifest-path contracts/simplicity/Cargo.toml
cargo test --release --locked --manifest-path contracts/simplicity/Cargo.toml
```

The crate compiles the leaf with the vendored SimplicityHL `f3fa882e` over rust-simplicity `a8896cf9`. That SimplicityHL commit calls itself 0.7.2 but is later work, with the `TemplateProgramWitness` API of the 0.8.0 release. The rust-simplicity commit's sources, `simplicity-sys` included, are file for file those of the crates.io simplicity-lang 0.8.0 and simplicity-sys 0.7.0 releases. Every test compiles the leaf, so `cargo test` is also its parser and type checker. The Liquid claim tool (`tools/sg16/bridge-guest/testnet/claim`) depends on the crate by path; `assemble.py manifest` and `verify-bootstrap` compile the leaf through that tool.

## smplx

The leaf's CMR comes from this crate. smplx compiles the same one, and `tests/smplx.rs` checks that on every `cargo test`. Its one extra dependency, `smplx-simplicityhl`, is the SimplicityHL 0.7.2 release that smplx 0.0.12 locks, with the same lock checksum (`ae77168f…`). It runs over the vendored rust-simplicity, whose sources are those of the simplicity-lang 0.8.0 release that smplx locks (`13ed081e…`). smplx's `Program` compiles the text as written, takes the parameters as arguments, enables every unstable feature, and adds debug symbols only at `simplex test -v` or above. The test makes that same call.

Measured on 2026-10-21 with the published `sepolia-liquid-testnet` parameters (manifest `claim_leaf.cmr` `98997455…f835`). The 0.6.0 and 0.8.0 rows came from one-off builds against the crates.io releases, and `cargo test` does not repeat them:

| SimplicityHL | Program text, parameters | CMR |
|---|---|---|
| vendored `f3fa882e` | `claim::source` (substituted) | `98997455…f835` |
| 0.6.0 (what smplx 0.0.9 embeds) | substituted | `98997455…f835` |
| 0.7.2 (what smplx 0.0.12 locks) | substituted; `simf/claim.simf` with arguments; smplx's module rewrite with arguments | `98997455…f835` |
| 0.8.0 | substituted | `98997455…f835` |
| 0.7.2 | `simf/claim.simf` with arguments and debug symbols | `53d11331…082b` |

### The CLI

The pinned version is smplx 0.0.12, tag `v0.0.12`, commit `5472e914`. Install it with `simplexup --install 0.0.12`, or with `cargo install --locked --git https://github.com/BlockstreamResearch/smplx --tag v0.0.12 smplx-cli`. Then:

```sh
cd contracts/simplicity
simplex --version    # Simplex 0.0.12
simplex build
cargo test --release --locked --test smplx -- --ignored
```

`simplex build` writes three things under `target/simplex/`:

- `claim.rs`: a `ClaimProgram` binding. Its `include_simf!` derives the argument and witness types when a crate compiles it.
- `simf/claim.simf`: the leaf rewritten as module `unit_0`.
- `metadata.json` (0.0.12 only). Its `cmr`, `d3cb4ef5…` here, is smplx's contract ID: the leaf compiled with every parameter zero. It is no instance's leaf.

The ignored test compiles the rewritten text with real arguments and requires the leaf's CMR. It refuses output older than `simf/claim.simf`, because a failed build can leave an earlier build's output in place. 0.0.9 and 0.0.12 write the same rewrite, and the test passes on both.

`simplex build` is not a check of the leaf; `cargo test` is. A copy of this project with a type error (`let count: u32 = witness::COUNT;`) and another with unparsable text showed:

- 0.0.12 refuses the type error with exit 1: ``Failed to dry run the program: Expected expression of type `u64`, found type `u32` ``. On unparsable text it writes nothing for the leaf, keeps any earlier `claim.rs`, and exits 0 once `target/simplex/` exists (before that, exit 1 with an I/O error).
- 0.0.9 accepts the type error with exit 0 and writes bindings for it. Unparsable text goes the same way as with 0.0.12. That is the version `simplexup` installed on the development machine, and it embeds SimplicityHL 0.6.0. 0.0.9 type-checks only when a crate compiles the bindings with smplx-std's `include_simf!`.

Both versions read exactly `Simplex.toml`. On a case-sensitive file system, a `simplex.toml` is not found.

### Not used, and the way to it

- **The generated bindings.** Nothing compiles `target/simplex/claim.rs`: it needs `smplx-std` 0.0.12 (crate `simplex`), whose SDK brings RPC, Esplora and signer dependencies that the leaf does not use. The CMR they would give is checked above, by the same call (`tests/smplx.rs`) and on the same text (the ignored test).
- **smplx's addresses and spends.** `Program` places a program under P2TR(key, {program leaf, storage}), with each storage slot a hidden `TapData`-tagged hash, and finalizes with its own control block. The bridge state is P2TR(NUMS, {{update, claim}, state}). Its update and state leaves are Simplicity leaves (version 0xbe) of the update CMR and the state hash, and the claim leaf checks `tappath_hash` against exactly that path. So smplx's address for the claim leaf, with any storage, is never a state output, and its finalizer cannot spend one. Spends come from `Bridge` (`state_script`, `control`, the witness).
- **`simplex test` and `simplex regtest`.** These were not run. They fund a wallet on a local Elements regtest (simplexup ships elementsd v23.3.1 and electrs) from the mnemonic in `Simplex.toml`, then sign and broadcast with it. A regtest claim would add what the harness lacks: Elements consensus and policy on real transactions. The way there:
  1. Install 0.0.12 and add the `[regtest]` and `[test]` tables from smplx's README to `Simplex.toml`.
  2. Add `smplx-std = "=0.0.12"` as an optional dev-dependency behind a `regtest` feature, so the default test graph stays as it is. Keep the simplicity-lang patch.
  3. In a `#[simplex::test]`:
     - fund a regtest UTXO and derive `Params` from it. The entropy follows the bootstrap outpoint, so the leaf is a regtest instance's, not the published one;
     - send `Bridge::bootstrap` with its funding input signed by smplx's signer;
     - send `Bridge::claim` with a wallet fee input in place of `fee_input`, also signed;
     - require elementsd to accept both, and to refuse a second claim of the same index.
  4. Run `simplex test` without `-v`. Debug symbols compile another leaf, so the program revealed would not be the CMR the state tree commits.

### One toolchain

The crate could compile with exactly what smplx locks: crates.io `simplicityhl = "=0.7.2"` in place of the vendored commit, and `simplicity-lang = "=0.8.0"` in place of the vendored rust-simplicity, whose sources it already is. For this leaf the CMR stays the same (table above), so no new instance is needed. Two pieces of work remain:

- `src/claim.rs` must move its witness handling from `TemplateProgramWitness` and `WitnessNameToValueMap` to 0.7.2's `WitnessName` maps.
- The Liquid claim tool and `tools/bootstrap-deps.py` must follow, because the tool shares this crate's graph.

A compiler's version is part of a leaf's identity. Before any compiler change ships, `published_claim_leaves_are_reproduced` and `tests/smplx.rs` must pass.
