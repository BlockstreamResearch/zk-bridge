# Simplicity contracts

The bridge's Liquid claim leaf, laid out as an [smplx](https://github.com/BlockstreamResearch/smplx) project:

| Path | Contents |
|---|---|
| `simf/claim.simf` | The claim leaf. It mints any unclaimed deposit of the escrow accumulator committed in the state to exactly the script the deposit named, requires an L-BTC fee, and moves the state token on with that deposit's slot set in the claimed tree |
| `src/claim.rs` | `source`: the leaf's text with each parameter replaced by its literal; `compile`; the domain tags; the deposit and claimed trees; and a local harness (`Bridge`) that builds claim and bootstrap transactions and runs input 0 the way a node would |
| `tests/claim.rs` | The leaf's rules and refusals, and, once an instance is published, its manifest's claim leaf rebuilt to the recorded CMR and source hash |
| `tests/vectors.rs` | The tags, state hash and claimed roots against `vectors/protocol.json` |
| `simplex.toml` | smplx configuration: `simplex build` type-checks `simf/claim.simf` and writes Rust bindings under the ignored `target/simplex/` |

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

The leaf's policy constants are SimplicityHL parameters (`param::STATE_TAG`, `param::ENTROPY`, …). `claim::source` replaces each with its literal, and the vendored SimplicityHL compiles the result. An instance's manifest records the CMR and the SHA-256 of that substituted text (`claim_leaf.cmr`, `claim_leaf.source_sha256`), and its state tree commits the CMR, so any change to the file or to the tags in `src/claim.rs` gives another leaf, which needs a new instance.

| Tag | Preimage |
|---|---|
| state leaf, `SHA256(tag)` | `liquid-bridge-poc/state` |
| set slot of the claimed tree, `SHA256(tag)` | `liquid-bridge-poc/claimed` |
| token blinding factor A / B, `SHA256(tag ‖ entropy)` | `liquid-bridge-poc/token-blinding/A`, `liquid-bridge-poc/token-blinding/B` |

## Build and test

From the repository root, after `python3 tools/bootstrap-deps.py`:

```sh
cargo test --release --locked --manifest-path contracts/simplicity/Cargo.toml
```

The crate compiles the leaf with the vendored SimplicityHL 0.7.2 (`f3fa882e`) over rust-simplicity `a8896cf9`. The Liquid claim tool (`tools/sg16/bridge-guest/testnet/claim`) depends on it by path; `assemble.py manifest` and `verify-bootstrap` compile the leaf through that tool.

With [smplx](https://github.com/BlockstreamResearch/smplx) installed (`simplexup`):

```sh
cd contracts/simplicity && simplex build
```

That parses and type-checks the leaf with smplx's own SimplicityHL and generates bindings under `target/simplex/`. Nothing in the bridge reads those bindings, and smplx is not the source of the leaf's CMR. `simplex test` and `simplex regtest` are not used: the leaf's tests run on the local harness above.

## One toolchain for the CMR

The leaf's CMR comes from one place: the SimplicityHL and rust-simplicity commits `tools/bootstrap-deps.py` pins, compiled through this crate. smplx cannot replace it today, because no smplx release builds on those sources:

- smplx 0.0.12 locks `simplicityhl` 0.7.2 and `simplicity-lang` 0.8.0 from crates.io (`Cargo.lock` checksums `ae77168f…` and `13ed081e…`). The vendored SimplicityHL commit also calls itself 0.7.2, but it is later work: it keys parameters and witnesses by `TemplateProgramWitness`, where the published 0.7.2, and smplx's code, use `WitnessName`. Two sources with one version number need not compile one program to one CMR.
- smplx 0.0.9 and earlier bundle SimplicityHL 0.6.0.

So `simplex build` is a second parser and type checker, useful for catching a syntax or type error before the crate runs, not a reproduction of a manifest's `claim_leaf.cmr`. The simplest way to one toolchain, when wanted, is to pin the crate to exactly what smplx locks: `simplicityhl = "=0.7.2"` and `simplicity-lang = "=0.8.0"` from crates.io, with their lock checksums, instead of the vendored commits, adapting `src/claim.rs` to the published 0.7.2 API and recompiling the leaf. That changes the claim CMR, so it must happen before an instance is deployed, or with a new one.
