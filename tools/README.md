# Tools

Everything an operator runs besides the contracts and the page. Rust is the default: whatever builds, signs,
verifies or recovers a transaction, or proves a statement, is a Rust CLI with Rust tests. Python remains in three
places, each for a reason given below. The Rust crates and the first two are checked against the shared vectors in
[`../vectors/protocol.json`](../vectors/protocol.json); the relay tools against real Liquid and Sepolia data and
the Solidity fixtures.

## Rust

| Crate | Binary | Role |
|---|---|---|
| `sg16-harness/` | `sg16` | Elements transactions with blinded tokens, surjection and range proofs; prunes, executes and encodes Simplicity programs under stock `simplicity-lang` 0.9 |
| `sg16/bridge-guest/core/` | `sg16-bridge-core` | The guest's rules and encodings, shared by the guest and the host: light-client commitment, Sepolia config, public values |
| `sg16/bridge-guest/program/` | (SP1 ELF) | The SP1 guest |
| `sg16/bridge-guest/host/` | `sg16-bridge-host` | Proof inputs from a published or reconstructed light-client store, proving, store files, vkey |
| `sg16/bridge-guest/testnet/tx/` | `sg16-testnet` | Bootstrap, update and recovery transactions; the node-like `verify`; `txid`, `output` and `input`, which read every transaction file the `justfile` checks |
| `sg16/bridge-guest/testnet/claim/` | `sg16-testnet-claim` | The deposits a state proves and has paid, and the claim transaction of any one of them (`--deposit <index>`), through the claim crate in `contracts/simplicity` |
| `sg16/liquid-testnet-wallet/` | `sg16-liquid-testnet-wallet` | The operator's fee key: new, address, split, sign, and the bare `OP_RETURN` burn |
| `bridge-operator/` | `bridge-operator` | Read-only commands against the escrow: a header's federation, the deployment checkpoint, the burn script, the next `submitHeaders` batch and `redeem`/`redeemTo` calldata, and the deposit list `assemble.py claim` reads. Its `eth_getLogs` scan narrows to the range a provider allows and backs off when rate-limited; it writes its output whole or not at all, and keeps RPC credentials out of every message |

The page has its own JavaScript implementation of the rules `bridge-operator` uses, in `bridge-core/lib`. To keep the
two equal, `tools/bridge-operator/tests` repeats that suite's expected values and checks the shared burn-script vectors
and the Solidity suite's Liquid testnet fixture.

## Python, and why

- **The update-leaf generator**, `sg16/sg16/` and `sg16/bridge-guest/liquid.py`. The Groth16 verifier it emits
  comes from the pinned [simple-groth16](https://github.com/BlockstreamResearch/simple-groth16), which is a
  Python library; the generator is a thin layer over it.
- **The assembly orchestrator**, `sg16/bridge-guest/testnet/assemble.py` with `pins.py`. It calls the generator
  and the Rust tools in order and holds the named gates each step must pass. Where it computes a value itself,
  such as the asset and token ids or the state address, a Rust tool computes it too and the two must agree.
- **The relay and fork-proof tools**, `liquid-relay/`. They are a separate implementation of the Liquid header,
  Merkle and batch encodings and of the progressive BeaconState proof, and the Solidity and JavaScript
  implementations are tested against them and against each other. Porting them into one of those languages would
  remove the independence the tests rely on.

`bootstrap-deps.py` fetches and verifies the pinned dependencies with nothing but `git`.

### What moving more to Rust would take

- The update-leaf generator and the SP1 key fold (`sg16/sg16/sp1.py`) run on simple-groth16's BN254 field, curve
  and Groth16 code. Moving them means reimplementing that library in Rust and proving the emitted program
  unchanged by its CMR, a project of its own; `assemble.py` would then shrink to argument handling.
- Two modules are named `liquid`: `liquid-relay/liquid.py` (Elements encodings) and `sg16/bridge-guest/liquid.py`
  (the update leaf). Renaming the second to `update_leaf.py` waits for the next guest rebuild: the guest
  workspace's manifest and core CLI name it, as the guest's `lib.rs` names `sg16/helios.py`, and edits there are
  kept out of a pinned guest build.

A port of any of these to Rust must carry their vectors with it unchanged: `vectors/protocol.json`, the real
transactions and headers in the Solidity and UI fixtures, the Sepolia finality update and fork proof, the SP1 key
and proof fixtures, and the claim leaf's CMR and source hash. One Simplicity toolchain is authoritative for every
CMR: the SimplicityHL and rust-simplicity commits pinned in `bootstrap-deps.py`. The claim crate also checks the
same leaf's CMR with smplx's SimplicityHL release. `simplex build` writes bindings, but is not by itself a
complete compile check ([contracts/simplicity/README.md](../contracts/simplicity/README.md#smplx)).

## Tests

From the repository root, after `python3 tools/bootstrap-deps.py`; each README below lists its own suites.

- [`sg16/README.md`](sg16/README.md): the guest, the generator and the SP1 key.
- [`sg16/bridge-guest/testnet/README.md`](sg16/bridge-guest/testnet/README.md): the assembly tools.
- [`liquid-relay/README.md`](liquid-relay/README.md): the relay and fork-proof tools.
