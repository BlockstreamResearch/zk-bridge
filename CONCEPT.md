# Liquid ⇄ Sepolia bridge proof of concept

A testnet bridge between Ethereum Sepolia and Liquid testnet. Liquid holds the bridge asset under Simplicity covenants that accept Ethereum deposits only with an SP1 proof of finalized Sepolia state. Ethereum pays redemptions after checking Liquid's signed block headers itself.

**The bridge** is [`BridgeEscrow.sol`](contracts/solidity/contracts/BridgeEscrow.sol) on Sepolia; the [claim leaf](contracts/simplicity/README.md) and the generated SP1 update leaf on Liquid testnet; the Rust SP1 guest in `tools/sg16/bridge-guest/`; the relay tools; and `ui/`. The escrow admits deposits only inside a deposit window, while a recent EIP-4788 proof shows Sepolia on the fork its guest can prove, and while its Liquid light client is current. Redemptions are never gated. A burn is an explicit output of the bridge asset whose script is a bare 72-byte `OP_RETURN` naming the bridge, the chain, the escrow and the Ethereum recipient in plain bytes.

**The instance** is one deployed escrow on Sepolia and one confirmed bootstrap on Liquid testnet, linked by their asset ID. Its record is `instances/sepolia-liquid-testnet/`: the escrow's pins, the manifest of its Liquid leaves, its initial state and bootstrap, and its light-client stores.

**The interface** is built from `ui/`, published from `main` by the [GitHub Pages workflow](.github/workflows/pages.yml) at [kyrylr.github.io/liquid-poc-bridge](https://kyrylr.github.io/liquid-poc-bridge/). It serves that one instance for deposits, claims, burns and redemptions; check the latest Pages run and the escrow address shown by the loaded page before using it. A Liquid proof update needs a prover, which in practice the project's operator runs; the [operator instructions](OPERATOR.md) list those duties and how anyone can take them over.

This is research code: nothing here has a formal cryptographic audit, and Liquid testnet has a single block signer. Redemptions trust Liquid's block signers and a checkpoint. Deposits trust SP1 and its Groth16 verifier, a weak-subjectivity Sepolia anchor, and the sync committee. Read the trust assumptions in [`contracts/README.md`](contracts/README.md) before relying on anything.

## Layout

| Path | Contents |
|---|---|
| `contracts/solidity/` | Foundry project: the escrow, its Liquid light client and Elements parser, tests and fixtures. [Design notes and testnet gates](contracts/README.md) |
| `contracts/simplicity/` | smplx project: the Liquid claim leaf and the Rust crate `liquid-bridge-poc` that compiles and tests it |
| `tools/sg16/` | The SP1 bridge guest and host (`bridge-guest/`), the Groth16-in-Simplicity update-leaf generator, and the Liquid testnet assembly tools (`bridge-guest/testnet/`) |
| `tools/sg16-harness/` | Rust harness over stock `simplicity-lang` 0.9 that the assembly tools build on |
| `tools/liquid-relay/` | Liquid header relay inputs for the light client, and the escrow's beacon fork-check proof |
| `vectors/` | Every domain tag and the values derived from them, which the Solidity, Rust, Python and JavaScript implementations all check |
| `ui/` | The React page, built with Vite to a static site |
| `bridge-core/` | Shared browser and CLI rules, tests, and the operator CLI |
| `justfile` | Recipes for proving, claiming and deploying ([OPERATOR.md](OPERATOR.md#the-same-steps-with-just)); `broadcast` and `deploy-escrow` send transactions after their checks and a prompt |
| `instances/` | The deployed instance's pins, manifest, initial state, bootstrap, light-client preimages and stores |
| `vendor/` | Pinned dependencies, ignored by git and fetched by `tools/bootstrap-deps.py` |

## Requirements

- `git`, and network access for the first step. Cargo and Foundry also download crates and `solc` 0.8.30 on first use.
- Rust stable, edition 2021.
- [Foundry](https://getfoundry.sh) (`forge`).
- Python 3.9 or later (`str.removeprefix`), standard library only.
- Node.js 22 or later and npm, for the page, its tests and the vectors.
- Optionally [smplx](https://github.com/BlockstreamResearch/smplx) (`simplex`), to type-check the claim leaf with its toolchain.
- Only for the SP1 guest: the SP1 toolchain 6.8.1 (`sp1up`) and Docker. See [`tools/sg16/README.md`](tools/sg16/README.md).

## Build and test

Run from the repository root. Each step needs the ones before it.

```sh
# 1. Pinned checkouts into vendor/, verified afterwards. `--check` re-verifies without the network.
python3 tools/bootstrap-deps.py

# 2. The shared protocol vectors, recomputed by their independent reference implementation.
node vectors/record.mjs --check

# 3. Solidity, default profile and the deployment's optimizer profile.
(cd contracts/solidity && forge test && FOUNDRY_PROFILE=deploy forge test)

# 4. The claim leaf: its rules and the deployed leaf rebuilt to its CMR and source hash.
cargo test --release --locked --manifest-path contracts/simplicity/Cargo.toml

# 5. The shared browser rules, the React page, and the relay tools.
npm --prefix ui test
npm ci --prefix ui && npm --prefix ui run check
python3 tools/liquid-relay/test_liquid.py
python3 tools/liquid-relay/test_beacon.py

# 6. Liquid testnet assembly tools, then their offline tests.
cargo build --release --locked --manifest-path tools/sg16-harness/Cargo.toml
CARGO_TARGET_DIR=tools/sg16/bridge-guest/target/testnet-tx cargo build --release --locked --manifest-path tools/sg16/bridge-guest/testnet/tx/Cargo.toml
CARGO_TARGET_DIR=tools/sg16/bridge-guest/target/testnet-claim cargo build --release --locked --manifest-path tools/sg16/bridge-guest/testnet/claim/Cargo.toml
python3 tools/sg16/bridge-guest/testnet/test_testnet.py          # sections A-D and G, seconds
python3 tools/sg16/bridge-guest/testnet/test_testnet.py --full   # E as well, minutes
python3 tools/sg16/bridge-guest/testnet/test_deploy_record.py     # just deploy-record against stand-in cast and curl
```

Some inputs exist only where they were produced, and tests that need them print a skip with the reason instead of failing: `test_liquid.py` reads live testnet transactions under `target/sg16-testnet-live/`; `test_testnet.py` takes real SP1 artifacts only from `--exec-artifact` and `--proof-artifact`, and its real-key section F (`--real`) runs only under the instance file `--artifact-instance` names. Section G checks the instance record under `instances/`.

The guest, its proving and the remaining `tools/sg16` suites are documented in their own READMEs: [`tools/sg16/README.md`](tools/sg16/README.md), [`tools/sg16/bridge-guest/testnet/README.md`](tools/sg16/bridge-guest/testnet/README.md), [`tools/liquid-relay/README.md`](tools/liquid-relay/README.md), [`bridge-core/README.md`](bridge-core/README.md) and [`ui/README.md`](ui/README.md).

The [CI workflow](.github/workflows/ci.yml) runs routine deterministic checks on pull requests and pushes to `main`; it downloads pinned public dependencies but does not read live chain state. The manual [Pages workflow](.github/workflows/pages.yml) requires CI before staging and publishing the site. CI checks the responsive React fixture with Chrome at desktop and narrow-phone widths. It does not broadcast transactions, generate an SP1 proof, or run the long folded-verifier tests. Those require the operator's separate proof and deployment checks.

## Sources a deployment pins

A deployed contract or a confirmed covenant cannot change, so once the instance is deployed the files its identity depends on are fixed for it:

- The escrow sources under `contracts/solidity/contracts/`, whose metadata hash ends the deployed runtime code.
- The claim leaf text in `contracts/simplicity/simf/claim.simf`, whose CMR and source hash the state tree commits ([contracts/simplicity/README.md](contracts/simplicity/README.md)).
- The SP1 guest under `tools/sg16/bridge-guest/`, whose ELF and vkey every update leaf folds in ([tools/sg16/README.md](tools/sg16/README.md)).

Every domain tag is `liquid-bridge-poc/<purpose>`: `state`, `claimed`, `lc`, `update`, `eth-config`, `deposit`, `burn`, `token-blinding/A` and `/B`, and `manifest` for the manifest schema.

## Keys, broadcasting and deployment

The Liquid testnet assembly builds unsigned transactions. The relay tools and CLI print calldata; they do not broadcast by themselves. The web app asks a connected Sepolia wallet to send deposits, relay batches and redemptions after simulating the contract call. Deployment is a separate operator step.

`tools/sg16/liquid-testnet-wallet` is the local key-file signer. It is the operator's minimal testnet wallet: it generates one key into a mode-0600 file the operator names, and signs only explicit testnet UTXOs. Keep that file under the ignored `target/` or outside the repository. The browser wallet signs Sepolia transactions. Deployment and public testnet transactions are operator steps, listed in order in `contracts/README.md` and `tools/liquid-relay/README.md`. The services a live instance needs afterwards (fork check, header relay, prover and Liquid update, claims), and what each costs and needs, are in [`OPERATOR.md`](OPERATOR.md). `.github/workflows/pages.yml` publishes the React build to GitHub Pages with the instance record it names (`ui/README.md`); none of those services can run there.
