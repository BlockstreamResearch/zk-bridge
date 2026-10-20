# sg16: the Liquid update leaf, the SP1 guest and the Liquid testnet tools

The Liquid side of the bridge has two leaves under one state UTXO, `P2TR(NUMS, {{update leaf, claim leaf}, state leaf})`. The claim leaf is [`contracts/simplicity/simf/claim.simf`](../../contracts/simplicity/README.md). The update leaf is generated here. It is one Simplicity program: a BN254 Groth16 verifier for SP1's v6.1.0 wrapper key, folded with the guest's program vkey, which uses only the activated secp256k1 field and scalar jets ([simple-groth16](https://github.com/BlockstreamResearch/simple-groth16)), plus the bridge-guest rules that open the proof's public values against the spending transaction.

| Path | Contents |
|---|---|
| `sg16/` | Python library. `ref.py` puts the pinned simple-groth16 (`vendor/simple-groth16`, `$SG16_REF`) on the path; `jets.py` the costs of the extra Elements jets; `statement.py` the public-input layout; `covenant.py` the Groth16 verifier with the public input bound to the transaction (`BridgeVerifier`); `helios.py` the state tags; `sp1.py` SP1 key extraction, folding of the fixed wrapper inputs and proof layouts; `harness.py` and `fixtures.py` drive `../sg16-harness` |
| `bridge-guest/` | The SP1 guest that proves a Sepolia finality update and the escrow's accumulator slot (`program/`, `core/`), the prover host `sg16-bridge-host` (`host/`: `inputs`, `run`, `store`, `reconstruct`, `vkey`), `liquid.py` (the update leaf, `BridgeGuestVerifier`), and the Liquid testnet assembly in [`testnet/`](bridge-guest/testnet/README.md) |
| `liquid-testnet-wallet/` | The operator's minimal key-file wallet for tL-BTC fee inputs: `new`, `address`, `split`, `sign`, and `burn` for the bare `OP_RETURN` form |
| `test_sp1_vk.py`, `test_sp1_v6_fixture.py` | The SP1 v6.1.0 key read from the pinned `sp1-contracts` source, and that source's v6.0.0 Groth16 test proof, of the same layout, through `sp1.py` |
| `../sg16-harness/` | Rust, stock `simplicity-lang =0.9.0`: builds Elements transactions (blinded token, surjection and range proofs), prunes and executes a program, round-trips its encoding and checks amount proofs. The testnet `tx` tool is built on it |

## The guest is a pinned build

The instance pins one guest ELF and its SP1 program vkey (`instance.json` `GUEST_ELF_SHA256`, `PROGRAM_VKEY`), and the vkey is folded into its update leaf. The guest is built in SP1's pinned Docker image (`just prover`, then `just check-elf`; or the commands in [OPERATOR.md](../../OPERATOR.md#4-prove-and-update)), and `sg16-bridge-host vkey --elf` prints both values for the instance file. `--workspace-directory` mounts the whole repository, so that `vendor/sp1-helios`, a path dependency outside the guest's workspace, is inside the container.

Once the instance is deployed, `bridge-guest/program/`, `bridge-guest/core/`, the workspace `Cargo.toml` and `Cargo.lock`, and their place in the repository do not change: any change gives another ELF and vkey, which its update leaf does not accept.

## Tests

From the repository root, after `python3 tools/bootstrap-deps.py`:

```sh
cargo test --release --locked -p sg16-bridge-core --manifest-path tools/sg16/bridge-guest/Cargo.toml
cargo build --release --locked -p sg16-bridge-core --features cli --manifest-path tools/sg16/bridge-guest/Cargo.toml
cargo test --release --locked -p sg16-bridge-host --manifest-path tools/sg16/bridge-guest/Cargo.toml
cargo test --release --locked --manifest-path tools/sg16-harness/Cargo.toml
cargo build --release --locked --manifest-path tools/sg16-harness/Cargo.toml
cargo test --release --locked --manifest-path tools/sg16/liquid-testnet-wallet/Cargo.toml
python3 tools/sg16/bridge-guest/test_bridge_guest.py            # seconds; --full adds the folded verifier (minutes)
python3 tools/sg16/test_sp1_vk.py --version v6.1.0
python3 tools/sg16/test_sp1_v6_fixture.py
```

The assembly tools and their tests are in [`bridge-guest/testnet/README.md`](bridge-guest/testnet/README.md).
