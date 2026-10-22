# Testnet Liquid ⇄ Sepolia ZK-Bridge

This repository presents a proof-of-concept bridge using Simplicity and zero-knowledge proofs to bridge ETH
from Ethereum Sepolia to Liquid testnet, with the ability to return SepETH to Sepolia.

## High-level Technical Overview

The concept was inspired by [recent research](https://github.com/BlockstreamResearch/simple-groth16) showing that Groth16 proofs can be verified on Liquid using Simplicity.

This allowed us to adapt and reuse the [code for verifying Ethereum's consensus](https://github.com/succinctlabs/sp1-helios) to
enable a trustless experience, subject to certain assumptions, between Ethereum Sepolia and Liquid.

At its heart, the mechanism is simple: prove to Liquid that something happened on Ethereum and take an action
(in our case, issue wrapped SepETH backed by SepETH locked in a contract on Sepolia).

And vice versa: prove to Sepolia that an action happened on Liquid and take an action (in our case, unlock the previously deposited SepETH).

For more details, see [concept](./CONCEPT.md).

Read the [design assumptions](./contracts/README.md) to understand trust assumptions. Each deployment's own trust roots are in its record under `instances/`, created when it is deployed.

## Implementation details

On Sepolia, the contract responsible for managing deposits is [BridgeEscrow](./contracts/solidity/contracts/BridgeEscrow.sol). 
Then a prover runs the [SP1 program](./tools/sg16/bridge-guest/program/src/main.rs) off-chain, starting from a 
trusted [weak-subjectivity checkpoint](https://ethereum.org/developers/docs/consensus-mechanisms/pos/weak-subjectivity/), 
to prove Sepolia finality and the escrow's deposit state. The [Simplicity update covenant](./tools/sg16/bridge-guest/liquid.py) 
verifies this proof on Liquid.

On Liquid, the Simplicity covenants control a reissuance token for wrapped SepETH. 
When the user provides the necessary proofs, namely the [deposit inclusion proof](./contracts/simplicity/simf/claim.simf#L173) 
and [proof that the deposit has not already been claimed](./contracts/simplicity/README.md#the-claimed-tree), 
the [claim covenant](./contracts/simplicity/simf/claim.simf) allows them to issue the exact amount of wrapped 
SepETH to the Liquid recipient recorded in the deposit.

The operation above concludes the first direction of bridging assets from Ethereum to Liquid.

The redemption of SepETH starts with burning wrapped SepETH on Liquid using the bridge's specific burn format, 
which names the chain, escrow and Sepolia recipient. Then the [Solidity contract](./contracts/solidity/contracts/BridgeEscrow.sol) 
verifies that the burn transaction was included in a Liquid block, using [signed block headers](./contracts/solidity/contracts/LiquidLightClient.sol) 
and the required confirmations. After the proof is verified and accepted, the corresponding amount of previously deposited SepETH is released. 
The same burn cannot be redeemed twice.

This concludes the other and final bridge direction that this proof of concept is meant to demonstrate. 
Both directions rely on the documented [trust assumptions](./contracts/README.md).

## Quick guide to completing a manual end-to-end test

### macOS prerequisites

For the full manual test, including generating a proof locally, install the following tools and apps.
Skip anything you already have. CI uses Rust 1.95.0 and Node.js 22.
The recipes also use the `bash` and `curl` commands supplied with macOS.

| Dependency                                                      | Used for                                                  |
| --------------------------------------------------------------- | --------------------------------------------------------- |
| Xcode Command Line Tools                                        | Git, C/C++ compilers, linker, make and the macOS SDK      |
| Rust and Cargo, managed by rustup                               | Building the bridge tools and SP1 CLI                     |
| Python 3.9 or later                                             | Fetching pinned dependencies and assembling transactions  |
| Node.js 22.13 or later in the 22.x series, with npm             | Instance checks, store checks and the local UI            |
| just                                                            | Running the commands below                                |
| Go and Protocol Buffers (`protoc`)                              | Building the SP1 prover host                              |
| CMake, LLVM/libclang, pkg-config and OpenSSL 3                  | Native dependencies of the prover host                    |
| Docker Desktop                                                  | Building the pinned guest ELF                             |
| Google Chrome with Humid 1.1.3 and an Ethereum wallet extension | Reviewing and signing the Liquid and Sepolia transactions |

Enable Liquid testnet in Humid and Sepolia in the Ethereum wallet. You need tL-BTC for Liquid fees and SepETH for the deposit and Ethereum gas. Keep Docker running for `just prover`, which builds the pinned guest ELF. The current `just prove` uses the native CPU prover.

Local proof generation can exhaust a 16 GB machine. You can try the experimental `just prove low-memory` profile or generate the proof on a larger machine and keep wallet signing local. The profile is not a RAM cap or verified 16 GB support. See [proving with limited RAM](OPERATOR.md#proving-with-limited-ram) for the limits and steps.

### Steps to complete the claim on Liquid

These steps finish an existing deposit made through the [website](https://blockstreamresearch.github.io/zk-bridge/) to the current bridge instance. Use the deposit number shown in Activity. The paths below assume the default `BRIDGE_INSTANCE` and `BRIDGE_WORK` settings.

1. Clone the [repository](https://github.com/BlockstreamResearch/zk-bridge) and run the following commands from its root directory.
2. Export the two RPC URLs: `export SEPOLIA_EXECUTION_RPC=... SEPOLIA_CONSENSUS_RPC=...`. The execution RPC must serve `eth_getLogs`, `eth_call` and `eth_getProof` at finalized blocks; the consensus RPC must serve Sepolia Beacon API light-client updates.
3. Run `just deps tools prover check-elf` to install the project dependencies and build the tools needed for the manual steps.
4. Run `just status <deposit number>` to recover the live state, read finalized deposits and print the next steps. Wait if the deposit is not final yet; skip to step 8 if it is proven and unclaimed. A claimed deposit needs no further claim.
5. For a final but unproven deposit, run `just inputs execute prove`. This proves Ethereum finality and the escrow's deposit accumulator at a finalized block; the claim later proves this deposit's inclusion. If `status` reports a missing light-client store, run `just reconstruct` first. If you need a new proof and `target/takeover/proof.json` already exists, move it and its matching `proof.store.json` aside first.
6. Open **Send a proof update** on the [website](https://blockstreamresearch.github.io/zk-bridge/#update) and load `target/takeover/proof.browser.json`. Prepare a fee coin with Humid, wait for confirmation, then build, review and send the update. The browser constructs the transaction; no CLI transaction assembly is needed.
7. Keep and optionally share `proof.store.json`, included in the proof bundle and available to download on the website. Loading it does not publish it. Without a shared store, the next prover must recover it from retained Beacon data or saved inputs; recovery can fail if neither is available. See [store recovery](OPERATOR.md#recovering-a-withheld-store).
8. Once the update confirms, open **Claim a proven deposit**, enter your deposit number and prepare a separate fee coin. Build, review and send the claim with Humid. This pays the deposit's original Liquid recipient, whoever pays the fee. Each update or claim spends its entire selected fee coin.
9. If another claim changes the state before your update is sent, run `just proof-bundle` and reload the bundle; no new proof is needed. If another update makes it stale, run `just status <deposit number>` first: your deposit may already be proven. Rebuild stale claims directly in the browser.

To redeem SepETH, follow the instructions in the **Redeem** tab on the [website](https://blockstreamresearch.github.io/zk-bridge/).

For more detail, troubleshooting and alternative workflows, see the [operator guide](OPERATOR.md#taking-over-a-stalled-deposit).
