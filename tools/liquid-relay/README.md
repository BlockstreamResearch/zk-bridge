# Relay inputs for the Sepolia escrow: Liquid headers and the beacon fork check

`contracts/solidity/contracts/LiquidLightClient.sol` follows Liquid's signed header chain on Ethereum. Every height is accepted once, in order, under the block-signing keys of its own DynaFed epoch. Redemptions then open a stored batch commitment instead of checking signatures. `BridgeEscrow.checkFork` takes a proof that Sepolia's beacon chain is still on the fork the bridge's SP1 guest can prove; deposits stay open only while such a proof is recent. This directory builds both inputs from public data and checks them before they are used:

- `liquid.py`: hash-form header cutting, the signblock-witness check (P2WSH `<key> OP_CHECKSIG` without a dummy or `OP_CHECKMULTISIG` with one, strict DER, `SIGHASH_ALL`, key order), Elements txid form, Merkle branches, the light client's batch tree, `submitHeaders` ABI encoding, keccak256 and secp256k1. Standard library only.
- `relay.py`: `fixture`, `batches`, `checkpoint` and `blockref`. See the module docstring. It is read-only: it never holds a key, signs or broadcasts.
- `beacon.py`: the SSZ hash tree roots `checkFork`'s proof needs, and the proof. Standard library only. See its docstring for where each node comes from and how they are checked against each other.
- `fork_proof.py`: `build` reads a Sepolia beacon node and execution RPC and prints the proof with `checkFork` calldata; `offline` rebuilds it from saved inputs. Read-only, like `relay.py`.
- `test_liquid.py`: offline tests, including the real confirmed testnet transactions under `target/sg16-testnet-live/` and an independent re-check of the Foundry fixture.
- `test_beacon.py`: offline tests of the fork proof. They use a real Sepolia (Gloas) finality update as served (`contracts/solidity/test/fixtures/sepolia-finality-update-11381920.json`), real Electra mainnet light-client branches (`fixtures/electra-mainnet-bootstrap.json`, `fixtures/electra-mainnet-updates.json`), and synthetic states in each shape, hashed by a separate recursive merkleization.

## Commands

From the project root:

```sh
python3 tools/liquid-relay/test_liquid.py

# Real-header fixture for contracts/solidity/test/LiquidLightClient.t.sol (network read, about 850 header requests).
# Checkpoint: the last block of epoch 2663. Batch tips at 2,664,802 (the block of transaction 63371b48…) and 2,664,846.
python3 tools/liquid-relay/relay.py fixture --checkpoint-height 2663999 --to 2664846 \
  --sign-at 2664802,2664846 --tx 63371b487d1140e07c192d3d0855f48061531970748480baab86ee7bd7ea124f
python3 tools/liquid-relay/test_liquid.py Fixture
(cd contracts/solidity && forge test --match-path test/LiquidLightClient.t.sol -vv)
```

The first fixture batch has 803 headers, so it also measures relaying most of an epoch in one call. The test logs execution gas, standard calldata gas and the EIP-7623 floor separately.

These are local figures under `contracts/solidity/foundry.toml`'s `prague` schedule, not Sepolia costs. Since Glamsterdam (6 October 2026), Sepolia reprices state access (EIP-8038) and charges new storage as separate state gas (EIP-8037). Each batch stores one entry of two new slots, 195,840 state gas whatever the batch size. The 2^24 transaction cap applies to execution gas. `relay.py batches` defaults to 100 headers per batch, which stays far below the cap. Before sending, take each transaction's gas limit from `eth_estimateGas` on Sepolia; `cast send` does that by default.

Relaying to a deployed client (the operator sends; nothing is broadcast here):

```sh
python3 tools/liquid-relay/relay.py batches --tip-height "$(cast call $CLIENT 'lcTipHeight()(uint32)')" \
  --tip-hash "$(cast call $CLIENT 'lcTipHash()(bytes32)')" \
  --signblockscript-hash "$(cast call $CLIENT 'signblockscriptHash()(bytes32)')" --to <height> --out-dir target/relay
# then, in the order of target/relay/batches.json:
cast send $CLIENT "$(cat target/relay/batch-<first>-<last>.calldata)"
```

## The beacon fork check

`checkFork` recomputes the EIP-4788 beacon block root for an execution block's timestamp. It hashes the beacon state's fields 0 to 3 (genesis time, genesis validators root, slot, fork) into Gloas's progressive BeaconState, with nodes 43 and 11 (`stateBranch`) and the active-fields bits at node 3 (`activeFields`), then the five-field block. Under the pinned fork it moves `forkCheckedAt` to the state's slot time. Under any later or different fork it ends deposits for good.

```sh
python3 tools/liquid-relay/test_beacon.py

# Network read. The beacon node must serve /eth/v1/beacon/light_client/finality_update, /eth/v1/beacon/genesis and
# /eth/v1/beacon/states/{id}/fork for recent states. No debug state is read.
export SEPOLIA_CONSENSUS_RPC=... SEPOLIA_EXECUTION_RPC=...
python3 tools/liquid-relay/fork_proof.py build --save-inputs target/fork-proof --out target/fork-proof/proof.json [--escrow $ESCROW]
python3 tools/liquid-relay/fork_proof.py offline --inputs target/fork-proof
cast send $ESCROW "$(jq -r .calldata target/fork-proof/proof.json)"   # operator step: spends gas

# At any later time, on any execution node: the recorded root is the one the chain's block header names.
python3 tools/liquid-relay/fork_proof.py verify --proof target/fork-proof/proof.json
```

The proof's values come from three sources, and the tool checks them against each other before printing anything:

- Genesis time and genesis validators root come from the genesis endpoint, and the fork from the fork endpoint of the header's state. The slot comes from the header. The state after a block holds that block's header, with a zero `state_root`, as `latest_block_header` (field 4, node 43).
- Nodes 11 and 3 come from a light-client branch of the same state: the finality update's `finalized_checkpoint.root` at node 735, or a bootstrap's `current_sync_committee` at node 2945. The branch must reach the header's state root. Its node 4 must be the genesis time's chunk, and its node 10 the root of fields 1 to 4 above. A fork served for another state, or another chain, therefore gives an error instead of a proof.
- The execution block whose EIP-4788 root is the header's root: found by `eth_call` to the EIP-4788 contract, then by its timestamp, and its header must name the same `parentBeaconBlockRoot`. The output records it as `executionBlock`.

The tree the branch proves is found, not assumed. `beacon.STATE_LAYOUTS` lists the BeaconState shapes: Containers of 32 to 256 leaves, and a ProgressiveContainer (EIP-7495, its fields in an EIP-7916 progressive tree). The branch's length narrows them down, and its hashes pick the one whose path reaches the state root. `checkFork` hashes only the progressive one. For any other shape the tool exits 3 with `UnprovableState`, and likewise for a state whose active-fields bits leave one of fields 0 to 3 inactive, because no proof of such a state can pass `checkFork`.

The public update of attested slot 11381920 is kept byte for byte as `contracts/solidity/test/fixtures/sepolia-finality-update-11381920.json` ([layout](../../contracts/README.md#checkfork-hashes-the-progressive-beaconstate)). `test_beacon.py` and `contracts/solidity/test/BridgeEscrowForkProof.t.sol` `testRealSepoliaStateRoot` build a proof from it and require the real block root. `--save-inputs` writes each input as it is read (`light_client.json`, `genesis.json`, `fork.json`, `beacon_root.json`), so a refused run keeps its data; `offline` then replays it.

EIP-4788 keeps a root for 8,191 slots, about 27 hours, but the proof is only useful while its slot time is younger than the escrow's `MAX_FORK_CHECK_AGE`. The output's `pinned` and `effect` say what sending it does: under the pin it keeps deposits open, under any other fork it ends them. With `--escrow` the pin is that escrow's own `FORK_VERSION()` and `FORK_EPOCH()`, a `--pin` that differs is refused, and the tool simulates `checkFork` there with `eth_call`; a simulation that disagrees with the verdict is an error. A `warning` says when the escrow's pin is not the last fork of the guest's schedule (`pins.py` `SEPOLIA_FORKS`), which a deployment must pin. Without `--escrow` the pin is that fork.

The Foundry fixture `contracts/solidity/test/fixtures/sepolia-fork-proof.json` is one such proof. It passed against the real EIP-4788 contract on a fork of Sepolia on 2026-10-18. Its fork test runs at the fixture's recorded `executionBlock`, so the answer does not change with time; it needs an RPC that still serves that block's state, such as an archive node. `verify` needs only block headers, which every node keeps. To recheck the fixture against execution headers, run:

```sh
python3 tools/liquid-relay/fork_proof.py verify --proof contracts/solidity/test/fixtures/sepolia-fork-proof.json --write
cd contracts/solidity
forge test --match-path test/BridgeEscrowForkProof.t.sol -vv   # offline: the recorded root from a stand-in
SEPOLIA_FORK_PROOF_RPC=$ARCHIVE_RPC forge test --match-test testRealSepoliaStateProof -vv   # the real EIP-4788 contract
```

A new fixture from `build --out contracts/solidity/test/fixtures/sepolia-fork-proof.json` records `executionBlock` itself, and any node serves its fork run for a while after it is built.

## Deployment order

This is the order for deploying an instance of `contracts/solidity/contracts/BridgeEscrow.sol`. Its record, `instances/sepolia-liquid-testnet/`, keeps the values and receipts.

Each value is fixed by the steps before it, so the order is forced. The operator runs every step that spends or deploys; these tools do neither. The root `justfile`'s `deploy` group runs the same steps with their checks, writing under the ignored `target/deploy/`: `deploy-config`, `deploy-asset`, `deploy-checkpoint`, `deploy-params`, `deploy-simulate`, `deploy-escrow` (the one Sepolia transaction, after a prompt), `deploy-anchor`, `deploy-record`, `deploy-manifest`, `deploy-bootstrap` (then `just broadcast`) and `deploy-verify`. The escrow is deployed by `contracts/solidity/script/DeployBridgeEscrow.s.sol`, which reads every constructor value and the fork pin back from the new contract.

1. Choose an explicit tL-BTC UTXO for the Liquid bootstrap and keep it unspent. `assemble.py asset --funding-txid <txid> --funding-vout <n>` gives the bridge asset id, both in internal order (for the escrow) and as the display id.
2. `relay.py checkpoint --height <H>`: H must be the last block of a past epoch before the bootstrap. It prints the checkpoint tuple: hash, next epoch's witness script and key ys. Compare the hash with a second source (assumption L2).
3. Deploy `BridgeEscrow(bridgeAsset, 2, maxRelayLag, admission, checkpoint)` on Sepolia. `maxRelayLag` is in seconds, between 1 hour and 30 days; 86,400 was the testnet choice. `admission` is `(depositsEnd, unsupportedForkAt, closer, maxForkCheckAge, genesisValidatorsRoot, forkVersion, forkEpoch)`:
   - `forkVersion`, `forkEpoch`: the last fork of the guest's committed schedule (`pins.py` `SEPOLIA_FORKS`; today gloas, `0x90000076` at epoch 353,024). It must already be active.
   - `unsupportedForkAt`: the announced activation time of the earliest Sepolia fork outside that schedule, from the published schedule at deployment, or `2^64 - 1` if none is announced. The constructor holds `depositsEnd` at least two days (`FORK_MARGIN`) before it. It checks consistency only, so the deployment review must check this value against the schedule.
   - `depositsEnd`: at most 180 days ahead.
   - `closer`: an address that may only bring `depositsEnd` forward for a newly announced fork, or zero for none.
   - `maxForkCheckAge`: 10 minutes to 6 hours.
   - `genesisValidatorsRoot`: Sepolia's, `0xd8ea…8078`.

   Then:
   - Build with `FOUNDRY_PROFILE=deploy` (pinned in `contracts/solidity/foundry.toml`; run forge from `contracts/solidity/`): without its optimizer the runtime code is 29,204 bytes, over EIP-170's 24,576-byte limit. Under that profile the deployed sources give an 18,650-byte runtime. Take the gas limit from a current Sepolia `eth_estimateGas` of the exact initcode and arguments, not a local one: most of it is EIP-8037 state gas.
   - Record the compiler settings with the code hash.
   - Read back `BRIDGE_ASSET`, `MAX_RELAY_LAG`, the admission immutables, `depositsEnd`, `lcTipHeight`, `signblockscriptHash`, `DOMAIN()` and `cast codehash`.
4. Compare `cast codehash $ESCROW` with a local compilation under the recorded settings. Write `instances/<name>/instance.json` with a name, the escrow, code hash, deployment block, DOMAIN and a Sepolia anchor. Its ELF hash and vkey are those of the pinned guest build ([build](../sg16/README.md#the-guest-is-a-pinned-build)); `sg16-bridge-host vkey --elf` prints both from the ELF the prover will use. Record the Sepolia config the guest commits to as `pins.py` `SEPOLIA_CONFIG`.
5. `assemble.py manifest --instance instances/<name>/instance.json --funding-txid <txid> --funding-vout <n>`, then `assemble.py bootstrap --instance …`. Every assembly command needs `--instance`; there is no default. The bootstrap re-derives the leaves and initial state before building.
6. After the bootstrap confirms, publish the manifest directory and run `assemble.py verify-bootstrap --instance … --manifest … --bootstrap-tx … --escrow-asset "$(cast call $ESCROW 'BRIDGE_ASSET()(bytes32)')"`. Then set `ui/config.js` `INSTANCE` to the record (name, escrow, code hash, bootstrap txid, state address) in a reviewed commit of its own: the page serves that instance and no other. It refuses an escrow whose code hash differs, and deposits until its own check of the bootstrap passes.
7. Open deposits:
   - Relay to Liquid's tip (`relay.py batches`).
   - Send `checkFork` with a proof of a current Sepolia beacon state against its EIP-4788 root, from `fork_proof.py build --escrow $ESCROW` ([above](#the-beacon-fork-check)). Its `pinned` must be true and its simulation must not revert.
   - Repeat both at least every `maxForkCheckAge` while deposits should stay open.

   Then deposit, wait for Ethereum finality, prove and update, and claim (`tools/sg16/bridge-guest/testnet/README.md`).
8. Burn to `burnScriptPubKey(recipient)`. At the current `BridgeEscrow` that is a bare `OP_RETURN` naming the chain, escrow and recipient (`contracts/README.md`). The UI's Humid route and `liquid-testnet-wallet burn …` build that value-bearing script; the wallet CLI independently derives its bytes and refuses a differing escrow answer. Wait for 2 Liquid confirmations, relay with `relay.py batches` up to the burn height + 1, then `redeem` (or use the UI, which does steps 8 and later). A recipient that refuses plain ETH makes `redeem` revert with the burn unspent; it then calls `redeemTo(to, …)` itself.
9. Before any fork outside the pin activates, confirm that Liquid's proven accumulator equals `accumulator()`, so every admitted deposit is claimable. This is the completion check in the contract header.

Deposits close by themselves when nobody relays for `MAX_RELAY_LAG` (Liquid header time against Ethereum block time), or when the light client halts on an undecidable DynaFed vote or a signing script it cannot parse. Relaying reopens them inside the window. They also close when no fork proof is younger than `maxForkCheckAge`, and a fresh proof reopens them. They close for good at `depositsEnd`, or once anyone proves a fork outside the pin. Redemptions are never gated.

## What is and is not checked

The light client assumes each epoch's keys sign one valid chain while current (L1) and a correct checkpoint (L2). Under L3, the keys of an epoch stay honest until every height of that epoch has been relayed, even after Liquid has retired them: whoever holds retired keys can sign a fork of the epoch's unrelayed heights, and the contract cannot tell it from the real chain. No time bound closes this, because header times are the signers' own. Relaying past each epoch boundary promptly keeps the window short. See the contract header and `contracts/solidity/test/LiquidLightClient.t.sol` `testUnrelayedHeightsOfAnEpochTrustThatEpochsKeys`. On Liquid testnet the signing script is 1-of-1, a single Blockstream key, so L1 is trust in that key. The bridge adds no signer of its own.

These tools check that each served header hashes to the id it was fetched by, that the headers form one chain, that the tip's signblock witness verifies, and that a transaction's Merkle branch reaches its header. They do not validate Liquid transactions or detect an undecidable vote tally; the contract reverts on the latter. An Esplora response is never an authority: the contract re-checks every byte.
