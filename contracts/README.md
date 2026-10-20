# Bridge contracts

| Project | Contents |
|---|---|
| [`solidity/`](solidity/) | Foundry project (`solidity/foundry.toml`): the Sepolia escrow and the contracts it imports, their tests and fixtures |
| [`simplicity/`](simplicity/README.md) | smplx project (`simplicity/simplex.toml`): the Liquid claim leaf, the crate that compiles it and its tests |

The Liquid update leaf is generated per instance by [`tools/sg16`](../tools/sg16/README.md) and published with the instance record. Each contract's header states its rules and assumptions; this note records the design decisions behind them and what has to hold before a public transfer.

## Solidity

| File (`solidity/contracts/`) | Role |
|---|---|
| `BridgeEscrow.sol` | The escrow: `BridgeDeposits` + `LiquidLightClient` + redemption of burns, which are bare `OP_RETURN` outputs, with deposit admission bounded by the proof path to Liquid (a deposit window, a permissionless EIP-4788 beacon fork check, and an optional deposit closer) |
| `BridgeDeposits.sol` | Deposits: the append-only SHA-256 leaf, tree and accumulator formulas the claim leaf opens, with a script recipient and an admission gate |
| `LiquidLightClient.sol` | Liquid's signed header chain on Ethereum, epoch by epoch, with DynaFed key changes |
| `ElementsParser.sol` | Elements transaction and Merkle encodings, checked against real testnet transactions |

```sh
cd contracts/solidity
forge test                          # default profile (prague, unoptimized)
FOUNDRY_PROFILE=deploy forge test   # the optimizer settings the escrow was deployed with
```

**A deployment pins these four files.** The escrow is `contracts/BridgeEscrow.sol` and its imports, built with `FOUNDRY_PROFILE=deploy`. solc's metadata names each source by its path from the Foundry root and the runtime code ends in that metadata's hash, so once the instance is deployed its code hash depends on these names and bytes; a changed escrow is a new deployment with a new instance. `forge inspect BridgeEscrow deployedBytecode` under `FOUNDRY_PROFILE=deploy`, with the escrow's immutables filled in, is the comparison with the deployed code.

Gas figures from the tests use the `prague` schedule. Sepolia has run Glamsterdam since 6 October 2026, which reprices state access (EIP-8038) and charges new state as separate state gas (EIP-8037: 97,920 per new storage slot, 1,530 per byte of deployed code), so **no local figure is a Sepolia cost**. Take every gas limit from a current Sepolia `eth_estimateGas`, and keep the instance's receipts in its record.

## Deposit admission is bounded by the proof path

A deposit reaches Liquid only through a Sepolia finality update that the instance's SP1 guest can prove under its pinned fork schedule. An escrow gated on Liquid header freshness alone would keep taking ETH after a fork outside that schedule, which no Liquid update could ever mint. `BridgeEscrow` admits a deposit only when all three of these hold:

- the time is before `depositsEnd`. It is set at deployment, at most 180 days ahead and at least `FORK_MARGIN` (2 days) before the stated earliest unsupported fork. It never increases.
- a beacon state proven through EIP-4788 under the pinned fork is at most `MAX_FORK_CHECK_AGE` old. Proving any other fork ends deposits for good.
- the light client is current: its tip header is at most `MAX_RELAY_LAG` older than the Ethereum block (between 1 hour and 30 days; testnet uses 1 day).

What this proves, and what it does not, is stated exactly in the contract header. Admission stops within `MAX_FORK_CHECK_AGE` of any fork's activation with nobody acting. A fork announced in time can be closed before activation, by the deployment's window or by the closer. A fork not announced in time leaves a residual: deposits admitted between the last pre-fork finality update and the moment admission stops may never be claimed. Nothing on Ethereum can see whether a deposit reached Liquid.

The closer is an availability and trust role. It can only bring the end forward; it cannot withdraw funds, reopen intake or block redemption. A halted light client never advances, so deposits stay closed; that covers an undecidable tally or a signing script the client cannot parse. Anyone can relay, including from the page's deposit form, and relaying reopens deposits inside the window. Redemptions and claims of deposits already admitted are never gated.

## Burns are bare OP_RETURN outputs

A burn is one explicit output of the bridge asset whose scriptPubKey is exactly `burnScriptPubKey(recipient)`:

```
6a 46 | "liquid-bridge-poc/burn" (22 bytes, BURN_TAG) | be64 chain id (BURN_CHAIN_ID) | escrow (20) | recipient (20)
OP_RETURN, one direct push of 70 bytes: a 72-byte script
```

- **Destruction by consensus.** Executing a scriptPubKey that starts with `OP_RETURN` fails whatever input spends it, so the output can never be spent.
- **Visible on chain.** An explorer shows the output as `OP_RETURN` with the amount, asset and payload, in plain bytes: anyone can read the tag, chain, escrow and recipient and sum a bridge's burns from public data. Humid 1.1.3's approval shows it with an empty address and `Script: 6a46…`, whose last 40 hex digits are the recipient.
- **Binding.** The script names the chain (fixed at deployment in 8 bytes; the constructor refuses a wider chain id with `ChainIdTooWide`), this escrow and the recipient. The escrow compares the keccak256 of the whole script, so only this exact encoding redeems: a push by `OP_PUSHDATA1`, a trailing push, another chain, escrow or recipient, and a bare `OP_RETURN` with no payload are all refused (`testBurnIsABareOpReturnNamingTheRecipient`).
- **Standardness (policy, not consensus).** Elements 23.3.4 budgets `MAX_OP_RETURN_RELAY`, 100,000 bytes by default, across a transaction's data outputs, so the 72-byte script fits by a wide margin. The dust check does not apply to a data output.
- **What it costs.** There is no address, so an ordinary wallet Send cannot burn. Burning needs a wallet or tool that pays an explicit output to a given script: Humid through the page's PSET route (`ui/lib/humid.js`), `liquid-testnet-wallet burn`, or a PSET or raw-transaction tool.

The page builds this script itself and reads `burnScriptPubKey(recipient)` only to require that the escrow agrees (`ui/lib/bridge.js` `escrowBurnTarget`), so an RPC that misreports the escrow cannot make the page pay another script.

Redemption pays in full or does not happen. `redeem` pays with a plain call that gets all remaining gas but 1/64 (EIP-150); if the call fails, the redemption reverts with `PayoutFailed` and the burn stays unspent. A recipient that refuses plain ETH but can make calls uses `redeemTo(to, burn, ref)`, which only it can call, because the burn script commits to the recipient. The payout path contains no fixed gas amount: no fixed stipend stays right across forks. Tests: `testRefusingRecipientRedeemsToAnotherAddress`, `testGasHungryRecipientIsPaidOrNothingHappens` and the reentrancy test. An address that can neither receive ETH nor call the escrow can never redeem, and a mistyped address loses the burn, so the page accepts a burn recipient only as the connected account or an EIP-55 checksummed address, and warns when it is a contract.

`testRedemptionSelectorsErrorsAndEvent` pins the selectors, error names and `Redeemed` topic that the page and `cli.js` encode and decode.

## checkFork hashes the progressive BeaconState

Sepolia's Gloas `BeaconState` is a ProgressiveContainer (EIP-7495): `hash_tree_root = sha256(progressive_tree(field roots) || active_fields)`, the field roots in an EIP-7916 tree whose levels hold 1, 4, 16, 64, ... fields. In it, `finalized_checkpoint.root` is at generalized index 735, node 4 is the chunk of `genesis_time` (field 0), node 10 is `merkleize([genesis_validators_root, slot, fork, latest_block_header])` (fields 1 to 4, with the header's `state_root` zero), and node 3 is the active-fields chunk. `checkFork` hashes:

```
fork   = node(node(previous_version, current_version), node(le64(epoch), 0))
node10 = node(node(genesis_validators_root, le64(slot)), node(fork, stateBranch[0]))   stateBranch[0] = node 43
state  = node(node(le64(genesis_time), node(node10, stateBranch[1])), activeFields)    stateBranch[1] = node 11
```

then the five-field BeaconBlock (nodes 10, 4 and 3). `BeaconProof` is `(uint64 timestamp, uint64 genesisTime, bytes32 genesisValidatorsRoot, uint64 slot, bytes4 previousVersion, bytes4 currentVersion, uint64 epoch, bytes32[2] stateBranch, bytes32 activeFields, bytes32[3] blockBranch)`, 13 static words of calldata.

`activeFields` is a typed member and is not pinned. Under SHA-256 collision resistance, a proof that reaches the EIP-4788 root shows the state's own node 3. A ProgressiveContainer keeps a field's index for the life of the type, and appending fields changes only node 3, so `checkFork` requires the bits of fields 0 to 3 to be set and nothing more: a later fork that appends fields can still be proven, and that proof ends deposits at once (`testForkProofsReadOnlyFieldsZeroToThree`). Pinning the exact value would turn that into a lapse after `MAX_FORK_CHECK_AGE`.

Evidence from independent constructions: `solidity/test/BridgeEscrowForkProof.t.sol` `testRealSepoliaStateRoot` walks a real 9-node branch (attested slot 11381920, `test/fixtures/`) to the real state root and builds the proof from it; `SepoliaBeacon.sol` hashes synthetic states by the EIP-7916 recursion, with retired and appended fields, for the admission suite; `tools/liquid-relay/test_beacon.py` and `ui/test/bridge.test.js` check the same update with their own merkleization; `testRealSepoliaStateProof` runs a proof that `fork_proof.py build` made from live data, against the real EIP-4788 contract when `SEPOLIA_FORK_PROOF_RPC` names an archive node. Under Gloas, block N's root appears in EIP-4788 at a timestamp after N's slot; `fork_proof.py` searches for that timestamp rather than assuming it.

## The guest pins no escrow code hash

The SP1 guest has no Cargo features and names no deployment. What binds a proof to this escrow:

- in the Liquid update leaf: the escrow address, the network config (genesis validators root and fork schedule) and slot 0, which the proof's public values must carry exactly (`tools/sg16/bridge-guest/liquid.py`). A proof about another contract, network or slot does not satisfy it.
- in the guest: an account with code (`KECCAK_EMPTY` in `program/src/main.rs`).

Code at an address cannot change after its creation transaction: `BridgeEscrow` has no `SELFDESTRUCT` or `DELEGATECALL`, and since EIP-6780 `SELFDESTRUCT` deletes code only in the creating transaction. The update leaf is built after deployment, so the address it pins already holds its final code. The invariant "the proven slot is the reviewed escrow's" therefore becomes: the leaf pins an address whose code, read after deployment, is the reviewed escrow's. The instance file's `ESCROW_CODE_HASH` records that reading, and deployment compares it with a local compilation. One ELF and one vkey serve every instance and can be built before deployment ([pinned values](../tools/sg16/README.md#the-guest-is-a-pinned-build)).

## Other trust decisions

- **Retired keys and relay liveness: an assumption, stated and tested.** L3 in `LiquidLightClient.sol`: the keys of epoch e stay honest until every height of e is relayed, even after Liquid retires them. A height-ordered client cannot tell a late honest relay from a fork signed by retired keys, and no time bound separates them, because header times are the signers' own. `testUnrelayedHeightsOfAnEpochTrustThatEpochsKeys` pins the boundary. Relaying past each epoch boundary promptly keeps the window short. On Liquid testnet every epoch has the same single Blockstream key, so L3 adds nothing to L1 there.
- **Bootstrap verification: off chain, one structural check in three implementations, gating deposits in the page.** The escrow pins the asset id but cannot see where that asset's only reissuance token went; checking that on chain would make the escrow's code depend on itself through the update leaf. So `sg16-testnet check-bootstrap` (rust-elements), `assemble.py verify-bootstrap` (which also recompiles the claim leaf, recomputes the update leaf's CMR from its published program text and rebuilds the state address) and `ui/lib/issuance.js` `checkBootstrap` check the bootstrap transaction against a published state address. Only the manifest-based check confirms that the state address commits to the reviewed leaves.
- **Recipient types: any standard script.** A deposit commits `SHA256(scriptPubKey)` for P2PKH, P2SH, P2WPKH, P2WSH, or P2TR with an on-curve key, and the claim leaf pays the output whose script hashes to the commitment. Empty, `OP_RETURN`, future witness versions and off-curve Taproot keys are refused, since each would make a claim unspendable or give it away. The check is mirrored in `BridgeDeposits.recipientOf`, `claim::is_standard_recipient`, the claim tool and `ui/lib/bridge.js`.
- **Direct header relay over a ZK proof of Liquid headers.** Relaying signed headers adds no Liquid-header prover or key, and Liquid testnet signs with one ECDSA key. A 100-header batch stores one entry, 195,840 state gas whatever its size; the relay tools default to 100 headers per batch, far below the 2^24 execution cap. Sustained operation and mainnet-scale economics have not been measured.

## Gates before a minimal-value public transfer on a new instance

Repeat these for any new instance rather than treating a test as a guarantee for another deployment. The full order, with the admission parameters, is in [`tools/liquid-relay/README.md`](../tools/liquid-relay/README.md#deployment-order).

1. From a fresh checkout, every suite in the [root build order](../CONCEPT.md#build-and-test) passes on this revision, including `FOUNDRY_PROFILE=deploy forge test` and `cargo test` of `simplicity/`. The guest is the pinned build ([tools/sg16](../tools/sg16/README.md#the-guest-is-a-pinned-build)).
2. Checkpoint: `relay.py checkpoint` at the most recent completed epoch end. Compare it with a separately operated source and record the exact hash and signing script (L2).
3. Deploy `BridgeEscrow(asset, 2, 86400, admission, checkpoint)`:
   - Check `admission.unsupportedForkAt` against Sepolia's published fork schedule; the constructor checks only its consistency with `depositsEnd`.
   - Build with `FOUNDRY_PROFILE=deploy` and take the gas limit from `eth_estimateGas` on current Sepolia, with margin.
   - Record the exact compiler settings (profile, optimizer runs, via-IR) with the code hash.
   - Read back `BRIDGE_ASSET`, `MAX_RELAY_LAG`, the admission immutables and `depositsEnd`, `lcTipHeight`, `signblockscriptHash`, `DOMAIN()` and the code hash, and compare `cast codehash` with a local compilation under those settings, with the immutables filled in. Then write the instance file, with the guest's ELF hash and vkey.
4. Bootstrap. Run `verify-bootstrap --escrow-asset` and publish the manifest directory with the instance file and bootstrap transaction under `instances/`. Set `ui/config.js` `INSTANCE` from that record (name, escrow, code hash, bootstrap txid, state address) in a commit of its own, pin its live state in `ui/test/live-state.js` (the anchor, until its first update), check that the Pages workflow's `RECORD` names its directory, and confirm that "Bridge checks" are all green. The React trust panel reads the instance and escrow state; review its deployment-specific statements before publishing.
5. Relay to Liquid's tip and send a `checkFork` proof from `fork_proof.py build --escrow $ESCROW`, so that `depositsOpen()` is true. Deposit a minimal amount to an ordinary test-wallet address. After finality, prove, update and claim. The claim's output 1 must pay the event's script.
6. Burn a minimal amount to an EOA recipient with the page's Humid route, which pays `burnScriptPubKey(recipient)`. Check the burn on an explorer: the output is `OP_RETURN` with the payload and is explicit. Wait for 2 confirmations, relay in batches of at most 100, each with a gas limit from a current-fork estimate, then redeem: expect `Redeemed` with `to` equal to the recipient, and `isRedeemed`.
7. Before a fork outside the pin activates, confirm that Liquid's proven accumulator equals `accumulator()`.
8. Stop at any failed gate. A stuck relay leaves the test funds locked until someone relays; that is part of the test, not a reason to add a rescue path.
