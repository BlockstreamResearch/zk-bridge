# Sepolia → Liquid testnet assembly for the sg16 bridge state UTXO

Tooling that turns real inputs into Liquid testnet transactions. The inputs are a funded explicit tL-BTC outpoint, an `sg16-bridge-host run --prove` artifact and Sepolia `Deposit` events. The transactions are bootstrap, update and claim. Every step goes through named gates. These assembly tools do not sign fee inputs or broadcast: `tools/sg16/liquid-testnet-wallet` or Humid signs the fee input, and the `justfile` wraps the whole sequence ([OPERATOR.md](../../../../OPERATOR.md#the-same-steps-with-just)).

## What is assembled

```
state UTXO   P2TR(NUMS, {{update leaf, claim leaf}, tapleaf(state_hash(lc, acc, claimed_root))})   holds the bridge asset's only reissuance token
update leaf  liquid.BridgeGuestVerifier: Groth16 verifier for the pinned SP1 v6.1.0 key folded with the Sepolia guest's
             program vkey, exit code 0, VK_ROOT and proof nonce 0, plus the bridge-guest rules (config, escrow, slot 0 pinned;
             prev_lc = spent state; successor commits new_lc and the proven accumulator, and keeps claimed_root)
claim leaf   contracts/simplicity/simf/claim.simf (SimplicityHL): mints any proven deposit whose slot of the claimed tree is
             unset, to the scriptPubKey whose SHA-256 the deposit committed (BridgeDeposits.sol), sets that slot, and
             requires an L-BTC fee
```

`claimed_root` is the root of the claimed tree, a depth-32 SHA-256 sparse Merkle tree indexed by deposit number whose slot is `SHA256("liquid-bridge-poc/claimed")` once the deposit is paid ([contracts/simplicity](../../../../contracts/simplicity/README.md#the-claimed-tree)). A state record carries the set it opens:

```
{"head", "header", "committee", "acc", "claimed": [0, 2], "claimed_root", "lc", "state_hash"[, "exec_root", "exec_block"]}
```

`claimed` lists the paid deposit indices strictly ascending, each below 2^32, and `claimed_root` must be their tree's root. Every tool refuses a record where either fails. After `recover` walks an update without a store hint the record has `lc` instead of `head`, `header` and `committee`.

Every command except `asset` needs `--instance <instance.json>`. There is no default instance, and no environment variable selects one. An instance file (`pins.py` `load`) gives the escrow, its code hash and DOMAIN, the guest ELF hash and program vkey, and the anchor; `pins.py` keeps only the values that do not depend on a deployment. The manifest records its instance (the `sepolia` and `sp1` sections, the claim leaf, the initial state). Bootstrap, verify-bootstrap, update and claim refuse a manifest that does not match the instance file given, and the claim tool refuses a manifest of another schema.

The guest pins no escrow code hash. The update leaf pins the escrow's address (`ESCROW` in the bridge-guest rules above), and the escrow's code cannot change after deployment ([decision](../../../../contracts/README.md#the-guest-pins-no-escrow-code-hash)). The instance file names the `GUEST_ELF_SHA256` and `PROGRAM_VKEY` of one reproducible Docker build ([`tools/sg16/README.md`](../../README.md#the-guest-is-a-pinned-build)).

| Step | Tool | Builds | Left to the operator |
| --- | --- | --- | --- |
| manifest | `assemble.py manifest` | Several values for one funding outpoint: the asset and token (Python and rust-elements independently); the token constants; the claim CMR (SimplicityHL 0.7.2 / rust-simplicity 0.8); the update-leaf CMR for the real key and its budget rehearsal (minutes); the initial state at the pinned anchor; the state address (TaprootBuilder and the harness's tagged hashes) | review, then fund and sign |
| bootstrap | `assemble.py bootstrap` → `sg16-testnet bootstrap` | First re-derives what the bootstrap commits forever: the initial state against the pinned anchor, the claim CMR recompiled, the update CMR recomputed from the program file (and its text hash), and the state script. Then the unsigned issuance tx: one token, no asset, at blinding A, to the state address, with a non-empty change script. It checks the amount proofs and the token commitments compiled into both leaves | sign input 0, broadcast |
| verify-bootstrap | `assemble.py verify-bootstrap` → `sg16-testnet check-bootstrap` | Anyone's check, before depositing, of the *public* bootstrap against the published manifest directory (`manifest.json` and `initial_state.json`). It runs the same re-derivations as bootstrap, then checks the confirmed transaction: input 0 spends the funding outpoint as a new issuance of no asset and exactly one explicit token; that token is the manifest's; no other input issues; output 0 is the state UTXO with the token at blinding A; every other output is explicit L-BTC. With `--escrow-asset` the escrow's `BRIDGE_ASSET()` must be the issued asset | publish the manifest directory |
| update | `assemble.py update` → `sg16-testnet update` | The artifact gate (pairing checks with the pinned key and the folded key), then the witness from the real proof. It builds the tx in exactly the layout of the harness's helios mode over the real spent outputs. The update leaf is pruned, executed, encoded, decoded and executed again, followed by budget, weight and fee-floor checks | sign the fee input, broadcast |
| deposits | `assemble.py deposits` → `sg16-testnet-claim deposits` | The deposits the state's accumulator proves, each with its units and script and whether the state has paid it, and `unclaimed`, the indices `claim` accepts. Python and the claim tool must agree on the count and the claimed set | choose a deposit |
| claim | `assemble.py claim --deposit <index>` → `sg16-testnet-claim claim --deposit <index>` → `sg16-testnet verify` | A prefix of the deposit events must reproduce the state accumulator (later deposits may follow it), and every event must be within the escrow's unit bounds. The deposit must be proven (below the count) and unclaimed in the record, whose claimed set must open the spent output's `claimed_root`. There is no default deposit. The claim leaf is satisfied under 0.8, and the spend is decoded and executed again under stock 0.9. The successor's record is written beside the transaction (`<out>.new_state.json`) | sign the fee input, broadcast |
| verify | `sg16-testnet verify` | Node-like check of any Simplicity input: control-block commitment, CMR, decode, execution, budget and amount proofs | |
| txid, output, input | `sg16-testnet txid <tx.hex>`, `output <tx.hex> <vout>`, `input <tx.hex> <vin>` | How the `justfile` reads a transaction file: one hex string that rust-elements reads as exactly one transaction, with no bytes left over. `output` gives the script and, where explicit, the asset and value, and whether it is explicit tL-BTC. `input` gives the outpoint spent. An index must be canonical decimal and present | |
| recover | `assemble.py recover` → `sg16-testnet recover` | The current state record from public transactions alone: the published bootstrap, then each update and claim that spent the state output, in chain order. Each spend's control block must commit its leaf to the spent output. An update's new lc, accumulator and head come from its witness, and it must carry `claimed_root` unchanged. A claim adds its deposit to `claimed`: the one 64-bit word of its witness, below 2^32 and not yet claimed, whose claimed tree gives output 0. Each successor output must be the state UTXO those values imply, with the token blinding alternated. An update's light-client roots come only from a `--hint` that hashes to its lc; the named store file must have matching metadata. The host separately decodes its CBOR and recomputes the roots before proving | check on Liquid that the transactions are confirmed and the last state output is unspent |

The update leaf reads the claim leaf's hash from the control block, and the claim leaf reads the update leaf's. **The bootstrap transaction alone fixes the pair, so the manifest's gates must pass before funding.** A non-`deployable` manifest is refused by bootstrap, update and claim unless `--local-test` is passed. Such a manifest is a dry run, or uses a stand-in or synthetic-key update leaf. With `--local-test` the reports say `"local_test_only": true`. A synthetic-key program cannot spend a real state: the real update CMR commits to the pinned SP1 key.

## Gates

- **Real proof.** The artifact has Groth16 bytes, and execute-only `0x` is refused. It must also match these values:
  - guest `sg16-bridge-program`, network `sepolia`, SDK 6.8.1 and the pinned program vkey;
  - selector `4388a21c`, exit code 0, `VK_ROOT` and nonce 0;
  - curve and subgroup checks on the proof points.

  The pinned five-input key must accept the proof, and so must the folded key. The folded key must reject a different digest.
- **CMR / program.** The program's CMR must equal the manifest's update CMR. The claim leaf is recompiled and must equal the manifest's claim CMR. The verifier source must match pinned `VERIFIER_HASH` and `VK_ROOT`, and its key constants must be exactly the pinned ones: both coordinates of every point, no other public input, and the parsed key equal to the key the pins give.
- **Generator.** The loaded generator is pinned only as `vendor/simple-groth16` at the pinned commit with the commit's bytes where Python imports from it (`tools/sg16/sg16/ref.py`). `git status` is not the check, since the index can hide edits (assume-unchanged, skip-worktree) and does not report ignored files. Instead the commit and its trees, read with `git cat-file`, must each hash to their names, and the files on disk are compared with them: every importable module or package at the checkout's top level, which is first on `sys.path`, must be pinned content, and under each such package, `groth/` always, every pinned file must be present and byte for byte its blob, with no symbolic link and no importable module or package added. Bytecode caches and files Python does not import are not compared, and caches are not used either: a checkout that passes is imported by compiling `groth` and its modules from the bytes the check read (`VerifiedSource`, first on `sys.meta_path`), since Python's own loader would run a `__pycache__` .pyc left from an edit whose recorded timestamp and size match the restored source. Another commit, any difference, or a directory where this cannot be checked loads only with `SG16_ALLOW_UNPINNED=1`, as Python normally imports it; an `SG16_REF` override loads but is never pinned. The manifest records `simple-groth16 <pin>` only for the pinned generator, and otherwise its commit and source hash marked "not pinned" (`update_leaf.generator`), with `generator_source_sha256`. A deployable manifest, a bootstrap, an update and an export need both the loaded generator and the leaf's to be pinned, since another generator's leaf reads another witness. An update for a leaf without that record, or with another commit, needs the checkout that compiled it; claims and recovery do not depend on the generator. The build also checks that every loop step's output bounds stay within the fixed point the CRT arithmetic assumes.
- **Budget.** The update leaf has one public input. Its budget is measured on a rehearsal (`update_leaf.budget.rehearsal`): a leaf with the same generator, constants, config, escrow and slot but a synthetic five-input key folded like the SP1 key, so that a valid proof exists, spent in a complete harness update transaction. The rehearsal must execute at its own predicted cost, which must equal the update leaf's, with one input and the update leaf's witness width. Less 1,000 mWU per byte of `program_variation`, its input budget must still cover that cost, and its weight plus that variation must stay below standard weight. `program_variation` bounds how much the pruned program of one leaf changes between spends, from rust-simplicity's encoding: one child-distance code per bit of each table window and one per window, and per bit of the shared digit function a hidden branch and three codes; neither pruning choice changes the number of nodes. It is 1,348 bytes for a 34,961-byte program. It does not bound the difference between the rehearsal leaf and the update leaf, which are for different keys. For the real SP1 key both predict 48,884,728 mWU, and the update with a real proof measured 34,957 program bytes against the rehearsal's 34,952 (`target/groth16-optimization/repair-real-proof`). `manifest` runs the rehearsal, and fails, leaving its manifest non-deployable and without an update leaf, if the gate does. `bootstrap`, and `verify-bootstrap` of a leaf that records its generator, regenerate the leaf from the instance key, require the same program text, take its cost, input count and witness width from the regenerated leaf (the manifest must record the same), and run the rehearsal again rather than read the manifest's (minutes, and the harness). `update` and `export-proof` check the manifest's record; `update` also requires its spend's program size to be within `program_variation` of the rehearsal's. What admits an update is its own spend's measured budget (`sg16-testnet update`, the browser builder).
- **Witness.** The public values must equal the `liquid.py` model of the witness fields. The numeric verifier model must accept the real proof. The leaf must execute on the real transaction, and the decoded cost must fit within the input's budget, with no padding.
- **Taproot / control block.** TaprootBuilder and the harness's code must give the same script and control blocks, with NUMS as the internal key. The output key is recomputed from each control block. The spent output must be the state of the given record.
- **Asset / issuance authority.** The entropy is derived from the funding outpoint, and Python and rust-elements must agree on it. The issuance must create exactly one token and no asset. The token commitments must equal the constants compiled into both leaves. The token phase must alternate. Updates must issue nothing. Claims must reissue with the spent token's blinding as the nonce.
- **Transaction binding.** These are enforced on chain by the leaves; the builders check them first:
  - `prev_lc` must equal the spent state's lc, and the head must advance;
  - the successor must commit `new_lc` and the proven accumulator;
  - a claim's deposit is recomputed from the transaction, its slot of the claimed tree must be unset under the spent `claimed_root`, and the successor sets exactly that slot; an update carries `claimed_root` unchanged.
- **Network parameters.** The tools require the Liquid testnet genesis and tL-BTC, and refuse other networks; the claim tool checks both too. They also require these Sepolia values:
  - chain ID 11155111 and the genesis validators root;
  - the config the guest commits to, `pins.py` `SEPOLIA_CONFIG`;
  - the instance file's escrow, its code hash and DOMAIN, with DOMAIN and the anchor lc recomputed before every command;
  - the empty accumulator, slot 0 and the anchor lc.

  The relay fee must be at least 0.1 sat/vB, and the transaction must weigh less than 400,000 WU.

## Commands

```sh
# build and unit tests (each crate has its own workspace and lockfile; the two testnet targets go to the ignored
# bridge-guest/target, where assemble.py looks for them)
cargo test --release --locked --manifest-path tools/sg16-harness/Cargo.toml
cargo build --release --locked --manifest-path tools/sg16-harness/Cargo.toml
export T=tools/sg16/bridge-guest
CARGO_TARGET_DIR=$T/target/testnet-tx cargo test --release --locked --manifest-path $T/testnet/tx/Cargo.toml
CARGO_TARGET_DIR=$T/target/testnet-tx cargo build --release --locked --manifest-path $T/testnet/tx/Cargo.toml
CARGO_TARGET_DIR=$T/target/testnet-claim cargo test --release --locked --manifest-path $T/testnet/claim/Cargo.toml
CARGO_TARGET_DIR=$T/target/testnet-claim cargo build --release --locked --manifest-path $T/testnet/claim/Cargo.toml

# local tests (no network): A-D and G fast; E (synthetic key, --full) and F (real key, --real) compile a full
# verifier each. F runs under the instance file --artifact-instance names; real SP1 artifacts of that instance's
# first update, if you have them, add the artifact gates and a real-proof update:
#   --exec-artifact <exec.json> --proof-artifact <proof.json>
python3 tools/sg16/bridge-guest/testnet/test_testnet.py --full --evidence target/sg16-testnet-local.json
python3 tools/sg16/bridge-guest/testnet/test_testnet.py --real --artifact-instance instances/<name>/instance.json
# `just deploy-record`'s Sepolia readback (needs just; stand-in cast, curl and host binary, no network)
python3 tools/sg16/bridge-guest/testnet/test_deploy_record.py
# the proof path's gates (needs just; stand-in host, curl and node, no network): `execute` and `prove` run only on
# inputs from the recovered state, `preflight` passes an update only once its store is read back from HTTPS, and a
# second operator with an empty work directory recovers a withheld store (`status`, `reconstruct`, `inputs`,
# `stage-recovered`), or is refused when the beacon data is gone
python3 tools/sg16/bridge-guest/testnet/test_proof_path.py
# the recipes' transaction reading (needs just and the built sg16-testnet; stand-in curl and wallet, no network):
# `sg16-testnet txid`, `output` and `input` of the record's bootstrap against liquid.py and the manifest, `just txid`
# and `just deploy-asset`'s funding output check
python3 tools/sg16/bridge-guest/testnet/test_tx_reading.py

# real path, in order (each prints a JSON report; exit 3 names the failed gate). I is the instance file,
# instances/<name>/instance.json
python3 tools/sg16/bridge-guest/testnet/assemble.py pins --instance $I
python3 tools/sg16/bridge-guest/testnet/assemble.py manifest --instance $I --funding-txid <display txid> --funding-vout <n> --out <dir>
python3 tools/sg16/bridge-guest/testnet/assemble.py bootstrap --instance $I --manifest <dir>/manifest.json --funding-tx <funding.hex> --fee <sat> \
    --change-spk <hex> --out <bootstrap.hex>
#   -> operator signs input 0 and broadcasts (authorization required; not done by these tools)
python3 tools/sg16/bridge-guest/testnet/assemble.py verify-bootstrap --instance $I --manifest <dir>/manifest.json --bootstrap-tx <public bootstrap.hex> \
    --escrow-asset "$(cast call $ESCROW 'BRIDGE_ASSET()(bytes32)')"
python3 tools/sg16/bridge-guest/testnet/assemble.py check-artifact --instance $I --artifact <proof.json> --state <dir>/initial_state.json
python3 tools/sg16/bridge-guest/testnet/assemble.py update --instance $I --manifest <dir>/manifest.json --artifact <proof.json> \
    --state <dir>/initial_state.json --state-tx <bootstrap.hex> --fee-tx <fee funding.hex> --fee-vout <n> --out <update.hex>
python3 tools/sg16/bridge-guest/testnet/assemble.py deposits --instance $I --manifest <dir>/manifest.json --state <state.json> --deposits <deposits.json>
python3 tools/sg16/bridge-guest/testnet/assemble.py claim --instance $I --manifest <dir>/manifest.json --state <state.json> --deposits <deposits.json> \
    --deposit <index> --state-tx <update.hex> --fee-tx <fee funding.hex> --fee-vout <n> --out <claim.hex>
```

The fee input of an update or claim is spent entirely as the fee: both leaves fix the output count, so there is no change. Use a fee UTXO sized for the transaction, about 95 kvB for an update. The builders refuse a fee input above 100 times the relay floor (at least 50,000 sat allowed), so a mistyped outpoint cannot burn a large UTXO.

`--deposits` lists the escrow's `Deposit` events in index order, each `[units, "scriptPubKey hex"]`, taken from the event's `scriptPubKey`. The recipient is its SHA-256, and the claim pays exactly that script. The claim tool refuses a script `BridgeDeposits.recipientOf` would not have accepted. The accepted forms are P2PKH, P2SH, P2WPKH, P2WSH and P2TR with an on-curve key.

## Recovering the state

Each update and claim spends the state UTXO, so it needs the spent state's fields. The state script commits to them only by hash. `claim` writes its successor's record, but another operator's claim does not publish one. Any operator can rebuild the record from public data. Fetch the raw hex of the bootstrap and of every later state spend from Esplora (`GET /tx/<txid>/hex`). To find each spend, follow `GET /tx/<txid>/outspend/0` from the bootstrap until it reports `"spent": false`. Then run:

```sh
python3 tools/sg16/bridge-guest/testnet/assemble.py recover --instance $I --manifest <dir>/manifest.json --bootstrap-tx <dir>/bootstrap.hex \
    --spend <first spend.hex> --spend <next spend.hex> ... --hint <dir>/lc_preimages.json --out <state.json>
```

Liquid carries the light-client commitment `lc`, the accumulator, the claimed root and the head; `recover` reads them from the update witnesses, and each claim's deposit from its witness and output 0, so the record lists the claimed set the root opens. An update's `lc` also commits to the finalized beacon header root and the sync committee root at its head, and Liquid holds only that hash. Without a `--hint` the record after an update has `lc` but no store. `claim` accepts that record, because the claim leaf needs only `lc`. `check-artifact --state` and `update` need the store. Two sources give it, and a hint is used only if it hashes to the recovered `lc`:

- the instance's published `lc_preimages.json`, to which each update's head, header and committee are appended;
- a store file, published or rebuilt by `sg16-bridge-host reconstruct` when the update reaching the head published none;
- the output of `sg16-bridge-host inputs --anchor-slot <head>` or `anchor`, whose store is read from a beacon node.

`--hint` may be repeated. `recover` takes the first hint that hashes to the recovered `lc`, preferring one that names a store file, and reports it as `hint`; a hint that does not fit is skipped. If none fits, the gate fails, and `just recover` then recovers the lc-only record.

The prover needs the full store, not only its roots. A beacon node gives it only as a light-client bootstrap, so each preimage entry also names a published store file, `lc_stores/<head>.json`. `sg16-bridge-host run` writes it beside each artifact, and `sg16-bridge-host store <inputs.cbor>` writes it from a proof's inputs. `recover` checks the named file's head, roots and `lc` against the recovered state, and reports it as `lc_store`. `sg16-bridge-host inputs --store <file> --lc <lc>` starts the next proof from it, after recomputing its roots from the CBOR; `sg16-bridge-host check-store <file> --lc <lc>` makes the same check alone. It needs no bootstrap. Share or publish the file for the next prover. The Humid route accepts a local store file without publication; `just broadcast` requires publication and readback before sending a signed update ([`OPERATOR.md`](../../../../OPERATOR.md)). Without an available file, the next prover rebuilds it (`just reconstruct`, [OPERATOR.md, Recovering a withheld store](../../../../OPERATOR.md#recovering-a-withheld-store)), and `assemble.py stage-recovered --instance $I --recovered <recover report> --store <rebuilt store>` writes the rebuilt file into the record under the update that reached that head.

Claims come in any order: each names its deposit with `--deposit`, and any proven deposit whose slot is unset may be paid, each exactly once. Anyone may submit a claim, because the leaf pays the deposit's own recipient and the submitter only supplies the L-BTC fee input. Two claims built from one state output compete: one confirms, and the other spends an output that is gone, so it is rebuilt from the recovered successor (where a claim of the same deposit is refused). Every claim spends the one state UTXO, so claims and updates are still serialized on Liquid.

## Limits

1. No second operator has sent a transaction from a recovered record. Several deposits in one update and adverse network conditions have local checks only.
2. Local execution and decoding under stock Simplicity 0.9 is operational evidence, not an independent audit.
3. The anchor is a weak-subjectivity checkpoint: users must accept a recent checkpoint or an equivalent trust mechanism.
4. The SP1 guest, proof setup, generator and covenant implementation need independent security review. Liquid federation trust remains inherent to Liquid testnet.
