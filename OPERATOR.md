# Operating a live instance

The interface is built from `ui/` into a static page: it holds no key and runs no prover. Sepolia transactions require the user's Ethereum wallet; Liquid transactions sent through the page require Humid's approval. GitHub Pages serves that build with the instance record it names (`.github/workflows/pages.yml`). An instance of `contracts/solidity/contracts/BridgeEscrow.sol` also needs the operator work below. None of it can run in a browser or on Pages. None of it can take funds: the escrow and the Liquid covenants check every value an operator supplies. What the operator holds is liveness. Deposits are minted on Liquid only when someone proves and claims them, and deposits stay open only while someone refreshes the fork check and the light client.

The instance is `instances/sepolia-liquid-testnet/`: one escrow on Sepolia, one confirmed bootstrap on Liquid testnet, linked by their asset ID. Its record holds the deployment parameters and public state needed by the page and the recipes below.

## Services

| Service | Chain it writes | When | Tools | Without it |
|---|---|---|---|---|
| Fork check | Sepolia: `checkFork` | Within every `MAX_FORK_CHECK_AGE` (10 minutes to 6 hours, set at deployment) while deposits should be open | `tools/liquid-relay/fork_proof.py build --escrow $ESCROW`, then `cast send` | Deposits pause. Anyone can send a proof, and the page's deposit form takes one pasted in, but building it needs a beacon node and an execution RPC |
| Pre-fork deposit close | Sepolia: `endDepositsBefore` | If an unsupported Sepolia fork is announced before this instance's deposit end, while there is still time to close by `FORK_MARGIN` | The immutable `DEPOSIT_CLOSER` key sends the announced activation time | Deposits admitted near that fork may become unclaimable; only this key can close early. `cast call $ESCROW 'DEPOSIT_CLOSER()(address)'` names it; it needs SepETH for gas before it can act, and nothing here funds it |
| Header relay | Sepolia: `submitHeaders` | At least once per `MAX_RELAY_LAG` to keep deposits open, and soon after each DynaFed epoch boundary (assumption L3, `contracts/README.md`) | `tools/liquid-relay/relay.py batches`, then `cast send` per batch | Deposits close. Redemptions still work: the page relays the blocks a burn needs from the user's wallet |
| Prover and Liquid update | Liquid: update of the state UTXO | After the Sepolia block holding a deposit is finalized. Each proof crosses every sync-committee period since the last one, so long gaps make larger proofs and need older light-client updates (below) | `sg16-bridge-host inputs --store instances/<name>/lc_stores/<head>.json --lc <state lc>` and `run --prove` (SP1 6.8.1, Docker for Groth16), `assemble.py check-artifact` and `update`, `liquid-testnet-wallet sign`, then Esplora `POST /tx` | Deposits stay in the escrow and are not minted on Liquid. Nothing refunds them; a later update covering them mints them |
| Claims | Liquid: claim of a proven, unclaimed deposit | Once an update proves that deposit; claims may be made in any order ([Claiming a deposit](#claiming-a-deposit)) | `assemble.py claim --deposit <index>` with the escrow's `Deposit` events, `liquid-testnet-wallet sign`, then Esplora `POST /tx` | That deposit's recipient is not paid until someone claims it |
| Light-client store | none: a reviewed commit and Pages publication | **Before broadcasting each update** | `run` writes the successor store beside its artifact (`<artifact>.store.json`). Copy it to `instances/<name>/lc_stores/<new head>.json`. Append the head, header and committee from the update's `*.new_state.json` to `lc_preimages.json`, with `"update"`, the signed update's txid, and `"store": "lc_stores/<new head>.json"`. Publish both, read back the served files, then broadcast that update | Liquid exposes only the hash of the store. Without the file, the next prover runs `just reconstruct`, which rebuilds the store from a public Beacon header and the previous period's light-client update and uses it only if its roots hash to the live `lc` ([Recovering a withheld store](#recovering-a-withheld-store)); a stored inputs file is another possible source. If all such sources are gone, the next update stalls |
| Completion check | none | Before a fork outside the pin activates | `cast call $ESCROW 'accumulator()(bytes32)'` against the last update's state record | Deposits admitted shortly before an unannounced fork may never be claimable (contract notes) |

The page never needs a server of its own. It reads Sepolia through the user's wallet, or through a Sepolia JSON-RPC the user sets in Settings, and Liquid through Esplora (Blockstream's public API by default, also changeable in Settings).

## What the operator needs

- A Sepolia execution RPC and a beacon node, passed as `SEPOLIA_EXECUTION_RPC` and `SEPOLIA_CONSENSUS_RPC`. Keep authenticated RPC URLs in a local protected secret store, never Git. `fork_proof.py` needs only standard beacon API endpoints: the light-client finality update, the genesis, and the fork of a recent state (`/eth/v1/beacon/states/{id}/fork`); it reads no debug state. `sg16-bridge-host inputs --store` needs execution proofs, the current finality update and the light-client update of every sync-committee period (about 27 hours each) since the slot the Liquid state last proved. It needs no bootstrap. Under the Gloas block-serving formula the recommended window is 14,299 epochs, about 64 days at 12-second slots; individual Beacon APIs may retain less. If the state falls further behind than available updates, an archive is needed.
- A Sepolia key with SepETH for gas, in an encrypted keystore that `cast` reads. Keep both keystore and RPC credentials outside Git. Build and test the escrow with `FOUNDRY_PROFILE=deploy` from `contracts/solidity/`; its optimizer settings are fixed in `contracts/solidity/foundry.toml`. Sepolia's gas schedule can change, so estimate each call against Sepolia itself rather than a local EVM.
- A Liquid testnet key file for fee inputs: `tools/sg16/liquid-testnet-wallet new <file>` writes it with mode 0600. Keep it under the ignored `target/` or outside the repository. The recipes reserve 12,000 sats for an update and 2,000 for a claim (`FEE_UPDATE_SATS`, `FEE_CLAIM_SATS`); the builders refuse a fee input above 100 times the relay floor.
- The prover host: SP1 6.8.1, Docker, and the guest ELF whose SHA-256 and vkey are the instance file's `GUEST_ELF_SHA256` and `PROGRAM_VKEY` ([build](tools/sg16/README.md); `sg16-bridge-host vkey --elf` prints both).
- The instance's files: its `instances/<name>/` directory (instance file, manifest, initial state, bootstrap, light-client preimages and store files). It also needs the record of the current state. `assemble.py recover` rebuilds that record from the public bootstrap, update and claim transactions ([recovery](tools/sg16/bridge-guest/testnet/README.md#recovering-the-state)). `assemble.py update` also writes its successor beside its transaction.

## Deploying the instance

Deployment is an operator step: the recipes below check and prepare each part, and only the operator, at a prompt, sends. In order:

1. Build the guest ELF in Docker (`just prover check-elf`) and record its SHA-256 and vkey (`sg16-bridge-host vkey --elf`). These go in `instance.json` and are folded into the update leaf.
2. Deploy `BridgeEscrow.sol` with `FOUNDRY_PROFILE=deploy` and its constructor arguments (`contracts/README.md`). Record its address, runtime code hash, deployment block and `DOMAIN()`. The justfile's `deploy` group does this: `just deploy-asset`, `deploy-checkpoint` and `deploy-params` write the arguments; `DEPLOYER=<address> just deploy-simulate` runs the deployment script against `SEPOLIA_EXECUTION_RPC` from that address's current nonce and sends nothing; `just deploy-escrow` sends the one transaction. It takes the deployer's encrypted key one of two ways:

   ```sh
   DEPLOYER=0x… DEPLOY_ACCOUNT=<name> just deploy-escrow                 # a keystore `cast wallet list` shows; cast asks for its password
   DEPLOYER=0x… DEPLOY_KEYSTORE=target/keystore/<file> \
     DEPLOY_PASSWORD_FILE=target/keystore/<password file> just deploy-escrow   # a keystore file and a file holding its password
   ```

   Keep the keystore and password file outside Git, under the ignored `target/` or outside the repository; the recipe refuses a file Git would track, and a password file other users can read (`chmod 600`). Only cast and forge read the password, from the file; no recipe prints it or puts it on a command line. `deploy-simulate` keeps a copy of the parameter file it simulated (`simulation.params.json`) only once the simulated transaction's gas limit has at least 15% headroom over Sepolia's live `eth_estimateGas`. Before its prompt, `deploy-escrow` requires the key to be `DEPLOYER`'s (`cast wallet address`), the RPC to be Sepolia's, `escrow-params.json` to be that copy byte for byte, and `DEPLOYER`'s next contract address to be the simulated escrow; it repeats the gas comparison. After the prompt it checks the parameters and the next address again, and that the Liquid asset funding output exists and is unspent (Esplora reports a never-seen output as unspent, so the output's existence is checked first). After sending, it requires the receipt to name the simulated escrow and code, and the sent transaction to carry the simulated input and gas limit: the light client's checkpoint and the deposit end are storage, which the code hash does not cover. `just deploy-record` then takes the deployment block from Sepolia's receipt of the deployment transaction, requires that block to be finalized, and reads `lcTipHash()`, `lcTipHeight()`, `signblockscriptHash()` and `depositsEnd()` at that block. It refuses the record unless they are the parameter file's, with `lcTipHash()` the byte reversal of the block hash `deploy-checkpoint` displayed. Reading at the deployment block lets header batches be relayed before the record is written. `SEPOLIA_EXECUTION_RPC` must therefore serve state at that block, which means an archive node once the block is older than the provider's recent-state window; without that state the recipe refuses. It also reads the escrow now. The code hash must still be the simulated one, `lcTipHeight()` must be at or above the checkpoint, and `depositsEnd()` must be at or before the parameter file's. It prints the current tip, and any earlier deposit end. A transaction in the deployment block itself that relays headers or moves the deposit end makes the recipe refuse; it never makes it accept.
3. Record the Sepolia configuration the guest commits to (`sg16-bridge-host inputs` prints it) as `SEPOLIA_CONFIG` in `tools/sg16/bridge-guest/testnet/pins.py`. Run `just deploy-anchor <finalized epoch-boundary slot>` to obtain and check the weak-subjectivity anchor, then `just deploy-record` to write `instance.json`, the starting light-client store, and its `lc_preimages.json` entry. The recipes refuse existing public files.
4. Build the manifest and the bootstrap with `assemble.py`, check the bootstrap with `just txid`, and broadcast it. Its asset ID is the escrow's `BRIDGE_ASSET`.
5. The first proof starts from the store named by the instance's initial state: `sg16-bridge-host inputs --store instances/sepolia-liquid-testnet/lc_stores/<initial head>.json --lc <initial_state.json lc> --escrow <instance.json ESCROW> --out <inputs.cbor>`. The host recomputes the store's roots and commitment before accepting it. Publish the starting store that `just deploy-record` wrote with the instance. Some beacon nodes cannot supply an arbitrary-slot bootstrap later. Publish every successor store before its update is broadcast.
6. Before publishing, check the guest binding from the checkout being released: `just prover check-elf` reproduces `GUEST_ELF_SHA256` and `PROGRAM_VKEY`; `assemble.py verify-bootstrap` recomputes the update leaf's CMR from its program text with that vkey, the escrow and `SEPOLIA_CONFIG`; and the first real proof passes `assemble.py check-artifact`, whose public values must name the escrow. Any change to a guest tag in `vectors/protocol.json` invalidates all three and needs a new instance.
7. In one reviewed commit, set `bridge-core/config.js` `INSTANCE` to the record (`name: 'sepolia-liquid-testnet'`, escrow, code hash, bootstrap txid and state address), and pin the live head and `lc` in `bridge-core/test/live-state.js`. `npm --prefix ui test` then checks every pin against the record before Pages publishes it.

## Limits to state plainly

- Updates and claims are open to anyone in the covenant. Each one spends the Liquid state UTXO and needs that state's fields: the light-client commitment `lc`, the deposit accumulator and the root of the claimed-deposit tree. A replacement operator reads them back from the public chain with `assemble.py recover`. The tool walks from the bootstrap through every public update and claim, reconstructs the claimed indices and checks their root, and accepts each successor only if its output commits to the reconstructed state. That is enough to claim every proven, unclaimed deposit in any order. An update also needs the light-client store behind `lc`: the finalized beacon header and the full sync committee at the head. Liquid holds only the hash of their roots. They are public Beacon data. `sg16-bridge-host reconstruct --state <recovered state.json> --out <store.json>` collects a header at that slot and the prior period's committee from a light-client update, or from `--source <inputs.cbor|store.json>`, and writes a store only if the pair hashes to the state's `lc`. An arbitrary-slot bootstrap is another possible source, but many nodes do not serve one.
- **What is durable.** The store itself is published, beside its preimage. `instances/<name>/lc_stores/<head>.json` holds the head, the two roots, `lc` and the store's CBOR. `sg16-bridge-host run` writes it for every proof, and `sg16-bridge-host store <inputs.cbor>` writes it from a proof's inputs without RPC. A replacement operator runs `sg16-bridge-host inputs --store <file> --lc <recovered lc>`. The host recomputes the roots from the CBOR and refuses the file unless they hash to the `lc` read from Liquid. The rest of the input is current data: later light-client updates, the finality update and the escrow proof. `recover --hint lc_preimages.json` names the store file for the recovered head. The file needs no trust beyond that hash check: a wrong store cannot give the spent state's `lc`, so its proof cannot spend the state.
- **Ordering, an operator duty and not a covenant rule.** The store at the new head must be committed, pass the Pages checkout and staged-artifact gates, be served by Pages and read back before the update that reaches that head is broadcast. Until then, `lc_preimages.json` lists that store after the live head's, and the page's trust copy calls it pending. After the update confirms, move the reviewed live-head and `lc` pin in `bridge-core/test/live-state.js` to that head, make the trust copy call that store live, and publish again. The gates check the files and the pinned value; they do not query Liquid to discover the live head. Without the pre-broadcast store, a live state can exist whose next proof depends on retained Beacon data or an archived proof-input file.
- **What remains assumed.**
  - The covenant cannot enforce that ordering, and anyone may submit an update. If an update is broadcast without its store file (by another submitter, or by an operator who stops between broadcast and publication), the next proof can reconstruct the store from a matching public Beacon header and the prior period's light-client update while they remain available; a bootstrap or archived inputs file is another source. Anyone holding that update's inputs file can instead write the store with `sg16-bridge-host store`, since the file is public data checked by `lc`.
  - A consensus RPC must serve the light-client updates since the head and a current finality update, and an execution RPC must serve `eth_getProof` at the finalized block. None of these is a bootstrap. Gloas recommends a 14,299-epoch block-serving window (about 64 days), but an API may provide less.
  - If neither a published store nor a matching header-and-committee pair can be recovered from public Beacon data or archived inputs, deposits after that head stay in the escrow. A bootstrap is one source, but not the only one.
- Each claim pays exactly the script its deposit committed to. `liquid-testnet-wallet burn` derives the bare 72-byte burn, the only form the escrow redeems.
- The immutable deposit closer is whatever `DEPOSIT_CLOSER()` names. It cannot send `endDepositsBefore` without SepETH for gas, and publishing or operating the static page does not fund or automate it. The deposit window ends at the escrow's `depositsEnd()` even if nobody uses the closer.
- A user who finds deposits paused can reopen them only with a fork proof someone built: the page checks and sends a pasted proof, but cannot build one.
- Proving needs an SP1 toolchain and minutes of CPU per update. There is no shared prover; each operator proves for itself.
- The page serves exactly one instance: `bridge-core/config.js` `INSTANCE`. Its value is checked against the instance record before publication; the page refuses an escrow whose code hash is not the record's. Neither links nor Settings can point it elsewhere.

## Taking over a stalled deposit

Anyone can finish a finalized deposit that nobody has claimed. You can start as soon as Ethereum finality is visible. The covenant's update and claim leaves accept a spend from anyone, check the proof, and pay only the deposit's own script, so whoever runs these steps pays the Liquid fees and gains nothing else. The page cannot do this for you. Proving needs an SP1 toolchain and minutes to hours of CPU, and the fee input needs a Liquid key. Nothing below runs in a browser or on Pages. Use only a clone of this repository and public services. The page's deposit card offers a guide button as soon as it sees an unclaimed deposit final on Ethereum.

The commands are the operator's own, with the file names changed.

### What you need

- A clone of this repository at `main`. Run `python3 tools/bootstrap-deps.py` once to fetch the pinned vendored dependencies.
- Rust with Cargo, Python 3.9 or later, Node.js 22 or later, `curl`, and `just` (the recipes were checked with 1.45.0).
- A Sepolia execution RPC that serves `eth_getLogs`, `eth_call`, and, for a proof, `eth_getProof` at the finalized block. Keep RPC URLs with credentials out of Git and out of shared shell history.
- **For a proof only:** a Sepolia beacon node (consensus RPC), Docker, and the SP1 6.8.1 toolchain (`cargo prove --version` must report 6.8.1). No minimum machine is established.
- tL-BTC for fees, in a key only you hold: about 12,000 sats per update and 2,000 sats per claim, plus 300 sats for each fee split below. Any Liquid testnet faucet that pays an unconfidential address will do.

### The same steps with `just`

The root `justfile` wraps steps 1 to 5 and Broadcasting, writing under `target/takeover/` (`BRIDGE_WORK`). It reads the escrow and deployment block from `BRIDGE_INSTANCE` (default `instances/sepolia-liquid-testnet`, the instance the published site serves). `just config` prints the settings in effect without printing RPC URLs, and `just --dry-run <recipe>` prints a recipe without running it. The groups in `just --list` say what each recipe may touch. RPC URLs reach the tools only through the environment, never their command lines. `just recover` needs no Sepolia RPC; `status`, `deposits`, `claim` and `claim-unsigned` need `SEPOLIA_EXECUTION_RPC`. `deposits` automatically reduces its `eth_getLogs` range when an RPC reports a smaller limit, including Alchemy's 10-block free-tier limit; it retries rate limits with backoff, keeps completed ranges, and replaces the deposit list only after the full scan passes its count check. Set `DEPOSIT_LOG_PACE` above its 250 ms default if the provider keeps throttling. Every transaction the recipes fetch from Esplora or sign is hashed locally (`tools/liquid-relay/liquid.py`) and refused unless it is the expected txid. Only `broadcast` sends anything. It runs `preflight` first, then asks for confirmation; `just preflight <file>` runs the same checks without sending. Preflight checks the recipe's transaction sidecar and exact txid, that Esplora does not know it yet, that its parents are confirmed, and that the state and fee outputs it spends remain unspent. The `update` and `claim` recipes verify their signed transactions before writing sidecars; the sidecar itself is a local file, not an authentication mechanism. For an update, preflight also checks that its store and `lc_preimages.json` entry are staged and byte-identical at `STORE_READBACK_URL`. This URL must use HTTPS. A user-supplied URL readback does not prove the files will remain public: publish them at a durable, discoverable location before sending an update. `stage-store` writes those two files into the working tree; committing and publishing them is yours to do. Before it writes anything, it checks offline that the update, its new state, the proof and the store all belong to `BRIDGE_INSTANCE`. The instance and its manifest must pass `assemble.py`'s own gates. The proof's public values must name the instance's escrow and the new state's head, `lc`, accumulator and execution block. The new state must recompute its hashes. The update must spend its sidecar's state output and recreate this instance's state output for that new state. The store must match the new state. The Groth16 pairing check is left to `update` and `update-unsigned`, which run it before writing an update.

Every recipe that walks the Liquid state, and `just config`, first prints a `target:` line with its directory and escrow, and whether the published site serves it. Served means all of `bridge-core/config.js` `INSTANCE`, not just its escrow: `BRIDGE_INSTANCE` is the record directory `instances/<name>` itself, and its escrow, escrow code hash, bootstrap txid and manifest state address are the ones the page pins. A copy of that record elsewhere is not served, even with the same escrow, and the line names every difference. A deposit belongs to the escrow it was sent to, the To address of its Sepolia transaction; a deposit to another escrow does not appear here.

```sh
export SEPOLIA_EXECUTION_RPC=... SEPOLIA_CONSENSUS_RPC=...   # read by the tools; no recipe prints them
export LIQUID_FEE_KEY=target/takeover/fee.key
just deps tools && just fee-key-new        # once; fund the printed address
just status                                # recover, read final deposits, print the next step
just status <deposit number>               # the same, focused on this deposit
# If deposits are unproven:
just prover check-elf                      # once
just reconstruct                           # only if status says no store is published for the live head
just inputs execute prove                  # prove asks before it starts
just split update <funding txid> <vout>    # each split prints its txid; its change is output 1
just broadcast target/takeover/fee-update.hex && just wait <split txid>
just update stage-store                    # then publish both staged files
STORE_READBACK_URL=<public URL of the instance directory> just broadcast target/takeover/update.signed.hex
# Claim any proven, unclaimed deposit; another claim must wait for this state spend to confirm:
just split claim <txid of your last split, or the funding> <vout>
just broadcast target/takeover/fee-claim.hex && just wait <split txid>
just claim <deposit number> && just broadcast target/takeover/claim.signed.hex
```

To have Humid pay for and send the **update**, run `just deps tools`, `just prover check-elf`, then `just inputs execute prove` as above. This route does not need `LIQUID_FEE_KEY` or `just fee-key-new` for the update. In Humid, send 12,000 sats of tL-BTC to its own Receive → Unconfidential address and wait for that open coin to confirm. Identify its transaction ID and output number on a Liquid testnet explorer. Then use that coin instead of the fee-key split and signing steps above:

```sh
just update-unsigned <Humid fee txid> <output number>  # checks the proof and builds target/takeover/update.hex
just txid target/takeover/update.hex                   # the ID does not change when Humid signs
just stage-store unsigned                              # stages the store under that ID; sends nothing
```

Publish the staged `lc_stores/<head>.json` and `lc_preimages.json` in this site's instance record, and read them back before opening the published site's **Send a proven update with Humid** panel. Load `target/takeover/update.hex` there. The page checks its leaf, published store, and unspent inputs, then asks Humid to sign **only input 1**, the fee coin, and broadcast. This requires a maintainer to publish the state files at the site's fixed record path; anyone can build and send a covenant-valid update, but this particular page withholds its Humid action until those files are published here. The local `just broadcast` recipe is for an already signed transaction and refuses `update.hex`. A claim can go through Humid as well (below); the fee-key route for claims needs `just fee-key-new`.

To have Humid pay for and send a **claim** of a proven deposit, no prover or fee key is needed: `just deps tools` and `SEPOLIA_EXECUTION_RPC` are enough. Run `just status <deposit number>` first: it says whether that deposit is proven and unclaimed. Other deposits do not have to be claimed first. In Humid, send tL-BTC to its own Receive → Unconfidential address and wait for that open coin to confirm. About 2,000 sats is enough; use a fee appropriate at submission time, no more than this page's 50,000-sat limit. The claim spends the whole fee coin. Identify its transaction ID and output number on a Liquid testnet explorer, then:

```sh
just claim-unsigned <Humid fee txid> <output number> <deposit number>  # builds target/takeover/claim.hex
just txid target/takeover/claim.hex                    # the ID does not change when Humid signs
```

Open the site's **Claim a proven deposit with Humid** panel and load `target/takeover/claim.hex`. This route exists only for the instance the published site serves: `update-unsigned` and `claim-unsigned` refuse any other `BRIDGE_INSTANCE` before reading the network. Nothing has to be published first: a claim moves no light-client store. The page checks the claim against the served record's `manifest.json`: the claim leaf, bridge asset and entropy, token in both phases, reissued units paid openly to a standard script, and its whole fee coin as the fee, at most 50,000 sats. It also checks that Liquid does not know the claim and its state and fee outputs are confirmed and unspent. It then asks Humid to sign **only input 1**, the fee coin, and broadcast, and requires Humid's txid to be the claim's. `just broadcast` refuses `claim.hex`. After it confirms, run `just status <deposit number>` again.

Use an execution RPC that serves and verifies the finalized block's `eth_getProof`: some public providers are stale, outside their proof window, or return a proof with the wrong state root. When no store is published for the live head, `just inputs` refuses and names `just reconstruct` (next section).

### Recovering a withheld store

Anyone may broadcast an update, and the covenant cannot require its store to be published first. If the update that reached the live head published none, the next prover rebuilds that store from public data. Use a fresh work directory; nothing here needs the first operator's files.

```sh
export BRIDGE_WORK=target/recovery                # empty: everything below comes from public data
just host          # build the prover host for reconstruction; Docker and cargo-prove are not needed yet
just status        # store: none published for head <H>, which update <txid> reached without publishing one
just reconstruct   # rebuild, check against the live lc, complete the state record; writes only under BRIDGE_WORK
just inputs execute prove                         # then the normal path: split, update, stage-store, broadcast
just stage-recovered                              # optional: stage the rebuilt store into the instance record
```

- **Discovery.** `just status` walks the Liquid state from the bootstrap and reads the live head and `lc` from the last update's witness. It says when no store at that head is published, and names the update that reached it.
- **Recovery.** `just reconstruct` asks `SEPOLIA_CONSENSUS_RPC` for the head block's header and the light-client update of the period before the head's. It also reads the instance's published stores, which carry the committee of their own periods, and any store or inputs file you name: `just reconstruct <file>...`. Without `SEPOLIA_CONSENSUS_RPC` it uses those files alone. The beacon node and the files are untrusted: only a header and committee whose roots hash to the live `lc` give a store.
- **Verification.** The store is written to `$BRIDGE_WORK/reconstructed.store.json` only after it matches. `sg16-bridge-host check-store` then recomputes its roots from its CBOR and compares them with the `lc` read from Liquid, and `recover` completes the state record with it. The recipe prints `recovered:` only after all three checks pass. `inputs` checks the store against the live `lc` again, and `execute` and `prove` start only on inputs anchored at the live head and `lc`.
- **Continuation.** Prove, update, `stage-store` and broadcast as usual. Your update's successor store is published before it is broadcast, so the next prover does not repeat this. `just stage-recovered` writes the rebuilt store into `instances/<name>/lc_stores/<head>.json` and `lc_preimages.json`, under the update that reached the head, in head order. Publish it with the record, so that later provers need neither the Beacon data nor your work directory.
- **When the data is gone.** If no source holds the head's committee, `reconstruct` refuses and writes nothing. The refusal lists the candidates tried, what the beacon node did not serve (each error cut to one line), and how far the head lies behind the node's finalized slot compared with the recommended 14,299-epoch (about 64-day) window. Inside the window, try another beacon API. Past it, you need an archive beacon node or an archived store or inputs file of that sync-committee period. Until one is found, deposits after that head cannot be proven. Claims of deposits the live state already proves still work: they need only `lc`.

### Claiming a deposit

The claim leaf can mint any proven deposit whose index is unset in the state's claimed tree (`contracts/simplicity/simf/claim.simf`). It proves the selected deposit's accumulator branch, proves that its claimed slot was unset, then sets that slot in the successor state. A second claim of the same index cannot pass. Claims still spend one state output, so two claims built against the same state compete; after one confirms, build the other again from the new state. Each claim pays its own deposit's committed script, whoever sends it, and costs the sender only the Liquid fee, about 2,000 sats. `just status <n>` reports whether deposit `n` is final, proven, claimed or claimable. The escrow accepts only standard script forms and amounts within its bounds (`BridgeDeposits.recipientOf`).

### 1. Build the tools and a fee key

```sh
python3 tools/bootstrap-deps.py
cargo build --release --manifest-path tools/sg16-harness/Cargo.toml
CARGO_TARGET_DIR=tools/sg16/bridge-guest/target/testnet-tx cargo build --release --manifest-path tools/sg16/bridge-guest/testnet/tx/Cargo.toml
CARGO_TARGET_DIR=tools/sg16/bridge-guest/target/testnet-claim cargo build --release --manifest-path tools/sg16/bridge-guest/testnet/claim/Cargo.toml
cargo build --release --manifest-path tools/sg16/liquid-testnet-wallet/Cargo.toml
assemble() { python3 tools/sg16/bridge-guest/testnet/assemble.py "$@"; }
TX=tools/sg16/bridge-guest/target/testnet-tx/release/sg16-testnet
W=tools/sg16/liquid-testnet-wallet/target/release/sg16-liquid-testnet-wallet
I=instances/sepolia-liquid-testnet
E=https://blockstream.info/liquidtestnet/api
ESCROW=$(python3 -c 'import json; print(json.load(open("'$I'/instance.json"))["ESCROW"])')
mkdir -p target/takeover
$W new target/takeover/fee.key      # mode 0600; prints the unconfidential address to fund
```

Fund that address with tL-BTC, then save the funding transaction: `curl -fsS $E/tx/<funding txid>/hex > target/takeover/funding.hex`.

### 2. Recover the live state

This follows the state output from the bootstrap through every public update and claim:

```sh
t=$(just txid $I/bootstrap.hex); spends=()
curl -fsS $E/tx/$t/hex | cmp - $I/bootstrap.hex
while next=$(curl -fsS $E/tx/$t/outspend/0 | python3 -c 'import json,sys; o=json.load(sys.stdin); print(o["txid"] if o.get("spent") else "")') && [ -n "$next" ]; do
  curl -fsS $E/tx/$next/hex > target/takeover/$next.hex; spends+=(--spend target/takeover/$next.hex); t=$next
done
ST=target/takeover/$t.hex; [ -f "$ST" ] || ST=$I/bootstrap.hex       # the transaction holding the live state, output 0
hint=(); [ -f $I/lc_preimages.json ] && hint=(--hint $I/lc_preimages.json)   # absent until the first update publishes a store
assemble recover --instance $I/instance.json --manifest $I/manifest.json --bootstrap-tx $I/bootstrap.hex \
  "${spends[@]}" "${hint[@]}" --out target/takeover/state.json > target/takeover/recover.json
```

Until the first update, the loop finds no spend, `$ST` is the bootstrap, and the record is the anchor with nothing claimed.

`lc_preimages.json` can list stores past the live head: an operator publishes each one before broadcasting its update, so the update may be signed but not yet broadcast or confirmed. `recover` uses only the entry at the head it recovers from Liquid, so `STORE` in step 4 is the live head's store. If such a pending update confirms before yours, yours is rejected (see Broadcasting). If the last spend is still unconfirmed, wait for it and run this step again. `recover` exits with status 3 and names a gate if anything does not fit. If that gate is "a hint is the preimage of the recovered lc", the latest update's preimage was never published. You can still claim: run `recover` again without `--hint`. For an update, see the last point of step 4.

### 3. Check whether your deposit is already proven

```sh
python3 -c 'import json; s=json.load(open("target/takeover/state.json")); print("claimed:", s["claimed"], "proven through Sepolia block:", s.get("exec_block"))'
```

The page's Activity row shows your deposit's block and its number. If the proven block is at or after your deposit's block, a proof already covers it, and only claims are left: skip to step 5. No prover is needed.

### 4. Prove and update

```sh
R=$PWD
(cd tools/sg16/bridge-guest/program && cargo prove build --docker --tag v6.8.1 --locked --workspace-directory ../../../.. --output-directory "$R/target/takeover/elf")
cargo build --release --locked --manifest-path tools/sg16/bridge-guest/Cargo.toml -p sg16-bridge-host
H=tools/sg16/bridge-guest/target/release/sg16-bridge-host
ELF=target/takeover/elf/sg16-bridge-program
$H vkey --elf $ELF          # must print instance.json's GUEST_ELF_SHA256 and PROGRAM_VKEY
STORE=$(python3 -c 'import json; print(json.load(open("target/takeover/recover.json"))["result"]["lc_store"] or "")')
LC=$(python3 -c 'import json; print(json.load(open("target/takeover/state.json"))["lc"])')
SEPOLIA_CONSENSUS_RPC=... SEPOLIA_EXECUTION_RPC=... $H inputs --store "$STORE" --lc $LC --escrow $ESCROW --out target/takeover/inputs.cbor
$H run --elf $ELF target/takeover/inputs.cbor target/takeover/proof.json --prove     # also writes target/takeover/proof.store.json
assemble check-artifact --instance $I/instance.json --artifact target/takeover/proof.json --state target/takeover/state.json
$W split target/takeover/fee.key target/takeover/funding.hex <funding vout> 12000 300 target/takeover/fee-update.hex
```

Broadcast the split (below), wait for it to confirm, then build, sign and check the update:

```sh
assemble update --instance $I/instance.json --manifest $I/manifest.json --artifact target/takeover/proof.json \
  --state target/takeover/state.json --state-tx $ST --fee-tx target/takeover/fee-update.hex --fee-vout 0 --out target/takeover/update.hex
$W sign target/takeover/fee.key target/takeover/update.hex 1 target/takeover/fee-update.hex 0 target/takeover/update.signed.hex
$TX verify target/takeover/update.signed.hex 0 $ST target/takeover/fee-update.hex
```

- **Publish the new store before you broadcast the update.** Its head is in `target/takeover/update.new_state.json`. Copy `proof.store.json` to `$I/lc_stores/<head>.json`. Append `{"head", "header", "committee", "update", "store": "lc_stores/<head>.json"}` to `lc_preimages.json`. The current instance already has an entry for its starting store; leave that entry intact. The first three fields come from `update.new_state.json`. `update` is the txid that `sign` printed for `update.signed.hex`. Make both files public: as a pull request to this repository, and somewhere anyone can fetch them. Only the maintainers can put them on the published site. The covenant does not check this step. If you skip it, the next prover must reconstruct the store from a matching public Beacon header and committee, a bootstrap, or archived inputs while those are available.
- If step 2 found no published store for the live head, `STORE` is empty. Rebuild it: `SEPOLIA_CONSENSUS_RPC=... $H reconstruct --state target/takeover/state.json --source $I/lc_stores/<any published head>.json --out target/takeover/reconstructed.store.json` (add `--source <archived store or inputs file>` and `--offline` if the Beacon API has pruned its data). It writes the file only if the roots it finds hash to the state's `lc`. Check it with `$H check-store target/takeover/reconstructed.store.json --lc $LC`, run step 2 again with `--hint target/takeover/reconstructed.store.json` after the instance's hint so that `state.json` gets its header and committee, and set `STORE` to that file. `just reconstruct` does all of this ([Recovering a withheld store](#recovering-a-withheld-store)).

### 5. Claim a proven deposit

```sh
FROM=$(python3 -c 'import json; print(json.load(open("'$I'/instance.json"))["ESCROW_DEPLOY_BLOCK"])')
node bridge-core/cli.js deposits --escrow $ESCROW --from $FROM --out target/takeover/deposits.json   # reads SEPOLIA_EXECUTION_RPC
$W split target/takeover/fee.key <change tx.hex> <change vout> 2000 300 target/takeover/fee-claim.hex
```

A split's output 0 is the fee slot and output 1 its change. So `<change tx.hex>` is the last split you made, with vout 1: `fee-update.hex` if you made an update in step 4, otherwise the previous `fee-claim.hex`. If you have made no split yet, use `funding.hex` and its funding vout. Each split overwrites `fee-claim.hex`, so broadcast it and let it confirm before you make the next one. The command starts with 2,000-block `Deposit` event ranges and automatically reduces the range if the RPC reports a smaller limit, including Alchemy's free-tier 10-block limit. You can set `--step` explicitly to start smaller. It takes the RPC URL from `SEPOLIA_EXECUTION_RPC`; `--rpc <url>` still works, but puts the URL, with any key in it, in the process list. It refuses a list with a gap or a count other than the escrow's `depositCount()`. After the split confirms, take the state from step 2: `target/takeover/state.json`, held by `$ST`. After your own update, use `target/takeover/update.new_state.json`, held by `target/takeover/update.signed.hex`:

```sh
assemble claim --instance $I/instance.json --manifest $I/manifest.json --state <state.json> --deposits target/takeover/deposits.json \
  --state-tx <state tx.hex> --fee-tx target/takeover/fee-claim.hex --fee-vout 0 --deposit <deposit number> --out target/takeover/claim.hex
$W sign target/takeover/fee.key target/takeover/claim.hex 1 target/takeover/fee-claim.hex 0 target/takeover/claim.signed.hex
$TX verify target/takeover/claim.signed.hex 0 <state tx.hex> target/takeover/fee-claim.hex
```

The selected deposit may be any proven, unclaimed index ([Claiming a deposit](#claiming-a-deposit)). A claim writes its successor state beside the transaction. After it confirms, recover again before building another claim, because the old state output has been spent. Use a fresh fee coin for each claim.

### Broadcasting

Four files are broadcast, each only after the one it spends has confirmed:

- `target/takeover/fee-update.hex` and `target/takeover/fee-claim.hex`, the splits. `split` signs them itself, so they have no `.signed` name.
- `target/takeover/update.signed.hex` and `target/takeover/claim.signed.hex`, from `sign`. Never post `update.hex` or `claim.hex` directly: their fee input is unsigned. The website's Humid panels are the separate `update.hex` and `claim.hex` routes; Humid signs that fee input before it broadcasts. `just broadcast` refuses the unsigned file.

Before an update or a claim, check that the state output it spends is still unspent. That is output 0 of `--state-tx`: `$ST`, or your own update after it confirms. `curl -fsS $E/tx/<state txid>/outspend/0` must show `"spent":false`. Then send the file. For example, for the update:

```sh
F=target/takeover/update.signed.hex
tr -d '\n' < $F | curl -fsS -X POST --data-binary @- $E/tx; echo     # prints the txid
```

The printed txid must be the one `split` or `sign` printed for that file. `curl -fsS $E/tx/<txid>/status` shows `"confirmed":true` once it is in a block.

If someone else spends the state first, your transaction is rejected as a double spend and costs nothing. Run step 2 again: their update or claim may already cover your deposit.

## What a user needs

- A browser wallet on Sepolia with SepETH, for deposits, relaying and redemption. Optionally, a Sepolia JSON-RPC URL of their own in Settings, which the page then reads through instead of the wallet.
- A Liquid testnet wallet that shows an unconfidential `tex1…` address, to receive the claim, and that can pay the bridge asset as an explicit output to an exact script: the page's 72-byte bare `OP_RETURN` burn script, which has no address. An ordinary Send cannot make it. `tools/sg16/liquid-testnet-wallet burn` builds this form, and Elements Core would need a raw or PSET transaction.
- Humid: claim to its address under Receive, then Unconfidential (its first address, the only one where it tracks open coins). Its ordinary Send cannot redeem: pinned LWK omits an explicit claim coin from Humid's balance and Send coin selection, and a bare `OP_RETURN` script has no address to send to. Redeem step 2's "Send with Humid" instead builds the burn as a PSET (`bridge-core/lib/humid.js`): the claim from Esplora, a tL-BTC fee coin from Humid's `getUTXOs`, every input with its witness UTXO, and a confidential fee coin with its output's rangeproof. Humid's `signPset` (1.1.1 and later) blinds the tL-BTC change, shows the outputs, and signs and broadcasts in one step after the user confirms. The user needs confirmed tL-BTC received at Humid's confidential address for the fee, and approves up to three prompts: connect, share coins, sign and send. The route was built from Humid 1.1.3's released source; its unit tests check the PSET and burn layout with synthetic transactions, including the bare `OP_RETURN` as output 0. Humid 1.1.3's source shows that output with an empty address and its script in hex. Public chain data cannot identify the wallet software that signed the Liquid transaction. If Humid reports a failure after the signing prompt, the burn may still have been broadcast: check Humid's activity, the claim address on the explorer and step 3 before trying again. Step 3 of Redeem checks any attempted send. A confidential output cannot be redeemed. Other wallets are untested.
- A little tL-BTC for the burn's fee.
