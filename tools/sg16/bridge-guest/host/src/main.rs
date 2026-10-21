//! sg16-bridge-host: inputs, execution and Groth16 proofs for the sg16 bridge update guest.
//!
//!   SEPOLIA_CONSENSUS_RPC=... SEPOLIA_EXECUTION_RPC=... \
//!   sg16-bridge-host inputs (--anchor-slot <slot> | --store <store.json> --lc <0x32 bytes>) --escrow <0x address>
//!                           [--slot-key <0x32 bytes>] --out <inputs.cbor>
//!       Start from the light-client store the Liquid state's lc commits to: with --anchor-slot, a Helios bootstrap
//!       of the finalized checkpoint of <slot> from the consensus RPC; with --store, a published store file (below),
//!       refused unless it hashes to --lc, the lc recovered from Liquid.  Then fetch sync-committee updates and the
//!       latest finality update, attach the Gloas execution header if needed, and fetch the escrow's account and
//!       slot proofs at the finalized execution block.  Read-only RPC.  Sepolia is enforced: chain id 11155111 on
//!       the execution RPC, and the genesis validators root must agree between the helios network config, the
//!       consensus RPC's /eth/v1/beacon/genesis and sg16-bridge-core.  RPC URLs come only from the environment
//!       and are never printed or written.
//!
//!   sg16-bridge-host anchor <inputs.cbor>
//!       Print the anchored store (slot, header root, committee root, prev_lc), the network config hash, the
//!       finalized target and the storage requests, without executing the guest.
//!
//!   sg16-bridge-host run --elf <guest elf> <inputs.cbor> <out.json> [--prove] [--pick <contract>:<slot>]
//!                        [--allow-non-sepolia]
//!       Execute the guest (and with --prove, make and SDK-verify a Groth16 proof), decode its public values and
//!       check each field against the host's own recomputation from the inputs.  --pick keeps one contract and
//!       one slot of a multi-slot input (its account proof stays valid).  Inputs for another network are refused
//!       unless --allow-non-sepolia, and the artifact then says "not-sepolia".  Also writes the successor store
//!       file beside <out.json> as <out>.store.json: the store the next proof starts from.
//!
//!   sg16-bridge-host store <inputs.cbor> --out <store.json>
//!       The successor store file of Sepolia inputs, without executing the guest or any RPC: the inputs' updates
//!       and finality update verified and applied as the guest applies them.
//!
//! A store file is JSON: `head`, `header` (finalized beacon header root), `committee` (current sync committee
//! root), `lc` and `store_cbor`, the CBOR of the Helios store as inputs.cbor encodes it, with no next sync
//! committee (the guest drops it).  Everything in it is public beacon-chain data, and it is checked only by
//! hashing: the roots are recomputed from `store_cbor` and must give `lc`.  A beacon node serves an equivalent
//! store only as a light-client bootstrap at that checkpoint, which nodes stop serving once they prune its state;
//! share the file with the next prover or publish it as instances/<name>/lc_stores/<head>.json. The Humid route
//! accepts a local store file; just broadcast requires publication and readback before sending a signed update.
//!
//!   SEPOLIA_CONSENSUS_RPC=... \
//!   sg16-bridge-host reconstruct (--state <state.json> | --head <slot> --lc <0x32 bytes>) --out <store.json>
//!                                [--source <store.json | inputs.cbor>]... [--offline]
//!       A store file for a Liquid state whose author never published one (src/reconstruct.rs).  Takes only head
//!       and lc from the state, collects header and committee candidates from the consensus RPC (bootstrap, the
//!       head block's header, the previous period's light-client update; read-only, Sepolia enforced) and from
//!       each --source, and writes the bootstrap-shaped store of the pair that hashes to lc.  Refuses, writing
//!       nothing, when a preimage is missing or no pair matches; the refusal lists what was tried, what the beacon
//!       node did not serve, and how far the head is behind its finalized slot.  --offline uses only the --source
//!       files.  Then run `inputs --store <store.json> --lc <lc>`, which checks lc again.
//!
//!   sg16-bridge-host check-store <store.json> --lc <0x32 bytes>
//!       The check `inputs --store` makes, alone and offline: the roots recomputed from the file's CBOR must hash
//!       to --lc, the lc of the live Liquid state.  Prints the head and roots.
//!
//!   sg16-bridge-host vkey --elf <guest elf>
//!       Print the ELF's SHA-256 and the program vkey the SDK derives from it, the two values an instance file
//!       pins, without inputs or RPC.  `run` reports the same vkey.
use alloy_primitives::{Address, B256};
use anyhow::{anyhow, bail, ensure, Context, Result};
use helios_consensus_core::{
    apply_finality_update, apply_update, consensus_spec::MainnetConsensusSpec,
    types::LightClientStore, verify_finality_update, verify_update,
};
use helios_ethereum::config::{networks::Network, Config};
use helios_ethereum::consensus::Inner;
use helios_ethereum::rpc::{http_rpc::HttpRpc, ConsensusRpc};
use sg16_bridge_core::{
    config_hash, lc, UpdateOutputs, SEPOLIA_CHAIN_ID, SEPOLIA_GENESIS_VALIDATORS_ROOT,
};
use sp1_helios_primitives::types::ProofInputs;
use sp1_helios_script::execution::{fill_execution_header, ExecutionRpc};
use sp1_sdk::{Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use std::path::Path;
use std::sync::Arc;
use tree_hash::TreeHash;

mod reconstruct;

type Store = LightClientStore<MainnetConsensusSpec>;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Every value of a repeatable flag.
fn flags(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].clone())
        .collect()
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn positional(args: &[String]) -> Vec<String> {
    let takes_value = [
        "--anchor-slot",
        "--store",
        "--lc",
        "--escrow",
        "--slot-key",
        "--out",
        "--elf",
        "--pick",
        "--head",
        "--state",
        "--source",
    ];
    let mut out = vec![];
    let mut i = 0;
    while i < args.len() {
        if takes_value.contains(&args[i].as_str()) {
            i += 2;
        } else if args[i].starts_with("--") {
            i += 1;
        } else {
            out.push(args[i].clone());
            i += 1;
        }
    }
    out
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

struct Anchor {
    slot: u64,
    header: B256,
    committee: B256,
    lc: [u8; 32],
    config: [u8; 32],
}

/// The fields of a store that lc commits to: head slot, finalized beacon header root, current sync committee root.
fn store_roots(store: &Store) -> (u64, B256, B256) {
    (
        store.finalized_header.beacon().slot,
        store.finalized_header.beacon().tree_hash_root(),
        store.current_sync_committee.tree_hash_root(),
    )
}

fn anchor_of(inputs: &ProofInputs) -> Result<Anchor> {
    let (slot, header, committee) = store_roots(&inputs.store);
    let forks = serde_cbor::to_vec(&inputs.forks).context("encode forks")?;
    Ok(Anchor {
        slot,
        header,
        committee,
        lc: lc(slot, &header.0, &committee.0),
        config: config_hash(&inputs.genesis_root.0, &forks),
    })
}

/// The store after the inputs' sync-committee updates and finality update, each verified first, exactly as the
/// guest applies them: the store whose lc the proof commits as new_lc, and the next proof's starting store.  Its
/// next sync committee is dropped, as the guest drops the prover-supplied one.
fn successor_store(inputs: &ProofInputs) -> Result<Store> {
    let mut store = inputs.store.clone();
    store.next_sync_committee = None;
    for update in &inputs.updates {
        verify_update(
            update,
            inputs.expected_current_slot,
            &store,
            inputs.genesis_root,
            &inputs.forks,
        )
        .map_err(|e| anyhow!("update: {e}"))?;
        apply_update(&mut store, update);
    }
    verify_finality_update(
        &inputs.finality_update,
        inputs.expected_current_slot,
        &store,
        inputs.genesis_root,
        &inputs.forks,
    )
    .map_err(|e| anyhow!("finality update: {e}"))?;
    apply_finality_update(&mut store, &inputs.finality_update);
    store.next_sync_committee = None;
    Ok(store)
}

const STORE_ABOUT: &str =
    "Light-client store a bridge proof starts from (sg16-bridge-host inputs --store): \
    head slot, finalized beacon header root, current sync committee root, \
    lc = SHA256(LC_TAG || be64(head) || header || committee), and the store's CBOR. \
    Public beacon-chain data; use it only if lc equals the lc of the Liquid state being updated.";

const RECONSTRUCTED_ABOUT: &str = "Light-client store a bridge proof starts from (sg16-bridge-host inputs --store), \
    rebuilt by sg16-bridge-host reconstruct from public beacon-chain data because no published store was available: \
    the finalized beacon header and the sync committee whose \
    lc = SHA256(LC_TAG || be64(head) || header || committee) equals the Liquid state's, in a bootstrap-shaped store. \
    Use it only if lc equals the lc of the Liquid state being updated.";

fn store_doc(store: &Store, about: &str) -> Result<serde_json::Value> {
    let mut store = store.clone();
    store.next_sync_committee = None;
    let (head, header, committee) = store_roots(&store);
    Ok(serde_json::json!({
        "about": about,
        "head": head,
        "header": hx(&header.0),
        "committee": hx(&committee.0),
        "lc": hx(&lc(head, &header.0, &committee.0)),
        "store_cbor": hx(&serde_cbor::to_vec(&store).context("encode store")?),
    }))
}

fn word(v: &serde_json::Value, name: &str) -> Result<[u8; 32]> {
    let s = v
        .as_str()
        .with_context(|| format!("{name}: a hex string"))?;
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .with_context(|| format!("{name}: 32 bytes of hex"))
}

/// A store file's store and lc, once the head, header root and committee root recomputed from its CBOR equal the
/// file's own fields and hash to its lc.  The caller still compares lc with the Liquid state's.
fn parse_store(doc: &serde_json::Value) -> Result<(Store, [u8; 32])> {
    let cbor = hex::decode(
        doc["store_cbor"]
            .as_str()
            .context("store_cbor: a hex string")?
            .trim_start_matches("0x"),
    )
    .context("store_cbor: hex")?;
    let mut store: Store =
        serde_cbor::from_slice(&cbor).context("store_cbor: a Helios light-client store")?;
    store.next_sync_committee = None;
    let (head, header, committee) = store_roots(&store);
    ensure!(
        doc["head"].as_u64() == Some(head),
        "the store is at slot {head}, not the file's head {}",
        doc["head"]
    );
    ensure!(
        word(&doc["header"], "header")? == header.0,
        "the store's finalized header root is {header}, not the file's header"
    );
    ensure!(
        word(&doc["committee"], "committee")? == committee.0,
        "the store's sync committee root is {committee}, not the file's committee"
    );
    let lc_ = lc(head, &header.0, &committee.0);
    ensure!(
        word(&doc["lc"], "lc")? == lc_,
        "the file's lc is not the hash of its head, header and committee ({})",
        hx(&lc_)
    );
    Ok((store, lc_))
}

/// The store in the store file at `path`, once its roots recompute from its CBOR and hash to `state_lc`, the lc of
/// the Liquid state the next proof spends.  This is the only check a store file needs, published or reconstructed:
/// a store that gives the state's lc is the store that state commits to.
fn load_store_for(path: &Path, state_lc: [u8; 32]) -> Result<Store> {
    let name = path.display();
    let bytes = std::fs::read(path).with_context(|| {
        format!("read {name} (if no store was published for the Liquid state's head, rebuild one with `reconstruct`)")
    })?;
    let doc: serde_json::Value =
        serde_json::from_slice(&bytes).with_context(|| format!("store file {name}: JSON"))?;
    let (store, file_lc) = parse_store(&doc).with_context(|| format!("store file {name}"))?;
    ensure!(
        file_lc == state_lc,
        "the store file {name} hashes to lc {}, not the Liquid state's {}",
        hx(&file_lc),
        hx(&state_lc)
    );
    Ok(store)
}

/// The value of `--lc`, the lc of the Liquid state a store must give.
fn state_lc_flag(args: &[String], usage: &str) -> Result<[u8; 32]> {
    let v = flag(args, "--lc")
        .with_context(|| format!("{usage} needs --lc <the lc of the Liquid state>"))?;
    word(&serde_json::json!(v), "--lc")
}

fn write_store(path: &Path, store: &Store, about: &str) -> Result<serde_json::Value> {
    let doc = store_doc(store, about)?;
    std::fs::write(path, serde_json::to_vec_pretty(&doc)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(doc)
}

/// `sp1_helios_script::get_client` without its bootstrap: the same Sepolia network config and RPC, for a store
/// taken from a store file.
fn client_without_bootstrap(
    consensus_rpc: &str,
    chain_id: u64,
) -> Result<Inner<MainnetConsensusSpec, HttpRpc>> {
    let base = Network::from_chain_id(chain_id)
        .map_err(|_| anyhow!("no helios network for chain id {chain_id}"))?
        .to_base_config();
    let config = Config {
        consensus_rpc: consensus_rpc.parse()?,
        execution_rpc: None,
        chain: base.chain,
        forks: base.forks,
        strict_checkpoint_age: false,
        ..Default::default()
    };
    let (block_send, _) = tokio::sync::mpsc::channel(256);
    let (finalized_block_send, _) = tokio::sync::watch::channel(None);
    let (channel_send, _) = tokio::sync::watch::channel(None);
    Ok(Inner::<MainnetConsensusSpec, HttpRpc>::new(
        consensus_rpc,
        block_send,
        finalized_block_send,
        channel_send,
        Arc::new(config),
    ))
}

fn summary(inputs: &ProofInputs, a: &Anchor) -> serde_json::Value {
    serde_json::json!({
        "anchor": {"slot": a.slot, "header": hx(&a.header.0), "committee": hx(&a.committee.0), "lc": hx(&a.lc)},
        "network": {
            "genesis_validators_root": hx(&inputs.genesis_root.0),
            "is_sepolia": inputs.genesis_root.0 == SEPOLIA_GENESIS_VALIDATORS_ROOT,
            "config": hx(&a.config),
            "forks": format!("{:?}", inputs.forks),
        },
        "target_finalized_slot": inputs.finality_update.finalized_header().beacon().slot,
        "updates": inputs.updates.len(),
        "execution_header_witness": inputs.execution_header.is_some(),
        "storage": inputs.contract_storage.iter().map(|c| serde_json::json!({
            "address": format!("{:?}", c.address),
            "code_hash": format!("{:?}", c.value.code_hash),
            "slots": c.storage_slots.iter().map(|s| serde_json::json!({
                "key": format!("{:?}", s.key),
                "value": format!("{:#x}", s.value),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

async fn beacon_genesis_root(consensus_rpc: &str) -> Result<B256> {
    // reqwest errors display their URL, which may carry an API key: drop it (see also `redact`).
    let quiet =
        |e: reqwest::Error| anyhow!("consensus RPC /eth/v1/beacon/genesis: {}", e.without_url());
    let v: serde_json::Value = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(quiet)?
        .get(format!(
            "{}/eth/v1/beacon/genesis",
            consensus_rpc.trim_end_matches('/')
        ))
        .send()
        .await
        .map_err(quiet)?
        .error_for_status()
        .map_err(quiet)?
        .json()
        .await
        .map_err(quiet)?;
    v["data"]["genesis_validators_root"]
        .as_str()
        .ok_or_else(|| anyhow!("no genesis_validators_root"))?
        .parse()
        .context("genesis root")
}

/// `message` with every form of the two RPC URLs replaced by their variable names: the whole value, the value
/// without a trailing slash, and its path-and-query and query parts, where providers put API keys.  Errors from
/// the Helios, alloy and reqwest stacks below this crate may quote a URL however they format it.
fn redact(message: &str) -> String {
    let mut out = message.to_string();
    for var in ["SEPOLIA_CONSENSUS_RPC", "SEPOLIA_EXECUTION_RPC"] {
        let Ok(value) = std::env::var(var) else {
            continue;
        };
        let mut secrets = vec![value.clone(), value.trim_end_matches('/').to_string()];
        if let Ok(url) = reqwest::Url::parse(&value) {
            secrets.push(url.to_string());
            let path_and_query = format!(
                "{}{}",
                url.path(),
                url.query().map(|q| format!("?{}", q)).unwrap_or_default()
            );
            secrets.push(path_and_query);
            secrets.extend(url.query().map(str::to_string));
            secrets.extend(url.password().map(str::to_string));
        }
        // Longest first, so a value is not left half-replaced by one of its own parts.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        for s in secrets.iter().filter(|s| s.len() >= 8) {
            out = out.replace(s.as_str(), &format!("<{}>", var));
        }
    }
    out
}

async fn inputs_cmd(args: &[String]) -> Result<()> {
    let consensus = std::env::var("SEPOLIA_CONSENSUS_RPC")
        .context("set SEPOLIA_CONSENSUS_RPC (Beacon API with light-client endpoints)")?;
    let execution = std::env::var("SEPOLIA_EXECUTION_RPC")
        .context("set SEPOLIA_EXECUTION_RPC (execution RPC with eth_getProof)")?;
    let escrow: Address = flag(args, "--escrow").context("--escrow")?.parse()?;
    let slot_key: B256 = flag(args, "--slot-key")
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(B256::ZERO);
    let out = flag(args, "--out").context("--out")?;

    let (client, anchor_slot) = match (flag(args, "--anchor-slot"), flag(args, "--store")) {
        (Some(slot), None) => {
            let slot: u64 = slot.parse().context("--anchor-slot")?;
            (
                sp1_helios_script::get_client(Some(slot), &consensus, SEPOLIA_CHAIN_ID)
                    .await
                    .context("bootstrap at the anchor checkpoint")?,
                slot,
            )
        }
        (None, Some(path)) => {
            let store = load_store_for(Path::new(&path), state_lc_flag(args, "--store")?)?;
            let mut client = client_without_bootstrap(&consensus, SEPOLIA_CHAIN_ID)?;
            let slot = store.finalized_header.beacon().slot;
            client.store = store;
            (client, slot)
        }
        _ => bail!(
            "give exactly one of --anchor-slot <slot> (bootstrap from the consensus RPC) \
             and --store <store.json> --lc <lc>"
        ),
    };
    let configured = client.config.chain.genesis_root;
    let served = beacon_genesis_root(&consensus).await?;
    ensure!(
        configured.0 == SEPOLIA_GENESIS_VALIDATORS_ROOT,
        "helios network config is not Sepolia's genesis validators root: {configured}"
    );
    ensure!(
        served == configured,
        "the consensus RPC serves genesis validators root {served}, expected {configured}"
    );
    let rpc = ExecutionRpc::new(&execution)?;
    rpc.check_chain_id(SEPOLIA_CHAIN_ID).await?;

    let updates = sp1_helios_script::get_updates(&client).await?;
    let finality_update = client
        .rpc
        .get_finality_update()
        .await
        .map_err(|e| anyhow!("finality update: {e}"))?;
    let mut inputs = ProofInputs {
        updates,
        finality_update,
        expected_current_slot: client.expected_current_slot(),
        store: client.store.clone(),
        genesis_root: client.config.chain.genesis_root,
        forks: client.config.forks.clone(),
        contract_storage: vec![],
        execution_header: None,
    };
    ensure!(
        inputs.store.finalized_header.beacon().slot == anchor_slot,
        "the starting store is not at the anchor slot"
    );
    // Verifies the whole update sequence on the host first (same functions as the guest), checkpoint and advance.
    // fill_execution_header (vendor/sp1-helios/script/src/execution.rs) also refuses a finalized header that is not at
    // an epoch's first slot, as the guest does: when that slot was missed no proof can exist for this update.
    let (target, fields) = fill_execution_header(&mut inputs, &rpc)
        .await
        .context(
            "the update sequence does not verify, or its finalized header is not at an epoch's first slot \
             (then retry after the next finalized epoch)",
        )?;
    let storage = rpc
        .storage_proof(
            fields.state_root,
            fields.block_number,
            escrow,
            vec![slot_key],
        )
        .await?;
    inputs.contract_storage = vec![storage];
    std::fs::write(&out, serde_cbor::to_vec(&inputs)?)?;
    let a = anchor_of(&inputs)?;
    let mut s = summary(&inputs, &a);
    s["finalized"] = serde_json::json!({
        "slot": target,
        "execution_block_number": fields.block_number,
        "execution_state_root": hx(&fields.state_root.0),
    });
    println!("{}", serde_json::to_string_pretty(&s)?);
    Ok(())
}

fn pick(inputs: &mut ProofInputs, spec: &str) -> Result<()> {
    let (c, s) = spec
        .split_once(':')
        .context("--pick <contract index>:<slot index>")?;
    let (c, s): (usize, usize) = (c.parse()?, s.parse()?);
    ensure!(c < inputs.contract_storage.len(), "no contract {c}");
    let mut contract = inputs.contract_storage.swap_remove(c);
    ensure!(s < contract.storage_slots.len(), "no slot {s}");
    let slot = contract.storage_slots.swap_remove(s);
    contract.storage_slots = vec![slot];
    inputs.contract_storage = vec![contract];
    Ok(())
}

async fn run_cmd(args: &[String]) -> Result<()> {
    let pos = positional(args);
    ensure!(
        pos.len() == 2,
        "usage: run --elf <elf> <inputs.cbor> <out.json> [--prove] [--pick C:S] [--allow-non-sepolia]"
    );
    let elf_path = flag(args, "--elf").context("--elf <guest elf>")?;
    let mut inputs: ProofInputs =
        serde_cbor::from_slice(&std::fs::read(&pos[0])?).context("decode ProofInputs")?;
    if let Some(spec) = flag(args, "--pick") {
        pick(&mut inputs, &spec)?;
    }
    let sepolia = inputs.genesis_root.0 == SEPOLIA_GENESIS_VALIDATORS_ROOT;
    if !sepolia && !has(args, "--allow-non-sepolia") {
        bail!(
            "inputs are for genesis validators root {}, not Sepolia; \
             pass --allow-non-sepolia to execute them as a test",
            inputs.genesis_root
        );
    }
    ensure!(
        inputs.contract_storage.len() == 1 && inputs.contract_storage[0].storage_slots.len() == 1,
        "the guest needs exactly one contract and one slot (got {} contracts); use --pick",
        inputs.contract_storage.len()
    );
    let a = anchor_of(&inputs)?;
    let cbor = serde_cbor::to_vec(&inputs)?;
    let elf_bytes: &'static [u8] = Box::leak(
        std::fs::read(&elf_path)
            .context("read guest ELF")?
            .into_boxed_slice(),
    );
    let elf = Elf::Static(elf_bytes);
    sp1_sdk::utils::setup_logger();
    let client = ProverClient::builder().cpu().build().await;
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&cbor);
    let t0 = std::time::Instant::now();
    let (public_values, report) = client
        .execute(elf.clone(), stdin.clone())
        .await
        .context("guest execution failed")?;
    ensure!(
        report.exit_code == 0,
        "guest exit code {}",
        report.exit_code
    );
    let values = public_values.to_vec();
    let o = UpdateOutputs::decode(&values).map_err(|e| anyhow!("guest public values: {e}"))?;
    // Recompute everything the host can: the anchor, the network, the requested contract and slot.
    let request = &inputs.contract_storage[0];
    ensure!(o.prev_lc == a.lc, "prev_lc differs from the anchored store");
    ensure!(
        o.config == a.config,
        "config differs from the inputs' genesis root and forks"
    );
    ensure!(
        o.escrow == request.address.into_array(),
        "escrow differs from the request"
    );
    ensure!(
        o.slot_key == request.storage_slots[0].key.0,
        "slot key differs from the request"
    );
    ensure!(
        o.slot_value == request.storage_slots[0].value.to_be_bytes::<32>(),
        "slot value differs from the request"
    );
    ensure!(o.new_head > a.slot && o.new_head % 32 == 0, "new head");
    // The successor store, recomputed on the host with the same helios functions: new_lc must match.
    let store = successor_store(&inputs)?;
    let (new_slot, new_header, new_committee) = store_roots(&store);
    ensure!(
        new_slot == o.new_head && o.new_lc == lc(new_slot, &new_header.0, &new_committee.0),
        "new_lc differs from the host's successor store"
    );
    let store_path = Path::new(&pos[1]).with_extension("store.json");
    write_store(&store_path, &store, STORE_ABOUT)?;
    println!(
        "successor store (load with the update in Humid; share or publish for the next prover): {}",
        store_path.display()
    );
    let pk = client
        .setup(elf)
        .await
        .map_err(|e| anyhow!("setup failed: {e}"))?;
    let vkey = pk.verifying_key().bytes32();
    println!(
        "executed: {} cycles, head {} -> {}, block {}, vkey {vkey} ({:.1}s)",
        report.total_instruction_count(),
        a.slot,
        o.new_head,
        o.execution_block_number,
        t0.elapsed().as_secs_f64()
    );
    let mut artifact = serde_json::json!({
        "guest": "sg16-bridge-program",
        "network": if sepolia { "sepolia".to_string() } else { format!("not-sepolia: {}", inputs.genesis_root) },
        "vkey": vkey,
        "publicValues": hx(&values),
        "public_input": hx(&o.public_input()),
        "proof": "0x",
        "cycles": report.total_instruction_count(),
        "sdkVersion": "6.8.1",
        "outputs": {
            "config": hx(&o.config),
            "escrow": hx(&o.escrow),
            "slot_key": hx(&o.slot_key),
            "prev_lc": hx(&o.prev_lc),
            "new_lc": hx(&o.new_lc),
            "slot_value": hx(&o.slot_value),
            "execution_state_root": hx(&o.execution_state_root),
            "execution_block_number": o.execution_block_number,
            "new_head": o.new_head,
        },
        "successor": {"slot": new_slot, "header": hx(&new_header.0), "committee": hx(&new_committee.0)},
        "inputs": summary(&inputs, &a),
    });
    if has(args, "--prove") {
        println!("generating a Groth16 proof (local CPU prover)");
        let t1 = std::time::Instant::now();
        let proof = client
            .prove(&pk, stdin)
            .groth16()
            .await
            .map_err(|e| anyhow!("proving failed: {e}"))?;
        client.verify(&proof, pk.verifying_key(), None)?;
        ensure!(
            proof.public_values.to_vec() == values,
            "proof/executor output mismatch"
        );
        artifact["proof"] = hx(&proof.bytes()).into();
        artifact["proving_seconds"] = t1.elapsed().as_secs_f64().into();
        println!(
            "Groth16 proof verified with the SDK: {} bytes",
            proof.bytes().len()
        );
    }
    std::fs::write(&pos[1], serde_json::to_vec_pretty(&artifact)?)?;
    Ok(())
}

fn store_cmd(args: &[String]) -> Result<()> {
    let pos = positional(args);
    ensure!(
        pos.len() == 1,
        "usage: store <inputs.cbor> --out <store.json>"
    );
    let out = flag(args, "--out").context("--out <store.json>")?;
    let inputs: ProofInputs =
        serde_cbor::from_slice(&std::fs::read(&pos[0])?).context("decode ProofInputs")?;
    ensure!(
        inputs.genesis_root.0 == SEPOLIA_GENESIS_VALIDATORS_ROOT,
        "inputs are for genesis validators root {}, not Sepolia",
        inputs.genesis_root
    );
    let mut doc = write_store(Path::new(&out), &successor_store(&inputs)?, STORE_ABOUT)?;
    doc.as_object_mut()
        .expect("store_doc is an object")
        .remove("store_cbor");
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"from_anchor": anchor_of(&inputs)?.slot, "successor": doc, "out": out})
        )?
    );
    Ok(())
}

/// The Liquid state's head and lc: from `--state` (sg16-testnet recover output, whose header and committee are
/// only hints and are not read) or from `--head` and `--lc`.
fn state_head_lc(args: &[String]) -> Result<(u64, [u8; 32])> {
    match (
        flag(args, "--state"),
        flag(args, "--head"),
        flag(args, "--lc"),
    ) {
        (Some(path), None, None) => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {path}"))?;
            let doc: serde_json::Value =
                serde_json::from_slice(&bytes).with_context(|| format!("{path}: JSON"))?;
            let head = doc["head"]
                .as_u64()
                .with_context(|| format!("{path}: no head slot"))?;
            let lc = word(&doc["lc"], "lc").with_context(|| path.clone())?;
            Ok((head, lc))
        }
        (None, Some(head), Some(l)) => {
            let head = head.parse().context("--head <slot>")?;
            Ok((head, word(&serde_json::json!(l), "--lc")?))
        }
        _ => bail!(
            "give the Liquid state as --state <state.json> (sg16-testnet recover output) \
             or as --head <slot> --lc <0x32 bytes>"
        ),
    }
}

async fn reconstruct_cmd(args: &[String]) -> Result<()> {
    let out = flag(args, "--out").context("--out <store.json>")?;
    let (head, state_lc) = state_head_lc(args)?;
    let mut sources = reconstruct::Sources::default();
    for path in flags(args, "--source") {
        sources.add_file(Path::new(&path))?;
    }
    if !has(args, "--offline") {
        let consensus = std::env::var("SEPOLIA_CONSENSUS_RPC").context(
            "set SEPOLIA_CONSENSUS_RPC (Beacon API with light-client endpoints), \
                 or pass --offline to use only --source files",
        )?;
        let served = beacon_genesis_root(&consensus).await?;
        ensure!(
            served.0 == SEPOLIA_GENESIS_VALIDATORS_ROOT,
            "the consensus RPC serves genesis validators root {served}, not Sepolia's"
        );
        reconstruct::fetch(&consensus, head, &mut sources).await?;
    }
    let (r, doc) = reconstruct_file(head, state_lc, &sources, Path::new(&out))?;
    let execution = if r.full_header {
        format!("from {}", r.header_source)
    } else {
        "zero: only the BeaconBlockHeader was found; lc does not commit to it and the guest does not use it".to_string()
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "reconstructed": doc,
            "matches_state_lc": true,
            "header_root": hx(&r.header.0),
            "committee_root": hx(&r.committee.0),
            "header_source": r.header_source,
            "committee_source": r.committee_source,
            "execution_commitment": execution,
            "not_available": sources.missing,
            "out": out,
            "next": format!(
                "sg16-bridge-host inputs --store {out} --lc {} --escrow <escrow> --out <inputs.cbor>",
                hx(&state_lc)
            ),
        }))?
    );
    Ok(())
}

/// `reconstruct` after the sources are collected: the store at `head` whose lc is `state_lc`, written to `out`
/// only once it is found, so that a refusal writes nothing.  Returns the match and the file as written, without
/// its CBOR.
fn reconstruct_file(
    head: u64,
    state_lc: [u8; 32],
    sources: &reconstruct::Sources,
    out: &Path,
) -> Result<(reconstruct::Reconstructed, serde_json::Value)> {
    let r = reconstruct::reconstruct(head, state_lc, sources)?;
    let mut doc = write_store(out, &r.store, RECONSTRUCTED_ABOUT)?;
    doc.as_object_mut()
        .expect("store_doc is an object")
        .remove("store_cbor");
    Ok((r, doc))
}

fn check_store_cmd(args: &[String]) -> Result<()> {
    let pos = positional(args);
    ensure!(
        pos.len() == 1,
        "usage: check-store <store.json> --lc <0x32 bytes>"
    );
    let state_lc = state_lc_flag(args, "check-store")?;
    let store = load_store_for(Path::new(&pos[0]), state_lc)?;
    let (head, header, committee) = store_roots(&store);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "store": pos[0],
            "head": head,
            "header": hx(&header.0),
            "committee": hx(&committee.0),
            "lc": hx(&state_lc),
            "matches_state_lc": true,
        }))?
    );
    Ok(())
}

async fn vkey_cmd(args: &[String]) -> Result<()> {
    let elf_path = flag(args, "--elf").context("usage: vkey --elf <guest elf>")?;
    let bytes = std::fs::read(&elf_path).context("read guest ELF")?;
    let elf_sha256 = hex::encode(sg16_bridge_core::sha256(&bytes));
    let elf = Elf::Static(Box::leak(bytes.into_boxed_slice()));
    let client = ProverClient::builder().cpu().build().await;
    let pk = client
        .setup(elf)
        .await
        .map_err(|e| anyhow!("setup failed: {e}"))?;
    println!(
        "{}",
        serde_json::json!({ "elf_sha256": elf_sha256, "vkey": pk.verifying_key().bytes32() })
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run_command().await {
        eprintln!("Error: {}", redact(&format!("{:?}", e)));
        std::process::exit(1);
    }
}

async fn run_command() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("inputs") => inputs_cmd(&args[1..]).await,
        Some("anchor") => {
            let pos = positional(&args[1..]);
            ensure!(pos.len() == 1, "usage: anchor <inputs.cbor>");
            let inputs: ProofInputs =
                serde_cbor::from_slice(&std::fs::read(&pos[0])?).context("decode ProofInputs")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&summary(&inputs, &anchor_of(&inputs)?))?
            );
            Ok(())
        }
        Some("run") => run_cmd(&args[1..]).await,
        Some("store") => store_cmd(&args[1..]),
        Some("reconstruct") => reconstruct_cmd(&args[1..]).await,
        Some("check-store") => check_store_cmd(&args[1..]),
        Some("vkey") => vkey_cmd(&args[1..]).await,
        _ => bail!(
            "usage: sg16-bridge-host inputs|anchor|run|store|reconstruct|check-store|vkey ... \
             (see the source header)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tampered(doc: &serde_json::Value, key: &str, value: serde_json::Value) -> serde_json::Value {
        let mut d = doc.clone();
        d[key] = value;
        d
    }

    fn flip(h: &str) -> String {
        let (head, last) = h.split_at(h.len() - 1);
        format!("{head}{}", if last == "0" { "1" } else { "0" })
    }

    fn refuses(doc: &serde_json::Value, fragment: &str) {
        let e = parse_store(doc)
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(
            e.contains(fragment),
            "expected a refusal naming {fragment:?}, got {e:?}"
        );
    }

    #[test]
    fn store_file_round_trips_and_binds_every_field() {
        let mut store = Store::default();
        store.next_sync_committee = Some(store.current_sync_committee.clone());
        let doc = store_doc(&store, STORE_ABOUT).unwrap();
        let (back, lc_) = parse_store(&doc).unwrap();
        assert!(
            back.next_sync_committee.is_none(),
            "a store file carries no next sync committee"
        );
        let (head, header, committee) = store_roots(&store);
        assert_eq!(store_roots(&back), (head, header, committee));
        assert_eq!(lc_, lc(head, &header.0, &committee.0));
        assert_eq!(doc["lc"], hx(&lc_));
        refuses(
            &tampered(&doc, "head", (head + 32).into()),
            "not the file's head",
        );
        refuses(
            &tampered(&doc, "header", flip(doc["header"].as_str().unwrap()).into()),
            "not the file's header",
        );
        refuses(
            &tampered(
                &doc,
                "committee",
                flip(doc["committee"].as_str().unwrap()).into(),
            ),
            "not the file's committee",
        );
        refuses(
            &tampered(&doc, "lc", flip(doc["lc"].as_str().unwrap()).into()),
            "not the hash of its head",
        );
        refuses(
            &tampered(&doc, "store_cbor", "0x00".into()),
            "a Helios light-client store",
        );
    }

    #[test]
    fn reconstruct_reads_only_head_and_lc_of_the_state() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let lc_: &str = &"ab".repeat(32);
        let path = std::env::temp_dir().join(format!("sg16-state-{}.json", std::process::id()));
        // A recovered state whose header and committee hints are wrong: they are not read.
        std::fs::write(
            &path,
            serde_json::json!({"head": 12000000, "lc": lc_, "header": "00", "committee": "00"})
                .to_string(),
        )
        .unwrap();
        let p = path.to_str().unwrap();
        let (head, l) = state_head_lc(&args(&["--state", p, "--out", "x"])).unwrap();
        assert_eq!((head, hex::encode(l)), (12_000_000, lc_.to_string()));
        assert_eq!(
            state_head_lc(&args(&["--head", "12000000", "--lc", lc_])).unwrap(),
            (head, l)
        );
        assert!(state_head_lc(&args(&["--state", p, "--head", "1"])).is_err());
        assert!(state_head_lc(&args(&["--head", "12000000"])).is_err());
        assert!(state_head_lc(&args(&["--head", "12000000", "--lc", "0x00"])).is_err());
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            flags(
                &args(&["--source", "a", "--offline", "--source", "b"]),
                "--source"
            ),
            ["a", "b"]
        );
        assert_eq!(
            positional(&args(&[
                "--source",
                "a",
                "--head",
                "1",
                "--state",
                "s",
                "--offline"
            ])),
            Vec::<String>::new()
        );
    }
}
