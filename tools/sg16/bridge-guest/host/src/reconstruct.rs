//! A starting store for a Liquid state whose store file was never published.
//!
//! The Liquid state holds its head slot and lc = SHA256(LC_TAG || be64(head) || header || committee), but neither
//! preimage: `header` is the SSZ root of the finalized BeaconBlockHeader at the head slot and `committee` the root
//! of the sync committee of the head's period.  Both are public beacon-chain data, so a prover who was not given
//! the store file collects candidates for them from wherever they can be found and keeps the one pair that hashes
//! to the state's lc.  The sources are untrusted: lc binds the result, so a wrong or lying source can only make
//! the reconstruction fail, never give another store.
//!
//! Where the two preimages are found:
//!   header      the head block's BeaconBlockHeader (Beacon API /eth/v1/beacon/headers/{root}, kept by every node
//!               that holds the block); or a light-client header with that root in a bootstrap, an update or a
//!               store or inputs file.
//!   committee   the next sync committee of a light-client update attested in the period before the head's
//!               (/eth/v1/beacon/light_client/updates; Gloas recommends a 14,299-epoch block-serving window,
//!               about 64 days, but individual Beacon APIs may retain less); or the current committee of
//!               a bootstrap or of any store in the head's period, which every proof's inputs and every published
//!               store of the same period carry.
//!
//! The store is built as a light-client bootstrap builds it: that header as finalized and optimistic header, that
//! committee, no next committee, zero participation and no pending update.  Only `beacon` and the committee are
//! committed by lc.  If no source has the full light-client header (its Gloas execution block hash and branch),
//! those two fields stay zero.  lc does not commit to them and the guest takes its execution fields from the
//! finalized header after the finality update, which replaces the starting one (the guest requires new_head >
//! prev_head).  The test header_only_store_drives_the_real_update_sequence runs a real Sepolia update sequence from
//! such a store and reaches the same successor as from the full store.
//!
//! A refusal names every candidate tried, each source the beacon node did not serve (its error cut to one short
//! line), and how far the head lies behind the node's finalized slot compared with the recommended serving window,
//! so that a pruned node is told apart from a wrong state or a lagging node.

use super::{hx, parse_store, store_roots, Store};
use alloy_primitives::B256;
use anyhow::{anyhow, bail, ensure, Context, Result};
use helios_consensus_core::{
    calc_sync_period,
    consensus_spec::MainnetConsensusSpec,
    types::{BeaconBlockHeader, LightClientHeader, LightClientHeaderGloas, SyncCommittee},
};
use sg16_bridge_core::lc;
use sp1_helios_primitives::types::ProofInputs;
use std::path::Path;
use tree_hash::TreeHash;

pub type Committee = SyncCommittee<MainnetConsensusSpec>;

fn period(slot: u64) -> u64 {
    calc_sync_period::<MainnetConsensusSpec>(slot)
}

/// A header a store may start from.  `full` is a light-client header as a beacon node serves it, with its
/// execution commitment; otherwise only its BeaconBlockHeader was found, in a zeroed Gloas light-client header.
pub struct HeaderCandidate {
    pub header: LightClientHeader,
    pub full: bool,
    pub source: String,
}

pub struct CommitteeCandidate {
    pub committee: Committee,
    pub source: String,
}

/// Every candidate found, what could not be fetched (`missing`) and the beacon node's finalized slot, if it gave
/// one, for the refusal message.
#[derive(Default)]
pub struct Sources {
    pub headers: Vec<HeaderCandidate>,
    pub committees: Vec<CommitteeCandidate>,
    pub missing: Vec<String>,
    pub finalized: Option<u64>,
}

/// The longest error detail a refusal quotes per source.  Beacon APIs may answer with a whole HTML page.
const DETAIL_CHARS: usize = 200;

/// `detail` on one line, at most DETAIL_CHARS characters, with RPC URLs redacted.
fn bounded(detail: &str) -> String {
    let line = super::redact(detail)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    match line.char_indices().nth(DETAIL_CHARS) {
        Some((cut, _)) => format!("{}…", &line[..cut]),
        None => line,
    }
}

/// The Gloas block-serving window a beacon node is recommended to keep, 14,299 epochs, in slots.
const SERVING_WINDOW_SLOTS: u64 = 14_299 * 32;

/// Why a beacon node whose finalized slot is `finalized` may not serve the light-client data of `head`.
pub fn retention(head: u64, finalized: u64) -> String {
    if finalized <= head {
        return format!(
            "the beacon node's finalized slot {finalized} is not past the head {head}: it is behind or not \
             synced; use a current Sepolia beacon API"
        );
    }
    let age = finalized - head;
    let days = age as f64 * 12.0 / 86_400.0;
    if age > SERVING_WINDOW_SLOTS {
        format!(
            "head {head} is {days:.1} days behind finalized slot {finalized}, past the recommended 14,299-epoch \
             (about 64-day) serving window, so beacon nodes may have pruned its data; use an archive beacon \
             node, or --source with a published store or inputs file of period {}",
            period(head)
        )
    } else {
        format!(
            "head {head} is {days:.1} days behind finalized slot {finalized}, inside the recommended 14,299-epoch \
             (about 64-day) serving window, so this node keeps less than recommended or failed; try another \
             Sepolia beacon API"
        )
    }
}

impl Sources {
    /// Records that `what` could not be fetched, quoting at most DETAIL_CHARS characters of `detail`.
    pub fn note_missing(&mut self, what: &str, detail: &str) {
        self.missing.push(format!("{what}: {}", bounded(detail)));
    }

    pub fn add_beacon_header(&mut self, beacon: BeaconBlockHeader, source: String) {
        let header = LightClientHeader::Gloas(LightClientHeaderGloas {
            beacon,
            ..Default::default()
        });
        self.headers.push(HeaderCandidate {
            header,
            full: false,
            source,
        });
    }

    pub fn add_header(&mut self, header: &LightClientHeader, source: String) {
        self.headers.push(HeaderCandidate {
            header: header.clone(),
            full: true,
            source,
        });
    }

    pub fn add_committee(&mut self, committee: &Committee, source: String) {
        self.committees.push(CommitteeCandidate {
            committee: committee.clone(),
            source,
        });
    }

    pub fn add_store(&mut self, store: &Store, source: &str) {
        let slot = store.finalized_header.beacon().slot;
        self.add_header(
            &store.finalized_header,
            format!("{source}: finalized header"),
        );
        self.add_committee(
            &store.current_sync_committee,
            format!("{source}: current committee (period {})", period(slot)),
        );
    }

    /// The light-client data in sg16 inputs: the starting store, each update's headers and next committee, and
    /// the finality update's headers, all as the Beacon API served them to whoever built the inputs.
    pub fn add_inputs(&mut self, inputs: &ProofInputs, source: &str) {
        self.add_store(&inputs.store, &format!("{source} store"));
        for (i, u) in inputs.updates.iter().enumerate() {
            let attested = u.attested_header().beacon().slot;
            self.add_header(
                &u.attested_header(),
                format!("{source} update {i}: attested header"),
            );
            self.add_header(
                &u.finalized_header(),
                format!("{source} update {i}: finalized header"),
            );
            self.add_committee(
                u.next_sync_committee(),
                format!(
                    "{source} update {i}: next committee (attested in period {}, so period {})",
                    period(attested),
                    period(attested) + 1
                ),
            );
        }
        self.add_header(
            &inputs.finality_update.attested_header(),
            format!("{source} finality update: attested header"),
        );
        self.add_header(
            &inputs.finality_update.finalized_header(),
            format!("{source} finality update: finalized header"),
        );
    }

    /// A store file (JSON, checked by `parse_store`) or sg16 inputs (CBOR).  A file that is neither is refused:
    /// a source given by name must contribute, or the caller has the wrong file.
    pub fn add_file(&mut self, path: &Path) -> Result<()> {
        let name = path.display().to_string();
        let bytes = std::fs::read(path).with_context(|| format!("source {name}: read"))?;
        if let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            let (store, _) =
                parse_store(&doc).with_context(|| format!("source {name}: store file"))?;
            self.add_store(&store, &name);
        } else {
            let inputs: ProofInputs = serde_cbor::from_slice(&bytes).with_context(|| {
                format!("source {name}: neither a store file (JSON) nor sg16 inputs (CBOR)")
            })?;
            self.add_inputs(&inputs, &name);
        }
        Ok(())
    }
}

/// The BeaconBlockHeader in a /eth/v1/beacon/headers/{root} response, once it is canonical, at `head` and hashes
/// to `root`, the block root the node gave for that slot.
pub fn header_from_api(v: &serde_json::Value, root: B256, head: u64) -> Result<BeaconBlockHeader> {
    let data = &v["data"];
    ensure!(
        data["canonical"] == serde_json::Value::Bool(true),
        "the header of block {root} is not canonical"
    );
    let header: BeaconBlockHeader = serde_json::from_value(data["header"]["message"].clone())
        .context("data.header.message: a BeaconBlockHeader")?;
    ensure!(
        header.slot == head,
        "block {root} is at slot {}, not the head slot {head}",
        header.slot
    );
    let computed = header.tree_hash_root();
    ensure!(
        computed == root,
        "the served header hashes to {computed}, not the block root {root} served for slot {head}"
    );
    Ok(header)
}

pub struct Reconstructed {
    pub store: Store,
    pub header: B256,
    pub committee: B256,
    pub header_source: String,
    pub committee_source: String,
    pub full_header: bool,
}

/// The store at `head` whose lc is `state_lc`, from the first header candidate at `head` and committee candidate
/// that hash to it (full light-client headers tried first, so a match keeps its execution commitment).  Refuses,
/// listing every candidate, when a preimage is missing or no pair hashes to `state_lc`.
pub fn reconstruct(head: u64, state_lc: [u8; 32], sources: &Sources) -> Result<Reconstructed> {
    let p = period(head);
    let mut missing = String::new();
    if !sources.missing.is_empty() {
        missing += &format!("\nnot available: {}", sources.missing.join("; "));
    }
    if let Some(finalized) = sources.finalized {
        missing += &format!("\nretention: {}", retention(head, finalized));
    }
    let mut headers: Vec<&HeaderCandidate> = sources
        .headers
        .iter()
        .filter(|h| h.header.beacon().slot == head)
        .collect();
    headers.sort_by_key(|h| !h.full);
    let mut committees: Vec<(B256, &CommitteeCandidate)> = vec![];
    for c in &sources.committees {
        let root = c.committee.tree_hash_root();
        if !committees.iter().any(|(r, _)| *r == root) {
            committees.push((root, c));
        }
    }
    ensure!(
        !headers.is_empty(),
        "missing data: no beacon block header at slot {head} in any source; fetch it from a beacon node \
         (SEPOLIA_CONSENSUS_RPC, /eth/v1/beacon/headers) or pass --source with a file holding it{missing}"
    );
    ensure!(
        !committees.is_empty(),
        "missing data: no sync committee in any source; the head's period {p} committee is the next committee of a \
         period {} light-client update or the current committee of any store in period {p}{missing}",
        p.saturating_sub(1)
    );
    for h in &headers {
        let header = h.header.beacon().tree_hash_root();
        for (committee, c) in &committees {
            if lc(head, &header.0, &committee.0) != state_lc {
                continue;
            }
            let mut store = Store::default();
            store.finalized_header = h.header.clone();
            store.optimistic_header = h.header.clone();
            store.current_sync_committee = c.committee.clone();
            store.next_sync_committee = None;
            let (slot, hr, cr) = store_roots(&store);
            ensure!(
                lc(slot, &hr.0, &cr.0) == state_lc,
                "internal: the built store does not hash to the matched lc"
            );
            return Ok(Reconstructed {
                store,
                header,
                committee: *committee,
                header_source: h.source.clone(),
                committee_source: c.source.clone(),
                full_header: h.full,
            });
        }
    }
    let list_h = headers
        .iter()
        .map(|h| format!("  {} ({})", h.header.beacon().tree_hash_root(), h.source))
        .collect::<Vec<_>>()
        .join("\n");
    let list_c = committees
        .iter()
        .map(|(r, c)| format!("  {r} ({})", c.source))
        .collect::<Vec<_>>()
        .join("\n");
    bail!(
        "refused: no header and committee from the sources hash to the Liquid state's lc {} at head {head}, so \
         nothing is written.\nheaders at slot {head}:\n{list_h}\ncommittees:\n{list_c}{missing}\nCheck --head and --lc \
         against the live state (sg16-testnet recover), and give a source with the period {p} committee: the period \
         {} light-client update, or a store or inputs file from period {p}.",
        hx(&state_lc),
        p.saturating_sub(1)
    )
}

/// Adds what a beacon node serves for `head`: its light-client bootstrap (often pruned), the head block's
/// BeaconBlockHeader and the light-client updates of the period before the head's, and its finalized slot, which
/// tells how old the head is.  What fails is recorded in `sources.missing`, not returned, so that the other
/// sources still count.  Error text never carries the URL.
pub async fn fetch(consensus: &str, head: u64, sources: &mut Sources) -> Result<()> {
    use helios_ethereum::rpc::ConsensusRpc;
    let mut client =
        super::client_without_bootstrap(consensus, sg16_bridge_core::SEPOLIA_CHAIN_ID)?;
    // HttpRpc serves every spec, and only the slot is read here, so name the spec.
    match ConsensusRpc::<MainnetConsensusSpec>::get_finality_update(&client.rpc).await {
        Ok(u) => sources.finalized = Some(u.finalized_header().beacon().slot),
        Err(e) => sources.note_missing("light-client finality update", &e.to_string()),
    }
    match sp1_helios_script::get_checkpoint_root(consensus, head).await {
        Ok(root) => {
            match client.bootstrap(root).await {
                Ok(()) => sources.add_store(
                    &client.store,
                    &format!("light-client bootstrap at block {root}"),
                ),
                Err(e) => sources.note_missing(
                    &format!("light-client bootstrap at block {root}"),
                    &e.to_string(),
                ),
            }
            match get_json(consensus, &format!("eth/v1/beacon/headers/{root}"))
                .await
                .and_then(|v| header_from_api(&v, root, head))
            {
                Ok(beacon) => {
                    sources.add_beacon_header(beacon, format!("beacon node header of block {root}"))
                }
                Err(e) => sources.note_missing(
                    &format!("beacon node header of block {root}"),
                    &format!("{e:#}"),
                ),
            }
        }
        Err(e) => sources.note_missing(&format!("block root at slot {head}"), &e.to_string()),
    }
    let p = period(head);
    if p > 0 {
        match client.rpc.get_updates(p - 1, 1).await {
            Ok(updates) if updates.is_empty() => sources.missing.push(format!(
                "light-client update of period {}: none served",
                p - 1
            )),
            Ok(updates) => {
                for u in &updates {
                    let attested = u.attested_header().beacon().slot;
                    let source =
                        format!("beacon node light-client update attested at slot {attested}");
                    sources
                        .add_header(&u.finalized_header(), format!("{source}: finalized header"));
                    sources.add_committee(
                        u.next_sync_committee(),
                        format!("{source}: next committee (period {})", period(attested) + 1),
                    );
                }
            }
            Err(e) => sources.note_missing(
                &format!("light-client update of period {}", p - 1),
                &e.to_string(),
            ),
        }
    }
    Ok(())
}

async fn get_json(consensus: &str, path: &str) -> Result<serde_json::Value> {
    let quiet = |e: reqwest::Error| anyhow!("{}", e.without_url());
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(quiet)?
        .get(format!("{}/{path}", consensus.trim_end_matches('/')))
        .send()
        .await
        .map_err(quiet)?
        .error_for_status()
        .map_err(quiet)?
        .json()
        .await
        .map_err(quiet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        anchor_of, load_store_for, reconstruct_file, store_doc, successor_store, write_store,
        RECONSTRUCTED_ABOUT, STORE_ABOUT,
    };

    /// Public Sepolia inputs between finalized slots 11385472 and 11388896, unedited, as `sg16-bridge-host inputs`
    /// writes them: the starting store at 11385472, two sync-committee updates that cross from period 1389 into
    /// 1390, and a finality update that reaches 11388896.  Everything in it is what a Beacon API serves.
    const INPUTS: &[u8] = include_bytes!("../tests/fixtures/inputs-11385472-11388896.cbor");

    /// The finalized slots of the fixture's starting store and of the store its updates reach.
    const START: u64 = 11385472;
    const SUCCESSOR: u64 = 11388896;

    fn inputs() -> ProofInputs {
        serde_cbor::from_slice(INPUTS).unwrap()
    }

    /// A store's head slot, the head's BeaconBlockHeader, the header and committee roots and their lc, all
    /// computed from the fixture with the functions the guest uses.
    struct Head {
        slot: u64,
        beacon: BeaconBlockHeader,
        header: B256,
        committee: B256,
        lc: [u8; 32],
    }

    fn head_of(store: &Store) -> Head {
        let (slot, header, committee) = store_roots(store);
        Head {
            slot,
            beacon: store.finalized_header.beacon().clone(),
            header,
            committee,
            lc: lc(slot, &header.0, &committee.0),
        }
    }

    /// The fixture's starting store.
    fn start() -> Head {
        head_of(&inputs().store)
    }

    /// The store the fixture's updates reach: a state whose store a prover rebuilds when it was not published.
    fn successor() -> Head {
        head_of(&successor_store(&inputs()).unwrap())
    }

    /// The /eth/v1/beacon/headers/{root} response for `beacon`, as a beacon node formats it.
    fn api_response(beacon: &BeaconBlockHeader, canonical: bool) -> serde_json::Value {
        serde_json::json!({"data": {
            "root": format!("{}", beacon.tree_hash_root()),
            "canonical": canonical,
            "header": {"message": serde_json::to_value(beacon).unwrap(), "signature": format!("0x{}", "00".repeat(96))},
        }})
    }

    /// The head's header as the Beacon API serves it: only its BeaconBlockHeader, without the light-client
    /// header's execution commitment.
    fn served_beacon(h: &Head) -> BeaconBlockHeader {
        header_from_api(&api_response(&h.beacon, true), h.header, h.slot).unwrap()
    }

    fn refusal(r: Result<Reconstructed>) -> String {
        match r {
            Ok(r) => panic!(
                "expected a refusal, got a store from {} and {}",
                r.header_source, r.committee_source
            ),
            Err(e) => format!("{e:#}"),
        }
    }

    /// An unpublished store rebuilt for the fixture's successor: the head block's header (Beacon API) and the next
    /// committee of the period 1389 light-client update give exactly the successor store's roots, so its lc.
    #[test]
    fn successor_from_its_beacon_header_and_the_previous_period_update() {
        let next = successor();
        assert_eq!(next.slot, SUCCESSOR);
        let mut sources = Sources::default();
        sources.add_inputs(&inputs(), "fixture");
        // The fixture's light-client headers include the successor's; keep only its served BeaconBlockHeader.
        sources.headers.clear();
        sources.add_beacon_header(served_beacon(&next), "beacon node header".into());
        let r = reconstruct(next.slot, next.lc, &sources).unwrap();
        assert!(!r.full_header);
        assert!(
            r.committee_source
                .contains("next committee (attested in period 1389, so period 1390)"),
            "{}",
            r.committee_source
        );
        assert_eq!((r.header, r.committee), (next.header, next.committee));
        // The file `reconstruct` writes passes the same check `inputs --store F --lc <lc>` makes.
        let doc = store_doc(&r.store, RECONSTRUCTED_ABOUT).unwrap();
        let (back, file_lc) = parse_store(&doc).unwrap();
        assert_eq!(file_lc, next.lc);
        assert_eq!(store_roots(&back), (next.slot, r.header, r.committee));
    }

    /// A header-only store (zero execution commitment and counters), its committee from a separate source,
    /// starts the fixture's real update sequence (sync-committee signatures across a period boundary) and
    /// reaches the same successor as the full store.
    #[test]
    fn header_only_store_drives_the_real_update_sequence() {
        let original = inputs();
        let first = start();
        assert_eq!(first.slot, START);
        let mut sources = Sources::default();
        sources.add_beacon_header(first.beacon.clone(), "beacon node header".into());
        sources.add_committee(
            &original.store.current_sync_committee,
            "period 1389 committee".into(),
        );
        let r = reconstruct(first.slot, first.lc, &sources).unwrap();
        assert!(!r.full_header);
        assert_eq!(r.committee_source, "period 1389 committee");
        assert_ne!(
            r.store.finalized_header, original.store.finalized_header,
            "the execution commitment was not recovered"
        );

        let mut replaced = inputs();
        replaced.store = r.store;
        assert_eq!(anchor_of(&replaced).unwrap().lc, first.lc);
        let (a, b) = (
            successor_store(&original).unwrap(),
            successor_store(&replaced).unwrap(),
        );
        assert_eq!(store_roots(&a), store_roots(&b));
        assert_eq!(store_roots(&b).0, SUCCESSOR);
    }

    /// When a source has the full light-client header, the store keeps it, execution commitment included.
    #[test]
    fn a_full_header_is_preferred() {
        let original = inputs();
        let first = start();
        let mut sources = Sources::default();
        sources.add_beacon_header(first.beacon.clone(), "beacon node header".into());
        sources.add_inputs(&original, "fixture");
        let r = reconstruct(first.slot, first.lc, &sources).unwrap();
        assert!(r.full_header);
        assert_eq!(r.header_source, "fixture store: finalized header");
        assert_eq!(r.store.finalized_header, original.store.finalized_header);
    }

    #[test]
    fn refuses_tampered_lc_header_and_committee() {
        let fixture = inputs();
        let next = successor();
        let honest = || {
            let mut s = Sources::default();
            s.add_beacon_header(served_beacon(&next), "beacon node header".into());
            s.add_inputs(&fixture, "fixture");
            s
        };
        // Another lc: the right preimages are all present, but nothing hashes to it.
        let mut other = next.lc;
        other[31] ^= 1;
        let e = refusal(reconstruct(next.slot, other, &honest()));
        assert!(
            e.contains("refused: no header and committee") && e.contains(&hex::encode(next.header)),
            "{e}"
        );
        assert!(
            e.contains(&hex::encode(next.committee)),
            "the refusal lists the committees tried: {e}"
        );

        // A committee with two members swapped (still valid keys) instead of the real one.
        let real = reconstruct(next.slot, next.lc, &honest()).unwrap();
        let mut v = serde_json::to_value(&real.store.current_sync_committee).unwrap();
        v["pubkeys"].as_array_mut().unwrap().swap(0, 1);
        let swapped: Committee = serde_json::from_value(v).unwrap();
        let mut s = Sources::default();
        s.add_beacon_header(served_beacon(&next), "beacon node header".into());
        s.add_committee(&swapped, "tampered".into());
        let e = refusal(reconstruct(next.slot, next.lc, &s));
        assert!(e.contains("refused") && e.contains("(tampered)"), "{e}");

        // A header with another proposer index, with the real committee.
        let mut v = serde_json::to_value(served_beacon(&next)).unwrap();
        let proposer: u64 = v["proposer_index"].as_str().unwrap().parse().unwrap();
        v["proposer_index"] = (proposer + 1).to_string().into();
        let forged: BeaconBlockHeader = serde_json::from_value(v).unwrap();
        let mut s = Sources::default();
        s.add_beacon_header(forged.clone(), "tampered header".into());
        s.add_committee(&real.store.current_sync_committee, "real committee".into());
        assert!(refusal(reconstruct(next.slot, next.lc, &s)).contains("refused"));

        // The same forged header served by a beacon node under the real block root, and other bad responses.
        let mut response = api_response(&next.beacon, true);
        response["data"]["header"]["message"] = serde_json::to_value(&forged).unwrap();
        let e = format!(
            "{:#}",
            header_from_api(&response, real.header, next.slot).unwrap_err()
        );
        assert!(e.contains("not the block root"), "{e}");
        let e = format!(
            "{:#}",
            header_from_api(&api_response(&next.beacon, false), real.header, next.slot)
                .unwrap_err()
        );
        assert!(e.contains("not canonical"), "{e}");
        let e = format!(
            "{:#}",
            header_from_api(
                &api_response(&next.beacon, true),
                real.header,
                next.slot + 32
            )
            .unwrap_err()
        );
        assert!(e.contains("not the head slot"), "{e}");
    }

    #[test]
    fn refuses_tampered_or_unknown_source_files() {
        let dir = std::env::temp_dir().join(format!("sg16-reconstruct-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut doc = store_doc(&inputs().store, STORE_ABOUT).unwrap();
        doc["lc"] = format!("0x{}", hex::encode([0u8; 32])).into();
        let tampered = dir.join("tampered.json");
        std::fs::write(&tampered, serde_json::to_vec(&doc).unwrap()).unwrap();
        let e = format!("{:#}", Sources::default().add_file(&tampered).unwrap_err());
        assert!(
            e.contains("tampered.json") && e.contains("not the hash of its head"),
            "{e}"
        );
        let junk = dir.join("junk.bin");
        std::fs::write(&junk, [0xffu8, 0x00, 0x01]).unwrap();
        let e = format!("{:#}", Sources::default().add_file(&junk).unwrap_err());
        assert!(e.contains("neither a store file"), "{e}");
        let e = format!(
            "{:#}",
            Sources::default()
                .add_file(&dir.join("absent.json"))
                .unwrap_err()
        );
        assert!(e.contains("absent.json: read"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_missing_data() {
        let fixture = inputs();
        let next = successor();
        let no_header = format!("no beacon block header at slot {SUCCESSOR}");
        let e = refusal(reconstruct(next.slot, next.lc, &Sources::default()));
        assert!(e.contains(&format!("missing data: {no_header}")), "{e}");

        // The committee is there (the fixture's updates) but not the head's header; what failed is reported.
        let mut s = Sources::default();
        for u in &fixture.updates {
            s.add_committee(u.next_sync_committee(), "update".into());
        }
        s.missing
            .push("beacon node header of block 0x…: 404 Not Found".into());
        let e = refusal(reconstruct(next.slot, next.lc, &s));
        assert!(
            e.contains(&no_header) && e.contains("not available: beacon node header"),
            "{e}"
        );

        let mut s = Sources::default();
        s.add_beacon_header(served_beacon(&next), "beacon node header".into());
        let e = refusal(reconstruct(next.slot, next.lc, &s));
        assert!(
            e.contains("missing data: no sync committee")
                && e.contains("period 1389 light-client update"),
            "{e}"
        );

        // Only the period 1389 committee, as when the update that rotates to 1390 has been pruned: refused, and
        // the message names the period whose committee is missing.
        let mut s = Sources::default();
        s.add_beacon_header(served_beacon(&next), "beacon node header".into());
        s.add_store(&fixture.store, "fixture");
        let e = refusal(reconstruct(next.slot, next.lc, &s));
        assert!(
            e.contains("refused")
                && e.contains("current committee (period 1389)")
                && e.contains("the period 1390 committee"),
            "{e}"
        );
    }

    /// The withheld-store round trip on real Sepolia data.  Prover A proves the fixture's update sequence and
    /// broadcasts the update to its successor, but never publishes the successor store.  Prover B starts from an
    /// empty work directory and public data only: the live Liquid state (head and lc, which `recover` reads from
    /// A's update witness), A's published starting store, and what a beacon node serves, the head block's header
    /// and the period 1389 light-client update.  B's store passes the check `inputs --store` makes against the
    /// live lc before any proof input is built, and has A's roots.  (header_only_store_drives_the_real_update_
    /// sequence shows that such a store drives a real update sequence.)  Without the period 1389 update, as on a
    /// pruned node, B is refused, writes nothing, and is told why.
    #[test]
    fn an_independent_prover_recovers_a_withheld_store() {
        let fixture = inputs();
        let withheld = successor_store(&fixture).unwrap();
        let live = head_of(&withheld);
        assert_eq!(live.slot, SUCCESSOR);

        let dir = std::env::temp_dir().join(format!("sg16-withheld-{}", std::process::id()));
        let (record, work) = (dir.join("lc_stores"), dir.join("work"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&record).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        let published = record.join(format!("{START}.json"));
        write_store(&published, &fixture.store, STORE_ABOUT).unwrap();
        assert!(std::fs::read_dir(&work).unwrap().next().is_none());

        let public = |served_update: bool| {
            let mut s = Sources::default();
            s.add_file(&published).unwrap();
            s.add_beacon_header(
                served_beacon(&live),
                "beacon node header of the head block".into(),
            );
            if served_update {
                let attested_1389 = fixture
                    .updates
                    .iter()
                    .filter(|u| period(u.attested_header().beacon().slot) + 1 == period(live.slot))
                    .collect::<Vec<_>>();
                assert!(
                    !attested_1389.is_empty(),
                    "the fixture holds the period 1389 update"
                );
                for u in attested_1389 {
                    s.add_committee(
                        u.next_sync_committee(),
                        "beacon node light-client update of period 1389: next committee".into(),
                    );
                }
            } else {
                s.note_missing(
                    "light-client update of period 1389",
                    &format!(
                        "HTTP status client error (404 Not Found)\n<html>{}</html>",
                        "x".repeat(4000)
                    ),
                );
            }
            s.finalized = Some(live.slot + 2 * SERVING_WINDOW_SLOTS);
            s
        };

        let out = work.join("reconstructed.store.json");
        let (r, doc) = reconstruct_file(live.slot, live.lc, &public(true), &out).unwrap();
        assert!(!r.full_header);
        assert!(
            r.committee_source.contains("period 1389"),
            "{}",
            r.committee_source
        );
        assert_eq!(doc["lc"], hx(&live.lc));
        let store = load_store_for(&out, live.lc).unwrap();
        assert_eq!(store_roots(&store), store_roots(&withheld));
        let mut other = live.lc;
        other[31] ^= 1;
        let e = format!("{:#}", load_store_for(&out, other).err().expect("refused"));
        assert!(e.contains("not the Liquid state's"), "{e}");

        let none = work.join("pruned.store.json");
        let e = format!(
            "{:#}",
            reconstruct_file(live.slot, live.lc, &public(false), &none)
                .err()
                .expect("refused")
        );
        assert!(!none.exists(), "a refusal writes no store");
        assert!(
            e.contains("refused")
                && e.contains("current committee (period 1389)")
                && e.contains("the period 1390 committee"),
            "{e}"
        );
        assert!(
            e.contains(
                "light-client update of period 1389: HTTP status client error (404 Not Found)"
            ),
            "{e}"
        );
        assert!(e.contains("past the recommended 14,299-epoch"), "{e}");
        assert!(
            e.len() < 2000,
            "the node's page is not quoted whole: {} bytes",
            e.len()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn diagnostics_are_bounded_and_place_the_head_in_the_serving_window() {
        let mut s = Sources::default();
        s.note_missing(
            "source",
            &format!("line one\n  line two {}", "é".repeat(500)),
        );
        let m = &s.missing[0];
        assert!(m.starts_with("source: line one line two é"), "{m}");
        assert!(m.ends_with('…'), "{m}");
        assert_eq!(m.chars().count(), "source: ".len() + DETAIL_CHARS + 1);
        s.note_missing("short", "404 Not Found");
        assert_eq!(s.missing[1], "short: 404 Not Found");

        let head = SUCCESSOR;
        assert!(retention(head, head).contains("not past the head"));
        let day = retention(head, head + 7200);
        assert!(
            day.contains("1.0 days behind") && day.contains("inside the recommended"),
            "{day}"
        );
        let old = retention(head, head + SERVING_WINDOW_SLOTS + 1);
        assert!(
            old.contains("past the recommended") && old.contains("period 1390"),
            "{old}"
        );
    }
}
