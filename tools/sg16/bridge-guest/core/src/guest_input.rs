//! The guest's stdin (feature `guest-input`): `ProofInputs` in an encoding the guest decodes once.
//!
//! inputs.cbor, the host's file, is `ProofInputs` as serde_cbor writes it. Helios deserializes its fork-versioned
//! values (updates, finality updates, light-client headers) as untagged enums, which buffer a value and try one
//! variant after another: a Gloas update is decoded under Base and Electra before Gloas, its 512 committee keys
//! each time. And Helios writes every BLS key as a 98-character hex string. In this encoding each such value
//! names its variant (the prover already chose it, by the field names it sent; the guest verifies the value the
//! same way whatever its variant), and sync committees are their SSZ bytes. Every field moves unchanged except
//! the store's `best_valid_update`, which reaches no output and is not sent: `decode(&guest_stdin(cbor))` is the
//! `ProofInputs` of `cbor` with that field None (tests/guest_input.rs). Measured on the saved Sepolia inputs
//! (target/guest-optimization/opus/REPORT.md, candidate `input`): stdin 60,953 → 34,272 bytes and 1,870,855 fewer
//! guest cycles; 114,671 → 61,291 bytes and 8,841,187 fewer on a period transition.

use alloy_primitives::B256;
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec as Spec,
    types::{
        FinalityUpdate, FinalityUpdateBase, FinalityUpdateElectra, FinalityUpdateGloas, Forks,
        LightClientHeader, LightClientHeaderBellatrix, LightClientHeaderCapella,
        LightClientHeaderDeneb, LightClientHeaderElectra, LightClientHeaderGloas, LightClientStore,
        SyncAggregate, SyncCommittee, Update, UpdateBase, UpdateElectra, UpdateGloas,
    },
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sp1_helios_primitives::types::{ContractStorage, ProofInputs};
use ssz::{Decode, Encode};
use ssz_types::{
    typenum::{U11, U9},
    FixedVector,
};

/// The guest's stdin for inputs.cbor (`ProofInputs` as serde_cbor encodes it).
pub fn guest_stdin(inputs_cbor: &[u8]) -> Result<Vec<u8>, serde_cbor::Error> {
    let inputs: ProofInputs = serde_cbor::from_slice(inputs_cbor)?;
    serde_cbor::to_vec(&GuestInputs::from(inputs))
}

/// `ProofInputs` from the guest's stdin.
pub fn decode(stdin: &[u8]) -> Result<ProofInputs, serde_cbor::Error> {
    serde_cbor::from_slice::<GuestInputs>(stdin).map(Into::into)
}

#[derive(Serialize, Deserialize)]
struct GuestInputs {
    updates: Vec<GuestUpdate>,
    finality_update: GuestFinalityUpdate,
    expected_current_slot: u64,
    store: GuestStore,
    genesis_root: B256,
    forks: Forks,
    contract_storage: Vec<ContractStorage>,
    execution_header: Option<alloy_consensus::Header>,
}

/// A sync committee as its SSZ encoding: 512 keys and the aggregate key, 48 bytes each, exactly.
struct Committee(SyncCommittee<Spec>);

impl Serialize for Committee {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0.as_ssz_bytes())
    }
}

impl<'de> Deserialize<'de> for Committee {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = <&[u8]>::deserialize(d)?;
        SyncCommittee::from_ssz_bytes(bytes)
            .map(Committee)
            .map_err(|e| D::Error::custom(format!("sync committee SSZ: {e:?}")))
    }
}

#[derive(Serialize, Deserialize)]
enum Header {
    Bellatrix(LightClientHeaderBellatrix),
    Capella(LightClientHeaderCapella),
    Deneb(LightClientHeaderDeneb),
    Electra(LightClientHeaderElectra),
    Gloas(LightClientHeaderGloas),
}

#[derive(Serialize, Deserialize)]
struct GuestStore {
    finalized_header: Header,
    current_sync_committee: Committee,
    next_sync_committee: Option<Committee>,
    optimistic_header: Header,
    previous_max_active_participants: u64,
    current_max_active_participants: u64,
    // No best_valid_update: helios only compares and replaces it (apply_generic_update), and it reaches no output,
    // so the guest starts from None rather than decode an untagged value it would never use.
}

#[derive(Serialize, Deserialize)]
enum GuestUpdate {
    Base(UpdateBase<Spec>),
    Electra(UpdateElectra<Spec>),
    Gloas(GloasUpdate),
}

/// `UpdateGloas` with its next sync committee as SSZ.
#[derive(Serialize, Deserialize)]
struct GloasUpdate {
    attested_header: LightClientHeaderGloas,
    next_sync_committee: Committee,
    next_sync_committee_branch: FixedVector<B256, U11>,
    finalized_header: LightClientHeaderGloas,
    finality_branch: FixedVector<B256, U9>,
    sync_aggregate: SyncAggregate<Spec>,
    signature_slot: u64,
}

#[derive(Serialize, Deserialize)]
enum GuestFinalityUpdate {
    Base(FinalityUpdateBase<Spec>),
    Electra(FinalityUpdateElectra<Spec>),
    Gloas(FinalityUpdateGloas<Spec>),
}

impl From<ProofInputs> for GuestInputs {
    fn from(i: ProofInputs) -> Self {
        let ProofInputs {
            updates,
            finality_update,
            expected_current_slot,
            store,
            genesis_root,
            forks,
            contract_storage,
            execution_header,
        } = i;
        GuestInputs {
            updates: updates.into_iter().map(Into::into).collect(),
            finality_update: finality_update.into(),
            expected_current_slot,
            store: store.into(),
            genesis_root,
            forks,
            contract_storage,
            execution_header,
        }
    }
}

impl From<GuestInputs> for ProofInputs {
    fn from(i: GuestInputs) -> Self {
        let GuestInputs {
            updates,
            finality_update,
            expected_current_slot,
            store,
            genesis_root,
            forks,
            contract_storage,
            execution_header,
        } = i;
        ProofInputs {
            updates: updates.into_iter().map(Into::into).collect(),
            finality_update: finality_update.into(),
            expected_current_slot,
            store: store.into(),
            genesis_root,
            forks,
            contract_storage,
            execution_header,
        }
    }
}

impl From<LightClientHeader> for Header {
    fn from(h: LightClientHeader) -> Self {
        match h {
            LightClientHeader::Bellatrix(h) => Header::Bellatrix(h),
            LightClientHeader::Capella(h) => Header::Capella(h),
            LightClientHeader::Deneb(h) => Header::Deneb(h),
            LightClientHeader::Electra(h) => Header::Electra(h),
            LightClientHeader::Gloas(h) => Header::Gloas(h),
        }
    }
}

impl From<Header> for LightClientHeader {
    fn from(h: Header) -> Self {
        match h {
            Header::Bellatrix(h) => LightClientHeader::Bellatrix(h),
            Header::Capella(h) => LightClientHeader::Capella(h),
            Header::Deneb(h) => LightClientHeader::Deneb(h),
            Header::Electra(h) => LightClientHeader::Electra(h),
            Header::Gloas(h) => LightClientHeader::Gloas(h),
        }
    }
}

impl From<LightClientStore<Spec>> for GuestStore {
    fn from(s: LightClientStore<Spec>) -> Self {
        let LightClientStore {
            finalized_header,
            current_sync_committee,
            next_sync_committee,
            optimistic_header,
            previous_max_active_participants,
            current_max_active_participants,
            best_valid_update: _,
        } = s;
        GuestStore {
            finalized_header: finalized_header.into(),
            current_sync_committee: Committee(current_sync_committee),
            next_sync_committee: next_sync_committee.map(Committee),
            optimistic_header: optimistic_header.into(),
            previous_max_active_participants,
            current_max_active_participants,
        }
    }
}

impl From<GuestStore> for LightClientStore<Spec> {
    fn from(s: GuestStore) -> Self {
        let GuestStore {
            finalized_header,
            current_sync_committee,
            next_sync_committee,
            optimistic_header,
            previous_max_active_participants,
            current_max_active_participants,
        } = s;
        LightClientStore {
            finalized_header: finalized_header.into(),
            current_sync_committee: current_sync_committee.0,
            next_sync_committee: next_sync_committee.map(|c| c.0),
            optimistic_header: optimistic_header.into(),
            previous_max_active_participants,
            current_max_active_participants,
            best_valid_update: None,
        }
    }
}

impl From<Update<Spec>> for GuestUpdate {
    fn from(u: Update<Spec>) -> Self {
        match u {
            Update::Base(u) => GuestUpdate::Base(u),
            Update::Electra(u) => GuestUpdate::Electra(u),
            Update::Gloas(UpdateGloas {
                attested_header_gloas,
                next_sync_committee,
                next_sync_committee_branch,
                finalized_header_gloas,
                finality_branch,
                sync_aggregate,
                signature_slot,
            }) => GuestUpdate::Gloas(GloasUpdate {
                attested_header: attested_header_gloas,
                next_sync_committee: Committee(next_sync_committee),
                next_sync_committee_branch,
                finalized_header: finalized_header_gloas,
                finality_branch,
                sync_aggregate,
                signature_slot,
            }),
        }
    }
}

impl From<GuestUpdate> for Update<Spec> {
    fn from(u: GuestUpdate) -> Self {
        match u {
            GuestUpdate::Base(u) => Update::Base(u),
            GuestUpdate::Electra(u) => Update::Electra(u),
            GuestUpdate::Gloas(GloasUpdate {
                attested_header,
                next_sync_committee,
                next_sync_committee_branch,
                finalized_header,
                finality_branch,
                sync_aggregate,
                signature_slot,
            }) => Update::Gloas(UpdateGloas {
                attested_header_gloas: attested_header,
                next_sync_committee: next_sync_committee.0,
                next_sync_committee_branch,
                finalized_header_gloas: finalized_header,
                finality_branch,
                sync_aggregate,
                signature_slot,
            }),
        }
    }
}

impl From<FinalityUpdate<Spec>> for GuestFinalityUpdate {
    fn from(u: FinalityUpdate<Spec>) -> Self {
        match u {
            FinalityUpdate::Base(u) => GuestFinalityUpdate::Base(u),
            FinalityUpdate::Electra(u) => GuestFinalityUpdate::Electra(u),
            FinalityUpdate::Gloas(u) => GuestFinalityUpdate::Gloas(u),
        }
    }
}

impl From<GuestFinalityUpdate> for FinalityUpdate<Spec> {
    fn from(u: GuestFinalityUpdate) -> Self {
        match u {
            GuestFinalityUpdate::Base(u) => FinalityUpdate::Base(u),
            GuestFinalityUpdate::Electra(u) => FinalityUpdate::Electra(u),
            GuestFinalityUpdate::Gloas(u) => FinalityUpdate::Gloas(u),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_is_exactly_its_ssz_bytes() {
        let committee = SyncCommittee::<Spec>::default();
        let bytes = serde_cbor::to_vec(&Committee(committee.clone())).unwrap();
        let back: Committee = serde_cbor::from_slice(&bytes).unwrap();
        assert!(back.0 == committee);
        let ssz = committee.as_ssz_bytes();
        assert_eq!(ssz.len(), 513 * 48);
        for len in [ssz.len() - 1, ssz.len() + 1, 0] {
            let mut wrong = ssz.clone();
            wrong.resize(len, 0);
            let cbor = serde_cbor::to_vec(&serde_cbor::Value::Bytes(wrong)).unwrap();
            assert!(
                serde_cbor::from_slice::<Committee>(&cbor).is_err(),
                "{len} bytes"
            );
        }
        // Hex text, the inputs.cbor form, is not accepted here.
        let text = serde_cbor::to_vec(&serde_cbor::Value::Text("0x00".into())).unwrap();
        assert!(serde_cbor::from_slice::<Committee>(&text).is_err());
    }
}
