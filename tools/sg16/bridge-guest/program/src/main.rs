//! sg16 bridge update guest (SP1 6.8.1).
//!
//! The verification is the stock SP1 Helios v1.3.0 `light_client` program (vendor/sp1-helios/program/src/
//! light_client.rs, commit 0dd8749f), unchanged in substance: drop the prover-supplied next sync committee
//! (GHSA-83q5-vwj7-gxww), verify and apply sync-committee updates and a finality update, require a strictly
//! newer checkpoint slot, authenticate the execution state root (Gloas: by the execution header's RLP hash) and
//! verify account and storage Merkle-Patricia proofs with sp1-helios-primitives.  The differences are what the
//! Liquid covenant needs:
//!
//!  - network binding: `config` commits the genesis validators root and the fork schedule the guest verified
//!    signatures and branches under; the covenant pins it.
//!  - exactly one contract and exactly one slot, so the proven value is unambiguous; the contract must have code.
//!    The guest pins no escrow address or code hash: the address is a public value, which the covenant pins.
//!  - fixed 272-byte public values (sg16-bridge-core) with prev_lc / new_lc, the Liquid state's light-client
//!    commitment, computed here from the anchored and the successor store.
//!
//! Three changes only cut cycles. Helios 0.12.0's consensus core is the copy in ../patches (patches/README.md):
//! a signature subgroup check that passed every point is removed (the decoder's check remains), and the
//! sync-committee root is computed directly. The input is `ProofInputs` in sg16_bridge_core::guest_input's
//! encoding: the host's inputs.cbor with each fork-versioned value tagged by its variant and the sync committees as
//! SSZ bytes, which the guest decodes once.
//!
//! Prover-controlled inputs and why they are safe:
//!   store.finalized_header, store.current_sync_committee   anchored: they define prev_lc, which the covenant
//!                                                           requires to equal the spent state's lc
//!   store.next_sync_committee                               discarded (set to None), as in the stock guest
//!   store.optimistic_header, participation counters         not read by finality verification
//!   store.best_valid_update                                 not in the guest's stdin: always None here; helios
//!                                                           only replaces it, and it reaches no output
//!   genesis_root, forks                                     committed in `config`
//!   expected_current_slot                                   only bounds signature slots from above; every update
//!                                                           must still carry valid sync-committee signatures
//!   updates, finality_update, execution_header,             verified against the anchored committee and the
//!     contract_storage                                      finalized header

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use helios_consensus_core::{
    apply_finality_update, apply_update, verify_finality_update, verify_update,
};
use sg16_bridge_core::{config_hash, lc, UpdateOutputs, KECCAK_EMPTY};
use sp1_helios_primitives::{
    execution::verified_execution_fields, types::ProofInputs, verify_storage_slot_proofs,
};
use tree_hash::TreeHash;

pub fn main() {
    let encoded_inputs = sp1_zkvm::io::read_vec();
    let ProofInputs {
        updates,
        finality_update,
        expected_current_slot,
        mut store,
        genesis_root,
        forks,
        contract_storage,
        execution_header,
    } = sg16_bridge_core::guest_input::decode(&encoded_inputs).unwrap();

    // Network: the signing domain and the fork-dependent branch layouts come from these two inputs.
    let config = config_hash(
        &genesis_root.0,
        &serde_cbor::to_vec(&forks).expect("encode forks"),
    );

    // The anchored store: only these fields are trusted, through prev_lc.
    store.next_sync_committee = None;
    let prev_committee: B256 = store.current_sync_committee.tree_hash_root();
    let prev_header: B256 = store.finalized_header.beacon().tree_hash_root();
    let prev_head = store.finalized_header.beacon().slot;

    for update in updates.iter() {
        verify_update(update, expected_current_slot, &store, genesis_root, &forks)
            .expect("Update is invalid!");
        apply_update(&mut store, update);
    }
    verify_finality_update(
        &finality_update,
        expected_current_slot,
        &store,
        genesis_root,
        &forks,
    )
    .expect("Finality update failed to verify.");
    apply_finality_update(&mut store, &finality_update);

    let new_head = store.finalized_header.beacon().slot;
    assert!(
        new_head > prev_head,
        "New head is not greater than previous head."
    );
    assert!(new_head % 32 == 0, "New head is not a checkpoint slot.");
    let new_header: B256 = store.finalized_header.beacon().tree_hash_root();
    let new_committee: B256 = store.current_sync_committee.tree_hash_root();
    let execution = verified_execution_fields(&store.finalized_header, execution_header.as_ref())
        .expect("Execution header failed to verify.");

    // One contract with code, one slot, verified under the finalized execution state root.
    assert_eq!(
        contract_storage.len(),
        1,
        "exactly one contract storage request"
    );
    let contract = &contract_storage[0];
    assert_eq!(contract.storage_slots.len(), 1, "exactly one storage slot");
    assert_ne!(
        contract.value.code_hash.0, KECCAK_EMPTY,
        "the proven account has no code"
    );
    let slots = verify_storage_slot_proofs(execution.state_root, contract)
        .expect("Storage slot proofs failed to verify.");
    assert_eq!(slots.len(), 1);
    let slot = &slots[0];

    let outputs = UpdateOutputs {
        config,
        escrow: slot.contractAddress.into_array(),
        slot_key: slot.key.0,
        prev_lc: lc(prev_head, &prev_header.0, &prev_committee.0),
        new_lc: lc(new_head, &new_header.0, &new_committee.0),
        slot_value: slot.value.0,
        execution_state_root: execution.state_root.0,
        execution_block_number: execution.block_number,
        new_head,
    };
    sp1_zkvm::io::commit_slice(&outputs.encode());
}
