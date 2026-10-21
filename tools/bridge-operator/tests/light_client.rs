//! Relaying and redeeming against an escrow stand-in and canned Esplora answers (bridge-core/test/redeem.test.js).
mod common;

use bridge_operator::bridge::{burn_script, Address, MAX_BATCH};
use bridge_operator::hash::keccak256;
use bridge_operator::light_client::{find_batch, next_relay_batch, redemption, Redemption};
use common::*;

/// The index of the batch `escrow` says holds `height`.
fn batch_of(escrow: &Escrow, height: u64) -> Option<u64> {
    find_batch(&mut |d: &str| escrow.call(d), height)
        .unwrap()
        .map(|b| b.index)
}

#[test]
fn find_batch_locates_heights_in_contiguous_batches() {
    let escrow = Escrow::new(
        vec![
            (2000, 100, [0; 32]),
            (2100, 100, [0; 32]),
            (2200, 50, [0; 32]),
        ],
        0,
    );
    assert_eq!(batch_of(&escrow, 2000), Some(0));
    assert_eq!(batch_of(&escrow, 2150), Some(1));
    assert_eq!(batch_of(&escrow, 2249), Some(2));
    assert_eq!(batch_of(&escrow, 1999), None, "at or before the checkpoint");
    assert_eq!(batch_of(&escrow, 2250), None, "not relayed yet");
    assert_eq!(batch_of(&Escrow::new(vec![], 0), 2000), None);
}

#[test]
fn relay_batches_stop_at_epoch_boundaries_and_at_the_target() {
    let chain = chain(1991, 2150, |h| [h as u8; 32]);
    let esplora = canned_esplora(esplora_routes(&chain));
    let escrow = Escrow::new(vec![], 1990);
    let mut seen = Vec::new();
    while let Some(b) = next_relay_batch(&esplora, &mut |d: &str| escrow.call(d), 2150).unwrap() {
        let first = (b.first_height - 1991) as usize;
        for (i, form) in b.headers.iter().enumerate() {
            assert_eq!(*form, chain[first + i].2.hash_form);
        }
        seen.push((
            b.first_height,
            b.headers.len() as u64,
            b.witness_script.len(),
        ));
        // As if the batch were sent and confirmed.
        escrow.set_tip(b.first_height + b.headers.len() as u64 - 1);
    }
    assert_eq!(
        seen,
        vec![(1991, 9, 0), (2000, MAX_BATCH, 0), (2100, 51, 0)]
    );
}

fn burn_chain() -> BurnChain {
    let script = burn_script(
        11_155_111,
        &Address::parse(ESCROW).unwrap(),
        &Address::parse(&format!("0x{}", "ab".repeat(20))).unwrap(),
    );
    BurnChain::new(&script)
}

#[test]
fn a_relayed_burn_is_ready_with_its_proof_and_block_reference() {
    let burn = burn_chain();
    let escrow = Escrow::new(vec![(5000, 3, batch_root(&burn.roots))], 5002);
    let esplora = canned_esplora(burn.routes(true));
    let Redemption::Ready {
        height,
        tip,
        burn: proof,
        block,
    } = redemption(&esplora, &mut |d: &str| escrow.call(d), &burn.txid, 0).unwrap()
    else {
        panic!("not ready");
    };
    assert_eq!((height, tip), (5000, 5002));
    assert_eq!(proof.transaction, burn.tx);
    assert_eq!((proof.vout, proof.position), (0, 1));
    assert_eq!(proof.branch, vec![burn.other]);
    assert_eq!((block.batch, block.index), (0, 0));
    assert_eq!(block.path.len(), 2);
    assert_eq!(block.path[0], keccak256(&burn.roots[1]));
}

#[test]
fn a_burn_waits_for_confirmations_and_for_relaying() {
    let burn = burn_chain();
    let escrow = Escrow::new(vec![(5000, 3, batch_root(&burn.roots))], 5000);
    let unconfirmed = canned_esplora(burn.routes(false));
    assert!(matches!(
        redemption(&unconfirmed, &mut |d: &str| escrow.call(d), &burn.txid, 0).unwrap(),
        Redemption::Unconfirmed
    ));

    // Two confirmations: the light client must reach 5001.
    let esplora = canned_esplora(burn.routes(true));
    let Redemption::AwaitingRelay {
        height,
        tip,
        needed,
    } = redemption(&esplora, &mut |d: &str| escrow.call(d), &burn.txid, 0).unwrap()
    else {
        panic!("not awaiting relay");
    };
    assert_eq!((height, tip, needed), (5000, 5000, 5001));
}

#[test]
fn a_burn_outside_every_batch_or_against_another_root_is_refused() {
    let burn = burn_chain();
    let esplora = canned_esplora(burn.routes(true));
    let refusal = |batches, txid: &str| {
        let escrow = Escrow::new(batches, 5002);
        redemption(&esplora, &mut |d: &str| escrow.call(d), txid, 0)
            .err()
            .unwrap()
    };
    assert_eq!(
        refusal(vec![(5001, 2, [0; 32])], &burn.txid),
        "no relayed batch holds height 5000; it is at or before the light client's checkpoint"
    );
    assert_eq!(
        refusal(vec![(5000, 3, [0x5a; 32])], &burn.txid),
        "rebuilt batch root differs from the stored one"
    );
    let unknown = "00".repeat(32);
    assert_eq!(
        refusal(vec![], &unknown),
        format!("Liquid API /tx/{unknown}/status: HTTP 404")
    );
}
