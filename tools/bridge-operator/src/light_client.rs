//! Relaying and redeeming against a deployed BridgeEscrow, from Esplora data and escrow reads, as
//! bridge-core/lib/redeem.js does for the page. `call` is an eth_call of escrow calldata, returning its return data.
use serde_json::Value;

use crate::abi;
use crate::bridge::{
    batch_at, batch_ref, burn_proof, relay_batch, view, Batch, BlockRef, BurnProof, RelayBatch,
    MAX_BATCH,
};
use crate::esplora::{block_hash, Esplora};

/// An eth_call of escrow calldata (`0x` hex), returning the return data.
pub type EthCall<'a> = dyn FnMut(&str) -> Result<Vec<u8>, String> + 'a;

fn read_uint(call: &mut EthCall, signature: &str) -> Result<u64, String> {
    abi::uint(&call(&view(signature))?)
}

/// The light client's batch holding `height`, by binary search over the contiguous stored batches.
pub fn find_batch(call: &mut EthCall, height: u64) -> Result<Option<Batch>, String> {
    let count = read_uint(call, "batchCount()")?;
    let (mut lo, mut hi) = (0, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let batch = Batch::decode(&call(&batch_at(mid))?, mid)?;
        if height < batch.first_height {
            hi = mid;
        } else if !batch.holds(height) {
            lo = mid + 1;
        } else {
            return Ok(Some(batch));
        }
    }
    Ok(None)
}

/// The next submitHeaders batch that brings the light client from its tip towards `target`, or `None` once the tip
/// has reached it: at most MAX_BATCH headers, never crossing a DynaFed epoch. Built only when asked for, because a
/// key change in one batch changes what the next must carry.
pub fn next_relay_batch(
    esplora: &Esplora,
    call: &mut EthCall,
    target: u64,
) -> Result<Option<RelayBatch>, String> {
    let epoch_length = read_uint(call, "EPOCH_LENGTH()")?;
    if epoch_length == 0 {
        return Err("the escrow reports an epoch length of 0".into());
    }
    let tip = read_uint(call, "lcTipHeight()")?;
    if tip >= target {
        return Ok(None);
    }
    // No overflow: tip < target. The escrow's answers are not trusted to keep the rest in range.
    let first = tip + 1;
    let epoch_end = (first / epoch_length)
        .saturating_add(1)
        .saturating_mul(epoch_length)
        - 1;
    let last = target
        .min(first.saturating_add(MAX_BATCH - 1))
        .min(epoch_end);
    let current = abi::word_at(&call(&view("signblockscriptHash()"))?, 0)?;
    relay_batch(&esplora.headers(first, last)?, &current).map(Some)
}

/// Where a burn stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Redemption {
    /// Not in a block yet.
    Unconfirmed,
    /// In block `height`, but the light client's tip must reach `needed` first.
    AwaitingRelay { height: u64, tip: u64, needed: u64 },
    /// Redeemable with these arguments.
    Ready {
        height: u64,
        tip: u64,
        burn: BurnProof,
        block: BlockRef,
    },
}

/// Where output `vout` of the burn `txid` (display hex) stands, and once the light client covers it, the full
/// redeem() arguments.
pub fn redemption(
    esplora: &Esplora,
    call: &mut EthCall,
    txid: &str,
    vout: u32,
) -> Result<Redemption, String> {
    let status = esplora.tx_status(txid)?;
    if status.get("confirmed") != Some(&Value::Bool(true)) {
        return Ok(Redemption::Unconfirmed);
    }
    let block = status
        .get("block_hash")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or("Liquid API returned an invalid block hash")?;
    let block = block_hash(block)?;
    let proof = burn_proof(
        txid,
        &esplora.tx_hex(txid)?,
        vout,
        &esplora.txids(&block)?,
        &esplora.header(&block)?,
    )?;
    let tip = read_uint(call, "lcTipHeight()")?;
    let min_confirmations = read_uint(call, "MIN_CONFIRMATIONS()")?;
    let needed = proof
        .height
        .saturating_add(min_confirmations)
        .saturating_sub(1);
    if tip < needed {
        return Ok(Redemption::AwaitingRelay {
            height: proof.height,
            tip,
            needed,
        });
    }
    let batch = find_batch(call, proof.height)?.ok_or_else(|| {
        format!(
            "no relayed batch holds height {}; it is at or before the light client's checkpoint",
            proof.height
        )
    })?;
    // The batch holds the height, so it has at least one header.
    let last = batch.first_height.saturating_add(batch.count - 1);
    let roots = esplora.merkle_roots(batch.first_height, last)?;
    if roots.get((proof.height - batch.first_height) as usize) != Some(&proof.merkle_root) {
        return Err("Liquid API Merkle roots disagree with the burn block header".into());
    }
    Ok(Redemption::Ready {
        height: proof.height,
        tip,
        block: batch_ref(&batch, &roots, proof.height)?,
        burn: proof.burn,
    })
}
