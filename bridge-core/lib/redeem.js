// Redemption and relaying against a deployed BridgeEscrow, from Esplora data and escrow reads. `call` is
// an eth_call of escrow calldata returning hex: the wallet or the Settings RPC. tools/bridge-operator implements the
// same relay and redeem steps for operators.
import { equal } from './bytes.js';
import { batchRef, burnProof, decode, decodeBatch, relayBatch, views } from './bridge.js';

export const MAX_BATCH = 100;

async function readUint(call, data) {
  return Number(decode.uint(await call(data)));
}

/** The light client's batch holding `height`, by binary search over the contiguous stored batches. */
export async function findBatch(call, height) {
  let lo = 0;
  let hi = (await readUint(call, views.batchCount())) - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const b = decodeBatch(await call(views.batchAt(mid)), mid);
    if (height < b.firstHeight) hi = mid - 1;
    else if (height >= b.firstHeight + b.count) lo = mid + 1;
    else return b;
  }
  return null;
}

/**
 * A burn transaction's Esplora status, for tracking. Esplora answers {confirmed: false} for a txid it has never
 * seen, so an unconfirmed burn is fetched as well. One the API does not have (it left the mempool or was never
 * broadcast) is an error rather than a burn waiting for a block; any other failure is passed on unchanged.
 */
export async function burnStatus(esplora, txid) {
  const status = await esplora.txStatus(txid);
  if (status.confirmed) return status;
  try {
    await esplora.txHex(txid);
  } catch (e) {
    if (e.status !== 404) throw e;
    throw new Error('The Liquid API does not have this burn transaction: it may have left the mempool or never been broadcast. '
      + 'Until it confirms, nothing is burned; check your wallet, or look up a replacement in step 3.');
  }
  return status;
}

/**
 * Where a burn stands: its height, the relayed tip, the height the tip must reach, and once it has,
 * the full redeem() arguments.
 */
export async function redemption({ esplora, call, recipient, txid, vout }) {
  const status = await esplora.txStatus(txid);
  if (!status.confirmed) return { state: 'unconfirmed' };
  const [txHex, txidsDisplay, blockHeaderHex] = await Promise.all([esplora.txHex(txid), esplora.txids(status.block_hash), esplora.header(status.block_hash)]);
  const proof = burnProof({ txidDisplay: txid, txHex, vout, txidsDisplay, blockHeaderHex });
  const [tip, minConf] = await Promise.all([readUint(call, views.lcTipHeight()), readUint(call, views.MIN_CONFIRMATIONS())]);
  const needed = proof.height + minConf - 1;
  if (tip < needed) return { state: 'awaiting-relay', height: proof.height, tip, needed };
  const batch = await findBatch(call, proof.height);
  if (!batch) throw new Error(`no relayed batch holds height ${proof.height}; it is at or before the light client's checkpoint`);
  const roots = await esplora.merkleRoots(batch.firstHeight, batch.firstHeight + batch.count - 1);
  if (!equal(roots[proof.height - batch.firstHeight], proof.merkleRoot)) throw new Error('Liquid API Merkle roots disagree with the burn block header');
  return { state: 'ready', height: proof.height, tip, needed, args: { recipient, burn: proof.burn, ref: batchRef(batch, roots, proof.height) } };
}

/**
 * The submitHeaders batches that bring the light client from its tip to `target`: at most MAX_BATCH
 * headers each, never crossing a DynaFed epoch. Each batch is built when requested, because a key
 * change in one batch changes what the next one must carry.
 */
export async function* relayBatches({ esplora, call, target }) {
  const epochLength = await readUint(call, views.EPOCH_LENGTH());
  for (;;) {
    const tip = await readUint(call, views.lcTipHeight());
    if (tip >= target) return;
    const first = tip + 1;
    const epochEnd = (Math.floor(first / epochLength) + 1) * epochLength - 1;
    const last = Math.min(target, first + MAX_BATCH - 1, epochEnd);
    const current = '0x' + decode.bytes32(await call(views.signblockscriptHash()));
    yield relayBatch(await esplora.headers(first, last), current);
  }
}
