import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bytesToHex, concat, hexToBytes } from '../lib/bytes.js';
import { keccak256 } from '../lib/hash.js';
import { parseHeader } from '../lib/elements.js';
import { views } from '../lib/bridge.js';
import { Esplora } from '../lib/esplora.js';
import { burnStatus, findBatch, MAX_BATCH, relayBatches } from '../lib/redeem.js';

const sha = (b) => new Uint8Array(createHash('sha256').update(b).digest());
const word = (v) => BigInt(v).toString(16).padStart(64, '0');

/** An eth_call stand-in for the light client's views over a mutable state. */
function fakeEscrow(state) {
  return async (data) => {
    if (data === views.batchCount()) return '0x' + word(state.batches.length);
    if (data === views.lcTipHeight()) return '0x' + word(state.tip);
    if (data === views.EPOCH_LENGTH()) return '0x' + word(state.epochLength);
    if (data === views.signblockscriptHash()) return '0x' + state.sbsHash;
    for (let i = 0; i < state.batches.length; i++) {
      const b = state.batches[i];
      if (data === views.batchAt(i)) return '0x' + word(b.firstHeight) + word(b.count) + '00'.repeat(32);
    }
    throw new Error(`unexpected call ${data.slice(0, 10)}`);
  };
}

test('findBatch locates heights in contiguous batches', async () => {
  const call = fakeEscrow({ batches: [{ firstHeight: 2000, count: 100 }, { firstHeight: 2100, count: 100 }, { firstHeight: 2200, count: 50 }] });
  assert.equal((await findBatch(call, 2000)).index, 0);
  assert.equal((await findBatch(call, 2150)).index, 1);
  assert.equal((await findBatch(call, 2249)).index, 2);
  assert.equal(await findBatch(call, 1999), null, 'at or before the checkpoint');
  assert.equal(await findBatch(call, 2250), null, 'not relayed yet');
  assert.equal(await findBatch(fakeEscrow({ batches: [] }), 2000), null);
});

/** An Esplora over canned responses by path, recording each path asked; other paths are 404s, as for unknown txids. */
function cannedEsplora(routes) {
  const asked = [];
  const base = 'https://esplora.test/api';
  const esplora = new Esplora(base, async (url) => {
    const path = url.slice(base.length);
    asked.push(path);
    const [status, body] = routes[path] ?? [404, 'Transaction not found'];
    return { ok: status === 200, status, text: async () => body };
  });
  return { esplora, asked };
}

test('an unconfirmed burn counts only while the Liquid API still has the transaction', async () => {
  const txid = 'd4'.repeat(32);
  const statusPath = `/tx/${txid}/status`;
  const hexPath = `/tx/${txid}/hex`;
  const unconfirmed = [200, '{"confirmed":false}'];

  // Esplora reports a txid it has never seen as unconfirmed; tracking that answer alone would wait forever.
  await assert.rejects(burnStatus(cannedEsplora({ [statusPath]: unconfirmed }).esplora, txid), /does not have this burn transaction/);
  assert.deepEqual(await burnStatus(cannedEsplora({ [statusPath]: unconfirmed, [hexPath]: [200, '0200'] }).esplora, txid), { confirmed: false });
  // An outage is reported as itself, not as a dropped burn.
  await assert.rejects(burnStatus(cannedEsplora({ [statusPath]: unconfirmed, [hexPath]: [503, ''] }).esplora, txid), /HTTP 503/);

  const confirmed = { confirmed: true, block_height: 2712000, block_hash: 'ab'.repeat(32) };
  const { esplora, asked } = cannedEsplora({ [statusPath]: [200, JSON.stringify(confirmed)] });
  assert.deepEqual(await burnStatus(esplora, txid), confirmed);
  assert.deepEqual(asked, [statusPath], 'a confirmed burn needs no second request');
});

function le32(x) {
  return Uint8Array.of(x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, x >>> 24);
}

test('relay batches stop at epoch boundaries and at the target', async () => {
  const key = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  const script = concat([0x51, 0x21], key, [0x51, 0xae]);
  const spk = concat([0x00, 0x20], sha(script));
  const sig = hexToBytes('3044022035cf30cbcf4d20c66a0fc5dd605238ffa322809af75f9e43a6fc0b55b5dc8c7e02202b864286584a4ff823f07b1bd50ac7deac49709ba0e81bc87db459d57b941dc501');
  const headerAt = new Map();
  let prev = new Uint8Array(32);
  for (let h = 1991; h <= 2150; h++) {
    const raw = concat(le32(0xa0000000), prev, new Uint8Array(32).fill(h & 0xff), le32(1_760_000_000), le32(h), [0x01, 34], spk, le32(150), new Uint8Array(32), [0x00],
      [0x03, 0x00, sig.length], sig, [script.length], script);
    headerAt.set(h, bytesToHex(raw));
    prev = parseHeader(raw).hash;
  }
  const esplora = { headers: async (first, last) => Array.from({ length: last - first + 1 }, (_, i) => headerAt.get(first + i)) };
  const state = { tip: 1990, epochLength: 1000, sbsHash: bytesToHex(keccak256(spk)), batches: [] };
  const seen = [];
  for await (const b of relayBatches({ esplora, call: fakeEscrow(state), target: 2150 })) {
    seen.push([b.firstHeight, b.headers.length, b.witnessScript.length]);
    state.tip = b.firstHeight + b.headers.length - 1; // as if the batch were sent and confirmed
  }
  assert.deepEqual(seen, [[1991, 9, 0], [2000, MAX_BATCH, 0], [2100, 51, 0]]);
});
