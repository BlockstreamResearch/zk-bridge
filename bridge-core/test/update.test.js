// Sending an update with Humid, and following the bridge state on Liquid (lib/update.js). The instance, its record and
// its chain are made up in the protocol's shapes (test/liquid-tx.js): updates whose leaf witness holds the update
// fields and whose control block opens the state they spend, claims whose output 0 is the successor state output, and
// the light-client stores the record publishes, each state's lc the hash of its store's head, header and committee.
// The state output's Taproot key is checked against node:crypto's secp256k1, and the PSET is decoded independently
// of the Humid code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createECDH, createHash } from 'node:crypto';
import { PUBLISHED } from '../config.js';
import { encodeSegwit } from '../lib/bech32.js';
import { bigToBytes, bytesToHex, concat, hexToBytes } from '../lib/bytes.js';
import { displayHex, parseTransaction, readWitness } from '../lib/elements.js';
import { Esplora } from '../lib/esplora.js';
import { HUMID_SCOPE, explicitTxOut, humidError } from '../lib/humid.js';
import {
  EMPTY_CLAIMED_ROOT, HUMID_MAX_PSET, MAX_FEE_SATS, claimedRoot, lcOf, lightClientStatus, liveState, prepareUpdate,
  publishes, readUpdate, sendUpdate, servedUntil, simplicityLeaf, siteStore, stateHash, stateLeaf, stateScript,
  stateTree, stateTreeRoot, storeFile, tapBranch, tweakKey, updateError, updateFields, updatePset, withStore,
} from '../lib/update.js';
import { ELEMENTS, psetTransaction, readPset } from './pset-reader.js';
import { LBTC, NUMS, blinded, cat, explicit, filler, hex, signedWitness, transaction, word } from './liquid-tx.js';

// ---- a made-up instance, its record and its chain ----

const UPDATE_CMR = hex(word('update leaf'));
const CLAIM_CMR = hex(word('claim leaf'));
const SIBLING = simplicityLeaf(CLAIM_CMR); // an update's sibling leaf: the claim leaf
const CLAIM_SIBLING = simplicityLeaf(UPDATE_CMR); // a claim's: the update leaf
const PROGRAM = filler('update program', 2_000);
const BOOT_TXID = word('bootstrap');
const FEE_SCRIPT = '0014' + word('fee key').slice(0, 40);
const RECIPIENT = '0014' + word('humid key').slice(0, 40);
const ASSET = hex(word('bridge asset'));
const TOKEN = cat([0x0b], hex(word('token')));
const TOKEN_VALUE = cat([0x09], hex(word('token value')));
const EMPTY = new Uint8Array(0);

/** A light-client store file at `head`: its head, header and committee, their lc, and a made-up store. */
function storeAt(head, label) {
  const header = word(`header ${label}`);
  const committee = word(`committee ${label}`);
  return { head, header, committee, lc: lcOf(head, header, committee), store_cbor: '0x' + word(`store ${label}`) };
}

const STORES = [storeAt(9_000_000, 'anchor'), storeAt(9_010_112, 'first'), storeAt(9_010_304, 'second')];
/** The state at store `s`, with a made-up accumulator and nothing claimed. */
const stateAt = (s, label) => ({ head: s.head, lc: s.lc, acc: word(`acc ${label}`), claimedRoot: EMPTY_CLAIMED_ROOT, claimed: [] });
const anchor = stateAt(STORES[0], 'anchor');
const state = { ...stateAt(STORES[1], 'first'), execBlock: 9_000_000 };
const next = { ...stateAt(STORES[2], 'second'), execBlock: 9_000_000 };
/** `s` with the deposits `indices` claimed, in that order. */
const withClaimed = (s, indices) => ({ ...s, claimed: indices, claimedRoot: claimedRoot(indices) });

const MANIFEST = {
  update_leaf: { cmr: bytesToHex(UPDATE_CMR) },
  claim_leaf: { cmr: bytesToHex(CLAIM_CMR) },
  constants: { nums: NUMS },
  initial_state: {
    head: anchor.head, lc: anchor.lc, acc: anchor.acc, claimed_root: EMPTY_CLAIMED_ROOT, state_hash: stateHash(anchor),
  },
};
const TREE = stateTree(MANIFEST);

/**
 * The update leaf's witness fields from `from` to `to`, as the leaf reads them: lc, acc and SIBLING, new_lc, new_acc,
 * exec_root and claimed_root, then be64(exec_block) and be64(new_head); `claimed` is the claimed root carried.
 */
const fieldBytes = (from, to, claimed = from.claimedRoot) => concat(
  hexToBytes(from.lc), hexToBytes(from.acc), SIBLING, hexToBytes(to.lc), hexToBytes(to.acc),
  hexToBytes(word(`exec ${to.head}`)), hexToBytes(claimed), bigToBytes(9_000_000n, 8), bigToBytes(BigInt(to.head), 8),
);

/**
 * An update leaf's whole witness around `fields`, as the leaf lays it out: made-up proof values, the fields, then
 * three 512-byte padding blocks, the second of which holds `padded` from bit 4,099 on, so off every byte boundary.
 */
function paddedWitness(fields, padded) {
  const bitsOf = (bytes) => Array.from(bytes, (b) => [7, 6, 5, 4, 3, 2, 1, 0].map((s) => (b >> s) & 1)).flat();
  const bits = bitsOf(filler('padding', 3 * 512));
  bits.splice(4_099, 8 * padded.length, ...bitsOf(padded));
  const blocks = new Uint8Array(3 * 512);
  bits.forEach((bit, k) => { blocks[k >> 3] |= bit << (7 - (k & 7)); });
  return concat(filler('proof values', 900), fields, blocks);
}

/** A control block of the state tree: leaf version 0xbe, NUMS, the other covenant leaf, and the spent state leaf. */
const control = (sibling, leaf) => cat([0xbe], hex(NUMS), sibling, leaf);

/** An open fee coin of 12,000 sats at FEE_SCRIPT: output 0 of a signed split. */
const FEE = transaction({
  inputs: [{ txid: word('fee funding'), vout: 1, witness: signedWitness('fee funding') }],
  outputs: [explicit(LBTC, 12_000n, hex(FEE_SCRIPT)), explicit(LBTC, 30_000n, hex(FEE_SCRIPT)), explicit(LBTC, 300n, EMPTY)],
});

/**
 * An update from `from` to `to` spending output 0 of `prev`: input 0 with the update leaf's witness, input 1 a fee
 * coin, signed unless `signed` is false; output 0 the state output of `to`, output 1 the fee. `claimed` is the claimed
 * root its fields carry, `leaf` the state leaf its control block opens, and `wrap` the leaf witness around the fields.
 */
function updateTx(prev, from, to, { fee = { txid: word(`fee ${to.head}`), vout: 0 }, signed = true, claimed, leaf = stateLeaf(from), wrap = (f) => f } = {}) {
  return transaction({
    inputs: [
      { txid: prev, vout: 0, witness: [wrap(fieldBytes(from, to, claimed)), PROGRAM, UPDATE_CMR, control(SIBLING, leaf)] },
      { ...fee, witness: signed ? signedWitness(`fee ${to.head}`) : [] },
    ],
    outputs: [blinded(TOKEN, TOKEN_VALUE, stateScript(TREE, to), `state ${to.head}`), explicit(LBTC, 12_000n, EMPTY)],
  });
}

/** The first update, from the anchor, confirmed; the second, built against FEE and not signed yet. */
const STATE = updateTx(BOOT_TXID, anchor, state);
const UPDATE = updateTx(STATE.txid, state, next, { fee: { txid: FEE.txid, vout: 0 }, signed: false });
const STATE_TXID = STATE.txid;
const UPDATE_TXID = UPDATE.txid;
const FEE_TXID = FEE.txid;
const STATE_TX = STATE.hex;
const FEE_TX = FEE.hex;

/**
 * A claim of deposit `index` spending output 0 of `prev`, which holds `spent`: its leaf witness holds `index` as a
 * u64 between made-up words, as the claim leaf's does among its other values, and `decoys`, other small values; its
 * output 0 is the state output of `spent` with that deposit claimed too, unless `commits` names another claimed set;
 * output 1 pays 100,000 units of the bridge asset to RECIPIENT.
 */
function claiming(prev, spent, index, { decoys = [], commits = [...spent.claimed, index] } = {}) {
  const witness = concat(hexToBytes(word(`claim ${prev}`)), bigToBytes(BigInt(index), 8),
    ...decoys.map((d) => concat(hexToBytes(word(`decoy ${d}`)), bigToBytes(BigInt(d), 8))), hexToBytes(word('claim end')));
  return transaction({
    inputs: [
      {
        txid: prev, vout: 0, issuance: { nonce: hex(word('token blinding')), entropy: hex(word('entropy')), amount: 100_000n, inflation: null },
        witness: [witness, filler('claim program', 1_636), CLAIM_CMR, control(CLAIM_SIBLING, stateLeaf(spent))],
      },
      { txid: word(`claim fee ${prev}`), vout: 0, witness: signedWitness(`claim fee ${prev}`) },
    ],
    outputs: [
      blinded(TOKEN, TOKEN_VALUE, stateScript(TREE, { ...spent, claimedRoot: claimedRoot(commits) }), `claim ${prev}`),
      explicit(ASSET, 100_000n, hex(RECIPIENT)),
      explicit(LBTC, 2_000n, EMPTY),
    ],
  });
}

const PAYS = { script: RECIPIENT, units: 100_000n };

// The record: the anchor's store, then the store of each update, named in lc_preimages.json.
const entries = STORES.map((s, k) => ({
  head: s.head, header: s.header, committee: s.committee, ...(k ? { update: [STATE_TXID, UPDATE_TXID][k - 1] } : {}),
  store: `lc_stores/${s.head}.json`,
}));
const storeText = (k) => JSON.stringify(STORES[k]);
const nextStore = entries[2].store;
const nextStoreText = storeText(2);
const initialRecord = {
  'manifest.json': JSON.stringify(MANIFEST),
  'lc_preimages.json': JSON.stringify({ preimages: entries.slice(0, 2) }),
  [entries[0].store]: storeText(0),
  [entries[1].store]: storeText(1),
};
const published = {
  'lc_preimages.json': JSON.stringify({ preimages: entries }),
  [nextStore]: nextStoreText,
};

const compactSizeLength = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : 5);
const stackLength = (items) => compactSizeLength(items.length)
  + items.reduce((sum, item) => sum + compactSizeLength(item.length) + item.length, 0);
const patched = (at, bytes) => {
  const copy = Uint8Array.from(UPDATE.raw);
  copy.set(bytes, at);
  return copy;
};

// ---- the update ----

test('the update spends the current state, pays its stated fee, and opens the successor', () => {
  const update = readUpdate(UPDATE.raw, UPDATE_CMR);
  assert.equal(update.txid, UPDATE_TXID);
  assert.deepEqual(update.state, { txid: STATE_TXID, vout: 0 });
  assert.deepEqual(update.fee, { txid: FEE_TXID, vout: 0, sats: 12_000n });
  assert.equal(bytesToHex(update.witness[2]), MANIFEST.update_leaf.cmr);
  assert.equal(update.witness[3].length, 97);
  assert.equal(bytesToHex(update.witness[3].subarray(33, 65)), bytesToHex(SIBLING));
  assert.equal(bytesToHex(update.successor.script), bytesToHex(stateScript(TREE, next)), 'output 0 is the successor state output');
  assert.ok(update.successor.blinded.rangeproof.length > 0);
  assert.ok(update.successor.blinded.surjectionProof.length > 0);
  assert.equal(storeFile(nextStoreText, next, nextStore).lc, next.lc);
});

test('an update\'s witness gives the state it moves to, its claimed root carried after exec_root', () => {
  const f = updateFields(fieldBytes(state, next), state, SIBLING);
  assert.deepEqual(f, {
    lc: next.lc, acc: next.acc, execRoot: word(`exec ${next.head}`), claimedRoot: state.claimedRoot,
    execBlock: 9_000_000, head: next.head,
  });
  // Found wherever the fields start in the witness.
  const at = concat(new Uint8Array(7), fieldBytes(state, next), new Uint8Array(5));
  assert.deepEqual(updateFields(at, state, SIBLING), f);
  assert.deepEqual(updateFields(paddedWitness(fieldBytes(state, next), EMPTY), state, SIBLING), f);
  assert.throws(() => updateFields(fieldBytes(state, next), { ...state, acc: word('other') }, SIBLING), /does not hold/);
});

test('padding that repeats the spent state\'s fields, even with another successor, does not move the fields read', () => {
  const f = updateFields(fieldBytes(state, next), state, SIBLING);
  const forged = { ...next, lc: word('lc forged'), acc: word('acc forged'), head: next.head + 1 };
  assert.deepEqual(updateFields(paddedWitness(fieldBytes(state, next), fieldBytes(state, next)), state, SIBLING), f);
  assert.deepEqual(updateFields(paddedWitness(fieldBytes(state, next), fieldBytes(state, forged)), state, SIBLING), f);
});

test('the PSET finalizes only the state input and asks Humid to sign the fee input', () => {
  const plan = updatePset(readUpdate(UPDATE.raw, UPDATE_CMR), STATE_TX, FEE_TX);
  const feeAddress = encodeSegwit('tex', 0, hexToBytes(FEE_SCRIPT).subarray(2));
  assert.deepEqual(plan.signInputs, [{ address: feeAddress, index: 1, sighashTypes: [1] }]);
  assert.equal(plan.successorAddress, encodeSegwit('tex', 1, stateScript(TREE, next).subarray(2)));
  assert.ok(plan.pset.length < HUMID_MAX_PSET);
  const pset = readPset(plan.pset);
  assert.deepEqual(pset.inputs.map((input) => [...input.keys()]),
    [['01', '0e', '0f', '08'], ['01', '0e', '0f']]);
  assert.equal(bytesToHex(pset.inputs[0].get('01')),
    bytesToHex(parseTransaction(hexToBytes(STATE_TX)).outputs[0].raw));
  assert.equal(bytesToHex(pset.inputs[1].get('01')),
    bytesToHex(explicitTxOut(LBTC, 12_000n, hexToBytes(FEE_SCRIPT))));
  // PSBT_IN_FINAL_SCRIPTWITNESS holds input 0's stack exactly as the update serializes it, the program included.
  const final = pset.inputs[0].get('08');
  const at = parseTransaction(UPDATE.raw).witnessAt + 2;
  assert.ok(final.length > PROGRAM.length);
  assert.equal(bytesToHex(UPDATE.raw.subarray(at, at + final.length)), bytesToHex(final));
  assert.equal(bytesToHex(UPDATE.raw.subarray(at + final.length, at + final.length + 5)), '0000000000');
  const proofs = readWitness(UPDATE.raw).outputs[0];
  assert.equal(bytesToHex(pset.outputs[0].get(ELEMENTS + '04')), bytesToHex(proofs.rangeproof));
  assert.equal(bytesToHex(pset.outputs[0].get(ELEMENTS + '05')), bytesToHex(proofs.surjectionProof));
  assert.equal(bytesToHex(pset.outputs[1].get('03')), bytesToHex(bigToBytes(12_000n, 8).reverse()));
  // What Humid extracts after signing, which adds only witnesses, is the update itself.
  assert.equal(bytesToHex(psetTransaction(pset)), bytesToHex(UPDATE.txidForm));
  assert.equal(displayHex(parseTransaction(psetTransaction(pset)).txid), UPDATE_TXID);
});

test('a signed fee input, another leaf, wrong outputs, or excessive fee is refused', () => {
  const tx = parseTransaction(UPDATE.raw);
  assert.throws(() => readUpdate(UPDATE.raw, new Uint8Array(32)), /not this instance's update leaf/);
  assert.throws(() => readUpdate(tx.txidForm, UPDATE_CMR), /carries no witness/);
  assert.throws(() => readUpdate(hexToBytes(FEE_TX), UPDATE_CMR), /two inputs/);
  assert.throws(() => readUpdate(claiming(UPDATE_TXID, next, 0).raw, UPDATE_CMR), /two outputs/, 'a claim is not an update');
  assert.throws(() => readUpdate(patched(tx.witnessAt - 4, [1, 0, 0, 0]), UPDATE_CMR), /locktime 0/);
  const items = readWitness(UPDATE.raw).inputs[0].script;
  const input1 = tx.witnessAt + 2 + stackLength(items) + 1 + 2;
  assert.equal(UPDATE.raw[input1], 0);
  const signed = concat(UPDATE.raw.subarray(0, input1), [2, 1, 0xaa, 1, 0xbb], UPDATE.raw.subarray(input1 + 1));
  assert.throws(() => readUpdate(signed, UPDATE_CMR), /input 1 is signed already/);
  assert.throws(() => readUpdate(STATE.raw, UPDATE_CMR), /input 1 is signed already/, 'the confirmed update, fee signed');
  const feeValue = tx.outputs[1].raw.byteOffset + 34;
  assert.equal(readUpdate(patched(feeValue, bigToBytes(MAX_FEE_SATS, 8)), UPDATE_CMR).fee.sats, MAX_FEE_SATS);
  assert.throws(() => readUpdate(patched(feeValue, bigToBytes(MAX_FEE_SATS + 1n, 8)), UPDATE_CMR), /at most 50000/);
  assert.throws(() => readUpdate(patched(tx.outputs[1].raw.byteOffset + 1, [0x48]), UPDATE_CMR), /not an open tL-BTC fee/);
});

test('the PSET refuses a substituted state or fee transaction', () => {
  const update = readUpdate(UPDATE.raw, UPDATE_CMR);
  assert.throws(() => updatePset(update, FEE_TX, FEE_TX), /different transaction/);
  assert.throws(() => updatePset(update, claiming(UPDATE_TXID, next, 0).hex, FEE_TX), /different transaction/);
  assert.throws(() => updatePset({ ...update, fee: { ...update.fee, sats: 11_999n } }, STATE_TX, FEE_TX),
    /not an open coin of exactly 11999 sats/);
  assert.throws(() => updatePset({ ...update, fee: { ...update.fee, vout: 3 } }, STATE_TX, FEE_TX),
    /has no output 3/);
});

// ---- light-client stores ----

const site = (changes = {}) => async (path) => {
  const files = { ...initialRecord, ...changes };
  if (!(path in files) || files[path] === null) {
    throw Object.assign(new Error('HTTP 404 for ' + path), { status: 404 });
  }
  return files[path];
};

test('a store must hash to the requested light-client state', () => {
  assert.equal(storeFile(nextStoreText, next, 'proof.store.json').head, next.head);
  assert.throws(() => storeFile(nextStoreText, state, 'proof.store.json'), /not the one at slot/);
  const raw = JSON.parse(nextStoreText);
  assert.throws(() => storeFile(JSON.stringify({ ...raw, committee: '11'.repeat(32) }), next, 'f'),
    /lc is not the hash/);
  assert.throws(() => storeFile(JSON.stringify({ ...raw, store_cbor: undefined }), next, 'f'),
    /holds no store CBOR/);
  assert.throws(() => storeFile('{}', next, 'f'), /names no head slot/);
  assert.throws(() => storeFile(UPDATE.hex, next, 'f'), /not a store file/);
});

/** The record with the published successor, its entry for `next` replaced by `entry`. */
const publishedAs = (entry) => site({
  ...published, 'lc_preimages.json': JSON.stringify({ preimages: [entries[0], entries[1], entry] }),
});

test('the site counts only listed, correctly named stores as published', async () => {
  assert.equal(await siteStore(site(), state, STATE_TXID), entries[1].store);
  assert.equal(await siteStore(site(), next, UPDATE_TXID), null);
  assert.equal(await siteStore(site(published), next, UPDATE_TXID), nextStore);
  assert.equal(await siteStore(site({ 'lc_preimages.json': null }), next, UPDATE_TXID), null);
  await assert.rejects(siteStore(site({ ...published, [nextStore]: null }), next, UPDATE_TXID), /HTTP 404/);
  await assert.rejects(siteStore(publishedAs({ ...entries[2], store: '../../elsewhere.json' }), next, UPDATE_TXID), /is malformed/);
});

test('the site counts a listed store only under the update that reaches its head', async () => {
  // The anchor's starting store names no update, as the initial state was reached by none.
  assert.equal(await siteStore(site(), anchor, null), entries[0].store);
  await assert.rejects(siteStore(site(), anchor, STATE_TXID), /under no update, but update .* reaches that slot/);
  await assert.rejects(siteStore(site(), state, null), /under update .*, but no update reaches that slot/);
  // A store listed for another update, or for none, past the anchor.
  await assert.rejects(siteStore(site(published), next, STATE_TXID), new RegExp(`under update ${UPDATE_TXID}, but update ${STATE_TXID}`));
  await assert.rejects(siteStore(publishedAs({ ...entries[2], update: undefined }), next, UPDATE_TXID), /under no update, but update/);
});

test('only the published site counts a listed store as published', () => {
  assert.equal(PUBLISHED.site, 'https://blockstreamresearch.github.io/zk-bridge/');
  assert.equal(publishes(PUBLISHED.site), true);
  assert.equal(publishes(`${PUBLISHED.site}?tab=redeem#main`), true);
  // Another copy of the page, however current it looks: an older site, a fork's, another path or scheme on the same host.
  for (const other of [
    'https://kyrylr.github.io/liquid-poc-bridge/', 'https://evil.github.io/zk-bridge/',
    'https://blockstreamresearch.github.io/', 'https://blockstreamresearch.github.io/zk-bridge/instances/',
    'https://blockstreamresearch.github.io/zk-bridge-old/', 'http://blockstreamresearch.github.io/zk-bridge/',
    'https://blockstreamresearch.github.io:8443/zk-bridge/',
  ]) assert.equal(publishes(other), false, other);
  assert.equal(publishes('http://localhost:5173/'), false);
  assert.equal(publishes('file:///tmp/index.html'), false);
  assert.ok(Number.isSafeInteger(servedUntil(next.head)));
});

// ---- the state output's key ----

test('the state output key is BIP 341\'s tweak under Elements\' tags, as node:crypto\'s secp256k1 computes it', () => {
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const sha = (b) => createHash('sha256').update(b).digest();
  const tagged = (tag, msg) => {
    const t = sha(Buffer.from(tag));
    return sha(Buffer.concat([t, t, Buffer.from(msg)]));
  };
  /** k G, compressed, by node:crypto. */
  const mulG = (k) => {
    const e = createECDH('secp256k1');
    e.setPrivateKey(Buffer.from(k.toString(16).padStart(64, '0'), 'hex'));
    return e.getPublicKey(null, 'compressed');
  };
  // For an internal key x(dG), the even-y point is dG or (N - d)G; the output key is that secret plus the tweak, times G.
  for (const d of [1n, 2n, 3n, 0xc0ffeen, N - 2n]) {
    const p = mulG(d);
    const even = p[0] === 2 ? d : N - d;
    const root = sha(Buffer.from(`root ${d}`));
    const t = BigInt('0x' + tagged('TapTweak/elements', Buffer.concat([p.subarray(1), root])).toString('hex'));
    const q = mulG((even + t) % N);
    assert.deepEqual(tweakKey(Uint8Array.from(p.subarray(1)), Uint8Array.from(root)),
      { key: Uint8Array.from(q.subarray(1)), parity: q[0] - 2 }, `d = ${d}`);
  }
  assert.throws(() => tweakKey(new Uint8Array(32).fill(0xff), new Uint8Array(32)), /below the field size/);

  // The tree {{update leaf, claim leaf}, state leaf}: each pair's TapBranch/elements in byte order, of TapLeaf/elements.
  const leaf = (w) => tagged('TapLeaf/elements', Buffer.concat([Buffer.from([0xbe, 32]), Buffer.from(w)]));
  const branch = (a, b) => tagged('TapBranch/elements', Buffer.compare(a, b) <= 0 ? Buffer.concat([a, b]) : Buffer.concat([b, a]));
  const s = Buffer.from(stateLeaf(state));
  assert.equal(bytesToHex(simplicityLeaf(UPDATE_CMR)), leaf(UPDATE_CMR).toString('hex'));
  assert.equal(bytesToHex(stateTreeRoot(TREE, s)), branch(branch(leaf(UPDATE_CMR), leaf(CLAIM_CMR)), s).toString('hex'));
  assert.equal(bytesToHex(tapBranch(SIBLING, CLAIM_SIBLING)), bytesToHex(tapBranch(CLAIM_SIBLING, SIBLING)));
  assert.equal(bytesToHex(stateScript(TREE, state)), '5120' + bytesToHex(tweakKey(hex(NUMS), stateTreeRoot(TREE, s)).key));
});

// ---- following the state ----

function liquidApi({ txs = {}, spends = {}, mempool = [], down = null } = {}) {
  const reply = (status, body) => ({
    ok: status === 200, status, text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  });
  const api = new Esplora('https://esplora.test/api/', async (url) => {
    const [, txid, what, vout] = url.match(
      /^https:\/\/esplora\.test\/api\/tx\/([0-9a-f]{64})\/(status|hex|outspend)(?:\/(\d+))?$/,
    );
    if (txid === api.down?.txid && api.down.status === 'offline') throw new TypeError('fetch failed');
    if (txid === api.down?.txid) return reply(api.down.status, 'unavailable');
    const txHex = api.txs[txid];
    if (what === 'status') {
      return reply(200, txHex && !api.mempool.includes(txid)
        ? { confirmed: true, block_height: 1, block_hash: 'aa'.repeat(32) } : { confirmed: false });
    }
    if (what === 'hex') return txHex ? reply(200, txHex) : reply(404, 'Transaction not found');
    const by = api.spends[txid + ':' + vout];
    return reply(200, by
      ? { spent: true, txid: by, vin: 0, status: { confirmed: !api.mempool.includes(by) } }
      : { spent: false });
  });
  return Object.assign(api, { txs: { ...txs }, spends: { ...spends }, mempool: [...mempool], down });
}

/** The Liquid API with the first update confirmed. */
const before = (changes = {}) => liquidApi({
  ...changes,
  txs: { [STATE_TXID]: STATE_TX, [FEE_TXID]: FEE_TX, ...changes.txs },
  spends: { [BOOT_TXID + ':0']: STATE_TXID, ...changes.spends },
});
/** The Liquid API with the second update confirmed as well. */
const after = (changes = {}) => before({
  ...changes,
  txs: { [UPDATE_TXID]: UPDATE.hex, ...changes.txs },
  spends: { [STATE_TXID + ':0']: UPDATE_TXID, ...changes.spends },
});
const prepare = (esplora, readRecord = site(), publishedSite = true) => prepareUpdate({
  esplora, readRecord, raw: UPDATE.raw, bootstrap: BOOT_TXID, published: publishedSite,
});
const walk = (esplora, m = MANIFEST, from = null) => liveState({ esplora, manifest: m, bootstrap: BOOT_TXID, from });

/** after(), with `txs` following, each spending output 0 of the one before. */
function chainOf(...txs) {
  return after({
    txs: Object.fromEntries(txs.map((t) => [t.txid, t.hex])),
    spends: Object.fromEntries(txs.map((t, k) => [(k ? txs[k - 1].txid : UPDATE_TXID) + ':0', t.txid])),
  });
}

test('the state walk follows both updates and rejects a substituted state, leaf or initial state', async () => {
  const live = await walk(after());
  assert.deepEqual(live, {
    outpoint: { txid: UPDATE_TXID, vout: 0 }, state: next, spends: 2, update: UPDATE_TXID, claims: [], moving: null,
    movingClaim: null,
  });
  const current = await walk(before());
  assert.deepEqual(current, {
    outpoint: { txid: STATE_TXID, vout: 0 }, state, spends: 1, update: STATE_TXID, claims: [], moving: null,
    movingClaim: null,
  });
  assert.deepEqual(await walk(after(), MANIFEST, current), live);
  // A spend whose state leaf is not the followed state's.
  const forged = updateTx(BOOT_TXID, anchor, state, { leaf: stateLeaf({ ...anchor, acc: word('acc other') }) });
  await assert.rejects(walk(before({ txs: { [STATE_TXID]: forged.hex } })), /holds another state/);
  await assert.rejects(walk(before(), { ...MANIFEST, update_leaf: { cmr: '00'.repeat(32) } }),
    /runs neither this instance's update leaf nor its claim leaf/);
  // The initial state must name the empty claimed root, and its state hash if stated; a claimed count is no state.
  const initial = (changes) => ({ ...MANIFEST, initial_state: { ...MANIFEST.initial_state, ...changes } });
  await assert.rejects(walk(before(), initial({ claimed_root: claimedRoot([0]) })), /has claimed deposits already/);
  await assert.rejects(walk(before(), initial({ state_hash: word('state') })), /initial state hash/);
  await assert.rejects(walk(before(), initial({ claimed_root: undefined, claimed: 0 })), /names no initial state with a claimed root/);
});

test('the state walk follows an update whose padding a relay rewrote to repeat the spent state\'s fields', async () => {
  // The leaf accepts any padding and the txid does not commit to it, so the confirmed update can carry the fields of
  // another successor in its padding, under the same txid.
  const forged = { ...state, lc: word('lc forged'), acc: word('acc forged') };
  const relayed = updateTx(BOOT_TXID, anchor, state, { wrap: (f) => paddedWitness(f, fieldBytes(anchor, forged)) });
  assert.equal(relayed.txid, STATE_TXID);
  const live = await walk(after({ txs: { [STATE_TXID]: relayed.hex } }));
  assert.deepEqual(live, await walk(after()));
  assert.deepEqual(live.state, next);
});

test('each claim is attributed to the deposit its output 0 commits, in any order, and never by order', async () => {
  // Deposit 2 is claimed, then deposit 0, whose witness holds the values 1 and 3 as well: only 0 gives output 0.
  const first = claiming(UPDATE_TXID, next, 2);
  const second = claiming(first.txid, withClaimed(next, [2]), 0, { decoys: [1, 3] });
  const live = await walk(chainOf(first, second));
  assert.deepEqual(live.state, withClaimed(next, [2, 0]));
  assert.deepEqual(live.claims, [
    { txid: first.txid, index: 2, pays: PAYS, confirmed: true },
    { txid: second.txid, index: 0, pays: PAYS, confirmed: true },
  ]);
  assert.equal(live.state.claimedRoot, claimedRoot([0, 2]));
  // Resumed from the first claim, the walk attributes the second the same way.
  const once = await walk(chainOf(first));
  assert.deepEqual((await walk(chainOf(first, second), MANIFEST, once)).claims, live.claims);
  // Unconfirmed, the second claim is attributed as the live output's spend, and not followed.
  const unconfirmed = chainOf(first, second);
  unconfirmed.mempool.push(second.txid);
  const pending = await walk(unconfirmed);
  assert.deepEqual(pending.movingClaim, { txid: second.txid, index: 0, pays: PAYS, confirmed: false });
  assert.equal(pending.moving, second.txid);
  assert.deepEqual(pending.state, withClaimed(next, [2]));
  // A claim of a known state must open it.
  const wrong = claiming(UPDATE_TXID, state, 2);
  await assert.rejects(walk(chainOf(wrong)), /holds another state/);
});

test('a claim no single index explains is unattributed, and so is every later claim until the set is known', async () => {
  // Output 0 commits deposits 5 and 6 claimed, but the witness holds only 5: no value makes that successor.
  const odd = claiming(UPDATE_TXID, next, 5, { commits: [5, 6] });
  const after1 = await walk(chainOf(odd));
  assert.deepEqual(after1.claims, [{ txid: odd.txid, index: null, pays: PAYS, confirmed: true }]);
  assert.deepEqual(after1.state, { ...next, claimed: null, claimedRoot: null });
  // The next claim would be attributable from a known set, but the set is not known: it is unattributed too.
  const then = claiming(odd.txid, withClaimed(next, [5, 6]), 7);
  const after2 = await walk(chainOf(odd, then));
  assert.deepEqual(after2.claims.map((c) => c.index), [null, null]);
});

test('an update after claims reveals the claimed root, checked against its spent state leaf', async () => {
  const later = (root) => ({ head: next.head + 64, lc: word('lc later'), acc: word('acc later'), claimedRoot: root, execBlock: 9_000_000 });
  // After an unattributed claim, the update reveals the root, but not the set.
  const odd = claiming(UPDATE_TXID, next, 5, { commits: [5, 6] });
  const root = claimedRoot([5, 6]);
  const revealed = updateTx(odd.txid, next, later(root), { claimed: root, leaf: stateLeaf({ ...next, claimedRoot: root }) });
  const live = await walk(chainOf(odd, revealed));
  assert.deepEqual(live.state, { ...later(root), claimed: null });
  assert.equal(live.update, revealed.txid);
  // The root the update carries must be the one its spent state leaf commits.
  const misled = updateTx(odd.txid, next, later(root), { claimed: root, leaf: stateLeaf(next) });
  await assert.rejects(walk(chainOf(odd, misled)), /holds another state/);
  // After attributed claims the set is known, and an update must carry its root.
  const first = claiming(UPDATE_TXID, next, 2);
  const kept = updateTx(first.txid, next, later(claimedRoot([2])), { claimed: claimedRoot([2]), leaf: stateLeaf(withClaimed(next, [2])) });
  assert.deepEqual((await walk(chainOf(first, kept))).state, { ...later(claimedRoot([2])), claimed: [2] });
  const lost = updateTx(first.txid, next, later(root), { claimed: root, leaf: stateLeaf({ ...next, claimedRoot: root }) });
  await assert.rejects(walk(chainOf(first, lost)), /does not keep the claimed root/);
});

// ---- the update panel and Humid ----

test('the panel identifies the live store and loads an unpublished successor store', async () => {
  const status = await lightClientStatus({ esplora: before(), readRecord: site(), bootstrap: BOOT_TXID });
  assert.equal(status.listed, entries[1].store);
  assert.deepEqual(status.live.state, state);
  const plan = await prepare(before());
  assert.deepEqual(plan.live.outpoint, { txid: STATE_TXID, vout: 0 });
  assert.deepEqual(plan.successor, next);
  assert.equal(plan.store, null);
  const held = withStore(plan, nextStoreText, 'proof.store.json');
  assert.deepEqual(held.store, {
    where: 'file', name: 'proof.store.json', entry: entries[2],
  });
  await assert.rejects(sendUpdate({ humid: fakeHumid(), esplora: before(), plan }), /load the store/);
  assert.deepEqual((await prepare(before(), site(published))).store, { where: 'site', path: nextStore });
  assert.equal((await prepare(before(), site(published), false)).store, null);
});

test('the panel refuses a store the record lists under another update than the live or loaded one', async () => {
  // Before the first update the live state is the anchor, whose starting store names none.
  const atAnchor = await lightClientStatus({ esplora: liquidApi(), readRecord: site(), bootstrap: BOOT_TXID });
  assert.equal(atAnchor.live.update, null);
  assert.equal(atAnchor.listed, entries[0].store);
  const record = (preimages) => site({ 'lc_preimages.json': JSON.stringify({ preimages }) });
  const named = { ...entries[0], update: STATE_TXID };
  await assert.rejects(lightClientStatus({ esplora: liquidApi(), readRecord: record([named, entries[1]]), bootstrap: BOOT_TXID }),
    /under update .*, but no update reaches that slot/);
  // The live head reached by STATE, listed under another update.
  const other = { ...entries[1], update: FEE_TXID };
  await assert.rejects(lightClientStatus({ esplora: before(), readRecord: record([entries[0], other]), bootstrap: BOOT_TXID }),
    new RegExp(`under update ${FEE_TXID}, but update ${STATE_TXID}`));
  // The loaded update's successor store, published under another update: nothing to send from the site's copy.
  await assert.rejects(prepare(before(), publishedAs({ ...entries[2], update: FEE_TXID })),
    new RegExp(`under update ${FEE_TXID}, but update ${UPDATE_TXID}`));
});

test('the panel refuses a spent state, used fee coin, sent update, or unavailable Liquid API', async () => {
  await assert.rejects(prepare(after()), /on Liquid already/);
  await assert.rejects(prepare(before({ spends: { [STATE_TXID + ':0']: 'cd'.repeat(32) } })), /spent already/);
  await assert.rejects(
    prepare(before({ spends: { [FEE_TXID + ':0']: 'cd'.repeat(32) } })), /fee coin .* spent already/,
  );
  await assert.rejects(prepare(before({ mempool: [FEE_TXID] })), /fee coin .* not confirmed yet/);
  await assert.rejects(prepare(before({ down: { txid: UPDATE_TXID, status: 429 } })), /HTTP 429/);
  await assert.rejects(prepare(before({ down: { txid: UPDATE_TXID, status: 'offline' } })), /fetch failed/);
});

function fakeHumid(sign = () => ({ txid: UPDATE_TXID })) {
  const calls = [];
  return {
    calls,
    async request({ method, params }) {
      calls.push({ method, params });
      if (method === 'wallet_getSession') return { sessionScopes: {} };
      if (method === 'wallet_createSession') {
        return { sessionScopes: { [HUMID_SCOPE]: { methods: ['getUTXOs', 'signPset'] } } };
      }
      if (method === 'wallet_invokeMethod' && params.request.method === 'signPset') {
        return sign(params.request.params);
      }
      throw new Error('unexpected ' + method);
    },
  };
}

test('Humid signs the fee input once; a known update is never sent again', async () => {
  const plan = withStore(await prepare(before()), nextStoreText, 'proof.store.json');
  const humid = fakeHumid();
  assert.equal(await sendUpdate({ humid, esplora: before(), plan }), UPDATE_TXID);
  const sign = humid.calls.filter((call) => call.params?.request?.method === 'signPset');
  assert.equal(sign.length, 1);
  assert.deepEqual(sign[0].params.request.params.signInputs,
    [{ address: plan.feeAddress, index: 1, sighashTypes: [1] }]);
  const already = fakeHumid();
  await assert.rejects(sendUpdate({ humid: already, esplora: after(), plan }), /on Liquid already/);
  assert.deepEqual(already.calls, []);
});

test('Humid refusal and an uncertain broadcast have distinct messages', async () => {
  const plan = withStore(await prepare(before()), nextStoreText, 'proof.store.json');
  const send = (sign) => sendUpdate({ humid: fakeHumid(sign), esplora: before(), plan }).catch((error) => error);
  const declined = await send(() => {
    throw Object.assign(new Error('user rejected'), { code: -32002, data: { reason: 'user_rejected' } });
  });
  assert.equal(declined.sent, 'no');
  assert.equal(updateError(declined), humidError(declined));
  const failed = await send(() => {
    throw Object.assign(new Error('broadcast failed'), {
      code: -32002, data: { reason: 'wallet_pset_broadcast_failed' },
    });
  });
  assert.equal(failed.sent, 'maybe');
  assert.match(updateError(failed), /may have been sent all the same/);
  const other = await send(() => ({ txid: 'ab'.repeat(32) }));
  assert.equal(other.sent, 'maybe');
  assert.match(other.message, /not the update/);
});
