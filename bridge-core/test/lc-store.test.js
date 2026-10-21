import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { INSTANCE } from '../config.js';
import { bigToBytes, bytesToHex, hexToBytes, utf8 } from '../lib/bytes.js';
import { LIVE } from './live-state.js';

// Pages publishes instances/$RECORD/ (.github/workflows/pages.yml). A replacement operator's next proof starts from
// the light-client store that record publishes: lc_preimages.json names lc_stores/<head>.json, and
// `sg16-bridge-host inputs --store` refuses the file unless its CBOR recomputes the head, roots and lc. This gate
// does the same recomputation, without Cargo, so the page is never published with a missing or altered store.
// The workflow runs it on the checkout (npm test) and again on the staged copy (RECORD_DIR) before upload.
// The live state it checks against is the reviewed pin in live-state.js. With no record named, the record checks
// skip; the gate's own refusal cases run on a synthetic record built below.

const LC_TAG = sha256(utf8('liquid-bridge-poc/lc'));
const SLOTS_PER_PERIOD = 8192; // sync-committee period: 256 epochs of 32 slots
const PUBKEYS = 512;

function sha256(...parts) {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

function need(ok, message) {
  if (!ok) throw new Error(message);
}

/** lc = SHA256(SHA256(LC_TAG) || be64(head) || header || committee), in hex (tools/sg16/bridge-guest/core lc). */
function lcOf(head, header, committee) {
  return bytesToHex(sha256(LC_TAG, bigToBytes(BigInt(head), 8), hexToBytes(header), hexToBytes(committee)));
}

/**
 * The one CBOR item in `b`: unsigned integers, byte and text strings, arrays, maps with distinct text keys, null
 * and booleans, all of definite length, which is what serde_cbor writes for a Helios store. Anything else, or
 * trailing bytes, throws.
 */
function decodeCbor(b) {
  const text = new TextDecoder('utf-8', { fatal: true });
  let p = 0;
  const take = (n) => {
    need(p + n <= b.length, `store_cbor: truncated at byte ${p}`);
    p += n;
    return b.subarray(p - n, p);
  };
  const arg = (ai) => {
    if (ai < 24) return BigInt(ai);
    need(ai <= 27, `store_cbor: indefinite or reserved length at byte ${p - 1}`);
    let v = 0n;
    for (const x of take(1 << (ai - 24))) v = (v << 8n) | BigInt(x);
    return v;
  };
  const len = (ai) => {
    const n = arg(ai);
    need(n <= BigInt(b.length - p), `store_cbor: length ${n} past the end at byte ${p}`);
    return Number(n);
  };
  function item() {
    const [ib] = take(1);
    const ai = ib & 31;
    switch (ib >> 5) {
      case 0: return arg(ai);
      case 2: return Uint8Array.from(take(len(ai)));
      case 3: return text.decode(take(len(ai)));
      case 4: return Array.from({ length: len(ai) }, () => item());
      case 5: {
        const n = len(ai);
        const o = Object.create(null);
        for (let i = 0; i < n; i++) {
          const k = item();
          need(typeof k === 'string' && !(k in o), 'store_cbor: a map key that is not text, or is repeated');
          o[k] = item();
        }
        return o;
      }
      case 7:
        if (ai === 20) return false;
        if (ai === 21) return true;
        if (ai === 22) return null;
    }
    throw new Error(`store_cbor: unsupported CBOR item 0x${ib.toString(16)} at byte ${p - 1}`);
  }
  const v = item();
  need(p === b.length, `store_cbor: ${b.length - p} trailing bytes`);
  return v;
}

const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Uint8Array);

/** A CBOR map with exactly the text keys `keys`, the fields serde_cbor writes for a Helios struct. */
function cborMap(v, keys, what) {
  need(isMap(v), `store_cbor ${what}: a map`);
  for (const k of keys) need(k in v, `store_cbor ${what}: no ${k}`);
  for (const k of Object.keys(v)) need(keys.includes(k), `store_cbor ${what}: unexpected key ${k}`);
  return v;
}

/** A plain u64 field: a CBOR unsigned integer, which is all serde_cbor decodes into one. */
function uint64(v, what) {
  need(typeof v === 'bigint' && v < 1n << 64n, `store_cbor ${what}: a CBOR unsigned integer`);
  return v;
}

/** A beacon uint64 (Helios serde_utils::u64): decimal text, never a CBOR integer. */
function decimal(v, what) {
  need(typeof v === 'string' && /^(0|[1-9][0-9]*)$/.test(v) && BigInt(v) < 1n << 64n, `store_cbor ${what}: a uint64 as decimal text`);
  return BigInt(v);
}

/** A B256 as serde_cbor writes it: a 32-byte CBOR byte string. */
function b256(v, what) {
  need(v instanceof Uint8Array && v.length === 32, `store_cbor ${what}: a 32-byte byte string`);
  return v;
}

/** A BLS public key as Helios writes it: text, 0x and 96 hex digits. */
function pubkey(v, what) {
  need(typeof v === 'string' && /^0x[0-9a-f]{96}$/.test(v), `store_cbor ${what}: a 0x hex 48-byte public key`);
  return hexToBytes(v);
}

function chunk(b) {
  const c = new Uint8Array(32);
  c.set(b);
  return c;
}

/** SSZ merkleization of a power-of-two number of chunks. */
function merkleize(chunks) {
  let layer = chunks;
  while (layer.length > 1) layer = Array.from({ length: layer.length / 2 }, (_, i) => sha256(layer[2 * i], layer[2 * i + 1]));
  return layer[0];
}

const uint64Root = (n) => chunk(bigToBytes(n, 8).reverse());
const pubkeyRoot = (k) => sha256(chunk(k.subarray(0, 32)), chunk(k.subarray(32)));

const EXECUTION_BRANCH = 11; // roots in a Gloas header's execution_branch (a fixed-length vector)

/**
 * A Gloas LightClientHeader, the variant every Sepolia finalized header now takes and sp1-helios needs for the
 * execution header witness: beacon, execution_block_hash and execution_branch, and no other key. Returns its slot
 * and BeaconBlockHeader SSZ root.
 */
function lightClientHeader(v, what) {
  const h = cborMap(v, ['beacon', 'execution_block_hash', 'execution_branch'], what);
  const beacon = cborMap(h.beacon, ['slot', 'proposer_index', 'parent_root', 'state_root', 'body_root'], `${what}.beacon`);
  b256(h.execution_block_hash, `${what}.execution_block_hash`);
  need(Array.isArray(h.execution_branch) && h.execution_branch.length === EXECUTION_BRANCH,
    `store_cbor ${what}.execution_branch: ${EXECUTION_BRANCH} roots`);
  h.execution_branch.forEach((r, i) => b256(r, `${what}.execution_branch[${i}]`));
  const slot = decimal(beacon.slot, `${what}.beacon.slot`);
  const root = merkleize([
    uint64Root(slot),
    uint64Root(decimal(beacon.proposer_index, `${what}.beacon.proposer_index`)),
    ...['parent_root', 'state_root', 'body_root'].map((k) => b256(beacon[k], `${what}.beacon.${k}`)),
    chunk([]), chunk([]), chunk([]),
  ]);
  return { slot, root };
}

/**
 * What lc commits to, recomputed from a store's CBOR as the host's store_roots does: the finalized beacon
 * header's slot and SSZ root (BeaconBlockHeader) and the current sync committee's SSZ root (SyncCommittee).
 * The whole store must first have the shape the host decodes (serde_cbor into LightClientStore), as the host's
 * own `store` and `run` write it, so the gate never passes a file that `inputs --store` cannot even parse.
 */
function storeRoots(cbor) {
  const store = cborMap(decodeCbor(cbor), ['finalized_header', 'current_sync_committee', 'next_sync_committee', 'optimistic_header',
    'previous_max_active_participants', 'current_max_active_participants', 'best_valid_update'], 'store');
  const finalized = lightClientHeader(store.finalized_header, 'finalized_header');
  lightClientHeader(store.optimistic_header, 'optimistic_header');
  const sc = cborMap(store.current_sync_committee, ['pubkeys', 'aggregate_pubkey'], 'current_sync_committee');
  need(Array.isArray(sc.pubkeys) && sc.pubkeys.length === PUBKEYS, `store_cbor current_sync_committee.pubkeys: ${PUBKEYS} keys`);
  const committee = sha256(
    merkleize(sc.pubkeys.map((k, i) => pubkeyRoot(pubkey(k, `current_sync_committee.pubkeys[${i}]`)))),
    pubkeyRoot(pubkey(sc.aggregate_pubkey, 'current_sync_committee.aggregate_pubkey')),
  );
  need(store.next_sync_committee === null, 'store_cbor: a store file carries no next sync committee');
  for (const k of ['previous_max_active_participants', 'current_max_active_participants']) uint64(store[k], k);
  // Not read by the guest, but the host must decode it. This gate does not model Helios's GenericUpdate, so a
  // store with a pending update is refused rather than published unchecked.
  need(store.best_valid_update === null, 'store_cbor best_valid_update: null (a pending update is not checked by this gate)');
  return { head: finalized.slot, header: bytesToHex(finalized.root), committee: bytesToHex(committee) };
}

function fields(o, required, optional, what) {
  need(isMap(o), `${what}: a JSON object`);
  for (const k of required) need(k in o, `${what}: no ${k}`);
  for (const k of Object.keys(o)) need(required.includes(k) || optional.includes(k), `${what}: unexpected key ${k}`);
  return o;
}

function word(v, what) {
  need(typeof v === 'string' && /^(0x)?[0-9a-f]{64}$/.test(v), `${what}: 32 bytes of lower-case hex`);
  return v.replace(/^0x/, '');
}

function slotOf(v, what) {
  need(Number.isSafeInteger(v) && v >= 0, `${what}: a slot number`);
  return v;
}

function readJson(dir, rel) {
  const path = join(dir, rel);
  need(existsSync(path), `${rel} is missing`);
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error(`${rel} is not valid JSON`);
  }
}

/** A store file whose CBOR recomputes its own head, header, committee and lc (host parse_store). */
function checkStore(doc, rel) {
  fields(doc, ['head', 'header', 'committee', 'lc', 'store_cbor'], ['about'], rel);
  const head = slotOf(doc.head, `${rel} head`);
  const header = word(doc.header, `${rel} header`);
  const committee = word(doc.committee, `${rel} committee`);
  const lc = word(doc.lc, `${rel} lc`);
  need(typeof doc.store_cbor === 'string' && /^0x([0-9a-f]{2})+$/.test(doc.store_cbor), `${rel} store_cbor: 0x hex`);
  const r = storeRoots(hexToBytes(doc.store_cbor));
  need(r.head === BigInt(head), `${rel}: the store is at slot ${r.head}, not the file's head ${head}`);
  need(r.header === header, `${rel}: the store's finalized header root is ${r.header}, not the file's header`);
  need(r.committee === committee, `${rel}: the store's sync committee root is ${r.committee}, not the file's committee`);
  need(lcOf(head, header, committee) === lc, `${rel}: the file's lc is not the hash of its head, header and committee`);
  return { head, header, committee, lc };
}

function refuseLinks(dir, rel = '') {
  for (const d of readdirSync(join(dir, rel), { withFileTypes: true })) {
    const r = join(rel, d.name);
    need(!d.isSymbolicLink(), `${r} is a symbolic link; the Pages artifact would publish its target`);
    if (d.isDirectory()) refuseLinks(dir, r);
  }
}

/**
 * Throws unless the record directory `dir` publishes a usable light-client store for the live state `live`
 * ({ head, lc }): lc_preimages.json well-formed and continuing from instance.json's anchor, each store it names at
 * lc_stores/<head>.json and recomputing that entry, no unnamed store, and both the latest entry and the live
 * head's entry naming one.
 *
 * Before the first update, the live state is at the anchor. Its starting store may be published with no update
 * transaction; otherwise the first prover needs a beacon node's light-client bootstrap. Later stores must name
 * their update transactions. Returns whether the live state is the anchor.
 */
function checkRecord(dir, live) {
  need(!lstatSync(dir).isSymbolicLink(), 'the record directory is a symbolic link');
  refuseLinks(dir);
  const pins = readJson(dir, 'instance.json');
  const a = pins.ANCHOR ?? {};
  const anchor = { head: slotOf(a.slot, 'instance.json ANCHOR.slot'), header: word(a.header, 'instance.json ANCHOR.header'),
    committee: word(a.committee, 'instance.json ANCHOR.committee') };
  need(lcOf(anchor.head, anchor.header, anchor.committee) === word(a.lc, 'instance.json ANCHOR.lc'),
    'instance.json ANCHOR.lc is not the hash of its slot, header and committee');
  const initial = readJson(dir, 'initial_state.json');
  need(initial.head === anchor.head && initial.header === anchor.header && initial.committee === anchor.committee && initial.lc === a.lc,
    'initial_state.json does not start from the instance.json anchor');
  const atAnchor = live.head === anchor.head;
  if (atAnchor) need(live.lc === a.lc, `the live state is at the anchor slot ${anchor.head}, but its lc is not the anchor's`);
  if (atAnchor && !existsSync(join(dir, 'lc_preimages.json'))) {
    need(!existsSync(join(dir, 'lc_stores')), 'lc_stores/ is published, but no lc_preimages.json names its files');
    return true;
  }

  const hints = fields(readJson(dir, 'lc_preimages.json'), ['preimages'], ['about'], 'lc_preimages.json');
  need(Array.isArray(hints.preimages) && hints.preimages.length > 0, 'lc_preimages.json preimages: a non-empty list');
  const entries = [];
  const updates = new Set();
  const named = new Set();
  let prev = { ...anchor, what: 'the anchor' };
  for (const [i, e] of hints.preimages.entries()) {
    const what = `lc_preimages.json entry ${i}`;
    fields(e, ['head', 'header', 'committee'], ['update', 'store'], what);
    const head = slotOf(e.head, `${what} head`);
    const header = word(e.header, `${what} header`);
    const committee = word(e.committee, `${what} committee`);
    const startingStore = i === 0 && head === anchor.head;
    if (startingStore) {
      need(header === anchor.header && committee === anchor.committee,
        `${what}: the starting store differs from the anchor`);
      need(!('update' in e) && 'store' in e, `${what}: the starting store needs a store and no update`);
    } else {
      need(head > prev.head, `${what}: head ${head} does not follow ${prev.what} at ${prev.head}`);
      const update = word(e.update, `${what} update`);
      need(!updates.has(update), `${what}: update ${update} is listed twice`);
      updates.add(update);
    }
    const period = Math.floor(head / SLOTS_PER_PERIOD);
    need(period !== Math.floor(prev.head / SLOTS_PER_PERIOD) || committee === prev.committee,
      `${what}: sync-committee period ${period} has one committee, but this is not ${prev.what}'s`);
    if ('store' in e) {
      const rel = `lc_stores/${head}.json`;
      need(e.store === rel, `${what}: store must be ${rel}`);
      const s = checkStore(readJson(dir, rel), rel);
      need(s.head === head && s.header === header && s.committee === committee, `${rel}: not ${what}'s head, header and committee`);
      named.add(`${head}.json`);
    }
    entries.push({ head, lc: lcOf(head, header, committee), store: e.store });
    prev = { head, committee, what: `entry ${i}` };
  }
  if (existsSync(join(dir, 'lc_stores'))) {
    for (const f of readdirSync(join(dir, 'lc_stores'))) need(named.has(f), `lc_stores/${f} is named by no lc_preimages.json entry`);
  }
  const last = entries.at(-1);
  need(last.store, `the latest lc_preimages.json entry (head ${last.head}) names no store, so no proof could start from it`);
  if (atAnchor) return true;
  const cur = entries.find((e) => e.head === live.head);
  need(cur, `lc_preimages.json has no entry at the live head ${live.head}`);
  need(cur.lc === live.lc, `the entry at the live head ${live.head} does not hash to the live lc ${live.lc}`);
  need(cur.store, `the entry at the live head ${live.head} names no store`);
  return false;
}

// The published record: RECORD and RECORD_DIR name it (the Pages workflow's staged copy), else config.js INSTANCE.
const name = process.env.RECORD ?? INSTANCE?.name ?? null;
const DIR = process.env.RECORD_DIR ?? (name && fileURLToPath(new URL(`../../instances/${name}/`, import.meta.url)));
const live = name === null ? undefined : LIVE[name];
const skip = !DIR && 'no instance is published and RECORD names none, so there is no record to check';
const skipPinned = skip || (!live && `no live state is pinned for ${name} in bridge-core/test/live-state.js`);
const anchorOf = (dir) => JSON.parse(readFileSync(join(dir, 'instance.json'), 'utf8')).ANCHOR;
const skipStore = skipPinned || (!existsSync(join(DIR, 'instance.json')) && 'the record has no instance.json')
  || (live.head === anchorOf(DIR).slot && !existsSync(join(DIR, `lc_stores/${live.head}.json`))
    && 'the live state is the anchor, and no starting store is published');

/** 32 bytes derived from `label`, for the synthetic record's roots, hashes and keys. */
const fake32 = (label) => sha256(utf8(label));

/** A 48-byte public key as Helios writes it, derived from `label`; only its form is checked here. */
const fakeKey = (label) => '0x' + bytesToHex(fake32(label)) + bytesToHex(fake32(`${label}/tail`)).slice(0, 32);

const COMMITTEE = {
  pubkeys: Array.from({ length: PUBKEYS }, (_, i) => fakeKey(`committee/${i}`)),
  aggregate_pubkey: fakeKey('committee/aggregate'),
};

/** A Gloas LightClientHeader at `slot`, with roots derived from `label`, as serde_cbor's input. */
function syntheticHeader(slot, label) {
  return {
    beacon: { slot: String(slot), proposer_index: '1234', parent_root: fake32(`${label}/parent`),
      state_root: fake32(`${label}/state`), body_root: fake32(`${label}/body`) },
    execution_block_hash: fake32(`${label}/block`),
    execution_branch: Array.from({ length: EXECUTION_BRANCH }, (_, i) => fake32(`${label}/branch/${i}`)),
  };
}

/** A store file for a store finalized at `slot`, whose head, header, committee and lc its CBOR recomputes. */
function syntheticStore(slot) {
  const store = {
    finalized_header: syntheticHeader(slot, `store/${slot}`),
    current_sync_committee: COMMITTEE,
    next_sync_committee: null,
    optimistic_header: syntheticHeader(slot + 1, `store/${slot}/optimistic`),
    previous_max_active_participants: 400n,
    current_max_active_participants: 410n,
    best_valid_update: null,
  };
  const cbor = encodeCbor(store);
  const r = storeRoots(cbor);
  return { head: slot, header: r.header, committee: r.committee, lc: lcOf(slot, r.header, r.committee), store_cbor: '0x' + bytesToHex(cbor) };
}

/**
 * A record directory with an anchor and three confirmed updates in the anchor's sync-committee period, each with
 * its store published, the last one live: what the refusal cases below edit. Returns { dir, live }.
 */
function syntheticRecord() {
  const dir = mkdtempSync(join(tmpdir(), 'lc-synthetic-'));
  const anchor = syntheticStore(SLOTS_PER_PERIOD * 1400 + 256);
  const pin = { header: anchor.header, committee: anchor.committee, lc: anchor.lc };
  writeFileSync(join(dir, 'instance.json'), JSON.stringify({ ANCHOR: { slot: anchor.head, ...pin } }));
  writeFileSync(join(dir, 'initial_state.json'), JSON.stringify({ head: anchor.head, ...pin }));
  mkdirSync(join(dir, 'lc_stores'));
  const preimages = [1, 2, 3].map((k) => {
    const s = syntheticStore(anchor.head + 256 * k);
    const store = `lc_stores/${s.head}.json`;
    writeFileSync(join(dir, store), JSON.stringify(s));
    return { head: s.head, header: s.header, committee: s.committee, update: bytesToHex(fake32(`update/${k}`)), store };
  });
  writeFileSync(join(dir, 'lc_preimages.json'), JSON.stringify({ preimages }));
  const last = syntheticStore(preimages.at(-1).head);
  return { dir, live: { head: last.head, lc: last.lc } };
}

const FIXTURE = syntheticRecord();
after(() => rmSync(FIXTURE.dir, { recursive: true, force: true }));

test('the published record carries the live light-client store', { skip }, (t) => {
  assert.ok(live, `no live state is pinned for instances/${name}/ in bridge-core/test/live-state.js`);
  const atAnchor = checkRecord(DIR, live);
  t.diagnostic(`live head ${live.head} is the reviewed pin in bridge-core/test/live-state.js; Liquid is not queried`);
  if (atAnchor) t.diagnostic('no update confirmed: the live state is the anchor; its first proof uses the published starting store or a beacon bootstrap');
});

test('the published anchor\'s lc is the hash the covenant pinned', { skip: skipPinned }, () => {
  // The anchor's lc is pinned by the covenant (manifest initial state); a wrong LC_TAG or byte order fails here.
  const a = anchorOf(DIR);
  assert.equal(lcOf(a.slot, a.header, a.committee), a.lc);
});

test('the published live store re-encodes byte for byte and has its period\'s committee', { skip: skipStore }, () => {
  // The re-encoder that the refusal cases below edit stores with reproduces serde_cbor's bytes.
  const s = JSON.parse(readFileSync(join(DIR, `lc_stores/${live.head}.json`), 'utf8'));
  assert.equal('0x' + bytesToHex(encodeCbor(decodeCbor(hexToBytes(s.store_cbor)))), s.store_cbor);
  // A live head in its anchor's sync-committee period must carry the anchor's committee root.
  const a = anchorOf(DIR);
  if (Math.floor(live.head / SLOTS_PER_PERIOD) === Math.floor(a.slot / SLOTS_PER_PERIOD)) {
    assert.equal(storeRoots(hexToBytes(s.store_cbor)).committee, a.committee);
  }
});

test('before the first update, only the anchor is live and no store may be published unnamed', () => {
  // A copy of the synthetic record with its update history removed is a record at its anchor.
  const { ANCHOR: a } = JSON.parse(readFileSync(join(FIXTURE.dir, 'instance.json'), 'utf8'));
  const atAnchor = { head: a.slot, lc: a.lc };
  const bare = (d) => { unlinkSync(join(d, 'lc_preimages.json')); rmSync(join(d, 'lc_stores'), { recursive: true }); };
  const dir = mkdtempSync(join(tmpdir(), 'lc-record-'));
  try {
    cpSync(FIXTURE.dir, dir, { recursive: true });
    bare(dir);
    assert.equal(checkRecord(dir, atAnchor), true);
    // Stores published ahead of the first update are checked, and none is called live.
    assert.equal(checkRecord(FIXTURE.dir, atAnchor), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  refused(bare, /at the anchor slot .* its lc is not the anchor's/, { ...atAnchor, lc: flip(a.lc) });
  refused((d) => unlinkSync(join(d, 'lc_preimages.json')), /lc_stores\/ is published, but no lc_preimages.json/, atAnchor);
  // Past the anchor, a record without its history is refused.
  refused(bare, /lc_preimages.json is missing/);
});

test('a named starting store at the anchor is usable without an update transaction', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lc-starting-store-'));
  try {
    cpSync(FIXTURE.dir, dir, { recursive: true });
    const anchor = anchorOf(dir);
    const store = syntheticStore(anchor.slot);
    const hints = JSON.parse(readFileSync(join(dir, 'lc_preimages.json'), 'utf8'));
    writeFileSync(join(dir, `lc_stores/${anchor.slot}.json`), JSON.stringify(store));
    hints.preimages.unshift({ head: anchor.slot, header: anchor.header, committee: anchor.committee,
      store: `lc_stores/${anchor.slot}.json` });
    writeFileSync(join(dir, 'lc_preimages.json'), JSON.stringify(hints));
    assert.equal(checkRecord(dir, { head: anchor.slot, lc: anchor.lc }), true);
    assert.equal(checkRecord(dir, FIXTURE.live), false);

    hints.preimages[0].update = bytesToHex(fake32('not-an-initial-update'));
    writeFileSync(join(dir, 'lc_preimages.json'), JSON.stringify(hints));
    assert.throws(() => checkRecord(dir, FIXTURE.live), /starting store needs a store and no update/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function flip(h) {
  return h.slice(0, -1) + (h.endsWith('0') ? '1' : '0');
}

/** store_cbor with the first ASCII decimal digit after `marker` (CBOR hex, byte-aligned) changed to another. */
function bumpDigit(cbor, marker) {
  const h = cbor.slice(2);
  const at = h.indexOf(marker);
  assert.ok(at >= 0 && at % 2 === 0, `store_cbor has ${marker}`);
  for (let i = at + marker.length; i < h.length; i += 2) {
    const c = parseInt(h.slice(i, i + 2), 16);
    if (c >= 0x30 && c <= 0x39) return '0x' + h.slice(0, i) + (c === 0x39 ? 0x38 : c + 1).toString(16) + h.slice(i + 2);
  }
  throw new Error('no digit to change');
}

const textKey = (k) => bytesToHex(utf8(k));

/** decodeCbor's inverse, with the shortest heads, as serde_cbor writes them. */
function encodeCbor(v) {
  const out = [];
  const head = (major, n) => {
    const x = BigInt(n);
    const w = x < 24n ? 0 : x < 0x100n ? 1 : x < 0x10000n ? 2 : x < 0x100000000n ? 4 : 8;
    out.push((major << 5) | (w ? 24 + Math.log2(w) : Number(x)));
    if (w) out.push(...bigToBytes(x, w));
  };
  const item = (x) => {
    if (typeof x === 'bigint') head(0, x);
    else if (x instanceof Uint8Array) { head(2, x.length); out.push(...x); }
    else if (typeof x === 'string') { const s = utf8(x); head(3, s.length); out.push(...s); }
    else if (Array.isArray(x)) { head(4, x.length); x.forEach(item); }
    else if (x === null) out.push(0xf6);
    else if (typeof x === 'boolean') out.push(x ? 0xf5 : 0xf4);
    else { const ks = Object.keys(x); head(5, ks.length); for (const k of ks) { item(k); item(x[k]); } }
  };
  item(v);
  return Uint8Array.from(out);
}

/** Decodes the store file's CBOR, applies `edit(store)` and writes it back re-encoded. */
function editStore(dir, rel, edit) {
  editJson(dir, rel, (s) => {
    const store = decodeCbor(hexToBytes(s.store_cbor));
    edit(store);
    s.store_cbor = '0x' + bytesToHex(encodeCbor(store));
  });
}

/** Copies the synthetic record, applies `edit(dir)` and expects checkRecord to refuse the copy with `message`. */
function refused(edit, message, pin = FIXTURE.live) {
  const dir = mkdtempSync(join(tmpdir(), 'lc-record-'));
  try {
    cpSync(FIXTURE.dir, dir, { recursive: true });
    edit(dir);
    assert.throws(() => checkRecord(dir, pin), message);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function editJson(dir, rel, edit) {
  const path = join(dir, rel);
  const doc = JSON.parse(readFileSync(path, 'utf8'));
  edit(doc);
  writeFileSync(path, JSON.stringify(doc));
}

test('a missing, altered or unnamed light-client store is refused', () => {
  const { dir: source, live } = FIXTURE;
  const store = `lc_stores/${live.head}.json`;
  const entry = (d) => d.preimages.find((p) => p.head === live.head);
  const latest = (d) => d.preimages.at(-1);
  // The synthetic record passes, and still does once its store is decoded and re-encoded, so each editStore case
  // below differs only by its edit.
  assert.equal(checkRecord(source, live), false);
  const copy = mkdtempSync(join(tmpdir(), 'lc-record-'));
  try {
    cpSync(source, copy, { recursive: true });
    editStore(copy, store, () => {});
    assert.equal(readFileSync(join(copy, store), 'utf8'), readFileSync(join(source, store), 'utf8'));
    checkRecord(copy, live);
  } finally {
    rmSync(copy, { recursive: true, force: true });
  }
  for (const [edit, message] of [
    [(d) => unlinkSync(join(d, 'lc_preimages.json')), /lc_preimages.json is missing/],
    [(d) => writeFileSync(join(d, 'lc_preimages.json'), '{"preimages": ['), /lc_preimages.json is not valid JSON/],
    [(d) => editJson(d, 'lc_preimages.json', (j) => { j.preimages = []; }), /non-empty list/],
    [(d) => unlinkSync(join(d, store)), new RegExp(`${store} is missing`)],
    [(d) => editJson(d, 'lc_preimages.json', (j) => { entry(j).store = `../${store}`; }), /store must be/],
    [(d) => editJson(d, 'lc_preimages.json', (j) => { entry(j).store = '/etc/passwd'; }), /store must be/],
    [(d) => { unlinkSync(join(d, store)); symlinkSync(join(source, store), join(d, store)); }, /symbolic link/],
    [(d) => writeFileSync(join(d, 'lc_stores', '1.json'), '{}'), /lc_stores\/1.json is named by no/],
    [(d) => editJson(d, 'lc_preimages.json', (j) => { unlinkSync(join(d, latest(j).store)); delete latest(j).store; }),
      /latest lc_preimages.json entry .* names no store/],
    [(d) => editJson(d, 'lc_preimages.json', (j) => { entry(j).header = flip(entry(j).header); }), /not lc_preimages.json entry \d+'s head, header and committee/],
    [(d) => editJson(d, 'lc_preimages.json', (j) => { entry(j).committee = flip(entry(j).committee); }), /committee/],
    [(d) => editJson(d, 'lc_preimages.json', (j) => { entry(j).head -= 1; }), /store must be/],
    [(d) => editJson(d, 'lc_preimages.json', (j) => { j.preimages.push(structuredClone(entry(j))); }), /does not follow/],
    [(d) => editJson(d, 'instance.json', (j) => { j.ANCHOR.lc = flip(j.ANCHOR.lc); }), /ANCHOR.lc/],
    [(d) => editJson(d, store, (s) => { s.head += 1; }), /not the file's head/],
    [(d) => editJson(d, store, (s) => { s.header = flip(s.header); }), /not the file's header/],
    [(d) => editJson(d, store, (s) => { s.committee = flip(s.committee); }), /not the file's committee/],
    [(d) => editJson(d, store, (s) => { s.lc = flip(s.lc); }), /lc is not the hash/],
    [(d) => editJson(d, store, (s) => { delete s.store_cbor; }), /no store_cbor/],
    [(d) => editJson(d, store, (s) => { s.store_cbor = '0x00'; }), /store_cbor store: a map/],
    [(d) => editJson(d, store, (s) => { s.store_cbor += '00'; }), /trailing bytes/],
    [(d) => editJson(d, store, (s) => { s.store_cbor = s.store_cbor.slice(0, -2); }), /truncated|past the end/],
    // One digit of the finalized header's proposer index, and one hex digit of the first committee key.
    [(d) => editJson(d, store, (s) => { s.store_cbor = bumpDigit(s.store_cbor, textKey('proposer_index')); }), /not the file's header/],
    [(d) => editJson(d, store, (s) => { s.store_cbor = bumpDigit(s.store_cbor, textKey('pubkeys') + '9902007862' + textKey('0x')); }),
      /not the file's committee/],
    // Stores whose roots still match but that the host's serde_cbor decoding of LightClientStore refuses.
    [(d) => editStore(d, store, (s) => { delete s.finalized_header.execution_branch; }), /finalized_header: no execution_branch/],
    [(d) => editStore(d, store, (s) => { s.finalized_header.execution_branch.pop(); }), /finalized_header.execution_branch: 11 roots/],
    [(d) => editStore(d, store, (s) => { s.finalized_header.execution_block_hash = '0x' + bytesToHex(s.finalized_header.execution_block_hash); }),
      /finalized_header.execution_block_hash: a 32-byte byte string/],
    [(d) => editStore(d, store, (s) => { s.finalized_header.beacon.slot = BigInt(s.finalized_header.beacon.slot); }),
      /finalized_header.beacon.slot: a uint64 as decimal text/],
    [(d) => editStore(d, store, (s) => { s.optimistic_header.beacon.proposer_index = BigInt(s.optimistic_header.beacon.proposer_index); }),
      /optimistic_header.beacon.proposer_index: a uint64 as decimal text/],
    [(d) => editStore(d, store, (s) => { s.optimistic_header.execution = s.optimistic_header.execution_block_hash; }),
      /optimistic_header: unexpected key execution/],
    [(d) => editStore(d, store, (s) => { delete s.optimistic_header; }), /store: no optimistic_header/],
    [(d) => editStore(d, store, (s) => { s.current_sync_committee.aggregate_pubkey = hexToBytes(s.current_sync_committee.aggregate_pubkey); }),
      /aggregate_pubkey: a 0x hex 48-byte public key/],
    [(d) => editStore(d, store, (s) => { s.next_sync_committee = s.current_sync_committee; }), /no next sync committee/],
    [(d) => editStore(d, store, (s) => { s.current_max_active_participants = String(s.current_max_active_participants); }),
      /current_max_active_participants: a CBOR unsigned integer/],
    [(d) => editStore(d, store, (s) => { s.best_valid_update = 'junk'; }), /best_valid_update: null/],
    [(d) => editStore(d, store, (s) => { s.best_valid_update = {}; }), /best_valid_update: null/],
    [(d) => editStore(d, store, (s) => { delete s.best_valid_update; }), /store: no best_valid_update/],
    [(d) => editStore(d, store, (s) => { s.extra = null; }), /store: unexpected key extra/],
  ]) {
    refused(edit, message);
  }
  // A record that stops before the live head, or whose entry there is not the live lc.
  refused(() => {}, /no entry at the live head/, { ...live, head: live.head + 32 });
  refused(() => {}, /does not hash to the live lc/, { ...live, lc: flip(live.lc) });
});
