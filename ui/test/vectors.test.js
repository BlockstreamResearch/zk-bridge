// The UI's protocol code against the shared golden vectors, vectors/protocol.json: the domain tags it uses, the
// light-client commitment, the claimed tree's root, the state hash and the burn script. The other sections (token
// blindings, deposit domain) are values this page reads from the instance record or the escrow, not ones it derives.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { BURN_TAG, burnTarget } from '../lib/bridge.js';
import { bytesToHex, utf8 } from '../lib/bytes.js';
import { sha256 } from '../lib/hash.js';
import { EMPTY_CLAIMED_ROOT, TAGS, claimedRoot, lcOf, stateHash } from '../lib/update.js';

const V = JSON.parse(readFileSync(new URL('../../vectors/protocol.json', import.meta.url), 'utf8'));
const bare = (hex) => {
  assert.match(hex, /^0x[0-9a-f]*$/, 'every vector output is recorded, as 0x-prefixed lowercase hex');
  return hex.slice(2);
};

test('the tags this page hashes are the protocol\'s', () => {
  assert.deepEqual(TAGS, { lc: V.tags.lc, state: V.tags.state, claimed: V.tags.claimed });
  assert.equal(BURN_TAG, V.tags.burn);
  const used = V.tag_sha256.filter((c) => c.tag in TAGS);
  assert.deepEqual(used.map((c) => c.tag).sort(), Object.keys(TAGS).sort());
  for (const c of used) assert.equal(bytesToHex(sha256(utf8(TAGS[c.tag]))), bare(c.sha256), c.tag);
});

test('lc is the protocol\'s light-client commitment', () => {
  assert.ok(V.lc.length > 0);
  for (const c of V.lc) assert.equal(lcOf(c.slot, bare(c.header), bare(c.committee)), bare(c.lc), `slot ${c.slot}`);
});

test('the claimed root is the protocol\'s, whatever order deposits are claimed in', () => {
  assert.ok(V.claimed_root.length > 0);
  for (const c of V.claimed_root) {
    assert.equal(claimedRoot(c.indices), bare(c.root), `indices ${c.indices}`);
    assert.equal(claimedRoot([...c.indices].reverse()), bare(c.root), `indices ${c.indices} reversed`);
  }
  assert.equal(EMPTY_CLAIMED_ROOT, bare(V.claimed_root.find((c) => c.indices.length === 0).root));
  // Every index is a slot of the depth-32 tree, set at most once.
  assert.throws(() => claimedRoot([2 ** 32]), /outside the claimed tree/);
  assert.throws(() => claimedRoot([-1]), /outside the claimed tree/);
  assert.throws(() => claimedRoot([1.5]), /outside the claimed tree/);
  assert.throws(() => claimedRoot([3, 3]), /claimed twice/);
});

test('the state hash commits lc, accumulator and claimed root', () => {
  assert.ok(V.state_hash.length > 0);
  for (const c of V.state_hash) {
    const claimed = claimedRoot(c.indices);
    assert.equal(claimed, bare(c.claimed_root), `indices ${c.indices}`);
    assert.equal(stateHash({ lc: bare(c.lc), acc: bare(c.acc), claimedRoot: claimed }), bare(c.state_hash));
  }
});

test('the burn script is the protocol\'s', () => {
  assert.ok(V.burn_script.length > 0);
  for (const c of V.burn_script) {
    assert.equal(bytesToHex(burnTarget(BigInt(c.chain_id), c.escrow, c.recipient).scriptPubKey), bare(c.script), `chain ${c.chain_id}`);
  }
});
