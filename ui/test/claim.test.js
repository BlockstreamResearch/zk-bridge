// Sending a claim with Humid (lib/claim.js). The instance and its transactions are made up, in the claim leaf's
// shape: a state output holding the bridge token in one blinding, a claim spending it with the claim leaf and
// reissuing a deposit's units, and an open fee coin (test/liquid-tx.js). The PSET is read back with
// test/pset-reader.js, and its transaction rebuilt here from the Elements PSET fields rather than from lib/claim.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeSegwit } from '../lib/bech32.js';
import { bigToBytes, bytesToHex, concat, hexToBytes } from '../lib/bytes.js';
import { LIQUID_TESTNET_LBTC } from '../lib/bridge.js';
import { displayHex, parseTransaction, readWitness } from '../lib/elements.js';
import { Esplora } from '../lib/esplora.js';
import { HUMID_SCOPE, explicitTxOut, humidError } from '../lib/humid.js';
import { HUMID_MAX_PSET, MAX_FEE_SATS } from '../lib/update.js';
import {
  claimError, claimOnLiquid, claimParams, claimPset, depositClaims, prepareClaim, readClaim, sendClaim, siteReader,
} from '../lib/claim.js';
import { ELEMENTS, readPset } from './pset-reader.js';
import { NUMS, blinded, cat, explicit, filler, hex, signedWitness, transaction, word } from './liquid-tx.js';

// ---- a made-up instance and its claims ----

const ASSET = hex(word('bridge asset')); // internal order
const ENTROPY = word('bridge asset entropy');
const MANIFEST = {
  claim_leaf: { cmr: word('claim leaf') },
  bootstrap: { asset: bytesToHex(ASSET), entropy: ENTROPY },
  harness_config: { abf_a: word('token blinding A'), abf_b: word('token blinding B') },
  // The token's asset commitment in each blinding, and its value commitment, as `bit` (the prefix's low bit) and x.
  constants: {
    token_a: { bit: 1, x: word('token A') }, token_b: { bit: 0, x: word('token B') }, token_value: { bit: 1, x: word('token value') },
  },
};
const MANIFEST_TEXT = JSON.stringify(MANIFEST);
const P = claimParams(MANIFEST);
const commitment = (base, { bit, x }) => cat([base | bit], hex(x));
const TOKEN = [commitment(0x0a, MANIFEST.constants.token_a), commitment(0x0a, MANIFEST.constants.token_b)];
const TOKEN_VALUE = commitment(0x08, MANIFEST.constants.token_value);

const FEE_SCRIPT = '0014' + word('fee key').slice(0, 40); // the fee coin's P2WPKH
const RECIPIENT = '0014' + word('humid key').slice(0, 40); // the Humid wallet's P2WPKH that output 1 pays
const UNITS = 100_000n;
const LBTC = hexToBytes(LIQUID_TESTNET_LBTC);
const OTHER = 'ee'.repeat(32);
const p2tr = (label) => hex('5120' + word(label));

/**
 * An update whose output 0 is the state, the token in blinding `phase` (0 for A, 1 for B): inputs [the state before,
 * its signed fee coin], outputs [the state, the fee].
 */
const stateTx = (phase) => transaction({
  inputs: [
    { txid: word(`state parent ${phase}`), vout: 0, witness: [filler('update witness', 240), filler('update program', 900)] },
    { txid: word(`update fee ${phase}`), vout: 0, witness: signedWitness(`update fee ${phase}`) },
  ],
  outputs: [blinded(TOKEN[phase], TOKEN_VALUE, p2tr(`state ${phase}`), `state ${phase}`), explicit(LBTC, 12_000n, new Uint8Array(0))],
});

/** An open fee coin of 2,000 sats at FEE_SCRIPT, output 0 of a signed split: its change, then its own fee. */
const FEE = transaction({
  inputs: [{ txid: word('fee funding'), vout: 1, witness: signedWitness('fee funding') }],
  outputs: [explicit(LBTC, 2_000n, hex(FEE_SCRIPT)), explicit(LBTC, 9_700n, hex(FEE_SCRIPT)), explicit(LBTC, 300n, new Uint8Array(0))],
});

/**
 * The claim of UNITS to RECIPIENT spending output 0 of `state`, whose token is in blinding `phase`: input 0 spends it
 * with the claim leaf, revealing that blinding as its reissuance nonce; input 1 is FEE's open coin, unsigned.
 */
function claimTx(state, phase) {
  const control = cat([0xbe], hex(NUMS), hex(word('update leaf hash')), hex(word(`state leaf ${phase}`)));
  return transaction({
    inputs: [
      {
        txid: state.txid, vout: 0, issuance: { nonce: P.blindings[phase], entropy: P.entropy, amount: UNITS, inflation: null },
        witness: [filler(`claim witness ${phase}`, 1_200), filler('claim program', 1_636), P.cmr, control],
      },
      { txid: FEE.txid, vout: 0 },
    ],
    outputs: [
      blinded(TOKEN[1 - phase], TOKEN_VALUE, p2tr(`successor ${phase}`), `successor ${phase}`),
      explicit(ASSET, UNITS, hex(RECIPIENT)),
      explicit(LBTC, 2_000n, new Uint8Array(0)),
    ],
  });
}

const STATE = stateTx(0);
const STATE_B = stateTx(1);
const STATE_TXID = STATE.txid;
const STATE_TX = STATE.hex;
const FEE_TXID = FEE.txid;
const FEE_TX = FEE.hex;
const CLAIM_TX = claimTx(STATE, 0);
const CLAIM_TXID = CLAIM_TX.txid;
const CLAIM = CLAIM_TX.raw;
const CLAIM_B = claimTx(STATE_B, 1);

const compactSizeLength = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : 5);
const stackLength = (items) => compactSizeLength(items.length)
  + items.reduce((s, x) => s + compactSizeLength(x.length) + x.length, 0);
/** CLAIM with `bytes` written at byte `at`. */
const patched = (at, bytes) => {
  const m = Uint8Array.from(CLAIM);
  m.set(bytes, at);
  return m;
};
const leafPrefix = (p) => `${bytesToHex(p.cmr).slice(0, 8)}…`;

/**
 * The transaction a claim's PSET describes, in txid serialization, from BIP 370 and Elements' PSET fields: an input
 * with PSBT_ELEMENTS_IN_ISSUANCE_VALUE (fc04pset00, little-endian) issues, with the outpoint flag 0x80000000, its
 * blinding nonce (0c) and entropy (0d), that explicit amount and no inflation keys; an output is either blinded already
 * (value and asset commitments, 01 and 03) or explicit.
 */
function psetClaimTransaction({ global, inputs, outputs }) {
  const varBytes = (b) => concat([b.length], b);
  const be = (le) => Uint8Array.from(le).reverse();
  return concat(
    global.get('02'), [0x00], [inputs.length],
    ...inputs.map((m) => {
      const issues = m.has(`${ELEMENTS}00`);
      const index = Uint8Array.from(m.get('0f'));
      if (issues) index[3] |= 0x80;
      return concat(m.get('0e'), index, [0x00], m.get('10') ?? [0xff, 0xff, 0xff, 0xff],
        ...(issues ? [m.get(`${ELEMENTS}0c`), m.get(`${ELEMENTS}0d`), [0x01], be(m.get(`${ELEMENTS}00`)), [0x00]] : []));
    }),
    [outputs.length],
    ...outputs.map((m) => (m.has(`${ELEMENTS}01`)
      ? concat(m.get(`${ELEMENTS}03`), m.get(`${ELEMENTS}01`), [0x00], varBytes(m.get('04')))
      : concat([0x01], m.get(`${ELEMENTS}02`), [0x01], be(m.get('03')), [0x00], varBytes(m.get('04'))))),
    global.get('03') ?? [0, 0, 0, 0],
  );
}

test('claimParams reads the claim leaf, the bridge asset and its token in both phases from a manifest', () => {
  assert.equal(bytesToHex(P.cmr), MANIFEST.claim_leaf.cmr);
  assert.equal(bytesToHex(P.asset), MANIFEST.bootstrap.asset);
  assert.equal(bytesToHex(P.entropy), MANIFEST.bootstrap.entropy);
  assert.deepEqual(P.blindings.map(bytesToHex), [MANIFEST.harness_config.abf_a, MANIFEST.harness_config.abf_b]);
  // The manifest gives each commitment as its prefix's low bit and x: 0x0a/0x0b for an asset, 0x08/0x09 a value.
  const { token_a: a, token_b: b, token_value: v } = MANIFEST.constants;
  const point = (base, { bit, x }) => (base | bit).toString(16).padStart(2, '0') + x;
  assert.deepEqual(P.tokens.map(bytesToHex), [point(0x0a, a), point(0x0a, b)]);
  assert.equal(bytesToHex(P.tokenValue), point(0x08, v));
  assert.throws(() => claimParams({ ...MANIFEST, claim_leaf: {} }), /names no claim leaf/);
  assert.throws(() => claimParams({ ...MANIFEST, constants: { ...MANIFEST.constants, token_b: { bit: 2, x: b.x } } }),
    /no bridge token commitments/);
});

test('the claim: its txid, the leaf and reissuance of input 0, the state and fee coin it spends, what it pays', () => {
  const c = readClaim(CLAIM, P);
  assert.equal(c.txid, CLAIM_TXID);
  assert.deepEqual([c.state.txid, c.state.vout], [STATE_TXID, 0]);
  assert.deepEqual(c.fee, { txid: FEE_TXID, vout: 0, sats: 2_000n });
  assert.equal(c.witness.length, 4);
  assert.equal(bytesToHex(c.witness[2]), MANIFEST.claim_leaf.cmr, 'item 2 is the claim leaf CMR');
  // A control block of depth 2, {{update, claim}, state}: the internal key, the update leaf, then the state leaf.
  assert.equal(c.witness[3].length, 97);
  assert.equal(bytesToHex(c.witness[3].subarray(1, 33)), NUMS);
  assert.equal(bytesToHex(c.issuance.nonce), MANIFEST.harness_config.abf_a, 'the spent token is in phase A');
  assert.equal(bytesToHex(c.issuance.entropy), MANIFEST.bootstrap.entropy);
  assert.equal(c.issuance.units, UNITS);
  assert.equal(bytesToHex(c.state.token), bytesToHex(P.tokens[0]));
  assert.equal(bytesToHex(c.successor.blinded.assetCommitment), bytesToHex(P.tokens[1]),
    'the successor holds the token in phase B');
  assert.deepEqual([bytesToHex(c.mint.script), c.mint.units], [RECIPIENT, UNITS]);
  assert.equal(c.mint.address, encodeSegwit('tex', 0, hexToBytes(RECIPIENT).subarray(2)));
});

test('the PSET: input 0 final with the claim\'s own witness and reissuance, input 1 the open fee coin', () => {
  const c = readClaim(CLAIM, P);
  const plan = claimPset(c, STATE_TX, FEE_TX);
  const feeAddress = encodeSegwit('tex', 0, hexToBytes(FEE_SCRIPT).subarray(2));
  assert.deepEqual([plan.txid, plan.feeAddress], [CLAIM_TXID, feeAddress]);
  assert.equal(plan.successorAddress, encodeSegwit('tex', 1, c.successor.script.subarray(2)));
  assert.deepEqual(plan.signInputs, [{ address: feeAddress, index: 1, sighashTypes: [1] }],
    'Humid is asked to sign the fee coin alone, SIGHASH_ALL');
  assert.ok(plan.pset.length < HUMID_MAX_PSET, `${plan.pset.length} base64 characters`);

  const pset = readPset(plan.pset);
  assert.deepEqual([...pset.global].map(([k, v]) => [k, bytesToHex(v)]),
    [['02', '02000000'], ['04', '02'], ['05', '03'], ['fb', '02000000']]);
  assert.deepEqual(pset.inputs.map((m) => [...m.keys()]), [
    ['01', '0e', '0f', `${ELEMENTS}00`, `${ELEMENTS}0c`, `${ELEMENTS}0d`, `${ELEMENTS}15`, '08'],
    ['01', '0e', '0f'],
  ]);
  const state = parseTransaction(hexToBytes(STATE_TX));
  assert.equal(bytesToHex(pset.inputs[0].get('01')), bytesToHex(state.outputs[0].raw),
    'input 0\'s witness UTXO is the state output it spends');
  assert.equal(bytesToHex(pset.inputs[0].get('0f')), '00000000',
    'the PSET index is the bare output number; the issuance flag is the transaction\'s');
  assert.equal(bytesToHex(pset.inputs[0].get(`${ELEMENTS}00`)), bytesToHex(bigToBytes(UNITS, 8).reverse()));
  assert.equal(bytesToHex(pset.inputs[0].get(`${ELEMENTS}0c`)), MANIFEST.harness_config.abf_a);
  assert.equal(bytesToHex(pset.inputs[0].get(`${ELEMENTS}0d`)), MANIFEST.bootstrap.entropy);
  assert.equal(bytesToHex(pset.inputs[0].get(`${ELEMENTS}15`)), '00',
    'the reissuance is marked not to be blinded, as LWK marks its own');
  assert.equal(bytesToHex(pset.inputs[1].get('01')), bytesToHex(explicitTxOut(LBTC, 2_000n, hexToBytes(FEE_SCRIPT))));
  // PSBT_IN_FINAL_SCRIPTWITNESS holds the stack exactly as the claim serializes it: after input 0's two empty issuance
  // proofs, and followed by its empty peg-in witness and input 1's four empty fields.
  const final = pset.inputs[0].get('08');
  const at = parseTransaction(CLAIM).witnessAt + 2;
  assert.ok(final.length > 1_000, 'the program and its witness');
  assert.equal(bytesToHex(CLAIM.subarray(at, at + final.length)), bytesToHex(final));
  assert.equal(bytesToHex(CLAIM.subarray(at + final.length, at + final.length + 5)), '0000000000');

  // Output 0 is blinded already; outputs 1 and 2 are open. None carries a blinding key, so Humid blinds nothing.
  assert.deepEqual(pset.outputs.map((m) => [...m.keys()]), [
    ['04', `${ELEMENTS}01`, `${ELEMENTS}03`, `${ELEMENTS}04`, `${ELEMENTS}05`],
    ['03', `${ELEMENTS}02`, '04'],
    ['03', `${ELEMENTS}02`, '04'],
  ]);
  const proofs = readWitness(CLAIM).outputs[0];
  assert.equal(bytesToHex(pset.outputs[0].get(`${ELEMENTS}04`)), bytesToHex(proofs.rangeproof));
  assert.equal(bytesToHex(pset.outputs[0].get(`${ELEMENTS}05`)), bytesToHex(proofs.surjectionProof));
  assert.deepEqual([bytesToHex(pset.outputs[1].get(`${ELEMENTS}02`)), bytesToHex(pset.outputs[1].get('04'))],
    [MANIFEST.bootstrap.asset, RECIPIENT]);
  assert.deepEqual([bytesToHex(pset.outputs[2].get('03')), bytesToHex(pset.outputs[2].get('04'))],
    [bytesToHex(bigToBytes(2_000n, 8).reverse()), '']);
  // What Humid extracts after signing, which adds only witnesses, is the claim itself.
  const tx = parseTransaction(psetClaimTransaction(pset));
  assert.equal(displayHex(tx.txid), CLAIM_TXID);
  assert.equal(bytesToHex(tx.txidForm), bytesToHex(parseTransaction(CLAIM).txidForm));
});

test('Humid\'s wallet moves only the fee coin: it signs input 1 alone, which pays only the fee', () => {
  const c = readClaim(CLAIM, P);
  const plan = claimPset(c, STATE_TX, FEE_TX);
  const tx = parseTransaction(psetClaimTransaction(readPset(plan.pset)));
  const fee = tx.outputs[2];
  assert.deepEqual([fee.script.length, fee.value.amount], [0, 2_000n],
    'the whole fee coin is the fee: no change, nothing else paid from it');
  assert.ok(tx.outputs.every((o) => o.nonce.kind === 'null'), 'no output names a blinding key');
  const lbtcOut = tx.outputs.filter((o) => o.asset.kind === 'explicit' && bytesToHex(o.asset.data) === LIQUID_TESTNET_LBTC);
  assert.deepEqual(lbtcOut.map((o) => o.value.amount), [2_000n], 'the only tL-BTC out is the fee');
  assert.equal(tx.inputs[1].issuance, null);
  assert.deepEqual(plan.signInputs.map((i) => i.index), [1]);
});

test('only an unsigned claim of this instance, within the fee limit, is read', () => {
  const tx = parseTransaction(CLAIM);
  assert.throws(() => readClaim(CLAIM, { ...P, cmr: new Uint8Array(32) }),
    new RegExp(`spends with Simplicity leaf ${leafPrefix(P)}, not this instance's claim leaf 00000000…`));
  assert.throws(() => readClaim(tx.txidForm, P), /carries no witness/);
  assert.throws(() => readClaim(hexToBytes(FEE_TX), P), /two inputs, the state and the fee, and three outputs/);
  assert.throws(() => readClaim(hexToBytes(STATE_TX), P), /three outputs/, 'an update is not a claim');
  assert.throws(() => readClaim(patched(tx.witnessAt - 4, [1, 0, 0, 0]), P), /locktime 0/);
  // Under its own leaf, another instance's entropy, asset, blinding or tokens is still refused.
  assert.throws(() => readClaim(CLAIM, { ...P, entropy: hexToBytes(OTHER) }), /issues another asset/);
  assert.throws(() => readClaim(CLAIM, { ...P, asset: hexToBytes(OTHER) }),
    /does not pay the reissued units of the bridge asset/);
  assert.throws(() => readClaim(CLAIM, { ...P, blindings: [P.blindings[1], P.blindings[1]] }),
    /not a reissuance with the bridge token's public blinding/);
  assert.throws(() => readClaim(CLAIM, { ...P, tokens: [P.tokens[0], P.tokens[0]] }), /output 0 is not a successor state/);
  // Read as if the spent token were in phase B, the successor must be in phase A: it is not.
  assert.throws(() => readClaim(CLAIM, { ...P, blindings: [P.blindings[1], P.blindings[0]] }),
    /output 0 is not a successor state/);

  // Input 1 with a signature: the fee key's claim.signed.hex, which needs no Humid.
  const items = readWitness(CLAIM).inputs[0].script;
  const input1 = tx.witnessAt + 2 + stackLength(items) + 1 + 2; // past input 0, then input 1's two issuance proofs
  assert.equal(CLAIM[input1], 0, 'input 1\'s empty stack');
  const signed = concat(CLAIM.subarray(0, input1), [2, 1, 0xaa, 1, 0xbb], CLAIM.subarray(input1 + 1));
  assert.throws(() => readClaim(signed, P), /input 1 is signed already/);

  // Output 1: asset (1 + 32 bytes), value (1 + 8), nonce (1), then the script's length and the script.
  const mint = tx.outputs[1].raw.byteOffset;
  assert.throws(() => readClaim(patched(mint + 34, bigToBytes(UNITS + 1n, 8)), P), /does not pay the reissued units/);
  assert.throws(() => readClaim(patched(mint + 1, [0x48]), P), /does not pay the reissued units/);
  assert.throws(() => readClaim(patched(mint + 44, [0x6a]), P), /not pay a standard wallet script/);
  // The fee is output 2's explicit value.
  const feeValue = tx.outputs[2].raw.byteOffset + 34;
  assert.equal(readClaim(patched(feeValue, bigToBytes(MAX_FEE_SATS, 8)), P).fee.sats, MAX_FEE_SATS);
  assert.throws(() => readClaim(patched(feeValue, bigToBytes(MAX_FEE_SATS + 1n, 8)), P),
    /pays 50001 sats of fee; this page sends at most 50000/);
  assert.throws(() => readClaim(patched(tx.outputs[2].raw.byteOffset + 1, [0x48]), P),
    /output 2 is not an open tL-BTC fee/);
});

test('a claim spending the token in phase B reissues with phase B\'s blinding and leaves the token in phase A', () => {
  const c = readClaim(CLAIM_B.raw, P);
  assert.equal(c.txid, CLAIM_B.txid);
  assert.deepEqual([c.state.txid, c.state.vout], [STATE_B.txid, 0]);
  assert.equal(bytesToHex(c.issuance.nonce), MANIFEST.harness_config.abf_b);
  assert.equal(bytesToHex(c.state.token), bytesToHex(P.tokens[1]));
  assert.equal(bytesToHex(c.successor.blinded.assetCommitment), bytesToHex(P.tokens[0]));
  const plan = claimPset(c, STATE_B.hex, FEE_TX);
  const tx = parseTransaction(psetClaimTransaction(readPset(plan.pset)));
  assert.equal(displayHex(tx.txid), CLAIM_B.txid, 'what Humid extracts after signing is the claim');
  assert.equal(bytesToHex(tx.txidForm), bytesToHex(CLAIM_B.txidForm));
  // The state output of the other phase holds the other token: it is not this claim's state.
  assert.throws(() => claimPset(c, STATE_TX, FEE_TX), /different transaction/);
  assert.throws(() => claimPset({ ...c, state: { ...c.state, token: P.tokens[0] } }, STATE_B.hex, FEE_TX), /does not spend a state UTXO/);
  // Read with the phases' blindings swapped, neither claim's successor is in the other phase.
  const swapped = { ...P, blindings: [P.blindings[1], P.blindings[0]] };
  assert.throws(() => readClaim(CLAIM, swapped), /output 0 is not a successor state/);
  assert.throws(() => readClaim(CLAIM_B.raw, swapped), /output 0 is not a successor state/);
});

test('the phase is the one whose blinding the reissuance reveals, whichever the manifest lists first', () => {
  // With both phases' labels swapped, the same claim reads as spending the second phase, and builds the same PSET.
  const swapped = { ...P, blindings: [P.blindings[1], P.blindings[0]], tokens: [P.tokens[1], P.tokens[0]] };
  const c = readClaim(CLAIM, swapped);
  assert.equal(bytesToHex(c.state.token), bytesToHex(swapped.tokens[1]));
  assert.equal(bytesToHex(c.successor.blinded.assetCommitment), bytesToHex(swapped.tokens[0]));
  assert.equal(claimPset(c, STATE_TX, FEE_TX).pset, claimPset(readClaim(CLAIM, P), STATE_TX, FEE_TX).pset);
});

test('the PSET needs the very outputs the claim spends: the state in the phase it reissues from, and the fee coin', () => {
  const c = readClaim(CLAIM, P);
  assert.throws(() => claimPset(c, FEE_TX, FEE_TX), /different transaction/);
  assert.throws(() => claimPset({ ...c, state: { ...c.state, token: P.tokens[1] } }, STATE_TX, FEE_TX),
    /does not spend a state UTXO/);
  assert.throws(() => claimPset({ ...c, fee: { ...c.fee, sats: 1_999n } }, STATE_TX, FEE_TX),
    /not an open coin of exactly 1999 sats/);
  assert.throws(() => claimPset({ ...c, fee: { ...c.fee, vout: 3 } }, STATE_TX, FEE_TX), /has no output 3/);
  // A claim object changed after it was read no longer describes its own txid: nothing is handed to Humid.
  assert.throws(() => claimPset({ ...c, mint: { ...c.mint, script: hexToBytes(FEE_SCRIPT) } }, STATE_TX, FEE_TX),
    /not the claim; nothing was sent/);
});

test('the manifest is read from this site, uncached, whether or not it is served over https', async () => {
  const asked = [];
  const fetchImpl = async (url, init) => {
    asked.push([url, init]);
    return url.endsWith('/manifest.json')
      ? { ok: true, status: 200, text: async () => '{}' }
      : { ok: false, status: 404, text: async () => '' };
  };
  assert.equal(await siteReader(fetchImpl, 'http://localhost:8080/', 'instances/x/')('manifest.json'), '{}');
  const missing = await siteReader(fetchImpl, 'https://kyrylr.github.io/liquid-poc-bridge/?tab=redeem#main',
    'instances/x/')('other.json').catch((e) => e);
  assert.equal(missing.status, 404);
  assert.deepEqual(asked, [
    ['http://localhost:8080/instances/x/manifest.json', { cache: 'no-store' }],
    ['https://kyrylr.github.io/liquid-poc-bridge/instances/x/other.json', { cache: 'no-store' }],
  ]);
});

// ---- the Liquid API and Humid ----

/** A record serving the instance manifest, as siteReader reads it, with `files` ({ path: text }) changed. */
const site = (files = {}) => async (path) => {
  const served = { 'manifest.json': MANIFEST_TEXT, ...files };
  if (!(path in served)) throw Object.assign(new Error(`HTTP 404 for ${path}`), { status: 404 });
  return served[path];
};

/**
 * The Liquid API at the moment before the claim, answering as Blockstream's Esplora does (lib/update.js tests):
 * /tx/<id>/status is HTTP 200 {"confirmed":false} for a txid it has never seen, and /tx/<id>/hex is 404 for it.
 * `claim` is where the claim is (null, 'mempool' or 'confirmed'); `down` fails every request about it with that HTTP
 * status, or 'offline'. The outputs it spends are confirmed and unspent unless named.
 */
function liquidApi({ claim = null, down = null, stateSpent = false, feeSpent = false, unconfirmed = null } = {}) {
  const txs = { [STATE_TXID]: STATE_TX, [FEE_TXID]: FEE_TX, [CLAIM_TXID]: bytesToHex(CLAIM) };
  const reply = (status, body) => ({
    ok: status === 200, status, text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  });
  const api = new Esplora('https://esplora.test/api/', async (url) => {
    const [, txid, what] = url.match(/^https:\/\/esplora\.test\/api\/tx\/([0-9a-f]{64})\/(status|hex|outspend\/0)$/);
    api.calls.push(what.replace(/\/0$/, ''));
    if (txid === CLAIM_TXID && api.down === 'offline') throw new TypeError('fetch failed');
    if (txid === CLAIM_TXID && api.down) return reply(api.down, 'unavailable');
    const where = txid === CLAIM_TXID ? api.claim : txid === unconfirmed ? 'mempool' : 'confirmed';
    if (what === 'status') {
      return reply(200, where === 'confirmed'
        ? { confirmed: true, block_height: 1, block_hash: 'aa'.repeat(32) } : { confirmed: false });
    }
    if (what === 'hex') return where ? reply(200, txs[txid]) : reply(404, 'Transaction not found');
    const spent = (txid === STATE_TXID && stateSpent) || (txid === FEE_TXID && feeSpent);
    return reply(200, spent ? { spent: true, txid: 'cd'.repeat(32), vin: 0 } : { spent: false });
  });
  return Object.assign(api, { claim, down, calls: [] });
}

function fakeHumid(sign = () => ({ txid: CLAIM_TXID })) {
  const calls = [];
  return {
    calls,
    async request({ method, params }) {
      calls.push({ method, params });
      if (method === 'wallet_getSession') return { sessionScopes: {} };
      if (method === 'wallet_createSession') {
        return { sessionScopes: { [HUMID_SCOPE]: { methods: ['getUTXOs', 'signPset'] } } };
      }
      if (method === 'wallet_invokeMethod' && params.request.method === 'signPset') return sign(params.request.params);
      throw new Error(`unexpected ${method}`);
    },
  };
}

const signings = (humid) => humid.calls.filter((c) => c.params?.request?.method === 'signPset').length;

test('prepareClaim checks the manifest and the chain before Humid; sendClaim checks again, then asks Humid once', async () => {
  const esplora = liquidApi();
  const plan = await prepareClaim({ esplora, readRecord: site(), raw: CLAIM });
  assert.deepEqual([plan.txid, plan.claim.mint.units, plan.claim.fee.sats], [CLAIM_TXID, UNITS, 2_000n]);
  assert.deepEqual(esplora.calls, ['status', 'hex', 'status', 'outspend', 'status', 'outspend', 'hex', 'hex']);

  const humid = fakeHumid();
  const steps = [];
  assert.equal(await sendClaim({ humid, esplora, plan, progress: (s) => steps.push(s) }), CLAIM_TXID);
  assert.deepEqual(humid.calls.map((c) => c.params?.request?.method ?? c.method),
    ['wallet_getSession', 'wallet_createSession', 'signPset']);
  assert.deepEqual(humid.calls[2].params, {
    scope: HUMID_SCOPE,
    request: { method: 'signPset', params: { pset: plan.pset, signInputs: plan.signInputs, broadcast: true } },
  });
  assert.deepEqual(steps, [
    'Checking on Liquid that the claim is unsent and its coins unspent…',
    'Approve the connection to this page in Humid, if it asks…',
    'Check the claim in Humid within 30 seconds, then sign and send it there…',
  ]);

  // Sent meanwhile, by this page or anyone: nothing is asked of Humid again.
  esplora.claim = 'mempool';
  const again = fakeHumid();
  await assert.rejects(sendClaim({ humid: again, esplora, plan }),
    /is on Liquid already \(not confirmed yet\); nothing to send/);
  assert.deepEqual(again.calls, []);
});

test('a claim whose state moved on, whose coins are unconfirmed or spent, that is sent already, or that the manifest does not fit, is refused', async () => {
  const run = (api, readRecord = site()) => prepareClaim({ esplora: api, readRecord, raw: CLAIM });
  await assert.rejects(run(liquidApi({ claim: 'mempool' })), /on Liquid already \(not confirmed yet\)/);
  await assert.rejects(run(liquidApi({ claim: 'confirmed' })), /on Liquid already \(confirmed\)/);
  // The bridge moved on: the page says how to recover the live state and find the next claim.
  await assert.rejects(run(liquidApi({ stateSpent: true })),
    /spent already, by cdcd.*the bridge has moved on, perhaps by this very claim\. To go on, run just status again: it recovers the live state and names the next claim, if one is due$/);
  await assert.rejects(run(liquidApi({ feeSpent: true })), new RegExp(`your fee coin ${FEE_TXID}:0 is spent already`));
  await assert.rejects(run(liquidApi({ unconfirmed: FEE_TXID })), /your fee coin .* is not confirmed yet/);
  await assert.rejects(run(liquidApi({ unconfirmed: STATE_TXID })), /the state output .* is not confirmed yet/);
  // A manifest that does not fit stops it before the Liquid API is asked anything.
  const api = liquidApi();
  await assert.rejects(run(api, site({ 'manifest.json': '{}' })), /names no claim leaf/);
  const otherLeaf = JSON.stringify({ ...MANIFEST, claim_leaf: { cmr: 'ab'.repeat(32) } });
  await assert.rejects(run(api, site({ 'manifest.json': otherLeaf })), /not this instance's claim leaf abababab…/);
  const otherAsset = JSON.stringify({ ...MANIFEST, bootstrap: { ...MANIFEST.bootstrap, entropy: OTHER } });
  await assert.rejects(run(api, site({ 'manifest.json': otherAsset })), /input 0 issues another asset/);
  assert.deepEqual(api.calls, []);
  // Neither a status nor the transaction can be read: nothing shows the claim unsent, so Humid is not asked.
  const plan = await run(liquidApi());
  for (const down of [500, 'offline']) {
    const failing = liquidApi({ down });
    await assert.rejects(run(failing), down === 'offline' ? /fetch failed/ : /HTTP 500/);
    const asked = fakeHumid();
    await assert.rejects(sendClaim({ humid: asked, esplora: failing, plan }));
    assert.deepEqual(asked.calls, []);
  }
});

test('Humid\'s refusals and uncertain sends are told apart; Humid must send the claim\'s own txid', async () => {
  const plan = await prepareClaim({ esplora: liquidApi(), readRecord: site(), raw: CLAIM });
  const send = (sign) => sendClaim({ humid: fakeHumid(sign), esplora: liquidApi(), plan }).catch((e) => e);
  const fails = (reason) => () => {
    throw Object.assign(new Error(`Humid says ${reason}`), { code: -32002, data: { reason } });
  };

  const declined = await send(fails('user_rejected'));
  assert.equal(declined.sent, 'no');
  assert.equal(claimError(declined), humidError(declined));
  const review = await send(() => { throw new Error('Input #0 is not blinded'); });
  assert.deepEqual([review.sent, review.stage], ['no', 'review']);
  assert.equal(claimError(review), 'Humid stopped before asking you to sign (Input #0 is not blinded): its review of '
    + 'the claim failed, so nothing was signed or sent.');
  const broadcast = await send(fails('wallet_pset_broadcast_failed'));
  assert.equal(broadcast.sent, 'maybe');
  assert.match(claimError(broadcast),
    /may have been sent all the same: look its txid up .* this page first checks whether Liquid knows it.*Humid signs only coins it holds/);
  const other = await send(() => ({ txid: 'ab'.repeat(32) }));
  assert.deepEqual([other.sent, other.reported, other.message],
    ['maybe', 'ab'.repeat(32), `Humid reports sending ${'ab'.repeat(32)}, not the claim ${CLAIM_TXID}`]);
  assert.match(claimError(other),
    /^Humid reports sending abab\w+, which is not this claim: this page did not build that transaction\. Look both txids up/);
  const humid = fakeHumid();
  await sendClaim({ humid, esplora: liquidApi(), plan });
  assert.equal(signings(humid), 1);
});

test('once Humid answers, only the claim itself on the Liquid API shows it sent: confirmed, in the mempool, or unknown', async () => {
  assert.deepEqual(await claimOnLiquid(liquidApi({ claim: 'confirmed' }), CLAIM_TXID), { where: 'confirmed', height: 1 });
  const mempool = liquidApi({ claim: 'mempool' });
  assert.deepEqual(await claimOnLiquid(mempool, CLAIM_TXID), { where: 'mempool' });
  assert.deepEqual(mempool.calls, ['hex', 'status']);

  // Esplora's {"confirmed":false} for a txid it never saw is not taken for the mempool: the transaction is asked for,
  // again while the API may lag Humid's broadcast, and then left unknown.
  const lagging = liquidApi();
  assert.deepEqual(await claimOnLiquid(lagging, CLAIM_TXID, { tries: 3, waitMs: 1 }),
    { where: 'unknown', why: 'the Liquid API does not show it' });
  assert.deepEqual(lagging.calls, ['hex', 'hex', 'hex']);
  // Shown on a later try: found.
  const late = liquidApi();
  const txHex = late.txHex.bind(late);
  let asked = 0;
  late.txHex = (txid) => {
    if (++asked === 2) late.claim = 'mempool';
    return txHex(txid);
  };
  assert.deepEqual(await claimOnLiquid(late, CLAIM_TXID, { tries: 3, waitMs: 1 }), { where: 'mempool' });
  assert.equal(asked, 2);

  // Any other failure is unknown at once, not retried, and not taken for a send either way.
  for (const down of [500, 'offline']) {
    const failing = liquidApi({ down });
    const seen = await claimOnLiquid(failing, CLAIM_TXID, { tries: 3, waitMs: 1 });
    assert.equal(seen.where, 'unknown');
    assert.match(seen.why, down === 'offline' ? /could not be read \(fetch failed\)/ : /could not be read \(.*HTTP 500\)/);
    assert.deepEqual(failing.calls, ['hex']);
  }

  // A copy that is not the claim, or unreadable, does not count; nor does one whose confirmation cannot be read.
  const wrong = liquidApi({ claim: 'confirmed' });
  wrong.txHex = async () => FEE_TX;
  assert.deepEqual(await claimOnLiquid(wrong, CLAIM_TXID),
    { where: 'unknown', why: 'the Liquid API serves another transaction for its txid' });
  wrong.txHex = async () => 'not hex';
  assert.equal((await claimOnLiquid(wrong, CLAIM_TXID)).where, 'unknown');
  const statusless = liquidApi({ claim: 'mempool' });
  statusless.txStatus = async () => { throw Object.assign(new Error('Liquid API status: HTTP 502'), { status: 502 }); };
  assert.deepEqual(await claimOnLiquid(statusless, CLAIM_TXID), {
    where: 'unknown', why: 'the Liquid API has it, but its confirmation could not be read (Liquid API status: HTTP 502)',
  });
});

// ---- which deposit a claim paid ----
//
// The walk (lib/update.js liveState, tested in test/update.test.js) finds the deposit index each claim paid from
// what its output 0 commits. These are its answers, made up: deposits are associated only by that index.

const txidOf = (n) => String(n).repeat(64).slice(0, 64);
/** A claim of deposit `index` (null: not attributed), paying `pays` ({ script, units }). */
const paid = (index, n, pays = { script: RECIPIENT, units: UNITS }) => ({ txid: txidOf(n), index, pays });
/** A walk's answer with confirmed `claims`, and `moving`, an unconfirmed one, if given. */
const walked = (claims, moving = null) => ({
  claims: claims.map((c) => ({ ...c, confirmed: true })), movingClaim: moving && { ...moving, confirmed: false },
});
/** One of this browser's deposits: all of them pay one Humid script the same units. */
const deposit = (index, held = {}) => ({
  kind: 'deposit', index: index === null ? null : String(index), units: UNITS.toString(), script: RECIPIENT, ...held,
});
const shown = (m) => new Map([...m].map(([d, r]) => [d.index,
  r.status === 'unresolved' ? r.status : `${r.status}:${r.txid.slice(0, 2)}:${r.vout}`]));

test('a claim is associated with the deposit whose index it paid, whatever the order of claims or deposits', () => {
  const [d0, d1, d2] = [deposit(0), deposit(1), deposit(2)];
  // Deposit 2 is claimed first, then deposit 0, whose claim is still unconfirmed; deposit 1, identical, waits.
  const live = walked([paid(2, 2)], paid(0, 0));
  assert.deepEqual(shown(depositClaims([d2, d1, d0], live)), new Map([['2', 'claimed:22:1'], ['0', 'claiming:00:1']]));
  // In the other order, each deposit still keeps its own claim, and the identical deposit 1 is not taken for either.
  const other = walked([paid(0, 0), paid(2, 2)]);
  assert.deepEqual(shown(depositClaims([d0, d1, d2], other)), new Map([['0', 'claimed:00:1'], ['2', 'claimed:22:1']]));
  // Only deposit 1 claimed: the older, identical deposit 0 is not taken for it.
  assert.deepEqual(shown(depositClaims([d0, d1, d2], walked([paid(1, 1)]))), new Map([['1', 'claimed:11:1']]));
  // A claim of a deposit this browser did not save is none of its deposits'.
  assert.equal(depositClaims([d0, d1, d2], walked([paid(7, 7)])).size, 0);
  // Scripts compare as hex, whatever their case.
  assert.deepEqual(shown(depositClaims([deposit(2, { script: RECIPIENT.toUpperCase() })], live)),
    new Map([['2', 'claimed:22:1']]));
  // No claims yet, or no walk: every deposit waits.
  assert.equal(depositClaims([d0, d1, d2], walked([])).size, 0);
  assert.equal(depositClaims([d0, d1, d2], null).size, 0);
});

test('a deposit an unattributed claim may have paid is unresolved, and never taken for claimed', () => {
  const [d0, d1, d2] = [deposit(0), deposit(1), deposit(2)];
  // Deposit 2's claim is known; the other claim paid deposit 0, deposit 1, or one this browser did not send.
  const r = depositClaims([d0, d1, d2], walked([paid(2, 2), paid(null, 9)]));
  assert.deepEqual(shown(r), new Map([['0', 'unresolved'], ['1', 'unresolved'], ['2', 'claimed:22:1']]));
  assert.match(r.get(d0).why, /^a claim on Liquid could not be attributed to a deposit/);
  assert.match(depositClaims([d0], walked([], paid(null, 9))).get(d0).why, /could not be attributed/);
  // A deposit whose own index this browser does not know is unresolved once any claim exists.
  const lost = deposit(null);
  assert.match(depositClaims([lost], walked([paid(2, 2), paid(1, 1)])).get(lost).why,
    /does not know this deposit's index, so it cannot tell whether 2 claims on Liquid paid it/);
  assert.equal(depositClaims([lost], walked([])).size, 0);
  // So is one whose index a claim paid, but to another script or amount than this browser saved for it.
  for (const pays of [{ script: '0014' + '99'.repeat(20), units: UNITS }, { script: RECIPIENT, units: UNITS + 1n }, null]) {
    const got = depositClaims([d2], walked([paid(2, 2, pays)])).get(d2);
    assert.equal(got.status, 'unresolved');
    assert.match(got.why, /paid deposit #2, but not the script and units this browser saved for it/);
  }
});
