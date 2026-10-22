// Sending a proven bridge update with Humid. The update is the transaction OPERATOR.md step 4's `assemble.py update`
// writes, update.hex: input 0 spends the live state UTXO with the update leaf's Simplicity witness, which carries the
// SP1 proof; input 1, the fee, is an open tL-BTC coin, left unsigned; output 0 is the successor state UTXO and
// output 1 the fee, the whole of input 1 (tools/sg16/bridge-guest/liquid.py). The leaf requires that shape but reads
// nothing else of input 1, so the update can be built against an open coin Humid holds, which Humid can then sign.
//
// This page proves nothing and changes nothing in the update. It follows the bridge state on Liquid to the live state
// output (liveState), checks that the update spends that output and reads from its witness the light-client state it
// moves to, and checks that the outputs it spends are confirmed and unspent; then it hands Humid a PSET whose input 0
// is final and whose input 1 Humid signs. A txid does not commit to witnesses, so the update's txid is fixed before
// signing, and Humid's broadcast must have it.
//
// The store. Liquid holds only lc, the hash of the light-client store an update moves to. The next prover needs the
// store itself: from this site's record, from whoever proved the update, or rebuilt from public beacon data while
// beacon nodes still serve it (sg16-bridge-host reconstruct). The covenant cannot make anyone publish it, and this page
// does not make this site's maintainers a gate either. It sends an update whose store this site publishes under that
// update's txid, or one whose store the sender loads here, so that the sender holds what the next prover needs and can
// publish it anywhere. Either way the store must hash to the lc in the update's own witness. The page uses the store
// for nothing else: no asset, escrow or amount comes from it.
import { PUBLISHED } from '../config.js';
import { encodeSegwit } from './bech32.js';
import { bigToBytes, bytesToBig, bytesToHex, concat, equal, hexToBytes, utf8 } from './bytes.js';
import { sha256 } from './hash.js';
import { LIQUID_TESTNET_HRP, LIQUID_TESTNET_LBTC } from './bridge.js';
import { displayHex, parseTransaction, readWitness } from './elements.js';
import { SIGN_DEADLINE_MS, base64, encodePset, humidError, humidSession, signAndBroadcast, unsignedTx } from './humid.js';

/**
 * The largest fee this page has Humid pay, in sats. The leaf spends the whole fee coin as fee, and the tools refuse
 * a coin above max(100 times the relay floor, 50,000 sats) (tools/sg16/bridge-guest/testnet/tx fee_ceiling). An
 * update of about 59,100 weight units has a relay floor of 1,478 sats; the page offers a 2,000-sat coin.
 */
export const MAX_FEE_SATS = 50_000n;
/** The longest PSET, in base64 characters, Humid 1.1.3's signPset accepts (domain/pset/validation.ts). */
export const HUMID_MAX_PSET = 1_000_000;
const SIMPLICITY_LEAF = 0xbe; // Elements' tapleaf version for Simplicity
const FINAL = 0xffffffff;
/** The tags of the light-client commitment, the state hash and a claimed slot (vectors/protocol.json tags). */
export const TAGS = Object.freeze({
  lc: 'liquid-bridge-poc/lc',
  state: 'liquid-bridge-poc/state',
  claimed: 'liquid-bridge-poc/claimed',
});
const LC_TAG = sha256(utf8(TAGS.lc));
const STATE_TAG = sha256(utf8(TAGS.state));
const CLAIMED_LEAF = sha256(utf8(TAGS.claimed));
const CLAIMED_DEPTH = 32;
const LBTC = hexToBytes(LIQUID_TESTNET_LBTC);
// The update leaf's fields: seven 256-bit words, then two 64-bit words (updateFields).
const FIELD_BITS = 7 * 256 + 2 * 64;
/** The most spends of the state output liveState follows in one walk. */
const MAX_SPENDS = 500;
// Sepolia's beacon chain: genesis time, seconds per slot, slots per sync-committee period, and the block-serving
// window Gloas recommends, 14,299 epochs (sg16-bridge-host reconstruct).
const SEPOLIA_GENESIS = 1_655_733_600;
const SLOT_SECONDS = 12;
const PERIOD_SLOTS = 8192;
const SERVED_SECONDS = 14_299 * 32 * SLOT_SECONDS;

const isP2tr = (s) => s.length === 34 && s[0] === 0x51 && s[1] === 0x20;
const isP2wpkh = (s) => s.length === 22 && s[0] === 0x00 && s[1] === 0x14;
const isOpenLbtc = (o) => o.asset.kind === 'explicit' && equal(o.asset.data, LBTC) && o.value.kind === 'explicit' && o.nonce.kind === 'null';
const isBlinded = (o) => o.asset.kind === 'confidential' && o.value.kind === 'confidential';

/**
 * The update in `raw` (update.hex as bytes): { txid, state, fee: { txid, vout, sats }, witness, successor }. Throws
 * unless it has exactly the update leaf's shape: inputs [state, fee] with no issuance or peg-in, input 0 spending
 * with `updateCmr` (this instance's update leaf), input 1 unsigned; outputs [the successor, blinded, to a Taproot
 * script; an open tL-BTC fee of at most MAX_FEE_SATS]. Version 2, locktime 0 and final sequences, the only values
 * the PSET this page writes can carry (lib/humid.js encodePset), and the txid commits to them.
 */
export function readUpdate(raw, updateCmr) {
  const tx = parseTransaction(raw);
  if (tx.witnessAt === null) throw new Error('this transaction carries no witness, so it is not an update: load the update.hex assemble.py update wrote');
  const w = readWitness(raw);
  if (tx.inputs.length !== 2 || tx.outputs.length !== 2) throw new Error('an update has two inputs, the state and the fee, and two outputs, the successor state and the fee');
  if (tx.version !== 2 || tx.locktime !== 0 || tx.inputs.some((i) => i.sequence !== FINAL)) {
    throw new Error('this update is not version 2 with locktime 0 and final sequences, as assemble.py update writes it');
  }
  if (tx.inputs.some((i) => i.issuance || (i.n & 0xc0000000) !== 0) || w.inputs.some((i) => i.issuanceProof.length || i.inflationProof.length || i.pegin.length)) {
    throw new Error('an update has no issuance or peg-in');
  }
  const [leaf, fee] = w.inputs;
  if (leaf.script.length !== 4) throw new Error('input 0 does not spend with an update leaf\'s witness: program witness, program, CMR, control block');
  const [, , cmr, control] = leaf.script;
  if (!equal(cmr, updateCmr)) throw new Error(`input 0 spends with Simplicity leaf ${bytesToHex(cmr).slice(0, 8)}…, not this instance's update leaf ${bytesToHex(updateCmr).slice(0, 8)}…`);
  if (control.length < 33 || (control.length - 33) % 32 !== 0 || (control[0] & 0xfe) !== SIMPLICITY_LEAF) throw new Error('input 0\'s control block is not a Simplicity leaf\'s');
  if (fee.script.length !== 0) {
    throw new Error('input 1 is signed already, so this update needs no Humid: broadcast it as OPERATOR.md says, or load the unsigned update.hex');
  }
  const [succ, feeOut] = tx.outputs;
  const proofs = w.outputs[0];
  if (!isBlinded(succ) || succ.nonce.kind !== 'null' || !isP2tr(succ.script) || !proofs.surjectionProof.length || !proofs.rangeproof.length) {
    throw new Error('output 0 is not a successor state: the bridge token, blinded with its proofs, to a Taproot script');
  }
  if (!isOpenLbtc(feeOut) || feeOut.script.length !== 0) throw new Error('output 1 is not an open tL-BTC fee');
  const sats = feeOut.value.amount;
  if (sats <= 0n || sats > MAX_FEE_SATS) throw new Error(`this update pays ${sats} sats of fee; this page sends at most ${MAX_FEE_SATS}. Build it against a smaller fee coin`);
  const outpoint = (i) => ({ txid: displayHex(i.prevTxid), vout: i.n });
  return {
    txid: displayHex(tx.txid),
    state: outpoint(tx.inputs[0]),
    fee: { ...outpoint(tx.inputs[1]), sats },
    witness: leaf.script,
    successor: { script: succ.script, blinded: { valueCommitment: succ.value.data, assetCommitment: succ.asset.data, ...proofs } },
  };
}

/**
 * The update `u` (readUpdate) as a PSET for Humid's signPset, given the transactions it spends as the Liquid API
 * serves them. Input 0 carries its witness as final, so no wallet touches it; Humid's review lists it as not the
 * wallet's. Input 1 must be an open coin of exactly the fee, at a P2WPKH script, as Humid's are: Humid adds its key
 * path from that script and signs it alone. Output 0 is the successor as the update has it, blinded already; output
 * 1 the open fee. Returns { txid, pset, signInputs, feeAddress, successorAddress }.
 */
export function updatePset(u, stateTxHex, feeTxHex) {
  const spent = (hex, { txid, vout }) => {
    const tx = parseTransaction(hexToBytes(hex));
    if (displayHex(tx.txid) !== txid) throw new Error('the Liquid API returned a different transaction');
    if (!tx.outputs[vout]) throw new Error(`transaction ${txid} has no output ${vout}`);
    return tx.outputs[vout];
  };
  const state = spent(stateTxHex, u.state);
  if (!isBlinded(state) || !isP2tr(state.script)) throw new Error('input 0 does not spend a state UTXO: the bridge token, blinded, at a Taproot script');
  const coin = spent(feeTxHex, u.fee);
  if (!isOpenLbtc(coin) || coin.value.amount !== u.fee.sats) throw new Error(`input 1 is not an open coin of exactly ${u.fee.sats} sats of tL-BTC, the update's whole fee`);
  if (!isP2wpkh(coin.script)) throw new Error('input 1 is not at a P2WPKH address, as Humid\'s coins are');
  const inputs = [{ ...u.state, witnessUtxo: state.raw, finalWitness: u.witness }, { ...u.fee, witnessUtxo: coin.raw }];
  const outputs = [{ script: u.successor.script, blinded: u.successor.blinded }, { asset: LBTC, amount: u.fee.sats, script: new Uint8Array(0) }];
  // Signing adds witnesses only, so Humid's transaction is the PSET's: it must be the update the record names.
  if (displayHex(parseTransaction(unsignedTx(inputs, outputs)).txid) !== u.txid) throw new Error('the PSET built here is not the update; nothing was sent. Report this');
  const pset = base64(encodePset({ inputs, outputs }));
  if (pset.length > HUMID_MAX_PSET) throw new Error(`this update is ${pset.length} characters as a PSET, more than the ${HUMID_MAX_PSET} Humid accepts`);
  const feeAddress = encodeSegwit(LIQUID_TESTNET_HRP, 0, coin.script.subarray(2));
  return {
    txid: u.txid, pset, signInputs: [{ address: feeAddress, index: 1, sighashTypes: [1] }],
    feeAddress, successorAddress: encodeSegwit(LIQUID_TESTNET_HRP, 1, u.successor.script.subarray(2)),
  };
}

// ---- the bridge state on Liquid ----
//
// Liquid holds the state's lc, accumulator and claimed root only as a leaf of the state output's Taproot tree,
// {{update leaf, claim leaf}, tapleaf(SHA256(STATE_TAG || lc || acc || claimed_root))}. A spend of the state output
// reveals that leaf in its control block, and an update's witness holds the spent lc, accumulator and claimed root
// and the lc and accumulator it moves to. Liquid checks each control block against the output it spends, so
// following the spends from the bootstrap gives the live state from public data alone, as far as the Liquid API
// serves the chain as it is, which every check on this page assumes.
//
// Claims may pay deposits in any order. Which deposit a claim pays is its witness's INDEX, which this page does not
// parse as a Simplicity value. It finds it instead from what the claim commits: its output 0 is the successor state
// output, whose key commits the claimed root with that slot set (claimIndex). Knowing every slot set so far, the walk
// tries each 32-bit value the witness holds and keeps the one whose successor is output 0. If none or several fit,
// the claim is unattributed, and the claimed set stays unknown from there on: later claims are unattributed too, and
// the claimed root is unknown until an update reveals it. Nothing is ever attributed by order.

const hex32 = (x, what) => {
  const h = String(x ?? '').toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error(`${what} is not 32 bytes of hex`);
  return h;
};

/** lc = SHA256(LC_TAG || be64(head) || header || committee), in hex. */
export const lcOf = (head, header, committee) => bytesToHex(sha256(concat(LC_TAG, bigToBytes(BigInt(head), 8),
  hexToBytes(header), hexToBytes(committee))));

/** The root of each empty subtree of the claimed tree, by height: 32 zero bytes, then SHA256 of two of the last. */
const EMPTY_SUBTREES = (() => {
  const zero = [new Uint8Array(32)];
  for (let h = 0; h < CLAIMED_DEPTH; h++) zero.push(sha256(concat(zero[h], zero[h])));
  return zero;
})();

/**
 * The claimed root, in hex, of the deposit indices `indices` (integers below 2^32, each at most once): the root of a
 * depth-32 SHA-256 sparse Merkle tree in which slot i is SHA256(TAGS.claimed) once deposit i is claimed, and 32 zero
 * bytes before. It depends only on the set of indices, not on the order in which they were claimed.
 */
export function claimedRoot(indices) {
  let level = new Map();
  for (const i of indices) {
    if (!Number.isSafeInteger(i) || i < 0 || i >= 2 ** CLAIMED_DEPTH) throw new Error(`deposit index ${i} is outside the claimed tree`);
    if (level.has(i)) throw new Error(`deposit index ${i} is claimed twice`);
    level.set(i, CLAIMED_LEAF);
  }
  for (let h = 0; h < CLAIMED_DEPTH; h++) {
    const parents = new Map();
    for (const i of level.keys()) {
      const p = Math.floor(i / 2);
      if (!parents.has(p)) parents.set(p, sha256(concat(level.get(2 * p) ?? EMPTY_SUBTREES[h], level.get(2 * p + 1) ?? EMPTY_SUBTREES[h])));
    }
    level = parents;
  }
  return bytesToHex(level.get(0) ?? EMPTY_SUBTREES[CLAIMED_DEPTH]);
}

/** The claimed root of the initial state, which has claimed nothing. */
export const EMPTY_CLAIMED_ROOT = bytesToHex(EMPTY_SUBTREES[CLAIMED_DEPTH]);

/** SHA256(STATE_TAG || lc || acc || claimed_root), in hex, of `s` ({ lc, acc, claimedRoot }, the words in hex). */
export function stateHash(s) {
  return bytesToHex(sha256(concat(STATE_TAG, hexToBytes(s.lc), hexToBytes(s.acc), hexToBytes(s.claimedRoot))));
}

function taggedHash(tag, msg) {
  const t = sha256(utf8(tag));
  return sha256(concat(t, t, msg));
}

/** The hash of the Simplicity tapleaf whose script is the 32 bytes `word`, a CMR or a state hash (pins.tapleaf_simplicity). */
export const simplicityLeaf = (word) => taggedHash('TapLeaf/elements', concat([SIMPLICITY_LEAF, 32], word));

/** The state leaf of `s` ({ lc, acc, claimedRoot }, the words in hex). */
export function stateLeaf(s) {
  return simplicityLeaf(hexToBytes(stateHash(s)));
}

// ---- the state output's Taproot key ----
//
// The state output is P2TR(NUMS, {{update leaf, claim leaf}, state leaf}) under Elements' tagged hashes (TapLeaf,
// TapBranch and TapTweak, each "/elements"). secp256k1 arithmetic here is in Jacobian coordinates [X, Y, Z], the
// affine point (X/Z^2, Y/Z^3), with null the point at infinity. It handles public data only: no secret is involved.

const FIELD = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GENERATOR = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
  1n,
];

const fp = (a) => {
  const r = a % FIELD;
  return r < 0n ? r + FIELD : r;
};

function fpow(b, e) {
  let r = 1n;
  for (b = fp(b); e > 0n; e >>= 1n) {
    if (e & 1n) r = r * b % FIELD;
    b = b * b % FIELD;
  }
  return r;
}

function pointDouble(p) {
  if (p === null || p[1] === 0n) return null;
  const [x, y, z] = p;
  const a = x * x % FIELD;
  const b = y * y % FIELD;
  const c = b * b % FIELD;
  const d = fp(2n * ((x + b) * (x + b) - a - c));
  const e = 3n * a % FIELD;
  const x3 = fp(e * e - 2n * d);
  return [x3, fp(e * (d - x3) - 8n * c), 2n * y * z % FIELD];
}

function pointAdd(p, q) {
  if (p === null) return q;
  if (q === null) return p;
  const [x1, y1, z1] = p;
  const [x2, y2, z2] = q;
  const z1z1 = z1 * z1 % FIELD;
  const z2z2 = z2 * z2 % FIELD;
  const u1 = x1 * z2z2 % FIELD;
  const u2 = x2 * z1z1 % FIELD;
  const s1 = y1 * z2 % FIELD * z2z2 % FIELD;
  const s2 = y2 * z1 % FIELD * z1z1 % FIELD;
  if (u1 === u2) return s1 === s2 ? pointDouble(p) : null;
  const h = fp(u2 - u1);
  const i = 4n * h * h % FIELD;
  const j = h * i % FIELD;
  const r = fp(2n * (s2 - s1));
  const v = u1 * i % FIELD;
  const x3 = fp(r * r - j - 2n * v);
  return [x3, fp(r * (v - x3) - 2n * s1 * j), fp((z1 + z2) * (z1 + z2) - z1z1 - z2z2) * h % FIELD];
}

/** 2^i G for i below 256, computed on first use. */
let generatorPowers = null;

/** k G, for a scalar k below the group order. */
function mulGenerator(k) {
  if (!generatorPowers) {
    generatorPowers = [GENERATOR];
    for (let i = 1; i < 256; i++) generatorPowers.push(pointDouble(generatorPowers[i - 1]));
  }
  let r = null;
  for (let i = 0; k > 0n; i++, k >>= 1n) {
    if (k & 1n) r = pointAdd(r, generatorPowers[i]);
  }
  return r;
}

/** The point with x-only key `x` (32 bytes) and even y (BIP 340). Throws unless x is on the curve. */
function liftX(x) {
  const px = bytesToBig(x);
  if (px >= FIELD) throw new Error('an x-only key is below the field size');
  const v = fp(px * px * px + 7n);
  let y = fpow(v, (FIELD + 1n) / 4n);
  if (y * y % FIELD !== v) throw new Error('an x-only key is not on secp256k1');
  if (y & 1n) y = FIELD - y;
  return [px, y, 1n];
}

/**
 * The output key of x-only `internal` with Taproot merkle root `merkleRoot` (BIP 341, with TapTweak/elements):
 * { key, parity }, the x-only key in 32 bytes and the parity of its y, which a control block's first byte carries.
 */
export function tweakKey(internal, merkleRoot) {
  const t = bytesToBig(taggedHash('TapTweak/elements', concat(internal, merkleRoot)));
  if (t >= ORDER) throw new Error('the Taproot tweak is not below the group order');
  const q = pointAdd(liftX(internal), mulGenerator(t));
  if (q === null) throw new Error('the Taproot output key is the point at infinity');
  const zi = fpow(q[2], FIELD - 2n);
  const zi2 = zi * zi % FIELD;
  return { key: bigToBytes(q[0] * zi2 % FIELD, 32), parity: Number(q[1] * zi2 % FIELD * zi % FIELD & 1n) };
}

const compareBytes = (a, b) => {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
};

/** The TapBranch/elements hash of two child hashes, in byte order. */
export const tapBranch = (a, b) => taggedHash('TapBranch/elements', compareBytes(a, b) <= 0 ? concat(a, b) : concat(b, a));

/** The merkle root of the state tree {{update leaf, claim leaf}, `leaf`} of this instance's leaves `tree` (stateTree). */
export const stateTreeRoot = (tree, leaf) => tapBranch(tapBranch(simplicityLeaf(tree.update), simplicityLeaf(tree.claim)), leaf);

/** The scriptPubKey of the state output that holds `state` ({ lc, acc, claimedRoot }): OP_1, then its 32-byte key. */
export function stateScript(tree, state) {
  return concat([0x51, 0x20], tweakKey(tree.nums, stateTreeRoot(tree, stateLeaf(state))).key);
}

/** The bits of `bytes`, most significant first, one to a byte: the order in which the bit machine reads a witness. */
function bitsOf(bytes) {
  const bits = new Uint8Array(bytes.length * 8);
  for (let i = 0; i < bits.length; i++) bits[i] = (bytes[i >> 3] >> (7 - (i & 7))) & 1;
  return bits;
}

/** The `n` bytes whose bits start at `at` in `bits` (bitsOf). */
function bytesAt(bits, at, n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < 8 * n; i++) out[i >> 3] |= bits[at + i] << (7 - (i & 7));
  return out;
}

/**
 * The state an update moves to, from its leaf's witness (`witness`, stack item 0), the spent state `spent` and the
 * claim leaf's hash `sibling`: { head, lc, acc, claimedRoot, execRoot, execBlock }. The leaf's fields are one balanced
 * product, so contiguous in the witness: lc, acc and sibling, which the leaf checks against the spent output, then
 * new_lc, new_acc, exec_root and claimed_root, then exec_block and new_head as big-endian 64-bit words. The update
 * carries claimed_root from the spent state to its successor unchanged; spendOf checks it against the spent state
 * leaf. The first 768 bits locate the rest, at their first occurrence: the proof's values and the fields
 * (tools/sg16/sg16/covenant.py BridgeVerifier) come before any bits a relayer could rewrite without changing the txid,
 * such as the padding blocks older leaves carry, and the proof's values cannot be made to hold these 768 bits.
 */
export function updateFields(witness, spent, sibling) {
  const bits = bitsOf(witness);
  const key = bitsOf(concat(hexToBytes(spent.lc), hexToBytes(spent.acc), sibling));
  let hit = -1;
  for (let o = 0; hit < 0 && o + FIELD_BITS <= bits.length; o++) {
    let i = 0;
    while (i < key.length && bits[o + i] === key[i]) i++;
    if (i === key.length) hit = o;
  }
  if (hit < 0) throw new Error('the update\'s witness does not hold the spent state\'s lc, accumulator and claim leaf hash');
  const at = hit + key.length;
  const word = (k) => bytesToHex(bytesAt(bits, at + 256 * k, 32));
  const u64 = (k) => {
    const v = bytesToBig(bytesAt(bits, at + 4 * 256 + 64 * k, 8));
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('the update\'s witness holds a block or slot too large to be one');
    return Number(v);
  };
  return { lc: word(0), acc: word(1), execRoot: word(2), claimedRoot: word(3), execBlock: u64(0), head: u64(1) };
}

/**
 * This instance's state tree, from its manifest `m`: { update, claim, nums }, the CMRs of its update and claim leaves
 * and its x-only internal key.
 */
export function stateTree(m) {
  const word = (x, what) => {
    if (!/^[0-9a-f]{64}$/.test(x ?? '')) throw new Error(`this site's manifest.json names no ${what}`);
    return hexToBytes(x);
  };
  return {
    update: word(m?.update_leaf?.cmr, 'update leaf'),
    claim: word(m?.claim_leaf?.cmr, 'claim leaf'),
    nums: word(m?.constants?.nums, 'internal key of the state tree'),
  };
}

/** The most distinct values claimIndex tries; a claim leaf's witness holds far fewer. */
const MAX_CANDIDATES = 2048;

/** Every distinct value below 2^32 of a 64-bit big-endian window of `witness`, at any bit offset. */
function indexCandidates(witness) {
  const bits = bitsOf(witness);
  const seen = new Set();
  for (let o = 0; o + 64 <= bits.length; o++) {
    let k = 0;
    while (k < 32 && bits[o + k] === 0) k++;
    if (k < 32) continue;
    let v = 0;
    for (let i = 32; i < 64; i++) v = v * 2 + bits[o + i];
    seen.add(v);
  }
  return [...seen];
}

/**
 * The deposit index the claim with leaf witness `witness` and output 0 `script` pays, given the state it spends and
 * that state's full claimed set `state.claimed`: the one value below 2^32 the witness holds, not claimed yet, for which
 * the state with that slot set too is the state output `script` pays. INDEX is a u64 of the witness, so it is among
 * those tried. null if none or more than one fits, or the witness holds too many values to try: then the page does
 * not know which deposit the claim paid.
 */
function claimIndex(witness, script, state, tree) {
  const tried = indexCandidates(witness).filter((i) => !state.claimed.includes(i));
  if (tried.length > MAX_CANDIDATES) return null;
  const fits = tried.filter((i) => equal(stateScript(tree, { ...state, claimedRoot: claimedRoot([...state.claimed, i]) }), script));
  return fits.length === 1 ? fits[0] : null;
}

/**
 * The state the bootstrap creates, from manifest `m`: { head, lc, acc, claimedRoot, claimed }, with `claimed` the
 * claimed deposit indices, none. Throws unless its claimed root is the empty tree's, and, if the manifest states the
 * state hash, unless that is this state's.
 */
function initialState(m) {
  const s = m?.initial_state;
  if (!Number.isSafeInteger(s?.head) || s.head <= 0 || s.claimed_root === undefined) {
    throw new Error('this site\'s manifest.json names no initial state with a claimed root');
  }
  const state = {
    head: s.head,
    lc: hex32(s.lc, 'the initial state\'s lc'),
    acc: hex32(s.acc, 'the initial state\'s accumulator'),
    claimedRoot: hex32(s.claimed_root, 'the initial state\'s claimed root'),
    claimed: [],
  };
  if (state.claimedRoot !== EMPTY_CLAIMED_ROOT) throw new Error('this site\'s manifest.json has an initial state that has claimed deposits already');
  if (s.state_hash !== undefined && hex32(s.state_hash, 'the initial state hash') !== stateHash(state)) {
    throw new Error('this site\'s manifest.json states an initial state hash that is not its initial state\'s');
  }
  return state;
}

/**
 * What the transaction `raw`, spending the state output `outpoint` that holds `state`, makes of it: { txid, kind,
 * state, claim }, where `kind` is 'update' or 'claim', `state` is what its output 0 holds, and `claim`, for a claim,
 * is { txid, index, pays }: the deposit index it paid (claimIndex), or null if unknown, and its output 1 as
 * { script, units } (script in hex), or null if that is not an open amount. Throws unless input 0 spends `outpoint`
 * with this instance's update or claim leaf (`tree`), through a control block of the state tree whose state leaf is
 * `state`'s and whose other leaf is the other of the two.
 *
 * `state.claimed` and `state.claimedRoot` are null once a claim was not attributed (see above). A claim from such a
 * state is checked for its leaf alone, and is not attributed either; an update reveals the spent claimed root, and
 * its control block is checked against the state with that root.
 */
function spendOf(raw, outpoint, state, tree) {
  const tx = parseTransaction(raw);
  const txid = displayHex(tx.txid);
  const at = `transaction ${txid.slice(0, 8)}…`;
  const input = tx.inputs[0];
  if (displayHex(input.prevTxid) !== outpoint.txid || (input.n & 0x3fffffff) !== outpoint.vout) {
    throw new Error(`${at} does not spend the state output ${outpoint.txid}:${outpoint.vout} at its input 0`);
  }
  const items = tx.witnessAt === null ? [] : readWitness(raw).inputs[0].script;
  if (items.length !== 4) throw new Error(`${at} does not spend the state output with a Simplicity leaf's witness: program witness, program, CMR, control block`);
  const [witness, , cmr, control] = items;
  if (control.length !== 97 || (control[0] & 0xfe) !== SIMPLICITY_LEAF) throw new Error(`${at}'s control block is not one of the state tree's`);
  const sibling = control.subarray(33, 65);
  const kind = equal(cmr, tree.update) ? 'update' : equal(cmr, tree.claim) ? 'claim' : null;
  if (!kind) throw new Error(`${at} runs neither this instance's update leaf nor its claim leaf`);
  if (!equal(sibling, simplicityLeaf(kind === 'update' ? tree.claim : tree.update))) throw new Error(`${at}'s control block is not one of this instance's state tree`);
  const opens = (s) => {
    if (!equal(control.subarray(65), stateLeaf(s))) {
      throw new Error(`${at} opens a state output that holds another state than the one followed from this site's record`);
    }
  };
  if (kind === 'claim') {
    if (state.claimedRoot !== null) opens(state);
    const index = state.claimed === null || !tx.outputs[0] ? null : claimIndex(witness, tx.outputs[0].script, state, tree);
    const claimed = index === null ? null : [...state.claimed, index];
    const mint = tx.outputs[1];
    const pays = mint?.value.kind === 'explicit' ? { script: bytesToHex(mint.script), units: mint.value.amount } : null;
    return {
      txid, kind, claim: { txid, index, pays },
      state: { ...state, claimed, claimedRoot: claimed === null ? null : claimedRoot(claimed) },
    };
  }
  const f = updateFields(witness, state, sibling);
  if (state.claimedRoot !== null && f.claimedRoot !== state.claimedRoot) throw new Error(`${at} does not keep the claimed root`);
  opens({ ...state, claimedRoot: f.claimedRoot });
  if (f.head <= state.head) throw new Error(`${at} does not move the light-client head forward`);
  return {
    txid, kind, claim: null,
    state: { head: f.head, lc: f.lc, acc: f.acc, claimedRoot: f.claimedRoot, claimed: state.claimed, execBlock: f.execBlock },
  };
}

/**
 * The bridge's live state on Liquid: { outpoint, state: { head, lc, acc, claimedRoot, claimed }, spends, update,
 * claims, moving, movingClaim }. It follows the state output from output 0 of the bootstrap transaction `bootstrap`,
 * which holds the initial state of this site's `manifest`, through each confirmed spend (spendOf) to the one output
 * still unspent. `update` is the txid of the update that moved the light client to `state.head`, or null while it is
 * still at the initial head; `spends` counts the spends followed; `claims` lists the claims followed, oldest first, as
 * spendOf gives them, with `confirmed` true. `moving` is the txid of an unconfirmed spend of the live output, if the
 * Liquid API has one, and `movingClaim` that spend as a claim, with `confirmed` false, if it is one. Given `from`, an
 * earlier answer for the same bootstrap, the walk resumes there: confirmed spends stay. `progress` is told each spend
 * followed.
 */
export async function liveState({ esplora, manifest, bootstrap, from = null, progress = () => {} }) {
  const tree = stateTree(manifest);
  let cur = from ?? {
    outpoint: { txid: bootstrap, vout: 0 }, state: initialState(manifest), spends: 0, update: null, claims: [],
  };
  for (;;) {
    const out = await esplora.outspend(cur.outpoint.txid, cur.outpoint.vout);
    if (!out?.spent) return { ...cur, moving: null, movingClaim: null };
    if (!out.status?.confirmed) {
      // Attributed once per transaction: an unconfirmed claim stays the live output's spend until it confirms.
      if (from?.movingClaim?.txid === out.txid) return { ...cur, moving: out.txid, movingClaim: from.movingClaim };
      let movingClaim = null;
      try {
        const spend = spendOf(hexToBytes(await esplora.txHex(out.txid)), cur.outpoint, cur.state, tree);
        if (spend.claim && spend.txid === out.txid) movingClaim = { ...spend.claim, confirmed: false };
      } catch {
        // A spend the mempool holds but this page cannot read attributes nothing; it is followed once confirmed.
      }
      return { ...cur, moving: out.txid, movingClaim };
    }
    if (cur.spends >= MAX_SPENDS) throw new Error(`the state has moved more than ${MAX_SPENDS} times, more than this page follows; just status recovers it`);
    const spend = spendOf(hexToBytes(await esplora.txHex(out.txid)), cur.outpoint, cur.state, tree);
    if (spend.txid !== out.txid) throw new Error('the Liquid API returned a different transaction');
    cur = {
      outpoint: { txid: spend.txid, vout: 0 },
      state: spend.state,
      spends: cur.spends + 1,
      update: spend.kind === 'update' ? spend.txid : cur.update,
      claims: spend.claim ? [...cur.claims, { ...spend.claim, confirmed: true }] : cur.claims,
    };
    progress(cur.spends);
  }
}

// ---- light-client stores ----

/**
 * The light-client store in `text`, a store file such as the proof.store.json sg16-bridge-host writes beside each
 * proof, if it is the store of `want` ({ head, lc }): { head, header, committee, lc }. Throws unless its head is
 * want's and its header and committee hash to want's lc. Its CBOR, the store itself, is the prover's to check:
 * sg16-bridge-host inputs refuses one whose roots are not these.
 */
export function storeFile(text, want, name) {
  let s;
  try {
    s = JSON.parse(text);
  } catch {
    throw new Error(`${name} is not a store file`);
  }
  if (!Number.isSafeInteger(s?.head) || s.head <= 0) throw new Error(`${name} names no head slot, so it is not a store file`);
  const header = hex32(s.header, `${name}'s header`);
  const committee = hex32(s.committee, `${name}'s committee`);
  const lc = hex32(s.lc, `${name}'s lc`);
  if (typeof s.store_cbor !== 'string' || !/^(?:0x)?(?:[0-9a-f]{2})+$/i.test(s.store_cbor)) throw new Error(`${name} holds no store CBOR, the store a prover starts from`);
  if (lcOf(s.head, header, committee) !== lc) throw new Error(`${name}'s lc is not the hash of its head, header and committee`);
  if (s.head !== want.head || lc !== want.lc) {
    throw new Error(`${name} is the store at slot ${s.head.toLocaleString('en')} with lc ${lc.slice(0, 8)}…, not the one at slot `
      + `${want.head.toLocaleString('en')} with lc ${want.lc.slice(0, 8)}…`);
  }
  return { head: s.head, header, committee, lc };
}

/**
 * The store this site's record lists for the light-client state `want` ({ head, lc }), reached by the update with txid
 * `update` (null for the initial state), read through `readRecord`: the path of the file named by the lc_preimages.json
 * entry at that head whose header and committee hash to lc, which must hold that store (storeFile). null if no entry
 * fits or the one that fits names no file. Throws if that entry names another update, as the justfile's preflight
 * does: the record would then say another transaction reached that head. The anchor's starting store names none.
 */
export async function siteStore(readRecord, want, update) {
  let entries;
  try {
    entries = JSON.parse(await readRecord('lc_preimages.json')).preimages;
  } catch (e) {
    if (e.status !== 404) throw e;
    entries = [];
  }
  const fits = (e) => {
    try {
      return e?.head === want.head && lcOf(e.head, hex32(e.header, ''), hex32(e.committee, '')) === want.lc;
    } catch {
      return false;
    }
  };
  const entry = (Array.isArray(entries) ? entries : []).find(fits);
  if (entry?.store === undefined) return null;
  if (entry.store !== `lc_stores/${want.head}.json`) throw new Error(`lc_preimages.json's entry for slot ${want.head} is malformed`);
  if ((entry.update ?? null) !== update) {
    const named = (txid) => (txid ? `update ${txid}` : 'no update');
    throw new Error(`lc_preimages.json lists the store at slot ${want.head} under ${named(entry.update)}, but ${named(update)} reaches that slot`);
  }
  storeFile(await readRecord(entry.store), want, `this site's ${entry.store}`);
  return entry.store;
}

/**
 * Whether the page whose base is `pageHref` (its directory, as ui/src/bridge/env.ts siteHref gives it; any query or
 * fragment is ignored) is the published site, config.js PUBLISHED.site, whose instance record shows what is published.
 * No other copy counts, as the justfile's preflight reads stores back only from that site: a copy on another host or
 * path may serve an older record, and a page served from this computer reads the working tree, which publishes nothing.
 */
export function publishes(pageHref) {
  const page = new URL(pageHref);
  return `${page.origin}${page.pathname}` === PUBLISHED.site;
}

/**
 * Until when, in Unix ms, beacon nodes are asked to keep what rebuilding the store at `head` takes, if no one publishes
 * it: the head's block header and a light-client update from the sync period before the head's, kept for the window
 * Gloas recommends from the start of that period. Some beacon APIs keep less.
 */
export const servedUntil = (head) => (SEPOLIA_GENESIS + (Math.floor(head / PERIOD_SLOTS) - 1) * PERIOD_SLOTS * SLOT_SECONDS + SERVED_SECONDS) * 1000;

/**
 * The light-client state on Liquid as the update panel shows it, before any update is loaded: { live, listed }, the
 * live state (liveState) and the path of its store in this page's record, or null if the record lists none. The
 * record must list it under the update that moved the light client there (siteStore).
 */
export async function lightClientStatus({ esplora, readRecord, bootstrap, from = null, progress }) {
  const manifest = JSON.parse(await readRecord('manifest.json'));
  const live = await liveState({ esplora, manifest, bootstrap, from, progress });
  return { live, listed: await siteStore(readRecord, live.state, live.update) };
}

/**
 * Throws unless update `u` is still to be sent: the Liquid API does not know its txid, and the outputs it spends are
 * confirmed and unspent, as the justfile's preflight requires. Esplora answers {confirmed: false} for a txid it has
 * never seen, so an unconfirmed status is not taken to mean the update is in the mempool: only a 404 for its
 * transaction, which Esplora serves from the mempool as from blocks, shows it unknown. Any other failure is passed on.
 */
async function unsent(esplora, u) {
  const s = await esplora.txStatus(u.txid).catch((e) => { if (e.status === 404) return null; throw e; });
  let known = Boolean(s?.confirmed);
  if (!known) {
    try {
      await esplora.txHex(u.txid);
      known = true;
    } catch (e) {
      if (e.status !== 404) throw e;
    }
  }
  if (known) throw new Error(`update ${u.txid} is on Liquid already (${s?.confirmed ? 'confirmed' : 'not confirmed yet'}); nothing to send`);
  for (const [o, what] of [[u.state, 'the state output'], [u.fee, 'your fee coin']]) {
    if (!(await esplora.txStatus(o.txid))?.confirmed) throw new Error(`${what} ${o.txid}:${o.vout} is not confirmed yet; wait for it, then load the update again`);
    const s = await esplora.outspend(o.txid, o.vout);
    if (s?.spent) {
      throw new Error(o === u.state
        ? `the state output this update spends is spent already, by ${s.txid}: the bridge has moved on. Recover the live state (just status) and build a new update`
        : `your fee coin ${o.txid}:${o.vout} is spent already, by ${s.txid}; build the update against another`);
    }
  }
}

/**
 * Everything the page checks before Humid is involved, for the update in `raw`: its shape against the update leaf
 * of this site's manifest.json (readUpdate); that it is unsent and the outputs it spends confirmed and unspent
 * (unsent); that it spends the live state output (liveState, from the bootstrap `bootstrap`, or resuming `from`); and
 * the light-client state its witness moves to (spendOf). `published` says whether this page is the published site
 * (publishes); only then does a store its record lists count as published.
 *
 * Returns the PSET plan of updatePset with { update, live, successor, listed, store }: `successor` is the state the
 * update moves to; `listed`, the path of its store in this page's record, listed under this update, or null (siteStore
 * refuses an entry naming another); `store`, { where: 'site', path }
 * when that store is published here, else null until withStore adds the sender's own file. sendUpdate needs one.
 */
export async function prepareUpdate({ esplora, readRecord, raw, bootstrap, published, from = null, progress }) {
  const manifest = JSON.parse(await readRecord('manifest.json'));
  const tree = stateTree(manifest);
  const update = readUpdate(raw, tree.update);
  await unsent(esplora, update);
  const live = await liveState({ esplora, manifest, bootstrap, from, progress });
  if (live.moving) throw new Error(`the live state output is being spent by ${live.moving}, not confirmed yet. Once it confirms, build the update again from just status`);
  if (live.outpoint.txid !== update.state.txid || live.outpoint.vout !== update.state.vout) {
    throw new Error(`this update spends ${update.state.txid}:${update.state.vout}, not the live state output ${live.outpoint.txid}:0. Build it again from just status`);
  }
  const successor = spendOf(raw, live.outpoint, live.state, tree).state;
  const listed = await siteStore(readRecord, successor, update.txid);
  const plan = updatePset(update, await esplora.txHex(update.state.txid), await esplora.txHex(update.fee.txid));
  return { ...plan, update, live, successor, listed, store: published && listed ? { where: 'site', path: listed } : null };
}

/**
 * `plan` (prepareUpdate) with the sender's own store file, `text` (named `name` in messages), once it is the store of
 * the state the update moves to (storeFile): { ...plan, store: { where: 'file', name, entry } }, where `entry` is the
 * lc_preimages.json entry that publishes it, in the form the justfile's stage-store writes.
 */
export function withStore(plan, text, name) {
  const s = storeFile(text, plan.successor, name);
  const entry = { head: s.head, header: s.header, committee: s.committee, update: plan.txid, store: `lc_stores/${s.head}.json` };
  return { ...plan, store: { where: 'file', name, entry } };
}

/**
 * Sends `plan` (prepareUpdate) with Humid, once it has the store the update moves to: checks again that it is unsent,
 * then has Humid sign input 1 and broadcast once the user confirms (signAndBroadcast, whose `sent` marks its errors
 * carry). Humid's txid must be the update's.
 */
export async function sendUpdate({ humid, esplora, plan, progress = () => {}, deadlineMs = SIGN_DEADLINE_MS }) {
  if (!plan.store) throw new Error('load the store this update moves to first: this site does not publish it, and the next prover needs it');
  progress('Checking on Liquid that the update is unsent and its coins unspent…');
  await unsent(esplora, plan.update);
  progress('Approve the connection to this page in Humid, if it asks…');
  await humidSession(humid);
  progress('Review the update in Humid, then sign and send…');
  const txid = await signAndBroadcast(humid, plan, deadlineMs);
  if (txid !== plan.txid) throw Object.assign(new Error(`Humid reports sending ${txid}, not the update ${plan.txid}`), { sent: 'maybe' });
  return txid;
}

/**
 * What to tell the user when Humid refuses or fails an update. Unlike a burn, an update cannot be sent twice: its
 * txid is fixed, and the page looks it up on Liquid before it asks Humid again.
 */
export function updateError(e) {
  if (e?.data?.reason === 'user_rejected') return humidError(e);
  const what = (e && e.message) || String(e);
  if (e?.sent === 'no' && e.stage === 'review') {
    return `Humid stopped before asking you to sign (${what}): its review of the update failed, so nothing was signed or sent.`;
  }
  if (e?.sent === 'maybe') {
    return `Humid did not confirm sending the update (${what}). It may have been sent all the same: look its txid up on a Liquid explorer. `
      + 'Sending again is safe, as this page first checks whether Liquid knows it.'
      + (e?.data?.reason === 'wallet_pset_broadcast_failed' ? ' If nothing was sent: Humid signs only coins it holds, so check that the fee coin is at '
        + 'this Humid wallet\'s address under Receive, then Unconfidential.' : '');
  }
  return `Humid: ${what}`;
}
