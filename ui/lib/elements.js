// Elements (Liquid) consensus encodings, mirroring contracts/solidity/contracts/ElementsParser.sol, plus the
// extraction a redemption submitter needs: the txid form of a transaction, the hash form and signatures of a DynaFed
// header, and a transaction's Merkle branch. Inputs are the full serializations nodes and Esplora serve.
import { Reader, concat, equal, reversed } from './bytes.js';
import { sha256, sha256d } from './hash.js';

const ISSUANCE_FLAG = 0x80000000;
const NULL_INDEX = 0xffffffff;

function readCommitment(r, explicitSize, a, b) {
  const prefix = r.u8();
  if (prefix === 0x00) return { kind: 'null' };
  if (prefix === 0x01) return { kind: 'explicit', data: r.bytes(explicitSize - 1) };
  if (prefix === a || prefix === b) return { kind: 'confidential', data: concat([prefix], r.bytes(32)) };
  throw new Error(`bad commitment prefix 0x${prefix.toString(16)}`);
}

function readValue(r) {
  const v = readCommitment(r, 9, 0x08, 0x09);
  if (v.kind === 'explicit') v.amount = v.data.reduce((acc, x) => (acc << 8n) | BigInt(x), 0n);
  return v;
}

/**
 * Parses a transaction in either serialization. `txidForm` is version, flags byte 0, inputs, outputs and
 * locktime: the bytes BridgeEscrow.redeem takes and SHA256d hashes to the txid (internal byte order).
 */
export function parseTransaction(raw) {
  const r = new Reader(raw);
  const version = r.u32le();
  const flags = r.u8();
  if (flags !== 0 && flags !== 1) throw new Error('unknown transaction flags');
  const inputs = [];
  const nin = r.compactSize();
  if (nin === 0) throw new Error('transaction has no inputs');
  for (let i = 0; i < nin; i++) {
    const prevTxid = r.bytes(32);
    const n = r.u32le();
    r.varBytes(); // scriptSig
    const sequence = r.u32le();
    let issuance = null;
    if (n !== NULL_INDEX && (n & ISSUANCE_FLAG) !== 0) {
      issuance = { nonce: r.bytes(32), entropy: r.bytes(32), amount: readValue(r), inflationKeys: readValue(r) };
    }
    inputs.push({ prevTxid, n, sequence, issuance });
  }
  const outputs = [];
  const nout = r.compactSize();
  if (nout === 0) throw new Error('transaction has no outputs');
  for (let i = 0; i < nout; i++) {
    const start = r.p;
    const asset = readCommitment(r, 33, 0x0a, 0x0b);
    const value = readValue(r);
    const nonce = readCommitment(r, 33, 0x02, 0x03);
    const script = r.varBytes();
    // `raw` is the output's serialization, which a PSET carries as the witness UTXO of an input spending it.
    outputs.push({ asset, value, nonce, script, raw: raw.subarray(start, r.p) });
  }
  const locktime = r.u32le();
  const end = r.p;
  if (flags === 0 && end !== raw.length) throw new Error('trailing bytes after the transaction');
  // With flags 1 the witness follows; the txid does not commit to it, so it is not parsed here (readWitness).
  const txidForm = concat(raw.subarray(0, 4), [0], raw.subarray(5, end));
  return { version, inputs, outputs, locktime, txidForm, txid: sha256d(txidForm), witnessAt: flags === 1 ? end : null };
}

/**
 * The witness of a transaction served with it, after the locktime: per input { issuanceProof, inflationProof,
 * script, pegin }, its issuance amount and inflation-key rangeproofs and its script and peg-in witness stacks (arrays
 * of items), then per output { surjectionProof, rangeproof }. Explicit outputs have empty proofs.
 */
export function readWitness(raw) {
  const tx = parseTransaction(raw);
  if (tx.witnessAt === null) throw new Error('the transaction was served without its witness');
  const r = new Reader(raw);
  r.p = tx.witnessAt;
  const stack = () => Array.from({ length: r.compactSize() }, () => r.varBytes());
  const inputs = tx.inputs.map(() => ({ issuanceProof: r.varBytes(), inflationProof: r.varBytes(), script: stack(), pegin: stack() }));
  const outputs = tx.outputs.map(() => ({ surjectionProof: r.varBytes(), rangeproof: r.varBytes() }));
  if (!r.done) throw new Error('trailing bytes after the witness');
  return { inputs, outputs };
}

/** Each output's witness, { surjectionProof, rangeproof } (readWitness). */
export function outputWitnesses(raw) {
  return readWitness(raw).outputs;
}

function readParams(r) {
  const kind = r.u8();
  if (kind === 0) return { kind: 'null' };
  if (kind !== 1 && kind !== 2) throw new Error(`bad DynaFed params type ${kind}`);
  const signblockscript = r.varBytes();
  r.u32le(); // signblock witness limit
  if (kind === 1) {
    r.bytes(32); // elided root
  } else {
    r.varBytes(); // fedpeg program
    r.varBytes(); // fedpegscript
    const n = r.compactSize();
    for (let i = 0; i < n; i++) r.varBytes(); // extension space
  }
  return { kind: kind === 1 ? 'compact' : 'full', signblockscript };
}

/** Parses a DynaFed header as served by /block/:hash/header: hash-form fields, then the signblock witness. */
export function parseHeader(raw) {
  const r = new Reader(raw);
  const version = r.u32le();
  if ((version & 0x80000000) === 0) throw new Error('not a DynaFed header');
  const prev = r.bytes(32);
  const merkleRoot = r.bytes(32);
  r.u32le(); // time
  const height = r.u32le();
  const current = readParams(r);
  if (current.kind === 'null') throw new Error('header has null current params');
  readParams(r); // proposed
  const hashForm = raw.slice(0, r.p);
  const witness = [];
  if (!r.done) {
    const n = r.compactSize();
    for (let i = 0; i < n; i++) witness.push(r.varBytes());
  }
  if (!r.done) throw new Error('trailing bytes after the header');
  return { hashForm, hash: sha256d(hashForm), prev, merkleRoot, height, signblockscript: current.signblockscript, witness };
}

/** A DER ECDSA signature followed by its sighash byte, as in the signblock witness, to 32-byte (r, s). */
export function parseDerSignature(sig) {
  const der = sig.subarray(0, sig.length - 1);
  if (sig.length < 9 || der[0] !== 0x30 || der[1] !== der.length - 2) throw new Error('not a DER signature');
  let p = 2;
  const integer = () => {
    if (der[p] !== 0x02) throw new Error('not a DER integer');
    const len = der[p + 1];
    if (len === 0 || len > 33 || p + 2 + len > der.length) throw new Error('bad DER integer length');
    let v = der.subarray(p + 2, p + 2 + len);
    p += 2 + len;
    while (v.length > 0 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) throw new Error('DER integer exceeds 32 bytes');
    return concat(new Uint8Array(32 - v.length), v);
  };
  const r = integer();
  const s = integer();
  if (p !== der.length) throw new Error('trailing bytes in DER signature');
  return { r, s };
}

/**
 * The block signatures of a header, in witness order. The signblockscript must be the P2WSH of the
 * witness script carried as the last witness item; OP_CHECKMULTISIG scripts carry an empty dummy first.
 */
export function blockSignatures(header) {
  const items = header.witness;
  if (items.length < 2) throw new Error('header has no signblock witness; fetch it with /block/:hash/header');
  const script = items[items.length - 1];
  const spk = header.signblockscript;
  if (spk.length !== 34 || spk[0] !== 0x00 || spk[1] !== 0x20 || !equal(spk.subarray(2), sha256(script))) {
    throw new Error('signblockscript is not the P2WSH of the witness script');
  }
  let sigs = items.slice(0, -1);
  if (script[script.length - 1] === 0xae) {
    if (sigs[0].length !== 0) throw new Error('missing OP_CHECKMULTISIG dummy');
    sigs = sigs.slice(1);
  }
  return { witnessScript: script, signatures: sigs.map(parseDerSignature) };
}

const sha256dPair = (a, b) => sha256d(concat(a, b));

/** The Bitcoin-style Merkle root of `leaves` and the branch of leaf `index` (internal byte order). */
export function merkleBranch(leaves, index) {
  if (index < 0 || index >= leaves.length) throw new Error('index outside the block');
  const branch = [];
  let level = leaves;
  let i = index;
  while (level.length > 1) {
    branch.push((i ^ 1) < level.length ? level[i ^ 1] : level[i]);
    const next = [];
    for (let j = 0; j < level.length; j += 2) next.push(sha256dPair(level[j], j + 1 < level.length ? level[j + 1] : level[j]));
    level = next;
    i >>= 1;
  }
  return { root: level[0], branch };
}

/** Internal-order txid bytes from display hex, and back. */
export function txidFromDisplay(hex) {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('a txid is 64 hex characters');
  return reversed(Uint8Array.from(hex.match(/../g), (x) => parseInt(x, 16)));
}

export function displayHex(internal) {
  return Array.from(reversed(internal), (x) => x.toString(16).padStart(2, '0')).join('');
}
