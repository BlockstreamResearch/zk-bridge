// Synthetic Liquid transactions for the tests, serialized here from Elements' consensus encoding rather than by
// lib/elements.js, which reads them back: explicit and blinded outputs, issuing inputs, and the witness of each input
// and output. A txid is SHA256d of the txid serialization, computed with node:crypto. Every key, commitment, proof,
// program and outpoint is made up: none of these transactions was ever on Liquid.
import { createHash } from 'node:crypto';

/** Liquid testnet's policy asset, tL-BTC, in internal byte order: a network constant. */
export const LBTC = hex('499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c14');
/** BIP 341's unspendable point H, x-only: the state tree's internal key. */
export const NUMS = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';

export function hex(h) {
  return Uint8Array.from(Buffer.from(h, 'hex'));
}

export const toHex = (b) => Buffer.from(b).toString('hex');
export const cat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));
export const sha256 = (b) => Uint8Array.from(createHash('sha256').update(b).digest());

/** A made-up 32-byte word derived from `label`, in hex. */
export const word = (label) => toHex(sha256(Buffer.from(label)));

/** `n` made-up bytes derived from `label`. */
export function filler(label, n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 32) out.set(sha256(Buffer.from(`${label}/${i}`)).subarray(0, Math.min(32, n - i)), i);
  return out;
}

const le32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0);
  return b;
};

const be64 = (v) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(v));
  return b;
};

export const compactSize = (n) => (n < 0xfd ? [n] : n <= 0xffff ? [0xfd, n & 0xff, n >> 8] : cat([0xfe], le32(n)));
export const varBytes = (b) => cat(compactSize(b.length), b);
export const witnessStack = (items) => cat(compactSize(items.length), ...items.map(varBytes));

/** An explicit amount, or null for none: 0x01 and 8 big-endian bytes, or 0x00. */
const amountBytes = (v) => (v === null ? [0x00] : cat([0x01], be64(v)));

/** An open output of `amount` of `asset` (internal order) to `script`. */
export const explicit = (asset, amount, script) => ({ asset, amount: BigInt(amount), script });

/** A blinded output: its 33-byte asset and value commitments, its script, and its proofs, which a witness carries. */
export const blinded = (assetCommitment, valueCommitment, script, label = 'proofs') => ({
  assetCommitment, valueCommitment, script, surjectionProof: filler(`${label}/surjection`, 67), rangeproof: filler(`${label}/range`, 4174),
});

function outputBytes(o) {
  return o.assetCommitment
    ? cat(o.assetCommitment, o.valueCommitment, [0x00], varBytes(o.script))
    : cat([0x01], o.asset, [0x01], be64(o.amount), [0x00], varBytes(o.script));
}

/**
 * A version 2 transaction: { raw, hex, txidForm, txid }, `txid` in display order. Each input is { txid (display hex),
 * vout, sequence?, issuance?, witness? }, with `issuance` { nonce, entropy, amount, inflation } (amounts as bigints or
 * null) and `witness` its script witness stack. Each output is explicit() or blinded(). With `witness` false the
 * transaction is in its txid serialization alone, as a txid commits to it.
 */
export function transaction({ inputs, outputs, locktime = 0, witness = true }) {
  const body = (flag) => cat(
    le32(2), [flag], compactSize(inputs.length),
    ...inputs.map((i) => cat(
      Buffer.from(i.txid, 'hex').reverse(), le32(i.issuance ? (i.vout | 0x80000000) >>> 0 : i.vout), [0x00],
      le32(i.sequence ?? 0xffffffff),
      ...(i.issuance ? [i.issuance.nonce, i.issuance.entropy, amountBytes(i.issuance.amount), amountBytes(i.issuance.inflation ?? null)] : []),
    )),
    compactSize(outputs.length), ...outputs.map(outputBytes), le32(locktime),
  );
  const txidForm = body(0);
  const raw = !witness ? txidForm : cat(
    body(1),
    ...inputs.map((i) => cat([0x00, 0x00], witnessStack(i.witness ?? []), [0x00])),
    ...outputs.map((o) => cat(varBytes(o.surjectionProof ?? []), varBytes(o.rangeproof ?? []))),
  );
  return { raw, hex: toHex(raw), txidForm, txid: toHex(Buffer.from(sha256(sha256(txidForm))).reverse()) };
}

/** A signed P2WPKH input's witness: a made-up DER signature with SIGHASH_ALL, and a made-up compressed key. */
export const signedWitness = (label) => [cat([0x30, 0x44, 0x02, 0x20], filler(`${label}/r`, 32).map((b) => b & 0x7f), [0x02, 0x20],
  filler(`${label}/s`, 32).map((b) => b & 0x7f), [0x01]), cat([0x02], filler(`${label}/key`, 32))];
