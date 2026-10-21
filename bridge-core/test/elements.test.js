// Elements transactions and DynaFed headers (lib/elements.js). The transactions are made up and serialized by
// test/liquid-tx.js, independently of the parser; the epoch-start header is a public Liquid testnet block's.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bytesToHex, concat, hexToBytes } from '../lib/bytes.js';
import {
  blockSignatures, displayHex, merkleBranch, outputWitnesses, parseDerSignature, parseHeader, parseTransaction, readWitness,
  txidFromDisplay,
} from '../lib/elements.js';
import { relayBatch } from '../lib/bridge.js';
import { keccak256 } from '../lib/hash.js';
import { LBTC, blinded, cat, explicit, filler, hex, signedWitness, transaction, word } from './liquid-tx.js';

const sha = (b) => new Uint8Array(createHash('sha256').update(b).digest());
const sha2 = (b) => sha(sha(b));

// A fee split: one signed P2WPKH input, three explicit tL-BTC outputs, the last the fee.
const FEE_SPLIT = transaction({
  inputs: [{ txid: word('funding'), vout: 1, witness: signedWitness('funding') }],
  outputs: [
    explicit(LBTC, 2_000n, hex('0014' + word('key').slice(0, 40))), explicit(LBTC, 72_100n, hex('0014' + word('key').slice(0, 40))),
    explicit(LBTC, 300n, new Uint8Array(0)),
  ],
});

// A claim: input 0 spends a state output and reissues 100,000 units; output 0 is the blinded successor, with its
// proofs in the witness, output 1 the units, openly, and output 2 the fee.
const ASSET = hex(word('asset'));
const CLAIM = transaction({
  inputs: [
    {
      txid: word('state'), vout: 0, issuance: { nonce: hex(word('blinding')), entropy: hex(word('entropy')), amount: 100_000n, inflation: null },
      witness: [filler('witness', 1_200), filler('program', 1_636), hex(word('cmr')), filler('control', 97)],
    },
    { txid: word('fee'), vout: 0 },
  ],
  outputs: [
    blinded(cat([0x0b], hex(word('token'))), cat([0x09], hex(word('value'))), hex('5120' + word('successor'))),
    explicit(ASSET, 100_000n, hex('0014' + word('recipient').slice(0, 40))),
    explicit(LBTC, 2_000n, new Uint8Array(0)),
  ],
});

test('transactions reproduce the txid SHA256d of their txid serialization gives', () => {
  const fee = parseTransaction(FEE_SPLIT.raw);
  assert.equal(displayHex(fee.txid), FEE_SPLIT.txid);
  assert.equal(bytesToHex(fee.txidForm), bytesToHex(FEE_SPLIT.txidForm));
  assert.equal(fee.outputs[1].value.amount, 72_100n);
  assert.equal(bytesToHex(fee.outputs[2].script), '');
  assert.equal(bytesToHex(fee.txidForm).slice(0, 10), '0200000000', 'flags byte cleared in the txid form');

  const claimForm = CLAIM.txidForm;
  const claim = parseTransaction(claimForm);
  assert.equal(displayHex(claim.txid), CLAIM.txid);
  assert.equal(bytesToHex(claim.txidForm), bytesToHex(claimForm));
  assert.equal(claim.inputs[0].n >>> 0, 0x80000000, 'the issuance flag on the outpoint index');
  assert.equal(claim.inputs[0].issuance.amount.amount, 100_000n, 'reissued units');
  assert.equal(claim.inputs[0].issuance.inflationKeys.kind, 'null');
  assert.equal(claim.inputs[1].issuance, null);
  assert.equal(claim.outputs[0].asset.kind, 'confidential');
  assert.equal(claim.outputs[0].value.kind, 'confidential');
  assert.equal(bytesToHex(claim.outputs[1].asset.data), bytesToHex(ASSET));
  assert.equal(claim.outputs[1].value.amount, 100_000n);
  assert.throws(() => parseTransaction(concat(claimForm, [0])), /trailing/);
  assert.throws(() => parseTransaction(claimForm.subarray(0, -1)), /truncated/);
});

test('a claim\'s output witness supplies the confidential proofs without changing its txid', () => {
  const raw = CLAIM.raw;
  const tx = parseTransaction(raw);
  assert.equal(displayHex(tx.txid), CLAIM.txid);
  const witnesses = outputWitnesses(raw);
  assert.equal(witnesses.length, tx.outputs.length);
  assert.equal(witnesses[0].rangeproof.length, 4_174);
  assert.equal(witnesses[0].surjectionProof.length, 67);
  assert.equal(witnesses[1].rangeproof.length, 0, 'the explicit bridge claim needs no rangeproof');
  assert.deepEqual(readWitness(raw).inputs[0].script.map((item) => item.length), [1_200, 1_636, 32, 97]);
  assert.throws(() => outputWitnesses(tx.txidForm), /without its witness/);
  assert.throws(() => outputWitnesses(concat(raw, [0])), /trailing bytes/);
  assert.throws(() => outputWitnesses(raw.subarray(0, -1)), /truncated/);
});

test('DER signatures', () => {
  const R = '11'.repeat(32);
  const S = '2b'.repeat(32);
  const sig = hexToBytes('30440220' + R + '0220' + S + '01');
  const { r, s } = parseDerSignature(sig);
  assert.equal(bytesToHex(r), R);
  assert.equal(bytesToHex(s), S);
  // A 33-byte r with its sign-padding zero.
  const padded = hexToBytes('3045022100' + 'ff'.repeat(32) + '0220' + '11'.repeat(32) + '01');
  assert.equal(bytesToHex(parseDerSignature(padded).r), 'ff'.repeat(32));
  assert.throws(() => parseDerSignature(sig.subarray(0, 20)), /DER/);
});

function le32(x) {
  return Uint8Array.of(x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, x >>> 24);
}

// A 1-of-1 OP_CHECKMULTISIG DynaFed header with its signblock witness, the shape Liquid testnet serves.
function signedHeader() {
  const key = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  const script = concat([0x51, 0x21], key, [0x51, 0xae]);
  const spk = concat([0x00, 0x20], sha(script));
  const sig = hexToBytes('30440220' + '11'.repeat(32) + '0220' + '2b'.repeat(32) + '01');
  const hashForm = concat(le32(0xa0000000), new Uint8Array(32).fill(0x11), new Uint8Array(32).fill(0x22), le32(1_760_000_000), le32(2_664_802),
    [0x01, spk.length], spk, le32(150), new Uint8Array(32).fill(0xe1), [0x00]);
  const witness = concat([0x03, 0x00, sig.length], sig, [script.length], script);
  return { hashForm, full: concat(hashForm, witness), script, spk };
}

test('DynaFed header: hash form, height and block signatures', () => {
  const { hashForm, full, script, spk } = signedHeader();
  const h = parseHeader(full);
  assert.equal(bytesToHex(h.hashForm), bytesToHex(hashForm));
  assert.equal(bytesToHex(h.hash), bytesToHex(sha2(hashForm)));
  assert.equal(h.height, 2_664_802);
  assert.equal(bytesToHex(h.signblockscript), bytesToHex(spk));
  const { witnessScript, signatures } = blockSignatures(h);
  assert.equal(bytesToHex(witnessScript), bytesToHex(script));
  assert.equal(signatures.length, 1);
  assert.equal(bytesToHex(signatures[0].r), '11'.repeat(32));
  assert.throws(() => blockSignatures(parseHeader(hashForm)), /no signblock witness/);
  assert.throws(() => parseHeader(concat(full, [0])), /trailing/);
  const legacy = Uint8Array.from(full);
  legacy[3] = 0x20; // clear the DynaFed bit
  assert.throws(() => parseHeader(legacy), /not a DynaFed/);
});

// Public Liquid testnet block 2,664,000, the first block of an epoch, so its current params are in full form (fedpeg program, fedpegscript and the PAK extension). Its
// signed form appends the signblock witness [empty, DER(r, s) || SIGHASH_ALL, witness script]; Elements requires
// strict DER, so these bytes are the 323-byte header Esplora serves.
const REAL_HASH_FORM =
  '000000a04054cb0dd4c42b4725aac4b85b1cb0d86738b09bc06789ade85088fc382c2e61e56e1c9fefbc09a6343654e694071b79bada50986eea3fba469f489439a4e1c3c9c1d26a40a6280002220020e9e4117540f7f23b3edd7c2cad660a17fb33c7959b8c37cf61d92b189133929a9600000017a91472c44f957fc011d97e3406667dca5b1c930c4026870151014202fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f02fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f00';
const REAL_SCRIPT = '51210217e403ddb181872c32a0cd468c710040b2f53d8cac69f18dad07985ee37e9a7151ae';
const REAL_R = '4b36a7485d57747c837f3d481966a896ac5ab610f9c99acce7cd1ef452d9e3db';
const REAL_S = '71d9ccd8f1598bb17f348f198168b82627da564fc1e79a7cf15d8f99cb33f8e5';
const REAL_SIGNED = REAL_HASH_FORM + '03' + '00' + '47' + '30440220' + REAL_R + '0220' + REAL_S + '01' + '25' + REAL_SCRIPT;

test('a real Liquid testnet epoch-start header: block id, signer script and signature', () => {
  assert.equal(REAL_SIGNED.length / 2, 323);
  const h = parseHeader(hexToBytes(REAL_SIGNED));
  assert.equal(bytesToHex(h.hashForm), REAL_HASH_FORM);
  assert.equal(displayHex(h.hash), '1a195d11b63038c91100a09efdb1489ae16e6f6f64cdc20a227015bc4ba77eb7', 'the block id Blockstream displays');
  assert.equal(h.height, 2_664_000);
  const { witnessScript, signatures } = blockSignatures(h);
  assert.equal(bytesToHex(witnessScript), REAL_SCRIPT, 'the 1-of-1 OP_CHECKMULTISIG of one Blockstream key');
  assert.deepEqual(signatures.map((s) => [bytesToHex(s.r), bytesToHex(s.s)]), [[REAL_R, REAL_S]]);

  // As a relay batch: no witness script unless the light client holds another signing script.
  const own = '0x' + bytesToHex(keccak256(h.signblockscript));
  const same = relayBatch([REAL_SIGNED], own);
  assert.equal(bytesToHex(same.headers[0]), REAL_HASH_FORM);
  assert.equal(same.witnessScript.length, 0);
  assert.equal(same.keyY.length, 0);
  const changed = relayBatch([REAL_SIGNED], '0x' + '11'.repeat(32));
  assert.equal(bytesToHex(changed.witnessScript), REAL_SCRIPT);
  assert.deepEqual(changed.keyY, [0x6b3e7c7a50a5a173b577290cb7ee976809b87df20db40875ee7acdd79b81b642n]);
});

test('Merkle branches, including the duplicated last leaf', () => {
  const leaves = [1, 2, 3].map((i) => sha(Uint8Array.of(i)));
  const n01 = sha2(concat(leaves[0], leaves[1]));
  const n22 = sha2(concat(leaves[2], leaves[2]));
  const root = sha2(concat(n01, n22));
  for (let i = 0; i < 3; i++) assert.equal(bytesToHex(merkleBranch(leaves, i).root), bytesToHex(root));
  assert.deepEqual(merkleBranch(leaves, 1).branch.map(bytesToHex), [bytesToHex(leaves[0]), bytesToHex(n22)]);
  assert.deepEqual(merkleBranch(leaves, 2).branch.map(bytesToHex), [bytesToHex(leaves[2]), bytesToHex(n01)]);
  assert.equal(merkleBranch([leaves[0]], 0).branch.length, 0);
  assert.equal(displayHex(txidFromDisplay(CLAIM.txid)), CLAIM.txid);
  assert.equal(bytesToHex(txidFromDisplay(CLAIM.txid)), bytesToHex(parseTransaction(CLAIM.raw).txid), 'display order is reversed');
});
