import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bytesToHex, concat, hexToBytes } from '../lib/bytes.js';
import { sha256Compress } from '../lib/hash.js';
import { parseTransaction, txidFromDisplay } from '../lib/elements.js';
import { assetEntropy, assetId, checkBootstrap, reissuanceToken } from '../lib/issuance.js';
import { LIQUID_TESTNET_LBTC } from '../lib/bridge.js';
import { LBTC, blinded, cat, explicit, hex, signedWitness, transaction, word } from './liquid-tx.js';

const sha = (b) => new Uint8Array(createHash('sha256').update(b).digest());

test('one SHA-256 compression of a padded single block is SHA-256 of the message', () => {
  for (const m of [new Uint8Array(0), Uint8Array.from([0x61, 0x62, 0x63]), new Uint8Array(55).fill(7)]) {
    const block = new Uint8Array(64);
    block.set(m);
    block[m.length] = 0x80;
    new DataView(block.buffer).setUint32(60, m.length * 8);
    assert.equal(bytesToHex(sha256Compress(block)), bytesToHex(sha(m)));
  }
  assert.throws(() => sha256Compress(new Uint8Array(63)), /64 bytes/);
});

// Elements' issuance (issuance.cpp): the entropy is the fast Merkle root of SHA256d(prevout) and the contract hash,
// the asset id that of the entropy and 32 zero bytes, and the reissuance token that of the entropy and the leaf 1 (2
// for a confidential issuance) in its first byte. A fast Merkle node is one SHA-256 compression of its two children,
// checked above against node:crypto. Written out here from those definitions, for made-up funding outpoints.
const node = (left, right) => sha256Compress(concat(left, right));
const leaf = (b) => concat([b], new Uint8Array(31));

test('asset and token ids of an issuance, from its funding outpoint', () => {
  for (const [funding, vout] of [[word('funding'), 0], [word('funding'), 1], [word('other funding'), 7]]) {
    const prevout = concat(txidFromDisplay(funding), Uint8Array.of(vout, 0, 0, 0));
    const entropy = node(sha(sha(prevout)), new Uint8Array(32));
    assert.equal(bytesToHex(assetEntropy(txidFromDisplay(funding), vout)), bytesToHex(entropy));
    assert.equal(bytesToHex(assetId(entropy)), bytesToHex(node(entropy, new Uint8Array(32))));
    assert.equal(bytesToHex(reissuanceToken(entropy)), bytesToHex(node(entropy, leaf(1))));
    assert.equal(bytesToHex(reissuanceToken(entropy, true)), bytesToHex(node(entropy, leaf(2))));
  }
  const entropy = assetEntropy(txidFromDisplay(word('funding')), 0);
  assert.notEqual(bytesToHex(assetEntropy(txidFromDisplay(word('funding')), 0, hex(word('contract')))), bytesToHex(entropy),
    'another contract hash, another asset');
  assert.notEqual(bytesToHex(assetId(entropy)), bytesToHex(reissuanceToken(entropy)));
});

// A bootstrap, made up in the shape the bridge tools issue it: input 0 a new issuance (zero blinding nonce and
// contract hash) of no asset and one explicit reissuance token, from a funding outpoint; output 0 the state UTXO,
// blinded, at the state address; the rest explicit tL-BTC change and fee.
const FUNDING = { txid: word('bootstrap funding'), vout: 0 };
const STATE_SCRIPT = hex('5120' + word('state key'));
const bootstrap = ({ amount = null, inflation = 1n, issuanceNonce = new Uint8Array(32), outputs } = {}) => transaction({
  inputs: [{ ...FUNDING, issuance: { nonce: issuanceNonce, entropy: new Uint8Array(32), amount, inflation }, witness: signedWitness('funding') }],
  outputs: outputs ?? [
    blinded(cat([0x0b], hex(word('token'))), cat([0x09], hex(word('token value'))), STATE_SCRIPT),
    explicit(LBTC, 99_000n, hex('0014' + word('change key').slice(0, 40))),
    explicit(LBTC, 1_000n, new Uint8Array(0)),
  ],
});

test('a bootstrap passes every check, and each mismatch is named', () => {
  const tx = parseTransaction(bootstrap().raw);
  const asset = assetId(assetEntropy(txidFromDisplay(FUNDING.txid), FUNDING.vout));
  const honest = { tx, confirmed: true, bridgeAsset: asset, stateScript: STATE_SCRIPT, feeAsset: hexToBytes(LIQUID_TESTNET_LBTC) };
  const ok = checkBootstrap(honest);
  assert.ok(ok.ok, JSON.stringify(ok.checks.filter((c) => !c.ok)));
  const failed = (r) => r.checks.filter((c) => !c.ok).map((c) => c.text);
  const of = (changes) => failed(checkBootstrap({ ...honest, tx: parseTransaction(bootstrap(changes).raw) }));
  assert.deepEqual(failed(checkBootstrap({ ...honest, confirmed: false })), ['the bootstrap transaction is confirmed on Liquid testnet']);
  assert.deepEqual(failed(checkBootstrap({ ...honest, bridgeAsset: new Uint8Array(32) })), ['its asset is the asset this escrow redeems']);
  assert.deepEqual(failed(checkBootstrap({ ...honest, stateScript: concat([0x51, 0x20], new Uint8Array(32).fill(1)) })), ['output 0 pays the published state address']);
  // An operator's bootstrap that kept a second token, or issued the asset itself, or reissued.
  assert.ok(of({ inflation: 2n }).includes('it issues exactly one explicit reissuance token'));
  assert.ok(of({ amount: 1n }).includes('it issues none of the asset itself'));
  assert.ok(of({ issuanceNonce: hex(word('blinding')) }).includes('input 0 is a new issuance (zero blinding nonce)'));
  // An output other than the state that is not explicit tL-BTC could hold the token.
  const outputs = [
    blinded(cat([0x0b], hex(word('token'))), cat([0x09], hex(word('token value'))), STATE_SCRIPT),
    blinded(cat([0x0a], hex(word('elsewhere'))), cat([0x08], hex(word('value'))), hex('0014' + word('operator key').slice(0, 40))),
  ];
  assert.ok(of({ outputs }).includes('every other output is explicit L-BTC, so the token can only be in output 0'));
});
