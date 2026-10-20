import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULTS, INSTANCE, parseInstance, parseSettings } from '../config.js';
import { encodeSegwit } from '../lib/bech32.js';
import { hexToBytes } from '../lib/bytes.js';

// EIP-55 example address (eips.ethereum.org/EIPS/eip-55), a second Liquid testnet API, and a Taproot state address
// whose key is the x coordinate of the secp256k1 generator, used only as a valid value.
const CHECKSUMMED = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const OTHER_API = 'https://liquid.example/api';
const STATE = encodeSegwit('tex', 1, hexToBytes('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'));
const RECORD = { name: 'sepolia-liquid-test', escrow: CHECKSUMMED, codeHash: 'cd'.repeat(32), bootstrap: 'ab'.repeat(32), state: STATE };
const RPC = 'https://sepolia.example/v3/0123456789abcdef'; // a provider's key-in-path form

test('the published instance is a valid record, or none', () => {
  assert.equal(INSTANCE === null || parseInstance(INSTANCE) !== null, true);
  assert.equal(parseInstance(null), null);
});

test('an instance record is checked field by field', () => {
  const r = parseInstance(RECORD);
  assert.deepEqual(r, { ...RECORD, escrow: CHECKSUMMED.toLowerCase(), record: 'instances/sepolia-liquid-test/' });
  assert.ok(Object.isFrozen(r));
  assert.throws(() => parseInstance({ ...RECORD, escrow: CHECKSUMMED.replace('a', 'A') }), /checksum/);
  assert.throws(() => parseInstance({ ...RECORD, codeHash: 'CD'.repeat(32) }), /codeHash/);
  assert.throws(() => parseInstance({ ...RECORD, bootstrap: 'ab'.repeat(31) }), /bootstrap/);
  assert.throws(() => parseInstance({ ...RECORD, name: '../elsewhere' }), /name/);
  assert.throws(() => parseInstance({ ...RECORD, state: 'tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn' }), /confidential/);
  // Only the listed fields are kept.
  assert.deepEqual(Object.keys(parseInstance({ ...RECORD, extra: 1 })).sort(), ['bootstrap', 'codeHash', 'escrow', 'name', 'record', 'state']);
});

test('settings: the Liquid API, defaulted when empty, and an optional Sepolia RPC, both checked', () => {
  assert.deepEqual(parseSettings({}), { esplora: DEFAULTS.esplora, ethRpc: null });
  assert.deepEqual(parseSettings({ esplora: 7, ethRpc: 7 }), { esplora: DEFAULTS.esplora, ethRpc: null });
  assert.deepEqual(parseSettings({ esplora: ` ${OTHER_API} `, ethRpc: '  ' }), { esplora: OTHER_API, ethRpc: null });
  // Keys other than these two are ignored, not applied.
  assert.deepEqual(parseSettings({ escrow: CHECKSUMMED, bootstrap: 'ab'.repeat(32), state: STATE }), { esplora: DEFAULTS.esplora, ethRpc: null });
  // Each refusal names its field, which the Settings form places the error under.
  for (const esplora of ['javascript:alert(1)', 'ftp://liquid.example/api', 'liquid.example/api', 'https://liquid example/api']) {
    assert.throws(() => parseSettings({ esplora, ethRpc: RPC }), { field: 'esplora', message: /Esplora API must be an http\(s\) URL/ }, esplora);
  }

  assert.deepEqual(parseSettings({ ethRpc: ` ${RPC} ` }), { esplora: DEFAULTS.esplora, ethRpc: RPC });
  for (const local of ['http://localhost:8545', 'http://127.0.0.1:8545/', 'http://[::1]:8545']) assert.equal(parseSettings({ ethRpc: local }).ethRpc, local);
  // Plain http elsewhere could be answered by anyone on the path; credentials in a URL are refused by fetch itself.
  for (const [ethRpc, message] of [
    ['http://sepolia.example/v3/0123456789abcdef', /https URL, or http only on this computer/],
    ['http://localhost.example:8545', /https URL, or http only on this computer/],
    ['https://user:secret-0123@sepolia.example/', /cannot carry a user name or password/],
    ['wss://sepolia.example/v3/0123456789abcdef', /Sepolia RPC must be an http\(s\) URL/],
    ['sepolia.example/v3/0123456789abcdef', /Sepolia RPC must be an http\(s\) URL/],
    ['not a url', /Sepolia RPC must be an http\(s\) URL/],
  ]) {
    let error;
    assert.throws(() => parseSettings({ ethRpc }), (e) => ((error = e), true), ethRpc);
    assert.match(error.message, message, ethRpc);
    assert.equal(error.field, 'ethRpc', ethRpc);
    // A URL may hold an API key: no message repeats it, or any part of it.
    assert.ok(!/0123456789abcdef|secret|sepolia\.example/.test(error.message), error.message);
  }
});
