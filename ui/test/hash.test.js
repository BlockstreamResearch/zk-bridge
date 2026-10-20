import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { bytesToHex, utf8 } from '../lib/bytes.js';
import { keccak256, selector, sha256 } from '../lib/hash.js';

test('sha256 agrees with node:crypto across padding boundaries', () => {
  for (const len of [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 4097]) {
    const msg = randomBytes(len);
    assert.equal(bytesToHex(sha256(msg)), createHash('sha256').update(msg).digest('hex'), `length ${len}`);
  }
});

test('keccak256 matches Ethereum vectors', () => {
  assert.equal(bytesToHex(keccak256(new Uint8Array(0))), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(bytesToHex(keccak256('abc')), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
  assert.equal(bytesToHex(keccak256(utf8('abc'))), bytesToHex(keccak256('abc')));
});

test('selectors match solc method identifiers', () => {
  // The first four bytes of keccak256 of each signature, as solc reports them in methodIdentifiers.
  const expected = {
    'deposit(bytes32)': '0xb214faa5',
    'accumulator()': '0x03381154',
    'DOMAIN()': '0x52a9674b',
    'depositCount()': '0x2dfdf0b5',
    'leafOf(uint64,uint64,bytes32)': '0x26fb51b9',
    'rootFromBranch(bytes32,uint64,bytes32[32])': '0x5174a4d8',
    'transfer(address,uint256)': '0xa9059cbb',
  };
  for (const [sig, sel] of Object.entries(expected)) assert.equal(selector(sig), sel, sig);
});
