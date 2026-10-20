import test from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex, hexToBytes } from '../lib/bytes.js';
import { decodeConfidential, decodeSegwit, encodeSegwit } from '../lib/bech32.js';

test('BIP-173 and BIP-350 valid addresses', () => {
  const cases = [
    ['bc', 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 0, '751e76e8199196d454941c45d1b3a323f1433bd6'],
    ['tb', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 0, '1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'],
    ['bc', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0', 1, '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'],
  ];
  for (const [hrp, addr, version, program] of cases) {
    const d = decodeSegwit(hrp, addr);
    assert.equal(d.version, version, addr);
    assert.equal(bytesToHex(d.program), program, addr);
    assert.equal(encodeSegwit(hrp, version, d.program), addr.toLowerCase());
  }
});

test('rejects bech32 checksums on v1, wrong prefixes and mixed case', () => {
  // BIP-350: a v1 program with a bech32 (not bech32m) checksum.
  assert.throws(() => decodeSegwit('bc', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd'), /checksum/);
  assert.throws(() => decodeSegwit('tex', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'), /prefix/);
  assert.throws(() => decodeSegwit('bc', 'bc1P0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'), /mixed-case/);
  const good = encodeSegwit('tex', 1, hexToBytes('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'));
  const flipped = good.slice(0, -1) + (good.endsWith('q') ? 'p' : 'q');
  assert.throws(() => decodeSegwit('tex', flipped), /checksum/);
});

test('Liquid testnet prefixes round-trip', () => {
  const key = hexToBytes('78dabc6d84b09f040140897d20a39b3a36b8cd4c558bd1af51bbc464394a9f21');
  const addr = encodeSegwit('tex', 1, key);
  assert.match(addr, /^tex1p[02-9ac-hj-np-z]{58}$/);
  assert.deepEqual(decodeSegwit('tex', addr), { version: 1, program: key });
});

test('LWK confidential Liquid testnet address yields its payment script and blinding key', () => {
  const address = 'tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn';
  const decoded = decodeConfidential('tlq', address);
  assert.equal(bytesToHex(decoded.program), 'd0c4a3ef09e997b6e99e397e518fe3e41a118ca1');
  assert.equal(encodeSegwit('tex', 0, decoded.program), 'tex1q6rz28mcfaxtmd6v789l9rrlrusdprr9p634wu8');
  assert.equal(decoded.blindingKey.length, 33);
  assert.deepEqual(decodeConfidential('tlq', address.toUpperCase()), decoded);
  assert.throws(() => decodeConfidential('el', address), /prefix/);
});
