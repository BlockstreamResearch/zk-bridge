// Segwit addresses (BIP-173 bech32 for v0, BIP-350 bech32m for v1+), after the reference implementation.
// Liquid uses the same format for unconfidential addresses with its own prefix: "tex" on Liquid
// testnet, "ex" on Liquid. Confidential addresses ("tlq", "lq") use blech32: decodeSegwit rejects them, and
// decodeConfidential reads a version 0 one, for the blinding key of a wallet's own change.

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const BECH32 = 1;
const BECH32M = 0x2bc830a3;

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GENERATOR[i];
  }
  return chk;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    if (value < 0 || value >> from !== 0) return null;
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    return null;
  }
  return out;
}

/** Decodes a segwit address with the expected prefix; throws a user-readable Error otherwise. */
export function decodeSegwit(hrp, address) {
  const addr = address.trim();
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) throw new Error('mixed-case address');
  const lower = addr.toLowerCase();
  const sep = lower.lastIndexOf('1');
  if (sep < 1 || sep + 7 > lower.length || lower.length > 90) throw new Error('not a bech32 address');
  const prefix = lower.slice(0, sep);
  if (prefix !== hrp) throw new Error(`address prefix is "${prefix}", expected "${hrp}"`);
  const data = [];
  for (const c of lower.slice(sep + 1)) {
    const d = CHARSET.indexOf(c);
    if (d === -1) throw new Error(`invalid address character "${c}"`);
    data.push(d);
  }
  const check = polymod(hrpExpand(prefix).concat(data));
  const version = data[0];
  if (version > 16) throw new Error('invalid witness version');
  if (check !== (version === 0 ? BECH32 : BECH32M)) throw new Error('address checksum is wrong');
  const program = convertBits(data.slice(1, -6), 5, 8, false);
  if (program === null || program.length < 2 || program.length > 40) throw new Error('invalid witness program');
  if (version === 0 && program.length !== 20 && program.length !== 32) throw new Error('invalid v0 program length');
  return { version, program: Uint8Array.from(program) };
}

// Blech32, after Elements' blech32.cpp: bech32's alphabet and HRP expansion, with a 60-bit checksum of 12 characters.
const BLECH32_GENERATOR = [0x7d52fba40bd886n, 0x5e8dbf1a03950cn, 0x1c3a3c74072a18n, 0x385d72fa0e5139n, 0x7093e5a608865bn];

function blech32Polymod(values) {
  let chk = 1n;
  for (const v of values) {
    const top = chk >> 55n;
    chk = ((chk & 0x7fffffffffffffn) << 5n) ^ BigInt(v);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) chk ^= BLECH32_GENERATOR[i];
  }
  return chk;
}

/**
 * Decodes a version 0 confidential address with the expected prefix: its 33-byte blinding key and its witness
 * program (P2WPKH or P2WSH). Throws a user-readable Error otherwise, including for v1+ (blech32m) addresses.
 */
export function decodeConfidential(hrp, address) {
  const addr = address.trim();
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) throw new Error('mixed-case address');
  const lower = addr.toLowerCase();
  const sep = lower.lastIndexOf('1');
  if (sep < 1 || sep + 13 > lower.length || lower.length > 1000) throw new Error('not a confidential address');
  const prefix = lower.slice(0, sep);
  if (prefix !== hrp) throw new Error(`address prefix is "${prefix}", expected "${hrp}"`);
  const data = [];
  for (const c of lower.slice(sep + 1)) {
    const d = CHARSET.indexOf(c);
    if (d === -1) throw new Error(`invalid address character "${c}"`);
    data.push(d);
  }
  if (data[0] !== 0) throw new Error('only version 0 (segwit v0) confidential addresses are read here');
  if (blech32Polymod(hrpExpand(prefix).concat(data)) !== 1n) throw new Error('address checksum is wrong');
  const payload = convertBits(data.slice(1, -12), 5, 8, false);
  if (payload === null || (payload.length !== 33 + 20 && payload.length !== 33 + 32)) throw new Error('invalid confidential address payload');
  const blindingKey = Uint8Array.from(payload.slice(0, 33));
  if (blindingKey[0] !== 0x02 && blindingKey[0] !== 0x03) throw new Error('invalid blinding key');
  return { version: 0, blindingKey, program: Uint8Array.from(payload.slice(33)) };
}

export function encodeSegwit(hrp, version, program) {
  const data = [version].concat(convertBits(Array.from(program), 8, 5, true));
  const values = hrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ (version === 0 ? BECH32 : BECH32M);
  const checksum = [0, 1, 2, 3, 4, 5].map((i) => (mod >> (5 * (5 - i))) & 31);
  const address = hrp + '1' + data.concat(checksum).map((d) => CHARSET[d]).join('');
  decodeSegwit(hrp, address); // round trip: never hand out an address we cannot read back
  return address;
}
