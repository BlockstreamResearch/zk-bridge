// The subset of the Solidity ABI the bridge calls need. Types: 'address', 'bool', 'uintN', 'bytes32',
// 'bytes', { array: T } and { tuple: [T...] }. Values: hex strings or Uint8Array for bytes, BigInt or
// number for integers, arrays for arrays and tuples.
import { bigToBytes, bytesToBig, bytesToHex, concat, hexToBytes } from './bytes.js';
import { selector } from './hash.js';

const asBytes = (v) => (typeof v === 'string' ? hexToBytes(v) : v);

function isDynamic(t) {
  if (t === 'bytes') return true;
  if (t.array) return true;
  if (t.tuple) return t.tuple.some(isDynamic);
  return false;
}

function staticSize(t) {
  return t.tuple ? t.tuple.reduce((n, m) => n + staticSize(m), 0) : 32;
}

function word(v) {
  return bigToBytes(BigInt(v), 32);
}

function encode(t, v) {
  if (t === 'address') {
    const b = asBytes(v);
    if (b.length !== 20) throw new Error('an address is 20 bytes');
    return concat(new Uint8Array(12), b);
  }
  if (t === 'bool') return word(v ? 1 : 0);
  if (t === 'bytes32') {
    const b = asBytes(v);
    if (b.length !== 32) throw new Error('bytes32 needs 32 bytes');
    return b;
  }
  if (typeof t === 'string' && t.startsWith('uint')) {
    const bits = Number(t.slice(4));
    if (BigInt(v) < 0n || BigInt(v) >> BigInt(bits) !== 0n) throw new Error(`${t} out of range`);
    return word(v);
  }
  if (t === 'bytes') {
    const b = asBytes(v);
    return concat(word(b.length), b, new Uint8Array((32 - (b.length % 32)) % 32));
  }
  if (t.array) return concat(word(v.length), encodeTuple(v.map(() => t.array), v));
  if (t.tuple) return encodeTuple(t.tuple, v);
  throw new Error(`unsupported ABI type ${JSON.stringify(t)}`);
}

function encodeTuple(types, values) {
  if (types.length !== values.length) throw new Error('ABI arity mismatch');
  const headSize = types.reduce((n, t) => n + (isDynamic(t) ? 32 : staticSize(t)), 0);
  const heads = [];
  const tails = [];
  let offset = headSize;
  types.forEach((t, i) => {
    const enc = encode(t, values[i]);
    if (isDynamic(t)) {
      heads.push(word(offset));
      tails.push(enc);
      offset += enc.length;
    } else {
      heads.push(enc);
    }
  });
  return concat(...heads, ...tails);
}

/** 0x-prefixed calldata for `signature`, e.g. 'redeem(address,(bytes,uint32,bytes32[],uint32),...)'. */
export function encodeCall(signature, types, values) {
  return selector(signature) + bytesToHex(encodeTuple(types, values));
}

// Decoders for the return values the app reads.
function at(data, offset) {
  if (offset + 32 > data.length) throw new Error('ABI data too short');
  return data.subarray(offset, offset + 32);
}

export const decode = {
  uint: (hex) => bytesToBig(at(hexToBytes(hex), 0)),
  bool: (hex) => bytesToBig(at(hexToBytes(hex), 0)) === 1n,
  bytes32: (hex) => bytesToHex(at(hexToBytes(hex), 0)),
  address: (hex) => '0x' + bytesToHex(at(hexToBytes(hex), 0).subarray(12)),
  bytes: (hex) => {
    const d = hexToBytes(hex);
    const off = Number(bytesToBig(at(d, 0)));
    const len = Number(bytesToBig(at(d, off)));
    if (off + 32 + len > d.length) throw new Error('ABI bytes too short');
    return d.slice(off + 32, off + 32 + len);
  },
  addressArray: (hex) => {
    const d = hexToBytes(hex);
    const off = Number(bytesToBig(at(d, 0)));
    const len = Number(bytesToBig(at(d, off)));
    return Array.from({ length: len }, (_, i) => '0x' + bytesToHex(at(d, off + 32 + 32 * i).subarray(12)));
  },
};
