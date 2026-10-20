// SHA-256 (FIPS 180-4) and Ethereum's Keccak-256, synchronous and dependency-free so the same code runs
// in the page (no secure-context requirement) and in Node tests. The round constants are derived here
// from their definitions instead of being typed in; ui/test/hash.test.js checks both functions against
// node:crypto and known Ethereum selectors.
import { utf8 } from './bytes.js';

function primes(count) {
  const out = [];
  for (let n = 2; out.length < count; n++) {
    if (out.every((p) => n % p !== 0)) out.push(n);
  }
  return out;
}

// floor(n^(1/k)) for a BigInt n, from a floating-point guess corrected to the exact integer root.
function iroot(n, k) {
  let x = BigInt(Math.floor(Math.pow(Number(n), 1 / k)));
  while (x ** BigInt(k) > n) x -= 1n;
  while ((x + 1n) ** BigInt(k) <= n) x += 1n;
  return x;
}

// First 32 bits of the fractional parts of the cube roots (K) and square roots (H0) of the first primes.
const K = Uint32Array.from(primes(64), (p) => Number(iroot(BigInt(p) << 96n, 3) & 0xffffffffn));
const H0 = Uint32Array.from(primes(8), (p) => Number(iroot(BigInt(p) << 64n, 2) & 0xffffffffn));

const rotr = (x, n) => (x >>> n) | (x << (32 - n));

/** One SHA-256 compression of the 64-byte block at `off` in `view`, updating the state words `h`. */
function compress(h, view, off, w) {
  for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + 4 * i);
  for (let i = 16; i < 64; i++) {
    const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
    const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }
  let [a, b, c, d, e, f, g, hh] = h;
  for (let i = 0; i < 64; i++) {
    const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
    const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
    [hh, g, f, e, d, c, b, a] = [g, f, e, (d + t1) >>> 0, c, b, a, (t1 + t2) >>> 0];
  }
  const add = [a, b, c, d, e, f, g, hh];
  for (let i = 0; i < 8; i++) h[i] = (h[i] + add[i]) >>> 0;
}

function stateBytes(h) {
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(4 * i, h[i]);
  return out;
}

export function sha256(msg) {
  const len = msg.length;
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(msg);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(len / 0x20000000)); // high bits of 8 * len
  view.setUint32(padded.length - 4, (len * 8) >>> 0);
  const h = Uint32Array.from(H0);
  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) compress(h, view, off, w);
  return stateBytes(h);
}

/**
 * The SHA-256 state after compressing one 64-byte block from the standard IV, without padding: a node of
 * Elements' "fast Merkle root" (consensus/merkle.cpp ComputeFastMerkleRoot), from which asset ids derive.
 */
export function sha256Compress(block) {
  if (block.length !== 64) throw new Error('a SHA-256 block is 64 bytes');
  const h = Uint32Array.from(H0);
  compress(h, new DataView(block.buffer, block.byteOffset, 64), 0, new Uint32Array(64));
  return stateBytes(h);
}

export function sha256d(msg) {
  return sha256(sha256(msg));
}

// Keccak-f[1600] on 25 BigInt lanes; lane (x, y) is A[x + 5y].
const MASK = (1n << 64n) - 1n;
const rotl = (v, n) => (n === 0n ? v : ((v << n) | (v >> (64n - n))) & MASK);

function rcBit(t) {
  let r = 1;
  for (let i = 0; i < t % 255; i++) {
    r <<= 1;
    if (r & 0x100) r ^= 0x171; // x^8 + x^6 + x^5 + x^4 + 1
  }
  return r & 1;
}

const RC = Array.from({ length: 24 }, (_, round) => {
  let rc = 0n;
  for (let j = 0; j < 7; j++) if (rcBit(j + 7 * round)) rc |= 1n << BigInt((1 << j) - 1);
  return rc;
});

const ROT = (() => {
  const r = new Array(25).fill(0n);
  let [x, y] = [1, 0];
  for (let t = 0; t < 24; t++) {
    r[x + 5 * y] = BigInt((((t + 1) * (t + 2)) / 2) % 64);
    [x, y] = [y, (2 * x + 3 * y) % 5];
  }
  return r;
})();

function keccakF(A) {
  for (let round = 0; round < 24; round++) {
    const C = [0, 1, 2, 3, 4].map((x) => A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20]);
    for (let x = 0; x < 5; x++) {
      const D = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1n);
      for (let y = 0; y < 5; y++) A[x + 5 * y] ^= D;
    }
    const B = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], ROT[x + 5 * y]);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) A[x + 5 * y] = B[x + 5 * y] ^ (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y]);
    }
    A[0] ^= RC[round];
  }
}

/** Ethereum's Keccak-256 (original Keccak padding 0x01 ... 0x80, not SHA3-256). Strings are UTF-8. */
export function keccak256(input) {
  const msg = typeof input === 'string' ? utf8(input) : input;
  const rate = 136;
  const padded = new Uint8Array((Math.floor(msg.length / rate) + 1) * rate);
  padded.set(msg);
  padded[msg.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const A = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(padded[off + 8 * i + j]);
      A[i] ^= lane;
    }
    keccakF(A);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = A[i];
    for (let j = 0; j < 8; j++) {
      out[8 * i + j] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

/** The 4-byte selector of a canonical function or error signature, as 0x-prefixed hex. */
export function selector(signature) {
  return '0x' + Array.from(keccak256(signature).subarray(0, 4), (x) => x.toString(16).padStart(2, '0')).join('');
}
