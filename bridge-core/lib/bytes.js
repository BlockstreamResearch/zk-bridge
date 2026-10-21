// Byte helpers shared by the browser app and the justfile's Node helpers. Uint8Array everywhere; hex without 0x
// unless a function says otherwise.

export function hexToBytes(hex) {
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('not a hex string');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function bytesToHex(b) {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function reversed(b) {
  return Uint8Array.from(b).reverse();
}

export function equal(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

export function utf8(s) {
  return new TextEncoder().encode(s);
}

/** Big-endian bytes of a non-negative BigInt, left-padded to `size`. */
export function bigToBytes(v, size) {
  if (v < 0n) throw new Error('negative');
  const out = new Uint8Array(size);
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error(`value does not fit in ${size} bytes`);
  return out;
}

export function bytesToBig(b) {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

/** A cursor over consensus-encoded bytes that throws on any read past the end. */
export class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.p = 0;
  }

  need(n) {
    if (this.p + n > this.b.length) throw new Error(`truncated at byte ${this.p}`);
  }

  u8() {
    this.need(1);
    return this.b[this.p++];
  }

  bytes(n) {
    this.need(n);
    const out = this.b.subarray(this.p, this.p + n);
    this.p += n;
    return out;
  }

  u32le() {
    const x = this.bytes(4);
    return (x[0] | (x[1] << 8) | (x[2] << 16) | (x[3] << 24)) >>> 0;
  }

  u64be() {
    return bytesToBig(this.bytes(8));
  }

  /** Bitcoin CompactSize; non-minimal encodings are rejected, as Elements does. */
  compactSize() {
    const first = this.u8();
    if (first < 0xfd) return first;
    const width = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
    const x = this.bytes(width);
    let v = 0n;
    for (let i = width - 1; i >= 0; i--) v = (v << 8n) | BigInt(x[i]);
    const min = width === 2 ? 0xfdn : width === 4 ? 0x10000n : 0x100000000n;
    if (v < min) throw new Error('non-canonical CompactSize');
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('CompactSize too large');
    return Number(v);
  }

  varBytes() {
    return this.bytes(this.compactSize());
  }

  get done() {
    return this.p === this.b.length;
  }
}
