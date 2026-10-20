// A reader of the PSETs lib/humid.js writes, for tests, written from BIP 370 and Elements' PSET fields rather than
// from lib/humid.js: the global, input and output maps (hex key -> value), and the unsigned transaction they describe.
import { Reader, bytesToHex, concat } from '../lib/bytes.js';

/** Elements' proprietary key prefix: 0xfc, then the identifier "pset". */
export const ELEMENTS = 'fc0470736574';

export function readPset(base64) {
  const bytes = Uint8Array.from(Buffer.from(base64, 'base64'));
  if (bytesToHex(bytes.subarray(0, 5)) !== '70736574ff') throw new Error('not a PSET');
  const r = new Reader(bytes);
  r.p = 5;
  const readMap = () => {
    const m = new Map();
    for (let n = r.compactSize(); n !== 0; n = r.compactSize()) {
      const key = bytesToHex(r.bytes(n));
      if (m.has(key)) throw new Error(`duplicate key ${key}`);
      m.set(key, r.varBytes());
    }
    return m;
  };
  const global = readMap();
  const count = (k) => new Reader(global.get(k)).compactSize();
  const inputs = Array.from({ length: count('04') }, readMap);
  const outputs = Array.from({ length: count('05') }, readMap);
  if (!r.done) throw new Error('trailing bytes after the PSET');
  return { global, inputs, outputs };
}

/**
 * The transaction of a PSET, in txid serialization, whose outputs are each either still explicit or blinded already
 * (value and asset commitments, Elements' PSBT_ELEMENTS_OUT_VALUE_COMMITMENT 0x01 and ASSET_COMMITMENT 0x03), with no
 * nonce.
 */
export function psetTransaction({ global, inputs, outputs }) {
  const varBytes = (b) => concat([b.length], b);
  return concat(
    global.get('02'), [0x00], [inputs.length],
    ...inputs.map((m) => concat(m.get('0e'), m.get('0f'), [0x00], m.get('10') ?? [0xff, 0xff, 0xff, 0xff])),
    [outputs.length],
    ...outputs.map((m) => (m.has(`${ELEMENTS}01`)
      ? concat(m.get(`${ELEMENTS}03`), m.get(`${ELEMENTS}01`), [0x00], varBytes(m.get('04')))
      : concat([0x01], m.get(`${ELEMENTS}02`), [0x01], Uint8Array.from(m.get('03')).reverse(), [0x00], varBytes(m.get('04'))))),
    global.get('03') ?? [0, 0, 0, 0],
  );
}
