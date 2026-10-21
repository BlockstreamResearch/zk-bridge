// Read-only Liquid data from an Esplora HTTP API (Blockstream's public instance by default). Nothing read
// here is trusted: every byte that matters is re-checked by lib/elements.js and then by the contracts.
import { txidFromDisplay } from './elements.js';

export class Esplora {
  constructor(base, fetchImpl = globalThis.fetch.bind(globalThis)) {
    this.base = base.replace(/\/+$/, '');
    this.fetch = fetchImpl;
  }

  async text(path) {
    const res = await this.fetch(this.base + path);
    if (!res.ok) throw Object.assign(new Error(`Liquid API ${path}: HTTP ${res.status}`), { status: res.status });
    return (await res.text()).trim();
  }

  async json(path) {
    return JSON.parse(await this.text(path));
  }

  tipHeight() {
    return this.text('/blocks/tip/height').then(Number);
  }

  blockHashAt(height) {
    return this.text(`/block-height/${height}`);
  }

  header(hash) {
    return this.text(`/block/${hash}/header`);
  }

  txids(hash) {
    return this.json(`/block/${hash}/txids`);
  }

  txHex(txid) {
    return this.text(`/tx/${txid}/hex`);
  }

  txStatus(txid) {
    return this.json(`/tx/${txid}/status`);
  }

  /** Whether output `vout` of `txid` is spent: { spent, txid?, vin?, status? } of the spending transaction. */
  outspend(txid, vout) {
    return this.json(`/tx/${txid}/outspend/${vout}`);
  }

  addressTxs(address) {
    return this.json(`/address/${address}/txs`);
  }

  /** Unspent outputs at an address; explicit ones carry `asset` (display id) and `value`. */
  addressUtxos(address) {
    return this.json(`/address/${address}/utxo`);
  }

  /** The current tip's raw header, for comparing its signblockscript with the light client's. */
  async tipHeader() {
    return this.header(await this.text('/blocks/tip/hash'));
  }

  /** Block summaries for heights first .. last, keyed by height (Esplora serves 10 per request, descending). */
  async blocks(first, last) {
    const out = new Map();
    for (let h = last; h >= first; h -= 10) {
      for (const b of await this.json(`/blocks/${h}`)) if (b.height >= first && b.height <= last) out.set(b.height, b);
    }
    for (let h = first; h <= last; h++) if (!out.has(h)) throw new Error(`Liquid API did not return block ${h}`);
    return out;
  }

  /** Transaction Merkle roots, internal byte order, for heights first .. last in order. */
  async merkleRoots(first, last) {
    const blocks = await this.blocks(first, last);
    const roots = [];
    for (let h = first; h <= last; h++) roots.push(txidFromDisplay(blocks.get(h).merkle_root));
    return roots;
  }

  /** Raw headers (with signblock witness) for heights first .. last in order. */
  async headers(first, last) {
    const blocks = await this.blocks(first, last);
    const out = [];
    for (let h = first; h <= last; h++) out.push(await this.header(blocks.get(h).id));
    return out;
  }
}
