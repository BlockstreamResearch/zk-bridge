// Runs under check:builders once the native synthetic fixtures have been generated.
// Its exact JSON outputs are then sent through real browser and production Workers.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Instance } from '@bridge/core/config.js';
import { bytesToHex, hexToBytes } from '@bridge/core/lib/bytes.js';
import { displayHex, parseTransaction } from '@bridge/core/lib/elements.js';
import { Esplora } from '@bridge/core/lib/esplora.js';
import { keccak256 } from '@bridge/core/lib/hash.js';
import * as stateCore from '@bridge/core/lib/update.js';
import type { LiveState } from '@bridge/core/lib/update.js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { prepareBrowserClaim, prepareBrowserUpdate } from './browser-build';

// Only chain traversal is replaced. All preparation validation, serialization,
// commitment calculations, bootstrap checks and deposit decoding execute unchanged.
vi.mock('@bridge/core/lib/update.js', async (original) => ({ ...(await original<object>()), liveState: vi.fn() }));
const fixture = (name: string) => resolve(dirname(fileURLToPath(import.meta.url)), '../../../target/browser-builders-tests', name);
const read = (name: string) => JSON.parse(readFileSync(fixture(name), 'utf8'));
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest();
const be64 = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const abi = (n: number) => BigInt(n).toString(16).padStart(64, '0');
const txid = (raw: string) => displayHex(parseTransaction(hexToBytes(raw.trim())).txid);
const CODE = '0x6080';
const TOPIC = '0x' + bytesToHex(keccak256('Deposit(uint64,uint64,bytes32,bytes32,bytes32,bytes)'));

function setup(kind: 'update' | 'claim') {
  const native = read(`${kind}-input.json`);
  expect(native.manifest.label).toMatch(/LOCAL TEST/);
  const manifest = structuredClone(native.manifest);
  // Test-only metadata supplies a fictional site/runtime identity. Cryptographic
  // constants, programs, CMRs, transactions and witnesses remain the native fixtures'.
  manifest.update_leaf.stand_in = false;
  manifest.sepolia.instance = 'synthetic-preparation';
  manifest.sepolia.escrow_code_hash = bytesToHex(keccak256(hexToBytes(CODE)));
  const initial = manifest.initial_state;
  // Native stress fixture uses 120,000 sats. Keep its original parity test and
  // use an explicit 50,000-sat source here, within the actual browser's fee cap.
  const feeHex = kind === 'update'
    ? native.fee_tx_hex.replace('01000000000001d4c0', '01000000000000c350') : native.fee_tx_hex;
  if (kind === 'update') expect(feeHex).not.toBe(native.fee_tx_hex);
  const pins = {
    name: manifest.sepolia.instance, ESCROW: manifest.sepolia.escrow,
    ESCROW_CODE_HASH: manifest.sepolia.escrow_code_hash, DEPOSIT_DOMAIN: manifest.sepolia.deposit_domain,
    GUEST_ELF_SHA256: manifest.sp1.elf_sha256, PROGRAM_VKEY: manifest.sp1.program_vkey,
    ESCROW_DEPLOY_BLOCK: 100,
    ANCHOR: { slot: initial.head, header: initial.header, committee: initial.committee, lc: initial.lc },
  };
  // A serialized fictional bootstrap for the claim fixture's original state.
  // Issuance entropy and every bootstrap check are computed by production code.
  const fundingVout = Buffer.alloc(4);
  fundingVout.writeUInt32LE((manifest.bootstrap.funding_vout | 0x80000000) >>> 0);
  const bootstrap = kind === 'update' ? native.state_tx_hex.trim()
    : '020000000001' + Buffer.from(manifest.bootstrap.funding_txid, 'hex').reverse().toString('hex')
      + fundingVout.toString('hex') + '00ffffffff' + '00'.repeat(64) + '00' + '010000000000000001'
      + '01' + (10 + manifest.constants.token_a.bit).toString(16).padStart(2, '0') + manifest.constants.token_a.x
      + (8 + manifest.constants.token_value.bit).toString(16).padStart(2, '0') + manifest.constants.token_value.x
      + '0022' + manifest.state_tree.script_pubkey + '00000000';
  const instance: Instance = {
    name: pins.name, escrow: '0x' + pins.ESCROW, codeHash: pins.ESCROW_CODE_HASH,
    bootstrap: txid(bootstrap), state: manifest.state_tree.address, record: 'instances/synthetic-preparation/',
  };
  const state = { ...native.state, head: native.state.head ?? initial.head,
    claimedRoot: native.state.claimed_root, ...(kind === 'claim' ? { execBlock: 102 } : {}) };
  const live: LiveState = { state, outpoint: { txid: txid(native.state_tx_hex), vout: native.state_vout },
    spends: kind === 'claim' ? 1 : 0, update: kind === 'claim' ? txid(native.state_tx_hex) : null,
    claims: [], moving: null, movingClaim: null };
  vi.mocked(stateCore.liveState).mockResolvedValue(live);
  const raws = new Map([[instance.bootstrap, bootstrap], [live.outpoint.txid, native.state_tx_hex], [txid(feeHex), feeHex]]);
  const esplora = new Esplora('https://no-network.invalid');
  vi.spyOn(esplora, 'txHex').mockImplementation(async (id) => {
    if (!raws.has(id)) throw new Error('Unexpected transaction source');
    return raws.get(id)!;
  });
  vi.spyOn(esplora, 'txStatus').mockResolvedValue({ confirmed: true, block_height: 1 });
  const outspend = vi.spyOn(esplora, 'json').mockResolvedValue({ spent: false });
  const zero = [Buffer.alloc(32)];
  for (let h = 0; h < 32; h++) zero.push(hash(Buffer.concat([zero[h], zero[h]])));
  const leaves: Buffer[] = [];
  const logs = (native.deposits ?? []).map(([units, script]: [number, string], index: number) => {
    const recipient = hash(Buffer.from(script, 'hex'));
    const leaf = hash(Buffer.concat([Buffer.from(pins.DEPOSIT_DOMAIN, 'hex'), be64(index), be64(units), recipient]));
    leaves.push(leaf);
    let level = [...leaves];
    for (let h = 0; h < 32; h++) {
      const next: Buffer[] = [];
      for (let i = 0; i < level.length; i += 2) next.push(hash(Buffer.concat([level[i], level[i + 1] ?? zero[h]])));
      level = next;
    }
    const accumulator = hash(Buffer.concat([level[0], be64(index + 1)])).toString('hex');
    return { address: instance.escrow, topics: [TOPIC, '0x' + abi(index)], blockNumber: '0x' + (100 + index).toString(16), removed: false,
      data: '0x' + abi(units) + recipient.toString('hex') + leaf.toString('hex') + accumulator + abi(160)
        + abi(script.length / 2) + script.padEnd(Math.ceil(script.length / 64) * 64, '0') };
  });
  const readEth = vi.fn(async (method: string, params: unknown[] = []) => {
    if (method === 'eth_chainId') return '0xaa36a7';
    if (method === 'eth_getCode') return CODE;
    if (method === 'eth_getBlockByNumber') return { number: '0x100' };
    if (method === 'eth_getLogs') {
      const range = params[0] as { fromBlock: string; toBlock: string };
      return logs.filter((log: { blockNumber: string }) => Number(log.blockNumber) >= Number(range.fromBlock) && Number(log.blockNumber) <= Number(range.toBlock));
    }
    throw new Error('Unexpected Ethereum source method: ' + method);
  });
  const readRecord = vi.fn(async (name: string) => {
    if (name === 'manifest.json') return JSON.stringify(manifest);
    if (name === 'instance.json') return JSON.stringify(pins);
    throw new Error('Unexpected site record');
  });
  const next = native.new_state;
  const bundle = kind === 'update' ? {
    schema: 'zk-bridge/browser-proof',
    instance: { liquid: manifest.liquid, sepolia: manifest.sepolia, sp1: manifest.sp1,
      update_cmr: manifest.update_leaf.cmr, claim_cmr: manifest.claim_leaf.cmr },
    state: native.state, new_state: next, program: native.program, witness: native.witness,
    compiled_program: native.compiled_program,
    successor_store: { head: next.head, header: next.header, committee: next.committee, lc: next.lc, store_cbor: '00' },
  } : null;
  return { native, feeHex, manifest, bundle, outspend, args: { instance, esplora, readRecord, readEth, feeTxid: txid(feeHex), feeVout: native.fee_vout } };
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.mocked(stateCore.liveState).mockReset();
  vi.stubGlobal('fetch', vi.fn(() => { throw new Error('Network is forbidden in preparation fixtures'); }));
});
afterEach(() => vi.unstubAllGlobals());

describe.skipIf(process.env.BROWSER_PREPARATION_INTEGRATION !== '1')('real preparation inputs for browser WASM integration', () => {
  it.each(['claim', 'update'] as const)('serializes the actual %s preparation result without adapter rewriting', async (kind) => {
    const f = setup(kind);
    const input = kind === 'claim' ? await prepareBrowserClaim({ ...f.args, depositIndex: f.native.index })
      : await prepareBrowserUpdate({ ...f.args, bundle: f.bundle });
    expect(input.state_tx_hex).toBe(f.native.state_tx_hex.trim());
    expect(input.fee_tx_hex).toBe(f.feeHex.trim());
    expect(input.state_vout).toBe(f.native.state_vout);
    expect(input.fee_vout).toBe(f.native.fee_vout);
    expect(f.outspend).toHaveBeenCalledTimes(4);
    if (kind === 'claim') {
      expect(input.deposits).toEqual(f.native.deposits);
      expect(input.index).toBe(f.native.index);
      expect(f.args.readEth.mock.calls.some(([method]) => method === 'eth_getLogs')).toBe(true);
    } else {
      expect(input.compiled_program).toEqual(f.native.compiled_program);
      expect(input).not.toHaveProperty('program');
      expect(input).not.toHaveProperty('witness');
    }
    writeFileSync(fixture(`${kind}-prepared-input.json`), JSON.stringify(input));
  });
});
