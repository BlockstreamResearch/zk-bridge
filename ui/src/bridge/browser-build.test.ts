import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { INSTANCE, parseInstance } from '@bridge/core/config.js';
import { LIQUID_TESTNET_LBTC } from '@bridge/core/lib/bridge.js';
import { bytesToHex, hexToBytes } from '@bridge/core/lib/bytes.js';
import { keccak256 } from '@bridge/core/lib/hash.js';
import * as stateCore from '@bridge/core/lib/update.js';
import type { LiveState } from '@bridge/core/lib/update.js';
import { Esplora } from '@bridge/core/lib/esplora.js';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { prepareBrowserClaim, prepareBrowserUpdate } from './browser-build';

vi.mock('@bridge/core/lib/update.js', async (original) => ({ ...(await original<object>()), liveState: vi.fn() }));
const core = stateCore as typeof stateCore & {
  stateTree(m: unknown): unknown;
  stateScript(tree: unknown, state: LiveState['state']): Uint8Array;
  stateHash(state: { lc: string; acc: string; claimedRoot: string }): string;
};
const read = (path: string) => readFileSync(fileURLToPath(new URL('../../../instances/sepolia-liquid-testnet/' + path, import.meta.url)), 'utf8');
const hash = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest();
const be64 = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const abi = (n: number | bigint) => BigInt(n).toString(16).padStart(64, '0');
const asHex = (n: number) => '0x' + n.toString(16);
const CODE = '0x6080';
const SCRIPT = '0014' + '11'.repeat(20);
const PROGRAM = 'synthetic program for browser preparation tests';
const TOPIC = '0x' + bytesToHex(keccak256('Deposit(uint64,uint64,bytes32,bytes32,bytes32,bytes)'));

// Independent consensus serialization for a synthetic parent transaction, with no real spendable inputs.
function transaction(output: string) {
  const hex = '020000000001' + '01'.repeat(32) + '0000000000ffffffff01' + output + '00000000';
  return { hex, txid: hash(hash(Buffer.from(hex, 'hex'))).reverse().toString('hex') };
}
function explicitFee(sats = 2000) {
  return transaction('01' + LIQUID_TESTNET_LBTC + '01' + be64(sats).toString('hex') + '00' + '16' + SCRIPT);
}

function setup(claim = false) {
  const manifest = JSON.parse(read('manifest.json'));
  const pins = JSON.parse(read('instance.json'));
  const instance = parseInstance({ ...INSTANCE!, codeHash: bytesToHex(keccak256(hexToBytes(CODE))) })!;
  manifest.sepolia.escrow_code_hash = instance.codeHash;
  pins.ESCROW_CODE_HASH = instance.codeHash;
  manifest.update_leaf.text_sha256 = hash(PROGRAM).toString('hex');
  manifest.update_leaf.text_bytes = Buffer.byteLength(PROGRAM);
  const start = pins.ESCROW_DEPLOY_BLOCK;
  const end = start + 24;
  const fee = explicitFee();
  const zero = [Buffer.alloc(32)];
  for (let h = 0; h < 32; h++) zero.push(hash(Buffer.concat([zero[h], zero[h]])));
  const leaves: Buffer[] = [];
  const logs = [0, 1].map((index) => {
    const recipient = hash(Buffer.from(SCRIPT, 'hex'));
    const leaf = hash(Buffer.concat([Buffer.from(manifest.sepolia.deposit_domain, 'hex'), be64(index), be64(250000), recipient]));
    leaves.push(leaf);
    let level = [...leaves];
    for (let h = 0; h < 32; h++) {
      const next: Buffer[] = [];
      for (let i = 0; i < level.length; i += 2) next.push(hash(Buffer.concat([level[i], level[i + 1] ?? zero[h]])));
      level = next;
    }
    const accumulator = hash(Buffer.concat([level[0], be64(index + 1)])).toString('hex');
    return { address: instance.escrow, topics: [TOPIC, '0x' + abi(index)], blockNumber: asHex(start + index), removed: false,
      data: '0x' + abi(250000) + recipient.toString('hex') + leaf.toString('hex') + accumulator + abi(160) + abi(22) + SCRIPT.padEnd(64, '0') };
  });
  const initial = manifest.initial_state;
  const state: LiveState['state'] = { head: initial.head, lc: initial.lc,
    acc: claim ? logs[1].data.slice(2 + 96 * 2, 2 + 128 * 2) : initial.acc,
    claimed: [], claimedRoot: initial.claimed_root, ...(claim ? { execBlock: end } : {}) };
  const stateScript = bytesToHex(core.stateScript(core.stateTree(manifest), state));
  const parent = transaction('0b' + manifest.constants.token_a.x + '09' + manifest.constants.token_value.x + '0022' + stateScript);
  const live: LiveState = { state, outpoint: { txid: claim ? parent.txid : instance.bootstrap, vout: 0 },
    spends: claim ? 1 : 0, update: claim ? parent.txid : null, claims: [], moving: null, movingClaim: null };
  vi.mocked(core.liveState).mockResolvedValue(live);
  const raw = new Map([[instance.bootstrap, read('bootstrap.hex').trim()], [fee.txid, fee.hex], [parent.txid, parent.hex]]);
  const esplora = new Esplora('https://unused.test');
  vi.spyOn(esplora, 'txHex').mockImplementation(async (id) => { if (!raw.has(id)) throw new Error('Unexpected txid'); return raw.get(id)!; });
  vi.spyOn(esplora, 'txStatus').mockResolvedValue({ confirmed: true, block_height: 1 });
  const outspend = vi.spyOn(esplora, 'json').mockImplementation(async () => ({ spent: false }));
  const readEth = vi.fn(async (method: string, params: unknown[] = []): Promise<unknown> => {
    if (method === 'eth_chainId') return asHex(11155111);
    if (method === 'eth_getCode') return CODE;
    if (method === 'eth_getBlockByNumber') return { number: asHex(end + 10) };
    if (method === 'eth_getLogs') {
      const q = params[0] as { fromBlock: string; toBlock: string };
      return logs.filter((l) => Number(l.blockNumber) >= Number(q.fromBlock) && Number(l.blockNumber) <= Number(q.toBlock));
    }
    throw new Error('Unexpected Ethereum method: ' + method);
  });
  const readRecord = vi.fn(async (path: string) => {
    if (path === 'manifest.json') return JSON.stringify(manifest);
    if (path === 'instance.json') return JSON.stringify(pins);
    throw new Error('Unexpected record path: ' + path);
  });
  const header = '44'.repeat(32), committee = '55'.repeat(32), head = initial.head + 32;
  const lc = hash(Buffer.concat([hash('liquid-bridge-poc/lc'), be64(head), Buffer.from(header, 'hex'), Buffer.from(committee, 'hex')])).toString('hex');
  const next = { ...initial, head, header, committee, lc, acc: '66'.repeat(32), exec_block: end, exec_root: '77'.repeat(32) };
  next.state_hash = core.stateHash({ lc, acc: next.acc, claimedRoot: next.claimed_root });
  const bundle = { schema: 'zk-bridge/browser-proof', instance: { liquid: manifest.liquid, sepolia: manifest.sepolia, sp1: manifest.sp1,
    update_cmr: manifest.update_leaf.cmr, claim_cmr: manifest.claim_leaf.cmr }, state: { ...initial }, new_state: next,
    program: PROGRAM, witness: { w_in: '0x00' },
    compiled_program: { program_hex: 'deadbeef', witness_hex: '00', cmr: manifest.update_leaf.cmr as string },
    successor_store: { head, header, committee, lc, store_cbor: '00' } };
  return { args: { instance, esplora, readEth, readRecord, feeTxid: fee.txid, feeVout: 0 }, manifest, pins, live, raw,
    logs, readEth, readRecord, outspend, bundle, fee, end, start };
}

beforeEach(() => vi.resetAllMocks());

describe('browser transaction input preparation', () => {
  it('prepares a proven claim from all contiguous Deposit logs and canonical parents', async () => {
    const f = setup(true);
    const input = await prepareBrowserClaim({ ...f.args, depositIndex: 1 });
    expect(input.deposits).toEqual([[250000, SCRIPT], [250000, SCRIPT]]);
    expect(input.index).toBe(1);
    expect(input.state).toMatchObject({ acc: f.live.state.acc, claimed: [], claimed_root: f.live.state.claimedRoot });
    expect(input.fee_tx_hex).toBe(f.fee.hex);
    expect(f.readRecord.mock.calls.map(([p]) => p)).toEqual(['manifest.json', 'instance.json']);
    expect(f.outspend).toHaveBeenCalledTimes(4);
  });

  it('reduces scans to Alchemy ten-block windows without skipping blocks', async () => {
    const f = setup(true);
    const original = f.readEth.getMockImplementation()!;
    f.readEth.mockImplementation(async (method, params = []) => {
      if (method === 'eth_getLogs') {
        const q = params[0] as { fromBlock: string; toBlock: string };
        if (Number(q.toBlock) - Number(q.fromBlock) + 1 > 10) throw new Error('eth_getLogs limited to a 10 block range');
      }
      return original(method, params);
    });
    await prepareBrowserClaim({ ...f.args, depositIndex: 0 });
    const ranges = f.readEth.mock.calls.filter(([m]) => m === 'eth_getLogs').map(([, p]) => p![0] as { fromBlock: string; toBlock: string });
    expect(ranges.slice(1).map((r) => [Number(r.fromBlock), Number(r.toBlock)])).toEqual([
      [f.start, f.start + 9], [f.start + 10, f.start + 19], [f.start + 20, f.end],
    ]);
  });

  it.each(['missing', 'duplicate', 'wrong accumulator', 'wrong recipient', 'removed', 'outside range'])(
    'refuses %s deposit evidence', async (kind) => {
      const f = setup(true);
      if (kind === 'missing') f.logs.shift();
      if (kind === 'duplicate') f.logs.push({ ...f.logs[0] });
      if (kind === 'wrong accumulator') f.logs[1].data = f.logs[1].data.slice(0, 194) + '00'.repeat(32) + f.logs[1].data.slice(258);
      if (kind === 'wrong recipient') f.logs[0].data = f.logs[0].data.slice(0, 66) + '00'.repeat(32) + f.logs[0].data.slice(130);
      if (kind === 'removed') f.logs[0].removed = true;
      if (kind === 'outside range') {
        f.logs[0].blockNumber = asHex(f.start - 1);
        const original = f.readEth.getMockImplementation()!;
        f.readEth.mockImplementation((m, p) => m === 'eth_getLogs' ? Promise.resolve(f.logs) : original(m, p));
      }
      await expect(prepareBrowserClaim({ ...f.args, depositIndex: 0 })).rejects.toThrow();
    },
  );

  it('propagates authorization failures instead of retrying every block range', async () => {
    const f = setup(true), original = f.readEth.getMockImplementation()!;
    f.readEth.mockImplementation((m, p) => m === 'eth_getLogs' ? Promise.reject(new Error('RPC unauthorized')) : original(m, p));
    await expect(prepareBrowserClaim({ ...f.args, depositIndex: 0 })).rejects.toThrow('RPC unauthorized');
    expect(f.readEth.mock.calls.filter(([m]) => m === 'eth_getLogs')).toHaveLength(1);
  });

  it('stops the RPC scan when the build is cancelled', async () => {
    const f = setup(true), original = f.readEth.getMockImplementation()!;
    const abort = new AbortController();
    f.readEth.mockImplementation(async (method, params) => {
      if (method === 'eth_getLogs') {
        abort.abort();
        throw new Error('eth_getLogs limited to a 10 block range');
      }
      return original(method, params);
    });
    await expect(prepareBrowserClaim({ ...f.args, signal: abort.signal, depositIndex: 0 })).rejects.toThrow('Build cancelled');
    expect(f.readEth.mock.calls.filter(([method]) => method === 'eth_getLogs')).toHaveLength(1);
  });

  it('does not scan deposits beyond the finalized head', async () => {
    const f = setup(true), original = f.readEth.getMockImplementation()!;
    f.readEth.mockImplementation((m, p) => m === 'eth_getBlockByNumber' ? Promise.resolve({ number: asHex(f.end - 1) }) : original(m, p));
    await expect(prepareBrowserClaim({ ...f.args, depositIndex: 0 })).rejects.toThrow(/not finalized/);
    expect(f.readEth.mock.calls.some(([m]) => m === 'eth_getLogs')).toBe(false);
  });

  it('rechecks state spending after the deposit scan', async () => {
    const f = setup(true);
    f.outspend.mockResolvedValueOnce({ spent: false }).mockResolvedValueOnce({ spent: false }).mockResolvedValue({ spent: true });
    await expect(prepareBrowserClaim({ ...f.args, depositIndex: 0 })).rejects.toThrow(/spent/);
  });

  it('refuses a chain change during deposit scanning', async () => {
    const f = setup(true), original = f.readEth.getMockImplementation()!;
    let scanned = false;
    f.readEth.mockImplementation((m, p) => {
      if (m === 'eth_chainId' && scanned) return Promise.resolve('0x1');
      if (m === 'eth_getLogs') scanned = true;
      return original(m, p);
    });
    await expect(prepareBrowserClaim({ ...f.args, depositIndex: 0 })).rejects.toThrow(/Ethereum chain/);
  });

  it('binds an update bundle to current state, instance and exact program bytes', async () => {
    const f = setup();
    const input = await prepareBrowserUpdate({ ...f.args, bundle: f.bundle });
    expect(input).toMatchObject({ compiled_program: f.bundle.compiled_program,
      state: f.bundle.state, new_state: f.bundle.new_state });
    expect(input).not.toHaveProperty('program');
    expect(input).not.toHaveProperty('witness');
  });

  it('explains that the initial state needs a proof before claiming', async () => {
    const f = setup();
    await expect(prepareBrowserClaim({ ...f.args, depositIndex: 0 })).rejects.toThrow('Send a proof update first');
    expect(f.readEth.mock.calls.some(([method]) => method === 'eth_getLogs')).toBe(false);
  });

  it('requires a newly exported compiled proof bundle', async () => {
    const f = setup();
    const bundle: Partial<typeof f.bundle> = { ...f.bundle };
    delete bundle.compiled_program;
    await expect(prepareBrowserUpdate({ ...f.args, bundle })).rejects.toThrow(/Run just proof-bundle again/);
    expect(f.readEth).not.toHaveBeenCalled();
  });

  it('rejects a compiled proof for another update CMR', async () => {
    const f = setup();
    f.bundle.compiled_program.cmr = 'ab'.repeat(32);
    await expect(prepareBrowserUpdate({ ...f.args, bundle: f.bundle })).rejects.toThrow(/Compiled proof CMR/);
  });

  for (const field of ['program_hex', 'witness_hex'] as const) {
    it.each(['', 'abc', 'gg', '0x00', 'ABCD'])(`rejects malformed compiled ${field}: %s`, async (value) => {
      const f = setup();
      f.bundle.compiled_program[field] = value;
      await expect(prepareBrowserUpdate({ ...f.args, bundle: f.bundle })).rejects.toThrow(/lowercase byte hex/);
      expect(f.readEth).not.toHaveBeenCalled();
    });

    it(`rejects oversized compiled ${field} before reading network data`, async () => {
      const f = setup();
      f.bundle.compiled_program[field] = '00'.repeat(4 * 1024 * 1024 + 1);
      await expect(prepareBrowserUpdate({ ...f.args, bundle: f.bundle })).rejects.toThrow(/at most 4194304 bytes/);
      expect(f.readEth).not.toHaveBeenCalled();
    });
  }

  it.each(['wrong chain', 'wrong code', 'wrong instance', 'stale proof', 'changed program', 'missing store', 'wrong fee hash', 'pending state'])(
    'refuses %s before producing builder input', async (kind) => {
      const f = setup(), original = f.readEth.getMockImplementation()!;
      if (kind === 'wrong chain') f.readEth.mockImplementation((m, p) => m === 'eth_chainId' ? Promise.resolve('0x1') : original(m, p));
      if (kind === 'wrong code') f.readEth.mockImplementation((m, p) => m === 'eth_getCode' ? Promise.resolve('0x6081') : original(m, p));
      if (kind === 'wrong instance') f.bundle.instance = { ...f.bundle.instance, claim_cmr: '00'.repeat(32) };
      if (kind === 'stale proof') f.bundle.state.acc = '88'.repeat(32);
      if (kind === 'changed program') f.bundle.program += '\n';
      if (kind === 'missing store') f.bundle.successor_store.store_cbor = '';
      if (kind === 'wrong fee hash') f.raw.set(f.fee.txid, explicitFee(2001).hex);
      if (kind === 'pending state') f.live.moving = 'ab'.repeat(32);
      await expect(prepareBrowserUpdate({ ...f.args, bundle: f.bundle })).rejects.toThrow();
    },
  );
});
