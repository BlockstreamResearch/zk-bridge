// A wallet timeout must not make its fee inputs available after a page reload.
import { discoverFeeCoins, prepareFeeWithHumid, releaseFeePreparationInputs } from '@bridge/core/lib/fee.js';
import { burnWithHumid, findHumid, type Humid } from '@bridge/core/lib/humid.js';
import { claimOnLiquid, prepareClaim, sendClaim, type ClaimPlan } from '@bridge/core/lib/claim.js';
import { prepareUpdate, sendUpdate, withStore, type UpdatePlan } from '@bridge/core/lib/update.js';
import { bytesToHex, hexToBytes } from '@bridge/core/lib/bytes.js';
import { displayHex, parseTransaction } from '@bridge/core/lib/elements.js';
import { beforeEach, expect, it, vi } from 'vitest';
import { ACCOUNT_CHECKSUMMED, BOOTSTRAP_TXID, DEPOSIT_ADDRESS, fixture } from '../dev/fixture';
import { prepareBrowserUpdate } from './browser-build';
import { BridgeController } from './controller';
import * as derive from './derive';

vi.mock('@bridge/core/lib/fee.js', () => ({ discoverFeeCoins: vi.fn(), prepareFeeWithHumid: vi.fn(), releaseFeePreparationInputs: vi.fn() }));
vi.mock('@bridge/core/lib/humid.js', async (original) => ({ ...await original<object>(), findHumid: vi.fn(), burnWithHumid: vi.fn() }));
vi.mock('@bridge/core/lib/claim.js', async (original) => ({ ...await original<object>(), prepareClaim: vi.fn(), sendClaim: vi.fn(), claimOnLiquid: vi.fn() }));
vi.mock('@bridge/core/lib/update.js', async (original) => ({ ...await original<object>(), prepareUpdate: vi.fn(), sendUpdate: vi.fn(), withStore: vi.fn() }));
vi.mock('./browser-build', () => ({ prepareBrowserUpdate: vi.fn(), prepareBrowserClaim: vi.fn() }));

const point = BOOTSTRAP_TXID + ':1';
const preparedTxid = 'cd'.repeat(32);
const preparedPoint = preparedTxid + ':0';
const otherPoint = 'ef'.repeat(32) + ':2';
const key = 'zk-bridge:reserved-fees';
const result = { txid: preparedTxid, vout: 0, sats: 2_000n, txHex: '', address: DEPOSIT_ADDRESS, confirmed: false,
  plan: { spends: [point] } } as Awaited<ReturnType<typeof prepareFeeWithHumid>>;
const planFee = { txid: preparedTxid, vout: 0, sats: 2000n };
const claimPlan = { txid: '12'.repeat(32), claim: { fee: planFee } } as ClaimPlan;
const updatePlan = { txid: '34'.repeat(32), update: { fee: planFee }, store: { where: 'site', path: 'store.json' } } as UpdatePlan;
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(findHumid).mockResolvedValue({} as Humid);
  vi.mocked(discoverFeeCoins).mockResolvedValue([]);
  vi.mocked(prepareClaim).mockResolvedValue(claimPlan);
  vi.mocked(prepareUpdate).mockResolvedValue(updatePlan);
  vi.mocked(claimOnLiquid).mockResolvedValue({ where: 'unknown' });
});

const saved = (f: ReturnType<typeof fixture>) => JSON.parse(f.storage.get(key)!);

function recoveryFixture() {
  const f = fixture('connected');
  const fetch = f.env.fetch;
  f.env.fetch = async (input, init) => {
    const path = new URL(String(input)).pathname;
    if (path.endsWith('/block-height/0')) return new Response('a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1');
    if (path.endsWith(`/tx/${BOOTSTRAP_TXID}/outspend/1`)) return Response.json({ spent: false });
    return fetch(input, init);
  };
  return f;
}

async function readyBurn(f: ReturnType<typeof fixture>) {
  const c = new BridgeController(f.instance, f.env);
  c.start();
  await c.restored;
  c.stop();
  c.setRedeemForm({ recipient: ACCOUNT_CHECKSUMMED, amount: '0.001', humidAddress: DEPOSIT_ADDRESS });
  await vi.waitFor(() => expect(derive.target(c.getSnapshot())).not.toBeNull());
  return c;
}

function uncertainPreparation() {
  vi.mocked(prepareFeeWithHumid).mockImplementation(async ({ onSign }) => {
    await onSign?.([point]);
    throw Object.assign(new Error('Wallet timed out'), { sent: 'maybe' });
  });
}

it('persists inputs before signing and excludes an uncertain send after reload', async () => {
  const f = fixture('connected');
  const c = new BridgeController(f.instance, f.env);
  vi.mocked(prepareFeeWithHumid).mockImplementation(async ({ onSign }) => {
    await onSign?.([point]);
    expect(saved(f).pending).toContain(point);
    throw Object.assign(new Error('Wallet timed out'), { sent: 'maybe' });
  });
  await expect(c.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {})).rejects.toThrow('Wallet timed out');
  const reloaded = new BridgeController(f.instance, f.env);
  expect(reloaded.getFeeReservationStatus()).toEqual({ pending: 1, busy: false });
  await reloaded.findFeeCoins(DEPOSIT_ADDRESS, 2000n);
  expect(vi.mocked(discoverFeeCoins).mock.calls[0][0].skip?.has(point)).toBe(true);
});

it('releases the reservation only when the wallet confirms nothing was sent', async () => {
  const f = fixture('connected');
  const c = new BridgeController(f.instance, f.env);
  vi.mocked(prepareFeeWithHumid).mockImplementation(async ({ onSign }) => {
    await onSign?.([point]);
    throw Object.assign(new Error('Declined'), { sent: 'no' });
  });
  await expect(c.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {})).rejects.toThrow('Declined');
  expect(saved(f).pending).not.toContain(point);
  await c.findFeeCoins(DEPOSIT_ADDRESS, 2000n);
  expect(vi.mocked(discoverFeeCoins).mock.calls[0][0].skip?.has(point)).toBe(false);
});

it('stops before signing when reservations cannot be saved', async () => {
  const f = fixture('connected');
  const c = new BridgeController(f.instance, f.env);
  const sign = vi.fn();
  f.env.storage.setItem = () => { throw new Error('Storage unavailable'); };
  vi.mocked(prepareFeeWithHumid).mockImplementation(async ({ onSign }) => {
    await onSign?.([point]);
    sign();
    throw new Error('Must not reach the wallet');
  });
  await expect(c.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {})).rejects.toThrow('Storage unavailable');
  expect(sign).not.toHaveBeenCalled();
});

it('keeps prepared outputs out of source selection after reload while discovery can still select them', async () => {
  const f = fixture('connected');
  const c = new BridgeController(f.instance, f.env);
  vi.mocked(prepareFeeWithHumid).mockImplementationOnce(async ({ onSign }) => {
    await onSign?.([point]);
    return result;
  });
  await c.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {});
  expect(saved(f)).toEqual({ pending: [], prepared: [preparedPoint] });
  const reloaded = await readyBurn(f);
  expect(reloaded.getFeeReservationStatus().pending).toBe(0);
  await reloaded.findFeeCoins(DEPOSIT_ADDRESS, 2000n);
  expect(vi.mocked(discoverFeeCoins).mock.calls.at(-1)?.[0].skip?.has(preparedPoint)).toBe(false);
  vi.mocked(prepareFeeWithHumid).mockImplementationOnce(async ({ skip }) => {
    expect(skip?.has(preparedPoint)).toBe(true);
    throw new Error('No source');
  });
  await expect(reloaded.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {})).rejects.toThrow('No source');
  vi.mocked(burnWithHumid).mockImplementationOnce(async ({ skip }) => {
    expect(skip?.has(preparedPoint)).toBe(true);
    throw new Error('No burn');
  });
  await reloaded.sendWithHumid();
  expect(burnWithHumid).toHaveBeenCalledOnce();
});

it('recovery requires confirmation, clears only checked preparation inputs, and never signs', async () => {
  const f = recoveryFixture();
  const c = await readyBurn(f);
  vi.mocked(burnWithHumid).mockImplementationOnce(async ({ onSign }) => {
    onSign?.([otherPoint]);
    throw Object.assign(new Error('Uncertain burn'), { sent: 'maybe' });
  });
  await c.sendWithHumid();
  uncertainPreparation();
  await expect(c.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {})).rejects.toThrow('timed out');
  f.env.confirm = vi.fn(() => false);
  expect(await c.recoverFeeReservations()).toBeNull();
  expect(c.getFeeReservationStatus().pending).toBe(1);
  expect(releaseFeePreparationInputs).not.toHaveBeenCalled();
  f.env.confirm = vi.fn(() => true);
  const listener = vi.fn();
  c.subscribe(listener);
  expect(await c.recoverFeeReservations()).toEqual({ released: 1, spent: 0, retained: 0 });
  expect(f.env.confirm).toHaveBeenCalledWith(expect.stringContaining('may still confirm'));
  expect(releaseFeePreparationInputs).toHaveBeenCalledWith([point]);
  expect(listener).toHaveBeenCalled();
  expect(saved(f).pending).toEqual([]);
  expect(prepareFeeWithHumid).toHaveBeenCalledOnce();
  await c.findFeeCoins(DEPOSIT_ADDRESS, 2000n);
  const skip = vi.mocked(discoverFeeCoins).mock.calls.at(-1)?.[0].skip;
  expect(skip?.has(point)).toBe(false);
  expect(skip?.has(otherPoint)).toBe(true);
});

it('retains holds when recovery cannot verify the source and resolves sources already spent', async () => {
  const f = recoveryFixture();
  f.storage.set(key, JSON.stringify({ pending: [point, otherPoint], prepared: [preparedPoint] }));
  const fetch = f.env.fetch;
  f.env.fetch = async (input, init) => String(input).endsWith(`/tx/${BOOTSTRAP_TXID}/outspend/1`)
    ? Response.json({ spent: true }) : fetch(input, init);
  const c = new BridgeController(f.instance, f.env);
  expect(await c.recoverFeeReservations()).toEqual({ released: 0, spent: 1, retained: 1 });
  expect(saved(f)).toEqual({ pending: [otherPoint], prepared: [preparedPoint] });
  await c.findFeeCoins(DEPOSIT_ADDRESS, 2000n);
  expect(vi.mocked(discoverFeeCoins).mock.calls.at(-1)?.[0].skip?.has(point)).toBe(true);
});

it('does not recover during a wallet request or lose a hold when its recovery cannot be saved', async () => {
  const f = recoveryFixture();
  const c = new BridgeController(f.instance, f.env);
  let finish!: () => void;
  vi.mocked(prepareFeeWithHumid).mockImplementationOnce(async ({ onSign }) => {
    await onSign?.([point]);
    await new Promise<void>((resolve) => { finish = resolve; });
    throw Object.assign(new Error('Uncertain'), { sent: 'maybe' });
  });
  const preparing = c.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {}).catch(() => {});
  await vi.waitFor(() => expect(c.getFeeReservationStatus()).toEqual({ pending: 1, busy: true }));
  await expect(c.recoverFeeReservations()).rejects.toThrow('Wait');
  finish();
  await preparing;
  f.env.storage.setItem = () => { throw new Error('Cannot save'); };
  await expect(c.recoverFeeReservations()).rejects.toThrow('Cannot save');
  expect(c.getFeeReservationStatus()).toEqual({ pending: 1, busy: false });
  expect(saved(f).pending).toContain(point);
});

it('preserves an uncertain hold if saving the successful preparation result fails', async () => {
  const f = fixture('connected');
  const c = new BridgeController(f.instance, f.env);
  const save = f.env.storage.setItem;
  let writes = 0;
  f.env.storage.setItem = (key, value) => { if (++writes > 1) throw new Error('Storage stopped'); save(key, value); };
  vi.mocked(prepareFeeWithHumid).mockImplementationOnce(async ({ onSign }) => { await onSign?.([point]); return result; });
  await expect(c.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {})).rejects.toMatchObject({ sent: 'maybe', txid: preparedTxid });
  expect(saved(f).pending).toContain(point);
  expect(c.getFeeReservationStatus().pending).toBe(1);
});

it('protects a reported fee output when its transaction readback remains unavailable', async () => {
  const f = fixture('connected');
  const c = new BridgeController(f.instance, f.env);
  vi.mocked(prepareFeeWithHumid).mockImplementationOnce(async ({ onSign }) => {
    await onSign?.([point]);
    throw Object.assign(new Error('Readback unavailable'), { sent: 'maybe', txid: preparedTxid });
  });
  await expect(c.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {})).rejects.toThrow('Readback unavailable');
  expect(saved(f)).toEqual({ pending: [point], prepared: [preparedPoint] });
  const reloaded = new BridgeController(f.instance, f.env);
  vi.mocked(prepareFeeWithHumid).mockImplementationOnce(async ({ skip }) => {
    expect(skip?.has(preparedPoint)).toBe(true);
    throw new Error('No source');
  });
  await expect(reloaded.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {})).rejects.toThrow('No source');
});

it('drops a prepared output record once its intended covenant spend is confirmed', async () => {
  const f = fixture('connected');
  f.storage.set(key, JSON.stringify({ pending: [], prepared: [preparedPoint] }));
  const c = new BridgeController(f.instance, f.env);
  await c.loadFile('liquidClaim', { size: 2, text: async () => '00' });
  vi.mocked(sendClaim).mockResolvedValueOnce(claimPlan.txid);
  vi.mocked(claimOnLiquid).mockResolvedValueOnce({ where: 'confirmed', height: 1 });
  await c.sendFile('liquidClaim');
  expect(saved(f).prepared).toEqual([]);
});

it('prunes verified spent outputs at the bound so 256 historical preparations do not block forever', async () => {
  const f = recoveryFixture();
  const prepared = [preparedPoint, ...Array.from({ length: 255 }, (_, index) => (index + 1).toString(16).padStart(64, '0') + ':0')];
  f.storage.set(key, JSON.stringify({ pending: [], prepared }));
  const raw = '020000000001' + bytesToHex(hexToBytes(preparedTxid).reverse()) + '0000000000ffffffff01'
    + '01499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c14010000000000000001000000000000';
  const spendingTxid = displayHex(parseTransaction(hexToBytes(raw)).txid);
  const fetch = f.env.fetch;
  f.env.fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith(`/tx/${preparedTxid}/outspend/0`)) return Response.json({ spent: true, txid: spendingTxid });
    if (url.endsWith(`/tx/${spendingTxid}/hex`)) return new Response(raw);
    if (url.endsWith(`/tx/${spendingTxid}/status`)) return Response.json({ confirmed: true });
    return fetch(input, init);
  };
  const c = new BridgeController(f.instance, f.env);
  vi.mocked(prepareFeeWithHumid).mockRejectedValueOnce(new Error('Reached new preparation'));
  await expect(c.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {})).rejects.toThrow('Reached new preparation');
  expect(saved(f).prepared).toHaveLength(255);
  expect(saved(f).prepared).not.toContain(preparedPoint);
});

it('reserves a covenant fee across both panels, releases a decline and retains an uncertain send', async () => {
  const f = fixture('connected');
  const c = new BridgeController(f.instance, f.env);
  const file = { size: 2, text: async () => '00' };
  await c.loadFile('liquidClaim', file);
  await c.loadFile('liquidUpdate', file);
  let decline!: () => void;
  vi.mocked(sendClaim).mockImplementationOnce(async () => new Promise((_resolve, reject) => {
    decline = () => reject(Object.assign(new Error('Declined'), { sent: 'no' }));
  }));
  const claiming = c.sendFile('liquidClaim');
  await vi.waitFor(() => expect(sendClaim).toHaveBeenCalledOnce());
  await c.sendFile('liquidUpdate');
  expect(sendUpdate).not.toHaveBeenCalled();
  expect(c.getSnapshot().liquidUpdate.error).toContain('reserved');
  decline();
  await claiming;
  vi.mocked(sendUpdate).mockRejectedValueOnce(Object.assign(new Error('Unknown'), { sent: 'maybe' }));
  await c.sendFile('liquidUpdate');
  expect(sendUpdate).toHaveBeenCalledOnce();
  await c.sendFile('liquidClaim');
  expect(sendClaim).toHaveBeenCalledOnce();
  expect(c.getSnapshot().liquidClaim.error).toContain('reserved');
  expect(c.getFeeReservationStatus().pending).toBe(0);
});

it('keeps an already published successor store when attaching the proof bundle', async () => {
  const f = fixture('connected');
  f.env.buildTransaction = vi.fn().mockResolvedValue({ raw_tx: '00' });
  const c = new BridgeController(f.instance, f.env);
  vi.mocked(prepareBrowserUpdate).mockResolvedValue({});
  const bundle = { successor_store: { fixture: true } };
  await c.buildFromBrowser('liquidUpdate', { feeTxid: preparedTxid, feeVout: 0,
    bundle: { size: 40, text: async () => JSON.stringify(bundle) } });
  expect(withStore).not.toHaveBeenCalled();
  expect(c.getSnapshot().liquidUpdate.plan?.store).toEqual(updatePlan.store);
  expect(prepareBrowserUpdate).toHaveBeenCalledWith(expect.objectContaining({ signal: expect.any(AbortSignal) }));
});
