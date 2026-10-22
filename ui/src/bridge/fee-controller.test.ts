// A wallet timeout must not make its fee inputs available after a page reload.
import { discoverFeeCoins, prepareFeeWithHumid } from '@bridge/core/lib/fee.js';
import { findHumid, type Humid } from '@bridge/core/lib/humid.js';
import { beforeEach, expect, it, vi } from 'vitest';
import { DEPOSIT_ADDRESS, fixture } from '../dev/fixture';
import { BridgeController } from './controller';

vi.mock('@bridge/core/lib/fee.js', () => ({ discoverFeeCoins: vi.fn(), prepareFeeWithHumid: vi.fn() }));
vi.mock('@bridge/core/lib/humid.js', async (original) => ({ ...await original<object>(), findHumid: vi.fn() }));

const point = 'ab'.repeat(32) + ':0';
const key = 'zk-bridge:reserved-fees';
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(findHumid).mockResolvedValue({} as Humid);
  vi.mocked(discoverFeeCoins).mockResolvedValue([]);
});

it('persists inputs before signing and excludes an uncertain send after reload', async () => {
  const f = fixture('connected');
  const c = new BridgeController(f.instance, f.env);
  vi.mocked(prepareFeeWithHumid).mockImplementation(async ({ onSign }) => {
    await onSign?.([point]);
    expect(JSON.parse(f.storage.get(key)!)).toContain(point);
    throw Object.assign(new Error('Wallet timed out'), { sent: 'maybe' });
  });
  await expect(c.prepareFee(DEPOSIT_ADDRESS, 2000n, () => {})).rejects.toThrow('Wallet timed out');
  const reloaded = new BridgeController(f.instance, f.env);
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
  expect(JSON.parse(f.storage.get(key)!)).not.toContain(point);
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
