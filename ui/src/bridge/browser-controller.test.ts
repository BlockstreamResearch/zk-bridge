// The real input/protocol/SDK gates have their own tests. These check orchestration: no signing while
// building, cancellation, late answers, and mandatory validation of the constructed transaction.
import { prepareClaim, type ClaimPlan } from '@bridge/core/lib/claim.js';
import { beforeEach, expect, it, vi } from 'vitest';
import { fixture } from '../dev/fixture';
import { prepareBrowserClaim } from './browser-build';
import { BridgeController } from './controller';

vi.mock('./browser-build', () => ({ prepareBrowserClaim: vi.fn(), prepareBrowserUpdate: vi.fn() }));
vi.mock('@bridge/core/lib/claim.js', async (original) => ({ ...await original<object>(), prepareClaim: vi.fn() }));

const values = { feeTxid: 'ab'.repeat(32), feeVout: 0, depositIndex: 4 };
const plan = { txid: 'cd'.repeat(32) } as ClaimPlan;
beforeEach(() => vi.resetAllMocks());

function setup() {
  const f = fixture('connected');
  const build = vi.fn().mockResolvedValue({ raw_tx: '00', report: {} });
  const wallet = vi.fn();
  f.env.buildTransaction = build;
  f.env.humidWindow = wallet;
  vi.mocked(prepareBrowserClaim).mockResolvedValue({ state: 'checked' });
  vi.mocked(prepareClaim).mockResolvedValue(plan);
  return { c: new BridgeController(f.instance, f.env), build, wallet };
}

it('validates public inputs, builds, and checks the resulting transaction without asking a wallet', async () => {
  const { c, build, wallet } = setup();
  await c.buildFromBrowser('liquidClaim', values);
  expect(prepareBrowserClaim).toHaveBeenCalledWith(expect.objectContaining({ depositIndex: 4, feeTxid: values.feeTxid }));
  expect(build).toHaveBeenCalledWith('claim', { state: 'checked' }, expect.any(AbortSignal));
  expect(prepareClaim).toHaveBeenCalledWith(expect.objectContaining({ raw: new Uint8Array([0]) }));
  expect(c.getSnapshot().liquidClaim.plan).toBe(plan);
  expect(c.getSnapshot().liquidClaim.busy).toBe(false);
  expect(wallet).not.toHaveBeenCalled();
});

it('never offers a constructed transaction that fails the second validation', async () => {
  const { c, wallet } = setup();
  vi.mocked(prepareClaim).mockRejectedValue(new Error('state spent'));
  await c.buildFromBrowser('liquidClaim', values);
  expect(c.getSnapshot().liquidClaim.plan).toBeNull();
  expect(c.getSnapshot().liquidClaim.error).toContain('state spent');
  expect(wallet).not.toHaveBeenCalled();
});

it('cancels an active worker and ignores its late result', async () => {
  const { c, build } = setup();
  let done!: (v: unknown) => void;
  build.mockImplementation(() => new Promise((resolve) => { done = resolve; }));
  const running = c.buildFromBrowser('liquidClaim', values);
  await vi.waitFor(() => expect(build).toHaveBeenCalledTimes(1));
  const signal = build.mock.calls[0][2] as AbortSignal;
  c.resetSend('liquidClaim');
  expect(signal.aborted).toBe(true);
  done({ raw_tx: '00', report: {} });
  await running;
  expect(c.getSnapshot().liquidClaim.plan).toBeNull();
  expect(prepareClaim).not.toHaveBeenCalled();
});

it('refuses concurrent build and imported-file replacement while a build runs', async () => {
  const { c, build } = setup();
  let done!: (v: unknown) => void;
  build.mockImplementation(() => new Promise((resolve) => { done = resolve; }));
  const running = c.buildFromBrowser('liquidClaim', values);
  await vi.waitFor(() => expect(build).toHaveBeenCalledTimes(1));
  await c.buildFromBrowser('liquidClaim', { ...values, depositIndex: 5 });
  await c.loadFile('liquidClaim', { size: 2, text: async () => 'aa' });
  expect(build).toHaveBeenCalledTimes(1);
  done({ raw_tx: '00', report: {} });
  await running;
  expect(prepareClaim).toHaveBeenCalledTimes(1);
});
