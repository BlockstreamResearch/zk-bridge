// Activity's deposit rows against the claims of the bridge state. lib/update.js liveState, which follows the state on
// Liquid and finds the deposit index each claim's output 0 commits, is replaced here by its answers; that attribution
// is tested in bridge-core/test/update.test.js, and lib/claim.js depositClaims in bridge-core/test/claim.test.js. The deposits below pay
// one script the same units, so nothing but a claim's index tells them apart: not their order, nor the claims'.
import { type ClaimSeen, type LiveState, liveState } from '@bridge/core/lib/update.js';
import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ActivityPanel, ExpandedProvider } from '../components/Journeys';
import { DEPOSIT_ADDRESS, ESCROW, fixture } from '../dev/fixture';
import { BridgeProvider } from './context';
import { BridgeController } from './controller';
import type { DepositJourney } from './types';

vi.mock('@bridge/core/lib/update.js', async (importOriginal) => ({ ...(await importOriginal<object>()), liveState: vi.fn() }));

beforeEach(() => vi.resetAllMocks());

const SCRIPT = '0014' + '11'.repeat(20);
const MINUTE = 60_000;
const NOW = Date.UTC(2026, 9, 20, 12, 0);
const txid = (n: number | string) => String(n).repeat(64);

/** Deposit `index` of this browser, final on Ethereum: 0.0025 ETH to the fixture's Humid address. */
function deposit(index: number, held: Partial<DepositJourney> = {}): DepositJourney {
  return {
    kind: 'deposit', id: '0x' + txid(index + 1), txHash: '0x' + txid(index + 1), escrow: ESCROW, asset: '33'.repeat(32),
    address: DEPOSIT_ADDRESS, script: SCRIPT, units: '250000', wei: '2500000000000000', status: 'finalized',
    created: NOW - 60 * MINUTE, block: 8_999_000, index: String(index), finalizedAt: NOW - 40 * MINUTE, ...held,
  };
}

/** A claim the walk attributed to deposit `index` (null: not attributed), paying this browser's script. */
const claim = (index: number | null, n: number | string, confirmed = true): ClaimSeen => ({
  txid: txid(n), index, pays: { script: SCRIPT, units: 250_000n }, confirmed,
});

/** The walk's answer: `claims` confirmed, and `moving`, an unconfirmed claim of the live output, if given. */
const walked = (claims: ClaimSeen[], moving: ClaimSeen | null = null): LiveState => ({
  outpoint: { txid: claims.at(-1)?.txid ?? txid('a'), vout: 0 },
  state: { head: 1, lc: '', acc: '', claimedRoot: null, claimed: null },
  spends: claims.length, update: null, claims, moving: moving?.txid ?? null, movingClaim: moving,
});

/** Activity after one poll of `journeys` against the walk `live`. */
async function activity(journeys: DepositJourney[], live: LiveState) {
  vi.mocked(liveState).mockResolvedValue(live);
  const f = fixture('activity', { now: NOW, journeys });
  const c = new BridgeController(f.instance, f.env);
  c.start();
  await c.restored;
  c.stop();
  render(<BridgeProvider controller={c}><ExpandedProvider><ActivityPanel onClaim={() => {}} /></ExpandedProvider></BridgeProvider>);
  const row = (i: number) => c.getSnapshot().journeys.find((j) => j.kind === 'deposit' && j.index === String(i)) as DepositJourney;
  return { c, row };
}

describe('Activity attributes a claim only to the deposit whose index it paid', () => {
  it('shows identical deposits claimed out of order each with its own claim, and the one unclaimed as waiting', async () => {
    // Deposit 2 claimed, then deposit 0, its claim not confirmed yet; deposit 1, older than 2 and identical, waits.
    const { row } = await activity([deposit(2), deposit(1), deposit(0)], walked([claim(2, 2)], claim(0, 0, false)));
    expect(vi.mocked(liveState)).toHaveBeenCalledTimes(1);
    expect(row(2)).toMatchObject({ status: 'claimed', claimTxid: txid(2), claimVout: 1, claimIndex: '2' });
    expect(row(0)).toMatchObject({ status: 'claiming', claimTxid: txid(0), claimIndex: '0' });
    expect(row(1).status).toBe('finalized');
    expect(row(1).claimTxid).toBeUndefined();
    expect(screen.getAllByText('Claimed')).toHaveLength(1);
    expect(screen.getAllByText('Claiming')).toHaveLength(1);
    expect(screen.getAllByText('Final')).toHaveLength(1);
    expect(document.querySelector(`a[href$="/tx/${txid(2)}"]`)).not.toBeNull();
    expect(screen.queryByText(/cannot tell yet/)).toBeNull();
  });

  it('shows deposits an unattributed claim may have paid as unresolved, and none of them as claimed', async () => {
    const { row } = await activity([deposit(2), deposit(1), deposit(0)], walked([claim(2, 2), claim(null, 9)]));
    expect(row(2).status).toBe('claimed');
    for (const i of [0, 1]) {
      expect(row(i)).toMatchObject({ status: 'unresolved', claimTxid: undefined });
      expect(row(i).claimWhy).toMatch(/a claim on Liquid could not be attributed to a deposit/);
    }
    expect(screen.getAllByText('Unresolved')).toHaveLength(2);
    expect(screen.getAllByText(/Claimed or not, this page cannot tell yet/)).toHaveLength(2);
    expect(screen.getAllByText(/^Claim on Liquid: not known whether a claim paid this deposit$/)).toHaveLength(2);
    expect(screen.queryByText('Final')).toBeNull();
  });

  it('checks again a deposit an earlier release paired by order, and keeps one shown to be paid', async () => {
    // Deposit 0 was saved as claimed by deposit 1's claim, paired by order alone; deposit 2's claim was attributed.
    const byOrder = deposit(0, { status: 'claimed', claimTxid: txid(1), claimVout: 1 });
    const shown = deposit(2, { status: 'claimed', claimTxid: txid(2), claimVout: 1, claimIndex: '2' });
    const { row } = await activity([shown, deposit(1), byOrder], walked([claim(1, 1)]));
    expect(row(0)).toMatchObject({ status: 'finalized', claimTxid: undefined, claimVout: undefined });
    expect(row(1)).toMatchObject({ status: 'claimed', claimTxid: txid(1), claimIndex: '1' });
    expect(row(2)).toMatchObject({ status: 'claimed', claimTxid: txid(2), claimIndex: '2' });
  });

  it('leaves a deposit as it was, with the failure shown, when the state cannot be followed', async () => {
    vi.mocked(liveState).mockRejectedValue(new Error('the Liquid API is down'));
    const f = fixture('activity', { now: NOW, journeys: [deposit(0, { status: 'unresolved', claimWhy: 'earlier' })] });
    const c = new BridgeController(f.instance, f.env);
    c.start();
    await c.restored;
    c.stop();
    const j = c.getSnapshot().journeys[0] as DepositJourney;
    expect(j).toMatchObject({ status: 'unresolved', claimWhy: 'earlier' });
    expect(j.lastError).toMatch(/the Liquid API is down/);
  });
});
