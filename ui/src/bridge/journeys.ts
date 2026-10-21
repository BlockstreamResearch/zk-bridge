// Saved journeys persist Activity across page reloads.
import { bytesToHex } from '@bridge/core/lib/bytes.js';
import type { ClaimPlan } from '@bridge/core/lib/claim.js';
import type { BridgeEnv, DepositJourney, Journey } from './types';

export const SETTINGS_KEY = 'liquid-bridge-poc.settings';
export const JOURNEYS_KEY = 'liquid-bridge-poc.journeys';

export function loadJourneys(storage: BridgeEnv['storage'], escrow: string | undefined): Journey[] {
  try {
    const list: unknown = JSON.parse(storage.getItem(JOURNEYS_KEY) || '[]');
    return Array.isArray(list) ? list.filter((j): j is Journey => !!j && (j.kind === 'deposit' || j.kind === 'redeem')
      && typeof j.id === 'string' && typeof j.escrow === 'string' && j.escrow.toLowerCase() === escrow) : [];
  } catch {
    return [];
  }
}

export function saveJourneys(storage: BridgeEnv['storage'], journeys: Journey[]) {
  storage.setItem(JOURNEYS_KEY, JSON.stringify(journeys));
}

export type Tone = 'pending' | 'progress' | 'done' | 'failed';

const LABELS: Record<string, [string, Tone]> = {
  submitted: ['Sent', 'pending'],
  mined: ['Mined', 'progress'],
  finalized: ['Final', 'progress'],
  claiming: ['Claiming', 'progress'],
  claimed: ['Claimed', 'done'],
  unresolved: ['Unresolved', 'pending'],
  failed: ['Failed', 'failed'],
  burned: ['Burned', 'pending'],
  relay: ['Relaying', 'pending'],
  ready: ['Ready', 'progress'],
  paid: ['Paid', 'done'],
};

export function label(j: Journey): { text: string; tone: Tone } {
  const [text, tone] = LABELS[j.status] ?? [j.status, 'pending'];
  return { text, tone };
}

export const FINISHED = new Set(['claimed', 'paid', 'failed']);

/**
 * Whether the page has nothing left to check for `j`. A deposit saved as claimed without the index its claim paid
 * needs another check: a repeated recipient script does not identify a deposit by itself.
 */
export const settled = (j: Journey) => FINISHED.has(j.status) && !(j.kind === 'deposit' && j.status === 'claimed' && !j.claimIndex);

/**
 * A redemption whose last check failed offers no chain action until a check succeeds: its burn may be gone from the
 * Liquid API, and relaying for it would spend gas toward a redemption that cannot happen.
 */
export function actionable(j: Journey, status: 'ready' | 'relay'): boolean {
  return j.kind === 'redeem' && j.status === status && !j.lastError;
}

/**
 * The unclaimed deposits this browser sent to `escrow` that claim `c` may pay: the same script and units, by index.
 * Deposits repeat a script, so there may be several; which one it pays, Activity shows once the claim is on Liquid
 * (lib/claim.js depositClaims).
 */
export function claimedDeposits(journeys: Journey[], c: ClaimPlan['claim'], escrow: string): DepositJourney[] {
  const script = bytesToHex(c.mint.script);
  return journeys
    .filter((j): j is DepositJourney => j.kind === 'deposit' && j.escrow?.toLowerCase() === escrow && !j.claimTxid
      && j.script === script && String(j.units) === c.mint.units.toString())
    .sort((a, b) => Number(a.index ?? Infinity) - Number(b.index ?? Infinity));
}
