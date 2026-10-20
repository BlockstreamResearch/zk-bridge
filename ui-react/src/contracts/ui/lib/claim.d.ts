import type { Esplora } from './esplora.js';
import type { Humid } from './humid.js';
import type { LiveState, Outpoint, RecordReader } from './update.js';
import type { LiquidSeen } from '../../../../bridge/types';

export interface ClaimPlan {
  txid: string;
  feeAddress: string;
  successorAddress: string;
  claim: {
    state: Outpoint;
    fee: Outpoint & { sats: bigint };
    successor: { script: Uint8Array };
    mint: { script: Uint8Array; units: bigint; asset: Uint8Array; address: string | null };
  };
}

export function siteReader(fetchImpl: typeof fetch, pageHref: string, record: string): RecordReader;
export function prepareClaim(args: { esplora: Esplora; readRecord: RecordReader; raw: Uint8Array }): Promise<ClaimPlan>;
export function sendClaim(args: { humid: Humid; esplora: Esplora; plan: ClaimPlan; progress?: (text: string) => void }): Promise<string>;
export function claimError(e: unknown): string;
export function claimOnLiquid(
  esplora: Esplora,
  txid: string,
  options?: { tries?: number; waitMs?: number },
): Promise<LiquidSeen>;

export type DepositClaim =
  | { status: 'claimed' | 'claiming'; txid: string; vout: number }
  | { status: 'unresolved'; why: string };

/**
 * Which claim paid each of `deposits`, by the deposit index the walk found each claim's output 0 to commit; deposits
 * no claim paid are left out, and those an unattributed claim may have paid are unresolved.
 */
export function depositClaims<D extends { script: string; units: string; index?: string | null }>(
  deposits: D[],
  live: LiveState | null,
): Map<D, DepositClaim>;
