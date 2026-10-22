import type { Esplora } from './esplora.js';
import type { Humid, HumidFailure } from './humid.js';

export const MAX_FEE_SATS: bigint;

/** Caller must obtain explicit user confirmation and verify current coin status.
 * Releases module holds only; throws while a matching request is in flight.
 */
export function releaseFeePreparationInputs(outpoints: string[]): void;

export interface FeeCoin {
  txid: string;
  vout: number;
  sats: bigint;
  txHex: string;
  address: string;
  script: Uint8Array;
}

export interface FeePlan {
  pset: string;
  unsigned: Uint8Array;
  signInputs: { address: string; index: number; sighashTypes: number[] }[];
  spends: string[];
  blindIndex: number;
  address: string;
  sats: bigint;
  changeSats: bigint;
  feeSats: bigint;
}

export interface FeeFailure extends HumidFailure {
  plan?: FeePlan;
  spends?: string[];
  txid?: string;
}

export function discoverFeeCoins(args: {
  esplora: Esplora;
  address: string;
  minSats?: bigint;
  maxSats?: bigint;
  skip?: Set<string>;
}): Promise<FeeCoin[]>;

/** Throws if any public field differs; hidden change amounts rely on Humid. */
export function feeBroadcastMatches(plan: FeePlan, txHex: string, txid: string): null;

/** The caller must show the destination and establish that the user controls it.
 * Persist onSign outpoints before approval; retain them on sent:'maybe' failures.
 * Success still needs a fresh confirmed/unspent lookup before a covenant spend.
 */
export function prepareFeeWithHumid(args: {
  humid: Humid;
  esplora: Esplora;
  address: string;
  sats: bigint;
  skip?: Set<string>;
  onSign?: (outpoints: string[]) => void | Promise<void>;
  progress?: (text: string) => void;
  deadlineMs?: number;
}): Promise<{ txid: string; vout: number; sats: bigint; txHex: string; address: string; confirmed: false; plan: FeePlan }>;
