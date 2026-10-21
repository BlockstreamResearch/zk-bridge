import type { Esplora } from './esplora.js';
import type { Humid } from './humid.js';

export type RecordReader = (path: string) => Promise<string>;

export interface Outpoint {
  txid: string;
  vout: number;
}

/**
 * A state of the bridge: its light-client head slot and lc, its deposit accumulator, the deposit indices it has
 * claimed, in the order claimed, and their root. `claimed` is null once a claim was not attributed, and
 * `claimedRoot` too, until an update reveals it.
 */
export interface BridgeStateWords {
  head: number;
  lc: string;
  acc: string;
  claimedRoot: string | null;
  claimed: number[] | null;
}

/** A claim the walk followed: the deposit index its output 0 commits, or null if not attributed, and its output 1. */
export interface ClaimSeen {
  txid: string;
  index: number | null;
  pays: { script: string; units: bigint } | null;
  confirmed: boolean;
}

/** The live state on Liquid, followed from the bootstrap (lib/update.js liveState). */
export interface LiveState {
  outpoint: Outpoint;
  state: BridgeStateWords;
  spends: number;
  /** The update that moved the light client to `state.head`; null while it is at the initial head. */
  update: string | null;
  /** The claims followed, oldest first. */
  claims: ClaimSeen[];
  /** An unconfirmed spend of the live output, if the Liquid API has one. */
  moving: string | null;
  /** That spend as a claim, if it is one. */
  movingClaim: ClaimSeen | null;
}

/** The claimed root of a state that has claimed nothing. */
export const EMPTY_CLAIMED_ROOT: string;

export function liveState(args: {
  esplora: Esplora;
  manifest: unknown;
  bootstrap: string;
  from?: LiveState | null;
  progress?: (spends: number) => void;
}): Promise<LiveState>;

/** The lc_preimages.json entry that publishes a store, as the justfile's stage-store writes it. */
export interface StoreEntry {
  head: number;
  header: string;
  committee: string;
  update: string;
  store: string;
}

export type UpdateStore = { where: 'site'; path: string } | { where: 'file'; name: string; entry: StoreEntry };

export interface UpdatePlan {
  txid: string;
  feeAddress: string;
  successorAddress: string;
  update: {
    state: Outpoint;
    fee: Outpoint & { sats: bigint };
    successor: { script: Uint8Array };
  };
  live: LiveState;
  successor: BridgeStateWords;
  /** The successor's store in this page's record, published or not. */
  listed: string | null;
  /** Where the successor's store comes from; sendUpdate refuses while it is null. */
  store: UpdateStore | null;
}

export function publishes(pageHref: string): boolean;
export function servedUntil(head: number): number;
export function lightClientStatus(args: {
  esplora: Esplora;
  readRecord: RecordReader;
  bootstrap: string;
  from?: LiveState | null;
  progress?: (spends: number) => void;
}): Promise<{ live: LiveState; listed: string | null }>;
export function prepareUpdate(args: {
  esplora: Esplora;
  readRecord: RecordReader;
  raw: Uint8Array;
  bootstrap: string;
  published: boolean;
  from?: LiveState | null;
  progress?: (spends: number) => void;
}): Promise<UpdatePlan>;
export function withStore(plan: UpdatePlan, text: string, name: string): UpdatePlan;
export function sendUpdate(args: { humid: Humid; esplora: Esplora; plan: UpdatePlan; progress?: (text: string) => void }): Promise<string>;
export function updateError(e: unknown): string;
