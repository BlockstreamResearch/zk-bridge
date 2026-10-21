// The bridge page's state, independent of React. Saved journeys are scoped to the published escrow.
import type { Instance, Settings } from '@bridge/core/config.js';
import type { AdmissionReads, BurnTarget } from '@bridge/core/lib/bridge.js';
import type { ClaimPlan } from '@bridge/core/lib/claim.js';
import type { Humid } from '@bridge/core/lib/humid.js';
import type { Check } from '@bridge/core/lib/issuance.js';
import type { LiveState, UpdatePlan } from '@bridge/core/lib/update.js';

/**
 * A deposit is 'claiming' or 'claimed' only once a claim is shown to have paid its index (lib/claim.js
 * depositClaims); 'unresolved' while a claim the page could not attribute may have paid it.
 */
export type DepositStatus = 'submitted' | 'mined' | 'finalized' | 'claiming' | 'claimed' | 'unresolved' | 'failed';
export type RedeemStatus = 'burned' | 'relay' | 'ready' | 'submitted' | 'paid';

interface JourneyBase {
  id: string;
  created: number;
  escrow: string;
  error?: string | null;
  /** The last poll's failure to check this journey; cleared by the next successful check. */
  lastError?: string;
}

export interface DepositJourney extends JourneyBase {
  kind: 'deposit';
  status: DepositStatus;
  /** Internal-order hex of the bridge asset when it was sent. */
  asset: string;
  txHash: string;
  address: string | null;
  script: string;
  units: string;
  wei: string;
  block?: number;
  index?: string | null;
  finalizedAt?: number;
  claimTxid?: string;
  claimVout?: number;
  /** The deposit index the claim `claimTxid` was shown to pay. Without it, the claim must be checked again. */
  claimIndex?: string;
  /** Why the deposit is 'unresolved'. */
  claimWhy?: string;
}

export interface RedeemJourney extends JourneyBase {
  kind: 'redeem';
  status: RedeemStatus;
  burnTxid: string;
  vout: number;
  units: string;
  recipient: string;
  confirmations?: number;
  burnHeight?: number;
  needed?: number;
  txHash?: string | null;
  payee?: string;
  block?: number;
}

export type Journey = DepositJourney | RedeemJourney;

/** EIP-1193, as far as the page uses it. */
export interface Eip1193 {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: string, listener: (...args: never[]) => void): void;
}

/** Everything the controller touches outside itself, so tests and the fixture mode can replace it. */
export interface BridgeEnv {
  /** The injected wallet, read each time: extensions may inject after the page loads. */
  ethereum(): Eip1193 | null;
  /** Where Humid injects `humid` (window). */
  humidWindow(): { humid?: Humid };
  fetch: typeof fetch;
  storage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
  /** The app's own URL, ending in '/': the instance record is `instances/<name>/` under it. */
  siteHref(): string;
  now(): number;
  sleep(ms: number): Promise<void>;
  confirm(message: string): boolean;
  copy(text: string): Promise<void>;
  pollMs: number;
  /** The pause between Liquid API lookups of a transaction Humid reports sending, which the API can lag; 3000 if unset. */
  liquidLagMs?: number;
}

/** The escrow's reads, once its code hash is the record's. */
export interface BridgeReads {
  /** Internal-order hex. */
  asset: string;
  assetDisplay: string;
  sbsHash: string;
  minConf: number;
  epochLength: number;
  lcTip: number;
  lcTime: number;
  depositsOpen: boolean;
  maxRelayLag: number;
  admission: AdmissionReads;
}

/**
 * The bootstrap check (lib/issuance.js checkBootstrap). `unavailable`: the Liquid API did not serve it, which is
 * retried after `retryAt`; a check that read it and failed is final until the escrow is read again.
 */
export interface BootstrapCheck {
  ok: boolean;
  checks: Check[];
  error: string | null;
  /** The escrow's asset this check confirmed (internal hex). */
  asset?: string | null;
  unavailable?: boolean;
  attempts?: number;
  retryAt?: number;
}

/** Step 1's burn target for one recipient. The amount is read from the form when used, never stored here. */
export interface TargetState {
  recipient: string;
  burn: BurnTarget;
  asset: string;
  assetDisplay: string;
  isContract: boolean;
}

export interface RedeemForm {
  recipient: string;
  amount: string;
  txid: string;
  humidAddress: string;
  payTo: string;
}

export interface FoundRow {
  vout: number;
  amount: string;
  note: string;
}

export interface HumidBurnState {
  busy: boolean;
  note: string;
  error: string;
  /** A send Humid reported that the page cannot verify; do not ask Humid to burn again. */
  held: string | null;
}

/** Where the Liquid API has a transaction, by its own copy hashing to the txid (lib/claim.js claimOnLiquid). */
export type LiquidSeen =
  | { where: 'confirmed'; height: number | null }
  | { where: 'mempool' }
  | { where: 'unknown'; why: string };

/**
 * An update or claim after Humid answered a request that may have sent it. Only `where`, what the Liquid API shows as
 * of `checkedAt`, counts: Humid's answer alone shows nothing on Liquid. `said` is what to tell the user when Humid did
 * not report it as sent (null when it did). Once set, the panel asks Humid for nothing more; it only asks Liquid
 * again, and sending again takes loading the file again, which checks Liquid before Humid is asked.
 */
export type LiquidSent = LiquidSeen & { txid: string; said: string | null; checkedAt: number };

export interface LiquidSend<P> {
  busy: boolean;
  note: string;
  plan: P | null;
  sent: LiquidSent | null;
  fileError: string;
  /** Why the store file loaded for an update was refused. */
  storeError: string;
  error: string;
}

/**
 * The light-client state on Liquid as the update panel shows it (lib/update.js lightClientStatus): the live state,
 * the path of its store in this page's record, and whether this page is the published site, so that the record shows
 * what is published (lib/update.js publishes).
 */
export interface LightClientCheck {
  busy: boolean;
  note: string;
  error: string;
  status: { live: LiveState; listed: string | null; published: boolean; checkedAt: number } | null;
}

export interface Message {
  id: number;
  text: string;
}

export interface BridgeState {
  instance: Instance | null;
  /**
   * Whether this page is the published site, config.js PUBLISHED.site (lib/update.js publishes). Any other copy says so
   * at the top, and its record's stores do not count as published.
   */
  published: boolean;
  settings: Settings;
  /** Bumped on each Save or reset, so a Settings form can reset its fields. */
  settingsVersion: number;
  hasWallet: boolean;
  account: string | null;
  chainId: bigint | null;
  bridge: BridgeReads | null;
  bridgeError: string | null;
  bootstrap: BootstrapCheck | null;
  liquid: { tip: number; sbsHash: string } | null;
  liquidError: string | null;
  relaying: boolean;
  depositBusy: boolean;
  redeemBusy: boolean;
  target: TargetState | null;
  targetError: string | null;
  redeemForm: RedeemForm;
  found: FoundRow[] | null;
  lookupError: string;
  humid: HumidBurnState;
  lightClient: LightClientCheck;
  liquidUpdate: LiquidSend<UpdatePlan>;
  liquidClaim: LiquidSend<ClaimPlan>;
  journeys: Journey[];
  toast: Message | null;
  announcement: Message | null;
  /** The clock at the last poll, for the deposit waits. */
  now: number;
}
