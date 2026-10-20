import type { ParsedTransaction } from './elements.js';

export const UNIT_WEI: bigint;
export const MIN_UNITS: bigint;
export const SEPOLIA_CHAIN_ID: bigint;
/** Internal byte order. */
export const LIQUID_TESTNET_LBTC: string;
export const BURN_TAG: string;
export const BEACON_ROOTS: string;

/** A Liquid recipient: its scriptPubKey, and its tex1… address when it is segwit (null for P2SH and P2PKH). */
export function depositRecipient(input: string): { script: Uint8Array; address: string | null };
export function parseEther(text: string): bigint;
export function redeemUnits(text: string): bigint;
export function formatUnits(value: bigint, decimals: number): string;
export function depositUnits(wei: bigint): bigint;
export function depositCalldata(script: Uint8Array): string;

export interface Receipt {
  status: string;
  blockNumber: string;
  logs: { address: string; topics: string[]; data: string }[];
}
export function depositEvent(receipt: Receipt, escrow: string): { index: bigint; units: bigint; script: string } | null;

/** Lower-case 0x address, or throws. */
export function ethAddress(text: string): string;
/** A burn's recipient: the connected account, or a checksummed address. Throws otherwise. */
export function burnRecipient(text: string, connected: string | null): string;

export interface BurnTarget {
  scriptPubKey: Uint8Array;
  chainId: bigint;
  escrow: string;
  recipient: string;
}
export function burnTarget(chainId: bigint, escrow: string, recipient: string): BurnTarget;
/** The page's own burn target, once the escrow's `onchain` answer is exactly that script; throws otherwise. */
export function escrowBurnTarget(chainId: bigint, escrow: string, recipient: string, onchain: Uint8Array): BurnTarget;

export interface BurnOutput {
  vout: number;
  units: bigint | null;
  usable: boolean;
}
export function burnOutputs(tx: ParsedTransaction, assetInternal: Uint8Array, scriptPubKey: Uint8Array): BurnOutput[];
export function burnDiagnosis(tx: ParsedTransaction, assetInternal: Uint8Array, target: BurnTarget): {
  outputs: { vout: number; units: bigint | null; text: string }[];
  blinded: number;
};

export interface RedeemArgs {
  recipient: string;
  burn: unknown;
  ref: unknown;
}
export function redeemCalldata(args: RedeemArgs): string;
export function redeemToCalldata(args: { to: string; burn: unknown; ref: unknown }): string;

export interface RelayBatch {
  firstHeight: number;
  headers: Uint8Array[];
  witnessScript: Uint8Array;
}
export function submitHeadersCalldata(b: RelayBatch): string;

export interface ForkProof {
  timestamp: number;
  genesisTime: number;
  slot: number;
  epoch: number;
  currentVersion: Uint8Array;
}
export function parseForkProof(text: string): ForkProof;
export function forkSlotTime(p: ForkProof): number;
export function beaconBlockRoot(p: ForkProof): Uint8Array;
export function checkForkCalldata(p: ForkProof): string;
export function beaconRootCall(timestamp: number): string;

/** Calldata of the escrow views the page reads. */
export const views: {
  BRIDGE_ASSET(): string;
  MIN_CONFIRMATIONS(): string;
  EPOCH_LENGTH(): string;
  signblockscriptHash(): string;
  lcTipHeight(): string;
  lcTipTime(): string;
  batchCount(): string;
  batchAt(i: number | bigint): string;
  depositsOpen(): string;
  MAX_RELAY_LAG(): string;
  depositsEnd(): string;
  forkCheckedAt(): string;
  MAX_FORK_CHECK_AGE(): string;
  FORK_VERSION(): string;
  FORK_EPOCH(): string;
  burnScriptPubKey(recipient: string): string;
  isRedeemed(txidInternal: Uint8Array, vout: number): string;
};

export const decode: {
  uint(hex: string): bigint;
  bool(hex: string): boolean;
  /** Lower-case hex without 0x. */
  bytes32(hex: string): string;
  address(hex: string): string;
  bytes(hex: string): Uint8Array;
};

export interface AdmissionReads {
  depositsEnd: number;
  forkCheckedAt: number;
  maxForkCheckAge: number;
}

export interface Admission {
  deposit: boolean;
  relayReopens: boolean;
  forkReopens: boolean;
  text: string;
}

export function depositAdmission(
  b: { depositsOpen: boolean; lcTime: number; maxRelayLag: number; admission: AdmissionReads },
  now: number,
): Admission;

export function explainRevert(data: string): string;
