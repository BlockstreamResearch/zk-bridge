import type { Esplora } from './esplora.js';

/** Humid's injected provider (window.humid). */
export interface Humid {
  request(args: { method: string; params?: unknown }): Promise<unknown>;
}

/** An error from Humid or the send helpers: an RPC `code`, or a `sent` mark saying whether anything may be on Liquid. */
export interface HumidFailure extends Error {
  code?: number;
  sent?: 'no' | 'maybe';
  stage?: string;
  status?: number;
  data?: { reason?: string };
}

export const FEE_SATS: bigint;
export const MIN_CHANGE_SATS: bigint;

export function humidAddress(text: string): { address: string; script: Uint8Array };
export function findHumid(win: { humid?: Humid }, timeoutMs?: number): Promise<Humid | null>;
export function humidError(e: unknown): string;

export interface BurnPlan {
  spends: string[];
}

export function burnWithHumid(args: {
  humid: Humid;
  esplora: Esplora;
  asset: Uint8Array;
  units: bigint;
  burnScript: Uint8Array;
  claim: { address: string; script: Uint8Array };
  skip?: Set<string>;
  onSign?: (outpoints: string[]) => void;
  progress?: (text: string) => void;
}): Promise<{ txid: string; plan: BurnPlan }>;

/** Null when the broadcast is the plan; else what differs. Throws if `txHex` cannot be read. */
export function broadcastMatches(plan: BurnPlan, txHex: string): string | null;
