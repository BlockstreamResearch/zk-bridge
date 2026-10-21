import type { ParsedTransaction } from './elements.js';

export interface Check {
  ok: boolean;
  text: string;
}

export function checkBootstrap(args: {
  tx: ParsedTransaction;
  confirmed: boolean;
  bridgeAsset: Uint8Array;
  stateScript: Uint8Array;
  feeAsset: Uint8Array;
}): { ok: boolean; checks: Check[] };
