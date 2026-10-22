// What Humid's "Sign Liquid PSET?" approval must show, in Humid's own form (amounts in base units, asset ids in
// full), so a reader can compare before signing.
import { LIQUID_TESTNET_LBTC, formatUnits } from '@bridge/core/lib/bridge.js';
import { bytesToHex, hexToBytes } from '@bridge/core/lib/bytes.js';
import type { ClaimPlan } from '@bridge/core/lib/claim.js';
import { displayHex } from '@bridge/core/lib/elements.js';
import { FEE_SATS, MIN_CHANGE_SATS } from '@bridge/core/lib/humid.js';
import type { UpdatePlan } from '@bridge/core/lib/update.js';
import type { TargetState } from './types';

const lbtc = () => displayHex(hexToBytes(LIQUID_TESTNET_LBTC));

/** The Humid burn's fee and the smallest fee coin it takes (fee plus the dust limit of change), in tL-BTC. */
export const HUMID_FEE = { sats: FEE_SATS, btc: formatUnits(FEE_SATS, 8), minCoin: formatUnits(FEE_SATS + MIN_CHANGE_SATS, 8), change: MIN_CHANGE_SATS };

export function burnApproval(t: TargetState, units: bigint): string {
  return `Check Humid: Output 0 has no address, ${units} · ${t.assetDisplay}, and Script: ${bytesToHex(t.burn.scriptPubKey)}. `
    + `Recipient: ${t.burn.recipient}. Wallet net change: -${units} · ${t.assetDisplay} and -${FEE_SATS} · ${lbtc()} for the fee. `
    + 'Decline if anything differs.';
}

export function updateApproval(plan: UpdatePlan): string {
  const sats = plan.update.fee.sats;
  return `Check Humid: Requested signing inputs must contain only Input 1 at ${plan.feeAddress}. `
    + `Output 0: ${plan.successorAddress}, "Confidential amount unavailable · Confidential asset unavailable", Script: ${bytesToHex(plan.update.successor.script)}. `
    + `Output 1 fee: ${sats} · ${lbtc()}. Wallet net change: -${sats} · ${lbtc()}. Decline if anything differs.`;
}

export function claimApproval(plan: ClaimPlan): string {
  const c = plan.claim;
  const asset = displayHex(c.mint.asset);
  const sats = c.fee.sats;
  return `Check Humid: Requested signing inputs must contain only Input 1 at ${plan.feeAddress}. `
    + `Output 0: ${plan.successorAddress}, "Confidential amount unavailable · Confidential asset unavailable", Script: ${bytesToHex(c.successor.script)}. `
    + `Output 1: ${c.mint.address ? `${c.mint.address}, ` : ''}${c.mint.units} · ${asset}, Script: ${bytesToHex(c.mint.script)}. `
    + `Output 2 fee: ${sats} · ${lbtc()}. Wallet net change: -${sats} · ${lbtc()}, plus ${c.mint.units} · ${asset} if this wallet receives the claim. `
    + 'Decline if anything differs.';
}
