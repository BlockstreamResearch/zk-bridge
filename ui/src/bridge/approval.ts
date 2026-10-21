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
  // Humid lists an OP_RETURN output with an empty address line; its script ends with the recipient's 40 hex digits.
  const output0 = `Output 0 shows no address, with "${units} · ${t.assetDisplay}" and "Script: ${bytesToHex(t.burn.scriptPubKey)}", `
    + `which starts with 6a46 (OP_RETURN) and ends with the recipient ${t.burn.recipient.slice(2)}`;
  return `In Humid's approval, sign only if ${output0}, and if "Wallet net change" shows "-${units} · ${t.assetDisplay}" `
    + `and "-${FEE_SATS} · ${lbtc()}", the fee. If anything differs, decline.`;
}

export function updateApproval(plan: UpdatePlan): string {
  const sats = plan.update.fee.sats;
  return `In Humid's approval, the "Requested signing inputs" section must name only Input 1 at ${plan.feeAddress}; Output 0 shows ${plan.successorAddress}, `
    + `"Confidential amount unavailable · Confidential asset unavailable" and "Script: ${bytesToHex(plan.update.successor.script)}"; `
    + `Output 1 (fee) shows "${sats} · ${lbtc()}"; and "Wallet net change" shows "-${sats} · ${lbtc()}". If anything differs, decline.`;
}

export function claimApproval(plan: ClaimPlan): string {
  const c = plan.claim;
  const asset = displayHex(c.mint.asset);
  const sats = c.fee.sats;
  return `In Humid's approval, the "Requested signing inputs" section must name only Input 1 at ${plan.feeAddress}; Output 0 shows ${plan.successorAddress}, `
    + `"Confidential amount unavailable · Confidential asset unavailable" and "Script: ${bytesToHex(c.successor.script)}"; `
    + `Output 1 shows ${c.mint.address ? `${c.mint.address}, ` : ''}"${c.mint.units} · ${asset}" and "Script: ${bytesToHex(c.mint.script)}"; `
    + `Output 2 (fee) shows "${sats} · ${lbtc()}"; and "Wallet net change" shows "-${sats} · ${lbtc()}", and "${c.mint.units} · ${asset}" as well `
    + 'if the claim pays this Humid wallet. If anything differs, decline.';
}
