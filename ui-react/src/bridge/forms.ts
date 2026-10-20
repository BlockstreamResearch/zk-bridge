// The page's form fields, read with the shared rules of ../ui/lib/bridge.js and humid.js. Pure: each returns the
// parsed value or the rule's own message, and the caller decides when to show it.
import { burnRecipient, depositRecipient, depositUnits, parseEther, redeemUnits } from '@bridge/ui/lib/bridge.js';
import { humidAddress } from '@bridge/ui/lib/humid.js';
import { message } from './format';

export interface DepositInput {
  script?: Uint8Array;
  address?: string | null;
  wei?: bigint;
  units?: bigint;
  errors: { recipient?: string; amount?: string };
}

/** Step 1 and 2 of Deposit: the Liquid recipient and the amount in ETH. Empty fields give neither value nor error. */
export function readDeposit(recipient: string, amount: string): DepositInput {
  const d: DepositInput = { errors: {} };
  if (recipient.trim()) {
    try {
      ({ script: d.script, address: d.address } = depositRecipient(recipient));
    } catch (e) {
      d.errors.recipient = message(e);
    }
  }
  if (amount.trim()) {
    try {
      d.wei = parseEther(amount);
      d.units = depositUnits(d.wei);
    } catch (e) {
      d.errors.amount = message(e);
    }
  }
  return d;
}

export interface RedeemInput {
  recipient?: string;
  units?: bigint;
  recipientError?: string;
  amountError?: string;
}

/**
 * Redeem step 1: the recipient, which defaults to the connected account, and the amount in bridge-asset units
 * (÷ 10⁸). A typed recipient must be checksummed unless it is the connected account: a burn cannot be redirected.
 */
export function readRedeem(form: { recipient: string; amount: string }, account: string | null): RedeemInput {
  const r: RedeemInput = {};
  const text = form.recipient.trim() || account || '';
  if (text) {
    try {
      r.recipient = burnRecipient(text, account);
    } catch (e) {
      r.recipientError = message(e);
    }
  }
  if (form.amount.trim()) {
    try {
      r.units = redeemUnits(form.amount);
    } catch (e) {
      r.amountError = message(e);
    }
  }
  return r;
}

/** Redeem step 4's optional payee: null to pay the burn's recipient, else a checked address, or the error. */
export function readPayTo(text: string, account: string | null): { payTo: string | null; error?: string } {
  if (!text.trim()) return { payTo: null };
  try {
    return { payTo: burnRecipient(text, account) };
  } catch (e) {
    return { payTo: null, error: message(e) };
  }
}

/** Redeem step 2's Humid address: the claim's address and script, or why it is not one. */
export function readHumid(text: string): { claim?: { address: string; script: Uint8Array }; error?: string } {
  if (!text.trim()) return {};
  try {
    return { claim: humidAddress(text) };
  } catch (e) {
    return { error: message(e) };
  }
}
