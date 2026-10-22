// What the page may do and say for a given state. Keep action gates and their explanations in pure functions so
// components and tests share them.
import { DEFAULTS } from '@bridge/core/config.js';
import { type Admission, depositAdmission } from '@bridge/core/lib/bridge.js';
import { readRedeem } from './forms';
import { short } from './format';
import type { BridgeState, TargetState } from './types';

type S = BridgeState;

export const onSepolia = (s: S) => s.chainId === DEFAULTS.chainId;

/** The page can read Sepolia: through the RPC in Settings, or a connected wallet on Sepolia (never another chain). */
export const canRead = (s: S) => s.settings.ethRpc !== null || (s.hasWallet && !!s.account && onSepolia(s));

/** The page can send Sepolia transactions for the bridge. */
export const ready = (s: S) => !!s.account && onSepolia(s) && !!s.bridge;

/** The page can read the bridge: enough to show a burn and have Humid make it. */
export const readable = (s: S) => canRead(s) && !!s.bridge;

export const admission = (s: S): Admission | null => (s.bridge ? depositAdmission(s.bridge, Math.floor(s.now / 1000)) : null);

/** Liquid's tip signs under keys the light client has not reached yet. */
export const signersAhead = (s: S) => !!s.bridge && !!s.liquid && s.bridge.sbsHash !== s.liquid.sbsHash;

export const relayLag = (s: S) => (s.bridge && s.liquid ? Math.max(0, s.liquid.tip - s.bridge.lcTip) : 0);

const unusable = (s: S) => (s.instance ? 'Escrow unavailable. See the notice above.' : 'No bridge instance. See the notice above.');

/** What is missing before the bridge can be used, in the order a user fixes it; null once ready. */
export function notReady(s: S): string | null {
  if (!s.account) return 'Connect a wallet to continue.';
  if (!onSepolia(s)) return 'Switch your wallet to Sepolia.';
  if (!s.bridge) return unusable(s);
  return null;
}

/** What is missing before the bridge can be read; null once readable. */
export function notReadable(s: S): string | null {
  if (!canRead(s)) return notReady(s);
  return s.bridge ? null : unusable(s);
}

/**
 * The asset (internal hex) a burn may hold: the escrow's BRIDGE_ASSET once the published bootstrap is shown to issue
 * it. That answer alone arrives through an RPC, and a burn destroys whatever asset it holds.
 */
export const burnAsset = (s: S): string | null =>
  s.bridge && s.bootstrap?.ok && s.bootstrap.asset === s.bridge.asset ? s.bootstrap.asset : null;

export const burnable = (s: S) => readable(s) && !!burnAsset(s);

/** What is missing before the page shows or makes a burn; null once burnable. */
export function notBurnable(s: S): string | null {
  const why = notReadable(s);
  if (why) return why;
  if (!s.bootstrap) return 'Verifying the bridge asset against its Liquid bootstrap.';
  if (burnAsset(s)) return null;
  return s.bootstrap.unavailable
    ? 'Bootstrap unavailable. Retrying automatically. Burn nothing until verification passes; see Bridge checks.'
    : 'Bridge asset verification failed. Burn nothing; see Bridge checks.';
}

/**
 * Step 1's burn target with the amount now in the form: only while its asset is still the one the bootstrap confirms
 * and its recipient is still the form's, so neither an RPC's later answer nor an edit can swap them underneath.
 */
export function target(s: S): (TargetState & { units: bigint | null }) | null {
  const t = s.target;
  if (!t || !burnable(s) || t.asset !== burnAsset(s)) return null;
  const r = readRedeem(s.redeemForm, s.account);
  if (r.recipient !== t.recipient) return null;
  return { ...t, units: r.units ?? null };
}

export type ChipState = 'idle' | 'ok' | 'warn' | 'bad';
export interface Chip {
  state: ChipState;
  value: string;
  sub: string;
  unit?: string;
}

/** The three overview readings: the wallet, Liquid's tip and the bridge's light client. */
export function chips(s: S): { eth: Chip; liquid: Chip; bridge: Chip } {
  const eth: Chip = !s.hasWallet ? { state: 'bad', value: 'No wallet', sub: 'Install an Ethereum browser wallet' }
    : !s.account ? { state: 'idle', value: 'Not connected', sub: 'Connect to deposit or redeem' }
      : !onSepolia(s) ? { state: 'bad', value: 'Wrong network', sub: 'Switch your wallet to Sepolia' }
        : { state: 'ok', value: short(s.account, 4), sub: 'Connected account' };
  const liquid: Chip = s.liquidError ? { state: 'bad', value: 'Unreachable', sub: 'Liquid API unavailable' }
    : s.liquid ? { state: 'ok', value: s.liquid.tip.toLocaleString('en'), sub: 'Latest Liquid block', unit: 'blocks' }
      : { state: 'idle', value: 'Checking…', sub: 'Reading Liquid API' };
  let bridge: Chip;
  if (!s.instance) bridge = { state: 'warn', value: 'Not deployed', sub: 'No published bridge instance' };
  else if (s.bridgeError) bridge = { state: 'bad', value: 'Unavailable', sub: `Escrow ${short(s.instance.escrow, 4)} cannot be read` };
  else if (!s.bridge) bridge = { state: 'idle', value: 'Connect to read', sub: `Escrow ${short(s.instance.escrow, 4)}: connect or set a Sepolia RPC` };
  else {
    const lag = relayLag(s);
    const behind = !s.liquid ? 'Relayed to the escrow' : lag === 0 ? 'Level with Liquid' : `${lag.toLocaleString('en')} block${lag === 1 ? '' : 's'} behind Liquid`;
    bridge = {
      state: lag > 60 || signersAhead(s) ? 'warn' : 'ok',
      value: s.bridge.lcTip.toLocaleString('en'),
      sub: `${signersAhead(s) ? 'Signing keys need relaying · ' : ''}${behind} · deposits ${admission(s)!.deposit ? 'open' : 'closed'}`,
      unit: 'blocks',
    };
  }
  return { eth, liquid, bridge };
}

/** The one notice under the route: the most pressing reason the bridge is not fully usable, or ''. */
export function notice(s: S): string {
  if (!s.instance) return 'No published bridge instance. Deposits and redemptions are unavailable.';
  if (s.bridgeError) return `Escrow ${short(s.instance.escrow)}: ${s.bridgeError}. Do not send funds.`;
  if (s.liquidError) return `Liquid data unavailable: ${s.liquidError}. Checks, tracking and redemption need it.`;
  if (s.bootstrap && !s.bootstrap.ok) return `Deposits are off: ${s.bootstrap.error}. See Bridge checks.`;
  const adm = admission(s);
  if (adm && !adm.deposit) return adm.text;
  if (signersAhead(s)) return 'New Liquid signing keys await relaying. New burns must wait.';
  if (relayLag(s) > 60) return `Liquid relay is ${relayLag(s)} blocks behind. Anyone can relay from a burn row to continue redemption.`;
  return '';
}

export interface CheckRow {
  ok: boolean | null;
  text: string;
}

/** Bridge checks: what the page verified about the instance, and what it does not check. */
export function checkRows(s: S): CheckRow[] {
  const rows: CheckRow[] = [];
  const add = (ok: boolean | null, text: string) => rows.push({ ok, text });
  const inst = s.instance;
  if (!inst) {
    add(null, 'No published bridge instance.');
    return rows;
  }
  if (!s.bridge) {
    add(s.bridgeError ? false : null, s.bridgeError ? `The escrow is ${s.bridgeError}.` : 'Connect on Sepolia or set a Sepolia RPC in Settings.');
  } else {
    add(true, `Escrow code hash matches ${inst.record}.`);
    add(true, `Redeemable asset: ${short(s.bridge.assetDisplay)}.`);
    if (s.bootstrap && s.bootstrap.checks.length) for (const c of s.bootstrap.checks) add(c.ok, c.text);
    else if (s.bootstrap) add(false, s.bootstrap.error ?? 'the bootstrap was not checked');
    const adm = admission(s)!;
    add(adm.deposit, adm.text);
  }
  add(null, `Not checked here: state address ${short(inst.state, 8)} and escrow code against source. `
    + `Verify from ${inst.record} with assemble.py verify-bootstrap and a local escrow compilation.`);
  return rows;
}
