import { buildTransaction } from './builder';
import { DEFAULTS } from '@bridge/core/config.js';
import type { Humid } from '@bridge/core/lib/humid.js';
import type { BridgeEnv, Eip1193 } from './types';

/**
 * The page's own base URL, ending in '/'. The build uses a relative base ('./'), so this is the directory the page
 * was loaded from: at a GitHub Pages project subpath the instance record is at <subpath>/instances/<name>/.
 */
export function siteHref(): string {
  return new URL(import.meta.env.BASE_URL, window.location.href).href;
}

/** The real browser: window.ethereum, window.humid, fetch, localStorage and the clipboard. */
export function browserEnv(): BridgeEnv {
  const w = window as unknown as Window & { ethereum?: Eip1193; humid?: Humid };
  return {
    ethereum: () => w.ethereum ?? null,
    humidWindow: () => w,
    // Bound through a wrapper: Esplora and EthRpc call it detached, and a detached window.fetch throws.
    fetch: (...args) => window.fetch(...args),
    storage: window.localStorage,
    siteHref,
    now: () => Date.now(),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    confirm: (text) => window.confirm(text),
    copy: (text) => navigator.clipboard.writeText(text),
    pollMs: DEFAULTS.pollMs,
    buildTransaction,
  };
}
