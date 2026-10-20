// Deployment settings.
//
// The page serves one bridge instance, INSTANCE, and only a reviewed change to this file changes it: no link,
// setting or stored value can. Its values are the instance's published record under instances/<name>/: the escrow
// and its runtime code hash from instance.json, and the Liquid bootstrap txid and state address of the manifest
// that `assemble.py verify-bootstrap` checked. The page builds every burn script itself and only checks it against
// the escrow, whose answer comes through an RPC. It reads every other bridge parameter (asset, federation,
// confirmations, deposit admission) from the escrow, once its code hash matches.
//
// No instance is published until its deployment record is reviewed.
import { depositRecipient, ethAddress } from './lib/bridge.js';

export const INSTANCE = null;

export const DEFAULTS = Object.freeze({
  chainId: 11155111n,
  chainName: 'Sepolia',
  esplora: 'https://blockstream.info/liquidtestnet/api',
  liquidExplorer: 'https://blockstream.info/liquidtestnet',
  ethExplorer: 'https://sepolia.etherscan.io',
  pollMs: 8000,
});

/**
 * Checks an instance record and returns it frozen, with the escrow in lower case: { name, record, escrow,
 * codeHash, bootstrap, state }. null stays null. Throws on any invalid value, so a mistaken edit of INSTANCE stops
 * the page instead of serving it.
 */
export function parseInstance(raw) {
  if (raw === null) return null;
  const hex64 = (k) => {
    if (typeof raw[k] !== 'string' || !/^[0-9a-f]{64}$/.test(raw[k])) throw new Error(`instance ${k}: 64 lower-case hex characters`);
    return raw[k];
  };
  if (typeof raw.name !== 'string' || !/^[a-z0-9-]+$/.test(raw.name)) throw new Error('instance name: its directory under instances/');
  depositRecipient(raw.state);
  return Object.freeze({
    name: raw.name,
    record: `instances/${raw.name}/`,
    escrow: ethAddress(raw.escrow),
    codeHash: hex64('codeHash'),
    bootstrap: hex64('bootstrap'),
    state: raw.state,
  });
}

/** A Settings error, with `field` the parseSettings key it is about ('esplora' or 'ethRpc'), so a form can place it. */
function settingsError(field, message) {
  return Object.assign(new Error(message), { field });
}

/** `text` as an http(s) URL, or throws for `field`, naming `what`; never echoes the URL, which may embed an API key. */
function httpUrl(text, field, what) {
  let url;
  try {
    url = new URL(text);
  } catch {
    url = null;
  }
  if (!url || (url.protocol !== 'https:' && url.protocol !== 'http:')) throw settingsError(field, `the ${what} must be an http(s) URL`);
  return url;
}

/**
 * The settings a reader can change, from `raw` (the Settings form or storage): the Liquid testnet Esplora API, empty
 * or missing for the default, and a Sepolia JSON-RPC URL for the page's Ethereum reads, empty or missing (null) to
 * read through the wallet. Other keys are ignored. Throws on an invalid URL, with the error's `field` naming the
 * setting.
 *
 * The RPC must be https, or http on this computer (a local node), because what it answers decides what the page
 * shows; and it must not carry a user name or password, which browsers refuse to send from a URL. Its URL may hold an
 * API key, so it is kept only in this browser's storage, and no message here repeats it.
 */
export function parseSettings(raw) {
  const text = typeof raw.esplora === 'string' ? raw.esplora.trim() : '';
  const esplora = text || DEFAULTS.esplora;
  httpUrl(esplora, 'esplora', 'Esplora API');
  const rpcText = typeof raw.ethRpc === 'string' ? raw.ethRpc.trim() : '';
  if (!rpcText) return { esplora, ethRpc: null };
  const url = httpUrl(rpcText, 'ethRpc', 'Sepolia RPC');
  if (url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
    throw settingsError('ethRpc', 'the Sepolia RPC must be an https URL, or http only on this computer (localhost)');
  }
  if (url.username || url.password) {
    throw settingsError('ethRpc', 'the Sepolia RPC URL cannot carry a user name or password; use the provider\'s key-in-path URL');
  }
  return { esplora, ethRpc: rpcText };
}
