import { DEFAULTS, PUBLISHED } from '@bridge/core/config.js';

/** The bridge's repository, and its published site (config.js PUBLISHED): the one copy whose record counts. */
export const REPO = PUBLISHED.repo;
export const SITE = PUBLISHED.site;
export const OPERATOR = `${REPO}/blob/${PUBLISHED.branch}/OPERATOR.md`;
export const TAKEOVER = `${REPO}/blob/${PUBLISHED.branch}/README.md#quick-guide-to-completing-a-manual-end-to-end-test`;
export const JUST_STEPS = `${OPERATOR}#the-same-steps-with-just`;
export const LIMITS = `${OPERATOR}#limits-to-state-plainly`;

/** `s` as a regular expression that matches it literally. */
const literal = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/** A file of the instance record, as vite.config.ts recordRequest serves it: safe segments, no dotfile, JSON, hex or README. */
const RECORD_FILE = /^(?:[A-Za-z0-9_-][A-Za-z0-9._-]*\/)*[A-Za-z0-9_-][A-Za-z0-9._-]*\.(?:json|hex|md)$/;

/** The pages outside this site the page may link to, as canonical URLs without query. */
const EXTERNAL = [
  // The repository, or one of its files on the published branch, with an optional heading anchor.
  new RegExp(`^${literal(REPO)}(?:/blob/${literal(PUBLISHED.branch)}/[A-Za-z0-9_-][A-Za-z0-9._/-]*(?:#[a-z0-9-]+)?)?$`),
  // The published site's front page, for a copy of the page served anywhere else.
  new RegExp(`^${literal(SITE)}$`),
  // A Sepolia address or transaction on the Sepolia explorer.
  new RegExp(`^${literal(DEFAULTS.ethExplorer)}/(?:address/0x[0-9a-fA-F]{40}|tx/0x[0-9a-fA-F]{64})$`),
  // A Liquid testnet transaction or address on Blockstream's explorer: never its API (/liquidtestnet/api).
  new RegExp(`^${literal(DEFAULTS.liquidExplorer)}/(?:tx/[0-9a-f]{64}|address/(?:tex|tlq)1[02-9ac-hj-np-z]+)$`),
  // The Sepolia beacon explorer, for checking finality.
  /^https:\/\/sepolia\.beaconcha\.in\/?$/,
];

/**
 * Whether the page may link to `href` while it serves the instance whose record is `record` (config.js parseInstance
 * `instances/<name>/`, or null for none): an in-page anchor; a file of that record, and of no other; the repository
 * or a file on its published branch; the published site's front page; a Sepolia or Liquid testnet explorer page of an address or transaction; or the
 * Sepolia beacon explorer. Nothing else: no other instance's record, no path out of the record, no data API, no other
 * host, scheme, port, credentials or query. An absolute link must be in canonical form, so `..` cannot hide in it.
 */
export function linkAllowed(href: string, record: string | null): boolean {
  if (/^#[A-Za-z][A-Za-z0-9_-]*$/.test(href)) return true;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(href) && !href.startsWith('/') && !href.startsWith('\\')) {
    return !!record && href.startsWith(record) && RECORD_FILE.test(href.slice(record.length))
      && !href.slice(record.length).split('/').some((s) => s === '..' || s === '.');
  }
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return false;
  }
  // Canonical: parsing changes nothing, except the '/' it adds to a bare origin.
  const canonical = url.href === href || (url.pathname === '/' && url.href === `${href}/`);
  if (!canonical || url.protocol !== 'https:' || url.username || url.password || url.port || url.search) return false;
  return EXTERNAL.some((p) => p.test(href));
}
