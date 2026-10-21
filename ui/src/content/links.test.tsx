// Where the page links. Every link must be one linkAllowed accepts for the configured record: an in-page anchor, a
// file of that one record, the repository, the published site's front page, or an explorer page. Each repository link must name a file of this
// checkout and a heading it has. Each record file the page links must be in the published record. The page is
// rendered in each fixture state that shows links.
import { DEFAULTS, INSTANCE, PUBLISHED, parseInstance } from '@bridge/core/config.js';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { render, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { App } from '../app/App';
import { BridgeProvider } from '../bridge/context';
import { BridgeController } from '../bridge/controller';
import { DEPOSIT_ADDRESS, ESCROW, FIXTURE_INSTANCE, type Scenario, fixture } from '../dev/fixture';
import { JUST_STEPS, LIMITS, OPERATOR, REPO, SITE, TAKEOVER, linkAllowed } from './links';

// The repository checkout, as a file system path from this file's own location (ui/src/content/), so it does
// not depend on the working directory npm, Vitest or CI starts in. Only path strings reach node:fs: in the jsdom
// environment the global URL is jsdom's, which node:fs does not take for a file URL.
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
/** A path of the checkout, from its root. */
const inCheckout = (relative: string) => path.join(ROOT, ...relative.split('/'));
const RECORD = `instances/${FIXTURE_INSTANCE.name}/`;
const BLOB = `${REPO}/blob/${PUBLISHED.branch}/`;

/** The anchors GitHub gives a Markdown file's headings; lines inside fenced code are not headings. */
function headingSlugs(markdown: string): string[] {
  const slugs: string[] = [];
  let fenced = false;
  for (const line of markdown.split('\n')) {
    if (/^\s*```/.test(line)) fenced = !fenced;
    else if (!fenced && /^#{1,6} /.test(line)) slugs.push(line.replace(/^#+ /, '').trim().toLowerCase().replace(/[^\w\- ]/g, '').replace(/ /g, '-'));
  }
  return slugs;
}

/** Why the repository link `href` is broken in this checkout, or null: its file must exist, and its anchor be a heading. */
function brokenRepoLink(href: string): string | null {
  if (!href.startsWith(BLOB)) return null;
  const [file, anchor] = href.slice(BLOB.length).split('#');
  const at = inCheckout(file);
  if (!existsSync(at)) return `${href}: ${file} is not in this checkout`;
  if (anchor && !headingSlugs(readFileSync(at, 'utf8')).includes(anchor)) return `${href}: ${file} has no heading #${anchor}`;
  return null;
}

describe('linkAllowed', () => {
  const tx = 'ab'.repeat(32);
  it.each([
    '#main', '#trust',
    `${RECORD}instance.json`, `${RECORD}manifest.json`, `${RECORD}lc_preimages.json`, `${RECORD}lc_stores/9000000.json`, `${RECORD}README.md`,
    REPO, OPERATOR, TAKEOVER, JUST_STEPS, LIMITS, SITE,
    `${DEFAULTS.ethExplorer}/address/${ESCROW}`, `${DEFAULTS.ethExplorer}/tx/0x${tx}`,
    `${DEFAULTS.liquidExplorer}/tx/${tx}`, `${DEFAULTS.liquidExplorer}/address/${DEPOSIT_ADDRESS}`,
    'https://sepolia.beaconcha.in',
  ])('allows %s', (href) => {
    expect(linkAllowed(href, RECORD)).toBe(true);
  });

  it.each([
    ['another instance\'s record', 'instances/other/manifest.json'],
    ['a path out of the record', `${RECORD}../other/manifest.json`],
    ['an encoded path out of the record', `${RECORD}%2e%2e/other/manifest.json`],
    ['a single-dot segment', `${RECORD}./manifest.json`],
    ['the record directory', RECORD],
    ['a record dotfile', `${RECORD}.secret.json`],
    ['a record file of another kind', `${RECORD}notes.txt`],
    ['a record file with a query', `${RECORD}manifest.json?x=1`],
    ['a root-relative record path, broken at a Pages subpath', `/${RECORD}manifest.json`],
    ['a page file', 'index.html'],
    ['the Liquid data API', `${DEFAULTS.esplora}/tx/${tx}/hex`],
    ['the Liquid data API by its explorer prefix', `${DEFAULTS.liquidExplorer}/api/blocks/tip/hash`],
    ['an explorer page with a query', `${DEFAULTS.liquidExplorer}/tx/${tx}?expand`],
    ['a malformed explorer address', `${DEFAULTS.ethExplorer}/address/0x1234`],
    ['another explorer path', `${DEFAULTS.ethExplorer}/token/${ESCROW}`],
    ['another host', 'https://evil.example/'],
    ['a look-alike repository', `${REPO}-evil`],
    ['another branch', `${REPO}/blob/other/OPERATOR.md`],
    ['main, which the site is not published from', `${REPO}/blob/main/OPERATOR.md`],
    ['the earlier repository', 'https://github.com/KyrylR/liquid-poc-bridge'],
    ['the earlier site', 'https://kyrylr.github.io/liquid-poc-bridge/'],
    ['a path of the published site', `${SITE}instances/x/manifest.json`],
    ['the published site with a query', `${SITE}?tab=redeem`],
    ['a non-canonical path', `${BLOB}../../evil/README.md`],
    ['a non-canonical scheme', REPO.replace('https', 'HTTPS')],
    ['plain http', DEFAULTS.liquidExplorer.replace('https', 'http') + `/tx/${tx}`],
    ['credentials', REPO.replace('https://', 'https://user:pw@')],
    ['a port', REPO.replace('github.com', 'github.com:8443')],
    ['a protocol-relative URL', '//evil.example/x'],
    ['a script URL', 'javascript:alert(1)'],
    ['a data URL', 'data:text/html,hi'],
    ['an empty anchor', '#'],
    ['an empty link', ''],
  ])('refuses %s', (_case, href) => {
    expect(linkAllowed(href, RECORD)).toBe(false);
  });

  it('allows no record file at all while no instance is configured', () => {
    expect(linkAllowed(`${RECORD}manifest.json`, null)).toBe(false);
  });
});

describe('the repository headings the page links to', () => {
  it('are read from the repository checkout, wherever the tests start', () => {
    // A wrong root would make every repository link look broken; say so plainly instead.
    expect(existsSync(inCheckout('ui/package.json')), ROOT).toBe(true);
    expect(existsSync(inCheckout('OPERATOR.md')), ROOT).toBe(true);
  });

  it.each([TAKEOVER, JUST_STEPS, LIMITS, OPERATOR])('%s exists', (href) => {
    expect(brokenRepoLink(href)).toBeNull();
  });

  it('notices a heading that is gone', () => {
    expect(brokenRepoLink(`${OPERATOR}#no-such-heading`)).toMatch(/has no heading #no-such-heading/);
    expect(brokenRepoLink(`${BLOB}NO-SUCH-FILE.md`)).toMatch(/is not in this checkout/);
  });
});

/** Every link the page renders in `scenario`, once it has read Liquid and, where it can, the escrow. */
async function renderedLinks(scenario: Scenario, raw = fixture(scenario).instance) {
  const f = fixture(scenario);
  const c = new BridgeController(raw, f.env);
  const { container, unmount } = render(<BridgeProvider controller={c}><App /></BridgeProvider>);
  await waitFor(() => expect(c.getSnapshot().liquid ?? c.getSnapshot().liquidError).toBeTruthy());
  const hrefs = [...container.querySelectorAll('a[href]')].map((a) => a.getAttribute('href')!);
  const named = [...container.innerHTML.matchAll(/instances\/([A-Za-z0-9._-]+)/g)].map((m) => m[1]);
  unmount();
  return { hrefs, named, record: parseInstance(raw)?.record ?? null };
}

describe('the links the page renders', () => {
  it.each(['connected', 'activity', 'bad-code', 'no-wallet', 'no-instance'] as const)('are all allowed, in the %s state', async (scenario) => {
    const { hrefs, named, record } = await renderedLinks(scenario);
    expect(hrefs.length).toBeGreaterThan(0);
    expect(hrefs.filter((h) => !linkAllowed(h, record))).toEqual([]);
    expect(hrefs.map(brokenRepoLink).filter(Boolean)).toEqual([]);
    // The page names no instance but the one it serves.
    expect(new Set(named)).toEqual(new Set(record ? [FIXTURE_INSTANCE.name] : []));
    if (record) expect(hrefs.some((h) => h.startsWith(record))).toBe(true);
  });

  it('link no record file while no instance is published', async () => {
    const { hrefs } = await renderedLinks('no-instance');
    expect(hrefs.filter((h) => h.includes('instances/'))).toEqual([]);
  });

  it.skipIf(INSTANCE === null)('link only files the published record has', async () => {
    const { hrefs, named, record } = await renderedLinks('no-wallet', INSTANCE);
    expect(hrefs.filter((h) => !linkAllowed(h, record))).toEqual([]);
    expect(new Set(named)).toEqual(new Set([INSTANCE!.name]));
    // lc_preimages.json lists the published light-client stores; before the first one is published there may be none.
    const noStores = !existsSync(inCheckout(`${record}lc_stores`));
    const missing = hrefs.filter((h) => h.startsWith(record!) && !existsSync(inCheckout(h)))
      .filter((h) => !(noStores && h === `${record}lc_preimages.json`));
    expect(missing).toEqual([]);
  });
});
