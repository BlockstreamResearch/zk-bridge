// The trust copy's structure: every permissionless step with what it needs, what each step costs with the Humid fee
// constants of lib/humid.js, one point per assumption each saying how it stands on this instance, the one bare
// OP_RETURN burn, and no version labels. Then each "On this instance" line against the fixture's deployment: its pins
// always, the escrow's settings only once its code hash matched, and the asset only once the bootstrap confirmed it.
import { cleanup, render, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { BridgeProvider } from '../bridge/context';
import { BridgeController } from '../bridge/controller';
import { SETTINGS_KEY } from '../bridge/journeys';
import { TrustPanel } from '../components/TrustPanel';
import { ASSET_DISPLAY, BOOTSTRAP_TXID, ESCROW, type Fixture, type Scenario, fixture } from '../dev/fixture';
import { ASSUMPTIONS } from './trust';

/** The fixture asset's display id as the page shortens it, and its first six characters, which no other line shows. */
const ASSET_SHORT = `${ASSET_DISPLAY.slice(0, 6)}…`;
const ASSET_PREFIX = new RegExp(ASSET_DISPLAY.slice(0, 6));

function renderTrust(scenario: Scenario = 'no-instance', tweak?: (f: Fixture) => void) {
  const f = fixture(scenario);
  tweak?.(f);
  const c = new BridgeController(f.instance, f.env);
  const { container } = render(<BridgeProvider controller={c}><TrustPanel panelRef={{ current: null }} /></BridgeProvider>);
  return container;
}

/** Each "On this instance" line, keyed by its action's name or its point's title. */
function here(page: HTMLElement) {
  const text = (e: Element | null) => e?.textContent ?? '';
  return {
    ...Object.fromEntries([...page.querySelectorAll('[data-action]')].map((a) => [a.getAttribute('data-action'), text(a.querySelector('.here'))])),
    ...Object.fromEntries([...page.querySelectorAll('.assumptions > li')].map((li) => [text(li.querySelector('b')), text(li.querySelector('.here'))])),
  } as Record<string, string>;
}

/** The page once the controller has read the fixture's escrow, checked its bootstrap and read Liquid's tip. */
async function readTrust(scenario: Scenario = 'connected') {
  const page = renderTrust(scenario);
  await waitFor(() => {
    expect(here(page).burn).toMatch(/Burn asset/);
    expect(here(page).relay).toMatch(/behind Liquid/);
  });
  return page;
}

describe('What you are trusting', () => {
  it('counts its points, and each point and step says how it stands on this instance', () => {
    const page = renderTrust();
    const points = page.querySelectorAll('.assumptions > li');
    expect(points).toHaveLength(ASSUMPTIONS.length);
    expect(page.querySelector('.count')?.textContent).toBe(String(points.length));
    for (const p of points) expect(p.querySelector('.here')?.textContent).toMatch(/^On this instance \S/);
    for (const a of page.querySelectorAll('[data-action]')) expect(a.querySelector('dd.here')?.textContent).toMatch(/^On this instance \S/);
  });

  it('lists every step anyone can take, each with what it needs, labelled in the markup', () => {
    const page = renderTrust();
    const actions = [...page.querySelectorAll('[data-action]')];
    expect(actions.map((a) => a.getAttribute('data-action'))).toEqual(['relay', 'fork-proof', 'burn', 'redeem', 'prove-claim', 'audit', 'sources']);
    const needs = Object.fromEntries(actions.map((a) => [a.getAttribute('data-action'), a.querySelector('dd.needs')?.textContent ?? '']));
    for (const [name, text] of Object.entries(needs)) expect(text, name).toMatch(/^Needs: \S/);
    expect(needs['prove-claim']).toMatch(/Docker[\s\S]*SP1[\s\S]*eth_getProof[\s\S]*light-client[\s\S]*tL-BTC/);
    expect(needs['fork-proof']).toMatch(/beacon node/);
    expect(needs.burn).toMatch(/Confirmed[\s\S]*tL-BTC/);
    // The escrow's MIN_CONFIRMATIONS is read at run time; static copy stating a count would go stale.
    expect(needs.redeem).not.toMatch(/\(\d+ on this escrow\)/);
  });

  it('says what each step costs, with the Humid fee route\'s own constants', () => {
    const page = renderTrust();
    const costs = Object.fromEntries([...page.querySelectorAll('[data-cost]')].map((c) => [c.getAttribute('data-cost'), c.textContent ?? '']));
    expect(Object.keys(costs)).toEqual(['deposit', 'sepolia', 'burn', 'prove-claim']);
    expect(costs.deposit).toMatch(/At least 0\.001[\s\S]*gas[\s\S]*unblinded outputs/);
    expect(costs.sepolia).toMatch(/sender pays Sepolia gas/);
    expect(costs.burn).toMatch(/500 sats[\s\S]*confirmed coin[\s\S]*0\.00001046 tL-BTC[\s\S]*confidential address[\s\S]*546 sats of change/);
    expect(costs['prove-claim']).toMatch(/tL-BTC for update and claim fees/);
  });

  it('describes the one bare 72-byte OP_RETURN burn', () => {
    const page = renderTrust();
    const burn = [...page.querySelectorAll('.assumptions > li')].find((li) => li.textContent?.includes('liquid-bridge-poc/burn'));
    expect(burn?.querySelector('.here')?.textContent).toMatch(/72 bytes[\s\S]*OP_RETURN[\s\S]*chain ID[\s\S]*escrow[\s\S]*recipient/);
    const step = page.querySelector('[data-action="burn"]')?.textContent;
    expect(step).toMatch(/unblinded burn[\s\S]*OP_RETURN[\s\S]*Ordinary Send cannot/);
    expect(step).toMatch(/Humid/);
    expect(page.textContent).not.toMatch(/redeem address/);
  });

  it('names no version and, with no instance published, links no escrow, transaction or record', () => {
    const page = renderTrust();
    expect(page.textContent).not.toMatch(/\b[vV][1-5]\b/);
    expect(page.textContent).toMatch(/No instance is published yet/);
    expect(page.innerHTML).not.toMatch(/etherscan\.io\/address\/|liquidtestnet\/tx\/|href="instances\/|data-store=/);
  });
});

describe('On this instance, from its pins and what the page checked', () => {
  it('states the escrow\'s own settings, the Liquid tip and the confirmed asset, with links to the escrow, bootstrap and record', async () => {
    const page = await readTrust();
    const h = here(page);
    for (const text of Object.values(h)) expect(text).not.toMatch(/No instance is published yet|shows none of its settings|Connect a wallet/);

    // The fixture escrow: tip 10 blocks behind Liquid's, a block timestamped 10 minutes before the fixture's noon, a
    // fork check 5 minutes old of at most an hour, a relay lag of at most six hours, deposits open for 90 days.
    expect(h.relay).toMatch(/through block 2,663,990, 10 blocks behind Liquid, timestamped 2026-10-20 11:50 UTC\.$/);
    expect(h['fork-proof']).toMatch(/fork check: 2026-10-20 11:55 UTC, valid until 2026-10-20 12:55 UTC/);
    expect(h['fork-proof']).not.toMatch(/reopens/);
    expect(h.redeem).toMatch(/requires 2 Liquid confirmations/);
    expect(h.burn).toMatch(new RegExp(`Burn asset ${ASSET_DISPLAY.slice(0, 6)}…${ASSET_DISPLAY.slice(-6)}`));
    expect(h['Liquid signers']).toMatch(/expects signing script hash 0x\w{6}…\w{6}\. It matches the latest Liquid block\./);
    expect(h['Liquid checkpoint and key changes']).toMatch(/DynaFed epochs of 20,160 blocks\./);
    expect(h['Ethereum forks']).toMatch(/closes deposits at 2027-01-18 12:00 UTC\./);
    expect(h['Keeping deposits open']).toMatch(/fork check up to 1 hour old and relayed block up to 6 hours old\. Deposits are open\./);
    expect(h['Bootstrap verification']).toMatch(/Bootstrap matches the escrow asset/);
    expect(h['Fixed, unaudited code']).toMatch(/Hash matched\./);
    expect(h['Exact burn script']).toMatch(/escrow 0x5e5e5e…5e5e5e[\s\S]*uses chain 11155111 and asset /);
    expect(h['Exact burn script']).toContain(`and asset ${ASSET_SHORT}`);
    expect(h['prove-claim']).toMatch(/BRIDGE_INSTANCE=instances\/fixture-instance just status/);
    expect(h['This site and its data sources']).toMatch(/your wallet's RPC[\s\S]*Blockstream's public API[\s\S]*Instance: fixture-instance/);
    // The fixture is served from this computer, not from the published site.
    expect(h['This site and its data sources']).toMatch(/Unofficial copy; its listed stores do not count as published here\./);

    const hrefs = [...page.querySelectorAll('a')].map((a) => a.getAttribute('href'));
    expect(hrefs).toContain(`https://sepolia.etherscan.io/address/${ESCROW}`);
    expect(hrefs).toContain(`https://blockstream.info/liquidtestnet/tx/${BOOTSTRAP_TXID}`);
    for (const file of ['instance.json', 'manifest.json', 'lc_preimages.json']) expect(hrefs).toContain(`instances/fixture-instance/${file}`);
  });

  it('says which step now reopens deposits', async () => {
    let h = here(await readTrust('fork-closed'));
    expect(h['fork-proof']).toMatch(/has no fork check\. A fork proof now reopens deposits\./);
    expect(h['Keeping deposits open']).toMatch(/Deposits are closed/);
    cleanup();
    h = here(await readTrust('relay-closed'));
    expect(h.relay).toMatch(/Relaying now reopens deposits\./);
  });

  it('shows none of a refused escrow\'s settings and no asset, only its pins', async () => {
    const page = renderTrust('bad-code');
    await waitFor(() => expect(page.textContent).toMatch(/so this page shows none of its settings/));
    const h = here(page);
    for (const name of ['relay', 'fork-proof', 'redeem', 'Ethereum forks', 'Keeping deposits open']) {
      expect(h[name], name).toMatch(/The escrow is not usable: its code hash is not the instances\/fixture-instance\/ record's \w+…\w+, so this page shows none of its settings\./);
    }
    expect(h.burn).toMatch(/Burns are disabled until[\s\S]*Burn nothing until verification passes\./);
    expect(h['Fixed, unaudited code']).toMatch(/Rejected:/);
    expect(h['Bootstrap verification']).toMatch(/Not checked: escrow rejected/);
    expect(page.textContent).not.toMatch(/requires \d+ Liquid confirmations|epochs of \d|closes deposits at|Burn asset|and asset/);
    expect(page.textContent).not.toMatch(ASSET_PREFIX);
    expect(page.innerHTML).toContain(`https://sepolia.etherscan.io/address/${ESCROW}`);
  });

  it('before the escrow is read, says how to read it and states no setting', async () => {
    const page = renderTrust('disconnected');
    const h = here(page);
    expect(h.redeem).toMatch(/Connect a wallet on Sepolia, or set a Sepolia RPC in Settings/);
    expect(h['Bootstrap verification']).toMatch(/Waiting to read the escrow/);
    expect(h['Fixed, unaudited code']).toMatch(/Not checked yet\./);
    expect(page.textContent).not.toMatch(/requires \d+ Liquid confirmations|closes deposits at|Burn asset/);
    expect(page.textContent).not.toMatch(ASSET_PREFIX);
  });

  it('names the Settings sources by host, never repeating a URL that may hold a key', () => {
    const page = renderTrust('connected', (f) => f.storage.set(SETTINGS_KEY, JSON.stringify({
      esplora: 'https://esplora.example/api?key=ESPLORA_SECRET', ethRpc: 'https://rpc.example/v2/RPC_SECRET',
    })));
    expect(here(page).sources).toBe('On this instance Sepolia: your custom RPC. Liquid: the Esplora API at esplora.example.');
    expect(page.querySelector('.trust')?.textContent).not.toMatch(/SECRET/);
  });
});
