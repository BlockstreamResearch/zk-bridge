// The controller against the fixture: a stand-in escrow with the real public Liquid bootstrap and header behind it.
// These check which escrow is read and paid, when deposits
// and burns are allowed, and that Settings never repeats a key-bearing RPC URL.
import { burnTarget, depositCalldata, depositRecipient } from '@bridge/ui/lib/bridge.js';
import { bytesToHex } from '@bridge/ui/lib/bytes.js';
import { selector } from '@bridge/ui/lib/hash.js';
import { describe, expect, it, vi } from 'vitest';
import {
  ACCOUNT, ACCOUNT_CHECKSUMMED, ASSET_DISPLAY, DEPOSIT_ADDRESS, ESCROW, LIQUID_TIP, abiBytes, fixture, type Fixture, type Scenario,
} from '../dev/fixture';
import { BridgeController } from './controller';
import * as derive from './derive';
import type { Eip1193 } from './types';

async function started(scenario: Scenario = 'connected', tweak?: (f: Fixture) => void) {
  const f = fixture(scenario);
  tweak?.(f);
  const c = new BridgeController(f.instance, f.env);
  c.start();
  await c.restored;
  c.stop();
  return { c, f, s: () => c.getSnapshot() };
}

const methods = (f: Fixture) => f.calls.map((x) => x.method);

describe('reading the published instance', () => {
  it('reads the escrow once its code hash is the record\'s, and verifies the real bootstrap issues its asset', async () => {
    const { s } = await started();
    expect(s().bridge?.assetDisplay).toBe(ASSET_DISPLAY);
    expect(s().bootstrap?.ok).toBe(true);
    expect(s().bootstrap?.checks.every((ch) => ch.ok)).toBe(true);
    expect(s().liquid?.tip).toBe(LIQUID_TIP);
    expect(derive.admission(s())?.deposit).toBe(true);
    expect(derive.notice(s())).toBe('');
    expect(derive.burnable(s())).toBe(true);
  });

  it('reads no view of an escrow whose code is not the record\'s, and says so', async () => {
    const { f, s } = await started('bad-code');
    expect(s().bridge).toBeNull();
    expect(s().bridgeError).toMatch(/code hash is not the instances\/fixture-instance\/ record's/);
    expect(methods(f)).not.toContain('eth_call');
    expect(derive.notice(s())).toMatch(/Do not send it anything/);
  });

  it('with no published instance, reads no escrow at all', async () => {
    const { f, s } = await started('no-instance');
    expect(methods(f)).not.toContain('eth_getCode');
    expect(methods(f)).not.toContain('eth_call');
    expect(derive.notice(s())).toMatch(/No instance of this bridge is published yet/);
    expect(derive.checkRows(s())).toEqual([{ ok: null, text: 'No bridge instance is published yet.' }]);
  });

  it('does not read through a disconnected wallet, and asks to connect', async () => {
    const { f, s } = await started('disconnected');
    expect(methods(f)).not.toContain('eth_call');
    expect(derive.notReady(s())).toBe('Connect a wallet to continue.');
  });

  it('holds burns back, without calling the escrow wrong, while the Liquid API is down', async () => {
    const { s } = await started('liquid-down');
    expect(s().bridge).not.toBeNull();
    expect(s().bootstrap?.unavailable).toBe(true);
    expect(derive.notBurnable(s())).toMatch(/did not serve the bridge's bootstrap/);
    expect(derive.notice(s())).toMatch(/Liquid testnet data is unavailable/);
  });

  it('explains which admission rule closes deposits, and which action reopens them', async () => {
    const relay = await started('relay-closed');
    expect(derive.admission(relay.s())).toMatchObject({ deposit: false, relayReopens: true, forkReopens: false });
    const fork = await started('fork-closed');
    expect(derive.admission(fork.s())).toMatchObject({ deposit: false, relayReopens: false, forkReopens: true });
  });
});

describe('deposits', () => {
  it('simulates, then asks the wallet to send to the published escrow with the recipient\'s script', async () => {
    const { c, f, s } = await started();
    await c.sendDeposit({ recipient: DEPOSIT_ADDRESS, amount: '0.0025' });
    const send = f.calls.find((x) => x.method === 'eth_sendTransaction');
    const tx = send?.params[0] as { to: string; data: string; value: string };
    expect(tx.to).toBe(ESCROW);
    expect(tx.data).toBe(depositCalldata(depositRecipient(DEPOSIT_ADDRESS).script));
    expect(BigInt(tx.value)).toBe(2_500_000_000_000_000n);
    const simulated = f.calls.findIndex((x) => x.method === 'eth_call' && (x.params[0] as { data: string }).data === tx.data);
    expect(simulated).toBeGreaterThanOrEqual(0);
    expect(simulated).toBeLessThan(f.calls.indexOf(send!));
    // The fixture wallet declines; nothing is saved as sent.
    expect(s().toast?.text).toBe('You declined the request in your wallet. Nothing was sent.');
    expect(s().journeys).toHaveLength(0);
  });

  it('asks the wallet nothing while deposits are closed', async () => {
    const { c, f } = await started('relay-closed');
    expect(await c.sendDeposit({ recipient: DEPOSIT_ADDRESS, amount: '0.0025' })).toBe(false);
    expect(methods(f)).not.toContain('eth_sendTransaction');
  });
});

describe('the burn script', () => {
  const burnSel = selector('burnScriptPubKey(address)');

  it('is the page\'s own bare OP_RETURN for a checksummed recipient, confirmed by the escrow', async () => {
    const { c, s } = await started();
    c.setRedeemForm({ recipient: ACCOUNT_CHECKSUMMED, amount: '0.001' });
    await vi.waitFor(() => expect(derive.target(s())).not.toBeNull());
    const t = derive.target(s())!;
    expect(bytesToHex(t.burn.scriptPubKey)).toBe(bytesToHex(burnTarget(11155111n, ESCROW, ACCOUNT).scriptPubKey));
    expect(bytesToHex(t.burn.scriptPubKey).startsWith('6a46')).toBe(true);
    expect(t.units).toBe(100_000n);
    // The amount is read from the form when used: an edit cannot leave a stale amount behind.
    c.setRedeemForm({ amount: '0.002' });
    expect(derive.target(s())!.units).toBe(200_000n);
  });

  it('is not shown when the escrow answers another script', async () => {
    const { c, s } = await started('connected', (f) => {
      const inner = f.env.ethereum()!;
      const lying: Eip1193 = {
        request: async (a) => {
          const p = a.params?.[0] as { data?: string } | undefined;
          if (a.method === 'eth_call' && p?.data?.startsWith(burnSel)) return abiBytes(burnTarget(11155111n, '0x' + '6f'.repeat(20), ACCOUNT).scriptPubKey);
          return inner.request(a);
        },
      };
      f.env.ethereum = () => lying;
    });
    c.setRedeemForm({ recipient: ACCOUNT_CHECKSUMMED, amount: '0.001' });
    await vi.waitFor(() => expect(s().targetError).toBeTruthy());
    expect(derive.target(s())).toBeNull();
  });

  it('is not shown while the bootstrap is unconfirmed', async () => {
    const { c, s } = await started('liquid-down');
    c.setRedeemForm({ recipient: ACCOUNT_CHECKSUMMED, amount: '0.001' });
    await Promise.resolve();
    expect(derive.target(s())).toBeNull();
  });
});

describe('Settings', () => {
  const KEY_URL = 'https://rpc.example/v2/SECRETKEY1234567890';

  /** A JSON-RPC endpoint at KEY_URL answering `chainId`, and forwarding other reads to a fixture wallet. */
  function rpcAt(f: Fixture, chainId: string, backend: Eip1193, seen: string[]) {
    const base = f.env.fetch;
    f.env.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) !== KEY_URL) return base(input, init);
      const { id, method, params } = JSON.parse(String(init?.body));
      seen.push(method);
      const result = method === 'eth_chainId' ? chainId : await backend.request({ method, params });
      return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }));
    }) as typeof fetch;
  }

  it('refuses an RPC of another chain without repeating its URL, and keeps reading through the wallet', async () => {
    const seen: string[] = [];
    const { c, f } = await started('connected', (f) => rpcAt(f, '0x1', fixture().env.ethereum()!, seen));
    const errors = await c.saveSettings({ esplora: '', ethRpc: KEY_URL });
    expect(errors?.ethRpc).toMatch(/not Sepolia/);
    expect(JSON.stringify(errors)).not.toContain('SECRETKEY');
    expect(f.storage.has('liquid-bridge-poc.settings')).toBe(false);
  });

  it('refuses plain http off this computer', async () => {
    const { c } = await started();
    expect((await c.saveSettings({ esplora: '', ethRpc: 'http://rpc.example/x' }))?.ethRpc).toMatch(/https/);
  });

  it('once saved, sends every read to the RPC and none to the wallet', async () => {
    const seen: string[] = [];
    const { c, f, s } = await started('connected', (f) => rpcAt(f, '0xaa36a7', fixture().env.ethereum()!, seen));
    const before = f.calls.length;
    expect(await c.saveSettings({ esplora: '', ethRpc: KEY_URL })).toBeNull();
    expect(seen).toContain('eth_getCode');
    expect(seen).toContain('eth_call');
    expect(f.calls.slice(before).map((x) => x.method)).toEqual([]);
    expect(s().bridge).not.toBeNull();
    expect(s().settings.ethRpc).toBe(KEY_URL);
  });
});

describe('journeys', () => {
  it('shows only activity belonging to the published escrow', async () => {
    const { s } = await started('activity', (f) => {
      const list = JSON.parse(f.storage.get('liquid-bridge-poc.journeys')!) as object[];
      f.storage.set('liquid-bridge-poc.journeys', JSON.stringify([
        ...list,
        { ...list[0], escrow: '0x' + 'aa'.repeat(20), id: 'another-escrow' },
      ]));
    });
    expect(s().journeys).toHaveLength(4);
  });

  it('resumes saved journeys and keeps a burn waiting for relaying in that state', async () => {
    const { s } = await started('activity');
    expect(s().journeys).toHaveLength(4);
    const burn = s().journeys.find((j) => j.kind === 'redeem')!;
    expect(burn.status).toBe('relay');
    expect(burn.lastError).toBeUndefined();
  });

  it('fills step 2\'s Humid address from the latest P2WPKH deposit in this browser', async () => {
    const { s } = await started('activity');
    expect(s().redeemForm.humidAddress).toBe(DEPOSIT_ADDRESS);
  });

  it('removes an entry only after confirmation, and only from the list', async () => {
    const { c, f, s } = await started('activity');
    f.env.confirm = () => false;
    c.removeJourney(s().journeys[0].id);
    expect(s().journeys).toHaveLength(4);
    f.env.confirm = () => true;
    c.removeJourney(s().journeys[0].id);
    expect(s().journeys).toHaveLength(3);
    expect(JSON.parse(f.storage.get('liquid-bridge-poc.journeys')!)).toHaveLength(3);
  });
});

describe('updates and claims built locally', () => {
  it('refuses an update when this site does not serve its instance manifest', async () => {
    const { c, s } = await started();
    await c.loadFile('liquidUpdate', { size: 4, text: async () => 'abcd' });
    expect(s().liquidUpdate.fileError).toMatch(/manifest\.json: HTTP 404/);
    expect(s().liquidUpdate.plan).toBeNull();
  });

  it('refuses a claim file that is not hex, or too large', async () => {
    const { c, s } = await started();
    await c.loadFile('liquidClaim', { size: 3, text: async () => 'xyz' });
    expect(s().liquidClaim.fileError).toMatch(/not hex/);
    await c.loadFile('liquidClaim', { size: 2_000_000, text: async () => '' });
    expect(s().liquidClaim.fileError).toMatch(/too large to be a claim/);
  });
});

describe('the wallet account', () => {
  it('is read in lower case', async () => {
    const { s } = await started();
    expect(s().account).toBe(ACCOUNT);
  });
});
