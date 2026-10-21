// Humid's answers are never taken as proof that anything is on Liquid. These drive the controller and the panels
// through the real lib/claim.js sendClaim, lib/update.js sendUpdate, lib/humid.js signAndBroadcast and
// lib/claim.js claimOnLiquid, against a mock Humid and a mock Liquid API. Only what needs a real proof or real coins
// is replaced: prepareClaim and prepareUpdate (the plan a file gives), and burnWithHumid and broadcastMatches (the
// burn Humid makes). The claim and update stand-in is the real public bootstrap transaction, so the Liquid API's copy
// of it hashes to its txid as a real send's would.
import { prepareClaim, type ClaimPlan } from '@bridge/core/lib/claim.js';
import { type Humid, broadcastMatches, burnWithHumid } from '@bridge/core/lib/humid.js';
import { prepareUpdate, type UpdatePlan } from '@bridge/core/lib/update.js';
import { bigToBytes, bytesToHex, concat, hexToBytes, utf8 } from '@bridge/core/lib/bytes.js';
import { sha256 } from '@bridge/core/lib/hash.js';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../app/App';
import { sentReport } from '../components/LiquidSendPanels';
import { ACCOUNT_CHECKSUMMED, BOOTSTRAP_TXID, DEPOSIT_ADDRESS, ESPLORA, type Fixture, fixture } from '../dev/fixture';
import { BridgeProvider } from './context';
import { BridgeController } from './controller';
import * as derive from './derive';

vi.mock('@bridge/core/lib/claim.js', async (importOriginal) => ({ ...(await importOriginal<object>()), prepareClaim: vi.fn() }));
vi.mock('@bridge/core/lib/update.js', async (importOriginal) => ({ ...(await importOriginal<object>()), prepareUpdate: vi.fn() }));
vi.mock('@bridge/core/lib/humid.js', async (importOriginal) => ({ ...(await importOriginal<object>()), burnWithHumid: vi.fn(), broadcastMatches: vi.fn() }));

const SCOPE = 'bip122:a771da8e52ee6ad581ed1e9a99825e5b'; // lib/humid.js HUMID_SCOPE, Liquid testnet
const TXID = BOOTSTRAP_TXID;
const OTHER_TXID = 'cd'.repeat(32);
const STATE_TX = 'aa'.repeat(32);
const FEE_TX = 'bb'.repeat(32);
let TX_HEX = '';
let OTHER_HEX = ''; // a readable transaction with another txid

// Each test sets the mocks' answers; their calls and answers must not carry over.
beforeEach(() => vi.resetAllMocks());

beforeAll(async () => {
  TX_HEX = await (await fixture().env.fetch(`${ESPLORA}/tx/${TXID}/hex`)).text();
  // The same transaction with locktime 1: still readable, another txid.
  OTHER_HEX = TX_HEX.slice(0, -8) + '01000000';
});

type Has = 'none' | 'mempool' | 'confirmed' | 'other' | 'garbage' | 'down';

/**
 * A Liquid API that holds the state and fee coins (confirmed, unspent), as lib/claim.js and update.js require before
 * Humid is asked, and that has the sent transaction as `has` says: not at all, in the mempool, confirmed in block
 * 2,664,001, or answering its txid with another transaction, unreadable bytes or HTTP 503.
 */
function liquidApi(f: Fixture) {
  const liquid = { has: 'none' as Has, hexReads: 0 };
  const json = (v: unknown) => new Response(JSON.stringify(v));
  const notFound = () => new Response('not found', { status: 404 });
  f.env.fetch = (async (input: RequestInfo | URL) => {
    const path = String(input).slice(ESPLORA.length);
    if (path === `/tx/${TXID}/hex`) {
      liquid.hexReads += 1;
      const answers: Partial<Record<Has, () => Response>> = {
        none: notFound, down: () => new Response('busy', { status: 503 }), other: () => new Response(OTHER_HEX), garbage: () => new Response('zz'),
      };
      return (answers[liquid.has] ?? (() => new Response(TX_HEX)))();
    }
    // Esplora answers {confirmed: false} for a txid it has never seen.
    if (path === `/tx/${TXID}/status`) return json(liquid.has === 'confirmed' ? { confirmed: true, block_height: 2_664_001 } : { confirmed: false });
    if ([STATE_TX, FEE_TX].some((t) => path === `/tx/${t}/status`)) return json({ confirmed: true, block_height: 1 });
    if ([STATE_TX, FEE_TX].some((t) => path.startsWith(`/tx/${t}/outspend/`))) return json({ spent: false });
    return notFound();
  }) as typeof fetch;
  f.env.liquidLagMs = 0;
  return liquid;
}

/** A Humid that holds a session and answers each signing request with `answer`. */
function mockHumid(answer: () => Promise<unknown>) {
  const asked = { sign: 0 };
  const humid: Humid = {
    request: async ({ method }) => {
      if (method === 'wallet_getSession') return { sessionScopes: { [SCOPE]: { methods: ['getUTXOs', 'signPset'] } } };
      if (method === 'wallet_invokeMethod') {
        asked.sign += 1;
        return answer();
      }
      throw new Error(`unexpected Humid request ${method}`);
    },
  };
  return { humid, asked };
}

const outpoints = { state: { txid: STATE_TX, vout: 0 }, fee: { txid: FEE_TX, vout: 1, sats: 2000n } };
const signing = { pset: 'cHNldP8A', signInputs: [{ address: DEPOSIT_ADDRESS, index: 1, sighashTypes: [1] }], feeAddress: DEPOSIT_ADDRESS, successorAddress: DEPOSIT_ADDRESS };
const claimPlan = {
  txid: TXID, ...signing,
  claim: { txid: TXID, ...outpoints, successor: { script: new Uint8Array(34) },
    mint: { script: hexToBytes('0014' + '11'.repeat(20)), units: 250_000n, asset: new Uint8Array(32), address: DEPOSIT_ADDRESS } },
} as unknown as ClaimPlan;
/**
 * A light-client store file at `head`, as sg16-bridge-host writes it: made-up roots, their lc
 * (SHA256(SHA256('liquid-bridge-poc/lc') || be64(head) || header || committee), lib/update.js lcOf), a made-up store.
 */
function storeAt(head: number, label: string) {
  const header = label.repeat(32);
  const committee = `${label[1]}${label[0]}`.repeat(32);
  const lc = bytesToHex(sha256(concat(sha256(utf8('liquid-bridge-poc/lc')), bigToBytes(BigInt(head), 8), hexToBytes(header), hexToBytes(committee))));
  return { head, header, committee, lc, store_cbor: '0xa0' };
}
const STORE = storeAt(9_000_000, 'a1');
const updatePlan = {
  txid: TXID, ...signing, successor: { head: STORE.head, lc: STORE.lc }, listed: 'lc_stores/9000000.json',
  store: { where: 'site', path: 'lc_stores/9000000.json' },
  update: { txid: TXID, ...outpoints, successor: { script: new Uint8Array(34) } },
} as unknown as UpdatePlan;

/** A controller with `kind`'s file loaded (its plan given), a mock Liquid API and a Humid answering `answer`. */
async function loaded(kind: 'liquidClaim' | 'liquidUpdate', answer: (liquid: { has: Has }) => Promise<unknown>, update = updatePlan) {
  const f = fixture('connected');
  const liquid = liquidApi(f);
  const { humid, asked } = mockHumid(() => answer(liquid));
  f.env.humidWindow = () => ({ humid });
  // lib/update.js reads the record only on an https page.
  f.env.siteHref = () => 'https://bridge.example/';
  vi.mocked(prepareClaim).mockResolvedValue(claimPlan);
  vi.mocked(prepareUpdate).mockResolvedValue(update);
  const c = new BridgeController(f.instance, f.env);
  await c.loadFile(kind, { size: 4, text: async () => 'abcd' });
  expect(c.getSnapshot()[kind].plan).not.toBeNull();
  return { c, f, liquid, asked, s: () => c.getSnapshot()[kind] };
}

/** Humid broadcasting: the Liquid API then has the transaction as `has` says, and Humid answers its txid. */
const broadcasts = (has: Has, txid = TXID) => async (liquid: { has: Has }) => {
  liquid.has = has;
  return { txid };
};

const failure = (reason: string, message = 'Humid failed') => Object.assign(new Error(message), { data: { reason } });

describe('a claim sent with Humid', () => {
  it('is reported confirmed only from the Liquid API, and is never sent twice', async () => {
    const { c, s, asked } = await loaded('liquidClaim', broadcasts('confirmed'));
    await c.sendFile('liquidClaim');
    expect(s().sent).toMatchObject({ txid: TXID, where: 'confirmed', height: 2_664_001, said: null });
    expect(s().error).toBe('');
    expect(c.getSnapshot().toast?.text).toBe('The claim is confirmed on Liquid.');
    await c.sendFile('liquidClaim');
    expect(asked.sign).toBe(1);
  });

  it('is not counted as sent when Humid reports it but the Liquid API never shows it; check again asks only Liquid', async () => {
    const { c, s, liquid, asked } = await loaded('liquidClaim', async () => ({ txid: TXID }));
    const before = liquid.hexReads;
    await c.sendFile('liquidClaim');
    // Once before Humid is asked (sendClaim checks the claim is unsent), then ten times, as the API can lag a broadcast.
    expect(liquid.hexReads - before).toBe(11);
    expect(s().sent).toMatchObject({ where: 'unknown', why: 'the Liquid API does not show it', said: null });
    expect(sentReport('claim', s().sent!)).toMatch(/^Humid reports sending claim .*, but the Liquid API does not show it.*Do not count it as claimed until it shows/);
    expect(c.getSnapshot().toast).toBeNull();
    // Held: a second click asks the Liquid API once more, never Humid.
    await c.sendFile('liquidClaim');
    expect(asked.sign).toBe(1);
    expect(liquid.hexReads - before).toBe(12);
    liquid.has = 'confirmed';
    await c.sendFile('liquidClaim');
    expect(s().sent).toMatchObject({ where: 'confirmed', said: null });
    expect(asked.sign).toBe(1);
  });

  it('tells the mempool from confirmation, and keeps checking until confirmed', async () => {
    const { c, s, liquid, asked } = await loaded('liquidClaim', broadcasts('mempool'));
    await c.sendFile('liquidClaim');
    expect(s().sent).toMatchObject({ where: 'mempool' });
    expect(c.getSnapshot().toast?.text).toBe('The Liquid API has the claim.');
    liquid.has = 'confirmed';
    await c.sendFile('liquidClaim');
    expect(s().sent).toMatchObject({ where: 'confirmed' });
    expect(asked.sign).toBe(1);
  });

  it.each([
    ['answers with no transaction id', async () => ({}), /Humid returned no transaction id/],
    ['answers with a malformed transaction id', async () => ({ txid: 'not-a-txid' }), /Humid returned no transaction id/],
    ['answers with another transaction id', async () => ({ txid: OTHER_TXID }), new RegExp(`Humid reports sending ${OTHER_TXID}, which is not this claim`)],
    ['fails after you may have confirmed', async () => { throw failure('wallet_pset_broadcast_failed'); }, /Humid did not confirm sending the claim/],
  ])('is held, not offered again, when Humid %s', async (_case, answer, said) => {
    const { c, s, asked } = await loaded('liquidClaim', answer);
    await c.sendFile('liquidClaim');
    expect(s().sent).toMatchObject({ where: 'unknown', said: expect.stringMatching(said) });
    expect(sentReport('claim', s().sent!)).toMatch(new RegExp(`Explorer: .*/tx/${TXID}$`));
    await c.sendFile('liquidClaim');
    expect(asked.sign).toBe(1);
  });

  it('is shown as sent when Humid gave no clear answer but the Liquid API has it', async () => {
    const { c, s } = await loaded('liquidClaim', async (liquid) => {
      liquid.has = 'mempool';
      throw failure('wallet_pset_broadcast_failed');
    });
    await c.sendFile('liquidClaim');
    expect(s().sent).toMatchObject({ where: 'mempool', said: expect.stringMatching(/did not confirm/) });
    expect(sentReport('claim', s().sent!)).toBe('Humid did not report sending this claim, but the Liquid API has it, so it was sent: see below.');
  });

  it.each([
    ['answers its txid with another transaction', 'other', 'the Liquid API serves another transaction for its txid'],
    ['answers its txid with unreadable bytes', 'garbage', 'the Liquid API serves another transaction for its txid'],
    ['cannot be read', 'down', 'the Liquid API could not be read'],
  ] as const)('is not counted as sent when the Liquid API %s', async (_case, has, why) => {
    const { c, s } = await loaded('liquidClaim', broadcasts(has));
    await c.sendFile('liquidClaim');
    expect(s().sent?.where).toBe('unknown');
    expect(s().sent).toMatchObject({ why: expect.stringContaining(why) });
  });

  it('may be tried again when Humid shows nothing was sent', async () => {
    const { c, s, asked } = await loaded('liquidClaim', async () => { throw failure('user_rejected'); });
    await c.sendFile('liquidClaim');
    expect(s().sent).toBeNull();
    expect(s().error).toMatch(/you declined, or its prompt closed itself/);
    await c.sendFile('liquidClaim');
    expect(asked.sign).toBe(2);
  });

  it('asks Humid once however fast the button is clicked', async () => {
    const { c, asked } = await loaded('liquidClaim', broadcasts('confirmed'));
    await Promise.all([c.sendFile('liquidClaim'), c.sendFile('liquidClaim'), c.sendFile('liquidClaim')]);
    expect(asked.sign).toBe(1);
  });
});

describe('an update sent with Humid', () => {
  it('is not counted as sent from Humid\'s answer alone', async () => {
    const { c, s, asked } = await loaded('liquidUpdate', async () => ({ txid: TXID }));
    await c.sendFile('liquidUpdate');
    expect(s().sent).toMatchObject({ where: 'unknown', said: null });
    expect(sentReport('update', s().sent!)).toMatch(/Do not count it as sent until it shows. If it never does, load update.hex again/);
    await c.sendFile('liquidUpdate');
    expect(asked.sign).toBe(1);
  });

  it('is reported confirmed once the Liquid API has it confirmed', async () => {
    const { c, s } = await loaded('liquidUpdate', broadcasts('confirmed'));
    await c.sendFile('liquidUpdate');
    expect(s().sent).toMatchObject({ where: 'confirmed', said: null });
    expect(c.getSnapshot().toast?.text).toBe('The update is confirmed on Liquid.');
  });

  it('is held when Humid reports another transaction', async () => {
    const { c, s, asked } = await loaded('liquidUpdate', broadcasts('none', OTHER_TXID));
    await c.sendFile('liquidUpdate');
    expect(s().sent).toMatchObject({ where: 'unknown', said: expect.stringMatching(/Humid did not confirm sending the update/) });
    await c.sendFile('liquidUpdate');
    expect(asked.sign).toBe(1);
  });
});

describe('the claim panel', () => {
  async function panel(answer: (liquid: { has: Has }) => Promise<unknown>) {
    const ctx = await loaded('liquidClaim', answer);
    const user = userEvent.setup();
    render(<BridgeProvider controller={ctx.c}><App /></BridgeProvider>);
    const claim = within(document.getElementById('claim')!);
    return { ...ctx, user, claim };
  }

  it('turns into a check on Liquid once Humid has answered, and says sent only when Liquid has it', async () => {
    const { user, claim, liquid, asked } = await panel(async () => ({ txid: TXID }));
    await user.click(claim.getByRole('button', { name: 'Sign and send with Humid', hidden: true }));
    const check = await claim.findByRole('button', { name: 'Check on Liquid again', hidden: true });
    expect(claim.getByText(/Do not count it as claimed until it shows/)).toBeInTheDocument();
    expect(claim.getByText(/Not on Liquid, as far as its API shows: check again in a minute\. Last checked/)).toBeInTheDocument();
    expect(claim.queryByText(/is confirmed on Liquid|The Liquid API has claim/)).toBeNull();
    expect(claim.queryByText(/In Humid's approval/)).toBeNull();
    liquid.has = 'confirmed';
    await user.click(check);
    expect(await claim.findByText(/is confirmed on Liquid in block 2,664,001, as the Liquid API reports/)).toBeInTheDocument();
    expect(claim.getByRole('button', { name: 'Sign and send with Humid', hidden: true })).toBeDisabled();
    expect(asked.sign).toBe(1);
  });
});

describe('the update panel', () => {
  async function opened(update: UpdatePlan) {
    const ctx = await loaded('liquidUpdate', broadcasts('confirmed'), update);
    const user = userEvent.setup();
    render(<BridgeProvider controller={ctx.c}><App /></BridgeProvider>);
    const tray = within(document.getElementById('update')!);
    const send = () => tray.getByRole('button', { name: 'Sign and send with Humid', hidden: true });
    const fact = () => tray.getByRole('row', { name: /^Store/, hidden: true });
    const updateState = () => ctx.c.getSnapshot().liquidUpdate;
    return { ...ctx, user, tray, send, fact, updateState };
  }

  const json = (name: string, text: string) => {
    const file = new File([text], name, { type: 'application/json' });
    // JSDOM's File lacks the browser's text() method.
    Object.defineProperty(file, 'text', { value: async () => text });
    return file;
  };

  it('sends an update whose store this site does not publish only once the sender loads that store', async () => {
    const { user, tray, send, fact, asked, updateState } = await opened({ ...updatePlan, listed: null, store: null });
    expect(fact()).toHaveTextContent('none yet: this site does not publish it. Load the file below');
    expect(send()).toBeDisabled();
    expect(tray.getByText(/^Load the store this update moves to first/)).toBeInTheDocument();
    const store = tray.getByLabelText(/The store this update moves to/);

    await user.upload(store, json('proof.store.json', 'not json'));
    expect(await tray.findByText('Not this update\'s store: proof.store.json is not a store file.')).toBeInTheDocument();
    expect(send()).toBeDisabled();

    await user.upload(store, json('proof.store.json', JSON.stringify(storeAt(9_000_064, 'b2'))));
    expect(await tray.findByText(/proof\.store\.json is the store at slot 9,000,064 .*, not the one at slot 9,000,000/)).toBeInTheDocument();
    expect(updateState().plan?.store).toBeNull();
    expect(send()).toBeDisabled();

    await user.upload(store, json('proof.store.json', JSON.stringify(STORE)));
    await waitFor(() => expect(fact()).toHaveTextContent('from your file proof.store.json, which hashes to the lc in the update\'s witness'));
    expect(tray.queryByText(/Not this update's store/)).toBeNull();
    expect(updateState().plan?.store).toMatchObject({ where: 'file', entry: { head: STORE.head, update: TXID, store: 'lc_stores/9000000.json' } });
    expect(send()).toBeEnabled();
    await user.click(send());
    expect(await tray.findByText(/is confirmed on Liquid in block 2,664,001/)).toBeInTheDocument();
    expect(asked.sign).toBe(1);
  });

  it('asks for no file when this site publishes the store', async () => {
    const { tray, send, fact } = await opened(updatePlan);
    expect(fact()).toHaveTextContent('published on this site, lc_stores/9000000.json');
    expect(tray.queryByLabelText(/The store this update moves to/)).toBeNull();
    expect(send()).toBeEnabled();
  });

  it('does not count a store this page\'s record lists when the page is not the published site', async () => {
    const { send, fact } = await opened({ ...updatePlan, store: null });
    expect(fact()).toHaveTextContent('this page\'s record lists lc_stores/9000000.json, but only the published site\'s record counts');
    expect(send()).toBeDisabled();
  });
});

describe('a burn sent with Humid', () => {
  /** A connected page with step 1 and Humid's address filled in, and Humid present. */
  async function ready() {
    const f = fixture('connected');
    f.env.humidWindow = () => ({ humid: { request: vi.fn() } });
    const c = new BridgeController(f.instance, f.env);
    c.start();
    await c.restored;
    c.stop();
    c.setRedeemForm({ recipient: ACCOUNT_CHECKSUMMED, amount: '0.001', humidAddress: DEPOSIT_ADDRESS });
    await vi.waitFor(() => expect(derive.target(c.getSnapshot())).not.toBeNull());
    return { c, f, s: () => c.getSnapshot().humid };
  }

  /** Humid sends `txid`, after being asked to sign the coins `spends`. */
  const sends = (txid: string, spends = ['c1:1']) => vi.mocked(burnWithHumid).mockImplementation(async ({ onSign }) => {
    onSign?.(spends);
    return { txid, plan: { spends } };
  });

  it('is tracked when the Liquid API\'s copy is the burn this page built', async () => {
    const { c, s } = await ready();
    sends(TXID);
    vi.mocked(broadcastMatches).mockReturnValue(null);
    await c.sendWithHumid();
    expect(s().held).toBeNull();
    expect(s().note).toMatch(/the burn this page built\. Step 3 below tracks it/);
    expect(c.getSnapshot().redeemForm.txid).toBe(TXID);
  });

  it.each([
    ['is not the burn this page built', TXID, 'output 0 pays another script', /does not count it as a burn/],
    ['is not shown by the Liquid API', OTHER_TXID, null, /the Liquid API does not show it yet, so this page cannot check/],
  ])('is held when the send %s, and Humid is asked for no other burn', async (_case, txid, mismatch, error) => {
    const { c, s } = await ready();
    sends(txid);
    vi.mocked(broadcastMatches).mockReturnValue(mismatch);
    await c.sendWithHumid();
    expect(s().held).toBe(txid);
    expect(s().error).toMatch(error);
    expect(s().error).toContain(`/tx/${txid}`);
    await c.sendWithHumid();
    expect(burnWithHumid).toHaveBeenCalledTimes(1);
  });

  it('is held when the Liquid API answers the txid with another transaction', async () => {
    const { c, s } = await ready();
    const esplora = (c as unknown as { esplora: { txHex(txid: string): Promise<string> } }).esplora;
    const original = esplora.txHex.bind(esplora);
    // The Liquid API answers the reported txid with the bootstrap's bytes, which hash to another txid.
    vi.spyOn(esplora, 'txHex').mockImplementation((txid) => txid === OTHER_TXID ? Promise.resolve(TX_HEX) : original(txid));
    sends(OTHER_TXID);
    await c.sendWithHumid();
    expect(s().held).toBe(OTHER_TXID);
    expect(s().error).toMatch(/serves another transaction for its txid/);
  });

  it('keeps coins Humid may have spent out of the next burn, and frees them when nothing was sent', async () => {
    const { c, s } = await ready();
    const skipped: string[][] = [];
    vi.mocked(burnWithHumid).mockImplementation(async ({ onSign, skip }) => {
      skipped.push([...(skip ?? [])]);
      onSign?.(['c1:1']);
      throw Object.assign(new Error('no answer'), { sent: skipped.length === 1 ? 'maybe' : 'no' });
    });
    await c.sendWithHumid();
    expect(s().error).toMatch(/It may have been sent all the same[\s\S]*Explorer: .*\/address\//);
    await c.sendWithHumid();
    await c.sendWithHumid();
    expect(skipped).toEqual([[], ['c1:1'], []]);
  });

  it('disables Send with Humid while held, and says why', async () => {
    const { c } = await ready();
    sends(TXID);
    vi.mocked(broadcastMatches).mockReturnValue('output 0 pays another script');
    await c.sendWithHumid();
    const user = userEvent.setup();
    render(<BridgeProvider controller={c}><App /></BridgeProvider>);
    await user.click(screen.getByRole('tab', { name: /Redeem/ }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Send with Humid' })).toBeDisabled());
    expect(screen.getByText(/Not the burn this page built\. Step 2 asks Humid for no other burn/)).toBeInTheDocument();
  });
});
