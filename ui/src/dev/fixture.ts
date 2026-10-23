// A stand-in Sepolia wallet, escrow and Liquid API, for the tests and for `npm run dev:fixture` screenshots. It is
// imported only when Vite's mode is 'fixture' (main.tsx) or by tests, so a production build does not contain it.
//
// The escrow is fictitious: its code is two bytes and the instance's code hash is computed from them. Its Liquid side
// is real public data: the Liquid testnet bootstrap 6c9d6523…11a7 and its asset (bridge-core/test/issuance.test.js), and the
// signed epoch-start header of block 2,664,000 (bridge-core/test/elements.test.js), so the page's own bootstrap check and
// header parsing pass on them as they would live. Nothing here sends: eth_sendTransaction is always declined.
import type { RawInstance } from '@bridge/core/config.js';
import { encodeSegwit } from '@bridge/core/lib/bech32.js';
import { burnTarget, views } from '@bridge/core/lib/bridge.js';
import { bytesToHex, hexToBytes } from '@bridge/core/lib/bytes.js';
import { parseHeader, txidFromDisplay } from '@bridge/core/lib/elements.js';
import { keccak256, selector } from '@bridge/core/lib/hash.js';
import { HUMID_SCOPE, type Humid } from '@bridge/core/lib/humid.js';
import { EMPTY_CLAIMED_ROOT } from '@bridge/core/lib/update.js';
import type { BridgeEnv, Eip1193, Journey } from '../bridge/types';

export const BOOTSTRAP_TXID = '6c9d6523f33912f763bcb35103d638c3300cab840e1202cf3b0f15d0f0c811a7';
const BOOTSTRAP = '0200000000'
  + '0184e569d9750e6266b1afca811c61f1f4fe6d0588748dacb9be7083e45ac2d5cf0000008000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000001030befe50ce30ade8f45d4cd5cbe8a27af87b0e4f3c8b0f44248ed461e41d4cb85ef096173b4d8ea6a0b4e775884a3018d03ce90568c009e8e9183d8d40f2abd0b2e2300225120de4e00598a4bd7fc9173e68448147b4492d2aa3e8b5599be54e92405d95b661f01499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140100000000000182b800160014afea9b1b6c5a9bd559c12d8a40633f88055acad201499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140100000000000003e8000000000000';
export const ASSET_DISPLAY = '2e4729204ebbfd4fbd5f7a1594fc39f1e5ce35989bfbde593829e8458541f62d';
const ASSET_INTERNAL = bytesToHex(txidFromDisplay(ASSET_DISPLAY));
const STATE = encodeSegwit('tex', 1, hexToBytes('de4e00598a4bd7fc9173e68448147b4492d2aa3e8b5599be54e92405d95b661f'));

const HEADER_HASH_FORM = '000000a04054cb0dd4c42b4725aac4b85b1cb0d86738b09bc06789ade85088fc382c2e61e56e1c9fefbc09a6343654e694071b79bada50986eea3fba469f489439a4e1c3c9c1d26a40a6280002220020e9e4117540f7f23b3edd7c2cad660a17fb33c7959b8c37cf61d92b189133929a9600000017a91472c44f957fc011d97e3406667dca5b1c930c4026870151014202fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f02fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f00';
const HEADER = HEADER_HASH_FORM + '03' + '00' + '47' + '30440220' + '4b36a7485d57747c837f3d481966a896ac5ab610f9c99acce7cd1ef452d9e3db'
  + '0220' + '71d9ccd8f1598bb17f348f198168b82627da564fc1e79a7cf15d8f99cb33f8e5' + '01' + '25' + '51210217e403ddb181872c32a0cd468c710040b2f53d8cac69f18dad07985ee37e9a7151ae';
const TIP_HASH = '1a195d11b63038c91100a09efdb1489ae16e6f6f64cdc20a227015bc4ba77eb7';
export const LIQUID_TIP = 2_664_000;

export const ACCOUNT = '0x8ba1f109551bd432803012645ac136ddd64dba72';
/** The same account, EIP-55 checksummed. */
export const ACCOUNT_CHECKSUMMED = '0x8ba1f109551bD432803012645Ac136ddd64DBA72';
export const ESCROW = '0x' + '5e'.repeat(20);
const CODE = '0x6080';
export const ESPLORA = 'https://blockstream.info/liquidtestnet/api';

export const FIXTURE_INSTANCE: RawInstance = {
  name: 'fixture-instance', escrow: ESCROW, codeHash: bytesToHex(keccak256(hexToBytes(CODE))), bootstrap: BOOTSTRAP_TXID, state: STATE,
};
const SITE = 'http://localhost:5173/';
/** The fields of a manifest the state walk reads (lib/update.js liveState); the leaves and words are made up. */
const MANIFEST = {
  update_leaf: { cmr: 'aa'.repeat(32) },
  claim_leaf: { cmr: 'bb'.repeat(32) },
  constants: { nums: '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0' },
  initial_state: { head: 9_000_000, lc: '11'.repeat(32), acc: '22'.repeat(32), claimed_root: EMPTY_CLAIMED_ROOT },
};

/** A wallet address of the form a deposit names (P2WPKH), not the covenant's state address. */
export const DEPOSIT_ADDRESS = encodeSegwit('tex', 0, hexToBytes('11'.repeat(20)));
export const BURN_TXID = 'ab'.repeat(32);

export type Scenario = 'connected' | 'disconnected' | 'no-wallet' | 'no-instance' | 'relay-closed' | 'fork-closed' | 'liquid-down' | 'bad-code' | 'activity' | 'humid';
export const SCENARIOS: Scenario[] = ['connected', 'disconnected', 'no-wallet', 'no-instance', 'relay-closed', 'fork-closed', 'liquid-down', 'bad-code', 'activity', 'humid'];

/** One ABI word, and ABI-encoded `bytes`, as an escrow's eth_call answers them. */
export const word = (n: bigint | number) => '0x' + BigInt(n).toString(16).padStart(64, '0');
export const abiBytes = (b: Uint8Array) => {
  const padded = bytesToHex(b).padEnd(Math.ceil(b.length / 32) * 64, '0');
  return '0x' + word(32).slice(2) + word(b.length).slice(2) + padded;
};

export interface Fixture {
  env: BridgeEnv;
  instance: RawInstance | null;
  /** Every wallet request, in order. */
  calls: { method: string; params: unknown[] }[];
  /** Every URL fetched. */
  fetched: string[];
  storage: Map<string, string>;
}

export interface FixtureOptions {
  /** Unix ms; the default is a fixed instant, so tests and screenshots are repeatable. */
  now?: number;
  journeys?: Journey[];
}

const MINUTE = 60_000;

export function fixture(scenario: Scenario = 'connected', options: FixtureOptions = {}): Fixture {
  const now = options.now ?? Date.UTC(2026, 9, 20, 12, 0);
  const secs = Math.floor(now / 1000);
  const calls: Fixture['calls'] = [];
  const fetched: string[] = [];
  const sbsHash = '0x' + bytesToHex(keccak256(parseHeader(hexToBytes(HEADER)).signblockscript));

  const lcTip = LIQUID_TIP - 10;
  const answers = new Map<string, string>([
    [views.BRIDGE_ASSET(), '0x' + ASSET_INTERNAL],
    [views.signblockscriptHash(), sbsHash],
    [views.MIN_CONFIRMATIONS(), word(2)],
    [views.EPOCH_LENGTH(), word(20160)],
    [views.lcTipHeight(), word(lcTip)],
    [views.lcTipTime(), word(scenario === 'relay-closed' ? secs - 30_000 : secs - 600)],
    [views.depositsOpen(), word(scenario === 'relay-closed' || scenario === 'fork-closed' ? 0 : 1)],
    [views.MAX_RELAY_LAG(), word(21_600)],
    [views.depositsEnd(), word(secs + 90 * 86_400)],
    [views.forkCheckedAt(), word(scenario === 'fork-closed' ? 0 : secs - 300)],
    [views.MAX_FORK_CHECK_AGE(), word(3600)],
  ]);
  const burnSelector = selector('burnScriptPubKey(address)');
  const redeemedSelector = selector('isRedeemed(bytes32,uint32)');

  const wallet: Eip1193 = {
    async request({ method, params = [] }) {
      calls.push({ method, params });
      const connected = scenario !== 'disconnected';
      switch (method) {
        case 'eth_accounts':
          return connected ? [ACCOUNT] : [];
        case 'eth_requestAccounts':
          return [ACCOUNT];
        case 'eth_chainId':
          return '0xaa36a7';
        case 'eth_getCode':
          return String(params[0]).toLowerCase() === ESCROW ? (scenario === 'bad-code' ? '0x6081' : CODE) : '0x';
        case 'eth_call': {
          const { to, data } = params[0] as { to: string; data: string };
          if (to.toLowerCase() !== ESCROW) throw Object.assign(new Error('execution reverted'), { code: 3, data: '0x' });
          if (data.startsWith(burnSelector)) {
            const recipient = '0x' + data.slice(-40);
            return abiBytes(burnTarget(11155111n, ESCROW, recipient).scriptPubKey);
          }
          if (data.startsWith(redeemedSelector)) return word(0);
          return answers.get(data) ?? word(0);
        }
        case 'eth_getBlockByNumber':
          return { number: '0x' + (9_000_000).toString(16) };
        case 'eth_getTransactionReceipt':
          return null;
        case 'eth_sendTransaction':
          throw Object.assign(new Error('The fixture wallet never sends.'), { code: 4001 });
        default:
          throw new Error(`fixture wallet: ${method} is not served`);
      }
    },
    on() {},
  };

  const routes = new Map<string, string>([
    ['/blocks/tip/hash', TIP_HASH],
    [`/block/${TIP_HASH}/header`, HEADER],
    [`/tx/${BOOTSTRAP_TXID}/hex`, BOOTSTRAP],
    [`/tx/${BOOTSTRAP_TXID}/status`, JSON.stringify({ confirmed: true, block_height: 2_600_000 })],
    // The state has not moved: no update or claim yet.
    [`/tx/${BOOTSTRAP_TXID}/outspend/0`, JSON.stringify({ spent: false })],
    [`/tx/${BURN_TXID}/status`, JSON.stringify({ confirmed: true, block_height: LIQUID_TIP - 5, block_hash: TIP_HASH })],
    [`/address/${DEPOSIT_ADDRESS}/txs`, '[]'],
  ]);
  // The instance record's manifest, which the Activity rows follow the state with. Served only with saved journeys:
  // the other scenarios show a site that does not serve it.
  const manifestUrl = `${SITE}instances/${FIXTURE_INSTANCE.name}/manifest.json`;
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = String(input instanceof Request ? input.url : input);
    fetched.push(url);
    if (url === manifestUrl && scenario === 'activity') return new Response(JSON.stringify(MANIFEST), { status: 200 });
    const path = url.startsWith(ESPLORA) ? url.slice(ESPLORA.length) : null;
    const body = scenario === 'liquid-down' || path === null ? undefined : routes.get(path);
    return body === undefined ? new Response('not found', { status: 404 }) : new Response(body, { status: 200 });
  }) as typeof fetch;

  const storage = new Map<string, string>();
  const journeys = options.journeys ?? (scenario === 'activity' ? seededJourneys(now) : []);
  if (journeys.length) storage.set('zk-bridge.journeys', JSON.stringify(journeys));

  const env: BridgeEnv = {
    ethereum: () => (scenario === 'no-wallet' ? null : wallet),
    humidWindow: () => (scenario === 'humid' ? { humid: addressOnlyHumid() } : {}),
    fetch: fetchImpl,
    storage: {
      getItem: (k) => storage.get(k) ?? null,
      setItem: (k, v) => void storage.set(k, v),
      removeItem: (k) => void storage.delete(k),
    },
    siteHref: () => SITE,
    now: () => now,
    sleep: () => Promise.resolve(),
    confirm: () => true,
    copy: () => Promise.resolve(),
    pollMs: 8000,
  };
  return { env, instance: scenario === 'no-instance' ? null : FIXTURE_INSTANCE, calls, fetched, storage };
}

/** The released getAddress response shape. This fixture never signs or broadcasts. */
function addressOnlyHumid(): Humid {
  return {
    async request({ method, params }) {
      const scope = { [HUMID_SCOPE]: { methods: ['getAddress'] } };
      if (method === 'wallet_getSession' || method === 'wallet_createSession') return { sessionScopes: scope };
      const invoke = params as { scope?: string; request?: { method?: string; params?: { confidential?: boolean; index?: number } } };
      if (method === 'wallet_invokeMethod' && invoke.scope === HUMID_SCOPE && invoke.request?.method === 'getAddress'
        && invoke.request.params?.confidential === false && invoke.request.params.index === 0) {
        return { chainId: HUMID_SCOPE, address: DEPOSIT_ADDRESS, accountIdentifier: 'fixture-account', confidential: false, index: 0 };
      }
      throw new Error(`The Humid fixture refuses ${method}. It only reads an address.`);
    },
  };
}

/** Journeys in each state a reader meets: waiting for finality (late), proven-and-waiting, claimed, a burn to relay. */
export function seededJourneys(now: number): Journey[] {
  const script = '0014' + '11'.repeat(20);
  const deposit = { kind: 'deposit' as const, escrow: ESCROW, asset: ASSET_INTERNAL, address: DEPOSIT_ADDRESS, script, units: '250000', wei: '2500000000000000' };
  return [
    { ...deposit, id: '0x' + '01'.repeat(32), txHash: '0x' + '01'.repeat(32), status: 'finalized', created: now - 40 * MINUTE, block: 8_999_000, index: '3', finalizedAt: now - 20 * MINUTE },
    { ...deposit, id: '0x' + '02'.repeat(32), txHash: '0x' + '02'.repeat(32), status: 'mined', created: now - 5 * 60 * MINUTE, block: 9_100_000, index: '4' },
    { ...deposit, id: '0x' + '03'.repeat(32), txHash: '0x' + '03'.repeat(32), status: 'claimed', created: now - 26 * 60 * MINUTE, block: 8_900_000, index: '1', finalizedAt: now - 25 * 60 * MINUTE, claimTxid: 'cd'.repeat(32), claimVout: 1, claimIndex: '1' },
    { kind: 'redeem', id: `${BURN_TXID}:0`, escrow: ESCROW, burnTxid: BURN_TXID, vout: 0, units: '100000', recipient: ACCOUNT, status: 'relay', created: now - 12 * MINUTE, confirmations: 6, burnHeight: LIQUID_TIP - 5, needed: LIQUID_TIP - 4 },
  ];
}
