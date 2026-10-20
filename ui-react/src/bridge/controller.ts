// The bridge page's controller as a framework-free store. Every rule is a shared module of
// ../ui/lib; this file only sequences reads, checks and wallet requests, and holds the state React renders
// (subscribe/getSnapshot, for useSyncExternalStore). Every outside effect goes through BridgeEnv.
//
// Reads of Sepolia go to the RPC in Settings once it has shown Sepolia's chain id, else to the wallet; every
// transaction goes to the wallet. Liquid is read through Esplora. Humid signs a burn, or an update's or claim's fee.
import { DEFAULTS, type RawInstance, type Settings, parseInstance, parseSettings } from '@bridge/ui/config.js';
import * as bridge from '@bridge/ui/lib/bridge.js';
import { bytesToHex, hexToBytes } from '@bridge/ui/lib/bytes.js';
import { type ClaimPlan, claimError, claimOnLiquid, depositClaims, prepareClaim, sendClaim, siteReader } from '@bridge/ui/lib/claim.js';
import { displayHex, parseHeader, parseTransaction, txidFromDisplay } from '@bridge/ui/lib/elements.js';
import { Esplora, type TxStatus } from '@bridge/ui/lib/esplora.js';
import { EthRpc, checkChain } from '@bridge/ui/lib/ethrpc.js';
import { keccak256 } from '@bridge/ui/lib/hash.js';
import { type BurnPlan, type HumidFailure, broadcastMatches, burnWithHumid, findHumid, humidError } from '@bridge/ui/lib/humid.js';
import { checkBootstrap } from '@bridge/ui/lib/issuance.js';
import { burnStatus, redemption, relayBatches } from '@bridge/ui/lib/redeem.js';
import {
  type LiveState, type UpdatePlan, lightClientStatus, liveState, prepareUpdate, publishes, sendUpdate, updateError, withStore,
} from '@bridge/ui/lib/update.js';
import * as derive from './derive';
import { readDeposit, readHumid, readPayTo, readRedeem } from './forms';
import { message, short } from './format';
import { SETTINGS_KEY, actionable, label, loadJourneys, saveJourneys, settled } from './journeys';
import type {
  BootstrapCheck, BridgeEnv, BridgeReads, BridgeState, DepositJourney, FoundRow, Journey, LightClientCheck, LiquidSend, RedeemForm, RedeemJourney,
} from './types';

// How often a panel asks the Liquid API for an update or claim Humid reports sending, as the API can lag a broadcast.
const LIQUID_LOOKUPS = 10;
const LIQUID_LAG_MS = 3000;

const INSTANCE_RETRY_MS = [15_000, 30_000, 60_000, 120_000, 300_000];
const NO_HUMID = 'Humid was not found in this browser. Install the Humid extension, unlock it, reload this page and try again.';
// A standard Liquid transaction is under 400,000 weight units, so its hex under 800,000 characters.
const MAX_FILE = 1_000_000;

const idleSend = <P>(): LiquidSend<P> => ({ busy: false, note: '', plan: null, sent: null, fileError: '', storeError: '', error: '' });

export function walletError(e: unknown): string {
  const code = (e as { code?: number } | null)?.code;
  if (code === 4001) return 'You declined the request in your wallet. Nothing was sent.';
  if (code === -32002) return 'Your wallet already has a pending request; open it to continue.';
  return message(e);
}

function revertData(e: unknown): string | null {
  const x = e as Record<string, any> | null; // eslint-disable-line @typescript-eslint/no-explicit-any
  for (const d of [x?.data?.data, x?.data, x?.error?.data, x?.info?.error?.data, x?.data?.originalError?.data]) {
    if (typeof d === 'string' && d.startsWith('0x')) return d;
  }
  return null;
}

/** A file the update and claim panels accept: a File, or anything with its size and text. */
export type HexFile = Pick<File, 'size' | 'text'> & { name?: string };

type SendKind = 'liquidUpdate' | 'liquidClaim';

export class BridgeController {
  private state: BridgeState;
  private readonly listeners = new Set<() => void>();
  /** The Liquid API in Settings; set by configure(). */
  private esplora!: Esplora;
  /** The Sepolia RPC from Settings and its chain check, run once per configuration and retried after a failure. */
  private ethReads: { rpc: EthRpc; checked: Promise<void> | null } | null = null;
  private instanceRun = 0;
  private targetVersion = 0;
  private ticking = false;
  private timer: ReturnType<typeof setInterval> | null = null;
  /** The first start's wallet read and poll; later starts only poll. */
  restored: Promise<void> | null = null;
  private messages = 0;
  /** Coins ("txid:vout") a Humid burn from this page may have spent; not offered again until a reload. */
  private readonly spent = new Set<string>();
  /** The last live state followed on Liquid through the Liquid API in Settings; the next walk resumes from it. */
  private live: LiveState | null = null;
  /** This poll's walk of the state on Liquid, which every deposit's check shares (claimsOnLiquid). */
  private polled: Promise<LiveState> | null = null;

  /** Throws if `published` is not a valid instance record, so a mistaken INSTANCE stops the page. */
  constructor(published: RawInstance | null, private readonly env: BridgeEnv) {
    const instance = parseInstance(published);
    const settings = this.configure();
    this.state = {
      instance, settings, settingsVersion: 0, hasWallet: !!env.ethereum(), account: null, chainId: null,
      bridge: null, bridgeError: null, bootstrap: null, liquid: null, liquidError: null,
      relaying: false, depositBusy: false, redeemBusy: false,
      target: null, targetError: null,
      redeemForm: { recipient: '', amount: '', txid: '', humidAddress: '', payTo: '' },
      found: null, lookupError: '',
      humid: { busy: false, note: '', error: '', held: null },
      lightClient: { busy: false, note: '', error: '', status: null },
      liquidUpdate: idleSend(), liquidClaim: idleSend(),
      journeys: loadJourneys(env.storage, instance?.escrow), toast: null, announcement: null, now: env.now(),
    };
    this.prefillHumid();
  }

  // ---- store ----

  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => void this.listeners.delete(listener);
  };

  getSnapshot = () => this.state;

  private set(patch: Partial<BridgeState>) {
    this.state = { ...this.state, ...patch };
    if (patch.journeys) saveJourneys(this.env.storage, patch.journeys);
    for (const l of this.listeners) l();
  }

  /** Reads the wallet, then polls. Idempotent, so React's development double effects start it once. */
  start() {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), this.env.pollMs);
    // The wallet's listeners are registered once, however often the page is mounted.
    if (this.restored) void this.tick();
    else this.restored = this.restoreWallet().then(() => this.tick());
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  // ---- configuration ----

  /** The saved Settings, or the defaults if they are unreadable or invalid; sets up the Sepolia RPC. */
  private configure(): Settings {
    let saved: Settings;
    try {
      saved = parseSettings(JSON.parse(this.env.storage.getItem(SETTINGS_KEY) || '{}'));
    } catch {
      saved = parseSettings({});
    }
    this.esplora = new Esplora(saved.esplora, this.env.fetch);
    this.live = null;
    this.polled = null;
    this.ethReads = saved.ethRpc ? { rpc: new EthRpc(saved.ethRpc, this.env.fetch), checked: null } : null;
    return saved;
  }

  /**
   * Checks and saves the Settings form. Returns field errors (never repeating a URL, which may hold an API key), or
   * null once saved. A Sepolia RPC is saved only once it answers with Sepolia's chain id.
   */
  async saveSettings(form: { esplora: string; ethRpc: string }): Promise<{ esplora?: string; ethRpc?: string } | null> {
    let settings: Settings;
    try {
      settings = parseSettings(form);
    } catch (e) {
      const field = (e as { field?: string }).field === 'esplora' ? 'esplora' : 'ethRpc';
      return { [field]: `Not saved: ${message(e)}.` };
    }
    if (settings.ethRpc) {
      try {
        await checkChain(new EthRpc(settings.ethRpc, this.env.fetch), DEFAULTS.chainId);
      } catch (e) {
        return { ethRpc: `Not saved: ${message(e)}.` };
      }
    }
    await this.applySettings(settings);
    this.toast('Settings saved.');
    return null;
  }

  async resetSettings() {
    await this.applySettings(null);
    this.toast('Using the default Liquid API, and your wallet for Sepolia.');
  }

  private async applySettings(settings: Settings | null) {
    if (settings) this.env.storage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    else this.env.storage.removeItem(SETTINGS_KEY);
    this.set({ settings: this.configure(), settingsVersion: this.state.settingsVersion + 1 });
    await this.refreshBridge();
    await this.refreshLiquid();
    void this.refreshTarget();
  }

  // ---- wallet and reads ----

  /** A request to the wallet: accounts, the chain, and every transaction. */
  private rpc(method: string, params: unknown[] = []): Promise<unknown> {
    const p = this.env.ethereum();
    if (!p) return Promise.reject(new Error('No Ethereum wallet found. Install a browser wallet such as MetaMask, then reload.'));
    return p.request({ method, params });
  }

  /** A read of Sepolia: through the RPC in Settings once it has shown it serves Sepolia, else through the wallet. */
  private async read(method: string, params: unknown[] = []): Promise<unknown> {
    const r = this.ethReads;
    if (!r) return this.rpc(method, params);
    r.checked ??= checkChain(r.rpc, DEFAULTS.chainId).catch((e) => {
      r.checked = null;
      throw e;
    });
    await r.checked;
    return r.rpc.request({ method, params });
  }

  private escrowCall = (data: string) => this.read('eth_call', [{ to: this.state.instance!.escrow, data }, 'latest']) as Promise<string>;

  /** eth_call the transaction first, so a revert is explained before the wallet asks to sign. */
  private async simulate(tx: object) {
    try {
      await this.read('eth_call', [tx, 'latest']);
    } catch (e) {
      const data = revertData(e);
      throw new Error(data ? bridge.explainRevert(data) : walletError(e), { cause: e });
    }
  }

  private async waitReceipt(hash: string) {
    for (;;) {
      // Through the RPC in Settings this may trail the wallet's node for a few blocks: null until it has the receipt.
      const receipt = (await this.read('eth_getTransactionReceipt', [hash])) as bridge.Receipt | null;
      if (receipt) {
        if (receipt.status !== '0x1') throw new Error('the transaction reverted on Ethereum');
        return receipt;
      }
      await this.env.sleep(4000);
    }
  }

  async connect() {
    try {
      const accounts = (await this.rpc('eth_requestAccounts')) as string[];
      this.set({ hasWallet: true, account: accounts[0]?.toLowerCase() ?? null, chainId: BigInt((await this.rpc('eth_chainId')) as string) });
      if (!derive.onSepolia(this.state)) {
        try {
          await this.rpc('wallet_switchEthereumChain', [{ chainId: '0x' + DEFAULTS.chainId.toString(16) }]);
          this.set({ chainId: DEFAULTS.chainId });
        } catch (e) {
          this.toast((e as { code?: number })?.code === 4902 ? 'Your wallet does not list Sepolia; enable test networks in it, then retry.' : walletError(e));
        }
      }
      await this.refreshBridge();
    } catch (e) {
      this.toast(walletError(e));
    }
    void this.refreshTarget();
  }

  private async restoreWallet() {
    const p = this.env.ethereum();
    if (!p) {
      // With no wallet, a Sepolia RPC in Settings can still show the bridge.
      await this.refreshBridge();
      void this.refreshTarget();
      return;
    }
    try {
      const accounts = (await this.rpc('eth_accounts')) as string[];
      this.set({ account: accounts[0]?.toLowerCase() ?? null, chainId: BigInt((await this.rpc('eth_chainId')) as string) });
      await this.refreshBridge();
    } catch {
      /* stay disconnected */
    }
    void this.refreshTarget();
    p.on?.('accountsChanged', (a: string[]) => {
      this.set({ account: a[0]?.toLowerCase() ?? null });
      void this.refreshTarget();
    });
    p.on?.('chainChanged', async (id: string) => {
      this.set({ chainId: BigInt(id) });
      await this.refreshBridge();
      void this.refreshTarget();
    });
  }

  // ---- chain state ----

  /** Reads the escrow, after checking its code hash is the record's; any failure makes it unusable for every action. */
  private async refreshBridge() {
    const { instance } = this.state;
    if (!instance || !derive.canRead(this.state)) {
      this.set({ bridge: null, bridgeError: null, bootstrap: null });
      return;
    }
    let reads: BridgeReads;
    try {
      const code = (await this.read('eth_getCode', [instance.escrow, 'latest'])) as string;
      if (!code || code === '0x') throw new Error('there is no contract at this address on Sepolia');
      // The published deployment's identity: a code hash covers the immutables, so it is this deployment's alone.
      if (bytesToHex(keccak256(hexToBytes(code))) !== instance.codeHash) {
        throw new Error(`its code hash is not the ${instance.record} record's ${short(instance.codeHash)}`);
      }
      const v = bridge.views;
      const [asset, sbs, conf, epochLength, lcTip, lcTime, open, lag, admission] = await Promise.all([
        this.escrowCall(v.BRIDGE_ASSET()), this.escrowCall(v.signblockscriptHash()), this.escrowCall(v.MIN_CONFIRMATIONS()),
        this.escrowCall(v.EPOCH_LENGTH()), this.escrowCall(v.lcTipHeight()), this.escrowCall(v.lcTipTime()),
        this.escrowCall(v.depositsOpen()), this.escrowCall(v.MAX_RELAY_LAG()), this.readAdmission(),
      ]);
      const assetHex = bridge.decode.bytes32(asset);
      reads = {
        asset: assetHex,
        assetDisplay: displayHex(hexToBytes(assetHex)),
        sbsHash: '0x' + bridge.decode.bytes32(sbs),
        minConf: Number(bridge.decode.uint(conf)),
        epochLength: Number(bridge.decode.uint(epochLength)),
        lcTip: Number(bridge.decode.uint(lcTip)),
        lcTime: Number(bridge.decode.uint(lcTime)),
        depositsOpen: bridge.decode.bool(open),
        maxRelayLag: Number(bridge.decode.uint(lag)),
        admission,
      };
    } catch (e) {
      this.set({ bridge: null, bridgeError: `not usable: ${message(e)}`, bootstrap: null });
      return;
    }
    this.set({ bridge: reads, bridgeError: null });
    await this.refreshInstance();
  }

  /** The escrow's deposit window and fork check, which bridge.depositAdmission explains. */
  private async readAdmission() {
    const v = bridge.views;
    const [end, checked, age] = await Promise.all([
      this.escrowCall(v.depositsEnd()), this.escrowCall(v.forkCheckedAt()), this.escrowCall(v.MAX_FORK_CHECK_AGE()),
    ]);
    return {
      depositsEnd: Number(bridge.decode.uint(end)),
      forkCheckedAt: Number(bridge.decode.uint(checked)),
      maxForkCheckAge: Number(bridge.decode.uint(age)),
    };
  }

  /**
   * Checks the published bootstrap against the escrow before deposits and burns are allowed: the escrow pins the
   * asset, but only the bootstrap shows that its one reissuance token went into the published state UTXO. A check
   * that could not read the bootstrap is `unavailable` and retried with backoff; one that read it and failed is final
   * until the escrow is read again. A `retry` keeps the last result on screen while it runs.
   */
  private async refreshInstance({ retry = false } = {}) {
    const run = ++this.instanceRun;
    const attempts = retry ? (this.state.bootstrap?.attempts ?? 0) + 1 : 0;
    if (!retry) this.set({ bootstrap: null });
    const { bridge: b, instance } = this.state;
    if (!b || !instance) return;
    let result: BootstrapCheck;
    try {
      const txid = instance.bootstrap;
      const [txHex, status] = await Promise.all([this.esplora.txHex(txid), this.esplora.txStatus(txid)]);
      const tx = parseTransaction(hexToBytes(txHex));
      if (displayHex(tx.txid) !== txid) throw new Error('the Liquid API returned another transaction');
      const r = checkBootstrap({
        tx, confirmed: !!status.confirmed, bridgeAsset: hexToBytes(b.asset),
        stateScript: bridge.depositRecipient(instance.state).script, feeAsset: hexToBytes(bridge.LIQUID_TESTNET_LBTC),
      });
      result = { ...r, asset: r.ok ? b.asset : null, error: r.ok ? null : 'the published bootstrap does not issue this escrow\'s asset into the published state address' };
    } catch (e) {
      const wait = INSTANCE_RETRY_MS[Math.min(attempts, INSTANCE_RETRY_MS.length - 1)];
      result = {
        ok: false, checks: [], unavailable: true, attempts, retryAt: this.env.now() + wait,
        error: `the bootstrap could not be read from the Liquid API (${message(e)}); this page tries again in about ${Math.round(wait / 1000)} seconds`,
      };
    }
    if (run === this.instanceRun) this.set({ bootstrap: result });
  }

  private async refreshLiquid() {
    try {
      const h = parseHeader(hexToBytes(await this.esplora.tipHeader()));
      this.set({ liquid: { tip: h.height, sbsHash: '0x' + bytesToHex(keccak256(h.signblockscript)) }, liquidError: null });
    } catch (e) {
      this.set({ liquidError: message(e) });
    }
  }

  /** Re-reads the light client's tip and signing script, which relayers move forward, and deposit admission. */
  private async refreshLightClient() {
    if (!derive.readable(this.state)) return;
    const v = bridge.views;
    const [tip, time, sbs, open] = await Promise.all([
      this.escrowCall(v.lcTipHeight()), this.escrowCall(v.lcTipTime()), this.escrowCall(v.signblockscriptHash()), this.escrowCall(v.depositsOpen()),
    ]);
    let admission = this.state.bridge!.admission;
    try {
      admission = await this.readAdmission();
    } catch {
      /* keep the last answer: one dropped request neither reopens nor closes deposits here */
    }
    if (!this.state.bridge) return;
    this.set({
      bridge: {
        ...this.state.bridge,
        lcTip: Number(bridge.decode.uint(tip)), lcTime: Number(bridge.decode.uint(time)), sbsHash: '0x' + bridge.decode.bytes32(sbs),
        depositsOpen: bridge.decode.bool(open), admission,
      },
      // A read failure of the last poll (tick) is history once a read succeeds; the escrow's identity was checked by
      // refreshBridge, which is what clears a code-hash failure.
      bridgeError: null,
    });
  }

  // ---- journeys ----

  private patchJourney(id: string, patch: Partial<DepositJourney> | Partial<RedeemJourney>) {
    const before = this.state.journeys.find((j) => j.id === id);
    if (!before) return;
    const after = { ...before, ...patch } as Journey;
    this.set({ journeys: this.state.journeys.map((j) => (j.id === id ? after : j)) });
    if (patch.status && patch.status !== before.status) this.announce(`${after.kind === 'deposit' ? 'Deposit' : 'Redemption'}: ${label(after).text}`);
  }

  private upsertJourney(j: Journey) {
    const exists = this.state.journeys.some((x) => x.id === j.id);
    this.set({ journeys: exists ? this.state.journeys.map((x) => (x.id === j.id ? ({ ...x, ...j } as Journey) : x)) : [j, ...this.state.journeys] });
  }

  removeJourney(id: string) {
    if (!this.env.confirm('Remove this entry from the list? This does not affect the chains.')) return;
    this.set({ journeys: this.state.journeys.filter((j) => j.id !== id) });
  }

  private journey(id: string) {
    return this.state.journeys.find((j) => j.id === id);
  }

  private async trackDeposit(id: string) {
    let j = this.journey(id) as DepositJourney | undefined;
    if (!j || settled(j) || !derive.canRead(this.state)) return;
    if (!j.block) {
      const receipt = (await this.read('eth_getTransactionReceipt', [j.txHash])) as bridge.Receipt | null;
      if (!receipt) return;
      if (receipt.status !== '0x1') {
        this.patchJourney(id, { status: 'failed', error: 'The deposit reverted on Ethereum. No ETH was locked.' });
        return;
      }
      const ev = bridge.depositEvent(receipt, j.escrow);
      this.patchJourney(id, { status: 'mined', block: Number(BigInt(receipt.blockNumber)), index: ev ? ev.index.toString() : null });
    }
    j = this.journey(id) as DepositJourney;
    if (!j.finalizedAt) {
      const fin = (await this.read('eth_getBlockByNumber', ['finalized', false])) as { number: string } | null;
      if (!fin || Number(BigInt(fin.number)) < j.block!) return;
      this.patchJourney(id, { status: 'finalized', finalizedAt: this.env.now() });
      j = this.journey(id) as DepositJourney;
    }
    // Only the claims of the served instance's escrow pay its deposits; a deposit to another escrow stays as it is.
    const instance = this.state.instance;
    if (!instance || j.escrow?.toLowerCase() !== instance.escrow) return;
    // A claim is this deposit's only if the walk shows it paid this deposit's index (lib/claim.js depositClaims):
    // deposits to one script may share their units, and claims may pay them in any order.
    const found = depositClaims([j], await this.claimsOnLiquid()).get(j);
    const patch: Partial<DepositJourney> = !found
      ? { status: 'finalized', claimTxid: undefined, claimVout: undefined, claimIndex: undefined, claimWhy: undefined }
      : found.status === 'unresolved'
        ? { status: 'unresolved', claimTxid: undefined, claimVout: undefined, claimIndex: undefined, claimWhy: found.why }
        : { status: found.status, claimTxid: found.txid, claimVout: found.vout, claimIndex: j.index!, claimWhy: undefined };
    if ((Object.keys(patch) as (keyof DepositJourney)[]).some((k) => j![k] !== patch[k])) this.patchJourney(j.id, patch);
  }

  /**
   * The state on Liquid followed to its live output (lib/update.js liveState), with every claim attributed to the
   * deposit index it paid, or not; one walk per poll, resuming where the last one ended.
   */
  private claimsOnLiquid(): Promise<LiveState> {
    this.polled ??= (async () => {
      const instance = this.state.instance!;
      const { esplora } = this;
      const manifest = JSON.parse(await siteReader(this.env.fetch, this.env.siteHref(), instance.record)('manifest.json'));
      const live = await liveState({ esplora, manifest, bootstrap: instance.bootstrap, from: this.live });
      if (esplora === this.esplora) this.live = live;
      return live;
    })();
    return this.polled;
  }

  /** The redeem journey state of a burn, from cheap reads only. */
  private burnState(status: TxStatus): Partial<RedeemJourney> {
    if (!status.confirmed) return { status: 'burned', confirmations: 0 };
    const b = this.state.bridge!;
    const height = status.block_height!;
    const confirmations = this.state.liquid ? this.state.liquid.tip - height + 1 : 0;
    const needed = height + b.minConf - 1;
    const s = confirmations < b.minConf ? 'burned' : b.lcTip < needed ? 'relay' : 'ready';
    return { status: s, confirmations, burnHeight: height, needed };
  }

  private async trackRedeem(id: string) {
    const j = this.journey(id) as RedeemJourney | undefined;
    if (!j || j.status === 'paid') return;
    if (j.status === 'submitted' && derive.canRead(this.state)) {
      const receipt = (await this.read('eth_getTransactionReceipt', [j.txHash])) as bridge.Receipt | null;
      if (!receipt) return;
      if (receipt.status === '0x1') this.patchJourney(id, { status: 'paid', block: Number(BigInt(receipt.blockNumber)) });
      else {
        this.patchJourney(id, {
          status: 'ready', txHash: null,
          error: 'The redemption reverted on Ethereum; nothing was paid or recorded, and the burn is still unspent. If the payout ran out of gas, retry with a higher limit; redeeming again shows the reason (it is simulated first).',
        });
      }
      return;
    }
    if (['burned', 'relay', 'ready'].includes(j.status) && this.state.bridge) {
      this.patchJourney(id, this.burnState(await burnStatus(this.esplora, j.burnTxid)));
    }
  }

  // ---- deposit ----

  /** Sends a deposit of `amount` ETH to the Liquid `recipient`, after the same gates the form shows. */
  async sendDeposit(form: { recipient: string; amount: string }) {
    const s = this.state;
    const d = readDeposit(form.recipient, form.amount);
    const adm = derive.admission(s);
    if (!derive.ready(s) || !d.script || !d.units || !d.wei || !adm?.deposit || !s.bootstrap?.ok || s.depositBusy) return false;
    const escrow = s.instance!.escrow;
    this.set({ depositBusy: true });
    try {
      const tx = { from: s.account, to: escrow, value: '0x' + d.wei.toString(16), data: bridge.depositCalldata(d.script) };
      await this.simulate(tx);
      const hash = (await this.rpc('eth_sendTransaction', [tx])) as string;
      this.upsertJourney({
        id: hash, kind: 'deposit', status: 'submitted', created: this.env.now(), escrow, asset: s.bridge!.asset,
        txHash: hash, address: d.address ?? null, script: bytesToHex(d.script), units: d.units.toString(), wei: d.wei.toString(),
      });
      this.toast('Deposit sent. Tracking it below.');
      void this.tick();
      return true;
    } catch (e) {
      this.toast(walletError(e));
      return false;
    } finally {
      this.set({ depositBusy: false });
    }
  }

  /**
   * Sends a pasted checkFork proof (tools/liquid-relay/fork_proof.py), when a stale fork check is what closes
   * deposits. Before the wallet is asked, the proof must reach the root Ethereum holds for its timestamp, be under the
   * escrow's pinned fork and be new enough. A proof of another fork would end deposits for good; that is anyone's
   * right on chain, but this page does not send it. Returns the error to show, or null once recorded.
   */
  async sendForkProof(text: string): Promise<string | null> {
    const s = this.state;
    const adm = derive.admission(s);
    if (!derive.ready(s) || !adm?.forkReopens) return 'Deposits are not waiting for a fork proof.';
    try {
      const p = bridge.parseForkProof(text);
      let held: string;
      try {
        held = bridge.decode.bytes32((await this.read('eth_call', [{ to: bridge.BEACON_ROOTS, data: bridge.beaconRootCall(p.timestamp) }, 'latest'])) as string);
      } catch {
        throw new Error('Ethereum holds no beacon block root for this proof\'s timestamp (EIP-4788 keeps about the last 27 hours). Build a new proof.');
      }
      if (held !== bytesToHex(bridge.beaconBlockRoot(p))) throw new Error('This proof does not reach the beacon block root Ethereum holds for its timestamp.');
      const [version, epoch] = await Promise.all([this.escrowCall(bridge.views.FORK_VERSION()), this.escrowCall(bridge.views.FORK_EPOCH())]);
      if (bridge.decode.bytes32(version).slice(0, 8) !== bytesToHex(p.currentVersion) || bridge.decode.uint(epoch) !== BigInt(p.epoch)) {
        throw new Error('This proof is not under the fork the escrow pins. Sent to the escrow it would end deposits for good, or revert for an older fork; this page does not send it.');
      }
      const { forkCheckedAt, maxForkCheckAge } = s.bridge!.admission;
      const slotTime = bridge.forkSlotTime(p);
      if (slotTime <= forkCheckedAt || slotTime + maxForkCheckAge < Math.floor(this.env.now() / 1000)) {
        throw new Error(`This proof's beacon state is too old to reopen deposits: it must be newer than the last fork check and less than ${Math.round(maxForkCheckAge / 60)} minutes old. Build a new one.`);
      }
      const tx = { from: s.account, to: s.instance!.escrow, data: bridge.checkForkCalldata(p) };
      await this.simulate(tx);
      this.toast('Sending the fork proof…');
      await this.waitReceipt((await this.rpc('eth_sendTransaction', [tx])) as string);
      await this.refreshLightClient();
      this.toast('Fork check recorded.');
      return null;
    } catch (e) {
      return walletError(e);
    }
  }

  // ---- relaying ----

  /**
   * Relays Liquid headers up to `target`, one submitHeaders transaction per batch (at most 100 headers, never across
   * a DynaFed epoch), waiting for each to confirm before building the next.
   */
  private async relayTo(target: number, { journey = null, done }: { journey?: string | null; done: string }) {
    if (!derive.ready(this.state) || this.state.relaying) return;
    this.set({ relaying: true });
    try {
      let sent = 0;
      for await (const batch of relayBatches({ esplora: this.esplora, call: this.escrowCall, target })) {
        const tx = { from: this.state.account, to: this.state.instance!.escrow, data: bridge.submitHeadersCalldata(batch) };
        await this.simulate(tx);
        this.toast(`Relaying Liquid heights ${batch.firstHeight}–${batch.firstHeight + batch.headers.length - 1}${batch.witnessScript.length ? ' (new signing keys)' : ''}…`);
        await this.waitReceipt((await this.rpc('eth_sendTransaction', [tx])) as string);
        sent += 1;
        await this.refreshLightClient();
      }
      this.toast(sent ? `Relayed in ${sent} transaction${sent > 1 ? 's' : ''}. ${done}` : `Already relayed. ${done}`);
      void this.tick();
    } catch (e) {
      if (journey) this.patchJourney(journey, { error: walletError(e) });
      this.toast(walletError(e));
    } finally {
      this.set({ relaying: false });
    }
  }

  relayFor(id: string) {
    const j = this.journey(id);
    if (j?.kind === 'redeem' && j.needed) return this.relayTo(j.needed, { journey: id, done: 'You can redeem now.' });
  }

  relayForDeposits() {
    if (this.state.liquid) return this.relayTo(this.state.liquid.tip, { done: 'Deposits are open again.' });
  }

  // ---- redeem ----

  setRedeemForm(patch: Partial<RedeemForm>) {
    const recipientChanged = patch.recipient !== undefined && patch.recipient !== this.state.redeemForm.recipient;
    this.set({ redeemForm: { ...this.state.redeemForm, ...patch } });
    if (recipientChanged) void this.refreshTarget();
  }

  /**
   * Step 1's burn target for the form's recipient: the page's own bare OP_RETURN script, used only if the escrow's
   * burnScriptPubKey answers exactly that script (bridge.escrowBurnTarget). The asset is the one the bootstrap
   * confirmed, kept with the target so that a later answer cannot swap it.
   */
  private async refreshTarget() {
    const version = ++this.targetVersion;
    const s = this.state;
    const { recipient } = readRedeem(s.redeemForm, s.account);
    if (!recipient || !derive.burnable(s)) {
      this.set({ target: null, targetError: null });
      return;
    }
    const asset = derive.burnAsset(s)!;
    try {
      const onchain = bridge.decode.bytes(await this.escrowCall(bridge.views.burnScriptPubKey(recipient)));
      const burn = bridge.escrowBurnTarget(DEFAULTS.chainId, s.instance!.escrow, recipient, onchain);
      const code = (await this.read('eth_getCode', [recipient, 'latest'])) as string;
      if (version !== this.targetVersion) return;
      this.set({ target: { recipient, burn, asset, assetDisplay: displayHex(hexToBytes(asset)), isContract: !!code && code !== '0x' }, targetError: null });
    } catch (e) {
      if (version !== this.targetVersion) return;
      this.set({ target: null, targetError: message(e) });
    }
  }

  /** Why a looked-up transaction redeems nothing for `recipient`, from bridge.burnDiagnosis. */
  private lookupFailure({ outputs, blinded }: ReturnType<typeof bridge.burnDiagnosis>, recipient: string) {
    const parts = outputs.map((f) => `output ${f.vout}${f.units === null ? '' : ` (${bridge.formatUnits(f.units, 8)})`} ${f.text}`);
    if (blinded) {
      parts.push(`${blinded === 1 ? 'one output is confidential, so this page cannot see what it holds' : `${blinded} outputs are confidential, so this page cannot see what they hold`}; `
        + 'a confidential send can never be redeemed');
    }
    return `This transaction holds no burn that redeems to ${short(recipient)}${parts.length ? `: ${parts.join('; ')}` : ', and sends no bridge asset openly'}. Check the recipient in step 1.`;
  }

  /** Step 3: finds the burn outputs of the form's txid and saves each usable one as a redemption journey. */
  async lookupBurn() {
    const txid = this.state.redeemForm.txid.trim().toLowerCase();
    this.set({ found: null, lookupError: '' });
    try {
      if (!/^[0-9a-f]{64}$/.test(txid)) throw new Error('a Liquid txid is 64 hex characters');
      const t = derive.target(this.state);
      if (!t) throw new Error(derive.notBurnable(this.state) || 'fill in step 1 first: the burn depends on the recipient');
      const tx = parseTransaction(hexToBytes(await this.esplora.txHex(txid)));
      if (displayHex(tx.txid) !== txid) throw new Error('the Liquid API returned a different transaction');
      const asset = hexToBytes(t.asset);
      const outs = bridge.burnOutputs(tx, asset, t.burn.scriptPubKey);
      const why = bridge.burnDiagnosis(tx, asset, t.burn);
      if (!outs.some((o) => o.usable)) throw new Error(this.lookupFailure(why, t.recipient));
      const st = this.burnState(await this.esplora.txStatus(txid));
      const rows: FoundRow[] = [];
      for (const o of outs) {
        let note: string;
        const existing = this.journey(`${txid}:${o.vout}`);
        if (!o.usable) note = `not redeemable: ${why.outputs.find((f) => f.vout === o.vout)?.text ?? 'it burns nothing usable'}`;
        else if (existing && ['submitted', 'paid'].includes(existing.status)) note = existing.status === 'submitted' ? 'redemption in flight' : 'already redeemed';
        else {
          const redeemed = bridge.decode.bool(await this.escrowCall(bridge.views.isRedeemed(txidFromDisplay(txid), o.vout)));
          this.upsertJourney({
            id: `${txid}:${o.vout}`, kind: 'redeem', created: this.env.now(), escrow: this.state.instance!.escrow, burnTxid: txid, vout: o.vout,
            units: o.units!.toString(), recipient: t.recipient, ...st, status: redeemed ? 'paid' : (st.status as RedeemJourney['status']),
          } as RedeemJourney);
          note = redeemed ? 'already redeemed'
            : st.status === 'ready' ? 'ready to redeem'
              : st.status === 'relay' ? `confirmed; waiting for the bridge to relay Liquid to height ${st.needed}`
                : `${st.confirmations} of ${this.state.bridge!.minConf} confirmations`;
        }
        rows.push({ vout: o.vout, amount: o.units === null ? '—' : `${bridge.formatUnits(o.units, 8)} (${o.units.toLocaleString('en')} units)`, note });
      }
      this.set({ found: rows });
    } catch (e) {
      this.set({ lookupError: message(e) });
    }
  }

  /** Step 4: redeems `id`, or the first redemption that is ready, to the form's optional payee. */
  async redeem(id?: string) {
    const s = this.state;
    const j = id ? this.journey(id) : s.journeys.find((x) => actionable(x, 'ready'));
    if (!j || j.kind !== 'redeem') return;
    const p = readPayTo(s.redeemForm.payTo, s.account);
    if (p.error) {
      this.toast(p.error);
      return;
    }
    await this.sendRedeem(j, p.payTo);
  }

  /**
   * Redeems a burn: to its recipient (anyone may send this), or with `payTo` to another address, which only the
   * recipient itself may do (redeemTo), for a contract that refuses plain ETH or by choice.
   */
  private async sendRedeem(j: RedeemJourney, payTo: string | null) {
    const s = this.state;
    if (!derive.ready(s) || s.redeemBusy) return;
    this.set({ redeemBusy: true });
    try {
      const escrow = s.instance!.escrow;
      if (j.escrow.toLowerCase() !== escrow) throw new Error('this burn was made for another escrow deployment');
      if (payTo && s.account !== j.recipient) throw new Error('only the burn\'s recipient can redeem it to another address; connect that account');
      this.toast('Assembling the proof from Liquid testnet data…');
      const r = await redemption({ esplora: this.esplora, call: this.escrowCall, recipient: j.recipient, txid: j.burnTxid, vout: j.vout });
      if (r.state === 'unconfirmed') throw new Error('the burn is not confirmed on Liquid yet');
      if (r.state === 'awaiting-relay') {
        this.patchJourney(j.id, { status: 'relay', needed: r.needed });
        throw new Error(`the bridge has relayed Liquid to height ${r.tip}; this burn needs ${r.needed}`);
      }
      const data = payTo ? bridge.redeemToCalldata({ to: payTo, burn: r.args.burn, ref: r.args.ref }) : bridge.redeemCalldata(r.args);
      const tx = { from: s.account, to: escrow, data };
      await this.simulate(tx);
      const hash = (await this.rpc('eth_sendTransaction', [tx])) as string;
      this.patchJourney(j.id, { status: 'submitted', txHash: hash, payee: payTo || j.recipient, error: null });
      this.toast('Redemption sent.');
      void this.tick();
    } catch (e) {
      this.patchJourney(j.id, { error: walletError(e) });
      this.toast(walletError(e));
    } finally {
      this.set({ redeemBusy: false });
    }
  }

  // ---- burning with Humid ----

  /** The latest deposit claimed to a P2WPKH address in this browser: Humid's kind, so its likely unconfidential address. */
  private prefillHumid() {
    const escrow = this.state.instance?.escrow;
    const j = this.state.journeys.find((x) => x.kind === 'deposit' && x.escrow?.toLowerCase() === escrow && /^tex1q[a-z0-9]{38}$/.test(x.address || '')) as DepositJourney | undefined;
    if (j && !this.state.redeemForm.humidAddress) this.state = { ...this.state, redeemForm: { ...this.state.redeemForm, humidAddress: j.address! } };
  }

  private setHumid(patch: Partial<BridgeState['humid']>) {
    this.set({ humid: { ...this.state.humid, ...patch } });
  }

  /**
   * Burns step 1's amount with Humid: lib/humid.js finds the claim on Liquid, builds the burn and has Humid sign and
   * broadcast it once the user confirms there. Then step 3 looks the send up.
   */
  async sendWithHumid() {
    // target() is null unless its asset is still the one the bootstrap confirms, so no other asset reaches the PSET.
    const t = derive.target(this.state);
    const h = readHumid(this.state.redeemForm.humidAddress);
    if (!t || !t.units || !h.claim || this.state.humid.busy || this.state.humid.held) return;
    const claim = h.claim;
    const note = (text: string) => this.setHumid({ note: text });
    this.set({ humid: { busy: true, note: 'Looking for Humid…', error: '', held: null } });
    let asked: string[] = [];
    try {
      const humid = await findHumid(this.env.humidWindow());
      if (!humid) throw new Error(NO_HUMID);
      const { txid, plan } = await burnWithHumid({
        humid, esplora: this.esplora, asset: hexToBytes(t.asset), units: t.units, burnScript: t.burn.scriptPubKey, claim, skip: this.spent,
        onSign: (outpoints) => {
          asked = outpoints;
          for (const o of outpoints) this.spent.add(o);
        },
        progress: note,
      });
      note(`Humid reports sending ${short(txid)}. Waiting for the Liquid API to show it…`);
      // Busy until step 3 has looked it up, so a second click cannot race the Liquid API's lag.
      note(await this.lookUpSent(txid, plan));
    } catch (e) {
      const err = e as HumidFailure | null;
      if (err?.sent === 'no') for (const o of asked) this.spent.delete(o);
      // Humid's errors carry an RPC code or a `sent` mark; the page's own checks and Liquid API failures carry neither.
      const text = err && (err.sent || err.code !== undefined)
        ? humidError(err) + (err.sent === 'maybe' ? ` Explorer: ${DEFAULTS.liquidExplorer}/address/${claim.address}` : '')
        : message(e);
      this.setHumid({ note: '', error: text });
    } finally {
      this.setHumid({ busy: false });
    }
  }

  /** Looks up a send Humid just broadcast once the Liquid API has it, after checking it is the planned burn. */
  private async lookUpSent(txid: string, plan: BurnPlan) {
    this.set({ redeemForm: { ...this.state.redeemForm, txid } });
    let hex: string | null = null;
    for (let i = 0; i < 10 && hex === null; i++) {
      try {
        hex = await this.esplora.txHex(txid);
      } catch (e) {
        if ((e as { status?: number }).status !== 404) break;
        await this.env.sleep(3000);
      }
    }
    if (hex === null) return this.holdBurn(txid, 'the Liquid API does not show it yet');
    let why: string | null;
    try {
      if (displayHex(parseTransaction(hexToBytes(hex)).txid) !== txid) {
        return this.holdBurn(txid, 'the Liquid API serves another transaction for its txid');
      }
      why = broadcastMatches(plan, hex);
    } catch (e) {
      return this.holdBurn(txid, `the Liquid API's copy of it could not be read (${message(e)})`);
    }
    if (why) return this.holdBurn(txid, why, true);
    this.toast('Humid sent the burn. Step 3 tracks it.');
    await this.lookupBurn();
    return `Humid sent ${short(txid)}, the burn this page built. Step 3 below tracks it.`;
  }

  private holdBurn(txid: string, why: string, mismatch = false) {
    const explorer = `${DEFAULTS.liquidExplorer}/tx/${txid}`;
    const status = mismatch ? 'does not count it as a burn' : 'cannot check that it is the burn it built';
    this.setHumid({
      held: txid,
      error: `Humid reports sending ${short(txid)}, but ${why}, so this page ${status}. Its txid is in step 3: `
        + `look it up there and check Humid's activity and ${explorer} before anything else.`,
    });
    return `${mismatch ? 'Not the burn this page built' : 'Unverified'}. Step 2 asks Humid for no other burn while this send is in doubt.`;
  }

  // ---- updates and claims built locally, sent with Humid paying the fee ----

  private patchSend(kind: SendKind, patch: Partial<LiquidSend<unknown>>) {
    const next = { ...this.state[kind], ...patch };
    this.set(kind === 'liquidUpdate' ? { liquidUpdate: next as LiquidSend<UpdatePlan> } : { liquidClaim: next as LiquidSend<ClaimPlan> });
  }

  private readonly sends = {
    liquidUpdate: {
      what: 'update', source: 'the update.hex that just update-unsigned wrote',
      prepare: prepareUpdate,
      send: sendUpdate,
      explain: updateError,
    },
    liquidClaim: {
      what: 'claim', source: 'the claim.hex that just claim-unsigned wrote',
      prepare: prepareClaim,
      send: sendClaim,
      explain: claimError,
    },
  } as const;

  private setLightClient(patch: Partial<LightClientCheck>) {
    this.set({ lightClient: { ...this.state.lightClient, ...patch } });
  }

  /** Says how far a walk of the state chain on Liquid has come (lib/update.js liveState). */
  private following = (set: (note: string) => void) => (spends: number) => set(`Following the bridge state on Liquid: ${spends} spend${spends === 1 ? '' : 's'} so far…`);

  /**
   * Follows the bridge state on Liquid to its live output and looks up the store at its head in this site's record
   * (lib/update.js lightClientStatus), for the update panel's status. A walk resumes where the last one ended.
   */
  async checkLightClient() {
    const { instance, lightClient } = this.state;
    if (!instance || lightClient.busy) return;
    const { esplora } = this;
    this.setLightClient({ busy: true, error: '', note: 'Following the bridge state on Liquid from its bootstrap…' });
    try {
      const site = this.env.siteHref();
      const { live, listed } = await lightClientStatus({
        esplora, readRecord: siteReader(this.env.fetch, site, instance.record), bootstrap: instance.bootstrap, from: this.live,
        progress: this.following((note) => this.setLightClient({ note })),
      });
      // Settings changed the Liquid API meanwhile: this answer is another API's.
      if (esplora !== this.esplora) return;
      this.live = live;
      this.setLightClient({ status: { live, listed, published: publishes(site), checkedAt: this.env.now() } });
    } catch (e) {
      this.setLightClient({ error: `The bridge state on Liquid could not be followed: ${message(e)}.` });
    } finally {
      this.setLightClient({ busy: false, note: '' });
    }
  }

  /**
   * Checks an unsigned update.hex or claim.hex against this site's instance record and the Liquid API
   * (prepareUpdate, prepareClaim). Humid is not involved yet. An update is checked against the live state followed from
   * the bootstrap, and its store counts as published only on the published site (lib/update.js publishes).
   */
  async loadFile(kind: SendKind, file: HexFile | null) {
    const k = this.sends[kind];
    const { instance } = this.state;
    this.patchSend(kind, idleSend());
    if (!file || !instance) return;
    const note = (text: string) => this.patchSend(kind, { note: text });
    this.patchSend(kind, { busy: true, note: `Checking the ${k.what} against this site's record and the Liquid API…` });
    try {
      if (file.size > MAX_FILE) throw new Error(`this file is too large to be ${k.what === 'update' ? 'an update' : 'a claim'}. Load ${k.source}`);
      let raw: Uint8Array;
      try {
        raw = hexToBytes((await file.text()).trim());
      } catch {
        throw new Error(`this file is not hex. Load ${k.source}`);
      }
      const site = this.env.siteHref();
      const readRecord = siteReader(this.env.fetch, site, instance.record);
      const { esplora } = this;
      // Each prepare reads only what it needs; the union of the two cannot see that.
      const plan = await (k.prepare as (a: object) => Promise<UpdatePlan | ClaimPlan>)({
        esplora, readRecord, raw, bootstrap: instance.bootstrap, published: publishes(site), from: this.live, progress: this.following(note),
      });
      if (kind === 'liquidUpdate' && esplora === this.esplora) this.live = (plan as UpdatePlan).live;
      this.patchSend(kind, { plan });
    } catch (e) {
      this.patchSend(kind, { fileError: `Cannot send this ${k.what}: ${message(e)}.` });
    } finally {
      this.patchSend(kind, { busy: false, note: '' });
    }
  }

  /**
   * Adds the sender's own store file to the loaded update when this site does not publish the store it moves to
   * (lib/update.js withStore). The file must hash to the lc in the update's witness; nothing else is read from it.
   */
  async loadStore(file: HexFile | null) {
    const { plan, sent, busy } = this.state.liquidUpdate;
    this.patchSend('liquidUpdate', { storeError: '' });
    if (!file || !plan || plan.store?.where === 'site' || sent || busy) return;
    try {
      if (file.size > MAX_FILE) throw new Error('this file is too large to be a store file');
      const text = await file.text();
      // An update loaded meanwhile replaced the plan: this file was chosen for another.
      if (this.state.liquidUpdate.plan !== plan) return;
      this.patchSend('liquidUpdate', { plan: withStore(plan, text, file.name || 'this file') });
    } catch (e) {
      this.patchSend('liquidUpdate', { storeError: `Not this update's store: ${message(e)}.` });
    }
  }

  /**
   * Sends the loaded update or claim with Humid, which signs only its fee coin, once the user confirms there. Whatever
   * Humid then answers, the panel reports what the Liquid API shows (lookUpOnLiquid): one Humid reports sending is not
   * shown as sent until the API has it, and one Humid gave no clear answer for is held, not offered again. From then
   * on this only asks the Liquid API again; sending again takes loading the file again, which checks Liquid first.
   * Errors that show nothing was sent (a decline, a refusal before signing, no Humid) leave the panel ready to retry.
   */
  async sendFile(kind: SendKind) {
    const k = this.sends[kind];
    const { plan, busy, sent } = this.state[kind];
    if (!plan || busy || sent?.where === 'confirmed') return;
    const note = (text: string) => this.patchSend(kind, { note: text });
    // Busy before the first await, so a second click cannot start a second request.
    this.patchSend(kind, { busy: true, error: '' });
    try {
      if (sent) {
        note(`Asking the Liquid API about the ${k.what}…`);
        await this.lookUpOnLiquid(kind, sent.said, 1);
        return;
      }
      note('Looking for Humid…');
      let said: string | null = null;
      try {
        const humid = await findHumid(this.env.humidWindow());
        if (!humid) throw new Error(NO_HUMID);
        // The plan is the one prepared for this kind; the union of the two senders cannot see that.
        await (k.send as (a: object) => Promise<string>)({ humid, esplora: this.esplora, plan, progress: note });
      } catch (e) {
        // Humid may have broadcast it, or another transaction: only the Liquid API can tell.
        if ((e as HumidFailure | null)?.sent !== 'maybe') throw e;
        said = k.explain(e);
      }
      note(said ? `Humid may have sent the ${k.what}. Asking the Liquid API…` : `Humid reports sending the ${k.what}. Waiting for the Liquid API to show it…`);
      await this.lookUpOnLiquid(kind, said, said ? 1 : LIQUID_LOOKUPS);
    } catch (e) {
      // Humid's errors carry an RPC code or a `sent` mark; the page's own checks and Liquid API failures carry neither.
      const err = e as HumidFailure | null;
      this.patchSend(kind, { error: err && (err.sent || err.code !== undefined) ? k.explain(err) : message(e) });
    } finally {
      this.patchSend(kind, { busy: false, note: '' });
    }
  }

  /** Records where the Liquid API has the loaded update or claim, after Humid's answer `said` (null: reported sent). */
  private async lookUpOnLiquid(kind: SendKind, said: string | null, tries: number) {
    const { plan } = this.state[kind];
    if (!plan) return;
    const seen = await claimOnLiquid(this.esplora, plan.txid, { tries, waitMs: this.env.liquidLagMs ?? LIQUID_LAG_MS });
    // A file loaded meanwhile replaced the plan: this answer is about one no longer shown.
    if (this.state[kind].plan !== plan) return;
    this.patchSend(kind, { sent: { ...seen, txid: plan.txid, said, checkedAt: this.env.now() } });
    if (seen.where !== 'unknown') {
      this.toast(seen.where === 'confirmed' ? `The ${this.sends[kind].what} is confirmed on Liquid.` : `The Liquid API has the ${this.sends[kind].what}.`);
    }
  }

  // ---- messages ----

  toast(text: string) {
    const id = ++this.messages;
    this.set({ toast: { id, text }, announcement: { id, text } });
  }

  private announce(text: string) {
    this.set({ announcement: { id: ++this.messages, text } });
  }

  async copy(text: string) {
    try {
      await this.env.copy(text);
      this.toast('Copied.');
    } catch {
      this.toast('Copy failed; select the text instead.');
    }
  }

  // ---- polling ----

  /** One poll: Liquid's tip, the light client, a pending bootstrap retry, then every saved journey. */
  async tick() {
    if (this.ticking) return;
    this.ticking = true;
    try {
      this.set({ now: this.env.now(), hasWallet: !!this.env.ethereum() });
      await this.refreshLiquid();
      try {
        await this.refreshLightClient();
      } catch (e) {
        this.set({ bridgeError: `unreadable (${message(e)})` });
      }
      // A bootstrap check the Liquid API failed is retried after its backoff; one whose data disagreed is not.
      const b = this.state.bootstrap;
      if (this.state.bridge && b?.unavailable && this.env.now() >= (b.retryAt ?? 0)) {
        await this.refreshInstance({ retry: true });
        if (this.state.bootstrap?.ok) void this.refreshTarget();
      }
      // A failed check leaves the journey as it was; its row shows lastError until a later check succeeds.
      this.polled = null;
      for (const { id, kind } of this.state.journeys) {
        try {
          if (kind === 'deposit') await this.trackDeposit(id);
          else await this.trackRedeem(id);
          if (this.journey(id)?.lastError) this.patchJourney(id, { lastError: undefined });
        } catch (e) {
          this.patchJourney(id, { lastError: message(e) });
        }
      }
    } finally {
      this.ticking = false;
      this.set({ now: this.env.now() });
    }
  }
}
