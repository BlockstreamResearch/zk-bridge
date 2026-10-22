// Prepare public inputs for the Rust builders. No wallet secrets, signing or broadcasting belongs here.
import type { Instance } from '@bridge/core/config.js';
import { depositEvent, depositRecipient, LIQUID_TESTNET_LBTC, SEPOLIA_CHAIN_ID } from '@bridge/core/lib/bridge.js';
import { bigToBytes, bytesToHex, concat, hexToBytes, utf8 } from '@bridge/core/lib/bytes.js';
import { displayHex, parseTransaction } from '@bridge/core/lib/elements.js';
import type { Esplora } from '@bridge/core/lib/esplora.js';
import { keccak256, sha256 } from '@bridge/core/lib/hash.js';
import { checkBootstrap } from '@bridge/core/lib/issuance.js';
import * as stateCore from '@bridge/core/lib/update.js';
import type { BridgeStateWords, LiveState, RecordReader } from '@bridge/core/lib/update.js';

export type BrowserBuildKind = 'update' | 'claim';
export interface BrowserBuildRequest { kind: BrowserBuildKind; input: Record<string, unknown> }
export type ReadEth = (method: string, params?: unknown[]) => Promise<unknown>;

interface CommonArgs {
  instance: Instance;
  esplora: Esplora;
  readRecord: RecordReader;
  readEth: ReadEth;
  feeTxid: string;
  feeVout: number;
  from?: LiveState | null;
  progress?: (message: string) => void;
  signal?: AbortSignal;
}

// These core functions are public JS exports; the original send-only declaration file predates their use here.
const core = stateCore as typeof stateCore & {
  claimedRoot(indices: number[]): string;
  stateHash(state: { lc: string; acc: string; claimedRoot: string }): string;
  stateTree(manifest: unknown): unknown;
  stateScript(tree: unknown, state: BridgeStateWords): Uint8Array;
  storeFile(text: string, want: { head: number; lc: string }, name: string): unknown;
};
const DEPOSIT_TOPIC = '0x' + bytesToHex(keccak256('Deposit(uint64,uint64,bytes32,bytes32,bytes32,bytes)'));
const MAX_ENTRIES = 10_000;
const MAX_LOG_REQUESTS = 20_000;
const MAX_RECORD_BYTES = 2 * 1024 * 1024;
const MAX_TX_HEX = 8 * 1024 * 1024;
const MAX_COMPILED_HEX = 8 * 1024 * 1024;
const LIQUID_GENESIS = 'a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1';
type ObjectValue = Record<string, unknown>;

function active(args: CommonArgs): void {
  if (args.signal?.aborted) throw new Error('Build cancelled');
}

function object(value: unknown, name: string): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} must be an object.`);
  return value as ObjectValue;
}
function word(value: unknown, name: string, digits = 64): string {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${digits}}$`).test(value)) throw new Error(`${name} is not canonical hex.`);
  return value;
}
function integer(value: unknown, name: string, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > max) throw new Error(`${name} is not a valid integer.`);
  return value;
}
function quantity(value: unknown, name: string): number {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)) throw new Error(`${name} is not an RPC quantity.`);
  const n = BigInt(value);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${name} is too large.`);
  return Number(n);
}
function same(actual: unknown, expected: unknown, name: string): void {
  if (actual !== expected) throw new Error(`${name} does not match this bridge instance.`);
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
    .map(([key, v]) => JSON.stringify(key) + ':' + canonical(v)).join(',') + '}';
  return JSON.stringify(value);
}
async function record(read: RecordReader, path: string): Promise<ObjectValue> {
  const text = await read(path);
  if (text.length > MAX_RECORD_BYTES) throw new Error(`${path} exceeds the size limit.`);
  return object(JSON.parse(text), path);
}
function stateRecord(value: unknown, name: string, requireStore: boolean): ObjectValue {
  const s = object(value, name);
  const head = integer(s.head, `${name}.head`);
  const lc = word(s.lc, `${name}.lc`), acc = word(s.acc, `${name}.acc`);
  const root = word(s.claimed_root, `${name}.claimed_root`);
  if (!Array.isArray(s.claimed) || s.claimed.length > MAX_ENTRIES) throw new Error(`${name}.claimed is not a bounded list.`);
  const claimed = s.claimed.map((i) => integer(i, 'Claimed deposit index', 0xffffffff));
  if (claimed.some((i, at) => at > 0 && i <= claimed[at - 1])) throw new Error(`${name}.claimed must be strictly increasing.`);
  same(core.claimedRoot(claimed), root, `${name} claimed root`);
  const hash = core.stateHash({ lc, acc, claimedRoot: root });
  if (s.state_hash !== undefined) same(s.state_hash, hash, `${name} state hash`);
  const out: ObjectValue = { head, lc, acc, claimed_root: root, claimed, state_hash: hash };
  if (requireStore || s.header !== undefined || s.committee !== undefined) {
    const header = word(s.header, `${name}.header`), committee = word(s.committee, `${name}.committee`);
    same(bytesToHex(sha256(concat(sha256(utf8('liquid-bridge-poc/lc')), bigToBytes(BigInt(head), 8), hexToBytes(header), hexToBytes(committee)))), lc, `${name} light-client commitment`);
    Object.assign(out, { header, committee });
  }
  if (s.exec_block !== undefined) out.exec_block = integer(s.exec_block, `${name}.exec_block`);
  if (s.exec_root !== undefined) out.exec_root = word(s.exec_root, `${name}.exec_root`);
  return out;
}

async function rawTransaction(esplora: Esplora, txid: string) {
  word(txid, 'Transaction ID');
  const hex = (await esplora.txHex(txid)).trim();
  if (hex.length > MAX_TX_HEX || !/^(?:[0-9a-f]{2})+$/i.test(hex)) throw new Error('Liquid returned an invalid or oversized transaction.');
  const tx = parseTransaction(hexToBytes(hex));
  same(displayHex(tx.txid), txid, 'Liquid transaction hash');
  return { hex, tx };
}
async function unspent(esplora: Esplora, txid: string, vout: number, name: string) {
  const [status, out] = await Promise.all([
    esplora.txStatus(txid), esplora.json<unknown>(`/tx/${txid}/outspend/${vout}`),
  ]);
  if (status?.confirmed !== true) throw new Error(`${name} is not confirmed on Liquid.`);
  if (object(out, `${name} outspend`).spent !== false) throw new Error(`${name} was spent or its status is unknown. Refresh and rebuild.`);
}

async function prepareCommon(args: CommonArgs) {
  active(args);
  const { instance, esplora, readRecord, readEth, feeTxid, feeVout, from, progress = () => {} } = args;
  word(feeTxid, 'Fee transaction ID');
  integer(feeVout, 'Fee output number', 0x3fffffff);
  progress('Checking the bridge instance and current Liquid state…');
  same(quantity(await readEth('eth_chainId'), 'Ethereum chain'), Number(SEPOLIA_CHAIN_ID), 'Ethereum chain');
  const [manifest, pins, code] = await Promise.all([
    record(readRecord, 'manifest.json'), record(readRecord, 'instance.json'), readEth('eth_getCode', [instance.escrow, 'latest']),
  ]);
  active(args);
  if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(code)) throw new Error('The escrow runtime code is unavailable.');
  same(bytesToHex(keccak256(hexToBytes(code))), instance.codeHash, 'Escrow runtime code');
  same(manifest.schema, 'liquid-bridge-poc/manifest', 'Manifest schema');
  same(manifest.deployable, true, 'Manifest deployment');
  const eth = object(manifest.sepolia, 'Manifest Sepolia pins');
  const liquid = object(manifest.liquid, 'Manifest Liquid pins');
  const sp1 = object(manifest.sp1, 'Manifest proof pins');
  const update = object(manifest.update_leaf, 'Manifest update leaf');
  if (update.stand_in === true) throw new Error('A test-only update leaf cannot build a bridge transaction.');
  word(update.cmr, 'Update CMR'); word(object(manifest.claim_leaf, 'Claim leaf').cmr, 'Claim CMR');
  same(liquid.network, 'liquidtestnet', 'Liquid network');
  same(liquid.genesis_display, LIQUID_GENESIS, 'Liquid genesis');
  same(eth.chain_id, Number(SEPOLIA_CHAIN_ID), 'Manifest Ethereum chain');
  same(eth.instance, instance.name, 'Manifest name'); same(pins.name, instance.name, 'Instance record name');
  same(eth.escrow, instance.escrow.slice(2), 'Manifest escrow'); same(pins.ESCROW, eth.escrow, 'Instance escrow');
  same(eth.escrow_code_hash, instance.codeHash, 'Manifest code hash'); same(pins.ESCROW_CODE_HASH, instance.codeHash, 'Instance code hash');
  same(pins.DEPOSIT_DOMAIN, word(eth.deposit_domain, 'Deposit domain'), 'Deposit domain');
  same(pins.GUEST_ELF_SHA256, word(sp1.elf_sha256, 'Guest hash'), 'Guest hash');
  same(pins.PROGRAM_VKEY, word(sp1.program_vkey, 'Program verification key'), 'Program verification key');
  const initial = stateRecord(manifest.initial_state, 'Initial state', true);
  const anchor = object(pins.ANCHOR, 'Anchor');
  for (const key of ['header', 'committee', 'lc']) same(initial[key], anchor[key], `Anchor ${key}`);
  same(initial.head, anchor.slot, 'Anchor slot');
  const stateScript = depositRecipient(instance.state).script;
  same(bytesToHex(stateScript), object(manifest.state_tree, 'State tree').script_pubkey, 'Initial state script');
  same(bytesToHex(core.stateScript(core.stateTree(manifest), { head: initial.head as number, lc: initial.lc as string,
    acc: initial.acc as string, claimedRoot: initial.claimed_root as string, claimed: initial.claimed as number[] })), bytesToHex(stateScript), 'Manifest covenant commitments');
  const bootstrap = await rawTransaction(esplora, instance.bootstrap);
  const bootstrapStatus = await esplora.txStatus(instance.bootstrap);
  const boot = checkBootstrap({ tx: bootstrap.tx, confirmed: bootstrapStatus.confirmed === true,
    bridgeAsset: hexToBytes(word(object(manifest.bootstrap, 'Bootstrap').asset, 'Bridge asset')), stateScript,
    feeAsset: hexToBytes(LIQUID_TESTNET_LBTC) });
  if (!boot.ok) throw new Error('The published bootstrap failed verification: ' + boot.checks.filter((c) => !c.ok).map((c) => c.text).join('; '));
  const live = await core.liveState({ esplora, manifest, bootstrap: instance.bootstrap, from,
    progress: (n) => { active(args); progress(`Following Liquid state transaction ${n}…`); } });
  active(args);
  if (live.moving) throw new Error('The bridge state has a pending spend. Wait for confirmation, then rebuild.');
  if (!live.state.claimed || !live.state.claimedRoot) throw new Error('The current claimed-deposit set could not be verified.');
  const state = stateRecord({ ...live.state, claimed: [...live.state.claimed].sort((a, b) => a - b),
    claimed_root: live.state.claimedRoot, exec_block: live.state.execBlock }, 'Current state', false);
  if (live.outpoint.txid === feeTxid && live.outpoint.vout === feeVout) throw new Error('The bridge state cannot also be the fee coin.');
  const [current, fee] = await Promise.all([rawTransaction(esplora, live.outpoint.txid), rawTransaction(esplora, feeTxid)]);
  const stateOutput = current.tx.outputs[live.outpoint.vout];
  if (!stateOutput) throw new Error('The current state output does not exist.');
  same(bytesToHex(stateOutput.script), bytesToHex(core.stateScript(core.stateTree(manifest), live.state)), 'Current state script');
  const feeOutput = fee.tx.outputs[feeVout];
  if (!feeOutput || feeOutput.asset.kind !== 'explicit' || !feeOutput.asset.data || bytesToHex(feeOutput.asset.data) !== LIQUID_TESTNET_LBTC
    || feeOutput.value.kind !== 'explicit' || feeOutput.nonce.kind !== 'null' || feeOutput.value.amount === undefined
    || feeOutput.value.amount <= 0n || feeOutput.value.amount > 50_000n || !/^0014[0-9a-f]{40}$/.test(bytesToHex(feeOutput.script))) {
    throw new Error('Use a confirmed, explicit tL-BTC fee coin at a Humid address, between 1 and 50,000 sats.');
  }
  const recheck = async () => {
    active(args);
    same(quantity(await readEth('eth_chainId'), 'Ethereum chain'), Number(SEPOLIA_CHAIN_ID), 'Ethereum chain');
    await Promise.all([unspent(esplora, live.outpoint.txid, live.outpoint.vout, 'Bridge state'), unspent(esplora, feeTxid, feeVout, 'Fee coin')]);
    active(args);
  };
  await recheck();
  return { manifest, pins, live, state, recheck, input: { manifest, state, state_tx_hex: current.hex,
    state_vout: live.outpoint.vout, fee_tx_hex: fee.hex, fee_vout: feeVout } as ObjectValue };
}

function rangeLimit(error: unknown): number | null {
  const e = error as { message?: unknown; code?: unknown };
  const text = typeof e?.message === 'string' ? e.message : '';
  if (/10[ -]block|block range.*10\b|\b10\b.*block range/i.test(text)) return 10;
  if (e?.code === -32005 || /block range|range (?:is )?too (?:large|wide)|too many results|response size exceeded|query returned more/i.test(text)) return 0;
  return null;
}

async function depositLogs(args: CommonArgs, start: number, end: number): Promise<ObjectValue[]> {
  const logs: ObjectValue[] = [];
  let next = start, window = 2048, requests = 0;
  while (next <= end) {
    active(args);
    if (++requests > MAX_LOG_REQUESTS) throw new Error('Deposit history exceeds the bounded RPC scan. Use an RPC that accepts wider log ranges.');
    const last = Math.min(end, next + window - 1);
    args.progress?.(`Reading proven deposits, Sepolia blocks ${next} to ${last}…`);
    let answer: unknown;
    try {
      answer = await args.readEth('eth_getLogs', [{ address: args.instance.escrow, topics: [DEPOSIT_TOPIC],
        fromBlock: '0x' + next.toString(16), toBlock: '0x' + last.toString(16) }]);
    } catch (error) {
      active(args);
      const limit = rangeLimit(error);
      if (limit === null || window === 1 || (limit > 0 && last - next + 1 <= limit)) throw error;
      window = limit || Math.max(1, Math.floor((last - next + 1) / 2));
      continue;
    }
    active(args);
    if (!Array.isArray(answer) || answer.length + logs.length > MAX_ENTRIES) throw new Error('Deposit logs are invalid or exceed 10,000 entries.');
    for (const value of answer) {
      const log = object(value, 'Deposit log');
      const block = quantity(log.blockNumber, 'Deposit block');
      if (block < next || block > last || log.removed === true) throw new Error('RPC returned a removed deposit or one outside the requested finalized range.');
      logs.push(log);
    }
    next = last + 1;
  }
  return logs;
}

function decodeDeposits(logs: ObjectValue[], escrow: string, domain: string, wantAccumulator: string): [number, string][] {
  const deposits = logs.map((log) => {
    if (typeof log.address !== 'string' || log.address.toLowerCase() !== escrow || !Array.isArray(log.topics)
      || log.topics.length !== 2 || log.topics[0] !== DEPOSIT_TOPIC || typeof log.topics[1] !== 'string'
      || !/^0x[0-9a-f]{64}$/i.test(log.topics[1]) || typeof log.data !== 'string' || log.data.length > 514 || !/^0x(?:[0-9a-f]{2})+$/i.test(log.data)) {
      throw new Error('RPC returned a malformed Deposit event.');
    }
    const data = hexToBytes(log.data);
    const valueAt = (at: number) => BigInt('0x' + bytesToHex(data.subarray(at, at + 32)));
    if (data.length < 224 || valueAt(128) !== 160n) throw new Error('Deposit event has a noncanonical script offset.');
    const length = Number(valueAt(160));
    if (![22, 23, 25, 34].includes(length) || data.length !== 192 + Math.ceil(length / 32) * 32
      || data.subarray(192 + length).some((b) => b !== 0)) throw new Error('Deposit event has a noncanonical script length.');
    const event = depositEvent({ status: '0x1', blockNumber: log.blockNumber as string,
      logs: [{ address: log.address, topics: log.topics as string[], data: log.data }] }, escrow);
    if (!event || event.index > 0xffffffffn || event.units < 100_000n || event.units > 2_100_000_000_000_000n) throw new Error('Deposit index or amount is outside the bridge limits.');
    const script = bytesToHex(depositRecipient(event.script).script);
    const recipient = sha256(hexToBytes(script));
    const leaf = sha256(concat(hexToBytes(domain), bigToBytes(event.index, 8), bigToBytes(event.units, 8), recipient));
    same(bytesToHex(recipient), bytesToHex(data.subarray(32, 64)), 'Deposit recipient');
    same(bytesToHex(leaf), bytesToHex(data.subarray(64, 96)), 'Deposit leaf');
    return { index: Number(event.index), units: Number(event.units), script, leaf, accumulator: bytesToHex(data.subarray(96, 128)) };
  }).sort((a, b) => a.index - b.index);
  const zero: Uint8Array[] = [new Uint8Array(32)];
  for (let h = 0; h < 32; h++) zero.push(sha256(concat(zero[h], zero[h])));
  const frontier: Uint8Array[] = [];
  let accumulator = bytesToHex(sha256(concat(zero[32], bigToBytes(0n, 8))));
  deposits.forEach((deposit, i) => {
    if (deposit.index !== i) throw new Error('Deposit history is incomplete or contains duplicate indices.');
    let size = i, node = deposit.leaf;
    for (let h = 0; h < 32; h++) {
      if (size % 2 === 0) { frontier[h] = node; break; }
      node = sha256(concat(frontier[h], node)); size = Math.floor(size / 2);
    }
    node = zero[0]; size = i + 1;
    for (let h = 0; h < 32; h++) {
      node = size % 2 ? sha256(concat(frontier[h], node)) : sha256(concat(node, zero[h]));
      size = Math.floor(size / 2);
    }
    accumulator = bytesToHex(sha256(concat(node, bigToBytes(BigInt(i + 1), 8))));
    same(deposit.accumulator, accumulator, 'Deposit event accumulator');
  });
  if (accumulator !== wantAccumulator) throw new Error('The complete deposit history does not match the accumulator proven on Liquid.');
  return deposits.map((d) => [d.units, d.script]);
}

export async function prepareBrowserClaim(args: CommonArgs & { depositIndex: number }): Promise<Record<string, unknown>> {
  integer(args.depositIndex, 'Deposit index', 0xffffffff);
  const common = await prepareCommon(args);
  if (common.live.state.execBlock === undefined) {
    throw new Error('No deposits are proven on Liquid yet. Send a proof update first.');
  }
  const end = integer(common.live.state.execBlock, 'Proven Sepolia execution block');
  const start = integer(common.pins.ESCROW_DEPLOY_BLOCK, 'Escrow deployment block');
  if (end < start) throw new Error('The current Liquid state has not proven any escrow deposits.');
  const finalized = object(await args.readEth('eth_getBlockByNumber', ['finalized', false]), 'Finalized Sepolia block');
  if (quantity(finalized.number, 'Finalized block number') < end) throw new Error('The proven execution block is not finalized according to this Sepolia RPC.');
  const deposits = decodeDeposits(await depositLogs(args, start, end), args.instance.escrow,
    word(object(common.manifest.sepolia, 'Sepolia pins').deposit_domain, 'Deposit domain'), common.live.state.acc);
  if (args.depositIndex >= deposits.length) throw new Error('This deposit is not proven by the current Liquid state.');
  if ((common.state.claimed as number[]).includes(args.depositIndex)) throw new Error('This deposit has already been claimed.');
  await common.recheck();
  return { ...common.input, deposits, index: args.depositIndex };
}

export async function prepareBrowserUpdate(args: CommonArgs & { bundle: unknown }): Promise<Record<string, unknown>> {
  const bundle = object(args.bundle, 'Proof bundle');
  same(bundle.schema, 'zk-bridge/browser-proof', 'Proof bundle schema');
  if (bundle.compiled_program === undefined || bundle.compiled_program === null) {
    throw new Error('The proof bundle has no compiled proof. Run just proof-bundle again, then upload the new bundle.');
  }
  const compiled = object(bundle.compiled_program, 'Compiled proof');
  const compiledHex = (name: 'program_hex' | 'witness_hex') => {
    const value = compiled[name];
    if (typeof value !== 'string' || value.length === 0 || value.length > MAX_COMPILED_HEX || !/^(?:[0-9a-f]{2})+$/.test(value)) {
      throw new Error(`Compiled proof ${name} must be nonempty, lowercase byte hex of at most ${MAX_COMPILED_HEX / 2} bytes.`);
    }
    return value;
  };
  const compiledProgram = { program_hex: compiledHex('program_hex'), witness_hex: compiledHex('witness_hex'),
    cmr: word(compiled.cmr, 'Compiled proof CMR') };
  const common = await prepareCommon(args);
  same(compiledProgram.cmr, object(common.manifest.update_leaf, 'Update leaf').cmr, 'Compiled proof CMR');
  const identity = object(bundle.instance, 'Proof bundle instance');
  for (const section of ['liquid', 'sepolia', 'sp1']) same(canonical(identity[section]), canonical(common.manifest[section]), `Proof bundle ${section} pins`);
  for (const leaf of ['update', 'claim']) same(identity[`${leaf}_cmr`], object(common.manifest[`${leaf}_leaf`], `${leaf} leaf`).cmr, `Proof bundle ${leaf} CMR`);
  const old = stateRecord(bundle.state, 'Proof starting state', true);
  for (const key of ['head', 'lc', 'acc', 'claimed_root']) same(old[key], common.state[key], `Proof starting ${key}`);
  same(canonical(old.claimed), canonical(common.state.claimed), 'Proof starting claimed set');
  const next = stateRecord(bundle.new_state, 'Proof successor state', true);
  if ((next.head as number) <= (old.head as number)) throw new Error('The proof does not advance the finalized head.');
  same(canonical(next.claimed), canonical(old.claimed), 'Proof successor claimed set');
  same(next.claimed_root, old.claimed_root, 'Proof successor claimed root');
  integer(next.exec_block, 'Proof successor execution block'); word(next.exec_root, 'Proof successor execution root');
  if (typeof bundle.program !== 'string' || bundle.program.length === 0 || bundle.program.length > 16 * 1024 * 1024) throw new Error('Proof program is missing or oversized.');
  const program = utf8(bundle.program), update = object(common.manifest.update_leaf, 'Update leaf');
  same(bytesToHex(sha256(program)), word(update.text_sha256, 'Update program hash'), 'Proof program hash');
  same(program.length, integer(update.text_bytes, 'Update program byte count'), 'Proof program byte count');
  const witness = object(bundle.witness, 'Proof witness');
  if (Object.keys(witness).length !== 1 || !Object.hasOwn(witness, 'w_in')) throw new Error('Proof witness must contain exactly w_in.');
  core.storeFile(JSON.stringify(bundle.successor_store), { head: next.head as number, lc: next.lc as string }, 'Proof successor store');
  await common.recheck();
  // The source remains in the bundle for review. Execution uses only its compiled form.
  return { ...common.input, state: old, compiled_program: compiledProgram, new_state: next };
}
