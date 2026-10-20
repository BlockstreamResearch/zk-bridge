#!/usr/bin/env node
// Operator commands over the same modules the web app uses. Read-only: nothing here signs or sends.
// Send the printed calldata with your own wallet tooling, e.g. `cast send <escrow> <calldata>`.
// --rpc takes a Sepolia JSON-RPC URL at run time; it is never printed or stored. deposits also reads it from
// SEPOLIA_EXECUTION_RPC when --rpc is absent, which keeps a URL carrying an API key out of the process list.
//
//   node ui/cli.js federation <header hex | @file | --esplora <api>>
//       the witness script, threshold and key y coordinates of a signed DynaFed header (default: the tip)
//   node ui/cli.js checkpoint --esplora <api> --epoch-length <L>
//       BridgeEscrow's Checkpoint for the last completed Liquid epoch: (L, height, hash, witnessScript, keyY)
//   node ui/cli.js burn-script <chain id> <escrow> <recipient>
//       the bare OP_RETURN scriptPubKey (BridgeEscrow.burnScriptPubKey) that redeems to <recipient> at <escrow>
//   node ui/cli.js relay --esplora <api> --rpc <url> --escrow <0x...> --target <height>
//       calldata of the next submitHeaders batch towards <target>; send it, wait, and run again
//   node ui/cli.js redeem --esplora <api> --rpc <url> --escrow <0x...> --txid <burn txid> --vout <n> --recipient <0x...> [--to <0x...>]
//       redeem() arguments and calldata, or how far the light client still has to be relayed; with --to,
//       redeemTo() calldata paying <to>, which only <recipient> itself can send
//   node ui/cli.js deposits [--rpc <url>] --escrow <0x...> --from <block> --out <deposits.json> [--to <block>] [--step <n>]
//                           [--pace <ms>] [--retries <n>] [--backoff <ms>]
//       the escrow's Deposit events up to the finalized block (or <to>), in index order, written as
//       `assemble.py claim --deposits` takes them: [units, "scriptPubKey hex"]. <from> is the instance's
//       ESCROW_DEPLOY_BLOCK; --step bounds each eth_getLogs range (default 2000). If the RPC refuses a range as
//       too large (JSON-RPC error -32005, or a block-range or response-size limit in its words, such as
//       Alchemy's free-tier 10 blocks), the reader asks again from the refused range's first block for as
//       many blocks as the RPC suggests, or half as many, and keeps that smaller range to the end.
//       Requests start at least --pace ms apart (default 250). A request the RPC rate-limits (HTTP 429, or
//       Alchemy's compute-units-per-second error) is retried up to --retries times (default 6) after
//       --backoff ms (default 1000), doubling up to 30 s, and every rate limit doubles the pace up to 5 s.
//       The file is written only once every range is read; if the retries run out, it is left untouched.
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { bytesToHex, hexToBytes, reversed } from './lib/bytes.js';
import { keccak256 } from './lib/hash.js';
import { blockSignatures, parseHeader } from './lib/elements.js';
import {
  DEPOSIT_TOPIC, burnTarget, decode, depositEvent, ethAddress, federationKeys, liftY, redeemCalldata, redeemToCalldata, submitHeadersCalldata, views,
} from './lib/bridge.js';
import { Esplora } from './lib/esplora.js';
import { redemption, relayBatches } from './lib/redeem.js';

function fail(msg) {
  console.error(msg);
  process.exit(2);
}

function opts(args, required) {
  const o = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!args[i].startsWith('--') || args[i + 1] === undefined) fail(`bad option ${args[i]}`);
    o[args[i].slice(2)] = args[i + 1];
  }
  for (const k of required) if (!o[k]) fail(`missing --${k}`);
  return o;
}

const hex = (b) => '0x' + bytesToHex(b);

/** `OP_m <key>... OP_n OP_CHECKMULTISIG` or `<key> OP_CHECKSIG`, as LiquidLightClient accepts them. */
export function federationOf(script) {
  if (script.length === 35 && script[0] === 0x21 && script[34] === 0xac) return { threshold: 1, keys: [script.subarray(1, 34)] };
  const n = (script.length - 3) / 34;
  const m = script[0] - 0x50;
  if (!Number.isInteger(n) || n < 1 || n > 16 || m < 1 || m > n || script[script.length - 2] !== 0x50 + n || script[script.length - 1] !== 0xae) {
    throw new Error('the witness script is not a multisig LiquidLightClient supports');
  }
  for (let i = 0; i < n; i++) if (script[1 + 34 * i] !== 0x21) throw new Error('the witness script has a non-compressed key');
  return { threshold: m, keys: federationKeys(script) };
}

function federationReport(headerHex) {
  const header = parseHeader(hexToBytes(headerHex));
  const { witnessScript, signatures } = blockSignatures(header);
  const { threshold, keys } = federationOf(witnessScript);
  if (signatures.length !== threshold) throw new Error(`header has ${signatures.length} signatures for a ${threshold}-of-${keys.length} script`);
  return {
    height: header.height,
    block_hash_display: bytesToHex(reversed(header.hash)),
    block_hash_internal: hex(header.hash),
    signblockscript: bytesToHex(header.signblockscript),
    signblockscript_keccak: hex(keccak256(header.signblockscript)),
    witness_script: hex(witnessScript),
    threshold,
    keys: keys.map((k) => bytesToHex(k)),
    key_y: keys.map((k) => '0x' + liftY(k).toString(16).padStart(64, '0')),
  };
}

/** `message` with the RPC URL and the credentials in it (an API key path segment, query values, user info) masked. */
export function redactRpc(message, url) {
  // Some providers put the credential-bearing endpoint in their error message.
  message = message.replaceAll(url, '[RPC URL]');
  try {
    const endpoint = new URL(url);
    const credential = endpoint.pathname.split('/').at(-1);
    if (credential?.length >= 12) message = message.replaceAll(credential, '[RPC credential]');
    for (const value of endpoint.searchParams.values()) {
      if (value.length >= 8) message = message.replaceAll(value, '[RPC credential]');
    }
    for (const value of [endpoint.username, endpoint.password]) {
      if (value.length >= 8) message = message.replaceAll(value, '[RPC credential]');
    }
  } catch { /* rpcUrl already reports a malformed URL through fetch */ }
  return message;
}

// Alchemy: HTTP 429, error code 429, "Your app has exceeded its compute units per second capacity". Other
// providers say "rate limit", "request rate" or "too many requests". A block-range limit is none of these.
const RATE_LIMITED = /compute units|rate.?limit|request rate|too many requests|throughput|capacity/i;

/** Retry-After in ms, as delta-seconds or an HTTP date; undefined if absent or unreadable. */
function retryAfterMs(header, now = Date.now()) {
  if (!header) return undefined;
  if (/^\d+$/.test(header.trim())) return Number(header) * 1000;
  const at = Date.parse(header);
  return Number.isNaN(at) ? undefined : Math.max(0, at - now);
}

async function rpcCall(url, method, params) {
  let res;
  try {
    res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  } catch {
    throw new Error('the Ethereum RPC is unreachable (URL not shown)');
  }
  let body;
  try {
    body = await res.json();
  } catch { /* a gateway's HTML or text page; its body is never echoed */ }
  if (body?.error || body === undefined || !res.ok) {
    const message = body?.error
      ? redactRpc(String(body.error.message ?? 'RPC error'), url)
      : `HTTP ${res.status}${body === undefined ? ' without a JSON-RPC body' : ''}`;
    const error = new Error(`${method} failed: ${message}`);
    if (body?.error) error.code = body.error.code;
    if (res.status === 429 || body?.error?.code === 429 || RATE_LIMITED.test(message)) {
      Object.assign(error, { rateLimited: true, retryAfter: retryAfterMs(res.headers.get('retry-after')) });
    }
    throw error;
  }
  return body.result;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const WAIT_MAX = 30_000;
const PACE_MAX = 5_000;

/**
 * `call(method, params)` paced for a long run of requests against a metered RPC, such as Alchemy's compute units
 * per second: requests start at least `pace` ms apart, and a rate-limited request is retried up to `retries` times,
 * first after `backoff` ms and then after twice the previous wait (or the RPC's Retry-After if longer), at most 30 s.
 * Each rate limit also doubles `pace`, up to 5 s, so the rest of the run stays under the limit it found. A request
 * still rate-limited after its retries throws an error marked `exhausted`; any other error passes through at once.
 */
export function pacedCall(call, { pace = 250, retries = 6, backoff = 1000, wait = sleep, now = Date.now, log = console.error } = {}) {
  let last = -Infinity;
  return async (method, params, what = method) => {
    let waited = 0;
    for (let attempt = 0; ; attempt++) {
      const gap = last + pace - now();
      if (gap > 0) await wait(gap);
      last = now();
      try {
        return await call(method, params);
      } catch (error) {
        if (!error.rateLimited) throw error;
        if (attempt === retries) {
          throw Object.assign(new Error(`${what} was still rate-limited after ${attempt + 1} attempts and ${Math.round(waited / 1000)} s of backoff (${error.message})`), { exhausted: true });
        }
        const ms = Math.min(WAIT_MAX, Math.max(backoff * 2 ** attempt, error.retryAfter ?? 0));
        pace = Math.max(pace, Math.min(PACE_MAX, Math.max(2 * pace, 100)));
        log(`${what} was rate-limited; retry ${attempt + 1} of ${retries} in ${ms} ms, then at most one request per ${pace} ms`);
        waited += ms;
        await wait(ms);
      }
    }
  };
}

function ethCall(url, to, block = 'latest') {
  return (data) => rpcCall(url, 'eth_call', [{ to, data }, block]);
}

/**
 * `assemble.py claim --deposits` from the escrow's Deposit logs: [units, scriptPubKey hex] in index order. Refuses a
 * gap, a repeat, or a count other than the escrow's depositCount() at the logs' last block, so a log range an RPC
 * silently dropped is caught here and not later as an accumulator the claim cannot reproduce.
 */
export function depositList(logs, escrow, count) {
  const events = logs.filter((l) => !l.removed).map((l) => {
    try {
      return depositEvent({ logs: [l] }, escrow);
    } catch {
      throw new Error('the Ethereum RPC returned an invalid Deposit log (details not shown)');
    }
  }).filter(Boolean)
    .sort((a, b) => (a.index < b.index ? -1 : a.index > b.index ? 1 : 0));
  events.forEach((e, i) => {
    if (e.index !== BigInt(i)) throw new Error(`deposit #${i} is missing or repeated in the logs; retry with a smaller --step`);
  });
  if (BigInt(events.length) !== count) throw new Error(`the logs hold ${events.length} deposits, but the escrow counted ${count} at that block`);
  return events.map((e) => [Number(e.units), e.script]);
}

/** The execution RPC URL: --rpc if given, else SEPOLIA_EXECUTION_RPC. Never echoed in errors. */
export function rpcUrl(o, env = process.env) {
  const url = o.rpc ?? env.SEPOLIA_EXECUTION_RPC;
  if (!url) throw new Error('set SEPOLIA_EXECUTION_RPC or pass --rpc');
  return url;
}

// eth_getLogs refusals that a smaller block range answers. Alchemy's free tier: "Under the Free tier plan, you can
// make eth_getLogs requests with up to a 10 block range. Based on your parameters, this block range should work:
// [0x..., 0x...]"; its paid tiers: "Log response size exceeded. ... up to a 2K block range ..."; Infura: "query
// returned more than 10000 results. Try with this block range [0x..., 0x...]"; others: "block range too large",
// "exceed maximum block range", "too many blocks".
const RANGE_LIMITED = /block range|range.*(large|wide|limit)|too many blocks|exceed.*blocks|response size|more than \d+ results/i;

// EIP-1474's "Limit exceeded". Providers send it for range limits and rate limits alike, so a rate limit is told
// apart by its words first (RATE_LIMITED, in rpcCall), and only then is the code read as a range limit.
const LIMIT_EXCEEDED = -32005;

/** Whether a failed eth_getLogs asks for fewer blocks. A rate limit never does: `call` retries it as it was. */
function rangeLimited(error) {
  if (error.rateLimited || error.exhausted) return false;
  return error.code === LIMIT_EXCEEDED || RANGE_LIMITED.test(String(error.message));
}

/**
 * How many blocks to ask for after an eth_getLogs of `width` blocks was refused with `message`: the size of the
 * range the RPC suggests, else its "up to N block range", else half of `width`. Always at least 1 and less than
 * `width`, which must be at least 2, so every refusal shrinks the scan's ranges and the refusals end.
 */
export function narrowedWidth(message, width) {
  const candidates = [];
  const suggested = /\[\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*\]/i.exec(message);
  if (suggested) candidates.push(Number(BigInt(suggested[2]) - BigInt(suggested[1]) + 1n));
  const stated = /up to (?:a )?(\d+)(k?) block range/i.exec(message);
  if (stated) candidates.push(Number(stated[1]) * (stated[2] ? 1000 : 1));

  for (const allowed of candidates) {
    if (Number.isSafeInteger(allowed) && allowed >= 1 && allowed < width) return allowed;
  }
  return Math.ceil(width / 2);
}

/** A log's identity: its block hash, its index in that block and whether it was removed, else all of it. */
function logKey(l) {
  if (typeof l?.blockHash === 'string' && typeof l?.logIndex === 'string') {
    return `${l.blockHash.toLowerCase()}:${l.logIndex.toLowerCase()}:${l.removed === true}`;
  }
  return JSON.stringify(l);
}

function readSoFar(from, next, to) {
  if (next === from) return `no block up to ${to} was read`;
  return `blocks ${from}-${next - 1} were read, but the list needs every block up to ${to}`;
}

/**
 * The escrow's Deposit logs over blocks from..to, read through `call` (a pacedCall) in consecutive ranges of at
 * most `step` blocks, each block in exactly one range that was read. A log the RPC returns more than once is kept
 * once.
 *
 * A range the RPC refuses as too large (rangeLimited) is asked again from its first block with fewer blocks
 * (narrowedWidth), and that smaller width is kept to the end: the ranges already read are kept, and as the width
 * only shrinks there are at most `step - 1` such refusals. A rate-limited range is retried as it was, inside `call`.
 * Every `progressEvery` ranges read, says how far the scan got.
 *
 * Throws, returning nothing, if a range cannot be read: on a refusal of a single block, on any other error, and on
 * a rate limit that outlasts `call`'s retries. The first and last also say how far the scan got.
 */
export async function depositLogs(call, { escrow, from, to, step, log = console.error, progressEvery = 100 }) {
  const logs = new Map();
  let width = step;
  let ranges = 0;

  for (let a = from; a <= to;) {
    const end = Math.min(to, a + width - 1);
    const what = `eth_getLogs of blocks ${a}-${end}`;
    const filter = { address: escrow, topics: [DEPOSIT_TOPIC], fromBlock: '0x' + a.toString(16), toBlock: '0x' + end.toString(16) };

    let result;
    try {
      result = await call('eth_getLogs', [filter], what);
    } catch (error) {
      if (error.exhausted) {
        throw Object.assign(new Error(`${error.message}; ${readSoFar(from, a, to)}`), { exhausted: true });
      }
      if (!rangeLimited(error)) throw error;
      if (end === a) {
        throw new Error(`${error.message}; the RPC refuses eth_getLogs even for block ${a} alone; ${readSoFar(from, a, to)}`);
      }

      // Alchemy's free tier, among others, limits eth_getLogs by block range. Retrying only the
      // refused range keeps every preceding result and never produces a partial deposits.json.
      width = narrowedWidth(String(error.message), end - a + 1);
      log(`eth_getLogs permits at most ${width} blocks per request; continuing from block ${a}, ${Math.ceil((to - a + 1) / width)} requests to go`);
      continue;
    }

    if (!Array.isArray(result)) throw new Error(`${what} returned something other than a list of logs (details not shown)`);
    for (const l of result) {
      const key = logKey(l);
      if (!logs.has(key)) logs.set(key, l);
    }

    a = end + 1;
    ranges++;
    if (ranges % progressEvery === 0 && a <= to) {
      log(`eth_getLogs read blocks ${from}-${end} of ${from}-${to} in ${ranges} ranges; ${logs.size} logs so far`);
    }
  }
  return [...logs.values()];
}

async function depositsCommand(o) {
  o = { ...o, rpc: rpcUrl(o) };
  const escrow = ethAddress(o.escrow);
  const from = Number(o.from);
  const step = Number(o.step ?? 2000);
  const [pace, retries, backoff] = [o.pace ?? 250, o.retries ?? 6, o.backoff ?? 1000].map(Number);
  if (![pace, retries, backoff].every(Number.isSafeInteger) || pace < 0 || retries < 0 || retries > 20 || backoff < 0) {
    fail('bad --pace, --retries or --backoff');
  }
  const call = pacedCall((method, params) => rpcCall(o.rpc, method, params), { pace, retries, backoff });
  try {
    // Claims cover only proven deposits, and a proof covers only finalized blocks: by default stop at finality.
    const block = o.to !== undefined ? null : await call('eth_getBlockByNumber', ['finalized', false], 'the finalized block');
    if (block && (typeof block.number !== 'string' || !/^0x[0-9a-fA-F]+$/.test(block.number))) {
      throw new Error('the Ethereum RPC returned an invalid finalized block number (details not shown)');
    }
    const to = o.to !== undefined ? Number(o.to) : Number(BigInt(block.number));
    if (![from, to, step].every(Number.isSafeInteger) || from < 0 || from > to || step < 1) fail('bad --from, --to or --step');
    const logs = await depositLogs(call, { escrow, from, to, step });
    const count = decode.uint(await call('eth_call', [{ to: escrow, data: views.depositCount() }, '0x' + to.toString(16)], 'depositCount()'));
    const list = depositList(logs, escrow, count);
    // A whole list or none: a crash mid-write leaves the temporary file, never a truncated deposits.json.
    const tmp = `${o.out}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(list) + '\n');
    renameSync(tmp, o.out);
    console.log(JSON.stringify({
      to_block: to, deposits: list.length, out: o.out,
      note: 'assemble.py claim pays one of these not yet claimed, and refuses the list unless its proven prefix gives the state\'s accumulator',
    }, null, 2));
  } catch (error) {
    if (!error.exhausted) throw error;
    throw new Error(`${error.message}. Nothing was written to ${o.out}; rerun once the provider's limit has reset, or with a larger --pace`);
  }
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === 'federation') {
    let h;
    if (rest[0] === '--esplora') h = await new Esplora(rest[1]).tipHeader();
    else if (rest[0]?.startsWith('@')) h = readFileSync(rest[0].slice(1), 'utf8').trim();
    else h = rest[0];
    if (!h) fail('federation needs a header');
    console.log(JSON.stringify(federationReport(h), null, 2));
  } else if (cmd === 'checkpoint') {
    const o = opts(rest, ['esplora', 'epoch-length']);
    const esplora = new Esplora(o.esplora);
    const L = Number(o['epoch-length']);
    const tip = await esplora.tipHeight();
    // The last epoch boundary whose successor block exists, so the next epoch's signing script is read
    // from a header actually signed in that epoch rather than predicted.
    const height = Math.floor(tip / L) * L - 1;
    if (height < 0) fail('no completed epoch yet');
    const [cpHeader, nextHeader] = await esplora.headers(height, height + 1);
    const cp = parseHeader(hexToBytes(cpHeader));
    const next = federationReport(nextHeader);
    console.log(JSON.stringify({
      note: 'BridgeEscrow(bridgeAsset, minConfirmations, maxRelayLag, admission, (epochLength, height, hash, witnessScript, keyY)); hash is internal byte order',
      epochLength: L, height, hash: hex(cp.hash), witnessScript: next.witness_script, keyY: next.key_y,
      checkpoint_hash_display: bytesToHex(reversed(cp.hash)), next_epoch_threshold: next.threshold,
    }, null, 2));
  } else if (cmd === 'burn-script') {
    const [chainId, escrow, recipient] = rest;
    if (!recipient) fail('burn-script <chain id> <escrow> <recipient>');
    const t = burnTarget(BigInt(chainId), ethAddress(escrow), ethAddress(recipient));
    console.log(JSON.stringify({
      scriptPubKey: bytesToHex(t.scriptPubKey), chain_id: t.chainId.toString(), escrow: t.escrow, recipient: t.recipient,
      note: 'burn with one explicit output of the bridge asset paying exactly this script; compare it with the escrow\'s burnScriptPubKey(recipient)',
    }, null, 2));
  } else if (cmd === 'relay') {
    const o = opts(rest, ['esplora', 'rpc', 'escrow', 'target']);
    const call = ethCall(o.rpc, ethAddress(o.escrow));
    const it = relayBatches({ esplora: new Esplora(o.esplora), call, target: Number(o.target) });
    const { value, done } = await it.next();
    if (done) {
      console.log(JSON.stringify({ relayed: true, note: 'the light client already covers the target' }));
      return;
    }
    console.log(JSON.stringify({
      first_height: value.firstHeight, count: value.headers.length, carries_new_keys: value.witnessScript.length > 0,
      calldata: submitHeadersCalldata(value), note: 'send this, wait for it to confirm, then run relay again',
    }, null, 2));
  } else if (cmd === 'redeem') {
    const o = opts(rest, ['esplora', 'rpc', 'escrow', 'txid', 'vout', 'recipient']);
    const to = o.to ? ethAddress(o.to) : null;
    const r = await redemption({ esplora: new Esplora(o.esplora), call: ethCall(o.rpc, ethAddress(o.escrow)), recipient: ethAddress(o.recipient), txid: o.txid.toLowerCase(), vout: Number(o.vout) });
    if (r.state !== 'ready') {
      console.log(JSON.stringify(r, null, 2));
      return;
    }
    const a = r.args;
    console.log(JSON.stringify({
      height: r.height, light_client_tip: r.tip,
      recipient: a.recipient, pay_to: to || a.recipient,
      burn: { transaction: hex(a.burn.transaction), vout: a.burn.vout, branch: a.burn.branch.map(hex), position: a.burn.position },
      ref: { batch: a.ref.batch, index: a.ref.index, path: a.ref.path.map(hex) },
      calldata: to ? redeemToCalldata({ to, burn: a.burn, ref: a.ref }) : redeemCalldata(a),
      ...(to ? { note: 'redeemTo: send this from the recipient account itself; from any other sender it reverts WrongBurnScript' } : {}),
    }, null, 2));
  } else if (cmd === 'deposits') {
    await depositsCommand(opts(rest, ['escrow', 'from', 'out']));
  } else {
    fail('usage: node ui/cli.js federation|checkpoint|burn-script|relay|redeem|deposits ... (see the header of ui/cli.js)');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((e) => fail(e.message));
