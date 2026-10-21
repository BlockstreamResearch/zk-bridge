// `node bridge-core/cli.js deposits` writes the list a takeover's `assemble.py claim --deposits` reads (OPERATOR.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { depositList, depositLogs, pacedCall, redactRpc, rpcUrl } from '../cli.js';
import { DEPOSIT_TOPIC } from '../lib/bridge.js';

const ESCROW = '0x' + '42'.repeat(20);
const word = (n) => BigInt(n).toString(16).padStart(64, '0');

/** A Deposit log as BridgeDeposits emits it: index indexed; units, recipient, leaf, accumulator, scriptPubKey. */
function log(index, units, script, { address = ESCROW, removed = false } = {}) {
  const padded = script.padEnd(Math.ceil(script.length / 64) * 64, '0');
  const data = '0x' + word(units) + 'ab'.repeat(32) + 'cd'.repeat(32) + 'ef'.repeat(32) + word(160) + word(script.length / 2) + padded;
  return { address, topics: [DEPOSIT_TOPIC, '0x' + word(index)], data, removed };
}

const P2TR = '5120' + '78'.repeat(32);
const P2WPKH = '0014' + '11'.repeat(20);

test('the deposit list is [units, scriptPubKey] in index order, whatever order the logs came in', () => {
  const logs = [log(1, 250000, P2WPKH), log(0, 100000, P2TR)];
  assert.deepEqual(depositList(logs, ESCROW, 2n), [[100000, P2TR], [250000, P2WPKH]]);
});

test('logs of another contract and removed logs are not deposits', () => {
  const logs = [log(0, 100000, P2TR), log(1, 100000, P2TR, { address: '0x' + '43'.repeat(20) }), log(1, 100000, P2TR, { removed: true })];
  assert.deepEqual(depositList(logs, ESCROW, 1n), [[100000, P2TR]]);
});

test('a missing or repeated deposit, or a count other than the escrow\'s, is refused', () => {
  assert.throws(() => depositList([log(0, 100000, P2TR), log(2, 100000, P2TR)], ESCROW, 3n), /deposit #1 is missing or repeated/);
  assert.throws(() => depositList([log(0, 100000, P2TR), log(0, 100000, P2TR)], ESCROW, 2n), /deposit #1 is missing or repeated/);
  assert.throws(() => depositList([log(0, 100000, P2TR)], ESCROW, 2n), /the logs hold 1 deposits, but the escrow counted 2/);
});

test('the RPC URL is --rpc if given, else SEPOLIA_EXECUTION_RPC, and its absence names only the variable', () => {
  assert.equal(rpcUrl({ rpc: 'http://flag' }, { SEPOLIA_EXECUTION_RPC: 'http://env' }), 'http://flag');
  assert.equal(rpcUrl({}, { SEPOLIA_EXECUTION_RPC: 'http://env' }), 'http://env');
  assert.throws(() => rpcUrl({}, {}), /^Error: set SEPOLIA_EXECUTION_RPC or pass --rpc$/);
  assert.throws(() => rpcUrl({ rpc: '' }, {}), /set SEPOLIA_EXECUTION_RPC/);
});

const CLI = fileURLToPath(new URL('../cli.js', import.meta.url));

/** Runs the CLI with `env` added; resolves with its exit code and output, never rejecting. */
function cli(args, env) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { env: { ...process.env, SEPOLIA_EXECUTION_RPC: '', ...env } },
      (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr }));
  });
}

test('deposits reads the RPC URL from SEPOLIA_EXECUTION_RPC, without it on the command line or in its output', async (t) => {
  // A local stub at a path standing in for an API key: one finalized deposit at block 0x10.
  const SECRET = '/v3/not-a-real-key-0123456789';
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const { method } = JSON.parse(body);
      seen.push([req.url, method]);
      const result = { eth_getBlockByNumber: { number: '0x10' }, eth_getLogs: [log(0, 100000, P2WPKH)], eth_call: '0x' + word(1) }[method];
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}${SECRET}`;
  const out = join(mkdtempSync(join(tmpdir(), 'bridge-deposits-')), 'deposits.json');
  const args = ['deposits', '--escrow', ESCROW, '--from', '0', '--out', out];

  const r = await cli(args, { SEPOLIA_EXECUTION_RPC: url });
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(JSON.parse(readFileSync(out, 'utf8')), [[100000, P2WPKH]]);
  assert.equal(JSON.parse(r.stdout).to_block, 16);
  assert.ok(!(r.stdout + r.stderr).includes(SECRET));
  assert.deepEqual(seen.map(([u]) => u), [SECRET, SECRET, SECRET]);
  assert.deepEqual(seen.map(([, m]) => m), ['eth_getBlockByNumber', 'eth_getLogs', 'eth_call']);

  const unset = await cli(args, {});
  assert.equal(unset.code, 2);
  assert.equal(unset.stderr.trim(), 'set SEPOLIA_EXECUTION_RPC or pass --rpc');

  // --rpc works on its own, and wins over the environment.
  seen.length = 0;
  const flag = await cli([...args, '--rpc', url], { SEPOLIA_EXECUTION_RPC: 'http://127.0.0.1:9/unused' });
  assert.equal(flag.code, 0, flag.stderr);
  assert.equal(seen.length, 3);
});

test('deposits adapts to a 10-block eth_getLogs limit without losing ranges already read or exposing the RPC URL', async (t) => {
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const { method, params } = JSON.parse(body);
      res.setHeader('content-type', 'application/json');
      if (method === 'eth_getBlockByNumber') return res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { number: '0x26' } }));
      if (method === 'eth_call') return res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x' + word(2) }));
      const a = Number(params[0].fromBlock);
      const b = Number(params[0].toBlock);
      seen.push([a, b]);
      if (b - a + 1 > 10) {
        return res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, error: {
          message: `Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range. Endpoint: http://127.0.0.1:${server.address().port}/v2/fake-secret-123456?apiKey=query-secret-123456; token query-secret-123456`,
        } }));
      }
      const result = [...(a <= 16 && b >= 16 ? [log(0, 100000, P2TR)] : []),
        ...(a <= 38 && b >= 38 ? [log(1, 250000, P2WPKH)] : [])];
      return res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}/v2/fake-secret-123456?apiKey=query-secret-123456`;
  const out = join(mkdtempSync(join(tmpdir(), 'bridge-deposits-limit-')), 'deposits.json');
  const r = await cli(['deposits', '--escrow', ESCROW, '--from', '16', '--out', out], { SEPOLIA_EXECUTION_RPC: url });
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(seen, [[16, 38], [16, 25], [26, 35], [36, 38]]);
  assert.deepEqual(JSON.parse(readFileSync(out, 'utf8')), [[100000, P2TR], [250000, P2WPKH]]);
  assert.match(r.stderr, /at most 10 blocks per request/);
  assert.ok(!(r.stdout + r.stderr).includes('fake-secret-123456'));
  assert.ok(!(r.stdout + r.stderr).includes('query-secret-123456'));
});

/** A clock that `pacedCall` waits on without real time passing; `waits` records each wait. */
function fakeClock() {
  const c = { t: 0, waits: [] };
  c.now = () => c.t;
  c.wait = async (ms) => { c.waits.push(ms); c.t += ms; };
  return c;
}

const throttled = (retryAfter) => Object.assign(new Error('eth_getLogs failed: Your app has exceeded its compute units per second capacity.'), { rateLimited: true, retryAfter });

test('paced calls start at least the pace apart, back off on a rate limit, and slow the pace after one', async () => {
  const c = fakeClock();
  const lines = [];
  const replies = [null, throttled(), throttled(3000), null, null];
  const call = pacedCall(async () => { const e = replies.shift(); if (e) throw e; return c.t; },
    { pace: 100, retries: 3, backoff: 1000, wait: c.wait, now: c.now, log: (l) => lines.push(l) });
  assert.equal(await call('eth_getLogs', [], 'first'), 0);
  // 100 of pace; 1000 of backoff; the Retry-After's 3000, being over the doubled 2000; then the doubled pace, twice.
  assert.equal(await call('eth_getLogs', [], 'second'), 4100);
  assert.equal(await call('eth_getLogs', [], 'third'), 4500);
  assert.deepEqual(c.waits, [100, 1000, 3000, 400]);
  assert.deepEqual(lines, [
    'second was rate-limited; retry 1 of 3 in 1000 ms, then at most one request per 200 ms',
    'second was rate-limited; retry 2 of 3 in 3000 ms, then at most one request per 400 ms',
  ]);
});

test('a request rate-limited on every attempt fails after the retries, with waits capped at 30 s', async () => {
  const c = fakeClock();
  let calls = 0;
  const call = pacedCall(async () => { calls++; throw throttled(); }, { pace: 0, retries: 3, backoff: 20000, wait: c.wait, now: c.now, log: () => {} });
  await assert.rejects(call('eth_getLogs', [], 'eth_getLogs of blocks 0-9'), (e) => {
    assert.equal(e.exhausted, true);
    assert.match(e.message, /^eth_getLogs of blocks 0-9 was still rate-limited after 4 attempts and 80 s of backoff \(eth_getLogs failed: Your app has exceeded/);
    return true;
  });
  assert.equal(calls, 4);
  assert.deepEqual(c.waits, [20000, 30000, 30000]);

  // Any other failure is not retried.
  calls = 0;
  const other = pacedCall(async () => { calls++; throw new Error('eth_call failed: execution reverted'); }, { wait: c.wait, now: c.now });
  await assert.rejects(other('eth_call', []), /^Error: eth_call failed: execution reverted$/);
  assert.equal(calls, 1);
});

/** A paced eth_getLogs over blocks 0-25 that rate-limits blocks 10-19 `times` times; `seen` lists the ranges asked. */
function scan(times) {
  const c = fakeClock();
  const seen = [];
  const call = pacedCall(async (method, [{ fromBlock, toBlock }]) => {
    const a = Number(fromBlock);
    seen.push([a, Number(toBlock)]);
    if (a === 10 && times-- > 0) throw throttled();
    return [{ a }];
  }, { pace: 0, retries: 2, backoff: 10, wait: c.wait, now: c.now, log: () => {} });
  return { seen, logs: depositLogs(call, { escrow: ESCROW, from: 0, to: 25, step: 10, log: () => {} }) };
}

test('a rate-limited range is retried alone, keeping the ranges before it, and the scan continues', async () => {
  const { seen, logs } = scan(2);
  assert.deepEqual(await logs, [{ a: 0 }, { a: 10 }, { a: 20 }]);
  assert.deepEqual(seen, [[0, 9], [10, 19], [10, 19], [10, 19], [20, 25]]);
});

test('a range still rate-limited after its retries ends the scan with how far it got, and no smaller range is tried', async () => {
  const { seen, logs } = scan(Infinity);
  await assert.rejects(logs, (e) => {
    assert.equal(e.exhausted, true);
    assert.match(e.message, /^eth_getLogs of blocks 10-19 was still rate-limited after 3 attempts .*; blocks 0-9 were read, but the list needs every block up to 25$/);
    return true;
  });
  assert.deepEqual(seen, [[0, 9], [10, 19], [10, 19], [10, 19]]);
});

test('RPC diagnostics mask the URL, an API key path segment, query values and user info', () => {
  const url = 'https://opsuser01:pass-secret-99@eth-sepolia.g.alchemy.com/v2/alchemy-key-0123456789?apiKey=query-secret-123';
  const message = `at ${url}: key alchemy-key-0123456789, query-secret-123, opsuser01:pass-secret-99`;
  const masked = redactRpc(message, url);
  assert.equal(masked, 'at [RPC URL]: key [RPC credential], [RPC credential], [RPC credential]:[RPC credential]');
});

test('a malformed Deposit index from an RPC cannot echo its contents in a conversion error', () => {
  const malformed = log(0, 100000, P2TR);
  malformed.topics[1] = 'secret-from-provider-123456';
  assert.throws(() => depositList([malformed], ESCROW, 1n), (e) => {
    assert.equal(e.message, 'the Ethereum RPC returned an invalid Deposit log (details not shown)');
    assert.ok(!e.message.includes('secret-from-provider-123456'));
    return true;
  });
});

/** A JSON-RPC stub on 127.0.0.1: finalized block 0x26 and two deposits; `getLogs(a, b, res)` answers eth_getLogs. */
async function stub(t, getLogs) {
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      const { method, params } = JSON.parse(body);
      const reply = (result) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result })); };
      if (method === 'eth_getBlockByNumber') { seen.push([method, performance.now()]); return reply({ number: '0x26' }); }
      if (method === 'eth_call') { seen.push([method, performance.now()]); return reply('0x' + word(2)); }
      const [a, b] = [Number(params[0].fromBlock), Number(params[0].toBlock)];
      seen.push([[a, b], performance.now()]);
      if (getLogs(a, b, res)) return;
      return reply([...(a <= 16 && b >= 16 ? [log(0, 100000, P2TR)] : []), ...(a <= 38 && b >= 38 ? [log(1, 250000, P2WPKH)] : [])]);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  return { seen, url: `http://127.0.0.1:${server.address().port}/v2/fake-secret-123456?apiKey=query-secret-123456` };
}

test('deposits paces its requests and rides out Alchemy\'s compute-unit 429s without exposing the RPC URL', async (t) => {
  let limits = 2;
  const { seen, url } = await stub(t, (a, b, res) => {
    if (a !== 26 || limits-- <= 0) return false;
    res.writeHead(429, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, error: {
      code: 429, message: 'Your app has exceeded its compute units per second capacity (app fake-secret-123456, key query-secret-123456).',
    } }));
    return true;
  });
  const out = join(mkdtempSync(join(tmpdir(), 'bridge-deposits-429-')), 'deposits.json');
  const r = await cli(['deposits', '--escrow', ESCROW, '--from', '16', '--out', out, '--step', '10', '--pace', '50', '--backoff', '5'], { SEPOLIA_EXECUTION_RPC: url });
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(seen.map(([w]) => w), ['eth_getBlockByNumber', [16, 25], [26, 35], [26, 35], [26, 35], [36, 38], 'eth_call']);
  // The fake-clock test checks pacing exactly; network scheduling can move observed arrival times.
  assert.deepEqual(JSON.parse(readFileSync(out, 'utf8')), [[100000, P2TR], [250000, P2WPKH]]);
  assert.match(r.stderr, /eth_getLogs of blocks 26-35 was rate-limited; retry 1 of 6 in 5 ms, then at most one request per 100 ms/);
  assert.match(r.stderr, /eth_getLogs of blocks 26-35 was rate-limited; retry 2 of 6 in 10 ms, then at most one request per 200 ms/);
  assert.ok(!(r.stdout + r.stderr).includes('fake-secret-123456'));
  assert.ok(!(r.stdout + r.stderr).includes('query-secret-123456'));
});

test('deposits that stay rate-limited fail with a redacted reason and leave the previous deposits.json as it was', async (t) => {
  const { seen, url } = await stub(t, (a, b, res) => {
    if (a !== 26) return false;
    // A gateway's plain-text 429, here carrying the key; its body is never echoed.
    res.writeHead(429, { 'content-type': 'text/plain' });
    res.end(`Too Many Requests for ${url}`);
    return true;
  });
  const out = join(mkdtempSync(join(tmpdir(), 'bridge-deposits-exhausted-')), 'deposits.json');
  writeFileSync(out, 'previous\n');
  const r = await cli(['deposits', '--escrow', ESCROW, '--from', '16', '--out', out, '--step', '10', '--pace', '1', '--retries', '2', '--backoff', '5'], { SEPOLIA_EXECUTION_RPC: url });
  assert.equal(r.code, 2);
  assert.equal(r.stdout, '');
  const lines = r.stderr.trimEnd().split('\n');
  assert.equal(lines.length, 3);
  assert.match(lines[0], /^eth_getLogs of blocks 26-35 was rate-limited; retry 1 of 2 in 5 ms/);
  assert.match(lines[1], /^eth_getLogs of blocks 26-35 was rate-limited; retry 2 of 2 in 10 ms/);
  assert.match(lines[2], /^eth_getLogs of blocks 26-35 was still rate-limited after 3 attempts and 0 s of backoff \(eth_getLogs failed: HTTP 429 without a JSON-RPC body\); blocks 16-25 were read, but the list needs every block up to 38\. Nothing was written to .*deposits\.json; rerun once the provider's limit has reset, or with a larger --pace$/);
  assert.deepEqual(seen.map(([w]) => w), ['eth_getBlockByNumber', [16, 25], [26, 35], [26, 35], [26, 35]]);
  assert.equal(readFileSync(out, 'utf8'), 'previous\n');
  assert.deepEqual(readdirSync(dirname(out)), ['deposits.json']);
  assert.ok(!r.stderr.includes('fake-secret-123456'));
  assert.ok(!r.stderr.includes('query-secret-123456'));
});
