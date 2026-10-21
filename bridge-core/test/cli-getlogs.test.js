// `node bridge-core/cli.js deposits` against RPCs that bound eth_getLogs: Alchemy's free tier refuses more than 10 blocks per
// request, with JSON-RPC error -32005 or its own words. The scan must still read every block exactly once.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { depositList, depositLogs, narrowedWidth } from '../cli.js';
import { DEPOSIT_TOPIC } from '../lib/bridge.js';

const ESCROW = '0x' + '42'.repeat(20);
const word = (n) => BigInt(n).toString(16).padStart(64, '0');
const hex = (n) => '0x' + n.toString(16);

const P2TR = '5120' + '78'.repeat(32);
const P2WPKH = '0014' + '11'.repeat(20);

/** Deposit #index of `units` to `script` as an RPC returns it: in block `block`, the first log there. */
function depositLog(index, block, units, script, { removed = false } = {}) {
  const padded = script.padEnd(Math.ceil(script.length / 64) * 64, '0');
  const data = '0x' + word(units) + 'ab'.repeat(32) + 'cd'.repeat(32) + 'ef'.repeat(32) + word(160) + word(script.length / 2) + padded;
  return {
    address: ESCROW, topics: [DEPOSIT_TOPIC, '0x' + word(index)], data, removed,
    blockNumber: hex(block), blockHash: '0x' + word(block + 0xb10c), logIndex: '0x0',
  };
}

// Deposits at the scan's first and last blocks, on both sides of a 10-block boundary, and in between.
const DEPOSITS = [
  depositLog(0, 100, 100000, P2TR),
  depositLog(1, 109, 250000, P2WPKH),
  depositLog(2, 110, 300000, P2TR),
  depositLog(3, 555, 400000, P2WPKH),
  depositLog(4, 1234, 500000, P2TR),
];

const inRange = (a, b) => DEPOSITS.filter((l) => a <= Number(l.blockNumber) && Number(l.blockNumber) <= b);

/** Checks that `ranges` are consecutive, each at most `max` blocks, and together exactly blocks from..to. */
function assertCovers(ranges, from, to, max) {
  assert.ok(ranges.length > 0);
  assert.equal(ranges[0][0], from);
  assert.equal(ranges.at(-1)[1], to);
  ranges.forEach(([a, b], i) => {
    assert.ok(a <= b && b - a + 1 <= max, `range ${a}-${b} is not 1 to ${max} blocks`);
    if (i > 0) assert.equal(a, ranges[i - 1][1] + 1, `range ${a}-${b} does not follow ${ranges[i - 1][1]}`);
  });
}

const CLI = fileURLToPath(new URL('../cli.js', import.meta.url));

/** Runs the CLI with `env` added; resolves with its exit code and output, never rejecting. */
function cli(args, env) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { env: { ...process.env, SEPOLIA_EXECUTION_RPC: '', ...env } },
      (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr }));
  });
}

/**
 * A JSON-RPC stub on 127.0.0.1: finalized block 1234 and DEPOSITS. `getLogs(a, b)` answers eth_getLogs of blocks
 * a..b with [status, body]; `seen` lists the ranges asked.
 */
async function stub(t, getLogs) {
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      const { method, params } = JSON.parse(body);
      const send = (status, reply) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, ...reply }));
      };
      if (method === 'eth_getBlockByNumber') return send(200, { result: { number: hex(1234) } });
      if (method === 'eth_call') return send(200, { result: '0x' + word(inRange(0, Number(params[1])).length) });

      const [a, b] = [Number(params[0].fromBlock), Number(params[0].toBlock)];
      seen.push([a, b]);
      return send(...getLogs(a, b));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  return { seen, url: `http://127.0.0.1:${server.address().port}/v2/fake-secret-123456` };
}

test('deposits reads every block exactly once past Alchemy\'s free-tier -32005, keeping each log once', async (t) => {
  const { seen, url } = await stub(t, (a, b) => {
    if (b - a + 1 > 10) {
      return [400, { error: {
        code: -32005,
        message: 'Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range. '
          + `Based on your parameters, this block range should work: [${hex(a)}, ${hex(a + 9)}]. Upgrade to PAYG for expanded block range.`,
      } }];
    }
    // A provider glitch: deposit #3 twice in one answer, and #1 again in the range after its own.
    const result = inRange(a, b);
    if (a <= 555 && 555 <= b) result.push(DEPOSITS[3]);
    if (a === 110) result.push(DEPOSITS[1]);
    return [200, { result }];
  });
  const out = join(mkdtempSync(join(tmpdir(), 'bridge-getlogs-')), 'deposits.json');
  const r = await cli(['deposits', '--escrow', ESCROW, '--from', '100', '--out', out, '--pace', '0'], { SEPOLIA_EXECUTION_RPC: url });
  assert.equal(r.code, 0, r.stderr);

  // One refusal of the default 2000 blocks, then the suggested 10 blocks per request through the finalized block.
  assert.deepEqual(seen[0], [100, 1234]);
  const read = seen.slice(1);
  assert.equal(read.length, 114);
  assertCovers(read, 100, 1234, 10);

  assert.deepEqual(JSON.parse(readFileSync(out, 'utf8')), [[100000, P2TR], [250000, P2WPKH], [300000, P2TR], [400000, P2WPKH], [500000, P2TR]]);
  assert.equal(JSON.parse(r.stdout).to_block, 1234);
  assert.deepEqual(r.stderr.trimEnd().split('\n'), [
    'eth_getLogs permits at most 10 blocks per request; continuing from block 100, 114 requests to go',
    'eth_getLogs read blocks 100-1099 of 100-1234 in 100 ranges; 4 logs so far',
  ]);
  assert.ok(!(r.stdout + r.stderr).includes('fake-secret-123456'));
});

test('a -32005 that is a rate limit in its words is retried as it was, never split', async (t) => {
  let limits = 2;
  const { seen, url } = await stub(t, (a, b) => {
    if (a === 110 && limits-- > 0) return [200, { error: { code: -32005, message: 'daily request count exceeded, request rate limited' } }];
    return [200, { result: inRange(a, b) }];
  });
  const out = join(mkdtempSync(join(tmpdir(), 'bridge-getlogs-rate-')), 'deposits.json');
  const r = await cli(['deposits', '--escrow', ESCROW, '--from', '100', '--to', '139', '--out', out, '--step', '10', '--pace', '0', '--backoff', '1'],
    { SEPOLIA_EXECUTION_RPC: url });
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(seen, [[100, 109], [110, 119], [110, 119], [110, 119], [120, 129], [130, 139]]);
  assert.deepEqual(JSON.parse(readFileSync(out, 'utf8')), [[100000, P2TR], [250000, P2WPKH], [300000, P2TR]]);
  assert.doesNotMatch(r.stderr, /permits at most/);
});

/** An unpaced eth_getLogs over `answer(a, b)`, which returns logs or throws; `seen` lists the ranges asked. */
function provider(answer) {
  const seen = [];
  const call = async (method, [{ fromBlock, toBlock }]) => {
    assert.equal(method, 'eth_getLogs');
    const [a, b] = [Number(fromBlock), Number(toBlock)];
    seen.push([a, b]);
    return answer(a, b);
  };
  return { seen, call };
}

/** The error rpcCall throws for a JSON-RPC error body. */
const rpcError = (code, message) => Object.assign(new Error(`eth_getLogs failed: ${message}`), { code });

test('a bare -32005 halves the range until the RPC answers, and the scan keeps that width', async () => {
  const { seen, call } = provider((a, b) => {
    if (b - a + 1 > 10) throw rpcError(-32005, 'limit exceeded');
    return inRange(a, b);
  });
  const lines = [];
  const logs = await depositLogs(call, { escrow: ESCROW, from: 100, to: 199, step: 64, log: (l) => lines.push(l) });

  assert.deepEqual(seen.slice(0, 4), [[100, 163], [100, 131], [100, 115], [100, 107]]);
  assertCovers(seen.slice(3), 100, 199, 8);
  assert.equal(seen.length, 3 + 13);
  assert.deepEqual(depositList(logs, ESCROW, 3n), [[100000, P2TR], [250000, P2WPKH], [300000, P2TR]]);
  assert.deepEqual(lines, [
    'eth_getLogs permits at most 32 blocks per request; continuing from block 100, 4 requests to go',
    'eth_getLogs permits at most 16 blocks per request; continuing from block 100, 7 requests to go',
    'eth_getLogs permits at most 8 blocks per request; continuing from block 100, 13 requests to go',
  ]);
});

test('a limit that appears mid-scan narrows from the refused range, keeping the ranges before it', async () => {
  // A response-size limit: the dense blocks from 500 on answer at most 100 blocks at a time.
  const { seen, call } = provider((a, b) => {
    if (b >= 500 && b - a + 1 > 100) {
      throw rpcError(-32602, `Log response size exceeded. You can make eth_getLogs requests with up to a 2K block range and no limit on the response size, or you can request any block range with a cap of 10K logs in the response. Based on your parameters, this block range should work: [${hex(a)}, ${hex(a + 99)}]`);
    }
    return inRange(a, b);
  });
  const logs = await depositLogs(call, { escrow: ESCROW, from: 100, to: 1234, step: 300, log: () => {} });

  assert.deepEqual(seen.slice(0, 3), [[100, 399], [400, 699], [400, 499]]);
  assertCovers([seen[0], ...seen.slice(2)], 100, 1234, 300);
  assert.ok(seen.slice(2).every(([a, b]) => b - a + 1 <= 100));
  assert.equal(depositList(logs, ESCROW, 5n).length, 5);
});

test('the refusals end: a single refused block is an explicit error that says how far the scan got', async () => {
  const { seen, call } = provider((a, b) => {
    if (a >= 120) throw rpcError(-32005, 'limit exceeded');
    return inRange(a, b);
  });
  await assert.rejects(depositLogs(call, { escrow: ESCROW, from: 100, to: 199, step: 20, log: () => {} }), (e) => {
    assert.equal(e.message, 'eth_getLogs failed: limit exceeded; the RPC refuses eth_getLogs even for block 120 alone; blocks 100-119 were read, but the list needs every block up to 199');
    assert.equal(e.exhausted, undefined);
    return true;
  });
  assert.deepEqual(seen, [[100, 119], [120, 139], [120, 129], [120, 124], [120, 122], [120, 121], [120, 120]]);
});

test('an error that is not a range limit ends the scan at once', async () => {
  const { seen, call } = provider(() => {
    throw rpcError(-32602, 'invalid argument 0: hex string has leading zero digits');
  });
  await assert.rejects(depositLogs(call, { escrow: ESCROW, from: 100, to: 199, step: 10, log: () => {} }),
    /^Error: eth_getLogs failed: invalid argument 0: hex string has leading zero digits$/);
  assert.deepEqual(seen, [[100, 109]]);

  const list = provider(() => ({ logs: [] }));
  await assert.rejects(depositLogs(list.call, { escrow: ESCROW, from: 100, to: 199, step: 10, log: () => {} }),
    /^Error: eth_getLogs of blocks 100-109 returned something other than a list of logs \(details not shown\)$/);
});

test('a log returned twice is kept once, but a removed log and its replacement are both kept', async () => {
  const removed = depositLog(1, 109, 250000, P2WPKH, { removed: true });
  const { call } = provider((a, b) => [...inRange(a, b), ...inRange(a - 1, b), ...(a === 100 ? [removed] : [])]);
  const logs = await depositLogs(call, { escrow: ESCROW, from: 100, to: 1234, step: 10, log: () => {} });

  assert.equal(logs.length, DEPOSITS.length + 1);
  assert.deepEqual(logs.filter((l) => l.removed), [removed]);
  assert.equal(depositList(logs, ESCROW, 5n).length, 5);
});

test('progress is reported every so many ranges, but not after the last', async () => {
  const { call } = provider((a, b) => inRange(a, b));
  const lines = [];
  await depositLogs(call, { escrow: ESCROW, from: 100, to: 159, step: 10, log: (l) => lines.push(l), progressEvery: 2 });
  assert.deepEqual(lines, [
    'eth_getLogs read blocks 100-119 of 100-159 in 2 ranges; 3 logs so far',
    'eth_getLogs read blocks 100-139 of 100-159 in 4 ranges; 3 logs so far',
  ]);
});

test('the narrowed width is the RPC\'s suggestion if it is smaller, else half, and always shrinks', () => {
  const alchemy = 'Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range.';
  assert.equal(narrowedWidth(alchemy, 2000), 10);
  assert.equal(narrowedWidth(`${alchemy} Based on your parameters, this block range should work: [0x8d1b20, 0x8d1b29].`, 2000), 10);
  assert.equal(narrowedWidth('query returned more than 10000 results. Try with this block range [0x0, 0x2b5].', 2000), 694);
  assert.equal(narrowedWidth('You can make eth_getLogs requests with up to a 2K block range', 5000), 2000);

  // A suggestion no smaller than the refused range, or backwards, is not one.
  assert.equal(narrowedWidth(alchemy, 10), 5);
  assert.equal(narrowedWidth('this block range should work: [0x10, 0x1]', 7), 4);
  assert.equal(narrowedWidth('block range too large', 3), 2);
  assert.equal(narrowedWidth('block range too large', 2), 1);
});
