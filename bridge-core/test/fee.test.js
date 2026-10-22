import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeSegwit } from '../lib/bech32.js';
import { bytesToHex, concat, hexToBytes } from '../lib/bytes.js';
import { displayHex, parseTransaction } from '../lib/elements.js';
import { HUMID_SCOPE } from '../lib/humid.js';
import { discoverFeeCoins, feeBroadcastMatches, prepareFeeWithHumid, releaseFeePreparationInputs } from '../lib/fee.js';
import { LBTC, blinded, explicit, hex, signedWitness, transaction, word } from './liquid-tx.js';
import { ELEMENTS, psetTransaction, readPset } from './pset-reader.js';

const GENESIS = 'a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1';
const TLQ = 'tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn';
const SCRIPT = hex('0014d0c4a3ef09e997b6e99e397e518fe3e41a118ca1');
const ADDRESS = encodeSegwit('tex', 0, SCRIPT.subarray(2));
const DEST_SCRIPT = hex('0014' + word('rotated receive address').slice(0, 40));
const DEST = encodeSegwit('tex', 0, DEST_SCRIPT.subarray(2));
const assetId = `${HUMID_SCOPE}/elip144:${displayHex(LBTC)}`;

function source(label, confidential = false, sats = 10_000n) {
  const output = confidential ? blinded(hex('0a' + word('asset')), hex('08' + word('value')), SCRIPT) : explicit(LBTC, sats, SCRIPT);
  let tx = transaction({ inputs: [{ txid: word(label), vout: 0, witness: signedWitness(label) }], outputs: [output] });
  if (confidential) tx = withNonce(tx, 0);
  const coin = { txid: tx.txid, vout: 0, amount: String(sats), assetId, scriptPubKey: bytesToHex(SCRIPT),
    address: confidential ? TLQ : ADDRESS, spendable: true };
  return { tx, coin, sats };
}

// The independent test serializer uses null nonces for covenant outputs. Wallet
// change needs an ephemeral nonce, so add that field to this synthetic fixture.
function walletResult(pset, { mutate = (spec) => spec, confidential = false } = {}) {
  const unsigned = parseTransaction(psetTransaction(readPset(pset)));
  let spec = {
    inputs: unsigned.inputs.map((i) => ({ txid: displayHex(i.prevTxid), vout: i.n, sequence: i.sequence, witness: signedWitness('fee preparation') })),
    outputs: unsigned.outputs.map((o) => explicit(o.asset.data, o.value.amount, o.script)),
  };
  if (confidential) spec.outputs[1] = blinded(hex('0b' + word('change asset')), hex('09' + word('change value')), spec.outputs[1].script);
  spec = mutate(spec);
  const result = transaction(spec);
  if (!confidential) return result;
  return withNonce(result, 1);
}

function withNonce(result, index) {
  const parsed = parseTransaction(result.raw);
  const old = parsed.outputs[index].raw;
  const nonceAt = old.byteOffset - result.raw.byteOffset + 66;
  const raw = concat(result.raw.subarray(0, nonceAt), hex('02' + word('ephemeral nonce')), result.raw.subarray(nonceAt + 1));
  return { raw, hex: bytesToHex(raw), txid: displayHex(parseTransaction(raw).txid) };
}

function fixture(label, { confidential = false, sign, mutate } = {}) {
  const funding = source(label, confidential);
  const transactions = new Map([[funding.tx.txid, funding.tx.hex]]);
  const calls = [];
  const api = {
    blockHashAt: async () => GENESIS,
    txHex: async (id) => { if (!transactions.has(id)) throw new Error('not found'); return transactions.get(id); },
    txStatus: async () => ({ confirmed: true }),
    outspend: async () => ({ spent: false }),
    addressUtxos: async () => [{ txid: funding.tx.txid, vout: 0, value: Number(funding.sats), asset: displayHex(LBTC), status: { confirmed: true } }],
  };
  const humid = { async request({ method, params }) {
    if (method === 'wallet_getSession') return { sessionScopes: { [HUMID_SCOPE]: { methods: ['signPset', 'getUTXOs'] } } };
    const request = params.request;
    calls.push(request);
    if (request.method === 'getUTXOs') return { utxos: [funding.coin] };
    if (sign) return sign(request.params);
    const sent = walletResult(request.params.pset, { confidential, mutate });
    transactions.set(sent.txid, sent.hex);
    return { txid: sent.txid };
  } };
  return { funding, transactions, calls, api, humid,
    run: (options = {}) => prepareFeeWithHumid({ humid, esplora: api, address: DEST, sats: 2_000n, ...options }) };
}

test('discovery verifies raw explicit outputs and statuses, preserves amount and parent bytes', async () => {
  const f = fixture('discover');
  const found = await discoverFeeCoins({ esplora: f.api, address: ADDRESS });
  assert.deepEqual(found, [{ txid: f.funding.tx.txid, vout: 0, sats: 10_000n, txHex: f.funding.tx.hex, address: ADDRESS, script: SCRIPT }]);
  assert.deepEqual(await discoverFeeCoins({ esplora: f.api, address: ADDRESS, minSats: 546n, maxSats: 9_999n }), []);
  assert.deepEqual(await discoverFeeCoins({ esplora: f.api, address: ADDRESS, skip: new Set([`${f.funding.tx.txid}:0`]) }), []);
  f.api.outspend = async () => ({ spent: true });
  assert.deepEqual(await discoverFeeCoins({ esplora: f.api, address: ADDRESS }), []);
  f.api.outspend = async () => ({ spent: false });
  f.api.txStatus = async () => ({ confirmed: false });
  assert.deepEqual(await discoverFeeCoins({ esplora: f.api, address: ADDRESS }), []);
});

test('discovery rejects wrong chain/address/txid, false output amounts, invalid outpoints and statuses', async () => {
  const f = fixture('discovery adversarial');
  const run = (options = {}) => discoverFeeCoins({ esplora: f.api, address: ADDRESS, ...options });
  await assert.rejects(run({ address: encodeSegwit('ert', 0, SCRIPT.subarray(2)) }), /valid Humid unconfidential testnet address/);
  await assert.rejects(run({ address: TLQ }), /[Uu]nconfidential/);
  await assert.rejects(run({ address: DEST }), /differs/);
  await assert.rejects(run({ maxSats: 50_001n }), /Maximum fee/);
  f.api.blockHashAt = async () => word('other chain');
  await assert.rejects(run(), /Liquid testnet/);
  f.api.blockHashAt = async () => GENESIS;
  f.api.txHex = async () => source('different transaction').tx.hex;
  await assert.rejects(run(), /different transaction/);
  f.api.txHex = async () => f.funding.tx.hex;
  f.api.outspend = async () => ({});
  await assert.rejects(run(), /coin status/);
  f.api.outspend = async () => ({ spent: false });
  const listed = (await f.api.addressUtxos())[0];
  f.api.addressUtxos = async () => [{ ...listed, value: listed.value - 1 }];
  await assert.rejects(run(), /differs/);
  f.api.addressUtxos = async () => [{ ...listed, vout: -1 }];
  await assert.rejects(run(), /invalid outpoint/);
  f.api.addressUtxos = async () => [listed, listed];
  await assert.rejects(run(), /duplicate/);
  f.api.addressUtxos = async () => Array(257).fill(listed);
  await assert.rejects(run(), /duplicate/);
  f.api.addressUtxos = async () => Array(10_001).fill(listed);
  await assert.rejects(run(), /at most 10000/);
});

test('discovery remains bounded with more than 32 matching outputs and ordinary address dust', async () => {
  const f = fixture('dust address');
  const sources = Array.from({ length: 300 }, (_, index) => source(`dust ${index}`, false, index < 260 ? 1n : 600n + BigInt(index)));
  f.api.addressUtxos = async () => sources.map(({ tx, sats }) => ({ txid: tx.txid, vout: 0,
    value: Number(sats), asset: displayHex(LBTC), status: { confirmed: true } }));
  let reads = 0;
  f.api.txHex = async (txid) => { reads++; return sources.find(({ tx }) => tx.txid === txid).tx.hex; };
  const found = await discoverFeeCoins({ esplora: f.api, address: ADDRESS });
  assert.equal(found.length, 32);
  assert.equal(reads, 32);
  assert.equal(found[0].sats, 860n);
  assert.equal(found[31].sats, 891n);
});

test('an explicit source prepares the chosen exact fee, change and miner fee in the browser', async () => {
  const f = fixture('explicit preparation');
  let spent;
  const result = await f.run({ onSign: (outpoints) => { spent = outpoints; assert.equal(f.calls.length, 1); } });
  assert.equal(result.confirmed, false);
  assert.equal(result.address, DEST, 'the user may choose a rotated receive address');
  assert.deepEqual(spent, [`${f.funding.tx.txid}:0`]);
  assert.equal(result.plan.blindIndex, -1);
  assert.equal(result.plan.changeSats, 7_500n);
  const pset = readPset(result.plan.pset);
  const tx = parseTransaction(psetTransaction(pset));
  assert.deepEqual(tx.outputs.map((o) => [o.value.amount, bytesToHex(o.script)]), [[2_000n, bytesToHex(DEST_SCRIPT)], [7_500n, bytesToHex(SCRIPT)], [500n, '']]);
  assert.deepEqual(result.plan.signInputs, [{ address: ADDRESS, index: 0, sighashTypes: [1] }]);
  assert.equal(f.calls[1].params.broadcast, true);
  assert.equal(feeBroadcastMatches(result.plan, result.txHex, result.txid), null);
  await assert.rejects(f.run(), /needs a confirmed/, 'the same source is reserved after success');
});

test('a confidential source carries its proof and blinds only change to its own address', async () => {
  const f = fixture('confidential preparation', { confidential: true });
  const result = await f.run();
  const pset = readPset(result.plan.pset);
  assert.ok(pset.inputs[0].get(`${ELEMENTS}0e`).length > 4_000);
  assert.equal(bytesToHex(pset.outputs[1].get(`${ELEMENTS}08`)), '00000000');
  assert.equal(pset.outputs[1].get(`${ELEMENTS}06`).length, 33);
  assert.ok(!pset.outputs[0].has(`${ELEMENTS}06`));
  assert.ok(!pset.outputs[2].has(`${ELEMENTS}06`));
  assert.equal(result.plan.blindIndex, 1);
  assert.equal(result.plan.signInputs[0].address, TLQ);
  assert.equal(parseTransaction(hexToBytes(result.txHex)).outputs[0].value.amount, 2_000n);
  assert.equal(feeBroadcastMatches(result.plan, result.txHex, result.txid), null);
});

test('source validation prevents signing wrong network, amount, script, raw bytes or spent inputs', async () => {
  for (const [label, change, pattern] of [
    ['wrong chain', (f) => { f.api.blockHashAt = async () => word('wrong'); }, /Liquid testnet/],
    ['wrong amount', (f) => { f.funding.coin.amount = '10001'; }, /amount it listed/],
    ['wrong address', (f) => { f.funding.coin.address = DEST; }, /different script/],
    ['wrong txid', (f) => { f.api.txHex = async () => source('other raw').tx.hex; }, /different transaction/],
    ['spent', (f) => { f.api.outspend = async () => ({ spent: true }); }, /needs a confirmed/],
    ['unconfirmed', (f) => { f.api.txStatus = async () => ({ confirmed: false }); }, /needs a confirmed/],
    ['unsafe amount', (f) => { f.funding.coin.amount = '9999999999999999'; }, /Wallet coin/],
  ]) {
    const f = fixture(label);
    change(f);
    await assert.rejects(f.run(), pattern);
    assert.ok(!f.calls.some((request) => request.method === 'signPset'));
  }
  const f = fixture('invalid prepared amount');
  for (const sats of [0n, 545n, 50_001n, 2_000, '2000']) await assert.rejects(f.run({ sats }), /Prepared fee/);
});

test('exact result checks reject altered amount, fee, change, sequence and txid as possibly sent', async () => {
  for (const [label, mutate] of [
    ['amount', (spec) => { spec.outputs[0].amount--; return spec; }],
    ['fee', (spec) => { spec.outputs[2].amount++; return spec; }],
    ['change', (spec) => { spec.outputs[1].script = DEST_SCRIPT; return spec; }],
    ['sequence', (spec) => { spec.inputs[0].sequence = 1; return spec; }],
    ['extra output', (spec) => { spec.outputs.push(explicit(LBTC, 1n, SCRIPT)); return spec; }],
  ]) {
    const f = fixture(`altered ${label}`, { mutate });
    const failure = await f.run().catch((e) => e);
    assert.equal(failure.sent, 'maybe', label);
    assert.match(failure.txid, /^[a-f0-9]{64}$/);
    assert.equal(failure.spends[0], `${f.funding.tx.txid}:0`);
    await assert.rejects(f.run(), /needs a confirmed/, 'possibly spent source remains reserved');
  }
  const missing = fixture('missing broadcast', { sign: () => ({ txid: word('missing') }) });
  const failure = await missing.run().catch((e) => e);
  assert.equal(failure.sent, 'maybe');
  assert.equal(failure.txid, word('missing'));
  const substituted = fixture('substituted reply');
  const txHex = substituted.api.txHex;
  substituted.api.txHex = async (id) => id === substituted.funding.tx.txid ? txHex(id) : substituted.funding.tx.hex;
  const wrong = await substituted.run().catch((e) => e);
  assert.equal(wrong.sent, 'maybe');
  assert.match(wrong.message, /different transaction/);
});

test('explicit declines release the reservation; unknown errors and timeouts preserve it', async () => {
  for (const reason of ['user_rejected', 'invalid_pset_request']) {
    const f = fixture(`decline ${reason}`, { sign: () => { throw Object.assign(new Error(reason), { data: { reason } }); } });
    for (let i = 0; i < 2; i++) assert.equal((await f.run().catch((e) => e)).sent, 'no');
    assert.equal(f.calls.filter((request) => request.method === 'signPset').length, 2);
  }
  for (const [label, sign] of [
    ['lost reply', () => { throw new Error('transport stopped'); }],
    ['broadcast failed', () => { throw Object.assign(new Error('failed'), { data: { reason: 'wallet_pset_broadcast_failed' } }); }],
    ['no txid', () => ({})],
    ['timeout', () => new Promise(() => {})],
  ]) {
    const f = fixture(label, { sign });
    assert.equal((await f.run({ deadlineMs: 10 }).catch((e) => e)).sent, 'maybe');
    await assert.rejects(f.run(), /needs a confirmed/);
  }
});

test('concurrent requests and a spend discovered immediately before signing are blocked', async () => {
  let release;
  const f = fixture('concurrent');
  const first = f.run({ onSign: () => new Promise((resolve) => { release = resolve; }) });
  while (!release) await new Promise((resolve) => setTimeout(resolve, 1));
  await assert.rejects(f.run(), /already open/);
  assert.throws(() => releaseFeePreparationInputs([`${f.funding.tx.txid}:0`]), /still open/);
  release();
  await first;
  const raced = fixture('spent before sign');
  let calls = 0;
  raced.api.outspend = async () => ({ spent: ++calls > 1 });
  await assert.rejects(raced.run(), /no longer available/);
  assert.ok(!raced.calls.some((request) => request.method === 'signPset'));
});

test('explicitly reviewed holds can be released without sending or clearing other held inputs', async () => {
  const f = fixture('reviewed hold', { sign: () => { throw new Error('reply lost'); } });
  const other = fixture('other hold', { sign: () => { throw new Error('reply lost'); } });
  await assert.rejects(f.run(), /reply lost/);
  await assert.rejects(other.run(), /reply lost/);
  await assert.rejects(f.run(), /needs a confirmed/);
  const calls = f.calls.length;
  releaseFeePreparationInputs([`${f.funding.tx.txid}:0`]);
  assert.equal(f.calls.length, calls, 'release itself never calls the wallet');
  await assert.rejects(f.run(), /reply lost/, 'a new explicit request can now reach the wallet');
  await assert.rejects(other.run(), /needs a confirmed/);
  assert.throws(() => releaseFeePreparationInputs(['malformed']), /Invalid/);
});

test('a temporarily missing broadcast is looked up again without asking Humid to send again', async () => {
  const f = fixture('indexing lag', { confidential: true });
  const read = f.api.txHex;
  let lookups = 0;
  const waits = [];
  f.api.txHex = async (txid) => {
    if (txid !== f.funding.tx.txid && ++lookups <= 2) throw Object.assign(new Error('HTTP 404'), { status: 404 });
    return read(txid);
  };
  const progress = [];
  const reports = [];
  const result = await f.run({ progress: (text) => progress.push(text), onBroadcast: async (txid) => {
    reports.push(txid);
    assert.equal(lookups, 0, 'report the output before the first API lookup');
  }, wait: async (ms) => {
    waits.push(ms);
    assert.equal(reports.length, 1, 'the caller can persist output 0 before any wait');
    assert.throws(() => releaseFeePreparationInputs([`${f.funding.tx.txid}:0`]), /still open/);
  } });
  assert.equal(lookups, 3);
  assert.deepEqual(waits, [3000, 3000]);
  assert.equal(f.calls.filter((call) => call.method === 'signPset').length, 1);
  assert.equal(feeBroadcastMatches(result.plan, result.txHex, result.txid), null);
  assert.ok(progress.at(-1).includes(`Humid reports sending ${result.txid}`));
  assert.deepEqual(reports, [result.txid]);
});

test('exhausted indexing retries retain the txid and source hold with an uncertainty message', async () => {
  const txid = word('not indexed');
  const f = fixture('exhausted lookup', { sign: () => ({ txid }) });
  const read = f.api.txHex;
  let lookups = 0;
  const waits = [];
  f.api.txHex = async (id) => {
    if (id === f.funding.tx.txid) return read(id);
    lookups++;
    throw Object.assign(new Error('Liquid API /tx/private/hex: HTTP 404'), { status: 404 });
  };
  const error = await f.run({ wait: async (ms) => { waits.push(ms); } }).catch((e) => e);
  assert.equal(lookups, 10);
  assert.equal(waits.length, 9);
  assert.ok(waits.every((ms) => ms === 3000));
  assert.equal(error.message, `Humid reports sending ${txid}; the Liquid API has not shown it yet.`);
  assert.equal(error.sent, 'maybe');
  assert.equal(error.txid, txid);
  assert.equal(error.stage, 'lookup');
  assert.equal(error.visibility, 'not-indexed');
  assert.deepEqual(error.spends, [`${f.funding.tx.txid}:0`]);
  assert.equal(f.calls.filter((call) => call.method === 'signPset').length, 1);
  await assert.rejects(f.run(), /needs a confirmed/);
});

test('API failures and transaction verification failures are distinct and are not retried', async () => {
  for (const status of [undefined, 503]) {
    const f = fixture(`API failure ${status}`);
    const read = f.api.txHex;
    let lookups = 0;
    f.api.txHex = async (txid) => {
      if (txid === f.funding.tx.txid) return read(txid);
      lookups++;
      throw Object.assign(new Error('private endpoint detail'), { status });
    };
    const error = await f.run({ wait: async () => assert.fail('must not retry an unavailable API') }).catch((e) => e);
    assert.equal(lookups, 1);
    assert.equal(error.sent, 'maybe');
    assert.equal(error.visibility, 'unavailable');
    assert.match(error.message, /Liquid API is unavailable/);
    assert.doesNotMatch(error.message, /private endpoint|not shown it yet/);
  }
  const f = fixture('invalid returned transaction');
  const read = f.api.txHex;
  let lookups = 0;
  f.api.txHex = async (txid) => {
    if (txid === f.funding.tx.txid) return read(txid);
    lookups++;
    return f.funding.tx.hex;
  };
  const error = await f.run({ wait: async () => assert.fail('must not retry a mismatching transaction') }).catch((e) => e);
  assert.equal(lookups, 1);
  assert.equal(error.sent, 'maybe');
  assert.equal(error.stage, 'verification');
  assert.equal(error.visibility, undefined);
  assert.match(error.message, /transaction could not be verified: Liquid returned a different transaction/);
  assert.equal(f.calls.filter((call) => call.method === 'signPset').length, 1);
});

test('lookup limits are bounded before signing and do not retry missing source transactions', async () => {
  const f = fixture('lookup policy');
  for (const options of [{ lookupTries: 0 }, { lookupTries: 11 }, { lookupWaitMs: -1 }, { lookupWaitMs: 3001 }, { wait: null }]) {
    await assert.rejects(f.run(options), /lookup limits/);
  }
  assert.equal(f.calls.length, 0);
  let reads = 0;
  f.api.txHex = async () => { reads++; throw Object.assign(new Error('Source missing'), { status: 404 }); };
  await assert.rejects(f.run({ wait: async () => assert.fail('source lookup must not retry') }), /Source missing/);
  assert.equal(reads, 1);
  assert.ok(!f.calls.some((call) => call.method === 'signPset'));
});

test('failure to save a reported broadcast preserves uncertainty and never repeats signing', async () => {
  const f = fixture('reported broadcast storage failure');
  const error = await f.run({ onBroadcast: async () => { throw new Error('Storage stopped'); } }).catch((e) => e);
  assert.equal(error.sent, 'maybe');
  assert.match(error.txid, /^[0-9a-f]{64}$/);
  assert.match(error.message, /Storage stopped/);
  assert.equal(f.calls.filter((call) => call.method === 'signPset').length, 1);
  await assert.rejects(f.run(), /needs a confirmed/);
});
