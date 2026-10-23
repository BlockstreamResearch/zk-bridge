import assert from 'node:assert/strict';
import test from 'node:test';
import { encodeSegwit } from '../lib/bech32.js';
import { HUMID_SCOPE, humidSession, receiveAddress } from '../lib/humid.js';

const ADDRESS = encodeSegwit('tex', 0, new Uint8Array(20).fill(7));
const response = { address: ADDRESS, chainId: HUMID_SCOPE, confidential: false, index: 0, accountIdentifier: 'test-account' };

function wallet({ methods = [], supported = ['getAddress', 'getUTXOs', 'signPset'], answer = response } = {}) {
  const calls = [];
  return {
    calls,
    async request(request) {
      calls.push(request);
      if (request.method === 'wallet_getSession') return { sessionScopes: { [HUMID_SCOPE]: { methods } } };
      if (request.method === 'wallet_createSession') {
        methods = request.params.optionalScopes[HUMID_SCOPE].methods.filter((method) => supported.includes(method));
        return { sessionScopes: { [HUMID_SCOPE]: { methods } } };
      }
      assert.equal(request.method, 'wallet_invokeMethod');
      assert.deepEqual(request.params, { scope: HUMID_SCOPE, request: { method: 'getAddress', params: { confidential: false, index: 0 } } });
      return answer;
    },
  };
}

test('a new address session requests only address access on Liquid testnet', async () => {
  const humid = wallet();
  assert.equal(await receiveAddress(humid), ADDRESS);
  assert.deepEqual(humid.calls.map((call) => call.method), ['wallet_getSession', 'wallet_createSession', 'wallet_invokeMethod']);
  assert.deepEqual(humid.calls[1].params, { optionalScopes: { [HUMID_SCOPE]: { methods: ['getAddress'], notifications: [] } } });
});

test('address access reuses an existing grant and preserves bridge permissions when expanding it', async () => {
  const connected = wallet({ methods: ['getAddress'] });
  await receiveAddress(connected);
  assert.equal(connected.calls.length, 2);

  const signing = wallet({ methods: ['getUTXOs', 'signPset'] });
  await receiveAddress(signing);
  assert.deepEqual(signing.calls[1].params.optionalScopes[HUMID_SCOPE].methods, ['getUTXOs', 'signPset', 'getAddress']);

  const addressOnly = wallet({ methods: ['getAddress'] });
  await humidSession(addressOnly);
  assert.deepEqual(addressOnly.calls[1].params.optionalScopes[HUMID_SCOPE].methods, ['getAddress', 'getUTXOs', 'signPset']);
});

test('signing alone does not grant coin access, and signing-only actions need no coin access', async () => {
  const humid = wallet({ methods: ['signPset'] });
  await humidSession(humid, ['signPset']);
  assert.equal(humid.calls.length, 1);
  await humidSession(humid);
  assert.equal(humid.calls[2].method, 'wallet_createSession');

  await assert.rejects(humidSession(wallet({ supported: ['signPset'] })), /allow coin access and signing/);
});

test('an older wallet can still sign and gives a manual address fallback', async () => {
  const humid = wallet({ supported: ['getUTXOs', 'signPset'] });
  await assert.rejects(receiveAddress(humid), /paste your unconfidential address/);
  assert.equal(humid.calls.length, 2, 'no unsupported method was invoked');
  await humidSession(humid);
});

for (const [name, answer] of [
  ['missing response', null],
  ['wrong chain', { ...response, chainId: 'bip122:' + '00'.repeat(16) }],
  ['confidential form', { ...response, confidential: true }],
  ['different index', { ...response, index: 1 }],
  ['missing metadata', { address: ADDRESS }],
  ['non-string address', { ...response, address: null }],
  ['invalid checksum', { ...response, address: ADDRESS.slice(0, -1) + 'q' }],
  ['mainnet address', { ...response, address: encodeSegwit('ex', 0, new Uint8Array(20)) }],
]) {
  test(`address retrieval refuses ${name}`, async () => {
    await assert.rejects(receiveAddress(wallet({ answer })));
  });
}

test('a rejected or unsupported read keeps manual entry available', async () => {
  for (const [error, message] of [
    [Object.assign(new Error('Method not found'), { code: -32601 }), /Update Humid or paste/],
    [Object.assign(new Error('Unsupported scopes'), { code: 5100 }), /Enable Liquid testnet/],
    [Object.assign(new Error('Declined'), { data: { reason: 'user_rejected' } }), /declined or expired/],
    [Object.assign(new Error('Connection declined'), { code: 4001 }), /declined or expired/],
  ]) {
    await assert.rejects(receiveAddress({ request: async () => { throw error; } }), message);
  }
});

test('a read timeout cannot issue another request after a late session reply', async () => {
  let finish;
  let calls = 0;
  const humid = { request: () => { calls++; return new Promise((resolve) => { finish = resolve; }); } };
  await assert.rejects(receiveAddress(humid, 1), /Close any pending wallet prompt/);
  finish({ sessionScopes: {} });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls, 1);
});
