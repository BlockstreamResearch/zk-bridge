import test from 'node:test';
import assert from 'node:assert/strict';
import { EthRpc, RPC_MESSAGE_MAX, checkChain } from '../lib/ethrpc.js';

// A provider's key-in-path URL; the key must never reach page copy, whatever the provider's errors say.
const URL_WITH_KEY = 'https://sepolia.example/v3/0123456789abcdef?apikey=fedcba9876543210';

/** An EthRpc over a fetch that answers every request with `reply` (a JSON-RPC body), recording the requests. */
function rpcAnswering(reply, status = 200) {
  const sent = [];
  const rpc = new EthRpc(URL_WITH_KEY, async (url, init) => {
    sent.push({ url, body: JSON.parse(init.body) });
    return { ok: status === 200, status, text: async () => (typeof reply === 'string' ? reply : JSON.stringify(reply)) };
  });
  return { rpc, sent };
}

async function errorOf(promise) {
  try {
    await promise;
  } catch (e) {
    return e;
  }
  assert.fail('expected a refusal');
}

test('the RPC\'s own error message is marked as its words, kept to one short line, with its code and data', async () => {
  const { rpc, sent } = rpcAnswering({ jsonrpc: '2.0', id: 1, error: { code: 3, message: 'execution reverted', data: '0x08c379a0' } });
  const e = await errorOf(rpc.request({ method: 'eth_call', params: [{ to: '0x' + '11'.repeat(20) }, 'latest'] }));
  assert.equal(e.message, 'the Sepolia RPC in Settings answered: "execution reverted"');
  assert.equal(e.code, 3);
  assert.equal(e.data, '0x08c379a0', 'revert data still reaches the page\'s own explanation');
  assert.deepEqual(sent.map((s) => [s.url, s.body.method]), [[URL_WITH_KEY, 'eth_call']]);

  const long = 'x'.repeat(5000);
  const capped = (await errorOf(rpcAnswering({ error: { code: -32000, message: `line one\n\tline two\u0007 ${long}` } }).rpc.request({ method: 'eth_chainId' }))).message;
  const said = capped.match(/^the Sepolia RPC in Settings answered: "(.*)"$/s)[1];
  assert.ok(said.length <= RPC_MESSAGE_MAX, `${said.length} characters`);
  assert.ok(said.startsWith('line one line two ') && said.endsWith('…'), said.slice(0, 40));
  assert.doesNotMatch(said, /[\u0000-\u001f]/);
});

test('an RPC error that echoes its URL or key does not carry them into the page', async () => {
  for (const message of [
    `invalid project id for ${URL_WITH_KEY}`,
    'rate limited: key 0123456789abcdef over quota',
    'apikey=fedcba9876543210 rejected',
    'see http://other.example/status/abcdef for details',
  ]) {
    const e = await errorOf(rpcAnswering({ error: { code: -32005, message } }).rpc.request({ method: 'eth_getCode', params: ['0x' + '22'.repeat(20), 'latest'] }));
    assert.match(e.message, /^the Sepolia RPC in Settings answered: "/, message);
    assert.doesNotMatch(e.message, /0123456789abcdef|fedcba9876543210|https?:\/\/|other\.example/, e.message);
  }
});

test('an RPC error with no usable message, and transport failures, are the page\'s own words', async () => {
  for (const error of [{ code: -32601 }, { code: -32601, message: 42 }, { code: -32601, message: ' \n ' }]) {
    const e = await errorOf(rpcAnswering({ error }).rpc.request({ method: 'eth_chainId' }));
    assert.equal(e.message, 'the Sepolia RPC in Settings refused the request');
  }
  assert.equal((await errorOf(rpcAnswering('', 503).rpc.request({ method: 'eth_chainId' }))).message, 'the Sepolia RPC in Settings answered HTTP 503');
  assert.equal((await errorOf(rpcAnswering('<html>').rpc.request({ method: 'eth_chainId' }))).message, 'the Sepolia RPC in Settings did not answer in JSON-RPC');
  const down = new EthRpc(URL_WITH_KEY, async () => {
    throw new TypeError(`fetch failed for ${URL_WITH_KEY}`);
  });
  assert.equal((await errorOf(down.request({ method: 'eth_chainId' }))).message, 'the Sepolia RPC in Settings did not answer');
  // The chain check's refusal names the chain, never the URL.
  const e = await errorOf(checkChain(rpcAnswering({ result: '0x1' }).rpc, 11155111n));
  assert.match(e.message, /serves chain id 1, not Sepolia \(11155111\)/);
  assert.doesNotMatch(e.message, /sepolia\.example|0123456789abcdef/);
});
