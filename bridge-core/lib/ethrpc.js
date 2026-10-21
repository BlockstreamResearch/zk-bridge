// A Sepolia JSON-RPC endpoint the reader names in Settings, for the page's Ethereum reads in place of the wallet's.
// It never signs or sends: accounts, chain switching and transactions stay with the wallet. What it answers decides
// what the page shows, not what the escrow does: every payout is decided on chain, and the page builds deposits and
// burn scripts itself from the reviewed instance record.
//
// Its URL may embed an API key. Errors here never repeat it, and the page shows it nowhere but the Settings field.

export class EthRpc {
  constructor(url, fetchImpl = globalThis.fetch.bind(globalThis)) {
    this.url = url;
    this.fetch = fetchImpl;
    this.id = 0;
  }

  /** EIP-1193's request, over HTTP: the result, or an Error with the node's JSON-RPC `code` and `data` (revert data). */
  async request({ method, params = [] }) {
    let res;
    try {
      res = await this.fetch(this.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++this.id, method, params }),
      });
    } catch {
      throw new Error('the Sepolia RPC in Settings did not answer');
    }
    if (!res.ok) throw new Error(`the Sepolia RPC in Settings answered HTTP ${res.status}`);
    let body;
    try {
      body = JSON.parse(await res.text());
    } catch {
      throw new Error('the Sepolia RPC in Settings did not answer in JSON-RPC');
    }
    if (body?.error) {
      const said = typeof body.error.message === 'string' ? rpcMessage(body.error.message, this.url) : '';
      throw Object.assign(new Error(said ? `the Sepolia RPC in Settings answered: "${said}"` : 'the Sepolia RPC in Settings refused the request'),
        { code: body.error.code, data: body.error.data });
    }
    if (!body || !('result' in body)) throw new Error('the Sepolia RPC in Settings did not answer in JSON-RPC');
    return body.result;
  }
}

/** The longest part of an RPC's own error message the page repeats. */
export const RPC_MESSAGE_MAX = 160;

/**
 * An RPC's own error message as the page may show it: one line of at most RPC_MESSAGE_MAX characters, with any URL in
 * it, and any part of `url` (the Settings URL) of 8 or more characters past its host, replaced, since a provider may
 * echo the key-bearing URL. The page marks it as the RPC's words; it is not the page's explanation.
 */
export function rpcMessage(message, url) {
  let text = message.replace(/[\s\u0000-\u001f\u007f]+/g, ' ').trim().replace(/\bhttps?:\/\/\S+/gi, '[a URL]');
  let secrets = [];
  try {
    const u = new URL(url);
    secrets = `${u.pathname}${u.search}`.split(/[/?&=]+/).filter((s) => s.length >= 8);
  } catch {
    /* no parts to hide */
  }
  for (const s of secrets) text = text.split(s).join('[redacted]');
  return text.length > RPC_MESSAGE_MAX ? `${text.slice(0, RPC_MESSAGE_MAX - 1)}…` : text;
}

/** Throws unless `rpc` serves chain `chainId` (a bigint): an RPC of another chain would show another chain's escrow. */
export async function checkChain(rpc, chainId) {
  const answer = await rpc.request({ method: 'eth_chainId' });
  let id;
  try {
    id = BigInt(answer);
  } catch {
    id = null;
  }
  if (id !== chainId) {
    throw new Error(`the Sepolia RPC in Settings serves ${id === null ? 'no readable chain id' : `chain id ${id}`}, not Sepolia (${chainId}); the page does not read through it`);
  }
}
