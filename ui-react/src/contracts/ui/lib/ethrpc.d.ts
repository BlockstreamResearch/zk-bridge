export interface RequestArgs {
  method: string;
  params?: unknown[];
}

export class EthRpc {
  constructor(url: string, fetchImpl?: typeof fetch);
  request(args: RequestArgs): Promise<unknown>;
}

/** Throws unless `rpc` answers eth_chainId with `chainId`. */
export function checkChain(rpc: { request(args: RequestArgs): Promise<unknown> }, chainId: bigint): Promise<void>;
