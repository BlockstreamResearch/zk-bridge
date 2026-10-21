export interface TxStatus {
  confirmed: boolean;
  block_height?: number;
  block_hash?: string;
}

export interface AddressTx {
  txid: string;
  status?: { confirmed?: boolean };
  vout: { asset?: string; value?: number; scriptpubkey?: string }[];
}

export class Esplora {
  constructor(base: string, fetchImpl?: typeof fetch);
  base: string;
  text(path: string): Promise<string>;
  json<T = unknown>(path: string): Promise<T>;
  tipHeight(): Promise<number>;
  txHex(txid: string): Promise<string>;
  txStatus(txid: string): Promise<TxStatus>;
  addressTxs(address: string): Promise<AddressTx[]>;
  tipHeader(): Promise<string>;
}
