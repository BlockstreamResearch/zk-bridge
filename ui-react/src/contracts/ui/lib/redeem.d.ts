import type { RedeemArgs, RelayBatch } from './bridge.js';
import type { Esplora, TxStatus } from './esplora.js';

export type EscrowCall = (data: string) => Promise<string>;

export function burnStatus(esplora: Esplora, txid: string): Promise<TxStatus>;

export type Redemption =
  | { state: 'unconfirmed' }
  | { state: 'awaiting-relay'; height: number; tip: number; needed: number }
  | { state: 'ready'; height: number; tip: number; needed: number; args: RedeemArgs };

export function redemption(args: { esplora: Esplora; call: EscrowCall; recipient: string; txid: string; vout: number }): Promise<Redemption>;

export function relayBatches(args: { esplora: Esplora; call: EscrowCall; target: number }): AsyncGenerator<RelayBatch>;
