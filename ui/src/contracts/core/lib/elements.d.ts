export interface Confidential {
  kind: 'null' | 'explicit' | 'confidential';
  data?: Uint8Array;
  amount?: bigint;
}

export interface TxOutput {
  asset: Confidential;
  value: Confidential;
  nonce: Confidential;
  script: Uint8Array;
}

export interface ParsedTransaction {
  version: number;
  inputs: { prevTxid: Uint8Array; n: number }[];
  outputs: TxOutput[];
  /** Internal byte order. */
  txid: Uint8Array;
  txidForm: Uint8Array;
}

export interface ParsedHeader {
  hash: Uint8Array;
  height: number;
  merkleRoot: Uint8Array;
  signblockscript: Uint8Array;
}

export function parseTransaction(raw: Uint8Array): ParsedTransaction;
export function parseHeader(raw: Uint8Array): ParsedHeader;
/** Display (explorer) hex to internal byte order. */
export function txidFromDisplay(hex: string): Uint8Array;
/** Internal byte order to display (explorer) hex. */
export function displayHex(internal: Uint8Array): string;
