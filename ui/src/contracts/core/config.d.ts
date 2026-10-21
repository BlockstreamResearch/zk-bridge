// ../bridge-core/config.js: the one published instance and the Settings parser.

export interface RawInstance {
  name: string;
  escrow: string;
  codeHash: string;
  bootstrap: string;
  state: string;
}

/** parseInstance's output: the record's values, checked and frozen, with the escrow in lower case. */
export interface Instance {
  readonly name: string;
  /** `instances/<name>/`, relative to the site root. */
  readonly record: string;
  readonly escrow: string;
  readonly codeHash: string;
  readonly bootstrap: string;
  readonly state: string;
}

export const INSTANCE: RawInstance | null;

export const DEFAULTS: Readonly<{
  chainId: bigint;
  chainName: string;
  esplora: string;
  liquidExplorer: string;
  ethExplorer: string;
  pollMs: number;
}>;

export function parseInstance(raw: RawInstance | null): Instance | null;

export interface Settings {
  esplora: string;
  ethRpc: string | null;
}

/** Throws an Error whose `field` is 'esplora' or 'ethRpc'; its message never repeats the URL. */
export function parseSettings(raw: { esplora?: unknown; ethRpc?: unknown }): Settings;
