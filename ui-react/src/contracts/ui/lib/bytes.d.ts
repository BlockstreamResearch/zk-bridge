export function hexToBytes(hex: string): Uint8Array;
/** Lower-case hex without a 0x prefix. */
export function bytesToHex(b: Uint8Array): string;
export function concat(...parts: (Uint8Array | number[])[]): Uint8Array;
export function bigToBytes(v: bigint, size: number): Uint8Array;
export function utf8(s: string): Uint8Array;
