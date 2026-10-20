export function keccak256(input: Uint8Array | string): Uint8Array;
export function sha256(msg: Uint8Array): Uint8Array;
/** 0x-prefixed 4-byte selector of a Solidity signature. */
export function selector(signature: string): string;
