// Bridge rules on the client side, each mirroring a contract rule so the app can refuse bad input before
// a user spends anything. The contracts stay the authority: the app cross-checks the burn script with
// BridgeEscrow.burnScriptPubKey and simulates every transaction with eth_call before sending it.
import { decodeSegwit, encodeSegwit } from './bech32.js';
import { bigToBytes, bytesToBig, bytesToHex, concat, equal, hexToBytes, utf8 } from './bytes.js';
import { blockSignatures, merkleBranch, parseHeader, parseTransaction, txidFromDisplay, displayHex } from './elements.js';
import { keccak256, selector, sha256 } from './hash.js';
import { decode, encodeCall } from './abi.js';

// Deposit constants (BridgeDeposits).
export const UNIT_WEI = 10_000_000_000n;
export const MIN_UNITS = 100_000n;
export const MAX_UNITS = 2_100_000_000_000_000n;
export const SEPOLIA_CHAIN_ID = 11155111n;
export const LIQUID_TESTNET_HRP = 'tex';
/** Liquid testnet L-BTC, internal byte order (displayed as 144c6543…9a49). */
export const LIQUID_TESTNET_LBTC = '499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c14';

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

function modpow(b, e, m) {
  let r = 1n;
  b %= m;
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
  }
  return r;
}

/** True when x is the x coordinate of a secp256k1 point, i.e. a usable x-only (Taproot) key. */
export function isXOnlyKey(x32) {
  const x = bytesToBig(x32);
  if (x >= P) return false;
  return modpow((x * x * x + 7n) % P, (P - 1n) / 2n, P) === 1n;
}

/** The y coordinate with the parity of a compressed key's prefix (BridgeEscrow's keyY argument). */
export function liftY(compressed) {
  if (compressed.length !== 33 || (compressed[0] !== 2 && compressed[0] !== 3)) throw new Error('not a compressed key');
  const x = bytesToBig(compressed.subarray(1));
  const v = (x * x * x + 7n) % P;
  let y = modpow(v, (P + 1n) / 4n, P);
  if ((y * y) % P !== v) throw new Error('key is not on secp256k1');
  if (Number(y & 1n) !== compressed[0] - 2) y = P - y;
  return y;
}

/**
 * The output scripts BridgeDeposits.recipientOf accepts: P2PKH, P2SH, P2WPKH, P2WSH, and P2TR with a valid
 * x-only key. Anything else would be unspendable, a fee, a burn, or spendable by anyone.
 */
export function isStandardRecipient(s) {
  const at = (i, b) => s[i] === b;
  if (s.length === 25) return at(0, 0x76) && at(1, 0xa9) && at(2, 0x14) && at(23, 0x88) && at(24, 0xac);
  if (s.length === 23) return at(0, 0xa9) && at(1, 0x14) && at(22, 0x87);
  if (s.length === 22) return at(0, 0x00) && at(1, 0x14);
  if (s.length === 34) return (at(0, 0x00) && at(1, 0x20)) || (at(0, 0x51) && at(1, 0x20) && isXOnlyKey(s.subarray(2)));
  return false;
}

/**
 * The deposit recipient: the scriptPubKey the claim pays explicit units to, and the unconfidential Liquid
 * testnet address of it when it has a segwit one (the page tracks claims by address). Accepted: a tex1q
 * (P2WPKH, P2WSH) or tex1p (P2TR) address, or a standard scriptPubKey in hex. The escrow commits the script's
 * SHA-256, and the claim leaf pays exactly that script, so the wallet that owns the address can spend it.
 */
export function depositRecipient(input) {
  const s = input.trim();
  if (/^(tlq|lq)1/i.test(s)) {
    throw new Error('this is a confidential address: the claim pays an explicit (public) output, so give the unconfidential tex1… form of the same address (Elements: getaddressinfo shows it)');
  }
  let script;
  if (/^(0x)?[0-9a-fA-F]+$/.test(s)) {
    const h = s.replace(/^0x/, '');
    if (h.length === 64) throw new Error('a bare Taproot key is not a script; give the tex1p… address of the key instead');
    if (h.length % 2) throw new Error('a scriptPubKey in hex has an even number of digits');
    script = hexToBytes(h);
  } else {
    const { version, program } = decodeSegwit(LIQUID_TESTNET_HRP, s);
    script = concat([version === 0 ? 0x00 : 0x50 + version, program.length], program);
  }
  if (!isStandardRecipient(script)) {
    throw new Error(script.length === 34 && script[0] === 0x51 ? 'not a valid Taproot key: the claim would be unspendable'
      : 'not a standard wallet script (P2WPKH, P2WSH, P2TR, P2SH or P2PKH): the claim could be unspendable');
  }
  const segwit = script[1] === script.length - 2 && (script[0] === 0x00 || script[0] === 0x51);
  return { script, address: segwit ? encodeSegwit(LIQUID_TESTNET_HRP, script[0] === 0 ? 0 : 1, script.subarray(2)) : null };
}

/** Exact decimal text to an integer with `decimals` places; no floating point. */
export function parseDecimal(text, decimals) {
  const s = text.trim();
  if (!new RegExp(`^\\d+(\\.\\d{1,${decimals}})?$`).test(s)) throw new Error(`enter an amount like 0.001 (at most ${decimals} decimals)`);
  const [whole, frac = ''] = s.split('.');
  return BigInt(whole) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, '0'));
}

export function parseEther(text) {
  return parseDecimal(text, 18);
}

/** Bridge units from the 8-decimal amount wallets display for Liquid assets. */
export function redeemUnits(text) {
  const units = parseDecimal(text, 8);
  if (units === 0n) throw new Error('redeem at least one unit');
  if (units > MAX_UNITS) throw new Error('amount above the Liquid maximum');
  return units;
}

export function formatUnits(value, decimals) {
  const neg = value < 0n;
  const v = neg ? -value : value;
  const base = 10n ** BigInt(decimals);
  const frac = (v % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + (v / base).toString() + (frac ? '.' + frac : '');
}

/** Deposit units for a wei amount, under BridgeDeposits' rules. */
export function depositUnits(wei) {
  if (wei % UNIT_WEI !== 0n) throw new Error('amounts are in steps of 0.00000001 ETH');
  const units = wei / UNIT_WEI;
  if (units < MIN_UNITS) throw new Error('the minimum deposit is 0.001 ETH');
  if (units > MAX_UNITS) throw new Error('amount above the bridge maximum');
  return units;
}

/** BridgeDeposits.deposit(bytes scriptPubKey). */
export function depositCalldata(script) {
  return encodeCall('deposit(bytes)', ['bytes'], [script]);
}

export const DEPOSIT_TOPIC = '0x' + bytesToHex(keccak256('Deposit(uint64,uint64,bytes32,bytes32,bytes32,bytes)'));
export const REDEEMED_TOPIC = '0x' + bytesToHex(keccak256('Redeemed(bytes32,uint32,address,address,uint64)'));

/** The Deposit event of a receipt from `escrow`, decoded: (units, recipient, leaf, accumulator, scriptPubKey). */
export function depositEvent(receipt, escrow) {
  const log = receipt.logs.find((l) => l.address.toLowerCase() === escrow.toLowerCase() && l.topics[0] === DEPOSIT_TOPIC);
  if (!log) return null;
  const d = hexToBytes(log.data);
  const at = Number(bytesToBig(d.subarray(128, 160)));
  const len = Number(bytesToBig(d.subarray(at, at + 32)));
  return {
    index: BigInt(log.topics[1]),
    units: bytesToBig(d.subarray(0, 32)),
    recipient: bytesToHex(d.subarray(32, 64)),
    accumulator: bytesToHex(d.subarray(96, 128)),
    script: bytesToHex(d.subarray(at + 32, at + 32 + len)),
  };
}

export function ethAddress(text) {
  const s = text.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) throw new Error('an Ethereum address is 0x followed by 40 hex characters');
  const lower = s.slice(2).toLowerCase();
  if (s.slice(2) !== lower && s.slice(2) !== s.slice(2).toUpperCase()) {
    // EIP-55: a mixed-case address carries a checksum.
    const h = bytesToHex(keccak256(lower));
    for (let i = 0; i < 40; i++) {
      const upper = parseInt(h[i], 16) >= 8;
      if (/[a-f]/i.test(lower[i]) && (s[2 + i] === lower[i].toUpperCase()) !== upper) throw new Error('address checksum is wrong');
    }
  }
  if (/^0+$/.test(lower)) throw new Error('the zero address cannot receive a redemption');
  return '0x' + lower;
}

/**
 * The recipient of a burn, which no one can change afterwards: the connected account, or an address with its
 * EIP-55 checksum (mixed case), so that a mistyped character cannot pass silently.
 */
export function burnRecipient(text, connected) {
  const address = ethAddress(text);
  const digits = text.trim().slice(2);
  const checksummed = digits !== digits.toLowerCase() && digits !== digits.toUpperCase();
  if (!checksummed && address !== (connected || '').toLowerCase()) {
    throw new Error('paste the checksummed (mixed-case) form of this address, or connect that account: a burn cannot be redirected later');
  }
  return address;
}

/** BridgeEscrow.BURN_TAG, the first bytes of every burn payload. */
export const BURN_TAG = 'liquid-bridge-poc/burn';
const BURN_PREFIX = concat([0x6a, 0x46], utf8(BURN_TAG)); // OP_RETURN, a direct push of 70 bytes, the tag

function address20(hex) {
  const b = hexToBytes(hex);
  if (b.length !== 20) throw new Error('an Ethereum address is 20 bytes');
  return b;
}

/**
 * BridgeEscrow.burnScriptPubKey(recipient): OP_RETURN PUSH70 (BURN_TAG || be64 chain id || escrow || recipient), a
 * bare OP_RETURN output script of 72 bytes, with no address.
 */
export function burnTarget(chainId, escrow, recipient) {
  const scriptPubKey = concat(BURN_PREFIX, bigToBytes(BigInt(chainId), 8), address20(escrow), address20(recipient));
  return { scriptPubKey, chainId: BigInt(chainId), escrow: escrow.toLowerCase(), recipient: recipient.toLowerCase() };
}

/** The chain id, escrow and recipient (0x-prefixed lowercase hex) a burn script names, or null if it is not one. */
export function readBurnScript(script) {
  const o = BURN_PREFIX.length;
  if (script.length !== o + 48 || !equal(script.subarray(0, o), BURN_PREFIX)) return null;
  return {
    chainId: bytesToBig(script.subarray(o, o + 8)),
    escrow: `0x${bytesToHex(script.subarray(o + 8, o + 28))}`,
    recipient: `0x${bytesToHex(script.subarray(o + 28))}`,
  };
}

/**
 * `recipient`'s burn target at `escrow`, after checking it against `onchain`, the escrow's own
 * burnScriptPubKey(recipient) answer. The page builds the script itself: the answer arrives through an RPC, and
 * one that lied could have a burn made that the escrow refuses, destroying the units. So the escrow can only
 * confirm the script, never choose it.
 */
export function escrowBurnTarget(chainId, escrow, recipient, onchain) {
  const t = burnTarget(chainId, escrow, recipient);
  if (!equal(t.scriptPubKey, onchain)) throw new Error('This page and the contract disagree on the burn script. Burn nothing; report this.');
  return t;
}

/** Why an explicit bridge-asset output paying `script` does not redeem for `target` (burnDiagnosis). */
function misdirected(script, target) {
  const named = readBurnScript(script);
  if (named) {
    if (named.chainId !== target.chainId) return `is a burn for chain id ${named.chainId}, which this escrow cannot redeem`;
    if (named.escrow !== target.escrow) return `is a burn for escrow ${named.escrow}, which this escrow cannot redeem`;
    return `is a burn naming recipient ${named.recipient}: set step 1's recipient to it and look this up again`;
  }
  if (script[0] === 0x6a) return 'is an OP_RETURN that names no recipient, as a wallet\'s Burn or Destroy control makes: the units are destroyed and nobody can redeem them';
  return 'pays another script, such as change or an ordinary address: it is not a burn';
}

/** Outputs of a parsed transaction that burn the bridge asset (internal-order id) to `scriptPubKey`. */
export function burnOutputs(tx, assetInternal, scriptPubKey) {
  const out = [];
  tx.outputs.forEach((o, vout) => {
    if (!equal(o.script, scriptPubKey)) return;
    const explicit = o.asset.kind === 'explicit' && o.value.kind === 'explicit';
    const isAsset = explicit && equal(o.asset.data, assetInternal);
    out.push({ vout, units: isAsset ? o.value.amount : null, usable: isAsset && o.value.amount > 0n });
  });
  return out;
}

/**
 * Why a transaction's outputs do not redeem for `target` (burnTarget), for a lookup that finds nothing usable.
 * `outputs` lists, as { vout, units, text }, the target script's unusable outputs and every explicit output of the
 * bridge asset (internal-order id) elsewhere. Units are null unless explicit and of that asset. A burn script says
 * what it names. `blinded` counts confidential outputs elsewhere, which this page cannot read.
 */
export function burnDiagnosis(tx, assetInternal, target) {
  const outputs = [];
  let blinded = 0;
  const [it, other, none] = [
    'is this recipient\'s burn',
    'is this recipient\'s burn script, but burns another asset',
    'is this recipient\'s burn script, but burns nothing',
  ];
  tx.outputs.forEach((o, vout) => {
    const explicit = o.asset.kind === 'explicit' && o.value.kind === 'explicit';
    const units = explicit && equal(o.asset.data, assetInternal) ? o.value.amount : null;
    const add = (text) => outputs.push({ vout, units, text });
    if (equal(o.script, target.scriptPubKey)) {
      if (!explicit) add(`${it}, but confidential (blinded), which Ethereum cannot read, so it can never be redeemed`);
      else if (units === null) add(`${other}, which the escrow does not redeem`);
      else if (units === 0n) add(none);
    } else if (!explicit) {
      blinded += 1;
    } else if (units !== null) {
      add(misdirected(o.script, target));
    }
  });
  return { outputs, blinded };
}

/**
 * BurnProof for output `vout` of the burn, with the checks BridgeEscrow makes that need no chain state:
 *   txHex         the burn transaction (either serialization); its txid must be `txidDisplay`
 *   txidsDisplay  the burn block's txids in block order (/block/:hash/txids)
 *   blockHeaderHex the burn block's header (/block/:hash/header), for its Merkle root and height
 */
export function burnProof({ txidDisplay, txHex, vout, txidsDisplay, blockHeaderHex }) {
  const tx = parseTransaction(hexToBytes(txHex));
  if (displayHex(tx.txid) !== txidDisplay.toLowerCase()) throw new Error('transaction bytes do not match the txid');
  const header = parseHeader(hexToBytes(blockHeaderHex));
  const leaves = txidsDisplay.map(txidFromDisplay);
  const position = leaves.findIndex((t) => equal(t, tx.txid));
  if (position < 0) throw new Error('the transaction is not in that block');
  const { root, branch } = merkleBranch(leaves, position);
  if (!equal(root, header.merkleRoot)) throw new Error('txids do not reproduce the block\'s Merkle root');
  return { burn: { transaction: tx.txidForm, vout, branch, position }, height: header.height, merkleRoot: header.merkleRoot };
}

/**
 * LiquidLightClient's batch tree: leaves keccak256(merkleRoot) for heights firstHeight .., zero-padded
 * to a power of two, parents keccak256(left || right). Returns the BlockRef of `height`, after checking
 * the rebuilt root against the stored one.
 */
export function batchRef(batch, merkleRoots, height) {
  if (merkleRoots.length !== batch.count) throw new Error('need one Merkle root per batch header');
  const index = height - batch.firstHeight;
  if (index < 0 || index >= batch.count) throw new Error('height outside the batch');
  let size = 1;
  while (size < batch.count) size *= 2;
  let level = Array.from({ length: size }, (_, i) => (i < batch.count ? keccak256(merkleRoots[i]) : new Uint8Array(32)));
  const path = [];
  let i = index;
  while (level.length > 1) {
    path.push(level[i ^ 1]);
    const next = [];
    for (let j = 0; j < level.length; j += 2) next.push(keccak256(concat(level[j], level[j + 1])));
    level = next;
    i >>= 1;
  }
  if (bytesToHex(level[0]) !== batch.root.replace(/^0x/, '')) throw new Error('rebuilt batch root differs from the stored one');
  return { batch: batch.index, index, path };
}

export const REDEEM_SIGNATURE = 'redeem(address,(bytes,uint32,bytes32[],uint32),(uint256,uint256,bytes32[]))';
const REDEEM_TYPES = ['address', { tuple: ['bytes', 'uint32', { array: 'bytes32' }, 'uint32'] }, { tuple: ['uint256', 'uint256', { array: 'bytes32' }] }];

export function redeemCalldata({ recipient, burn, ref }) {
  return encodeCall(REDEEM_SIGNATURE, REDEEM_TYPES, [
    recipient,
    [burn.transaction, burn.vout, burn.branch, burn.position],
    [BigInt(ref.batch), BigInt(ref.index), ref.path],
  ]);
}

/** redeemTo(to, burn, ref): the burn's recipient, sending it, has the ETH paid to `to` instead. */
export const REDEEM_TO_SIGNATURE = 'redeemTo(address,(bytes,uint32,bytes32[],uint32),(uint256,uint256,bytes32[]))';

export function redeemToCalldata({ to, burn, ref }) {
  return encodeCall(REDEEM_TO_SIGNATURE, REDEEM_TYPES, [
    to,
    [burn.transaction, burn.vout, burn.branch, burn.position],
    [BigInt(ref.batch), BigInt(ref.index), ref.path],
  ]);
}

/**
 * A relay batch for LiquidLightClient.submitHeaders from consecutive raw headers of one epoch: their hash
 * forms, the last header's block signatures, and the witness script and key y coordinates when the batch
 * starts an epoch under a signblockscript other than `currentSignblockscriptHash` (a DynaFed key change).
 */
export function relayBatch(headerHexes, currentSignblockscriptHash) {
  const headers = headerHexes.map((h) => parseHeader(hexToBytes(h)));
  for (let i = 1; i < headers.length; i++) {
    if (!equal(headers[i].prev, headers[i - 1].hash) || headers[i].height !== headers[i - 1].height + 1) throw new Error(`header ${i} is not the child of header ${i - 1}`);
  }
  const tip = headers[headers.length - 1];
  const { witnessScript, signatures } = blockSignatures(tip);
  const changed = '0x' + bytesToHex(keccak256(headers[0].signblockscript)) !== currentSignblockscriptHash.toLowerCase();
  const keyY = changed ? federationKeys(witnessScript).map((k) => liftY(k)) : [];
  return { headers: headers.map((h) => h.hashForm), sigs: signatures, witnessScript: changed ? witnessScript : new Uint8Array(0), keyY, firstHeight: headers[0].height };
}

/** The compressed keys of `<key> OP_CHECKSIG` or `OP_m <key>... OP_n OP_CHECKMULTISIG`. */
export function federationKeys(script) {
  if (script.length === 35 && script[0] === 0x21 && script[34] === 0xac) return [script.subarray(1, 34)];
  const n = (script.length - 3) / 34;
  if (!Number.isInteger(n) || n < 1 || n > 16 || script[script.length - 1] !== 0xae) throw new Error('unsupported block-signing script');
  return Array.from({ length: n }, (_, i) => script.subarray(2 + 34 * i, 35 + 34 * i));
}

export const SUBMIT_SIGNATURE = 'submitHeaders(bytes[],(bytes32,bytes32)[],bytes,uint256[])';

export function submitHeadersCalldata(b) {
  return encodeCall(SUBMIT_SIGNATURE, [{ array: 'bytes' }, { array: { tuple: ['bytes32', 'bytes32'] } }, 'bytes', { array: 'uint256' }],
    [b.headers, b.sigs.map((s) => [s.r, s.s]), b.witnessScript, b.keyY]);
}

/** The EIP-4788 contract: the parent beacon block root of the execution block at a timestamp, for about 27 hours. */
export const BEACON_ROOTS = '0x000f3df6d732807ef1319fb7b8bb8522d0beac02';
export const CHECK_FORK_SIGNATURE = 'checkFork((uint64,uint64,bytes32,uint64,bytes4,bytes4,uint64,bytes32[2],bytes32,bytes32[3]))';
const SECONDS_PER_SLOT = 12;

/**
 * BridgeEscrow.checkFork's BeaconProof from the JSON that tools/liquid-relay/fork_proof.py prints, or from its
 * `proof` member alone, with every field's type checked. Nothing else about it is trusted: beaconBlockRoot gives
 * the root Ethereum must hold for its timestamp, and the escrow recomputes that root itself.
 */
export function parseForkProof(text) {
  let j;
  try {
    j = JSON.parse(text);
  } catch {
    throw new Error('paste the JSON that fork_proof.py prints');
  }
  const p = j && typeof j === 'object' && j.proof && typeof j.proof === 'object' ? j.proof : j || {};
  const int = (k) => {
    if (!Number.isSafeInteger(p[k]) || p[k] < 0) throw new Error(`proof.${k} is not a non-negative integer`);
    return p[k];
  };
  const hex = (v, n, k) => {
    if (typeof v !== 'string' || !new RegExp(`^0x[0-9a-fA-F]{${2 * n}}$`).test(v)) throw new Error(`proof.${k} is not ${n} bytes in 0x hex`);
    return hexToBytes(v);
  };
  const nodes = (k, n) => {
    if (!Array.isArray(p[k]) || p[k].length !== n) throw new Error(`proof.${k} lists ${n} nodes`);
    return p[k].map((v, i) => hex(v, 32, `${k}[${i}]`));
  };
  // checkFork's rule: an inactive field's root is zero, which would read as a zero genesis time or slot.
  const activeFields = hex(p.activeFields, 32, 'activeFields');
  if ((activeFields[0] & 0x0f) !== 0x0f) throw new Error('proof.activeFields leaves one of fields 0 to 3 inactive');
  return {
    timestamp: int('timestamp'), genesisTime: int('genesisTime'), genesisValidatorsRoot: hex(p.genesisValidatorsRoot, 32, 'genesisValidatorsRoot'),
    slot: int('slot'), previousVersion: hex(p.previousVersion, 4, 'previousVersion'), currentVersion: hex(p.currentVersion, 4, 'currentVersion'),
    epoch: int('epoch'), stateBranch: nodes('stateBranch', 2), activeFields, blockBranch: nodes('blockBranch', 3),
  };
}

/** The slot time of a proof's beacon state: what checkFork records as forkCheckedAt. */
export const forkSlotTime = (p) => p.genesisTime + p.slot * SECONDS_PER_SLOT;

/** An SSZ chunk: `b` zero-padded on the right to 32 bytes; a uint64 is little-endian. */
function sszChunk(b) {
  const c = new Uint8Array(32);
  c.set(b);
  return c;
}

const sszUint64 = (n) => sszChunk(bigToBytes(BigInt(n), 8).reverse());
const sszNode = (left, right) => sha256(concat(left, right));

/**
 * The beacon block root BridgeEscrow.checkFork computes from proof `p`, in the contract's order: a progressive
 * BeaconState (node 4 genesis_time, node 10 fields 1 to 4, node 11 the rest, node 3 the active-fields bits) under
 * the block's state_root.
 */
export function beaconBlockRoot(p) {
  const fork = sszNode(sszNode(sszChunk(p.previousVersion), sszChunk(p.currentVersion)), sszNode(sszUint64(p.epoch), new Uint8Array(32)));
  const fields1to4 = sszNode(sszNode(p.genesisValidatorsRoot, sszUint64(p.slot)), sszNode(fork, p.stateBranch[0]));
  const state = sszNode(sszNode(sszUint64(p.genesisTime), sszNode(fields1to4, p.stateBranch[1])), p.activeFields);
  const b = p.blockBranch;
  return sszNode(sszNode(b[1], sszNode(b[0], state)), b[2]);
}

/** checkFork(BeaconProof): a static tuple, so its thirteen words follow the selector in place. */
export function checkForkCalldata(p) {
  const word = (n) => bigToBytes(BigInt(n), 32);
  return selector(CHECK_FORK_SIGNATURE) + bytesToHex(concat(word(p.timestamp), word(p.genesisTime), p.genesisValidatorsRoot, word(p.slot),
    sszChunk(p.previousVersion), sszChunk(p.currentVersion), word(p.epoch), ...p.stateBranch, p.activeFields, ...p.blockBranch));
}

/** eth_call data for the EIP-4788 contract: the timestamp as one word. */
export const beaconRootCall = (timestamp) => '0x' + bytesToHex(bigToBytes(BigInt(timestamp), 32));

/** Calldata of the escrow's view functions the app reads. */
export const views = {
  BRIDGE_ASSET: () => encodeCall('BRIDGE_ASSET()', [], []),
  MIN_CONFIRMATIONS: () => encodeCall('MIN_CONFIRMATIONS()', [], []),
  EPOCH_LENGTH: () => encodeCall('EPOCH_LENGTH()', [], []),
  signblockscriptHash: () => encodeCall('signblockscriptHash()', [], []),
  lcTipHeight: () => encodeCall('lcTipHeight()', [], []),
  lcTipTime: () => encodeCall('lcTipTime()', [], []),
  batchCount: () => encodeCall('batchCount()', [], []),
  batchAt: (i) => encodeCall('batchAt(uint256)', ['uint256'], [BigInt(i)]),
  depositCount: () => encodeCall('depositCount()', [], []),
  depositsOpen: () => encodeCall('depositsOpen()', [], []),
  MAX_RELAY_LAG: () => encodeCall('MAX_RELAY_LAG()', [], []),
  depositsEnd: () => encodeCall('depositsEnd()', [], []),
  forkCheckedAt: () => encodeCall('forkCheckedAt()', [], []),
  MAX_FORK_CHECK_AGE: () => encodeCall('MAX_FORK_CHECK_AGE()', [], []),
  FORK_VERSION: () => encodeCall('FORK_VERSION()', [], []),
  FORK_EPOCH: () => encodeCall('FORK_EPOCH()', [], []),
  burnScriptPubKey: (recipient) => encodeCall('burnScriptPubKey(address)', ['address'], [recipient]),
  isRedeemed: (txidInternal, vout) => encodeCall('isRedeemed(bytes32,uint32)', ['bytes32', 'uint32'], [txidInternal, vout]),
};

/** batchAt's return value: (uint32 firstHeight, uint32 count, bytes32 root). */
export function decodeBatch(hex, index) {
  const d = hexToBytes(hex);
  if (d.length < 96) throw new Error('batchAt returned too little data');
  return { index, firstHeight: Number(bytesToBig(d.subarray(0, 32))), count: Number(bytesToBig(d.subarray(32, 64))), root: bytesToHex(d.subarray(64, 96)) };
}
export { decode };

const utcMinute = (seconds) => new Date(seconds * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';

/**
 * Whether this page takes a deposit for the escrow reads `b`, and why not: { deposit, relayReopens, forkReopens,
 * text }. relayReopens: relaying Liquid headers would reopen deposits; forkReopens: a fresh checkFork proof would.
 * The escrow's own depositsOpen() decides; its other reads only explain the answer. `b.admission` holds
 * { depositsEnd, forkCheckedAt, maxForkCheckAge }. `now` is Unix seconds.
 */
export function depositAdmission(b, now) {
  const closed = (text, relayReopens = false, forkReopens = false) => ({ deposit: false, relayReopens, forkReopens, text });
  const { depositsEnd, forkCheckedAt, maxForkCheckAge } = b.admission;
  if (b.depositsOpen) {
    return { deposit: true, relayReopens: false, forkReopens: false, text: `Deposits are open, until ${utcMinute(depositsEnd)} at the latest: the light client is current, and Sepolia was recently proven to be on the fork the bridge's proofs cover.` };
  }
  if (now >= depositsEnd) {
    return closed('Deposits have ended for good: the deposit window has closed, or a Sepolia fork outside the bridge\'s '
      + 'proof path was proven. Nothing reopens them; redemptions are not affected.');
  }
  if (forkCheckedAt === 0 || now > forkCheckedAt + maxForkCheckAge) {
    return closed('Deposits are paused: nobody has recently proven that Sepolia is still on the fork the bridge\'s proofs '
      + 'cover. Anyone can send that proof (checkFork, against an EIP-4788 beacon block root): the instance\'s operator '
      + 'normally does, and you can paste one below. Relaying Liquid headers does not help. Redemptions are not affected.', false, true);
  }
  if (b.lcTime === 0 || now > b.lcTime + b.maxRelayLag) {
    return closed(`Deposits are closed: the bridge's view of Liquid is more than ${Math.round(b.maxRelayLag / 3600)} hours behind, so a redemption could not be served now. Relaying Liquid headers reopens them; redemptions are not affected.`, true);
  }
  return closed('The escrow reports deposits closed.');
}

const ERRORS = {
  AlreadyRedeemed: 'This burn output has already been redeemed.',
  WrongAsset: 'That output does not hold the bridge asset.',
  ZeroAmount: 'That burn output is empty.',
  WrongBurnScript: 'That output is not this escrow\'s burn for this recipient.',
  ZeroRecipient: 'A redemption needs a recipient.',
  ShortTransaction: 'The transaction bytes are malformed.',
  TooFewConfirmations: 'The bridge has not relayed enough Liquid blocks after the burn yet; relay more headers or wait.',
  UnknownBatch: 'That relayed batch does not exist.',
  BadBlockRef: 'The block reference does not fit its batch.',
  NotInBatch: 'The burn block is not among the relayed Liquid blocks (or the Merkle proof is wrong).',
  WrongSignblockscript: 'The headers commit to block signers the light client does not expect at that height.',
  BrokenChain: 'The headers do not extend the light client\'s tip.',
  WrongSignatureCount: 'The header carries the wrong number of block signatures.',
  BadSignature: 'The block signatures do not match the current signing keys.',
  EmptyBatch: 'No headers to relay.',
  CrossesEpoch: 'A relay batch must stay within one DynaFed epoch.',
  AmbiguousTally: 'The light client cannot decide a DynaFed key change from the votes it saw and has stopped.',
  MissingWitnessScript: 'This batch starts an epoch with new signing keys; it must include their witness script.',
  UnexpectedWitnessScript: 'The signing keys did not change; do not include a witness script.',
  WrongWitnessScript: 'The witness script does not match the newly elected signblockscript.',
  BadWitnessScript: 'Unsupported block-signing script.',
  BadKey: 'A signing key or its y coordinate is invalid.',
  BadEpochLength: 'Invalid epoch length.',
  BadCheckpoint: 'Invalid light-client checkpoint.',
  PayoutFailed: 'The ETH could not be paid: the receiving address refused it, or the transaction had too little gas for its receive hook. Nothing was redeemed and the burn is still unspent. Retry with more gas; if the recipient is a contract that refuses plain ETH, that account can redeem to another address.',
  Insolvent: 'The escrow holds less ETH than this burn redeems, which only a failure of Liquid\'s block signers could cause. Nothing was recorded.',
  DepositsClosed: 'Deposits are closed: the deposit window has ended, the fork check is stale or found a fork outside the bridge\'s proof path, or the bridge\'s view of Liquid is too far behind. Bridge checks says which; only the last is fixed by relaying Liquid headers.',
  NotDepositCloser: 'Only the escrow\'s deposit closer can end deposits early.',
  DepositsEndNotEarlier: 'The deposit closer can only bring the end of deposits forward.',
  NoBeaconRoot: 'Ethereum holds no beacon block root for that timestamp (EIP-4788 keeps about the last 27 hours); build a new proof.',
  BadBeaconProof: 'The beacon-state proof does not reach Ethereum\'s beacon block root, or is not for Sepolia.',
  StaleFork: 'That beacon state predates the fork the escrow pins; prove a newer one.',
  ZeroAsset: 'Invalid deployment: no bridge asset.',
  ZeroConfirmations: 'Invalid deployment: a burn needs at least one confirmation.',
  BadDepositsEnd: 'Invalid deployment: the deposit window must end after deployment and within 180 days.',
  EndInsideForkMargin: 'Invalid deployment: deposits must end at least two days before the announced fork outside the pin.',
  BadForkCheckAge: 'Invalid deployment: the fork-check age must be between 10 minutes and 6 hours.',
  ZeroGenesisValidatorsRoot: 'Invalid deployment: no genesis validators root.',
  ChainIdTooWide: 'Invalid deployment: a burn names the chain id in 8 bytes, and this chain\'s does not fit.',
  BadRecipientScript: 'The Liquid recipient is not a standard wallet script.',
  BadDepositAmount: 'Deposits are at least 0.001 ETH, in steps of 0.00000001 ETH.',
  DepositTreeFull: 'The deposit tree is full.',
  BadRelayLag: 'Invalid relay lag.',
  Truncated: 'The proof data is truncated.',
  NonCanonicalSize: 'The proof data is not canonically encoded.',
  BadPrefix: 'The transaction uses an unknown commitment encoding.',
  WitnessFlag: 'The transaction must be given without its witness.',
  NoInputs: 'The transaction has no inputs.',
  NoOutputs: 'The transaction has no outputs.',
  NoSuchOutput: 'The transaction has no output with that index.',
  NotExplicit: 'The burn output is confidential; only explicit (unblinded) burns can be redeemed.',
  TrailingBytes: 'The proof data has trailing bytes.',
  NotDynafed: 'A header is not a DynaFed header.',
  NullCurrentParams: 'A header has no current federation parameters.',
  BadParamsType: 'A header has malformed federation parameters.',
  BadBranch: 'The Merkle branch and position do not fit together.',
};
const BY_SELECTOR = Object.fromEntries(Object.entries(ERRORS).map(([name, text]) => [selector(name + '()'), { name, text }]));

/**
 * A human explanation of revert data (hex) from BridgeEscrow, its bases or ElementsParser. The contracts revert with
 * custom errors; a plain Error(string), from anything else on the call path, is shown as its reason.
 */
export function explainRevert(data) {
  if (!data || data === '0x') return 'The transaction reverted without a reason.';
  const sel = data.slice(0, 10).toLowerCase();
  if (BY_SELECTOR[sel]) return BY_SELECTOR[sel].text;
  if (sel === '0x08c379a0') {
    const reason = new TextDecoder().decode(decode.bytes('0x' + data.slice(10)));
    return `Reverted: ${reason}`;
  }
  return `Reverted with unknown error ${sel}.`;
}
