// Prepare the explicit fee coin required by the deployed update and claim covenants.
// The destination is supplied by the user. Signing proves ownership of the source
// coin, not the destination. Never infer destination ownership from wallet approval.
import { decodeConfidential, decodeSegwit } from './bech32.js';
import { concat, equal, hexToBytes } from './bytes.js';
import { LIQUID_TESTNET_LBTC } from './bridge.js';
import { displayHex, parseTransaction, readWitness } from './elements.js';
import {
  FEE_SATS, MIN_CHANGE_SATS, SIGN_DEADLINE_MS, base64, encodePset, feeInput,
  humidAddress, humidCall, humidSession, signAndBroadcast, unsignedTx,
} from './humid.js';

const GENESIS = 'a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1';
const LBTC = hexToBytes(LIQUID_TESTNET_LBTC);
const ASSET = displayHex(LBTC);
const MAX_MONEY = 2_100_000_000_000_000n;
const MAX_COINS = 256;
const MAX_ADDRESS_COINS = 10_000;
const MAX_CHECKS = 32;
const MAX_TX_HEX = 8_000_000;
export const MAX_FEE_SATS = 50_000n;

// These reservations survive retries through this module, including a replacement
// provider object. The caller must persist uncertain sends across page reloads.
const reserved = new Set();
const active = new WeakSet();
const inFlight = new Set();
const outpoint = (coin) => `${coin.txid}:${coin.vout}`;

/** Clear only preparation holds that the caller has explicitly reviewed with
 * the user and checked against current chain data. This never sends anything.
 * An active request cannot be released. The caller also owns persisted holds.
 */
export function releaseFeePreparationInputs(points) {
  if (!Array.isArray(points) || points.length > MAX_COINS
    || points.some((point) => typeof point !== 'string' || !/^[0-9a-f]{64}:(0|[1-9][0-9]{0,9})$/.test(point)
      || Number(point.slice(65)) > 0x3fffffff)) throw new Error('Invalid fee preparation reservations.');
  if (points.some((point) => inFlight.has(point))) throw new Error('A fee preparation is still open in Humid.');
  for (const point of points) reserved.delete(point);
}

function amount(value, name, min, max) {
  if (typeof value !== 'bigint' || value < min || value > max) {
    throw new Error(`${name} must be ${min} to ${max} whole sats.`);
  }
  return value;
}

function destination(address) {
  if (typeof address !== 'string' || address.length > 100) throw new Error('Enter a Humid unconfidential testnet address.');
  try { return humidAddress(address); }
  catch { throw new Error('Enter a valid Humid unconfidential testnet address.'); }
}

function validateOutpoint(coin) {
  if (!coin || typeof coin.txid !== 'string' || !/^[0-9a-f]{64}$/.test(coin.txid)
    || !Number.isSafeInteger(coin.vout) || coin.vout < 0 || coin.vout > 0x3fffffff) {
    throw new Error('The coin list contains an invalid outpoint.');
  }
}

function coinList(coins, limit = MAX_COINS) {
  if (!Array.isArray(coins) || coins.length > limit) throw new Error(`Expected at most ${limit} coins.`);
  const seen = new Set();
  for (const coin of coins) {
    validateOutpoint(coin);
    if (seen.has(outpoint(coin))) throw new Error('The coin list contains a duplicate outpoint.');
    seen.add(outpoint(coin));
  }
  return coins;
}

function transaction(txHex, txid) {
  if (typeof txHex !== 'string' || txHex.length > MAX_TX_HEX || !/^(?:[0-9a-fA-F]{2})+$/.test(txHex)) {
    throw new Error('Liquid returned invalid transaction bytes.');
  }
  const raw = hexToBytes(txHex);
  const tx = parseTransaction(raw);
  if (displayHex(tx.txid) !== txid) throw new Error('Liquid returned a different transaction.');
  if (tx.witnessAt !== null) readWitness(raw);
  return tx;
}

async function network(esplora) {
  if (await esplora.blockHashAt(0) !== GENESIS) throw new Error('Connect to Liquid testnet.');
}

async function available(esplora, coin) {
  const [status, spend] = await Promise.all([esplora.txStatus(coin.txid), esplora.outspend(coin.txid, coin.vout)]);
  if (typeof status?.confirmed !== 'boolean' || typeof spend?.spent !== 'boolean') {
    throw new Error('Liquid did not confirm the coin status.');
  }
  return status.confirmed && !spend.spent;
}

const compare = (a, b) => a.sats === b.sats ? outpoint(a).localeCompare(outpoint(b)) : a.sats < b.sats ? -1 : 1;

/** Confirmed, unspent explicit tL-BTC at the supplied address, smallest first.
 * Raw parent bytes verify amounts and scripts; confirmation/unspent state relies
 * on Esplora and must be checked again immediately before the eventual spend.
 * Checks the smallest 32 candidates from at most 10,000 listed outputs.
 */
export async function discoverFeeCoins({ esplora, address, minSats = MIN_CHANGE_SATS, maxSats = MAX_FEE_SATS, skip = new Set() }) {
  const target = destination(address);
  amount(minSats, 'Minimum fee', 1n, MAX_FEE_SATS);
  amount(maxSats, 'Maximum fee', minSats, MAX_FEE_SATS);
  await network(esplora);
  const coins = coinList(await esplora.addressUtxos(target.address), MAX_ADDRESS_COINS).filter((coin) => coin.asset === ASSET
    && coin.status?.confirmed === true && !skip.has(outpoint(coin)) && !reserved.has(outpoint(coin)));
  const candidates = [];
  for (const coin of coins) {
    if (!Number.isSafeInteger(coin.value) || coin.value <= 0) throw new Error('Liquid returned an invalid coin amount.');
    const sats = BigInt(coin.value);
    if (sats >= minSats && sats <= maxSats) candidates.push({ ...coin, sats });
  }
  const found = [];
  for (const coin of candidates.sort(compare).slice(0, MAX_CHECKS)) {
    const txHex = await esplora.txHex(coin.txid);
    const tx = transaction(txHex, coin.txid);
    const output = tx.outputs[coin.vout];
    if (!output || output.asset.kind !== 'explicit' || output.value.kind !== 'explicit'
      || output.nonce.kind !== 'null' || !equal(output.asset.data, LBTC)
      || output.value.amount !== coin.sats || !equal(output.script, target.script)) {
      throw new Error('Liquid listed a fee coin that differs from its transaction.');
    }
    if (await available(esplora, coin)) found.push({ txid: coin.txid, vout: coin.vout, sats: coin.sats, txHex, ...target });
  }
  return found;
}

function walletCoin(coin) {
  if (typeof coin.amount !== 'string' || !/^[1-9][0-9]{0,15}$/.test(coin.amount)) throw new Error('Humid returned an invalid coin amount.');
  const sats = amount(BigInt(coin.amount), 'Wallet coin', 1n, MAX_MONEY);
  if (typeof coin.scriptPubKey !== 'string' || !/^0014[0-9a-fA-F]{40}$/.test(coin.scriptPubKey)
    || typeof coin.address !== 'string' || coin.address.length > 150) throw new Error('Humid returned an invalid coin address.');
  const decoded = /^tlq1/i.test(coin.address) ? decodeConfidential('tlq', coin.address) : decodeSegwit('tex', coin.address);
  if (decoded.version !== 0 || decoded.program.length !== 20
    || !equal(concat([0, 20], decoded.program), hexToBytes(coin.scriptPubKey))) {
    throw new Error('Humid returned a coin address with a different script.');
  }
  return { ...coin, sats };
}

function makePlan(fee, target, sats) {
  const change = fee.amount - sats - FEE_SATS;
  if (change < MIN_CHANGE_SATS) throw new Error('The wallet coin does not leave enough change.');
  const outputs = [
    { asset: LBTC, amount: sats, script: target.script },
    { asset: LBTC, amount: change, script: fee.script,
      ...(fee.blindingKey ? { blindingKey: fee.blindingKey, blinderIndex: 0 } : {}) },
    { asset: LBTC, amount: FEE_SATS, script: new Uint8Array() },
  ];
  const inputs = [fee];
  return {
    pset: base64(encodePset({ inputs, outputs })),
    unsigned: unsignedTx(inputs, outputs),
    signInputs: [{ address: fee.address, index: 0, sighashTypes: [1] }],
    spends: [outpoint(fee)], blindIndex: fee.blindingKey ? 1 : -1,
    address: target.address, sats, changeSats: change, feeSats: FEE_SATS,
  };
}

/** Verify every public field, allowing only the change commitments to be blinded.
 * The wallet validates the confidential amount and its proofs. Public transaction
 * bytes cannot independently reveal or prove that hidden change amount here.
 */
export function feeBroadcastMatches(plan, txHex, txid) {
  const sent = transaction(txHex, txid);
  const built = parseTransaction(plan.unsigned);
  const head = (tx) => tx.txidForm.subarray(0, tx.txidForm.length - 4 - tx.outputs.reduce((n, o) => n + o.raw.length, 0));
  if (!equal(head(sent), head(built)) || sent.locktime !== built.locktime) throw new Error('The sent fee preparation uses different transaction inputs.');
  if (sent.outputs.length !== built.outputs.length) throw new Error('The sent fee preparation has different outputs.');
  const witness = readWitness(hexToBytes(txHex));
  if (witness.inputs[0].script.length !== 2) throw new Error('The sent fee preparation has no wallet signature.');
  for (let index = 0; index < built.outputs.length; index++) {
    const output = sent.outputs[index];
    if (index === plan.blindIndex) {
      if (!equal(output.script, built.outputs[index].script) || output.asset.kind !== 'confidential'
        || output.value.kind !== 'confidential' || output.nonce.kind !== 'confidential') {
        throw new Error('The sent change does not match the wallet address.');
      }
      const proof = witness.outputs[index];
      if (!proof.rangeproof.length || !proof.surjectionProof.length) throw new Error('The sent change has no confidential proofs.');
    } else if (!equal(output.raw, built.outputs[index].raw)) {
      throw new Error('The sent fee coin or miner fee differs from the approved plan.');
    }
  }
  return null;
}

/** One wallet-approved transfer. No retry or confirmation polling. Caller must
 * show the destination and confirm the user controls it. onSign runs before the
 * request and must persist its spent outpoints across reloads. A possibly sent
 * request reserves its input; only an explicit pre-sign refusal releases it.
 */
export async function prepareFeeWithHumid({ humid, esplora, address, sats, skip = new Set(), onSign = () => {}, progress = () => {}, deadlineMs = SIGN_DEADLINE_MS }) {
  const target = destination(address);
  amount(sats, 'Prepared fee', MIN_CHANGE_SATS, MAX_FEE_SATS);
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > SIGN_DEADLINE_MS) throw new Error('Invalid wallet request deadline.');
  if (active.has(humid)) throw new Error('A fee preparation is already open in Humid.');
  active.add(humid);
  let plan;
  let ownsReservation = false;
  let signing = false;
  let txid;
  try {
    await network(esplora);
    progress('Connect Humid to Liquid testnet.');
    await humidSession(humid);
    progress('Checking wallet coins…');
    const answer = await humidCall(humid, 'getUTXOs', {});
    const coins = coinList(answer?.utxos).filter((coin) => coin.spendable === true
      && (coin.assetId === ASSET || coin.assetId === `bip122:a771da8e52ee6ad581ed1e9a99825e5b/elip144:${ASSET}`)
      && !skip.has(outpoint(coin)) && !reserved.has(outpoint(coin))).map(walletCoin)
      .filter((coin) => coin.sats >= sats + FEE_SATS + MIN_CHANGE_SATS).sort(compare);
    let fee;
    for (const coin of coins.slice(0, MAX_CHECKS)) {
      if (!await available(esplora, coin)) continue;
      const raw = await esplora.txHex(coin.txid);
      const source = transaction(raw, coin.txid).outputs[coin.vout];
      if (source?.value.kind === 'confidential' && source.nonce.kind !== 'confidential') {
        throw new Error('The wallet coin has no confidential nonce.');
      }
      fee = feeInput(coin, raw);
      break;
    }
    if (!fee) throw new Error(`Humid needs a confirmed tL-BTC coin of at least ${sats + FEE_SATS + MIN_CHANGE_SATS} sats.`);
    plan = makePlan(fee, target, sats);
    // Recheck after fetching and validating the source, before requesting approval.
    if (!await available(esplora, fee) || reserved.has(outpoint(fee)) || skip.has(outpoint(fee))) {
      throw new Error('The wallet coin is no longer available.');
    }
    reserved.add(outpoint(fee));
    inFlight.add(outpoint(fee));
    ownsReservation = true;
    progress('Check the fee transfer in Humid, then approve.');
    await onSign(plan.spends);
    signing = true;
    txid = await signAndBroadcast(humid, plan, deadlineMs);
    const txHex = await esplora.txHex(txid);
    feeBroadcastMatches(plan, txHex, txid);
    return { txid, vout: 0, sats, txHex, address: target.address, confirmed: false, plan };
  } catch (error) {
    const failure = error instanceof Error ? error : new Error('Fee preparation failed.');
    const reason = error?.data?.reason;
    const refused = !txid && (reason === 'user_rejected' || (typeof reason === 'string' && reason.startsWith('invalid_')));
    failure.sent = signing && !refused ? 'maybe' : 'no';
    if (plan) {
      failure.plan = plan;
      failure.spends = plan.spends;
      if (failure.sent === 'no' && ownsReservation) for (const spend of plan.spends) reserved.delete(spend);
    }
    if (txid) failure.txid = txid;
    throw failure;
  } finally {
    if (ownsReservation) for (const point of plan.spends) inFlight.delete(point);
    active.delete(humid);
  }
}
