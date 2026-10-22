// Sending a claim with Humid. The claim is the transaction OPERATOR.md step 5's `assemble.py claim` writes,
// claim.hex: input 0 spends the live state UTXO with the claim leaf's Simplicity witness and reissues the deposit's
// units of the bridge asset; input 1, the fee, is an open tL-BTC coin, left unsigned; output 0 is the successor
// state, output 1 the units, paid openly to the script the deposit committed, and output 2 the fee, the whole of
// input 1. The claim leaf requires that shape but reads nothing of input 1 beyond its having no issuance, so the
// claim can be built against an open coin Humid holds, which Humid can then sign.
//
// This page builds no claim and changes nothing in one. It checks the file against this site's manifest and the
// outputs it spends against the Liquid API, then hands Humid a PSET whose input 0 is final, reissuance included, and
// whose input 1 Humid signs. A txid does not commit to witnesses, so the claim's txid is fixed before signing, and
// Humid's broadcast must have it. Unlike an update, a claim moves no light-client store, so nothing need be published
// first: the covenant pays only the deposit's own script, whoever sends it.
//
// lib/humid.js encodePset has no issuance fields, so the PSET is written here, in the fields LWK writes for an
// explicit reissuance (lwk_wollet pset_create.rs set_reissuance) and otherwise as encodePset writes them.
import { encodeSegwit } from './bech32.js';
import { bigToBytes, bytesToHex, concat, equal, hexToBytes } from './bytes.js';
import { LIQUID_TESTNET_HRP, LIQUID_TESTNET_LBTC, MAX_UNITS, MIN_UNITS, isStandardRecipient } from './bridge.js';
import { displayHex, parseTransaction, readWitness, txidFromDisplay } from './elements.js';
import { SIGN_DEADLINE_MS, base64, explicitTxOut, humidError, humidSession, signAndBroadcast } from './humid.js';
import { HUMID_MAX_PSET, MAX_FEE_SATS } from './update.js';

const SIMPLICITY_LEAF = 0xbe; // Elements' tapleaf version for Simplicity
const FINAL = 0xffffffff;
const ISSUANCE = 0x80000000; // the outpoint index flag of an input that issues; 0x40000000 marks a peg-in
const LBTC = hexToBytes(LIQUID_TESTNET_LBTC);

const isP2tr = (s) => s.length === 34 && s[0] === 0x51 && s[1] === 0x20;
const isP2wpkh = (s) => s.length === 22 && s[0] === 0x00 && s[1] === 0x14;
const isOpenLbtc = (o) => o.asset.kind === 'explicit' && equal(o.asset.data, LBTC) && o.value.kind === 'explicit' && o.nonce.kind === 'null';
const isBlinded = (o) => o.asset.kind === 'confidential' && o.value.kind === 'confidential';
/** A confidential commitment as an output serializes it, from the manifest's { bit, x } (`sg16-testnet-claim cmr`). */
const commitment = (p, base) => (p && (p.bit === 0 || p.bit === 1) && /^[0-9a-f]{64}$/.test(p.x ?? '') ? concat([base | p.bit], hexToBytes(p.x)) : null);

/**
 * The bridge parameters a claim must use, from this site's manifest.json: the claim leaf's CMR, the bridge asset
 * (internal order) and its reissuance entropy, the token's public blinding factor in each phase, which a claim
 * reveals as its reissuance nonce, and the token's asset commitment in each phase and its constant value commitment.
 * Throws unless the manifest names each.
 */
export function claimParams(m) {
  const word = (x, what) => {
    if (!/^[0-9a-f]{64}$/.test(x ?? '')) throw new Error(`this site's manifest.json names no ${what}`);
    return hexToBytes(x);
  };
  const cmr = word(m?.claim_leaf?.cmr, 'claim leaf');
  const asset = word(m?.bootstrap?.asset, 'bridge asset');
  const entropy = word(m?.bootstrap?.entropy, 'bridge asset entropy');
  const blindings = [word(m?.harness_config?.abf_a, 'token blinding'), word(m?.harness_config?.abf_b, 'token blinding')];
  const tokens = [commitment(m?.constants?.token_a, 0x0a), commitment(m?.constants?.token_b, 0x0a)];
  const tokenValue = commitment(m?.constants?.token_value, 0x08);
  if (!tokens[0] || !tokens[1] || !tokenValue) throw new Error('this site\'s manifest.json names no bridge token commitments');
  return { cmr, asset, entropy, blindings, tokens, tokenValue };
}

/** The unconfidential address of a segwit script, or null for P2SH and P2PKH, which have none in bech32. */
const segwitAddress = (s) => (s[1] === s.length - 2 && (s[0] === 0x00 || s[0] === 0x51) ? encodeSegwit(LIQUID_TESTNET_HRP, s[0] === 0 ? 0 : 1, s.subarray(2)) : null);

/**
 * The claim in `raw` (claim.hex as bytes), against this instance's parameters `p` (claimParams): { txid, txidForm,
 * state: { txid, vout, token, tokenValue }, fee: { txid, vout, sats }, witness, issuance: { nonce, entropy, units },
 * successor, mint: { script, units, asset, address } }, where `token` is the commitment the spent state must hold.
 * Throws unless it has exactly the claim leaf's shape: inputs [state, fee], input 0 spending with this instance's
 * claim leaf and reissuing the bridge asset openly with the spent token's blinding, input 1 unsigned, with no
 * issuance; outputs [the successor, the bridge token in the other phase, to a Taproot script; the reissued units,
 * openly, to a standard wallet script; an open tL-BTC fee of at most MAX_FEE_SATS]. Version 2, locktime 0 and final
 * sequences, the only values the PSET written here carries.
 */
export function readClaim(raw, p) {
  const tx = parseTransaction(raw);
  if (tx.witnessAt === null) throw new Error('this transaction carries no witness, so it is not a claim: load the claim.hex that just claim-unsigned wrote');
  const w = readWitness(raw);
  if (tx.inputs.length !== 2 || tx.outputs.length !== 3) {
    throw new Error('a claim has two inputs, the state and the fee, and three outputs, the successor state, the claimed units and the fee');
  }
  if (tx.version !== 2 || tx.locktime !== 0 || tx.inputs.some((i) => i.sequence !== FINAL)) {
    throw new Error('this claim is not version 2 with locktime 0 and final sequences, as assemble.py claim writes it');
  }
  const [stateIn, feeIn] = tx.inputs;
  if ((stateIn.n >>> 30) !== 2 || !stateIn.issuance) throw new Error('input 0 issues nothing, so this is not a claim');
  if ((feeIn.n >>> 30) !== 0 || feeIn.issuance) throw new Error('input 1 issues or pegs in; a claim\'s fee input does neither');
  const { nonce, entropy, amount, inflationKeys } = stateIn.issuance;
  if (!equal(entropy, p.entropy)) throw new Error('input 0 issues another asset than this instance\'s bridge asset');
  const phase = p.blindings.findIndex((b) => equal(b, nonce));
  if (phase < 0) throw new Error('input 0 is not a reissuance with the bridge token\'s public blinding');
  if (amount.kind !== 'explicit' || inflationKeys.kind !== 'null') throw new Error('input 0 must reissue an open amount and no tokens');
  const units = amount.amount;
  if (units < MIN_UNITS || units > MAX_UNITS) throw new Error(`input 0 reissues ${units} units, outside the escrow's deposit bounds`);
  if (w.inputs.some((i) => i.issuanceProof.length || i.inflationProof.length || i.pegin.length)) throw new Error('a claim has no issuance proofs or peg-in witness');
  const [leaf, fee] = w.inputs;
  if (leaf.script.length !== 4) throw new Error('input 0 does not spend with a claim leaf\'s witness: program witness, program, CMR, control block');
  const [, , cmr, control] = leaf.script;
  if (!equal(cmr, p.cmr)) throw new Error(`input 0 spends with Simplicity leaf ${bytesToHex(cmr).slice(0, 8)}…, not this instance's claim leaf ${bytesToHex(p.cmr).slice(0, 8)}…`);
  if (control.length < 33 || (control.length - 33) % 32 !== 0 || (control[0] & 0xfe) !== SIMPLICITY_LEAF) throw new Error('input 0\'s control block is not a Simplicity leaf\'s');
  if (fee.script.length !== 0) {
    throw new Error('input 1 is signed already, so this claim needs no Humid: broadcast it as OPERATOR.md says, or load the unsigned claim.hex');
  }
  const [succ, mint, feeOut] = tx.outputs;
  const proofs = w.outputs[0];
  if (!isBlinded(succ) || succ.nonce.kind !== 'null' || !isP2tr(succ.script) || !proofs.surjectionProof.length || !proofs.rangeproof.length
    || !equal(succ.asset.data, p.tokens[1 - phase]) || !equal(succ.value.data, p.tokenValue)) {
    throw new Error('output 0 is not a successor state: the bridge token, in its other blinding, with its proofs, to a Taproot script');
  }
  if (mint.asset.kind !== 'explicit' || !equal(mint.asset.data, p.asset) || mint.value.kind !== 'explicit' || mint.value.amount !== units || mint.nonce.kind !== 'null') {
    throw new Error('output 1 does not pay the reissued units of the bridge asset openly');
  }
  if (!isStandardRecipient(mint.script)) throw new Error('output 1 does not pay a standard wallet script, as every deposit names');
  if (!isOpenLbtc(feeOut) || feeOut.script.length !== 0) throw new Error('output 2 is not an open tL-BTC fee');
  if (w.outputs.slice(1).some((o) => o.surjectionProof.length || o.rangeproof.length)) throw new Error('an open output carries proofs');
  const sats = feeOut.value.amount;
  if (sats <= 0n || sats > MAX_FEE_SATS) throw new Error(`this claim pays ${sats} sats of fee; this page sends at most ${MAX_FEE_SATS}. Build it against a smaller fee coin`);
  const outpoint = (i) => ({ txid: displayHex(i.prevTxid), vout: i.n & 0x3fffffff });
  return {
    txid: displayHex(tx.txid),
    txidForm: tx.txidForm,
    state: { ...outpoint(stateIn), token: p.tokens[phase], tokenValue: p.tokenValue },
    fee: { ...outpoint(feeIn), sats },
    witness: leaf.script,
    issuance: { nonce, entropy, units },
    successor: { script: succ.script, blinded: { valueCommitment: succ.value.data, assetCommitment: succ.asset.data, ...proofs } },
    mint: { script: mint.script, units, asset: p.asset, address: segwitAddress(mint.script) },
  };
}

// ---- the PSET ----

const ELEMENTS = Uint8Array.of(0xfc, 0x04, 0x70, 0x73, 0x65, 0x74); // proprietary key prefix "pset"
const le32 = (n) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, n >>> 24);
const le64 = (v) => bigToBytes(v, 8).reverse();

function compactSize(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
  if (n <= 0xffffffff) return concat([0xfe], le32(n));
  throw new Error('PSET field too large');
}

const field = (key, value) => concat(compactSize(key.length), key, compactSize(value.length), value);
const keyMap = (...fields) => concat(...fields, [0x00]); // a PSET map ends with a zero-length key
const elements = (type, value) => field(concat(ELEMENTS, [type]), value);
const witnessStack = (items) => concat(compactSize(items.length), ...items.map((x) => concat(compactSize(x.length), x)));

/**
 * The claim's PSET v2 of `inputs` { txid, vout, witnessUtxo, finalWitness?, issuance? } and `outputs` { script,
 * blinded } or { asset, amount, script }. An issuing input carries its explicit amount (PSBT_ELEMENTS_IN_ISSUANCE_VALUE,
 * little-endian), blinding nonce and entropy as the transaction has them, and the flag that it is not to be blinded
 * (PSBT_ELEMENTS_IN_BLINDED_ISSUANCE 0), as LWK writes a reissuance. Every other field is as lib/humid.js encodePset
 * writes it; no output carries a blinding key, so Humid blinds nothing.
 */
function encodeClaimPset({ inputs, outputs }) {
  return concat(
    Uint8Array.of(0x70, 0x73, 0x65, 0x74, 0xff),
    keyMap(field([0x02], le32(2)), field([0x04], compactSize(inputs.length)), field([0x05], compactSize(outputs.length)), field([0xfb], le32(2))),
    ...inputs.map((i) => keyMap(
      field([0x01], i.witnessUtxo),
      field([0x0e], txidFromDisplay(i.txid)),
      field([0x0f], le32(i.vout)),
      ...(i.issuance ? [elements(0x00, le64(i.issuance.units)), elements(0x0c, i.issuance.nonce), elements(0x0d, i.issuance.entropy), elements(0x15, [0x00])] : []),
      ...(i.finalWitness ? [field([0x08], witnessStack(i.finalWitness))] : []),
    )),
    ...outputs.map((o) => keyMap(
      ...(o.blinded ? [] : [field([0x03], le64(o.amount)), elements(0x02, o.asset)]),
      field([0x04], o.script),
      ...(o.blinded ? [elements(0x01, o.blinded.valueCommitment), elements(0x03, o.blinded.assetCommitment),
        elements(0x04, o.blinded.rangeproof), elements(0x05, o.blinded.surjectionProof)] : []),
    )),
  );
}

/** The transaction the PSET's inputs and outputs describe, in txid serialization: what Humid extracts and signs. */
function claimTransaction({ inputs, outputs }) {
  return concat(
    le32(2), [0x00], compactSize(inputs.length),
    ...inputs.map((i) => concat(
      txidFromDisplay(i.txid), le32(i.issuance ? (i.vout | ISSUANCE) >>> 0 : i.vout), [0x00], le32(FINAL),
      ...(i.issuance ? [i.issuance.nonce, i.issuance.entropy, [0x01], bigToBytes(i.issuance.units, 8), [0x00]] : []),
    )),
    compactSize(outputs.length),
    ...outputs.map((o) => (o.blinded
      ? concat(o.blinded.assetCommitment, o.blinded.valueCommitment, [0x00], compactSize(o.script.length), o.script)
      : explicitTxOut(o.asset, o.amount, o.script))),
    le32(0),
  );
}

/**
 * The claim `c` (readClaim) as a PSET for Humid's signPset, given the transactions it spends as the Liquid API serves
 * them. Input 0 carries its witness as final and its reissuance, so no wallet touches it; Humid's review lists it as
 * not the wallet's. Input 1 must be an open coin of exactly the fee, at a P2WPKH script, as Humid's are: Humid adds its
 * key path from that script and signs it alone. The outputs are the claim's. Returns { txid, pset, signInputs,
 * feeAddress, successorAddress }; throws unless the PSET's transaction is the claim, byte for byte.
 */
export function claimPset(c, stateTxHex, feeTxHex) {
  const spent = (hex, { txid, vout }) => {
    const tx = parseTransaction(hexToBytes(hex));
    if (displayHex(tx.txid) !== txid) throw new Error('the Liquid API returned a different transaction');
    if (!tx.outputs[vout]) throw new Error(`transaction ${txid} has no output ${vout}`);
    return tx.outputs[vout];
  };
  const state = spent(stateTxHex, c.state);
  if (!isBlinded(state) || !isP2tr(state.script) || !equal(state.asset.data, c.state.token) || !equal(state.value.data, c.state.tokenValue)) {
    throw new Error('input 0 does not spend a state UTXO: the bridge token, in the blinding its reissuance names, at a Taproot script');
  }
  const coin = spent(feeTxHex, c.fee);
  if (!isOpenLbtc(coin) || coin.value.amount !== c.fee.sats) throw new Error(`input 1 is not an open coin of exactly ${c.fee.sats} sats of tL-BTC, the claim's whole fee`);
  if (!isP2wpkh(coin.script)) throw new Error('input 1 is not at a P2WPKH address, as Humid\'s coins are');
  const inputs = [
    { txid: c.state.txid, vout: c.state.vout, witnessUtxo: state.raw, finalWitness: c.witness, issuance: c.issuance },
    { txid: c.fee.txid, vout: c.fee.vout, witnessUtxo: coin.raw },
  ];
  const outputs = [
    { script: c.successor.script, blinded: c.successor.blinded },
    { asset: c.mint.asset, amount: c.mint.units, script: c.mint.script },
    { asset: LBTC, amount: c.fee.sats, script: new Uint8Array(0) },
  ];
  // Signing adds witnesses only, so Humid's transaction is the PSET's: it must be this claim.
  if (!equal(claimTransaction({ inputs, outputs }), c.txidForm)) throw new Error('the PSET built here is not the claim; nothing was sent. Report this');
  const pset = base64(encodeClaimPset({ inputs, outputs }));
  if (pset.length > HUMID_MAX_PSET) throw new Error(`this claim is ${pset.length} characters as a PSET, more than the ${HUMID_MAX_PSET} Humid accepts`);
  const feeAddress = encodeSegwit(LIQUID_TESTNET_HRP, 0, coin.script.subarray(2));
  return {
    txid: c.txid, pset, signInputs: [{ address: feeAddress, index: 1, sighashTypes: [1] }],
    feeAddress, successorAddress: encodeSegwit(LIQUID_TESTNET_HRP, 1, c.successor.script.subarray(2)),
  };
}

// ---- the Liquid API and Humid ----

/**
 * A reader of this site's copy of the instance record (config.js INSTANCE.record), for a page at `pageHref`: path ->
 * the file's text, bypassing the browser cache. A claim needs nothing published, so unlike lib/update.js recordReader
 * a page served from this computer may read its working tree's record.
 */
export function siteReader(fetchImpl, pageHref, record) {
  return async (path) => {
    const res = await fetchImpl(new URL(record + path, pageHref).href, { cache: 'no-store' });
    if (!res.ok) throw Object.assign(new Error(`this site's ${record}${path}: HTTP ${res.status}`), { status: res.status });
    return res.text();
  };
}

/**
 * Throws unless claim `c` is still to be sent: the Liquid API does not know its txid, and the outputs it spends are
 * confirmed and unspent. As for an update (lib/update.js), only a 404 for the transaction itself shows it unknown:
 * Esplora answers {confirmed: false} for a txid it has never seen. Any other failure is passed on.
 */
async function unsent(esplora, c) {
  const s = await esplora.txStatus(c.txid).catch((e) => { if (e.status === 404) return null; throw e; });
  let known = Boolean(s?.confirmed);
  if (!known) {
    try {
      await esplora.txHex(c.txid);
      known = true;
    } catch (e) {
      if (e.status !== 404) throw e;
    }
  }
  if (known) throw new Error(`claim ${c.txid} is on Liquid already (${s?.confirmed ? 'confirmed' : 'not confirmed yet'}); nothing to send`);
  // `just status` recovers the live state before it names the next claim.
  const next = 'run just status again: it recovers the live state and names the next claim, if one is due';
  for (const [o, what] of [[c.state, 'the state output'], [c.fee, 'your fee coin']]) {
    if (!(await esplora.txStatus(o.txid))?.confirmed) throw new Error(`${what} ${o.txid}:${o.vout} is not confirmed yet; wait for it, then load the claim again`);
    const spent = await esplora.outspend(o.txid, o.vout);
    if (spent?.spent) {
      throw new Error(o === c.state
        ? `the state output this claim spends is spent already, by ${spent.txid}: the bridge has moved on, perhaps by this very claim. To go on, ${next}`
        : `your fee coin ${o.txid}:${o.vout} is spent already, by ${spent.txid}; build the claim against another`);
    }
  }
}

/**
 * Everything the page checks before Humid is involved, for the claim in `raw`: its shape against the parameters of
 * this site's manifest.json (claimParams, readClaim), and the Liquid state of what it spends (unsent). Returns the
 * PSET plan of claimPset with { claim }.
 */
export async function prepareClaim({ esplora, readRecord, raw }) {
  const claim = readClaim(raw, claimParams(JSON.parse(await readRecord('manifest.json'))));
  await unsent(esplora, claim);
  const plan = claimPset(claim, await esplora.txHex(claim.state.txid), await esplora.txHex(claim.fee.txid));
  return { ...plan, claim };
}

/**
 * Sends `plan` (prepareClaim) with Humid: checks again that it is unsent, then has Humid sign input 1 and broadcast
 * once the user confirms (signAndBroadcast, whose `sent` marks its errors carry). Humid's txid must be the claim's;
 * another is thrown as `reported`, since Humid may have broadcast it.
 */
export async function sendClaim({ humid, esplora, plan, progress = () => {}, deadlineMs = SIGN_DEADLINE_MS }) {
  progress('Checking on Liquid that the claim is unsent and its coins unspent…');
  await unsent(esplora, plan.claim);
  progress('Approve the connection to this page in Humid, if it asks…');
  await humidSession(humid);
  progress('Review the claim in Humid, then sign and send…');
  const txid = await signAndBroadcast(humid, plan, deadlineMs);
  if (txid !== plan.txid) {
    throw Object.assign(new Error(`Humid reports sending ${txid}, not the claim ${plan.txid}`), { sent: 'maybe', reported: txid });
  }
  return txid;
}

/**
 * Where the Liquid API has the claim `txid`, once Humid has answered a request to send it: { where: 'confirmed',
 * height }, { where: 'mempool' }, or { where: 'unknown', why }. Humid's answer alone shows nothing on Liquid, so the
 * panel reports this instead.
 *
 * Only the transaction itself shows the claim sent: Esplora answers {confirmed: false} for a txid it has never seen.
 * The copy served must hash to `txid`, which fixes the claim's inputs and outputs. A 404 is asked again up to `tries`
 * times, `waitMs` apart, as the Liquid API can lag Humid's broadcast by a few seconds; any other failure, or a copy
 * that is not the claim, is 'unknown' at once. This trusts the Liquid API, as every check on this page does.
 */
export async function claimOnLiquid(esplora, txid, { tries = 1, waitMs = 3000 } = {}) {
  let hex = null;
  for (let i = 1; hex === null; i++) {
    try {
      hex = await esplora.txHex(txid);
    } catch (e) {
      if (e?.status !== 404) return { where: 'unknown', why: `the Liquid API could not be read (${(e && e.message) || e})` };
      if (i >= tries) return { where: 'unknown', why: 'the Liquid API does not show it' };
      await new Promise((r) => setTimeout(r, waitMs));
    }
  }
  let served = null;
  try {
    served = displayHex(parseTransaction(hexToBytes(hex)).txid);
  } catch {
    // Unreadable: not the claim either.
  }
  if (served !== txid) return { where: 'unknown', why: 'the Liquid API serves another transaction for its txid' };
  let s;
  try {
    s = await esplora.txStatus(txid);
  } catch (e) {
    return { where: 'unknown', why: `the Liquid API has it, but its confirmation could not be read (${(e && e.message) || e})` };
  }
  return s?.confirmed ? { where: 'confirmed', height: s.block_height ?? null } : { where: 'mempool' };
}

/**
 * Where each of `deposits` stands against the claims of the bridge state, for the Activity rows. `deposits` are this
 * browser's deposits to this instance's escrow, each with its `index` (from its Deposit event, or null), `script`
 * (hex) and `units`; `live` is lib/update.js liveState's answer, whose `claims` and `movingClaim` say which deposit
 * index each claim paid, as its output 0 commits it, or null where that is unknown.
 *
 * A deposit is associated with a claim only by that index, never by order or by matching outputs: deposits to one
 * script may share their units, and claims may pay them in any order. Returns a Map from each deposit to
 *   { status: 'claimed' | 'claiming', txid, vout: 1 } when a confirmed or unconfirmed claim paid exactly its index,
 *     to the script and units saved for it;
 *   { status: 'unresolved', why } when no claim is known to have paid it, but one may have: some claim's index is
 *     unknown, or the deposit's own index is, while claims exist, or the claim of its index paid another script or
 *     amount than this browser saved;
 * and leaves out the deposits that no claim paid, every claim's index being known: they are still to be claimed.
 */
export function depositClaims(deposits, live) {
  const claims = [...(live?.claims ?? []), ...(live?.movingClaim ? [live.movingClaim] : [])];
  const unknown = claims.filter((c) => c.index === null).length;
  const some = (n) => (n === 1 ? 'a claim' : `${n} claims`);
  const out = new Map();
  for (const d of deposits) {
    const index = d.index === null || d.index === undefined ? null : Number(d.index);
    const c = index === null ? undefined : claims.find((x) => x.index === index);
    if (c && c.pays?.script === String(d.script).toLowerCase() && c.pays.units === BigInt(d.units)) {
      out.set(d, { status: c.confirmed ? 'claimed' : 'claiming', txid: c.txid, vout: 1 });
    } else if (c) {
      out.set(d, { status: 'unresolved', why: `claim ${c.txid} paid deposit #${index}, but not the script and units this browser saved for it` });
    } else if (index === null && claims.length) {
      out.set(d, { status: 'unresolved', why: `this browser does not know this deposit's index, so it cannot tell whether ${some(claims.length)} on Liquid paid it` });
    } else if (unknown) {
      out.set(d, { status: 'unresolved', why: `${some(unknown)} on Liquid could not be attributed to a deposit, so this page cannot tell whether one paid this deposit` });
    }
  }
  return out;
}

/**
 * What to tell the user when Humid refuses or fails a claim. Like an update, a claim cannot be sent twice: its txid is
 * fixed, and the page looks it up on Liquid before it asks Humid again.
 */
export function claimError(e) {
  if (e?.data?.reason === 'user_rejected') return humidError(e);
  const what = (e && e.message) || String(e);
  if (e?.sent === 'no' && e.stage === 'review') {
    return `Humid stopped before asking you to sign (${what}): its review of the claim failed, so nothing was signed or sent.`;
  }
  if (e?.reported) {
    return `Humid reports sending ${e.reported}, which is not this claim: this page did not build that transaction. `
      + 'Look both txids up on a Liquid explorer before you do anything else with this claim or its fee coin.';
  }
  if (e?.sent === 'maybe') {
    return `Humid did not confirm sending the claim (${what}). It may have been sent all the same: look its txid up on a Liquid explorer. `
      + 'To send it again, load claim.hex again: this page first checks whether Liquid knows it.'
      + (e?.data?.reason === 'wallet_pset_broadcast_failed' ? ' If nothing was sent: Humid signs only coins it holds, so check that the fee coin is at '
        + 'this Humid wallet\'s address under Receive, then Unconfidential.' : '');
  }
  return `Humid: ${what}`;
}
