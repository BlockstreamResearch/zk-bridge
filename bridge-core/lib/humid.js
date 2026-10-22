// Burning a claim with the Humid browser wallet (BlockstreamResearch/humid, read at release 1.1.3, commit c5c8940,
// with its pinned LWK 693c4fb). A claim pays an explicit output, which Humid's ordinary Send and its coin list skip.
// Its signPset method (1.1.1 and later) can spend it: given a PSET whose inputs carry their witness UTXOs, Humid adds
// the key path of each input that is its own, blinds the outputs the PSET marks for blinding, shows every output and
// the fee, and once the user confirms signs that PSET and broadcasts it. So this page builds the burn from public
// Liquid data: the claim, found at the unconfidential address it paid, and a tL-BTC coin Humid lists for the fee.
// Nothing here holds a key. Humid signs only its own inputs, and the escrow reads only the burn output built here.
import { decodeConfidential, decodeSegwit } from './bech32.js';
import { bigToBytes, concat, equal, hexToBytes } from './bytes.js';
import { LIQUID_TESTNET_HRP, LIQUID_TESTNET_LBTC, burnOutputs, formatUnits, isStandardRecipient, readBurnScript } from './bridge.js';
import { displayHex, outputWitnesses, parseTransaction, txidFromDisplay } from './elements.js';

/** Humid's CAIP-2 scope for Liquid testnet. */
export const HUMID_SCOPE = 'bip122:a771da8e52ee6ad581ed1e9a99825e5b';
export const LIQUID_TESTNET_CONFIDENTIAL_HRP = 'tlq';
/**
 * The burn's miner fee in sats. At Liquid's 0.1 sat/vB relay floor the largest burn built here (MAX_CLAIMS claims and
 * a confidential fee coin) is about 2,300 vB, 230 sats, before Liquid's discount for confidential outputs.
 */
export const FEE_SATS = 500n;
/** The least tL-BTC change a burn leaves, as tools/sg16/liquid-testnet-wallet burn requires. */
export const MIN_CHANGE_SATS = 546n;
export const MAX_CLAIMS = 10;
/**
 * How long the page waits for Humid's answer to the signing request: its review (with a wallet sync), the user's
 * approval, which Humid closes after 30 seconds, and its broadcast. Humid's page provider never times out.
 */
export const SIGN_DEADLINE_MS = 3 * 60_000;

// ---- encodings ----

const MAGIC = Uint8Array.of(0x70, 0x73, 0x65, 0x74, 0xff); // "pset", 0xff
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
/** A witness stack as consensus serializes it: the item count, then each item with its length. */
const witnessStack = (items) => concat(compactSize(items.length), ...items.map((x) => concat(compactSize(x.length), x)));

/** An explicit output's serialization: asset (internal order), value (big-endian), no nonce, script. */
export function explicitTxOut(asset, amount, script) {
  return concat([0x01], asset, [0x01], bigToBytes(amount, 8), [0x00], compactSize(script.length), script);
}

/**
 * A PSET v2 (BIP 370 with Elements' fields) of `inputs` { txid (display hex), vout, witnessUtxo, rangeproof? } and
 * `outputs` { asset (internal order), amount, script, blindingKey?, blinderIndex? }, in the fields LWK writes: the
 * global transaction version, counts and PSET version; each input's witness UTXO, previous txid and index, and for a
 * confidential one the rangeproof of the output it spends; each output's amount, asset and script, and for one to be
 * blinded, its receiver's blinding key and the input whose owner blinds it.
 *
 * A witness UTXO is serialized without its output witness, so a wallet can unblind a confidential input only from
 * that separate rangeproof (Elements' PSBT_ELEMENTS_IN_UTXO_RANGEPROOF): LWK's pset_balance, which Humid's review
 * runs, fails on a wallet input that has neither it nor blind proofs, which only the input's owner can make.
 *
 * Two forms serve a transaction someone else has already partly made, as a bridge update is. An input with
 * `finalWitness`, its stack of items, is final (PSBT_IN_FINAL_SCRIPTWITNESS): no wallet signs it. An output given
 * `blinded` { valueCommitment, assetCommitment, rangeproof, surjectionProof } instead of an amount and asset is
 * already confidential, in the fields rust-elements writes for a confidential output (Output::from_txout), with no
 * nonce, so no wallet blinds it again or can read it.
 */
export function encodePset({ inputs, outputs }) {
  return concat(
    MAGIC,
    keyMap(field([0x02], le32(2)), field([0x04], compactSize(inputs.length)), field([0x05], compactSize(outputs.length)), field([0xfb], le32(2))),
    ...inputs.map((i) => keyMap(
      field([0x01], i.witnessUtxo),
      field([0x0e], txidFromDisplay(i.txid)),
      field([0x0f], le32(i.vout)),
      ...(i.rangeproof ? [field(concat(ELEMENTS, [0x0e]), i.rangeproof)] : []),
      ...(i.finalWitness ? [field([0x08], witnessStack(i.finalWitness))] : []),
    )),
    ...outputs.map((o) => keyMap(
      ...(o.blinded ? [] : [field([0x03], le64(o.amount)), field(concat(ELEMENTS, [0x02]), o.asset)]),
      field([0x04], o.script),
      ...(o.blindingKey ? [field(concat(ELEMENTS, [0x06]), o.blindingKey), field(concat(ELEMENTS, [0x08]), le32(o.blinderIndex))] : []),
      ...(o.blinded ? [
        field(concat(ELEMENTS, [0x01]), o.blinded.valueCommitment),
        field(concat(ELEMENTS, [0x03]), o.blinded.assetCommitment),
        field(concat(ELEMENTS, [0x04]), o.blinded.rangeproof),
        field(concat(ELEMENTS, [0x05]), o.blinded.surjectionProof),
      ] : []),
    )),
  );
}

/** The transaction a PSET of these inputs and outputs describes before blinding, in txid serialization. */
export function unsignedTx(inputs, outputs) {
  return concat(
    le32(2), [0x00], compactSize(inputs.length),
    ...inputs.map((i) => concat(txidFromDisplay(i.txid), le32(i.vout), [0x00], le32(0xffffffff))),
    compactSize(outputs.length),
    ...outputs.map((o) => (o.blinded
      ? concat(o.blinded.assetCommitment, o.blinded.valueCommitment, [0x00], compactSize(o.script.length), o.script)
      : explicitTxOut(o.asset, o.amount, o.script))),
    le32(0),
  );
}

export function base64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

// ---- coins ----

/**
 * The address holding the claim: Humid's unconfidential address, under Receive, then Unconfidential. Humid's wallet
 * is P2WPKH, and it tracks open coins only at that address, its first.
 */
export function humidAddress(text) {
  const s = text.trim();
  if (/^tlq1/i.test(s)) throw new Error('this is Humid\'s confidential address: in Humid open Receive, then the Unconfidential tab, and copy the tex1q… address there');
  const { version, program } = decodeSegwit(LIQUID_TESTNET_HRP, s);
  if (version !== 0 || program.length !== 20) throw new Error('Humid\'s unconfidential address is a tex1q… address of 43 characters');
  return { address: s.toLowerCase(), script: concat([0x00, 0x14], program) };
}

const byAmount = (key) => (a, b) => (a[key] !== b[key] ? (a[key] < b[key] ? -1 : 1) : `${a.txid}:${a.vout}` < `${b.txid}:${b.vout}` ? -1 : 1);

/**
 * The claim coins a burn of `units` spends: confirmed explicit outputs of the bridge asset (display id) among Esplora's
 * /address/:address/utxo entries, largest first, as few as cover `units`. The amounts are Esplora's; claimInput checks
 * each against its transaction's bytes. `skip` holds "txid:vout" of coins a send from this page may already have
 * spent: Esplora can list them for a while after.
 */
export function selectClaims(utxos, assetDisplay, units, skip = new Set()) {
  const held = utxos.filter((u) => u.asset === assetDisplay && Number.isSafeInteger(u.value) && u.value > 0 && !skip.has(`${u.txid}:${u.vout}`))
    .map((u) => ({ txid: u.txid, vout: u.vout, units: BigInt(u.value), confirmed: !!u.status?.confirmed }));
  const confirmed = held.filter((c) => c.confirmed).sort(byAmount('units')).reverse();
  const picked = [];
  let sum = 0n;
  for (const c of confirmed) {
    if (sum >= units) break;
    picked.push(c);
    sum += c.units;
  }
  if (sum < units) {
    const all = held.reduce((n, c) => n + c.units, 0n);
    if (!held.length) {
      throw new Error(skip.size ? 'this address holds no bridge asset openly that this page has not just sent. Check step 3 for that send'
        : 'this address holds no bridge asset openly. Give the address the claim paid (in Humid, Receive, then Unconfidential), and wait until its deposit shows Claimed');
    }
    if (all >= units) throw new Error('the claim has not confirmed on Liquid yet; retry after confirmation');
    throw new Error(`this address holds ${formatUnits(all, 8)} of the bridge asset openly; redeem at most that`);
  }
  if (picked.length > MAX_CLAIMS) throw new Error(`that amount needs ${picked.length} claim coins; redeem less at a time (at most ${MAX_CLAIMS} coins per send)`);
  return picked.map(({ txid, vout, units: u }) => ({ txid, vout, units: u }));
}

/** The burn input of claim coin `c` (selectClaims), from its transaction: it must pay `c.units` of `asset` (internal order) openly to `script`. */
export function claimInput(c, txHex, asset, script) {
  const tx = parseTransaction(hexToBytes(txHex));
  if (displayHex(tx.txid) !== c.txid) throw new Error('the Liquid API returned a different transaction');
  const o = tx.outputs[c.vout];
  const explicit = !!o && o.asset.kind === 'explicit' && o.value.kind === 'explicit';
  if (!explicit || !equal(o.asset.data, asset) || o.value.amount !== c.units || !equal(o.script, script)) {
    throw new Error(`output ${c.vout} of ${c.txid} is not the open claim the Liquid API listed`);
  }
  return { txid: c.txid, vout: c.vout, witnessUtxo: o.raw, units: c.units, script };
}

const rawAssetId = (id) => String(id).slice(String(id).lastIndexOf(':') + 1);

/**
 * The tL-BTC coin that pays the fee: the smallest confirmed one in Humid's getUTXOs answer that leaves at least
 * MIN_CHANGE_SATS of change. Humid lists its confidential coins, and at times open ones at its first address. Coins
 * in `skip` ("txid:vout"), which a send from this page may have spent, are passed over: Humid can list them still.
 */
export function selectFeeCoin(answer, feeSats = FEE_SATS, skip = new Set()) {
  const lbtc = displayHex(hexToBytes(LIQUID_TESTNET_LBTC));
  const coins = (answer?.utxos ?? [])
    .filter((u) => u.spendable === true && rawAssetId(u.assetId) === lbtc && /^\d{1,16}$/.test(String(u.amount)) && !skip.has(`${u.txid}:${u.vout}`))
    .map((u) => ({ ...u, sats: BigInt(u.amount) }))
    .filter((u) => u.sats >= feeSats + MIN_CHANGE_SATS)
    .sort(byAmount('sats'));
  if (!coins.length) {
    // Humid's coin list can omit open coins, so the fee is best received confidentially.
    throw new Error(`Humid has no confirmed tL-BTC coin of at least ${feeSats + MIN_CHANGE_SATS} sats for the fee. Get testnet L-BTC from `
      + 'the Liquid testnet faucet at Humid\'s confidential address (Receive, then Confidential), wait for it to confirm, and try again');
  }
  const { sats, ...coin } = coins[0];
  return coin;
}

/**
 * The burn input of Humid's fee coin `u` (selectFeeCoin), from its transaction as served with its witness. An open
 * coin gets its change back openly. A confidential one gets it blinded to the blinding key of `u.address`, the
 * confidential address Humid's own coin list gives for the coin, which must be that of the coin's script; and it
 * carries its output's rangeproof, from which Humid unblinds it to review the burn (encodePset).
 */
export function feeInput(u, txHex) {
  const raw = hexToBytes(txHex);
  const tx = parseTransaction(raw);
  if (displayHex(tx.txid) !== u.txid) throw new Error('the Liquid API returned a different transaction');
  const o = tx.outputs[u.vout];
  const script = hexToBytes(u.scriptPubKey);
  if (!o || !equal(o.script, script) || !isStandardRecipient(script)) throw new Error('Humid\'s fee coin is not in its transaction as Humid listed it');
  const amount = BigInt(u.amount);
  let blindingKey = null;
  let rangeproof = null;
  if (o.asset.kind === 'explicit' && o.value.kind === 'explicit') {
    if (!equal(o.asset.data, hexToBytes(LIQUID_TESTNET_LBTC)) || o.value.amount !== amount) throw new Error('Humid\'s open fee coin is not the tL-BTC amount it listed');
  } else if (o.asset.kind === 'confidential' && o.value.kind === 'confidential') {
    const a = decodeConfidential(LIQUID_TESTNET_CONFIDENTIAL_HRP, u.address);
    if (!equal(concat([0x00, a.program.length], a.program), script)) throw new Error('Humid\'s fee coin address is not that of its script');
    // The change is blinded to this key as given. Neither this page nor Humid checks that it is the wallet's: Humid
    // blinds to whatever key the PSET names, so the key's source is Humid's own getUTXOs answer, nothing more.
    blindingKey = a.blindingKey;
    // The rangeproof is checked, by Humid: its review unblinds the coin with it and compares the commitments.
    rangeproof = outputWitnesses(raw)[u.vout].rangeproof;
    if (rangeproof.length === 0) throw new Error('the Liquid API served Humid\'s confidential fee coin without its rangeproof');
  } else {
    throw new Error('Humid\'s fee coin is partly blinded, which this page does not spend');
  }
  return { txid: u.txid, vout: u.vout, witnessUtxo: o.raw, rangeproof, amount, script, blindingKey, address: u.address };
}

// ---- the burn ----

/**
 * The burn as a PSET, laid out as tools/sg16/liquid-testnet-wallet burn lays it out: inputs [claims…, fee coin],
 * outputs [burn, bridge-asset change if any, tL-BTC change, fee]. The burn pays `units` of `asset` (internal order)
 * openly to `burnScript`, the escrow's burnScriptPubKey for the recipient: a bare OP_RETURN naming it. Humid's
 * review lists an OP_RETURN output with no address and its script in hex, and leaves it explicit, as it blinds only
 * the outputs marked for blinding. The escrow reads only that output. Asset change returns openly to the claims'
 * address. The tL-BTC change is open for an open fee coin. For a confidential one it is marked for Humid to blind,
 * with the fee coin's input as blinder, because a confidential input's commitments balance only against a blinded
 * output. Returns the PSET in base64, the inputs signPset is to sign, the outpoints it spends ("txid:vout"),
 * `unsigned`, the transaction before blinding, and `blindIndex`, the output Humid blinds (-1 if none). Blinding
 * changes only that output, so the broadcast's other outputs, the burn first, are `unsigned`'s; its txid is not
 * (broadcastMatches).
 */
export function redeemPset({ asset, units, burnScript, claims, fee, claimAddress, feeSats = FEE_SATS }) {
  if (!readBurnScript(burnScript)) throw new Error('the burn script must be the escrow\'s bare OP_RETURN burn');
  if (claims.length === 0 || claims.length > MAX_CLAIMS) throw new Error(`a burn spends 1 to ${MAX_CLAIMS} claim coins`);
  const script = claims[0].script;
  if (!claims.every((c) => equal(c.script, script))) throw new Error('every claim coin must be at the same address');
  const held = claims.reduce((n, c) => n + c.units, 0n);
  if (units <= 0n || units > held) throw new Error('the claim coins do not cover the amount');
  const change = fee.amount - feeSats;
  if (change < MIN_CHANGE_SATS) throw new Error(`the fee coin must leave at least ${MIN_CHANGE_SATS} sats of change`);
  const lbtc = hexToBytes(LIQUID_TESTNET_LBTC);
  const inputs = [...claims, fee];
  const outputs = [{ asset, amount: units, script: burnScript }];
  if (held > units) outputs.push({ asset, amount: held - units, script });
  outputs.push(fee.blindingKey
    ? { asset: lbtc, amount: change, script: fee.script, blindingKey: fee.blindingKey, blinderIndex: claims.length }
    : { asset: lbtc, amount: change, script: fee.script });
  outputs.push({ asset: lbtc, amount: feeSats, script: new Uint8Array(0) });
  return {
    pset: base64(encodePset({ inputs, outputs })),
    signInputs: inputs.map((i, index) => ({ address: index < claims.length ? claimAddress : fee.address, index, sighashTypes: [1] })),
    spends: inputs.map((i) => `${i.txid}:${i.vout}`),
    unsigned: unsignedTx(inputs, outputs),
    blindIndex: outputs.findIndex((o) => o.blindingKey),
  };
}

/**
 * Why the transaction Humid broadcast (as the Liquid API serves it) is not the burn `plan` built, or null if it is:
 * the same inputs in order, and the same outputs, except that the one marked for blinding may be blinded, to the
 * same script.
 */
export function broadcastMatches(plan, txHex) {
  const sent = parseTransaction(hexToBytes(txHex));
  const built = parseTransaction(plan.unsigned);
  const outpoint = (i) => `${displayHex(i.prevTxid)}:${i.n}`;
  if (sent.inputs.map(outpoint).join() !== built.inputs.map(outpoint).join()) return 'it spends other coins than the burn this page built';
  if (sent.outputs.length !== built.outputs.length) return 'it has other outputs than the burn this page built';
  for (const [i, o] of sent.outputs.entries()) {
    const same = i === plan.blindIndex ? equal(o.script, built.outputs[i].script) : equal(o.raw, built.outputs[i].raw);
    if (!same) return `its output ${i} is not the one this page built`;
  }
  return null;
}

// ---- Humid ----

/** Humid's injected provider, which its content script adds shortly after a page loads; null if none appears. */
export async function findHumid(win, timeoutMs = 3000) {
  for (let waited = 0; !win.humid && waited < timeoutMs; waited += 100) await new Promise((r) => setTimeout(r, 100));
  return win.humid ?? null;
}

const canSign = (answer) => !!answer?.sessionScopes?.[HUMID_SCOPE]?.methods?.includes('signPset');

/** A session with Humid for Liquid testnet: the current one, or a new one the user approves in Humid. */
export async function humidSession(humid) {
  if (canSign(await humid.request({ method: 'wallet_getSession' }))) return;
  const answer = await humid.request({
    method: 'wallet_createSession',
    params: { optionalScopes: { [HUMID_SCOPE]: { methods: ['getUTXOs', 'signPset'], notifications: [] } } },
  });
  if (!canSign(answer)) throw new Error('Humid did not connect Liquid testnet with transaction signing; check that Liquid testnet is enabled in Humid, then connect again');
}

export function humidCall(humid, method, params) {
  return humid.request({ method: 'wallet_invokeMethod', params: { scope: HUMID_SCOPE, request: { method, params } } });
}

/**
 * What to tell the user when Humid refuses or fails. Humid's error codes are not EIP-1193's. An error burnWithHumid
 * marks `sent: 'maybe'` came after the user may have confirmed: Humid signs and broadcasts in one step, so the burn
 * may be on Liquid even though Humid reported a failure, and retrying blindly could burn a second time.
 */
export function humidError(e) {
  const reason = e?.data?.reason;
  // Humid 1.1.3 answers a prompt left open for 30 seconds exactly as it answers a decline (confirmations/index.ts).
  if (reason === 'user_rejected') {
    return 'Humid did not receive approval. Nothing was sent. Reopen the request to try again.';
  }
  const what = (e && e.message) || String(e);
  if (e?.sent === 'no' && e.stage === 'review') {
    return `Humid stopped before asking you to sign (${what}): its review of the burn failed, so nothing was signed or sent. `
      + 'If Humid did show you the burn and you confirmed it, check step 3 before trying again.';
  }
  if (e?.sent === 'maybe') {
    return `Humid did not confirm a sent burn (${what}). It may have been sent all the same. Before trying again, check Humid's activity and `
      + 'this address on a Liquid explorer, and look up any burn you find in step 3. Until you reload it, this page will not spend these coins again.'
      + (reason === 'wallet_pset_broadcast_failed' ? ' If nothing was sent: Humid signs only coins it holds, so check that the address is the one under Receive, then Unconfidential, in this Humid wallet.' : '');
  }
  return `Humid: ${what}`;
}

/**
 * Has Humid sign the inputs `signInputs` names of the PSET `pset` (base64) and broadcast it, once the user confirms
 * in Humid, and returns Humid's txid. An error is marked `sent`: 'no' when Humid refused before the user could
 * confirm (declined, or an invalid request), otherwise 'maybe'. One with no reason is 'no' too, with `stage`
 * 'review': in Humid 1.1.3 signPset's execute step, the only one that signs or broadcasts, gives every failure a
 * reason (signPset.ts), and the transport passes a raw error, such as one from LWK during review, on without any.
 * Humid's page provider has no timeout of its own, so a signing request still unanswered after `deadlineMs` is
 * abandoned as 'maybe': Humid may have broadcast and then lost the reply.
 */
export async function signAndBroadcast(humid, { pset, signInputs }, deadlineMs = SIGN_DEADLINE_MS) {
  let signed;
  let timer;
  try {
    signed = await Promise.race([
      humidCall(humid, 'signPset', { pset, signInputs, broadcast: true }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error(`Humid gave no answer within ${deadlineMs / 1000} seconds`), { deadline: true })), deadlineMs);
      }),
    ]);
  } catch (e) {
    const reason = String(e?.data?.reason ?? '');
    const error = e instanceof Error ? e : new Error(String(e));
    if (error.deadline) {
      error.sent = 'maybe';
    } else {
      error.sent = !reason || reason === 'user_rejected' || reason.startsWith('invalid_') ? 'no' : 'maybe';
      if (!reason) error.stage = 'review';
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
  if (!/^[0-9a-f]{64}$/.test(signed?.txid ?? '')) throw Object.assign(new Error('Humid returned no transaction id'), { sent: 'maybe' });
  return signed.txid;
}

/**
 * Burns `units` of the bridge `asset` (internal order) held at `claim` (humidAddress) to `burnScript` with Humid:
 * finds the claim coins on `esplora` (except those in `skip`), takes a fee coin from Humid, checks the burn output as
 * the escrow will, and has Humid sign and broadcast the PSET once the user confirms (signAndBroadcast, whose `sent`
 * and `stage` marks its errors carry). `onSign` gets the outpoints the burn spends just before Humid is asked to
 * sign; `progress` is told each step. Returns Humid's txid and the plan.
 */
export async function burnWithHumid({ humid, esplora, asset, units, burnScript, claim, skip = new Set(), onSign = () => {}, progress = () => {}, deadlineMs = SIGN_DEADLINE_MS }) {
  progress('Finding the claim on Liquid testnet…');
  const coins = selectClaims(await esplora.addressUtxos(claim.address), displayHex(asset), units, skip);
  const claims = [];
  for (const c of coins) claims.push(claimInput(c, await esplora.txHex(c.txid), asset, claim.script));
  progress('Approve the connection to this page in Humid, if it asks…');
  await humidSession(humid);
  progress('Let Humid share its coins with this page, if it asks…');
  const coin = selectFeeCoin(await humidCall(humid, 'getUTXOs', {}), FEE_SATS, skip);
  const fee = feeInput(coin, await esplora.txHex(coin.txid));
  const plan = redeemPset({ asset, units, burnScript, claims, fee, claimAddress: claim.address });
  const burns = burnOutputs(parseTransaction(plan.unsigned), asset, burnScript);
  if (burns.length !== 1 || burns[0].vout !== 0 || !burns[0].usable || burns[0].units !== units) {
    throw new Error('the burn built here does not pay the burn script as the escrow requires; nothing was sent. Report this');
  }
  progress('Review the burn in Humid, then sign and send…');
  onSign(plan.spends);
  return { txid: await signAndBroadcast(humid, plan, deadlineMs), plan };
}
