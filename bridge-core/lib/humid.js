// Humid integration, checked against release 1.1.4, commit a6d211d. Its getAddress method supplies an unconfidential
// receive address; getUTXOs includes explicit and confidential owned coins. The page builds the bridge's OP_RETURN
// burn from public Liquid data. Humid reviews the outputs, signs its inputs and broadcasts after user approval.
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
 * The address holding the claim: a Liquid testnet P2WPKH address controlled by Humid. The caller may paste one or
 * request address index 0 from the wallet. Existing claims can belong to a different address index or account.
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
 * MIN_CHANGE_SATS of change. Humid 1.1.4 lists both confidential and explicit owned coins. Coins
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

function sessionMethods(answer) {
  const methods = answer?.sessionScopes?.[HUMID_SCOPE]?.methods;
  return Array.isArray(methods) ? methods : [];
}

/** Request only the needed methods, preserving bridge permissions already granted on Liquid testnet. */
export async function humidSession(humid, required = ['getUTXOs', 'signPset']) {
  const existing = sessionMethods(await humid.request({ method: 'wallet_getSession' }));
  if (required.every((method) => existing.includes(method))) return;
  // Creating a Humid session replaces the previous session for this origin.
  const retained = existing.filter((method) => ['getAddress', 'getUTXOs', 'signPset'].includes(method));
  const methods = [...new Set([...retained, ...required])];
  const answer = await humid.request({
    method: 'wallet_createSession',
    params: { optionalScopes: { [HUMID_SCOPE]: { methods, notifications: [] } } },
  });
  if (!required.every((method) => sessionMethods(answer).includes(method))) {
    if (required.includes('getAddress')) throw new Error('Humid did not allow address access. Use Humid 1.1.4 or later with Liquid testnet enabled, or paste your unconfidential address.');
    throw new Error('Humid did not allow the required Liquid testnet methods; enable Liquid testnet and allow coin access and signing, then connect again');
  }
}

export function humidCall(humid, method, params) {
  return humid.request({ method: 'wallet_invokeMethod', params: { scope: HUMID_SCOPE, request: { method, params } } });
}

/** Read address 0 after approval, without requesting coin access or signing for a new connection. */
export async function receiveAddress(humid, deadlineMs = SIGN_DEADLINE_MS) {
  let timer;
  let expired = false;
  const bounded = {
    request(args) {
      if (expired) throw new Error('Address request expired');
      return humid.request(args);
    },
  };
  const read = async () => {
    await humidSession(bounded, ['getAddress']);
    const answer = await humidCall(bounded, 'getAddress', { confidential: false, index: 0 });
    if (answer?.chainId !== HUMID_SCOPE || answer.confidential !== false || answer.index !== 0 || typeof answer.address !== 'string') {
      throw new Error('Humid returned an unexpected address response. Choose Liquid testnet or paste your unconfidential address.');
    }
    return humidAddress(answer.address).address;
  };

  try {
    return await Promise.race([
      read(),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          expired = true;
          reject(new Error('Humid did not return an address. Close any pending wallet prompt, then retry or paste your unconfidential address.'));
        }, deadlineMs);
      }),
    ]);
  } catch (e) {
    if (e?.code === -32601) throw new Error('Address access needs Humid 1.1.4 or later. Update Humid or paste your unconfidential address.');
    if (e?.code === 5100) throw new Error('Humid address access is unavailable. Enable Liquid testnet in Humid 1.1.4 or later, or paste your unconfidential address.');
    if (e?.code === 4001 || e?.data?.reason === 'user_rejected') throw new Error('Address access was declined or expired. Retry or paste your unconfidential address.');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * What to tell the user when Humid refuses or fails. Humid's error codes are not EIP-1193's. An error burnWithHumid
 * marks `sent: 'maybe'` came after the user may have confirmed: Humid signs and broadcasts in one step, so the burn
 * may be on Liquid even though Humid reported a failure, and retrying blindly could burn a second time.
 */
export function humidError(e) {
  const reason = e?.data?.reason;
  // Humid 1.1.4 answers a prompt left open for 30 seconds exactly as it answers a decline (confirmations/index.ts).
  if (reason === 'user_rejected') {
    return 'Humid did not receive approval: the request was declined or expired. Nothing was sent. Reopen the request to try again.';
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
 * 'review': in Humid 1.1.4 signPset's execute step, the only one that signs or broadcasts, gives every failure a
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
