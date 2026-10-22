// lib/humid.js: the burn PSET this page has Humid sign, its coins, and the requests it sends Humid. Its PSETs are read
// back with test/pset-reader.js, which follows BIP 370 and Elements' fields independently of lib/humid.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULTS } from '../config.js';
import { decodeConfidential, encodeSegwit } from '../lib/bech32.js';
import { bytesToHex, concat, hexToBytes } from '../lib/bytes.js';
import { LIQUID_TESTNET_LBTC, burnOutputs, burnTarget, liftY, readBurnScript } from '../lib/bridge.js';
import { displayHex, outputWitnesses, parseTransaction } from '../lib/elements.js';
import {
  FEE_SATS, HUMID_SCOPE, MAX_CLAIMS, broadcastMatches, burnWithHumid, claimInput, explicitTxOut, feeInput, humidAddress, humidError,
  redeemPset, selectClaims, selectFeeCoin,
} from '../lib/humid.js';
import { ELEMENTS, psetTransaction, readPset } from './pset-reader.js';
import { blinded, cat, explicit, hex, signedWitness, transaction, word } from './liquid-tx.js';

// ---- a claim, a fee coin, and a spend of both, made up in the shapes Liquid serves (test/liquid-tx.js) ----

const ASSET = hex(word('bridge asset')); // the asset the claim pays, internal order
const SCRIPT = hex('0014' + word('humid key').slice(0, 40)); // Humid's P2WPKH, which the claim pays
const ADDRESS = encodeSegwit('tex', 0, SCRIPT.subarray(2));
// A claim: output 0 the blinded successor state, output 1 100,000 units of the bridge asset openly to SCRIPT, output
// 2 the fee. CLAIM_TX is its txid form, CLAIM_SERVED the claim as Liquid serves it, witness and all.
const CLAIM_SPEC = {
  inputs: [
    {
      txid: word('state'), vout: 0, issuance: { nonce: hex(word('blinding')), entropy: hex(word('entropy')), amount: 100_000n, inflation: null },
      witness: [hex(word('claim witness')), hex(word('claim program')), hex(word('claim leaf')), cat([0xbe], hex(word('control')), hex(word('a')), hex(word('b')))],
    },
    { txid: word('claim fee'), vout: 0, witness: signedWitness('claim fee') },
  ],
  outputs: [
    blinded(cat([0x0b], hex(word('token'))), cat([0x09], hex(word('token value'))), hex('5120' + word('successor'))),
    explicit(ASSET, 100_000n, SCRIPT),
    explicit(hex(LIQUID_TESTNET_LBTC), 2_000n, new Uint8Array(0)),
  ],
};
const CLAIM_TX = transaction({ ...CLAIM_SPEC, witness: false });
const CLAIM_SERVED = transaction(CLAIM_SPEC);
const CLAIM_TXID = CLAIM_TX.txid;
const CLAIM = CLAIM_TX.hex;
// A fee transfer, as served with its witness: output 0 is 2,000 explicit tL-BTC sats to SCRIPT.
const FEE = transaction({
  inputs: [{ txid: word('fee funding'), vout: 1, witness: signedWitness('fee funding') }],
  outputs: [
    explicit(hex(LIQUID_TESTNET_LBTC), 2_000n, SCRIPT), explicit(hex(LIQUID_TESTNET_LBTC), 21_600n, hex('0014' + word('other key').slice(0, 40))),
    explicit(hex(LIQUID_TESTNET_LBTC), 100n, new Uint8Array(0)),
  ],
});
const FEE_TXID = FEE.txid;
const FEE_TX = FEE.hex;
/**
 * The spend of both coins Humid makes for a burn of all 100,000 units at a fee of `fee` sats, written here from the
 * layout LWK gives it: inputs [the claim's output 1, the fee coin], final sequences, locktime 0; outputs [the burn, the
 * tL-BTC change to the fee coin's script, the fee]. `burnScript` is output 0's script; with `witness`, as served.
 */
const spendOfBoth = (burnScript, fee, witness = false) => transaction({
  inputs: [
    { txid: CLAIM_TXID, vout: 1, witness: signedWitness('claim coin') },
    { txid: FEE_TXID, vout: 0, witness: signedWitness('fee coin') },
  ],
  outputs: [
    explicit(ASSET, 100_000n, burnScript), explicit(hex(LIQUID_TESTNET_LBTC), 2_000n - fee, SCRIPT),
    explicit(hex(LIQUID_TESTNET_LBTC), fee, new Uint8Array(0)),
  ],
  witness,
});
// A spend that pays output 0 to a script with an address, a P2WSH: no burn.
const P2WSH = hex('0020' + word('not a burn'));
const NOT_A_BURN = spendOfBoth(P2WSH, 300n, true);
// The bare burn of a made-up escrow for an Ethereum recipient: OP_RETURN naming the chain, the escrow and the recipient.
const ESCROW = '0x' + '7e'.repeat(20);
const RECIPIENT = '0x' + '40'.repeat(20);
const BURN_SCRIPT = burnTarget(DEFAULTS.chainId, ESCROW, RECIPIENT).scriptPubKey;

const LBTC_DISPLAY = displayHex(hexToBytes(LIQUID_TESTNET_LBTC));
const lbtcId = `${HUMID_SCOPE}/elip144:${LBTC_DISPLAY}`; // Humid's asset id form (toLiquidAssetId)
// Humid's getUTXOs entry for the fee output, as its explicit-coin reader lists an open coin at its first address.
const OPEN_FEE = { txid: FEE_TXID, vout: 0, amount: '2000', assetId: lbtcId, scriptPubKey: bytesToHex(SCRIPT), address: ADDRESS, confidential: false, spendable: true, txOut: '' };

// A P2WPKH confidential address from LWK's own tests (lwk_wasm/src/blockdata/address.rs): its script and
// unconfidential form are LWK's. And the same key's ELIP-151 address, which has another blinding key.
const TLQ = 'tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn';
const TLQ_SCRIPT = '0014d0c4a3ef09e997b6e99e397e518fe3e41a118ca1';
const TLQ_ELIP151 = 'tlq1qqv74shw44vxlpdhtmwqc2zfr5365hm8p6rg8cjnu77w57000dmuc05xy50hsn6vhkm5euwt72x878eq6zxx2z4zm4jus26k72';
const EL1 = 'el1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z0z676mna6kdq';

/** A one-input transaction with these outputs, in txid form, and its display txid. */
function txWith(...outputs) {
  const raw = concat(hexToBytes('0200000000' + '01' + 'cc'.repeat(32) + '00000000' + '00' + 'ffffffff'), [outputs.length], ...outputs, new Uint8Array(4));
  return { hex: bytesToHex(raw), txid: displayHex(parseTransaction(raw).txid) };
}
/**
 * The same as served with its witness, as Esplora serves a transaction: an empty input witness, then for each output
 * the surjection proof and rangeproof in `proofs` (empty when not given). Proofs here are placeholders, not valid ones.
 */
function servedWith(outputs, proofs = []) {
  const vb = (b) => concat(b.length < 0xfd ? [b.length] : [0xfd, b.length & 0xff, b.length >> 8], b);
  const witness = concat([0, 0, 0, 0], ...outputs.map((_, i) => concat(vb(proofs[i]?.[0] ?? []), vb(proofs[i]?.[1] ?? []))));
  const raw = concat(hexToBytes('0200000001' + '01' + 'cc'.repeat(32) + '00000000' + '00' + 'ffffffff'), [outputs.length], ...outputs, new Uint8Array(4), witness);
  return { hex: bytesToHex(raw), txid: displayHex(parseTransaction(raw).txid) };
}
const confidentialOut = (script) => concat([0x0a], new Uint8Array(32).fill(1), [0x09], new Uint8Array(32).fill(2), [0x03], new Uint8Array(32).fill(3), [script.length], script);
// A rangeproof-sized placeholder (real ones on Liquid are about 4.2 kB, so their length needs a 3-byte CompactSize).
const RANGEPROOF = Uint8Array.from({ length: 4174 }, (_, i) => (i * 7) & 0xff);
const SURJECTION = new Uint8Array(67).fill(0x5e);

test('output witnesses: a claim\'s confidential output carries its proofs, explicit ones none', () => {
  const full = CLAIM_SERVED.raw;
  assert.equal(displayHex(parseTransaction(full).txid), CLAIM_TXID, 'the witness does not change the txid');
  const w = outputWitnesses(full);
  assert.equal(w.length, 3);
  assert.ok(w[0].rangeproof.length > 0 && w[0].surjectionProof.length > 0, 'output 0, the blinded state, has both proofs');
  assert.deepEqual(w.slice(1).map((x) => [x.surjectionProof.length, x.rangeproof.length]), [[0, 0], [0, 0]], 'the claim and its fee are explicit');
  assert.deepEqual(outputWitnesses(hexToBytes(FEE_TX)).map((x) => x.rangeproof.length), [0, 0, 0]);
  assert.throws(() => outputWitnesses(hexToBytes(CLAIM)), /without its witness/);
  assert.throws(() => outputWitnesses(concat(full, [0])), /trailing bytes after the witness/);
  assert.throws(() => outputWitnesses(full.subarray(0, full.length - 1)), /truncated/);
});

test('blech32: LWK\'s confidential address gives its script, its unconfidential form and a key on the curve', () => {
  const a = decodeConfidential('tlq', TLQ);
  assert.equal(bytesToHex(concat([0x00, 0x14], a.program)), TLQ_SCRIPT);
  assert.equal(encodeSegwit('tex', 0, a.program), 'tex1q6rz28mcfaxtmd6v789l9rrlrusdprr9p634wu8');
  assert.equal(a.blindingKey.length, 33);
  liftY(a.blindingKey); // throws off the curve
  assert.equal(bytesToHex(decodeConfidential('tlq', TLQ.toUpperCase()).blindingKey), bytesToHex(a.blindingKey));
  // The same script under another blinding key, and the same key and script on another network.
  const other = decodeConfidential('tlq', TLQ_ELIP151);
  assert.equal(bytesToHex(other.program), bytesToHex(a.program));
  assert.notEqual(bytesToHex(other.blindingKey), bytesToHex(a.blindingKey));
  const el = decodeConfidential('el', EL1);
  assert.deepEqual([bytesToHex(el.program), bytesToHex(el.blindingKey)], [bytesToHex(a.program), bytesToHex(a.blindingKey)]);

  const flipped = TLQ.slice(0, 20) + (TLQ[20] === 'q' ? 'p' : 'q') + TLQ.slice(21);
  assert.throws(() => decodeConfidential('tlq', flipped), /checksum/);
  assert.throws(() => decodeConfidential('tlq', EL1), /prefix is "el"/);
  assert.throws(() => decodeConfidential('tlq', 'tex1q6rz28mcfaxtmd6v789l9rrlrusdprr9p634wu8'), /prefix is "tex"|confidential/);
});

test('Humid\'s claim address is its unconfidential P2WPKH address', () => {
  assert.deepEqual(humidAddress(` ${ADDRESS.toUpperCase()} `), { address: ADDRESS, script: SCRIPT });
  assert.throws(() => humidAddress(TLQ), /Unconfidential tab/);
  assert.equal(ADDRESS.length, 43);
  assert.throws(() => humidAddress(encodeSegwit('tex', 1, new Uint8Array(32).fill(1))), /tex1q… address of 43/);
  assert.throws(() => humidAddress(encodeSegwit('tex', 0, new Uint8Array(32))), /tex1q… address of 43/);
});

test('the claim and fee coin as listed give, byte for byte, the spend of them with output 0 the bare burn', () => {
  assert.equal(BURN_SCRIPT.length, 72);
  const [coin] = selectClaims([{ txid: CLAIM_TXID, vout: 1, value: 100_000, asset: displayHex(ASSET), status: { confirmed: true } }], displayHex(ASSET), 100_000n);
  const claim = claimInput(coin, CLAIM, ASSET, SCRIPT);
  assert.equal(bytesToHex(claim.witnessUtxo), bytesToHex(explicitTxOut(ASSET, 100_000n, SCRIPT)));
  const fee = feeInput(selectFeeCoin({ utxos: [OPEN_FEE] }, 300n), FEE_TX);
  assert.equal(fee.blindingKey, null, 'an open fee coin gets open change');

  // At a fee of 300 sats, the page's burn is exactly the spend written out above; Humid's burns pay FEE_SATS.
  const plan = redeemPset({ asset: ASSET, units: 100_000n, burnScript: BURN_SCRIPT, claims: [claim], fee, claimAddress: ADDRESS, feeSats: 300n });
  const expected = spendOfBoth(BURN_SCRIPT, 300n);
  assert.equal(bytesToHex(plan.unsigned), bytesToHex(expected.txidForm));
  const tx = parseTransaction(plan.unsigned);
  assert.equal(displayHex(tx.txid), expected.txid);
  assert.equal(bytesToHex(tx.outputs[0].raw), bytesToHex(explicitTxOut(ASSET, 100_000n, BURN_SCRIPT)));
  assert.deepEqual(readBurnScript(tx.outputs[0].script), { chainId: DEFAULTS.chainId, escrow: ESCROW, recipient: RECIPIENT });
  assert.deepEqual(burnOutputs(tx, ASSET, BURN_SCRIPT), [{ vout: 0, units: 100_000n, usable: true }]);
  assert.equal(plan.blindIndex, -1);
  assert.deepEqual(plan.spends, [`${CLAIM_TXID}:1`, `${FEE_TXID}:0`]);
  assert.equal(broadcastMatches(plan, bytesToHex(plan.unsigned)), null);
  assert.equal(broadcastMatches(plan, spendOfBoth(BURN_SCRIPT, 300n, true).hex), null, 'the same spend, signed, as Liquid serves it');
  assert.match(broadcastMatches(plan, NOT_A_BURN.hex), /output 0 is not/, 'the same coins, signed, paying another output 0');

  // The PSET describes exactly that transaction, in the fields LWK writes, with each input's witness UTXO. The burn is
  // an explicit output Humid is not asked to blind: amount, asset and script only.
  const pset = readPset(plan.pset);
  assert.equal(bytesToHex(psetTransaction(pset)), bytesToHex(plan.unsigned));
  assert.deepEqual([...pset.global].map(([k, v]) => [k, bytesToHex(v)]), [['02', '02000000'], ['04', '02'], ['05', '03'], ['fb', '02000000']]);
  assert.deepEqual(pset.inputs.map((m) => [...m.keys()]), [['01', '0e', '0f'], ['01', '0e', '0f']]);
  assert.equal(bytesToHex(pset.inputs[0].get('01')), bytesToHex(parseTransaction(hexToBytes(CLAIM)).outputs[1].raw));
  assert.equal(bytesToHex(pset.inputs[1].get('01')), bytesToHex(parseTransaction(hexToBytes(FEE_TX)).outputs[0].raw));
  assert.deepEqual(pset.outputs.map((m) => [...m.keys()]), [['03', `${ELEMENTS}02`, '04'], ['03', `${ELEMENTS}02`, '04'], ['03', `${ELEMENTS}02`, '04']]);
  assert.equal(bytesToHex(pset.outputs[0].get('04')), bytesToHex(BURN_SCRIPT));
  assert.equal(bytesToHex(pset.outputs[2].get('04')), '', 'the fee output has no script');
  assert.deepEqual(plan.signInputs, [{ address: ADDRESS, index: 0, sighashTypes: [1] }, { address: ADDRESS, index: 1, sighashTypes: [1] }]);
});

test('a confidential fee coin carries its output\'s rangeproof, so its owner can unblind it to review the burn', () => {
  const outs = [explicitTxOut(hexToBytes(LIQUID_TESTNET_LBTC), 5_000n, SCRIPT), confidentialOut(hexToBytes(TLQ_SCRIPT))];
  const coinTx = servedWith(outs, [[], [SURJECTION, RANGEPROOF]]);
  const listed = { txid: coinTx.txid, vout: 1, amount: '100000', assetId: lbtcId, scriptPubKey: TLQ_SCRIPT, address: TLQ, confidential: true, spendable: true, txOut: '' };
  const fee = feeInput(listed, coinTx.hex);
  assert.equal(bytesToHex(fee.rangeproof), bytesToHex(RANGEPROOF), 'output 1\'s rangeproof, not output 0\'s empty one');
  const claim = claimInput({ txid: CLAIM_TXID, vout: 1, units: 100_000n }, CLAIM, ASSET, SCRIPT);
  const pset = readPset(redeemPset({ asset: ASSET, units: 100_000n, burnScript: BURN_SCRIPT, claims: [claim], fee, claimAddress: ADDRESS }).pset);
  // PSBT_ELEMENTS_IN_UTXO_RANGEPROOF on the fee input only: the claim is explicit and needs none.
  assert.deepEqual(pset.inputs.map((m) => [...m.keys()]), [['01', '0e', '0f'], ['01', '0e', '0f', `${ELEMENTS}0e`]]);
  assert.equal(bytesToHex(pset.inputs[1].get(`${ELEMENTS}0e`)), bytesToHex(RANGEPROOF));
  assert.equal(bytesToHex(pset.inputs[1].get('01')), bytesToHex(outs[1]), 'the witness UTXO stays the bare output, as LWK writes it');

  // Without the proof Humid's review could not unblind the coin, so the page refuses rather than send that PSET.
  assert.throws(() => feeInput(listed, txWith(...outs).hex), /without its witness/);
  assert.throws(() => feeInput(listed, servedWith(outs).hex), /without its rangeproof/);
  // An open fee coin needs none.
  assert.equal(feeInput({ ...listed, vout: 0, amount: '5000', scriptPubKey: bytesToHex(SCRIPT), confidential: false }, coinTx.hex).rangeproof, null);
});

test('a confidential fee coin\'s change is marked for Humid to blind to that coin\'s own key; the rest stays open', () => {
  const coinTx = servedWith([confidentialOut(hexToBytes(TLQ_SCRIPT))], [[SURJECTION, RANGEPROOF]]);
  const listed = { txid: coinTx.txid, vout: 0, amount: '100000', assetId: lbtcId, scriptPubKey: TLQ_SCRIPT, address: TLQ, confidential: true, spendable: true, txOut: '' };
  const fee = feeInput(listed, coinTx.hex);
  assert.equal(bytesToHex(fee.blindingKey), bytesToHex(decodeConfidential('tlq', TLQ).blindingKey));
  const claim = claimInput({ txid: CLAIM_TXID, vout: 1, units: 100_000n }, CLAIM, ASSET, SCRIPT);

  // A partial burn: 40,000 units, and 60,000 back openly to the claim's address.
  const plan = redeemPset({ asset: ASSET, units: 40_000n, burnScript: BURN_SCRIPT, claims: [claim], fee, claimAddress: ADDRESS });
  assert.equal(plan.blindIndex, 2);
  const pset = readPset(plan.pset);
  const tx = parseTransaction(psetTransaction(pset));
  assert.deepEqual(tx.outputs.map((o) => [bytesToHex(o.script), o.value.amount]),
    [[bytesToHex(BURN_SCRIPT), 40_000n], [bytesToHex(SCRIPT), 60_000n], [TLQ_SCRIPT, 100_000n - FEE_SATS], ['', FEE_SATS]]);
  assert.deepEqual(tx.outputs.map((o) => bytesToHex(o.asset.data)), [bytesToHex(ASSET), bytesToHex(ASSET), LIQUID_TESTNET_LBTC, LIQUID_TESTNET_LBTC]);
  assert.equal(bytesToHex(pset.outputs[2].get(`${ELEMENTS}06`)), bytesToHex(fee.blindingKey));
  assert.equal(bytesToHex(pset.outputs[2].get(`${ELEMENTS}08`)), '01000000', 'blinded by the owner of input 1, the fee coin');
  for (const i of [0, 1, 3]) assert.deepEqual([...pset.outputs[i].keys()], ['03', `${ELEMENTS}02`, '04'], `output ${i} is not to be blinded`);
  assert.equal(bytesToHex(pset.inputs[1].get('01')), bytesToHex(parseTransaction(hexToBytes(coinTx.hex)).outputs[0].raw), 'the coin\'s commitments, as on chain');

  // The escrow's rule: only output 0 redeems, for exactly the burned units.
  assert.deepEqual(burnOutputs(tx, ASSET, BURN_SCRIPT), [{ vout: 0, units: 40_000n, usable: true }]);

  // The coin's address must be its script's: another key or script would blind the change away from Humid.
  assert.throws(() => feeInput({ ...listed, address: EL1 }, coinTx.hex), /prefix is "el"/);
  const elsewhere = txWith(confidentialOut(SCRIPT));
  assert.throws(() => feeInput({ ...listed, txid: elsewhere.txid, scriptPubKey: bytesToHex(SCRIPT) }, elsewhere.hex), /not that of its script/);
});

test('claim coins: confirmed, open, of the bridge asset, largest first, as few as cover the amount', () => {
  const asset = displayHex(ASSET);
  const u = (n, value, confirmed = true, a = asset) => ({ txid: String(n).repeat(64), vout: n, value, asset: a, status: { confirmed } });
  const utxos = [u(1, 30_000), u(2, 100_000), u(3, 50_000), u(4, 999_999, true, LBTC_DISPLAY), u(5, 500_000, false), { txid: '6'.repeat(64), vout: 0, valuecommitment: '08' + '11'.repeat(32), status: { confirmed: true } }];
  assert.deepEqual(selectClaims(utxos, asset, 100_000n).map((c) => c.vout), [2]);
  assert.deepEqual(selectClaims(utxos, asset, 120_000n).map((c) => [c.vout, c.units]), [[2, 100_000n], [3, 50_000n]]);
  assert.deepEqual(selectClaims(utxos, asset, 180_000n).map((c) => c.vout), [2, 3, 1]);
  assert.throws(() => selectClaims(utxos, asset, 190_000n), /not confirmed on Liquid yet/);
  assert.throws(() => selectClaims(utxos, asset, 700_000n), /holds 0\.0068 of the bridge asset openly; redeem at most that/);
  assert.throws(() => selectClaims([u(4, 999_999, true, LBTC_DISPLAY)], asset, 1n), /holds no bridge asset openly/);
  const many = Array.from({ length: MAX_CLAIMS + 1 }, (_, i) => ({ ...u(1, 1_000), txid: (i + 10).toString(16).padStart(64, '0') }));
  assert.equal(selectClaims(many, asset, BigInt(MAX_CLAIMS * 1_000)).length, MAX_CLAIMS);
  assert.throws(() => selectClaims(many, asset, BigInt(MAX_CLAIMS * 1_000 + 1)), /redeem less at a time/);
  // Coins a send from this page may have spent are not offered again, though Esplora still lists them.
  const skip = new Set([`${'2'.repeat(64)}:2`]);
  assert.deepEqual(selectClaims(utxos, asset, 80_000n, skip).map((c) => c.vout), [3, 1]);
  assert.throws(() => selectClaims([u(2, 100_000)], asset, 1n, skip), /not just sent\. Check step 3/);

  // Each coin is checked in its transaction's bytes.
  const coin = { txid: CLAIM_TXID, vout: 1, units: 100_000n };
  assert.throws(() => claimInput({ ...coin, units: 99_999n }, CLAIM, ASSET, SCRIPT), /not the open claim/);
  assert.throws(() => claimInput(coin, CLAIM, ASSET, hexToBytes(TLQ_SCRIPT)), /not the open claim/);
  assert.throws(() => claimInput(coin, CLAIM, hexToBytes(LIQUID_TESTNET_LBTC), SCRIPT), /not the open claim/);
  assert.throws(() => claimInput({ ...coin, vout: 0 }, CLAIM, ASSET, SCRIPT), /not the open claim/, 'the confidential state output');
  assert.throws(() => claimInput({ ...coin, txid: FEE_TXID }, CLAIM, ASSET, SCRIPT), /different transaction/);
});

test('fee coin: Humid\'s smallest confirmed tL-BTC coin that leaves change', () => {
  const c = (txid, amount, extra = {}) => ({ ...OPEN_FEE, txid: txid.repeat(64), amount, ...extra });
  const answer = { utxos: [c('1', '5000'), c('2', '1046'), c('3', '1045'), c('4', '900', { spendable: false }), c('5', '700', { assetId: `${HUMID_SCOPE}/elip144:${displayHex(ASSET)}` })] };
  assert.equal(selectFeeCoin(answer).txid, '2'.repeat(64), `${FEE_SATS} + 546 sats at least`);
  assert.equal(selectFeeCoin(answer, FEE_SATS, new Set([`${'2'.repeat(64)}:0`])).txid, '1'.repeat(64), 'not a coin a send from this page may have spent');
  assert.throws(() => selectFeeCoin({ utxos: [c('3', '1045')] }), /no confirmed tL-BTC coin of at least 1046 sats/);
  assert.throws(() => selectFeeCoin({}), /faucet/);
  assert.throws(() => feeInput({ ...OPEN_FEE, amount: '2001' }, FEE_TX), /not the tL-BTC amount it listed/);
  assert.throws(() => feeInput({ ...OPEN_FEE, scriptPubKey: TLQ_SCRIPT }, FEE_TX), /not in its transaction as Humid listed it/);
  assert.throws(() => feeInput({ ...OPEN_FEE, vout: 2, amount: '100', scriptPubKey: '' }, FEE_TX), /not in its transaction/, 'a fee output is no coin');
});

test('the burn refuses what the escrow or the coins do not allow', () => {
  const claim = claimInput({ txid: CLAIM_TXID, vout: 1, units: 100_000n }, CLAIM, ASSET, SCRIPT);
  const fee = feeInput(OPEN_FEE, FEE_TX);
  const args = { asset: ASSET, units: 100_000n, burnScript: BURN_SCRIPT, claims: [claim], fee, claimAddress: ADDRESS };
  assert.ok(redeemPset(args).pset);
  assert.throws(() => redeemPset({ ...args, burnScript: hexToBytes('6a20' + '11'.repeat(32)) }), /must be the escrow's bare OP_RETURN burn/);
  assert.throws(() => redeemPset({ ...args, burnScript: Uint8Array.of(0x6a) }), /bare OP_RETURN burn/, 'destroyamount\'s script names no recipient');
  assert.throws(() => redeemPset({ ...args, burnScript: P2WSH }), /bare OP_RETURN burn/, 'a script with an address is no burn');
  assert.throws(() => redeemPset({ ...args, burnScript: SCRIPT }), /bare OP_RETURN burn/, 'nor is the claim\'s own script');
  assert.ok(redeemPset({ ...args, burnScript: burnTarget(DEFAULTS.chainId, '0x' + '11'.repeat(20), RECIPIENT).scriptPubKey }).pset, 'any escrow\'s bare burn');
  assert.throws(() => redeemPset({ ...args, units: 100_001n }), /do not cover/);
  assert.throws(() => redeemPset({ ...args, units: 0n }), /do not cover/);
  assert.throws(() => redeemPset({ ...args, claims: [] }), /1 to 10 claim coins/);
  assert.throws(() => redeemPset({ ...args, claims: [claim, { ...claim, vout: 2, script: hexToBytes(TLQ_SCRIPT) }] }), /same address/);
  assert.throws(() => redeemPset({ ...args, fee: { ...fee, amount: FEE_SATS + 545n } }), /at least 546 sats of change/);
});

// ---- the requests Humid gets ----

function fakeHumid({ session = null, utxos = [OPEN_FEE], sign = null } = {}) {
  const calls = [];
  return {
    calls,
    async request({ method, params }) {
      calls.push({ method, params });
      if (method === 'wallet_getSession') return { sessionScopes: session ?? {} };
      if (method === 'wallet_createSession') return { sessionScopes: { [HUMID_SCOPE]: { accounts: [], methods: ['getUTXOs', 'signPset'], notifications: [] } } };
      if (method === 'wallet_invokeMethod' && params.request.method === 'getUTXOs') return { utxos };
      if (method === 'wallet_invokeMethod' && params.request.method === 'signPset') {
        if (sign) return sign(params.request.params);
        return { pset: params.request.params.pset, txid: blindedTxid(params.request.params.pset) };
      }
      throw Object.assign(new Error(`unexpected ${method}`), { code: -32601 });
    },
  };
}

/**
 * What Humid's broadcast of `pset` could look like: its transaction with the tL-BTC change (output -2) blinded, as
 * placeholder commitments, so its txid is not that of the PSET's transaction before blinding.
 */
function blindedBurn(pset) {
  const tx = parseTransaction(psetTransaction(readPset(pset)));
  const outs = tx.outputs.map((o, i) => (i === tx.outputs.length - 2 ? confidentialOut(o.script) : o.raw));
  const head = concat([2, 0, 0, 0, 0, tx.inputs.length], ...tx.inputs.map((i) => concat(i.prevTxid, [i.n & 0xff, (i.n >> 8) & 0xff, (i.n >> 16) & 0xff, i.n >>> 24], [0], [0xff, 0xff, 0xff, 0xff])));
  const raw = concat(head, [outs.length], ...outs, new Uint8Array(4));
  return { hex: bytesToHex(raw), txid: displayHex(parseTransaction(raw).txid), unsignedTxid: displayHex(tx.txid) };
}
const blindedTxid = (pset) => blindedBurn(pset).txid;

const esplora = {
  addressUtxos: async (a) => (a === ADDRESS ? [{ txid: CLAIM_TXID, vout: 1, value: 100_000, asset: displayHex(ASSET), status: { confirmed: true } }] : []),
  txHex: async (txid) => ({ [CLAIM_TXID]: CLAIM, [FEE_TXID]: FEE_TX })[txid],
};

test('burnWithHumid connects, takes a fee coin, and asks Humid to sign and broadcast exactly the burn; Humid\'s txid is the one kept', async () => {
  const humid = fakeHumid();
  const steps = [];
  let signing = null;
  const { txid, plan } = await burnWithHumid({
    humid, esplora, asset: ASSET, units: 100_000n, burnScript: BURN_SCRIPT, claim: humidAddress(ADDRESS),
    progress: (s) => steps.push(s), onSign: (o) => { signing = [o, humid.calls.length]; },
  });
  assert.deepEqual(humid.calls.map((c) => c.params?.request?.method ?? c.method), ['wallet_getSession', 'wallet_createSession', 'getUTXOs', 'signPset']);
  assert.deepEqual(humid.calls[1].params, { optionalScopes: { [HUMID_SCOPE]: { methods: ['getUTXOs', 'signPset'], notifications: [] } } });
  assert.equal(humid.calls[2].params.scope, HUMID_SCOPE);
  assert.deepEqual(humid.calls[3].params, { scope: HUMID_SCOPE, request: { method: 'signPset', params: { pset: plan.pset, signInputs: plan.signInputs, broadcast: true } } });
  assert.deepEqual(signing, [plan.spends, 3], 'told what it spends before the signing request');
  // Humid's broadcast is blinded, so its txid is not the unblinded transaction's; the one Humid returns is kept.
  const sent = blindedBurn(plan.pset);
  assert.notEqual(sent.txid, sent.unsignedTxid);
  assert.equal(txid, sent.txid);
  assert.deepEqual(steps, ['Finding the claim on Liquid testnet…', 'Approve the connection to this page in Humid, if it asks…',
    'Let Humid share its coins with this page, if it asks…', 'Review the burn in Humid, then sign and send…']);

  // A session that can sign already: no second connection prompt.
  const again = fakeHumid({ session: { [HUMID_SCOPE]: { methods: ['getUTXOs', 'signPset'] } } });
  await burnWithHumid({ humid: again, esplora, asset: ASSET, units: 100_000n, burnScript: BURN_SCRIPT, claim: humidAddress(ADDRESS) });
  assert.deepEqual(again.calls.map((c) => c.params?.request?.method ?? c.method), ['wallet_getSession', 'getUTXOs', 'signPset']);
});

test('the broadcast must be the burn built: same inputs, same outputs but the blinded change', () => {
  const claim = claimInput({ txid: CLAIM_TXID, vout: 1, units: 100_000n }, CLAIM, ASSET, SCRIPT);
  const coinTx = servedWith([confidentialOut(hexToBytes(TLQ_SCRIPT))], [[SURJECTION, RANGEPROOF]]);
  const fee = feeInput({ txid: coinTx.txid, vout: 0, amount: '100000', assetId: lbtcId, scriptPubKey: TLQ_SCRIPT, address: TLQ, confidential: true, spendable: true }, coinTx.hex);
  const plan = redeemPset({ asset: ASSET, units: 100_000n, burnScript: BURN_SCRIPT, claims: [claim], fee, claimAddress: ADDRESS });
  const sent = blindedBurn(plan.pset);
  assert.equal(broadcastMatches(plan, sent.hex), null);
  const tx = parseTransaction(hexToBytes(sent.hex));
  const rebuilt = (outs, inputs = tx.inputs) => bytesToHex(concat([2, 0, 0, 0, 0, inputs.length],
    ...inputs.map((i) => concat(i.prevTxid, [i.n, 0, 0, 0], [0], [0xff, 0xff, 0xff, 0xff])), [outs.length], ...outs, new Uint8Array(4)));
  const raws = tx.outputs.map((o) => o.raw);
  assert.match(broadcastMatches(plan, rebuilt([explicitTxOut(ASSET, 99_999n, BURN_SCRIPT), ...raws.slice(1)])), /output 0 is not/);
  assert.match(broadcastMatches(plan, rebuilt([raws[0], confidentialOut(SCRIPT), raws[2]])), /output 1 is not/, 'blinded to another script');
  assert.match(broadcastMatches(plan, rebuilt(raws.slice(0, 2))), /other outputs/);
  assert.match(broadcastMatches(plan, rebuilt(raws, [tx.inputs[1], tx.inputs[0]])), /other coins/);
});

test('nothing reaches Humid\'s signer without a claim and a fee coin; refusals and uncertain sends are told apart', async () => {
  const run = (humid, units = 100_000n, address = ADDRESS) => burnWithHumid({ humid, esplora, asset: ASSET, units, burnScript: BURN_SCRIPT, claim: humidAddress(address) });
  const none = fakeHumid();
  await assert.rejects(run(none, 100_000n, 'tex1q6rz28mcfaxtmd6v789l9rrlrusdprr9p634wu8'), /holds no bridge asset openly/);
  assert.deepEqual(none.calls, [], 'Humid is not even asked to connect');
  const poor = fakeHumid({ utxos: [] });
  await assert.rejects(run(poor), /no confirmed tL-BTC coin/);
  assert.ok(!poor.calls.some((c) => c.params?.request?.method === 'signPset'));

  const fails = (reason, code = -32000) => fakeHumid({ sign: () => { throw Object.assign(new Error(`Humid says ${reason}`), { code, data: { reason } }); } });
  const declined = await run(fails('user_rejected')).catch((x) => x);
  assert.equal(declined.sent, 'no');
  assert.equal(humidError(declined), 'Humid did not receive approval: the request was declined or expired. Nothing was sent. Reopen the request to try again.');
  const invalid = await run(fails('invalid_pset_request', -32002)).catch((x) => x);
  assert.equal(invalid.sent, 'no', 'Humid refuses an invalid request before the user can confirm');
  assert.equal(humidError(invalid), 'Humid: Humid says invalid_pset_request');

  // Signing and broadcasting are one step in Humid: after a failure there, the burn may be on Liquid regardless.
  const broadcast = await run(fails('wallet_pset_broadcast_failed', -32002)).catch((x) => x);
  assert.equal(broadcast.sent, 'maybe');
  assert.match(humidError(broadcast), /may have been sent all the same\. Before trying again, check Humid's activity and this address on a Liquid explorer, and look up any burn you find in step 3/);
  assert.match(humidError(broadcast), /Humid signs only coins it holds/);
  const internal = await run(fails('internal_error', -32603)).catch((x) => x);
  assert.equal(internal.sent, 'maybe', 'any other reason stays uncertain');

  // A failure in Humid's review, before its prompt: the transport passes a raw error, such as LWK's, on with only its
  // message (no code, no reason), which Humid 1.1.3's signing step never gives. Nothing was signed or sent.
  const review = await run(fakeHumid({ sign: () => { throw new Error('Input #1 is not unblindable'); } })).catch((x) => x);
  assert.deepEqual([review.sent, review.stage], ['no', 'review']);
  assert.equal(humidError(review), 'Humid stopped before asking you to sign (Input #1 is not unblindable): its review of the burn failed, '
    + 'so nothing was signed or sent. If Humid did show you the burn and you confirmed it, check step 3 before trying again.');
  assert.doesNotMatch(humidError(review), /may have been sent/);
  const noTxid = await run(fakeHumid({ sign: (p) => ({ pset: p.pset }) })).catch((x) => x);
  assert.deepEqual([noTxid.message, noTxid.sent], ['Humid returned no transaction id', 'maybe']);
  assert.match(humidError(noTxid), /may have been sent/);
});

test('a signing request Humid never answers is given up as possibly sent, not as a review failure', async () => {
  // Humid's page provider has no timeout: if its background stops after broadcasting, the request never settles.
  const silent = fakeHumid({ sign: () => new Promise(() => {}) });
  let spends = null;
  const started = Date.now();
  const e = await burnWithHumid({
    humid: silent, esplora, asset: ASSET, units: 100_000n, burnScript: BURN_SCRIPT, claim: humidAddress(ADDRESS), deadlineMs: 50,
    onSign: (o) => { spends = o; },
  }).catch((x) => x);
  assert.ok(Date.now() - started >= 45, 'it waited for the deadline');
  assert.deepEqual([e.message, e.sent, e.stage], ['Humid gave no answer within 0.05 seconds', 'maybe', undefined], 'no reason, yet not "review"');
  assert.ok(spends.length === 2, 'the page was told which coins the request may have spent');
  assert.match(humidError(e), /^Humid did not confirm a sent burn \(Humid gave no answer within 0\.05 seconds\)\. It may have been sent all the same\./);
  // An answer that does come in time is used as before.
  const prompt = fakeHumid({ sign: (p) => new Promise((r) => setTimeout(() => r({ pset: p.pset, txid: 'ab'.repeat(32) }), 10)) });
  const ok = await burnWithHumid({ humid: prompt, esplora, asset: ASSET, units: 100_000n, burnScript: BURN_SCRIPT, claim: humidAddress(ADDRESS), deadlineMs: 1_000 });
  assert.equal(ok.txid, 'ab'.repeat(32));
});
