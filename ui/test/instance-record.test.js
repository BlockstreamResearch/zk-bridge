import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { INSTANCE, parseInstance } from '../config.js';
import { encodeSegwit } from '../lib/bech32.js';
import { bytesToHex, hexToBytes } from '../lib/bytes.js';
import { depositRecipient, LIQUID_TESTNET_LBTC } from '../lib/bridge.js';
import { displayHex, parseTransaction } from '../lib/elements.js';
import { checkBootstrap } from '../lib/issuance.js';

// Pages publishes the page with the record INSTANCE names, instances/<name>/ (.github/workflows/pages.yml), and
// runs these tests first. Every value config.js hardcodes must be that record's, or the page would check one escrow's
// code against another record's bootstrap and state.
function files(name) {
  const dir = new URL(`../../instances/${name}/`, import.meta.url);
  const read = (f) => readFileSync(new URL(f, dir), 'utf8');
  return {
    pins: JSON.parse(read('instance.json')),
    manifest: JSON.parse(read('manifest.json')),
    initial: JSON.parse(read('initial_state.json')),
    bootstrap: parseTransaction(hexToBytes(read('bootstrap.hex').trim())),
  };
}

/** Throws unless the parsed instance `inst` is exactly its record `r` (files()). */
function checkRecord(inst, r) {
  const escrow = inst.escrow.slice(2);
  const { manifest: m, bootstrap: tx } = r;
  assert.equal(r.pins.ESCROW, escrow, 'escrow = instance.json ESCROW');
  assert.equal(r.pins.ESCROW_CODE_HASH, inst.codeHash, 'code hash = instance.json ESCROW_CODE_HASH');
  assert.equal(m.sepolia.escrow, escrow, 'escrow = the manifest escrow');
  assert.equal(m.harness_config.escrow, escrow, 'escrow = the escrow the update leaf pins');
  assert.equal(m.sepolia.escrow_code_hash, inst.codeHash, 'code hash = the manifest code hash');
  assert.equal(m.deployable, true, 'the manifest is deployable');
  assert.equal(m.state_tree.address, inst.state, 'state = the manifest state address');
  assert.equal(bytesToHex(depositRecipient(inst.state).script), m.state_tree.script_pubkey, 'state address = the manifest state script');
  assert.deepEqual(r.initial, m.initial_state, 'initial_state.json = the manifest initial state');
  assert.equal(displayHex(tx.txid), inst.bootstrap, 'bootstrap = the txid of bootstrap.hex');
  assert.equal(displayHex(tx.inputs[0].prevTxid), m.bootstrap.funding_txid, 'bootstrap.hex spends the manifest funding transaction');
  assert.equal(tx.inputs[0].n & 0x3fffffff, m.bootstrap.funding_vout, 'at the manifest funding vout');
  const { ok, checks } = checkBootstrap({
    tx, confirmed: true, bridgeAsset: hexToBytes(m.bootstrap.asset), stateScript: hexToBytes(m.state_tree.script_pubkey),
    feeAsset: hexToBytes(LIQUID_TESTNET_LBTC),
  });
  assert.ok(ok, checks.filter((c) => !c.ok).map((c) => c.text).join('; '));
}

const skip = INSTANCE === null && 'no instance is published, so there is no record to check config.js against';

test('INSTANCE is its published record', { skip }, () => {
  checkRecord(parseInstance(INSTANCE), files(INSTANCE.name));
});

test('a hardcoded value that is not the record is refused', { skip }, () => {
  const r = files(INSTANCE.name);
  // Valid values that are not this record's; the state is a Taproot address of the secp256k1 generator's x.
  const otherState = encodeSegwit('tex', 1, hexToBytes('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'));
  for (const [key, value, message] of [
    ['escrow', '0x' + '11'.repeat(20), /ESCROW/],
    ['codeHash', 'cd'.repeat(32), /ESCROW_CODE_HASH/],
    ['bootstrap', 'ab'.repeat(32), /txid of bootstrap.hex/],
    ['state', otherState, /state address/],
  ]) {
    assert.throws(() => checkRecord(parseInstance({ ...INSTANCE, [key]: value }), r), message, key);
  }
  const other = structuredClone(r);
  other.initial.head += 1;
  assert.throws(() => checkRecord(parseInstance(INSTANCE), other), /initial_state.json/);
});
