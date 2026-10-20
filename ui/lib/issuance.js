// Elements asset issuance (issuance.cpp, rust-elements AssetId) and the bootstrap check the page makes before it
// allows deposits. The escrow pins the bridge asset id but cannot see where that asset's only reissuance token
// went; this checks it from the public bootstrap transaction, as `sg16-testnet check-bootstrap` does for an
// operator holding the manifest.
import { concat, equal } from './bytes.js';
import { sha256Compress, sha256d } from './hash.js';

const OUTPOINT_INDEX_MASK = 0x3fffffff; // the prevout index below the issuance (31) and peg-in (30) flags
const zero32 = () => new Uint8Array(32);

function le32(x) {
  return Uint8Array.of(x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, x >>> 24);
}

/** Issuance entropy: the fast Merkle root of SHA256d(prevout) and the contract hash (internal byte order). */
export function assetEntropy(prevTxid, vout, contractHash = zero32()) {
  return sha256Compress(concat(sha256d(concat(prevTxid, le32(vout))), contractHash));
}

/** The asset id of an issuance's entropy. */
export function assetId(entropy) {
  return sha256Compress(concat(entropy, zero32()));
}

/** The reissuance token of an issuance's entropy; `confidential` when the issued amount was blinded. */
export function reissuanceToken(entropy, confidential = false) {
  const leaf = zero32();
  leaf[0] = confidential ? 2 : 1;
  return sha256Compress(concat(entropy, leaf));
}

/**
 * The checks a bootstrap must pass, as a list of { ok, text }:
 *   tx              the parsed bootstrap transaction (lib/elements.js parseTransaction)
 *   confirmed       whether Liquid has confirmed it
 *   bridgeAsset     the escrow's BRIDGE_ASSET (internal byte order)
 *   stateScript     the scriptPubKey of the instance's published state address
 *   feeAsset        Liquid testnet L-BTC (internal byte order)
 * Together: the outpoint the escrow's asset derives from issued no asset and exactly one explicit token, the
 * only confidential output is the state UTXO, and every other output is explicit L-BTC, so the token is there.
 * Whether that state address commits to the reviewed leaves is not checked here: rebuild it from the
 * manifest with tools/sg16/bridge-guest/testnet/assemble.py verify-bootstrap.
 */
export function checkBootstrap({ tx, confirmed, bridgeAsset, stateScript, feeAsset }) {
  const checks = [];
  const need = (ok, text) => checks.push({ ok: !!ok, text });
  need(confirmed, 'the bootstrap transaction is confirmed on Liquid testnet');
  const input = tx.inputs[0];
  const iss = input && input.issuance;
  need(iss && equal(iss.nonce, zero32()), 'input 0 is a new issuance (zero blinding nonce)');
  need(iss && equal(iss.entropy, zero32()), 'with a zero contract hash, as the bridge tools issue it');
  need(iss && iss.amount.kind === 'null', 'it issues none of the asset itself');
  need(iss && iss.inflationKeys.kind === 'explicit' && iss.inflationKeys.amount === 1n, 'it issues exactly one explicit reissuance token');
  need(tx.inputs.slice(1).every((i) => i.issuance === null), 'no other input issues anything');
  const issued = input ? assetId(assetEntropy(input.prevTxid, input.n & OUTPOINT_INDEX_MASK, iss ? iss.entropy : zero32())) : null;
  need(issued && equal(issued, bridgeAsset), 'its asset is the asset this escrow redeems');
  const out0 = tx.outputs[0];
  need(out0 && equal(out0.script, stateScript), 'output 0 pays the published state address');
  need(out0 && out0.asset.kind === 'confidential', 'output 0 holds a blinded asset (the token, under its public blinding)');
  need(tx.outputs.slice(1).every((o) => o.asset.kind === 'explicit' && equal(o.asset.data, feeAsset) && o.value.kind === 'explicit'),
    'every other output is explicit L-BTC, so the token can only be in output 0');
  return { ok: checks.every((c) => c.ok), checks };
}
