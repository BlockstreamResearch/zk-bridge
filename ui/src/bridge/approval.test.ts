import { LIQUID_TESTNET_LBTC, burnTarget } from '@bridge/core/lib/bridge.js';
import { bytesToHex, hexToBytes } from '@bridge/core/lib/bytes.js';
import type { ClaimPlan } from '@bridge/core/lib/claim.js';
import { displayHex } from '@bridge/core/lib/elements.js';
import type { UpdatePlan } from '@bridge/core/lib/update.js';
import { describe, expect, it } from 'vitest';
import { ACCOUNT, ASSET_DISPLAY, DEPOSIT_ADDRESS, ESCROW } from '../dev/fixture';
import { burnApproval, claimApproval, updateApproval } from './approval';

const feeAsset = displayHex(hexToBytes(LIQUID_TESTNET_LBTC));
const ASSET_INTERNAL = bytesToHex(hexToBytes(ASSET_DISPLAY).reverse());
const stateScript = hexToBytes('5120' + 'ab'.repeat(32));
const recipientScript = hexToBytes('0014' + '23'.repeat(20));
const claim: ClaimPlan = {
  txid: 'aa'.repeat(32), feeAddress: DEPOSIT_ADDRESS, successorAddress: 'test-successor-address',
  claim: {
    state: { txid: 'bb'.repeat(32), vout: 0 },
    fee: { txid: 'cc'.repeat(32), vout: 1, sats: 2345n },
    successor: { script: stateScript },
    mint: { script: recipientScript, units: 123456n, asset: hexToBytes(ASSET_INTERNAL), address: 'test-recipient-address' },
  },
};
const state = { head: 42, lc: 'dd'.repeat(32), acc: 'ee'.repeat(32), claimedRoot: null, claimed: null };
const update: UpdatePlan = {
  txid: claim.txid, feeAddress: claim.feeAddress, successorAddress: claim.successorAddress,
  update: { state: claim.claim.state, fee: claim.claim.fee, successor: claim.claim.successor },
  successor: state,
  live: { outpoint: claim.claim.state, state, spends: 0, update: null, claims: [], moving: null, movingClaim: null },
  listed: null,
  store: null,
};

function expectStateReview(text: string) {
  expect(text).toContain(`only Input 1 at ${claim.feeAddress}`);
  expect(text).toContain(`Output 0: ${claim.successorAddress}`);
  expect(text).toContain('Confidential amount unavailable · Confidential asset unavailable');
  expect(text).toContain(`Script: ${bytesToHex(stateScript)}`);
  expect(text).toContain(`Wallet net change: -2345 · ${feeAsset}`);
  expect(text).toContain('Decline if anything differs');
}

describe('Humid approval details', () => {
  it('keeps the burn amount, asset, full script, recipient and net deductions', () => {
    const burn = burnTarget(11155111n, ESCROW, ACCOUNT);
    const text = burnApproval({ recipient: ACCOUNT, burn, asset: ASSET_INTERNAL, assetDisplay: ASSET_DISPLAY, isContract: false }, 123456n);
    expect(text).toContain('Output 0 has no address');
    expect(text).toContain(`123456 · ${ASSET_DISPLAY}`);
    expect(text).toContain(`Script: ${bytesToHex(burn.scriptPubKey)}`);
    expect(text).toContain(`Recipient: ${burn.recipient}`);
    expect(text).toContain(`Wallet net change: -123456 · ${ASSET_DISPLAY}`);
    expect(text).toContain(`-500 · ${feeAsset}`);
    expect(text).toContain('Decline if anything differs');
  });

  it('keeps the sole signing input, successor and full update fee', () => {
    const text = updateApproval(update);
    expectStateReview(text);
    expect(text).toContain(`Output 1 fee: 2345 · ${feeAsset}`);
  });

  it('keeps the claim recipient, minted asset and amount, fee, and conditional credit', () => {
    const text = claimApproval(claim);
    expectStateReview(text);
    expect(text).toContain(`Output 1: test-recipient-address, 123456 · ${ASSET_DISPLAY}`);
    expect(text).toContain(`Script: ${bytesToHex(recipientScript)}`);
    expect(text).toContain(`Output 2 fee: 2345 · ${feeAsset}`);
    expect(text).toContain(`plus 123456 · ${ASSET_DISPLAY} if this wallet receives the claim`);
  });

  it('still shows the full recipient script when it has no standard address', () => {
    const text = claimApproval({ ...claim, claim: { ...claim.claim, mint: { ...claim.claim.mint, address: null } } });
    expect(text).toContain(`Output 1: 123456 · ${ASSET_DISPLAY}`);
    expect(text).toContain(`Script: ${bytesToHex(recipientScript)}`);
    expect(text).not.toContain('null');
  });
});
