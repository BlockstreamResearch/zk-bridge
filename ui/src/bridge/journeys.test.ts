// Saved journeys come back from storage anyone can edit. Their hashes, txids and addresses reach explorer links and
// Liquid API paths, so loadJourneys keeps only journeys of the shape the page writes, and keeps every one of those.
import { describe, expect, it } from 'vitest';
import { ACCOUNT, ACCOUNT_CHECKSUMMED, BURN_TXID, ESCROW, seededJourneys } from '../dev/fixture';
import { JOURNEYS_KEY, loadJourneys, saveJourneys } from './journeys';
import type { DepositJourney, Journey, RedeemJourney } from './types';

const NOW = 1_800_000_000_000;

function storage(value: unknown) {
  const items = new Map<string, string>([[JOURNEYS_KEY, JSON.stringify(value)]]);
  return {
    getItem: (k: string) => items.get(k) ?? null,
    setItem: (k: string, v: string) => void items.set(k, v),
    removeItem: (k: string) => void items.delete(k),
  };
}

const seeded = seededJourneys(NOW);
const deposit = seeded.find((j): j is DepositJourney => j.kind === 'deposit' && !!j.claimTxid)!;
const redeem = seeded.find((j): j is RedeemJourney => j.kind === 'redeem')!;
const sent: RedeemJourney = { ...redeem, id: `${BURN_TXID}:1`, vout: 1, status: 'submitted', txHash: '0x' + 'ef'.repeat(32), payee: ACCOUNT_CHECKSUMMED };

describe('loadJourneys', () => {
  it('recovers every journey the page saved, through a save and a load', () => {
    const journeys: Journey[] = [...seeded, sent, { ...deposit, id: '0x' + '04'.repeat(32), txHash: '0x' + '04'.repeat(32), address: null }];
    const s = storage([]);
    saveJourneys(s, journeys);
    expect(loadJourneys(s, ESCROW)).toEqual(journeys);
  });

  it.each<[string, Partial<DepositJourney>]>([
    ['a Sepolia hash that is not one', { txHash: 'javascript:alert(1)' }],
    ['a Sepolia hash with a path after it', { txHash: `0x${'03'.repeat(32)}/../../address/0x${'00'.repeat(20)}` }],
    ['a short Sepolia hash', { txHash: '0x' + '03'.repeat(31) }],
    ['a missing Sepolia hash', { txHash: undefined }],
    ['a claim txid with a path in it', { claimTxid: `${'cd'.repeat(32)}/../../api/blocks` }],
    ['a claim txid in upper case', { claimTxid: 'CD'.repeat(32) }],
    ['a deposit address with a query', { address: 'tex1qexample?ref=x' }],
    ['a deposit address that is not a string', { address: 7 as unknown as string }],
  ])('drops a deposit with %s', (_, patch) => {
    expect(loadJourneys(storage([{ ...deposit, ...patch }, redeem]), ESCROW)).toEqual([redeem]);
  });

  it.each<[string, Partial<RedeemJourney>]>([
    ['a burn txid with a path in it', { burnTxid: `${BURN_TXID}/../../address/x` }],
    ['a burn txid with a 0x prefix', { burnTxid: '0x' + BURN_TXID.slice(2) }],
    ['a missing burn txid', { burnTxid: undefined }],
    ['a negative output', { vout: -1 }],
    ['a fractional output', { vout: 0.5 }],
    ['an output as text', { vout: '0' as unknown as number }],
    ['a recipient that is not an address', { recipient: 'https://evil.example/' }],
    ['a short recipient', { recipient: ACCOUNT.slice(0, 40) }],
    ['a payee that is not an address', { payee: '0xnot-an-address' }],
    ['a redemption hash with a path after it', { txHash: `0x${'ef'.repeat(32)}?x=1` }],
  ])('drops a redemption with %s', (_, patch) => {
    expect(loadJourneys(storage([deposit, { ...sent, ...patch }]), ESCROW)).toEqual([deposit]);
  });
});
