import type { FeeCoin as DiscoveredCoin } from '@bridge/core/lib/fee.js';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { BridgeProvider } from '../bridge/context';
import { BridgeController } from '../bridge/controller';
import { DEPOSIT_ADDRESS, fixture } from '../dev/fixture';
import { FeePicker } from './FeePicker';

const first: DiscoveredCoin = {
  txid: 'aa'.repeat(32), vout: 0, sats: 2000n,
  address: DEPOSIT_ADDRESS, script: new Uint8Array(), txHex: '',
};
const second: DiscoveredCoin = { ...first, txid: 'bb'.repeat(32), vout: 1, sats: 3000n };
const prepared = {
  ...first, confirmed: false as const,
  plan: { pset: '', unsigned: new Uint8Array(), signInputs: [], spends: [], blindIndex: -1,
    address: DEPOSIT_ADDRESS, sats: first.sats, changeSats: 546n, feeSats: 500n },
};

function setup(disabled = false) {
  const f = fixture();
  const c = new BridgeController(f.instance, f.env);
  vi.spyOn(c, 'start').mockImplementation(() => {});
  c.setRedeemForm({ humidAddress: DEPOSIT_ADDRESS });
  const find = vi.spyOn(c, 'findFeeCoins').mockResolvedValue([first, second]);
  const prepare = vi.spyOn(c, 'prepareFee').mockResolvedValue(prepared);
  const onCoin = vi.fn();
  render(<BridgeProvider controller={c}><FeePicker kind="claim" disabled={disabled} onCoin={onCoin} /></BridgeProvider>);
  return { user: userEvent.setup(), find, prepare, onCoin };
}

async function openPreparation(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByText('Prepare a fee coin with Humid'));
  return screen.getByRole('button', { name: 'Prepare fee coin' });
}

describe('fee picker', () => {
  it('discovers confirmed coins without wallet approval and selects only the chosen outpoint', async () => {
    const { user, find, prepare, onCoin } = setup();
    await user.click(screen.getByRole('button', { name: 'Find fee coins' }));
    const choice = await screen.findByLabelText('Confirmed fee coin');
    expect(find).toHaveBeenCalledWith(DEPOSIT_ADDRESS, 2000n);
    expect(prepare).not.toHaveBeenCalled();
    expect(onCoin).toHaveBeenLastCalledWith(null);
    await user.selectOptions(choice, `${second.txid}:${second.vout}`);
    expect(onCoin).toHaveBeenLastCalledWith(expect.objectContaining({ txid: second.txid, vout: second.vout }));
    await user.selectOptions(choice, '');
    expect(onCoin).toHaveBeenLastCalledWith(null);
  });

  it('requires ownership before preparation and waits for confirmation before another preparation', async () => {
    const { user, prepare } = setup();
    const button = await openPreparation(user);
    expect(button).toBeDisabled();
    await user.click(button);
    expect(prepare).not.toHaveBeenCalled();
    await user.click(screen.getByRole('checkbox'));
    await user.click(button);
    expect(prepare).toHaveBeenCalledExactlyOnceWith(DEPOSIT_ADDRESS, 2000n, expect.any(Function));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(first.txid));
    expect(button).toBeDisabled();
    await user.click(button);
    expect(prepare).toHaveBeenCalledTimes(1);
  });

  it('clears a selection and ownership when the address changes', async () => {
    const { user, onCoin } = setup();
    await openPreparation(user);
    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByRole('button', { name: 'Find fee coins' }));
    await user.selectOptions(await screen.findByLabelText('Confirmed fee coin'), `${first.txid}:0`);
    await user.clear(screen.getByLabelText('Your Humid unconfidential address'));
    expect(onCoin).toHaveBeenLastCalledWith(null);
    expect(screen.queryByLabelText('Confirmed fee coin')).not.toBeInTheDocument();
    expect(screen.getByRole('checkbox')).not.toBeChecked();
    expect(screen.getByRole('button', { name: 'Prepare fee coin' })).toBeDisabled();
  });

  it('clears the previous selection while refreshing and after a failed lookup', async () => {
    const { user, find, onCoin } = setup();
    await user.click(screen.getByRole('button', { name: 'Find fee coins' }));
    await user.selectOptions(await screen.findByLabelText('Confirmed fee coin'), `${first.txid}:0`);
    let reject!: (reason: Error) => void;
    find.mockImplementationOnce(() => new Promise((_, failure) => { reject = failure; }));
    await user.click(screen.getByRole('button', { name: 'Find fee coins' }));
    expect(onCoin).toHaveBeenLastCalledWith(null);
    await act(async () => reject(new Error('Liquid unavailable')));
    expect(screen.getByRole('alert')).toHaveTextContent('Liquid unavailable');
    expect(screen.queryByLabelText('Confirmed fee coin')).not.toBeInTheDocument();
  });

  it('does not let an earlier confirmed preparation clear a later uncertain send', async () => {
    const { user, find, prepare } = setup();
    const button = await openPreparation(user);
    await user.click(screen.getByRole('checkbox'));
    await user.click(button);
    find.mockResolvedValue([first]);
    await user.click(screen.getByRole('button', { name: 'Find fee coins' }));
    await waitFor(() => expect(button).toBeEnabled());
    prepare.mockRejectedValueOnce(Object.assign(new Error('Broadcast uncertain'), { sent: 'maybe' }));
    await user.click(button);
    expect(screen.getByRole('alert')).toHaveTextContent('Broadcast uncertain');
    expect(button).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Find fee coins' }));
    await waitFor(() => expect(find).toHaveBeenCalledTimes(2));
    expect(button).toBeDisabled();
    await user.click(button);
    expect(prepare).toHaveBeenCalledTimes(2);
  });

  it('releases a known uncertain preparation only when that output is found confirmed', async () => {
    const { user, find, prepare } = setup();
    prepare.mockRejectedValueOnce(Object.assign(new Error('Readback unavailable'), { sent: 'maybe', txid: first.txid }));
    const button = await openPreparation(user);
    await user.click(screen.getByRole('checkbox'));
    await user.click(button);
    expect(button).toBeDisabled();
    find.mockResolvedValueOnce([{ ...first, vout: 1 }]);
    await user.click(screen.getByRole('button', { name: 'Find fee coins' }));
    expect(button).toBeDisabled();
    find.mockResolvedValueOnce([first]);
    await user.click(screen.getByRole('button', { name: 'Find fee coins' }));
    await waitFor(() => expect(button).toBeEnabled());
    expect(prepare).toHaveBeenCalledTimes(1);
  });

  it.each(['545', '50001', '1.5', ''])('refuses the fee budget %j before discovery or preparation', async (amount) => {
    const { user, find, prepare } = setup();
    const button = await openPreparation(user);
    await user.click(screen.getByRole('checkbox'));
    const input = screen.getByLabelText('Fee budget (tL-BTC sats)');
    await user.clear(input);
    if (amount) await user.type(input, amount);
    expect(button).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Find fee coins' })).toBeDisabled();
    expect(find).not.toHaveBeenCalled();
    expect(prepare).not.toHaveBeenCalled();
  });

  it('respects the parent lock on discovery and preparation', async () => {
    const { user, find, prepare } = setup(true);
    const button = await openPreparation(user);
    expect(screen.getByLabelText('Your Humid unconfidential address')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Find fee coins' })).toBeDisabled();
    expect(button).toBeDisabled();
    await user.click(button);
    expect(find).not.toHaveBeenCalled();
    expect(prepare).not.toHaveBeenCalled();
  });
});
