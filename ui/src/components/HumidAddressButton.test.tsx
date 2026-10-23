import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { BridgeProvider } from '../bridge/context';
import { BridgeController } from '../bridge/controller';
import { DEPOSIT_ADDRESS, fixture } from '../dev/fixture';
import { DepositPanel } from './DepositPanel';
import { HumidAddressButton } from './HumidAddressButton';

function controller() {
  const f = fixture();
  const c = new BridgeController(f.instance, f.env);
  vi.spyOn(c, 'start').mockImplementation(() => {});
  return c;
}

describe('Humid address access', () => {
  it('fills the deposit recipient only after approval and clears its previous ownership acknowledgement', async () => {
    const c = controller();
    const read = vi.spyOn(c, 'getHumidAddress');
    let finish!: (address: string) => void;
    read.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    render(<BridgeProvider controller={c}><DepositPanel onClaim={() => {}} /></BridgeProvider>);
    const user = userEvent.setup();
    const input = screen.getByLabelText('Liquid testnet address');
    await user.type(input, 'original-address');
    await user.click(screen.getByRole('checkbox'));
    expect(read).not.toHaveBeenCalled();
    const button = screen.getByRole('button', { name: 'Use Humid address' });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(read).toHaveBeenCalledTimes(1);
    expect(input).toBeDisabled();
    expect(input).toHaveValue('original-address');
    expect(screen.getByRole('button', { name: 'Send deposit' })).toBeDisabled();

    await act(async () => finish(DEPOSIT_ADDRESS));
    expect(input).toHaveValue(DEPOSIT_ADDRESS);
    expect(input).toBeEnabled();
    expect(screen.getByRole('checkbox')).not.toBeChecked();
  });

  it('keeps manual entry available after an unsupported read', async () => {
    const c = controller();
    vi.spyOn(c, 'getHumidAddress').mockRejectedValue(new Error('Update Humid or paste your unconfidential address.'));
    render(<BridgeProvider controller={c}><DepositPanel onClaim={() => {}} /></BridgeProvider>);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Use Humid address' }));
    await screen.findByText('Update Humid or paste your unconfidential address.');
    const input = screen.getByLabelText('Liquid testnet address');
    await user.type(input, DEPOSIT_ADDRESS);
    expect(input).toHaveValue(DEPOSIT_ADDRESS);
  });

  it.each(['edit', 'lock', 'unmount'] as const)('discards an address reply after %s', async (change) => {
    const c = controller();
    let finish!: (address: string) => void;
    vi.spyOn(c, 'getHumidAddress').mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    const onAddress = vi.fn();
    const onBusyChange = vi.fn();
    const show = (value = '', disabled = false) => <BridgeProvider controller={c}>
      <HumidAddressButton value={value} disabled={disabled} onAddress={onAddress} onBusyChange={onBusyChange} />
    </BridgeProvider>;
    const view = render(show());
    fireEvent.click(screen.getByRole('button', { name: 'Use Humid address' }));
    if (change === 'unmount') view.unmount();
    else view.rerender(show(change === 'edit' ? 'a manually entered address' : '', change === 'lock'));
    await act(async () => finish(DEPOSIT_ADDRESS));
    expect(onAddress).not.toHaveBeenCalled();
    expect(onBusyChange.mock.calls).toEqual([[true], [false]]);
  });

  it('uses the injected provider through the controller without signing or fetching chain data', async () => {
    const f = fixture();
    const request = vi.fn(async (args: { method: string }) => {
      if (args.method === 'wallet_getSession') return { sessionScopes: {
        'bip122:a771da8e52ee6ad581ed1e9a99825e5b': { methods: ['getAddress'] },
      } };
      return { address: DEPOSIT_ADDRESS, confidential: false, index: 0, chainId: 'bip122:a771da8e52ee6ad581ed1e9a99825e5b' };
    });
    const c = new BridgeController(f.instance, { ...f.env, humidWindow: () => ({ humid: { request } }) });
    expect(await c.getHumidAddress()).toBe(DEPOSIT_ADDRESS);
    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    expect(request.mock.calls[1][0]).toEqual({ method: 'wallet_invokeMethod', params: {
      scope: 'bip122:a771da8e52ee6ad581ed1e9a99825e5b', request: { method: 'getAddress', params: { confidential: false, index: 0 } },
    } });
    expect(f.calls).toEqual([]);
    expect(f.fetched).toEqual([]);
  });
});
