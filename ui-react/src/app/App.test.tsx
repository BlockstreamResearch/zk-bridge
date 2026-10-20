// The whole page against the fixture, as a reader uses it: readings, tabs, the deposit form's gates, step 2's burn and
// Humid approval line, and Settings.
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { BridgeProvider } from '../bridge/context';
import { BridgeController } from '../bridge/controller';
import { ACCOUNT_CHECKSUMMED, DEPOSIT_ADDRESS, fixture, type Scenario } from '../dev/fixture';
import { App } from './App';

function renderPage(scenario: Scenario = 'connected') {
  const f = fixture(scenario);
  const controller = new BridgeController(f.instance, f.env);
  const user = userEvent.setup();
  const view = render(<BridgeProvider controller={controller}><App /></BridgeProvider>);
  return { f, controller, user, ...view };
}

describe('the page', () => {
  it('shows the three readings and the checks it made', async () => {
    renderPage();
    expect(await screen.findByText('2,664,000')).toBeInTheDocument();
    expect(await screen.findByText('2,663,990')).toBeInTheDocument();
    const checks = screen.getByRole('region', { name: 'Bridge checks' });
    expect(await within(checks).findByText(/its code hash is the one in instances\/fixture-instance\//)).toBeInTheDocument();
    expect(within(checks).getByText('output 0 pays the published state address')).toBeInTheDocument();
    expect(within(checks).getAllByRole('img', { name: 'Not checked here' }).length).toBeGreaterThan(0);
  });

  it('moves between tabs with the arrow keys, as a tablist should', async () => {
    const { user } = renderPage();
    const deposit = screen.getByRole('tab', { name: /Deposit/ });
    deposit.focus();
    await user.keyboard('{ArrowRight}');
    const redeem = screen.getByRole('tab', { name: /Redeem/ });
    expect(redeem).toHaveAttribute('aria-selected', 'true');
    expect(redeem).toHaveFocus();
    expect(screen.getByRole('tabpanel', { name: /Redeem/ })).toBeVisible();
    await user.keyboard('{ArrowLeft}{ArrowLeft}');
    expect(screen.getByRole('tab', { name: /Activity/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('says plainly when no instance is published, everywhere it matters', async () => {
    renderPage('no-instance');
    expect(await screen.findByText(/No instance of this bridge is published yet/)).toBeInTheDocument();
    expect(screen.getAllByText(/No instance is published yet/).length).toBeGreaterThan(3);
    expect(screen.queryByRole('link', { name: /Escrow on Etherscan/ })).toBeNull();
  });
});

describe('the deposit form', () => {
  it('enables Send only with a valid address, a valid amount and the acknowledgement', async () => {
    const { user } = renderPage();
    const send = screen.getByRole('button', { name: 'Send deposit' });
    await screen.findByText('2,663,990');
    await user.type(screen.getByLabelText('Liquid testnet address'), DEPOSIT_ADDRESS);
    await user.type(screen.getByLabelText('Amount in ETH'), '0.0025');
    expect(send).toBeDisabled();
    expect(screen.getByText(/You lock 0.0025 SepETH/)).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox'));
    await waitFor(() => expect(send).toBeEnabled());
  });

  it('explains an invalid address once the field is left', async () => {
    const { user } = renderPage();
    const field = screen.getByLabelText('Liquid testnet address');
    await user.type(field, 'tex1notanaddress');
    expect(field).not.toHaveAttribute('aria-invalid');
    await user.tab();
    expect(field).toHaveAttribute('aria-invalid', 'true');
  });

  it('offers to relay when relaying is all that keeps deposits closed', async () => {
    renderPage('relay-closed');
    expect(await screen.findByRole('button', { name: 'Relay Liquid to reopen deposits' })).toBeInTheDocument();
  });

  it('offers the fork-proof form when a stale fork check closes deposits', async () => {
    renderPage('fork-closed');
    expect(await screen.findByText('Send a fork proof to reopen deposits')).toBeInTheDocument();
  });
});

describe('redeem step 2', () => {
  it('shows the bare OP_RETURN burn, then Humid\'s approval line once Humid\'s address is known', async () => {
    const { user } = renderPage();
    await user.click(screen.getByRole('tab', { name: /Redeem/ }));
    await screen.findByText('2,663,990');
    await user.type(screen.getByLabelText('Ethereum address'), ACCOUNT_CHECKSUMMED);
    await user.type(screen.getByLabelText('Amount to redeem, in bridge asset'), '0.001');
    const script = await screen.findByLabelText('Burn script');
    expect(script.textContent).toMatch(/^6a46/);
    expect(script.textContent).toMatch(new RegExp(`${ACCOUNT_CHECKSUMMED.slice(2).toLowerCase()}$`));
    expect(screen.queryByText(/In Humid's approval/)).toBeNull();
    await user.type(screen.getByLabelText(/Humid's unconfidential address/), DEPOSIT_ADDRESS);
    expect(await screen.findByText(/In Humid's approval, sign only if Output 0 shows no address, with "100000 · /)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Send with Humid' })).toBeEnabled();
  });
});

describe('Settings', () => {
  it('refuses a plain-http RPC off this computer without repeating the URL', async () => {
    const { user } = renderPage();
    await user.click(screen.getByText('Settings'));
    const rpc = screen.getByLabelText('Ethereum Sepolia RPC (optional)');
    await user.type(rpc, 'http://rpc.example/SECRETKEY123456');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/Not saved: the Sepolia RPC must be an https URL/)).toBeInTheDocument();
    // Only the field itself holds the URL.
    expect(document.body.textContent).not.toContain('SECRETKEY');
  });
});
