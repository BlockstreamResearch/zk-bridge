// The whole page against the fixture, as a reader uses it: readings, tabs, the deposit form's gates, step 2's burn and
// Humid approval line, and Settings.
import { PUBLISHED } from '@bridge/core/config.js';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { BridgeProvider } from '../bridge/context';
import { BridgeController } from '../bridge/controller';
import { ACCOUNT_CHECKSUMMED, ASSET_DISPLAY, DEPOSIT_ADDRESS, fixture, seededJourneys, type Scenario } from '../dev/fixture';
import { App } from './App';

function renderPage(scenario: Scenario = 'connected', site?: string) {
  const f = fixture(scenario);
  if (site) f.env.siteHref = () => site;
  const controller = new BridgeController(f.instance, f.env);
  const user = userEvent.setup();
  const view = render(<BridgeProvider controller={controller}><App /></BridgeProvider>);
  return { f, controller, user, ...view };
}

describe('the page', () => {
  it('opens the claim builder with the deposit number from Activity', async () => {
    const deposit = seededJourneys(Date.now()).find((journey) => journey.kind === 'deposit')!;
    const f = fixture('connected', { journeys: [{ ...deposit, status: 'proven', index: '7' }] });
    const c = new BridgeController(f.instance, f.env);
    vi.spyOn(c, 'start').mockImplementation(() => {});
    render(<BridgeProvider controller={c}><App /></BridgeProvider>);
    const user = userEvent.setup();
    await user.click(screen.getByRole('tab', { name: /Activity/ }));
    await user.click(screen.getByRole('button', { name: 'Claim with Humid' }));
    expect(document.getElementById('claim')).toHaveAttribute('open');
    expect(screen.getByLabelText('Deposit number')).toHaveValue('7');
    expect(screen.getByLabelText('Deposit number')).toHaveFocus();
    expect(screen.getByRole('button', { name: 'Build claim' })).toHaveAccessibleDescription('To build, find and select a confirmed fee coin.');
  });

  it('shows the three readings and the checks it made', async () => {
    renderPage();
    expect(await screen.findByText('2,664,000')).toBeInTheDocument();
    expect(await screen.findByText('2,663,990')).toBeInTheDocument();
    const checks = screen.getByRole('region', { name: 'Bridge checks' });
    expect(await within(checks).findByText(/Escrow code hash matches instances\/fixture-instance\//)).toBeInTheDocument();
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
    expect(await screen.findByText(/No published bridge instance. Deposits and redemptions are unavailable/)).toBeInTheDocument();
    expect(screen.getAllByText(/No instance is published yet/).length).toBeGreaterThan(3);
    expect(screen.queryByRole('link', { name: /Escrow on Etherscan/ })).toBeNull();
  });

  it.each([
    ['served from this computer', undefined],
    ['the earlier site', 'https://kyrylr.github.io/liquid-poc-bridge/'],
    ['another path on the published host', 'https://blockstreamresearch.github.io/zk-bridge-old/'],
  ])('names the published site at the top when it is %s', (_case, site) => {
    renderPage('connected', site);
    const note = screen.getByRole('note');
    expect(note).toHaveTextContent('Unofficial copy.');
    expect(note).toHaveTextContent('listed stores do not count as published here');
    expect(within(note).getAllByRole('link').map((a) => a.getAttribute('href'))).toEqual([PUBLISHED.site, PUBLISHED.repo]);
    // First on the page, before the masthead.
    expect(document.body.querySelector('.site-notice + .masthead')).not.toBeNull();
  });

  it('says nothing about other copies on the published site itself', () => {
    renderPage('connected', `${PUBLISHED.site}`);
    expect(screen.queryByRole('note')).toBeNull();
    expect(screen.queryByText(/Unofficial copy/)).toBeNull();
  });
});

describe('the original layout', () => {
  it('keeps What you are trusting in the proof-of-concept slip, and every tray under the bridge closed', () => {
    renderPage();
    const slip = screen.getByRole('complementary', { name: 'Proof of concept' });
    expect(slip.querySelector('details#trust')).not.toBeNull();
    for (const id of ['trust', 'update', 'claim', 'checks', 'settings']) {
      const panel = document.getElementById(id);
      expect(panel?.tagName, id).toBe('DETAILS');
      expect((panel as HTMLDetailsElement).open, id).toBe(false);
    }
  });

  it('starts the keyboard path with a link that skips to the bridge', async () => {
    const { user } = renderPage();
    await user.tab();
    const skip = screen.getByRole('link', { name: 'Skip to the bridge' });
    expect(skip).toHaveFocus();
    expect(skip).toHaveAttribute('href', '#main');
    expect(document.getElementById('main')).not.toBeNull();
  });

  it('labels the activity rows\' columns above them', async () => {
    const { user } = renderPage('activity');
    await user.click(screen.getByRole('tab', { name: /Activity/ }));
    const activity = screen.getByRole('tabpanel', { name: /Activity/ });
    await waitFor(() => expect(activity.querySelector('.table-head + .journeys')).not.toBeNull());
    expect(activity.querySelector('.table-head')?.textContent).toBe('TypeDeposit #TransferStartedStatus');
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
    expect(screen.getByText(/Lock 0.0025 SepETH/)).toBeInTheDocument();
    await user.click(within(screen.getByRole('tabpanel', { name: /Deposit/ })).getByRole('checkbox'));
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
    expect(await screen.findByRole('button', { name: 'Relay to reopen deposits' })).toBeInTheDocument();
  });

  it('offers the fork-proof form when a stale fork check closes deposits', async () => {
    renderPage('fork-closed');
    expect(await screen.findByText('Reopen with a fork proof')).toBeInTheDocument();
  });
});

describe('redeem step 2', () => {
  it('shows the bare OP_RETURN burn, then Humid\'s approval line once Humid\'s address is known', async () => {
    const { user } = renderPage();
    await user.click(screen.getByRole('tab', { name: /Redeem/ }));
    await screen.findByText('2,663,990');
    await user.type(screen.getByLabelText('Ethereum address'), ACCOUNT_CHECKSUMMED);
    await user.type(screen.getByLabelText('Bridge asset amount'), '0.001');
    const script = await screen.findByLabelText('Burn script');
    expect(script.textContent).toMatch(/^6a46/);
    expect(script.textContent).toMatch(new RegExp(`${ACCOUNT_CHECKSUMMED.slice(2).toLowerCase()}$`));
    const panel = screen.getByRole('tabpanel', { name: /Redeem/ });
    expect(panel.querySelector('.approval')).toBeNull();
    await user.type(screen.getByLabelText("Claim's Humid address"), DEPOSIT_ADDRESS);
    await waitFor(() => expect(panel.querySelector('.approval')).not.toBeNull());
    const approval = panel.querySelector('.approval')!;
    expect(approval).toHaveTextContent('100000');
    expect(approval).toHaveTextContent(ASSET_DISPLAY);
    expect(approval).toHaveTextContent(script.textContent!);
    expect(approval).toHaveTextContent('500');
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
