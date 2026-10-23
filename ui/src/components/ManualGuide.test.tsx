import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { BridgeProvider } from '../bridge/context';
import { BridgeController } from '../bridge/controller';
import type { DepositJourney } from '../bridge/types';
import { fixture, seededJourneys } from '../dev/fixture';
import { JourneyList } from './Journeys';
import { ManualGuide } from './ManualGuide';

function controller(scenario: 'connected' | 'no-instance' = 'connected', journey?: DepositJourney) {
  const f = fixture(scenario, { journeys: journey ? [journey] : [] });
  const c = new BridgeController(f.instance, f.env);
  // These tests exercise guidance for a known state, without polling it into another state.
  vi.spyOn(c, 'start').mockImplementation(() => {});
  return c;
}

function renderGuide(scenario: 'connected' | 'no-instance' = 'connected') {
  const actions = { onUpdate: vi.fn(), onClaim: vi.fn(), onRedeem: vi.fn() };
  render(<BridgeProvider controller={controller(scenario)}><ManualGuide {...actions} /></BridgeProvider>);
  return actions;
}

describe('manual bridge guide', () => {
  it('provides local proof commands for this instance and keeps transaction construction in the browser', () => {
    renderGuide();
    const guide = screen.getByRole('region', { name: 'Bridge guide' });
    expect(guide.id).toBe('guide');
    expect(within(guide).getByLabelText('Choose bridge instance')).toHaveTextContent("export BRIDGE_INSTANCE='instances/fixture-instance'");
    expect(within(guide).getByLabelText('Configure Sepolia RPCs')).toHaveTextContent('SEPOLIA_EXECUTION_RPC');
    expect(within(guide).getByLabelText('Configure Sepolia RPCs')).toHaveTextContent('SEPOLIA_CONSENSUS_RPC');
    expect(within(guide).getByLabelText('Build proof tools')).toHaveTextContent('just deps tools prover check-elf');
    expect(within(guide).getByLabelText('Generate proof')).toHaveTextContent('just inputs execute prove');
    expect(guide).toHaveTextContent('target/takeover/proof.browser.json');
    expect(guide).toHaveTextContent('just proof-bundle');
    expect(guide).toHaveTextContent('The page builds the transaction');
    expect(guide).toHaveTextContent('The page builds the claim');
    expect(guide.textContent).not.toMatch(/update-unsigned|claim-unsigned|update\.hex|claim\.hex/);
    expect(guide).toHaveTextContent('There is no refund');
    expect(guide).toHaveTextContent('entire selected fee coin');
    expect(guide).toHaveTextContent('Uploading it here does not publish it');
    expect(guide).toHaveTextContent('Optional: publish the store');
    expect(within(guide).getByLabelText('Stage generated store')).toHaveTextContent('just stage-generated');
    expect(within(guide).getByLabelText('Review store files')).toHaveTextContent('instances/fixture-instance/lc_stores');
    expect(within(guide).getByLabelText('Push store files')).toHaveTextContent('git push https://github.com/BlockstreamResearch/zk-bridge.git HEAD:master');
    expect(guide).toHaveTextContent('recovery may be impossible');
    expect(guide).toHaveTextContent('Burning is irreversible');
    expect(guide).toHaveTextContent('Humid signing is unavailable on mobile');
    expect(guide).toHaveTextContent('Claim preparation reads deposit logs since deployment');
    expect(within(guide).getByRole('link', { name: /testnet tL-BTC/ })).toHaveAttribute('href', 'https://liquidtestnet.com/faucet');
  });

  it('opens the update, claim and redeem controls through their owning callbacks', () => {
    const actions = renderGuide();
    fireEvent.click(screen.getByRole('button', { name: 'Open update' }));
    fireEvent.click(screen.getByRole('button', { name: 'Open claim' }));
    fireEvent.click(screen.getByRole('button', { name: 'Open redeem' }));
    for (const action of Object.values(actions)) expect(action).toHaveBeenCalledOnce();
  });

  it('does not offer commands or transaction actions without an instance', () => {
    renderGuide('no-instance');
    expect(screen.getByRole('region', { name: 'Bridge guide' })).toHaveTextContent('No bridge instance is available');
    expect(screen.queryByLabelText('Choose bridge instance')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Open update' })).not.toBeInTheDocument();
  });

  it('opens the claim panel from the skip link', () => {
    const { onClaim } = renderGuide();
    const link = screen.getByRole('link', { name: 'Skip to claim' });
    expect(link).toHaveAttribute('href', '#claim');
    fireEvent.click(link);
    expect(onClaim).toHaveBeenCalledOnce();
  });

  it.each(['finalized', 'proven'] as const)('routes a %s deposit to the correct next step without time predictions', (status) => {
    const deposit = seededJourneys(Date.now()).find((j): j is DepositJourney => j.kind === 'deposit')!;
    const onClaim = vi.fn();
    const { container } = render(
      <BridgeProvider controller={controller('connected', { ...deposit, status })}>
        <JourneyList onClaim={onClaim} />
      </BridgeProvider>,
    );
    if (status === 'finalized') {
      expect(screen.getByRole('link', { name: 'Prepare proof' })).toHaveAttribute('href', '#guide');
      expect(screen.queryByRole('button', { name: 'Claim with Humid' })).not.toBeInTheDocument();
      expect(container).toHaveTextContent('no refund');
    } else {
      expect(screen.queryByRole('link', { name: 'Prepare proof' })).not.toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Claim with Humid' }));
      expect(onClaim).toHaveBeenCalledExactlyOnceWith(deposit.index);
      expect(container).toHaveTextContent('no new proof is needed');
    }
    expect(container.textContent).not.toMatch(/usually|operator|minutes|hours|claim-unsigned/);
  });
});
