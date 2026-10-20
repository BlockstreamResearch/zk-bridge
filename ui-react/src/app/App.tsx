import { type KeyboardEvent, useRef, useState } from 'react';
import { useBridge } from '../bridge/context';
import { ActivityPanel, ExpandedProvider } from '../components/Journeys';
import { DepositPanel } from '../components/DepositPanel';
import { Footer } from '../components/Footer';
import { ClaimPanel, UpdatePanel, useClaimPanel } from '../components/LiquidSendPanels';
import { Masthead, Notice, Slip } from '../components/Masthead';
import { Messages } from '../components/Messages';
import { RedeemPanel } from '../components/RedeemPanel';
import { Route } from '../components/Route';
import { ChecksPanel, SettingsPanel } from '../components/Sidebar';
import { TrustPanel } from '../components/TrustPanel';
import { ExtLink } from '../components/primitives';
import { TAKEOVER } from '../content/links';

type Tab = 'deposit' | 'redeem' | 'activity';
const TABS: { id: Tab; label: string; sub: string }[] = [
  { id: 'deposit', label: 'Deposit', sub: 'ETH → Liquid' },
  { id: 'redeem', label: 'Redeem', sub: 'Liquid → ETH' },
  { id: 'activity', label: 'Activity', sub: '' },
];

export function App() {
  const { journeys } = useBridge();
  const [tab, setTab] = useState<Tab>('deposit');
  const tabRefs = useRef(new Map<Tab, HTMLButtonElement>());
  const trustRef = useRef<HTMLDetailsElement>(null);
  const claim = useClaimPanel();

  const select = (t: Tab, focus = false) => {
    setTab(t);
    if (focus) tabRefs.current.get(t)?.focus();
  };
  // Arrow keys move between tabs, as the WAI-ARIA tabs pattern expects; Home and End go to the ends.
  const onKey = (e: KeyboardEvent, i: number) => {
    const next = e.key === 'ArrowRight' ? (i + 1) % TABS.length : e.key === 'ArrowLeft' ? (i + TABS.length - 1) % TABS.length
      : e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1 : null;
    if (next === null) return;
    e.preventDefault();
    select(TABS[next].id, true);
  };

  return (
    <ExpandedProvider>
      <a className="skip" href="#main">Skip to the bridge</a>
      <Masthead onTrust={() => {
        if (trustRef.current) trustRef.current.open = true;
      }} />
      <Slip />
      <div className="layout shell">
        <main id="main" tabIndex={-1}>
          <div className="tray bridge-tray">
            <div className="tabs" role="tablist" aria-label="Bridge direction">
              {TABS.map((t, i) => (
                <button key={t.id} ref={(el) => {
                  if (el) tabRefs.current.set(t.id, el);
                }} role="tab" type="button" id={`tab-${t.id}`} aria-controls={`panel-${t.id}`} aria-selected={tab === t.id}
                tabIndex={tab === t.id ? 0 : -1} onClick={() => select(t.id)} onKeyDown={(e) => onKey(e, i)}>
                  {t.label} {t.sub ? <small>{t.sub}</small> : <small className="count">{journeys.length}</small>}
                </button>
              ))}
            </div>
            {tab !== 'activity' && <Route direction={tab} />}
            <Notice />
            {/* All three stay mounted, so a half-filled form survives switching tabs. */}
            <section className="panel" id="panel-deposit" role="tabpanel" aria-labelledby="tab-deposit" hidden={tab !== 'deposit'}>
              <DepositPanel onClaim={claim.open} />
            </section>
            <section className="panel" id="panel-redeem" role="tabpanel" aria-labelledby="tab-redeem" hidden={tab !== 'redeem'}>
              <RedeemPanel onClaim={claim.open} />
            </section>
            <section className="panel" id="panel-activity" role="tabpanel" aria-labelledby="tab-activity" hidden={tab !== 'activity'}>
              <ActivityPanel onClaim={claim.open} />
            </section>
          </div>
          <section className="sends" aria-labelledby="sends-title">
            <div className="sends-head">
              <h2 id="sends-title">Finish a deposit yourself</h2>
              <p className="hint">For a deposit still waiting on Liquid. An update proves finalized deposits, then a claim pays each one, in any order; if
                an update already covers yours, only its claim is left. Build either on your computer with the repository tools
                (<ExtLink href={TAKEOVER}>the OPERATOR.md guide</ExtLink>), then load the file below and Humid pays only the fee.</p>
            </div>
            <UpdatePanel />
            <ClaimPanel panelRef={claim.panelRef} fileRef={claim.fileRef} />
          </section>
        </main>
        <aside className="sidebar" aria-label="Verification and settings">
          <ChecksPanel />
          <SettingsPanel />
        </aside>
      </div>
      <TrustPanel panelRef={trustRef} />
      <Footer onTab={(t) => {
        select(t, true);
        document.getElementById('main')?.scrollIntoView?.({ block: 'start' });
      }} />
      <Messages />
    </ExpandedProvider>
  );
}
