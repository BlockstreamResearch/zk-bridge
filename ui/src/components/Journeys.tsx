// Saved journeys as rows that open onto their steps. A row nobody has toggled starts open while its journey is
// unfinished; a reader's toggle is kept across polls and across the three lists that show the same journey.
// React keeps each row's DOM element across polls, so keyboard focus stays where the reader left it.
import { DEFAULTS } from '@bridge/core/config.js';
import { UNIT_WEI, formatUnits } from '@bridge/core/lib/bridge.js';
import { type ReactNode, createContext, useCallback, useContext, useMemo, useState } from 'react';
import { useBridge, useController } from '../bridge/context';
import { ready } from '../bridge/derive';
import { short } from '../bridge/format';
import { actionable, label, settled } from '../bridge/journeys';
import type { DepositJourney, Journey, RedeemJourney } from '../bridge/types';
import { Button, ExtLink, Pill } from './primitives';

const Expanded = createContext<{ open(id: string, fallback: boolean): boolean; set(id: string, open: boolean): void }>({
  open: (_id, fallback) => fallback,
  set: () => {},
});

export function ExpandedProvider({ children }: { children: ReactNode }) {
  const [map, setMap] = useState<ReadonlyMap<string, boolean>>(new Map());
  const set = useCallback((id: string, open: boolean) => setMap((m) => (m.get(id) === open ? m : new Map(m).set(id, open))), []);
  const value = useMemo(() => ({ open: (id: string, fallback: boolean) => map.get(id) ?? fallback, set }), [map, set]);
  return <Expanded.Provider value={value}>{children}</Expanded.Provider>;
}

type StepState = 'done' | 'active' | 'failed' | 'todo';
const stepState = (done: boolean, active: boolean, failed = false): StepState => (failed ? 'failed' : done ? 'done' : active ? 'active' : 'todo');

function JourneyRow({ j, kind, title, steps, extras, actions }: {
  j: Journey; kind: string; title: string; steps: [StepState, ReactNode][]; extras: ReactNode; actions: ReactNode;
}) {
  const ex = useContext(Expanded);
  const { text, tone } = label(j);
  const open = ex.open(j.id, !settled(j));
  return (
    <details className="journey" open={open} onToggle={(e) => {
      const now = e.currentTarget.open;
      if (now !== open) ex.set(j.id, now);
    }}>
      <summary>
        <span className="journey-kind" data-kind={j.kind}>{kind}</span>
        <span className="journey-number">
          {j.kind === 'deposit' && (j.index != null
            ? <span className="journey-deposit-number"><span className="sr-only">Deposit </span>#{j.index}</span>
            : 'Pending')}
        </span>
        <span className="journey-title">{title}</span>
        <span className="journey-meta">{new Date(j.created).toLocaleString()}</span>
        {/* Keyed by status, so a change replays the pill's arrival. */}
        <Pill key={j.status} tone={tone}>{text}</Pill>
      </summary>
      <div className="journey-body">
        <ol className="track">
          {steps.map(([state, content], i) => <li key={i} className="track-step" data-state={state}><span>{content}</span></li>)}
        </ol>
        {extras}
        <div className="journey-actions">{actions}</div>
      </div>
    </details>
  );
}

/** The last poll's failure to check `j`: the row may be stale, and `waits` names the action held back. */
function StaleNote({ j, waits }: { j: Journey; waits?: string }) {
  const m = j.lastError!.charAt(0).toUpperCase() + j.lastError!.slice(1);
  return (
    <p className="warn"><b>Status may be stale. </b>
      {m}{/[.!?]$/.test(m) ? '' : '.'} Retrying{waits ? `; ${waits} until verified` : ''}.</p>
  );
}

/** The next action depends on chain state, without predicting how long it takes. */
function WaitNote({ j }: { j: DepositJourney }) {
  if (j.status === 'claiming') return <p className="help">Claim sent. Waiting for Liquid confirmation.</p>;
  if (j.status === 'mined') {
    return (
      <p className="help">Waiting for Ethereum finality. If progress stalls, compare block {j.block?.toLocaleString('en') ?? 'status'} with
        {' '}<ExtLink href="https://sepolia.beaconcha.in">Sepolia finality</ExtLink> and check your RPC.</p>
    );
  }
  if (j.status !== 'finalized') return null;
  return <p className="help">Finalized on Ethereum. You or anyone else must prove it on Liquid, then claim it. Until then, SepETH stays
    in escrow with no refund.</p>;
}

/**
 * Why the page cannot tell whether a claim paid this deposit. It shows a deposit claimed only once a claim's own
 * output commits its index, never by order or by an output's script and amount, which deposits can share.
 */
function UnresolvedNote({ j }: { j: DepositJourney }) {
  const why = j.claimWhy ? j.claimWhy.charAt(0).toUpperCase() + j.claimWhy.slice(1) : 'A claim on Liquid could not be attributed to a deposit';
  return (
    <div className="warn">
      <p><b>Claim status unknown. </b>{why}. Check your wallet{j.address
        ? <> or <ExtLink href={`${DEFAULTS.liquidExplorer}/address/${j.address}`}>Liquid address</ExtLink></>
        : ''}. Tracking continues until a claim can be matched to this deposit.</p>
    </div>
  );
}

function DepositRow({ j, onClaim }: { j: DepositJourney; onClaim: () => void }) {
  const c = useController();
  const order = ['submitted', 'mined', 'finalized', 'claiming', 'claimed'];
  const at = j.status === 'unresolved' || j.status === 'proven' ? 3 : order.indexOf(j.status);
  const failed = j.status === 'failed';
  const eth = DEFAULTS.ethExplorer;
  const liq = DEFAULTS.liquidExplorer;
  const steps: [StepState, ReactNode][] = [
    [stepState(at >= 1, at === 0, failed), <>Sent on Sepolia <ExtLink href={`${eth}/tx/${j.txHash}`}>{short(j.txHash)}</ExtLink></>],
    [stepState(at >= 2, at === 1), `${at >= 2 ? 'Finalized' : 'Waiting for finality'}${j.block ? ` in block ${j.block.toLocaleString('en')}` : ''}${j.index != null ? `, deposit #${j.index}` : ''}`],
    [stepState(at >= 3, at === 2), j.proofTxid
      ? <>Proven on Liquid <ExtLink href={`${liq}/tx/${j.proofTxid}`}>{short(j.proofTxid)}</ExtLink></>
      : j.status === 'unresolved' ? 'Checking the Liquid claim'
        : at >= 3 ? 'Proof accepted on Liquid'
        : 'Waiting for a proof update on Liquid'],
    [stepState(at >= 4, at === 3), j.claimTxid
      ? <>Claimed on Liquid <ExtLink href={`${liq}/tx/${j.claimTxid}`}>{short(j.claimTxid)}</ExtLink>{j.status === 'claiming' ? ' (confirming)' : ''}</>
      : j.status === 'unresolved' ? 'Claim status unknown'
        : j.status === 'proven' ? 'Ready to claim on Liquid' : 'Claim on Liquid'],
  ];
  const title = `${formatUnits(BigInt(j.wei), 18)} ETH → ${j.address ? short(j.address, 8) : `script ${short(j.script, 8)}`}`;
  return (
    <JourneyRow j={j} kind="Deposit" title={title} steps={steps}
      extras={<>
        {j.error && <p className="error">{j.error}</p>}
        {j.lastError && <StaleNote j={j} />}
        {j.status === 'unresolved' && <UnresolvedNote j={j} />}
        {j.status === 'proven' && <p className="help">Proven on Liquid. Anyone can claim it now; no new proof is needed.</p>}
        <WaitNote j={j} />
      </>}
      actions={<>
        {j.status === 'finalized' && <a className="btn btn-primary" href="#guide">Prepare proof</a>}
        {j.status === 'proven' && <Button variant="primary" onClick={onClaim}>Claim with Humid</Button>}
        <Button variant="ghost" onClick={() => c.removeJourney(j.id)}>Remove from list</Button>
      </>} />
  );
}

function RedeemRow({ j }: { j: RedeemJourney }) {
  const s = useBridge();
  const c = useController();
  const need = s.bridge ? s.bridge.minConf : '?';
  const relayed = ['ready', 'submitted', 'paid'].includes(j.status);
  const eth = `${formatUnits(BigInt(j.units) * UNIT_WEI, 18)} ETH`;
  const payee = j.payee || j.recipient;
  const steps: [StepState, ReactNode][] = [
    ['done', <>Burned on Liquid <ExtLink href={`${DEFAULTS.liquidExplorer}/tx/${j.burnTxid}`}>{`${short(j.burnTxid)}:${j.vout}`}</ExtLink></>],
    [stepState(j.status !== 'burned', j.status === 'burned'), `${Math.max(0, j.confirmations ?? 0)} of ${need} Liquid confirmations`],
    [stepState(relayed, j.status === 'relay'), `${j.needed ? `Liquid headers through block ${j.needed}` : 'Liquid headers relayed'}${j.status === 'relay' && s.bridge ? ` (now at ${s.bridge.lcTip})` : ''}`],
    [stepState(['submitted', 'paid'].includes(j.status), j.status === 'ready'), j.txHash
      ? <>Redemption sent <ExtLink href={`${DEFAULTS.ethExplorer}/tx/${j.txHash}`}>{short(j.txHash)}</ExtLink></> : 'Redeem on Sepolia'],
    [stepState(j.status === 'paid', j.status === 'submitted'), `${eth} paid to ${short(payee)}${payee !== j.recipient ? `, as ${short(j.recipient)} directed` : ''}`],
  ];
  const missing = s.bridge && j.needed ? Math.max(0, j.needed - s.bridge.lcTip) : 0;
  return (
    <JourneyRow j={j} kind="Redeem" title={`${eth} → ${short(j.recipient)}`} steps={steps}
      extras={<>
        {j.error && <p className="error">{j.error}</p>}
        {j.lastError && <StaleNote j={j} waits={j.status === 'ready' ? 'Redeem waits' : j.status === 'relay' ? 'relaying waits' : undefined} />}
        {actionable(j, 'relay') && s.bridge && (
          <p className="help">Relay {missing} missing block{missing === 1 ? '' : 's'} in {Math.ceil(missing / 100)} transaction{missing > 100 ? 's' : ''}.
            Anyone can relay; the sender pays Sepolia gas.</p>
        )}
      </>}
      actions={<>
        {j.status === 'ready' && (
          <Button variant="primary" disabled={!ready(s) || !actionable(j, 'ready') || s.redeemBusy} onClick={() => void c.redeem(j.id)}>Redeem</Button>
        )}
        {j.status === 'relay' && (
          <Button disabled={!ready(s) || s.relaying || !actionable(j, 'relay')} onClick={() => void c.relayFor(j.id)}>
            {s.relaying ? 'Relaying…' : 'Relay missing blocks'}
          </Button>
        )}
        <Button variant="ghost" onClick={() => c.removeJourney(j.id)}>Remove from list</Button>
      </>} />
  );
}

/** Journeys of `kind` (or all), newest first, at most `limit`. */
export function JourneyList({ kind, limit, onClaim }: { kind?: Journey['kind']; limit?: number; onClaim: () => void }) {
  const { journeys } = useBridge();
  const list = journeys.filter((j) => !kind || j.kind === kind).slice(0, limit);
  if (!list.length) return null;
  return (
    <div className="journeys">
      {list.map((j) => (j.kind === 'deposit' ? <DepositRow key={j.id} j={j} onClaim={onClaim} /> : <RedeemRow key={j.id} j={j} />))}
    </div>
  );
}

export function ActivityPanel({ onClaim }: { onClaim: () => void }) {
  const { journeys } = useBridge();
  return (
    <>
      <div className="panel-head">
        <h2 className="tray-title">
          <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path d="M20 11a8 8 0 0 0-14.3-4.9L4 8M4 4v4h4M4 13a8 8 0 0 0 14.3 4.9L20 16M20 20v-4h-4" /></svg>
          Bridge activity
        </h2>
        <p className="hint">Saved in this browser.</p>
      </div>
      {journeys.length
        ? <>
          {/* Column labels for the rows' grid; each row's own text says the same to assistive technology. */}
          <div className="table-head" aria-hidden="true"><span>Type</span><span>Deposit #</span><span>Transfer</span><span>Started</span><span>Status</span></div>
          <JourneyList onClaim={onClaim} />
        </>
        : <p className="empty">No saved deposits or redemptions.</p>}
    </>
  );
}
