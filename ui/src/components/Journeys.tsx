// Saved journeys as rows that open onto their steps. A row nobody has toggled starts open while its journey is
// unfinished; a reader's toggle is kept across polls and across the three lists that show the same journey.
// React keeps each row's DOM element across polls, so keyboard focus stays where the reader left it.
import { DEFAULTS } from '@bridge/core/config.js';
import { UNIT_WEI, formatUnits } from '@bridge/core/lib/bridge.js';
import { type Wait, depositWait, duration } from '@bridge/core/lib/waits.js';
import { type ReactNode, createContext, useCallback, useContext, useMemo, useState } from 'react';
import { useBridge, useController } from '../bridge/context';
import { ready } from '../bridge/derive';
import { short } from '../bridge/format';
import { actionable, label, settled } from '../bridge/journeys';
import { REPO, TAKEOVER } from '../content/links';
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
    <p className="warn"><b>Status may be out of date. </b>
      {m}{/[.!?]$/.test(m) ? '' : '.'} This page keeps checking{waits ? `; ${waits} until a check succeeds` : ''}.</p>
  );
}

/**
 * What a deposit is waiting for, how long that usually takes (lib/waits.js), and how the depositor can finish it.
 * Nothing here promises a time: a claim may need someone to run a prover, which this page cannot.
 */
function WaitNote({ j, wait }: { j: DepositJourney; wait: Wait }) {
  const { stage, elapsed, late } = wait;
  const sent = `Sent ${duration(elapsed)} ago. `;
  if (stage === 'confirm') return <p className="help">{sent}The claim is on Liquid; it usually confirms in the next block, about a minute.</p>;
  if (stage === 'finality' && !late) {
    return <p className="help">{sent}Sepolia usually finalizes a block 13 to 20 minutes after it is mined. There is nothing to do meanwhile; this page moves on when it sees the block final.</p>;
  }
  if (stage === 'finality') {
    return (
      <div className="warn wait">
        <p><b>Not final after {duration(elapsed)}. </b>Sepolia usually takes 13 to 20 minutes. Either Sepolia is not finalizing, which happens on test networks, or
          your wallet's Sepolia RPC is behind. While the deposit remains on Sepolia's current chain, your ETH is locked in the escrow; Liquid waits for finality before a claim.</p>
        <p>Compare Sepolia's latest finalized block on a beacon explorer such as <ExtLink href="https://sepolia.beaconcha.in">sepolia.beaconcha.in</ExtLink> with
          block {j.block?.toLocaleString('en')}. If Sepolia is finalizing, switch your wallet to another Sepolia RPC. This page moves on by itself.</p>
      </div>
    );
  }
  const usual = 'With the operator at work, deposits are usually claimed 30 minutes to 2 hours after they are sent: an SP1 proof (about 7 minutes on '
    + 'the operator\'s machine), then an update and a claim on Liquid, about a minute each. No prover service runs for this instance, and no time is promised.';
  const selfServe = ' You can prove and claim it yourself with the repository tools. This page cannot run the prover; use the guide button below for the local steps.';
  if (!late) return <p className="help">{sent}{usual}{selfServe}</p>;
  const i = j.index === null || j.index === undefined ? null : Number(j.index);
  const order = `Claims may go in any order: once an update has proven ${i === null ? 'your deposit' : `deposit #${i}`}, no other unclaimed `
    + 'deposit holds its claim back.';
  return (
    <div className="warn wait">
      <p><b>No claim after {duration(elapsed)}. </b>That is longer than usual: the operator may be away, or a proof may have failed. Your SepETH remains
        locked in the escrow with no refund path. A claim still depends on the verification and availability assumptions above. What you can do:</p>
      <ul>
        <li>Wait. The next proof anyone makes covers every deposit before it, yours included.</li>
        <li>{order}</li>
        <li>Ask the operator, through the <ExtLink href={REPO}>project's repository</ExtLink>.</li>
        <li>Prove and claim it yourself. The Liquid covenant accepts both from anyone, but this page cannot run them. You need a computer with Docker and the
          SP1 6.8.1 toolchain, a Sepolia beacon node and execution RPC, a little tL-BTC for fees, and a clone of the repository. If a later update has already
          proven your deposit, only the claim is left, and that needs no prover. Use the guide button below.</li>
      </ul>
    </div>
  );
}

/**
 * Why the page cannot tell whether a claim paid this deposit. It shows a deposit claimed only once a claim's own
 * output commits its index, never by order or by an output's script and amount, which deposits can share.
 */
function UnresolvedNote({ j }: { j: DepositJourney }) {
  const why = j.claimWhy ? j.claimWhy.charAt(0).toUpperCase() + j.claimWhy.slice(1) : 'A claim on Liquid could not be attributed to a deposit';
  return (
    <div className="warn">
      <p><b>Claimed or not, this page cannot tell yet. </b>{why}. A claim pays only the script and amount its deposit named, so check the receiving
        wallet{j.address ? <> or <ExtLink href={`${DEFAULTS.liquidExplorer}/address/${j.address}`}>its address on a Liquid explorer</ExtLink></> : ''}. This page
        keeps checking, and shows the deposit claimed once a claim is shown to have paid it.</p>
    </div>
  );
}

function DepositRow({ j, onClaim }: { j: DepositJourney; onClaim: () => void }) {
  const s = useBridge();
  const c = useController();
  const order = ['submitted', 'mined', 'finalized', 'claiming', 'claimed'];
  const at = j.status === 'unresolved' ? 3 : order.indexOf(j.status);
  const failed = j.status === 'failed';
  const eth = DEFAULTS.ethExplorer;
  const liq = DEFAULTS.liquidExplorer;
  const steps: [StepState, ReactNode][] = [
    [stepState(at >= 1, at === 0, failed), <>Sent on Sepolia <ExtLink href={`${eth}/tx/${j.txHash}`}>{short(j.txHash)}</ExtLink></>],
    [stepState(at >= 2, at === 1), `Mined${j.block ? ` in block ${j.block.toLocaleString('en')}` : ''}${j.index != null ? `, deposit #${j.index}` : ''}; waiting for Ethereum finality`],
    [stepState(at >= 3, at === 2), 'Final on Ethereum; waiting for someone, in practice the instance\'s operator, to prove it to Liquid and claim it'],
    [stepState(at >= 4, at === 3), j.claimTxid
      ? <>Claimed on Liquid <ExtLink href={`${liq}/tx/${j.claimTxid}`}>{short(j.claimTxid)}</ExtLink>{j.status === 'claiming' ? ' (confirming)' : ''}</>
      : j.status === 'unresolved' ? 'Claim on Liquid: not known whether a claim paid this deposit' : 'Claim on Liquid'],
  ];
  const wait = depositWait(j, s.now);
  const title = `${formatUnits(BigInt(j.wei), 18)} ETH → ${j.address ? short(j.address, 8) : `script ${short(j.script, 8)}`}`;
  return (
    <JourneyRow j={j} kind="Deposit" title={title} steps={steps}
      extras={<>
        {j.error && <p className="error">{j.error}</p>}
        {j.lastError && <StaleNote j={j} />}
        {j.status === 'unresolved' && <UnresolvedNote j={j} />}
        {wait && <WaitNote j={j} wait={wait} />}
      </>}
      actions={<>
        {j.status === 'finalized' && <ExtLink className="btn btn-primary" href={TAKEOVER}>Prove &amp; claim: guide ↗</ExtLink>}
        {/* Once an update has proven the deposit, its claim can go through Humid with no fee key (the claim panel). */}
        {j.status === 'finalized' && <Button onClick={onClaim}>Have a proven claim? Send with Humid</Button>}
        <Button variant="ghost" onClick={() => c.removeJourney(j.id)}>Remove from this list</Button>
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
    [stepState(relayed, j.status === 'relay'), `${j.needed ? `Liquid relayed to the bridge through height ${j.needed}` : 'Liquid relayed to the bridge'}${j.status === 'relay' && s.bridge ? ` (now at ${s.bridge.lcTip})` : ''}`],
    [stepState(['submitted', 'paid'].includes(j.status), j.status === 'ready'), j.txHash
      ? <>Redemption sent <ExtLink href={`${DEFAULTS.ethExplorer}/tx/${j.txHash}`}>{short(j.txHash)}</ExtLink></> : 'Prove and redeem on Ethereum'],
    [stepState(j.status === 'paid', j.status === 'submitted'), `${eth} paid to ${short(payee)}${payee !== j.recipient ? `, as ${short(j.recipient)} directed` : ''}`],
  ];
  const missing = s.bridge && j.needed ? Math.max(0, j.needed - s.bridge.lcTip) : 0;
  return (
    <JourneyRow j={j} kind="Redeem" title={`${eth} → ${short(j.recipient)}`} steps={steps}
      extras={<>
        {j.error && <p className="error">{j.error}</p>}
        {j.lastError && <StaleNote j={j} waits={j.status === 'ready' ? 'Redeem waits' : j.status === 'relay' ? 'relaying waits' : undefined} />}
        {actionable(j, 'relay') && s.bridge && (
          <p className="help">Relayers keep the bridge's view of Liquid current; nobody has relayed the {missing} block{missing === 1 ? '' : 's'} this burn needs yet.
            Anyone can, in about {Math.ceil(missing / 100)} transaction{missing > 100 ? 's' : ''} of at most 100 blocks each, checked against Liquid's block
            signatures; the wallet estimates each one's gas.</p>
        )}
      </>}
      actions={<>
        {j.status === 'ready' && (
          <Button variant="primary" disabled={!ready(s) || !actionable(j, 'ready') || s.redeemBusy} onClick={() => void c.redeem(j.id)}>Redeem</Button>
        )}
        {j.status === 'relay' && (
          <Button disabled={!ready(s) || s.relaying || !actionable(j, 'relay')} onClick={() => void c.relayFor(j.id)}>
            {s.relaying ? 'Relaying…' : 'Relay the missing blocks'}
          </Button>
        )}
        <Button variant="ghost" onClick={() => c.removeJourney(j.id)}>Remove from this list</Button>
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
          Your bridge activity
        </h2>
        <p className="hint">Saved in this browser; tracking resumes after a reload.</p>
      </div>
      {journeys.length
        ? <>
          {/* Column labels for the rows' grid; each row's own text says the same to assistive technology. */}
          <div className="table-head" aria-hidden="true"><span>Type</span><span>Transfer</span><span>Started</span><span>Status</span></div>
          <JourneyList onClaim={onClaim} />
        </>
        : <p className="empty">Nothing yet. Deposits and redemptions you start here are saved in this browser.</p>}
    </>
  );
}
