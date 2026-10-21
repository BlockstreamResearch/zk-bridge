// Sending an update or a claim built on the reader's computer, with Humid paying only the fee. The proof's (or the
// reissuance's) input is already final, so neither Humid nor this page can change it.
import { DEFAULTS } from '@bridge/core/config.js';
import { formatUnits } from '@bridge/core/lib/bridge.js';
import { bytesToHex } from '@bridge/core/lib/bytes.js';
import type { ClaimPlan } from '@bridge/core/lib/claim.js';
import { displayHex } from '@bridge/core/lib/elements.js';
import type { UpdatePlan } from '@bridge/core/lib/update.js';
import { type ReactNode, type RefObject, useId, useRef } from 'react';
import { claimApproval, updateApproval } from '../bridge/approval';
import { useBridge, useController } from '../bridge/context';
import { claimedDeposits } from '../bridge/journeys';
import { short } from '../bridge/format';
import type { LiquidSend, LiquidSent } from '../bridge/types';
import { JUST_STEPS } from '../content/links';
import { Button, ExtLink, Hint, Linkified } from './primitives';

function Facts({ caption, rows }: { caption: string; rows: [string, string][] }) {
  return (
    <table className="facts">
      <caption className="sr-only">{caption}</caption>
      <tbody>{rows.map(([k, v]) => <tr key={k}><th scope="row">{k}</th><td>{v}</td></tr>)}</tbody>
    </table>
  );
}

// What the hint says once Humid has answered, by where the Liquid API has the transaction.
const SENT_HINTS: Record<LiquidSent['where'], string> = {
  confirmed: '',
  mempool: 'Not confirmed yet: check again in a minute or two.',
  unknown: 'Not on Liquid, as far as its API shows: check again in a minute.',
};

/**
 * What the error line says once Humid has answered: why the update or claim is not to be counted as sent while the
 * Liquid API does not show it, or that Humid's uncertain answer was overtaken by Liquid. Only the Liquid API's answer
 * counts as sent; Humid's word alone shows nothing on Liquid.
 */
export function sentReport(what: 'update' | 'claim', s: LiquidSent): string {
  if (s.where !== 'unknown') return s.said ? `Humid did not report sending this ${what}, but the Liquid API has it, so it was sent: see below.` : '';
  const explorer = ` Explorer: ${DEFAULTS.liquidExplorer}/tx/${s.txid}`;
  if (s.said) return `${s.said} This ${what}, ${short(s.txid)}: ${s.why}, as of the last check.${explorer}`;
  return `Humid reports sending ${what} ${short(s.txid)}, but ${s.why}, as of the last check. Do not count it as ${what === 'claim' ? 'claimed' : 'sent'} until it shows. `
    + `If it never does, load ${what}.hex again to send it: the page checks Liquid first.${explorer}`;
}

function SendPanel<P extends { txid: string }>({ kind, title, icon, intro, needs, flow, fileLabel, fileHelp, send, facts, missing, approval, done, panelRef, fileRef, children }: {
  kind: 'liquidUpdate' | 'liquidClaim';
  title: string;
  icon: ReactNode;
  intro: ReactNode;
  needs: ReactNode;
  flow: ReactNode;
  fileLabel: ReactNode;
  fileHelp: string;
  send: LiquidSend<P>;
  facts: (plan: P) => [string, string][];
  /** What the loaded file still needs before Humid may be asked, or '' once it needs nothing. */
  missing?: (plan: P) => string;
  approval: (plan: P) => string;
  /** What to say once the Liquid API has it (`sent.where` is 'mempool' or 'confirmed'). */
  done: (plan: P, sent: LiquidSent) => ReactNode;
  panelRef?: RefObject<HTMLDetailsElement | null>;
  fileRef?: RefObject<HTMLInputElement | null>;
  /** Shown below the facts: what the loaded file still needs. */
  children?: ReactNode;
}) {
  const s = useBridge();
  const c = useController();
  const id = useId();
  const { busy, note, plan, sent, fileError, error } = send;
  const what = kind === 'liquidUpdate' ? 'update' : 'claim';
  const confirmed = sent?.where === 'confirmed';
  const checked = sent ? ` Last checked ${new Date(sent.checkedAt).toLocaleTimeString()}.` : '';
  // Once Humid has answered, nothing is missing: the button only asks Liquid again.
  const needed = plan && !sent ? missing?.(plan) ?? '' : '';
  const hint = note || (!s.instance ? 'No bridge instance is deployed yet.'
    : sent ? `${SENT_HINTS[sent.where]}${confirmed ? '' : checked}`.trim()
      : needed || (plan ? 'Ready. Humid may ask twice; before signing, compare its approval with the line below.' : `Load ${what}.hex first.`));
  // Once Humid has answered, the button only asks Liquid again: Humid is never asked to send the same file twice.
  const label = busy && plan ? 'Working…' : sent && !confirmed ? 'Check on Liquid again' : 'Sign and send with Humid';
  const report = [sent ? sentReport(what, sent) : '', error].filter(Boolean).join(' ');
  return (
    <details className="tray disclosure" ref={panelRef} id={kind === 'liquidClaim' ? 'claim' : 'update'}>
      <summary>{icon}{title}</summary>
      <div className="disclosure-body">
        {intro}
        <p className="help">Before you start, you need:</p>
        <ul className="help">{needs}</ul>
        <details className="aside-form">
          <summary>What the page hands Humid to sign</summary>
          <ol className="help flow">{flow}</ol>
        </details>
        <div className="field">
          <label htmlFor={`${id}-file`}>{fileLabel}</label>
          <input id={`${id}-file`} ref={fileRef} type="file" accept=".hex,.txt,text/plain" disabled={busy || !s.instance}
            aria-describedby={`${id}-help ${id}-error`} aria-invalid={fileError ? true : undefined}
            onChange={(e) => void c.loadFile(kind, e.target.files?.[0] ?? null)} />
          <p className="help" id={`${id}-help`}>{fileHelp}</p>
          <p className="error" id={`${id}-error`} role="alert">{fileError}</p>
        </div>
        <div aria-live="polite">{plan && <Facts caption={title} rows={facts(plan)} />}</div>
        {children}
        <div className="actions">
          <Button variant="primary" disabled={busy || !plan || confirmed || !!needed} onClick={() => void c.sendFile(kind)}>{label}</Button>
          <Hint live>{hint}</Hint>
        </div>
        {plan && !sent && <p className="warn approval">{approval(plan)}</p>}
        <p className="error" role="alert">{report && <Linkified text={report} />}</p>
        {plan && sent && sent.where !== 'unknown' && <p className="help done">{done(plan, sent)}</p>}
      </div>
    </details>
  );
}

const UploadIcon = () => (
  <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path d="M12 15V4M7 9l5-5 5 5M5 15v4a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-4" /></svg>
);
const ClaimIcon = () => (
  <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path d="M12 4v11M7 10l5 5 5-5M5 15v4a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-4" /></svg>
);

const inBlock = (sent: LiquidSent) => (sent.where === 'confirmed' && sent.height !== null ? ` in block ${sent.height.toLocaleString('en')}` : '');

const sendTx = (txid: string) => <ExtLink href={`${DEFAULTS.liquidExplorer}/tx/${txid}`}>{txid.slice(0, 6)}…{txid.slice(-6)}</ExtLink>;

/** Where the store the loaded update moves to comes from (lib/update.js prepareUpdate, withStore). */
function storeFact(plan: UpdatePlan): string {
  const { store, listed } = plan;
  if (store?.where === 'site') return `published on this site, ${store.path}`;
  if (store?.where === 'file') return `from your file ${store.name}; its head and roots match the update's lc. The next prover checks its contents`;
  return listed ? `none yet: this page's record lists ${listed}, but only the published site's record counts. Load the file below`
    : 'none yet: this site does not publish it. Load the file below';
}

const STORE_MISSING = 'Load the store this update moves to first: this site does not publish it, and the next prover needs it.';

/**
 * The sender's own store, for an update whose store this site does not publish (controller.loadStore). The page
 * checks its head and roots against the lc in the update's witness. The next prover checks its contents.
 */
function StoreField({ plan }: { plan: UpdatePlan }) {
  const s = useBridge();
  const c = useController();
  const id = useId();
  const { busy, sent, storeError } = s.liquidUpdate;
  if (plan.store?.where === 'site') return null;
  return (
    <div className="field">
      <label htmlFor={`${id}-store`}>The store this update moves to, <code className="mono">proof.store.json</code></label>
      <input id={`${id}-store`} type="file" accept=".json,application/json" disabled={busy || !!sent}
        aria-describedby={`${id}-store-help ${id}-store-error`} aria-invalid={storeError ? true : undefined}
        onChange={(e) => void c.loadStore(e.target.files?.[0] ?? null)} />
      <p className="help" id={`${id}-store-help`}>
        <code className="mono">just prove</code> writes it beside the proof, in <code className="mono">target/takeover/</code>. It stays in this browser.
        Keep it: the next prover starts from it, so publish it, here by pull request or anywhere public.
      </p>
      <p className="error" id={`${id}-store-error`} role="alert">{storeError}</p>
    </div>
  );
}

export function UpdatePanel() {
  const s = useBridge();
  const plan = s.liquidUpdate.plan;
  return (
    <SendPanel<UpdatePlan> kind="liquidUpdate" title="Send a proven update with Humid" icon={<UploadIcon />} send={s.liquidUpdate}
      intro={<p className="help">Finalized deposits reach Liquid in an update, a transaction carrying an SP1 proof that the covenant checks. This page runs no
        prover, but it can send an update you built on your computer, with Humid paying the fee. Humid signs only that fee coin. The proof's input is
        already final, so neither Humid nor this page can change it. This route was built from Humid 1.1.3's released code; no update has been sent
        through it yet.</p>}
      needs={<>
        <li>an open fee coin in Humid: send 0.00012 tL-BTC (12,000 sats, about what an update pays) from Humid to its own address under Receive, then
          Unconfidential, and wait for it to confirm. The update spends the whole coin as its fee, and this page sends none above 0.0005 tL-BTC;</li>
        <li>the update built against that coin, unsigned: after proving locally, run <code className="mono">just update-unsigned &lt;Humid fee txid&gt; &lt;output number&gt;</code>.
          It writes <code className="mono">target/takeover/update.hex</code> without signing or sending it. The <ExtLink href={JUST_STEPS}>short operator
          commands</ExtLink> cover the proof, update and store;</li>
        <li>the light-client store the update moves to. If this site publishes it, as <code className="mono">lc_stores/&lt;head&gt;.json</code> with
          the <code className="mono">lc_preimages.json</code> entry naming the update's transaction id, the panel says so once you load the update.
          Otherwise load your own copy, <code className="mono">proof.store.json</code>, after the update. Only the project's maintainers can publish
          here; anyone can open a pull request adding these two files for review.</li>
      </>}
      flow={<>
        <li><b>Input 0:</b> the live state output, spent with the update leaf's witness, which carries the proof. It is final: Humid lists it as not its own
          and does not sign it.</li>
        <li><b>Input 1:</b> your open fee coin, the only input Humid signs.</li>
        <li><b>Output 0:</b> the successor state, blinded as the update has it, so Humid shows its address and script but not its amount or asset.
          <b> Output 1:</b> the fee, all of input 1.</li>
        <li><b>Humid</b> shows these, signs and broadcasts. Signatures do not change a transaction's id, so the page checks that Humid sent exactly the update
          the record names.</li>
      </>}
      fileLabel={<>The unsigned update, <code className="mono">update.hex</code></>}
      fileHelp="The file stays in this browser. Before Humid is asked anything, the page checks it against this site's instance record and the Liquid API: this instance's update leaf, the store it moves to, and coins that are confirmed and unspent."
      facts={(plan) => [
        ['Transaction', plan.txid],
        ['Light-client head', `slot ${plan.successor.head.toLocaleString('en')}`],
        ['Store', storeFact(plan)],
        ['Spends', `state output ${plan.update.state.txid}:${plan.update.state.vout}, and your open coin ${plan.update.fee.txid}:${plan.update.fee.vout}`],
        ['Pays', `the successor state, to ${plan.successorAddress}, and a fee of ${plan.update.fee.sats} sats (${formatUnits(plan.update.fee.sats, 8)} tL-BTC): the whole coin`],
      ]}
      missing={(plan) => (plan.store ? '' : STORE_MISSING)}
      approval={updateApproval}
      done={(_plan, sent) => (sent.where === 'confirmed'
        ? <>Update {sendTx(sent.txid)} is confirmed on Liquid{inBlock(sent)}, as the Liquid API reports. The deposits it proves can now be claimed, in any order
          (OPERATOR.md, step 5).</>
        : <>The Liquid API has update {sendTx(sent.txid)}, not confirmed yet; it should confirm within a minute or two. Then the deposits it proves can be
          claimed, in any order (OPERATOR.md, step 5).</>)}>
      {plan && <StoreField key={plan.txid} plan={plan} />}
    </SendPanel>
  );
}

export function ClaimPanel({ panelRef, fileRef }: { panelRef: RefObject<HTMLDetailsElement | null>; fileRef: RefObject<HTMLInputElement | null> }) {
  const s = useBridge();
  const escrow = s.instance?.escrow ?? '';
  const to = (c: ClaimPlan['claim']) => c.mint.address ?? `script ${bytesToHex(c.mint.script)}`;
  return (
    <SendPanel<ClaimPlan> kind="liquidClaim" title="Claim a proven deposit with Humid" icon={<ClaimIcon />} send={s.liquidClaim} panelRef={panelRef} fileRef={fileRef}
      intro={<p className="help">Once an update has proven a deposit, a claim pays it on Liquid: it mints the deposit's units of the bridge asset, openly, to the
        script the deposit named. A claim may pay any proven deposit not yet claimed, and it needs no prover. This page cannot build a claim, but it can send one you built on your
        computer, with Humid paying the fee. Humid signs only that fee coin. The claim's state input is already final, so neither Humid nor this page can
        change it, and the covenant pays only the deposit's script, whoever sends it. This route was built from Humid 1.1.3's released code; no claim has been
        sent through it yet.</p>}
      needs={<>
        <li>the deposit proven and not yet claimed: <code className="mono">just status</code> recovers the live state and says which deposits are;</li>
        <li>an open fee coin in Humid: for example, send 0.00002 tL-BTC (2,000 sats) from Humid to its own address under Receive, then Unconfidential, and wait
          for it to confirm. A new claim may need a different fee. It spends the whole coin as its fee, and this page sends none above 0.0005 tL-BTC;</li>
        <li>the claim built against that coin, unsigned: run <code className="mono">just claim-unsigned &lt;Humid fee txid&gt; &lt;output number&gt; &lt;deposit number&gt;</code>.
          Use the deposit number shown in Activity or by <code className="mono">just status</code>, for example <code className="mono">3</code> for deposit #3. It reads
          the deposits from a Sepolia RPC, writes <code className="mono">claim.hex</code> without signing or sending it, and prints where it wrote it. The
          {' '}<ExtLink href={JUST_STEPS}>short operator commands</ExtLink> cover it.</li>
      </>}
      flow={<>
        <li><b>Input 0:</b> the live state output, spent with the claim leaf's witness, reissuing the deposit's units. It is final: Humid lists it as not its own
          and does not sign it.</li>
        <li><b>Input 1:</b> your open fee coin, the only input Humid signs.</li>
        <li><b>Output 0:</b> the successor state, blinded as the claim has it. <b>Output 1:</b> the deposit's units, openly, to the script the deposit named.
          <b> Output 2:</b> the fee, all of input 1. No output is blinded by Humid and none pays change.</li>
        <li><b>Humid</b> shows these, signs and broadcasts. Signatures do not change a transaction's id, so the page checks that Humid sent exactly the claim you
          loaded.</li>
      </>}
      fileLabel={<>The unsigned claim, <code className="mono">claim.hex</code></>}
      fileHelp="The file stays in this browser. Before Humid is asked anything, the page checks it against this site's instance record and the Liquid API: this instance's claim leaf, bridge asset and token, the deposit's units paid openly, a fee coin that pays only the fee, and coins that are confirmed and unspent."
      facts={(plan) => {
        const c = plan.claim;
        const mine = claimedDeposits(s.journeys, c, escrow);
        const deposit = mine.length === 1 ? `#${mine[0].index ?? '?'}, sent from this browser on ${new Date(mine[0].created).toLocaleString()}`
          : mine.length ? `one of ${mine.map((j) => `#${j.index ?? '?'}`).join(', ')}, sent from this browser to this script; which one, Activity shows once the claim is on Liquid`
            : 'not one this browser sent; the covenant pays the deposit the claim names, to the script it named';
        return [
          ['Transaction', plan.txid],
          ['Bridge', `this page's bridge, escrow ${escrow}`],
          ['Asset', `${displayHex(c.mint.asset)}, the bridge asset`],
          ['Pays', `${formatUnits(c.mint.units, 8)} of the bridge asset (${c.mint.units} units), openly, to ${to(c)}`],
          ['Deposit', deposit],
          ['Spends', `state output ${c.state.txid}:${c.state.vout}, and your open coin ${c.fee.txid}:${c.fee.vout}`],
          ['Fee', `${c.fee.sats} sats (${formatUnits(c.fee.sats, 8)} tL-BTC): the whole coin`],
        ];
      }}
      approval={claimApproval}
      done={(plan, sent) => {
        const units = `${formatUnits(plan.claim.mint.units, 8)} of the bridge asset`;
        const spend = 'Humid\'s balance leaves it out, but Redeem step 2 can send it with Humid.';
        return sent.where === 'confirmed'
          ? <>Claim {sendTx(sent.txid)} is confirmed on Liquid{inBlock(sent)}, as the Liquid API reports. Its {units} is open at {to(plan.claim)}: {spend} To
            claim another proven deposit, build its claim against the new state and send it the same way.</>
          : <>The Liquid API has claim {sendTx(sent.txid)}, not confirmed yet; it should confirm within a minute or two. Its {units} is then open at
            {' '}{to(plan.claim)}: {spend} To claim another proven deposit, build its claim once this one confirms and send it the same way.</>;
      }} />
  );
}

/** Opens the claim panel from a deposit's row, brings it into view and focuses its file input. */
export function useClaimPanel() {
  const panelRef = useRef<HTMLDetailsElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const open = () => {
    if (panelRef.current) {
      panelRef.current.open = true;
      panelRef.current.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
    }
    fileRef.current?.focus();
  };
  return { panelRef, fileRef, open };
}
