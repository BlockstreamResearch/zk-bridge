// Browser-built covenant transactions and optional imports share the same validation and wallet path.
import { DEFAULTS } from '@bridge/core/config.js';
import { formatUnits } from '@bridge/core/lib/bridge.js';
import { bytesToHex } from '@bridge/core/lib/bytes.js';
import type { ClaimPlan } from '@bridge/core/lib/claim.js';
import type { UpdatePlan } from '@bridge/core/lib/update.js';
import { type ReactNode, type RefObject, useId, useRef, useState } from 'react';
import { claimApproval, updateApproval } from '../bridge/approval';
import { useBridge, useController } from '../bridge/context';
import { short } from '../bridge/format';
import type { LiquidSend, LiquidSent } from '../bridge/types';
import { REPO } from '../content/links';
import { FeePicker, type FeeCoin } from './FeePicker';
import { Button, CopyLine, ExtLink, Hint, Linkified } from './primitives';

function Facts({ rows }: { rows: [string, string][] }) {
  return <table className="facts"><caption className="sr-only">Transaction details</caption>
    <tbody>{rows.map(([key, value]) => <tr key={key}><th scope="row">{key}</th><td>{value}</td></tr>)}</tbody>
  </table>;
}

/** Only a matching transaction read back from Liquid counts as sent. */
export function sentReport(what: 'update' | 'claim', sent: LiquidSent): string {
  if (sent.where !== 'unknown') return sent.said ? `Liquid has this ${what}, although Humid did not report sending it.` : '';
  return `${sent.said || 'Humid reports sending it.'} The Liquid API has not verified ${what} ${short(sent.txid)}: ${sent.why}. `
    + `Check again before retrying. Explorer: ${DEFAULTS.liquidExplorer}/tx/${sent.txid}`;
}

function downloadStore(text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'proof.store.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

interface ClaimDraft {
  deposit: string;
  setDeposit: (value: string) => void;
}

function BuildFields({ kind, busy, building, locked, inputRef, claimDraft }: {
  kind: 'liquidUpdate' | 'liquidClaim'; busy: boolean; building: boolean; locked: boolean; inputRef?: RefObject<HTMLInputElement | null>;
  claimDraft?: ClaimDraft;
}) {
  const c = useController();
  const id = useId();
  const [bundle, setBundle] = useState<File | null>(null);
  const [localDeposit, setLocalDeposit] = useState('');
  const deposit = claimDraft?.deposit ?? localDeposit;
  const setDeposit = claimDraft?.setDeposit ?? setLocalDeposit;
  const [coin, setCoin] = useState<FeeCoin | null>(null);
  const update = kind === 'liquidUpdate';
  const validDeposit = /^\d+$/.test(deposit) && Number.isSafeInteger(Number(deposit));
  const missing = [update ? !bundle && 'load a proof bundle' : !validDeposit && 'enter a deposit number',
    !coin && 'find and select a confirmed fee coin'].filter(Boolean).join(' and ');
  return <>
    <div className="field">
      <label htmlFor={`${id}-input`}>{update ? 'Proof bundle · proof.browser.json' : 'Deposit number'}</label>
      {update
        ? <input id={`${id}-input`} type="file" accept=".json,application/json" disabled={busy || locked}
          onChange={(event) => { c.resetSend(kind); setBundle(event.target.files?.[0] ?? null); }} />
        : <input id={`${id}-input`} ref={inputRef} inputMode="numeric" value={deposit} placeholder="e.g. 4" disabled={busy || locked}
          onChange={(event) => { c.resetSend(kind); setDeposit(event.target.value); }} />}
      <p className="help">{update ? <>Generate it with <code>just inputs execute prove</code>. <a href="#guide">See the guide.</a></>
        : 'Use the number shown in Activity. Any proven, unclaimed deposit can be claimed.'}</p>
    </div>
    <FeePicker kind={update ? 'update' : 'claim'} disabled={busy || locked} onCoin={(value) => { c.resetSend(kind); setCoin(value); }} />
    <div className="actions">
      <Button aria-describedby={`${id}-build-help`} disabled={busy || locked || !!missing} onClick={() => {
        if (coin) void c.buildFromBrowser(kind, { feeTxid: coin.txid, feeVout: coin.vout,
          ...(update ? { bundle } : { depositIndex: Number(deposit) }) });
      }}>Build {update ? 'update' : 'claim'}</Button>
      {building && <Button onClick={() => c.resetSend(kind)}>Cancel build</Button>}
    </div>
    <p className="help" id={`${id}-build-help`}>{!locked && !busy && missing ? `To build, ${missing}.` : ''}</p>
  </>;
}

function SendPanel<P extends { txid: string }>({ kind, title, intro, send, facts, approval, done, panelRef, fileRef, claimDraft, children }: {
  kind: 'liquidUpdate' | 'liquidClaim'; title: string; intro: ReactNode; send: LiquidSend<P>;
  facts: (plan: P) => [string, string][]; approval: (plan: P) => string;
  done: (plan: P, sent: LiquidSent) => ReactNode;
  panelRef?: RefObject<HTMLDetailsElement | null>; fileRef?: RefObject<HTMLInputElement | null>; children?: ReactNode;
  claimDraft?: ClaimDraft;
}) {
  const s = useBridge();
  const c = useController();
  const id = useId();
  const [formVersion, setFormVersion] = useState(0);
  const { busy, note, plan, sent, fileError, error } = send;
  const what = kind === 'liquidUpdate' ? 'update' : 'claim';
  const missing = kind === 'liquidUpdate' && plan && !(plan as unknown as UpdatePlan).store;
  const confirmed = sent?.where === 'confirmed';
  const hint = note || (!s.instance ? 'No deployment is configured.'
    : sent ? confirmed ? 'Confirmed on Liquid.' : 'Check Liquid before sending again.'
      : missing ? 'Load the successor store below.' : plan ? 'Review the details, then sign with Humid.' : 'Build a transaction to continue.');
  return <details className="tray disclosure" ref={panelRef} id={what}>
    <summary>{title}</summary>
    <div className="disclosure-body">
      <p className="help">{intro}</p>
      <BuildFields key={formVersion} kind={kind} busy={busy} building={!!send.building} locked={!s.instance || !!sent}
        inputRef={fileRef} claimDraft={claimDraft} />
      <details className="aside-form">
        <summary>Import a transaction built elsewhere</summary>
        <div className="field">
          <label htmlFor={`${id}-file`}>Unsigned {what} · {what}.hex</label>
          <input key={formVersion} id={`${id}-file`} type="file" accept=".hex,.txt,text/plain" disabled={busy || !s.instance || !!sent}
            aria-describedby={`${id}-error`} aria-invalid={fileError ? true : undefined}
            onChange={(event) => void c.loadFile(kind, event.target.files?.[0] ?? null)} />
          <p className="help">Checked against this deployment and the current Liquid state before signing.</p>
          <p className="error" id={`${id}-error`} role="alert">{fileError}</p>
        </div>
      </details>
      <div aria-live="polite">{plan && <Facts rows={facts(plan)} />}</div>
      {children}
      <div className="actions">
        <Button variant="primary" disabled={busy || !plan || confirmed || (!sent && !!missing)} onClick={() => void c.sendFile(kind)}>
          {busy ? 'Working…' : sent && !confirmed ? 'Check on Liquid again' : 'Sign and send with Humid'}
        </Button>
        {confirmed && <Button onClick={() => {
          c.resetSend(kind);
          claimDraft?.setDeposit('');
          setFormVersion((version) => version + 1);
        }}>Start another {what}</Button>}
        <Hint live>{hint}</Hint>
      </div>
      {plan && !sent && <p className="warn approval">{approval(plan)}</p>}
      <p className="error" role="alert"><Linkified text={[sent ? sentReport(what, sent) : '', error].filter(Boolean).join(' ')} /></p>
      {plan && sent && sent.where !== 'unknown' && <p className="help done">{done(plan, sent)}</p>}
    </div>
  </details>;
}

const sendTx = (txid: string) => <ExtLink href={`${DEFAULTS.liquidExplorer}/tx/${txid}`}>{short(txid)}</ExtLink>;

function StoreField({ plan }: { plan: UpdatePlan }) {
  const s = useBridge();
  const c = useController();
  const id = useId();
  const { busy, sent, storeError, storeText } = s.liquidUpdate;
  return <div className="field">
    {plan.store ? <p className="help">{plan.store.where === 'site' ? 'Successor store: published on this site.' : 'Successor store: loaded locally; not published by this page.'}</p>
      : null}
    {plan.store?.where !== 'site' && <details className="aside-form" open={!plan.store}>
      <summary>{plan.store ? 'Replace successor store' : 'Load successor store'}</summary>
      <label htmlFor={`${id}-store`}>Successor store · proof.store.json</label>
      <input id={`${id}-store`} type="file" accept=".json,application/json" disabled={busy || !!sent}
        onChange={(event) => void c.loadStore(event.target.files?.[0] ?? null)} />
    </details>}
    {storeText && <Button onClick={() => downloadStore(storeText)}>Download successor store</Button>}
    {plan.store?.where === 'file' && s.instance && <details className="aside-form">
      <summary>Optional: share store</summary>
      <p className="help">To publish your locally generated store after this update confirms, follow the
        {' '}<a href="#guide">guide's optional publication commands</a>.</p>
      <p className="help">Open a pull request in the <ExtLink href={REPO}>repository</ExtLink> with the downloaded store at this path:</p>
      <CopyLine label="Store publication path" value={`${s.instance.record}${plan.store.entry.store}`} />
      <p className="help">Add this entry to the <code className="mono">preimages</code> list in
        {' '}<code className="mono">{s.instance.record}lc_preimages.json</code>, preserving existing entries. Maintainers review and publish both files.</p>
      <CopyLine label="Store publication entry" value={JSON.stringify(plan.store.entry)} />
    </details>}
    <p className="help">Keep and share this file so anyone can make the next proof. Without it, they must recover the store from retained beacon data;
      recovery may fail if that data is unavailable. Loading it here does not publish it. <a href="#guide">Sharing options</a>.</p>
    <p className="error" role="alert">{storeError}</p>
  </div>;
}

export function UpdatePanel() {
  const s = useBridge();
  return <SendPanel<UpdatePlan> kind="liquidUpdate" title="Send a proof update" send={s.liquidUpdate}
    intro="Load your proof bundle. This page builds and verifies the Liquid update; Humid signs its fee input."
    facts={(plan) => [
      ['Transaction', plan.txid], ['Proven head', `slot ${plan.successor.head.toLocaleString('en')}`],
      ['Successor address', plan.successorAddress], ['Fee', `${plan.update.fee.sats} tL-BTC sats · entire coin`],
    ]} approval={updateApproval}
    done={(_plan, sent) => <>Update {sendTx(sent.txid)} {sent.where === 'confirmed' ? 'confirmed. Its proven deposits can now be claimed.' : 'is awaiting confirmation.'}</>}>
    {s.liquidUpdate.plan && <StoreField plan={s.liquidUpdate.plan} />}
  </SendPanel>;
}

export function ClaimPanel({ panelRef, fileRef, claimDraft }: {
  panelRef: RefObject<HTMLDetailsElement | null>; fileRef: RefObject<HTMLInputElement | null>; claimDraft?: ClaimDraft;
}) {
  const s = useBridge();
  const to = (plan: ClaimPlan) => plan.claim.mint.address ?? `script ${bytesToHex(plan.claim.mint.script)}`;
  return <SendPanel<ClaimPlan> kind="liquidClaim" title="Claim a proven deposit" send={s.liquidClaim} panelRef={panelRef} fileRef={fileRef} claimDraft={claimDraft}
    intro="Choose a proven deposit. This page reads Sepolia through your connected wallet or custom RPC and builds the claim; Humid pays the fee. The asset goes to the deposit's original recipient."
    facts={(plan) => [
      ['Transaction', plan.txid], ['Recipient', to(plan)],
      ['Amount', `${formatUnits(plan.claim.mint.units, 8)} bridge asset · ${plan.claim.mint.units} units`],
      ['Fee', `${plan.claim.fee.sats} tL-BTC sats · entire coin`],
    ]} approval={claimApproval}
    done={(plan, sent) => <>Claim {sendTx(sent.txid)} {sent.where === 'confirmed' ? 'confirmed.' : 'is awaiting confirmation.'}
      {' '}Recipient: {to(plan)}. Use Redeem to send the asset back to Sepolia.</>} />;
}

/** Open the claim builder and focus the deposit number. */
export function useClaimPanel() {
  const c = useController();
  const { liquidClaim } = useBridge();
  const panelRef = useRef<HTMLDetailsElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [deposit, setDeposit] = useState('');
  const open = (index?: string) => {
    if (typeof index === 'string' && !liquidClaim.busy && !liquidClaim.sent) {
      c.resetSend('liquidClaim');
      setDeposit(index);
    }
    if (panelRef.current) {
      panelRef.current.open = true;
      panelRef.current.scrollIntoView?.({ block: 'start' });
    }
    fileRef.current?.focus({ preventScroll: true });
  };
  return { panelRef, fileRef, open, claimDraft: { deposit, setDeposit } };
}
