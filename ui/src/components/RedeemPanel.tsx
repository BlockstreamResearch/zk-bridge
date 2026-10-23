import { formatUnits } from '@bridge/core/lib/bridge.js';
import { bytesToHex } from '@bridge/core/lib/bytes.js';
import { useState } from 'react';
import { HUMID_FEE, burnApproval } from '../bridge/approval';
import { useBridge, useController } from '../bridge/context';
import { notBurnable, notReady, ready, target } from '../bridge/derive';
import { readHumid, readPayTo, readRedeem } from '../bridge/forms';
import { short } from '../bridge/format';
import { actionable } from '../bridge/journeys';
import { JourneyList } from './Journeys';
import { HumidAddressButton } from './HumidAddressButton';
import { Button, CopyLine, Field, Hint, Linkified, Step } from './primitives';

/** Step 2's Humid route: the page builds the burn as a PSET and Humid signs and broadcasts it after showing it. */
function HumidBurn() {
  const s = useBridge();
  const c = useController();
  const [touched, setTouched] = useState(false);
  const [readingAddress, setReadingAddress] = useState(false);
  const t = target(s);
  const h = readHumid(s.redeemForm.humidAddress);
  const can = !!(t && t.units && h.claim);
  const hint = s.humid.note
    || (s.humid.held ? 'Broadcast uncertain. Check step 3 and the explorer before another burn.' : '')
    || (!h.claim ? 'Enter Humid\'s unconfidential address.'
      : notBurnable(s) || (!(t && t.units) ? 'Fill in step 1 first.' : 'Review the details below, then approve in Humid.'));
  return (
    <section className="wallet-box" aria-labelledby="humid-burn-title">
      <h4 id="humid-burn-title">Burn with Humid</h4>
      <p className="help">Connect Humid on Liquid testnet with your confirmed claim and one confirmed coin of at least {HUMID_FEE.minCoin} tL-BTC
        for fees. Fee: {HUMID_FEE.sats.toString()} sats ({HUMID_FEE.btc} tL-BTC).</p>
      <details className="aside-form">
        <summary>Review the burn</summary>
        <p className="help">Humid shows the burn as an unblinded <code className="mono">OP_RETURN</code> output with no address.
          Check its amount and script. Unburned bridge units return to your unconfidential address; tL-BTC change returns to Humid.</p>
        <p className="help">Humid may ask to connect, share coins, then sign and broadcast. If the last request times out,
          check the explorer before retrying. A missing reply does not mean nothing was sent.</p>
      </details>
      <Field label="Claim's Humid address" placeholder="tex1q…" value={s.redeemForm.humidAddress}
        disabled={readingAddress || s.humid.busy || !!s.humid.held}
        onChange={(e) => c.setRedeemForm({ humidAddress: e.target.value })} onBlur={() => setTouched(true)}
        error={touched ? h.error : undefined}
        help="Use the address that received your claim. Prefilled from your latest deposit." />
      <HumidAddressButton value={s.redeemForm.humidAddress} disabled={s.humid.busy || !!s.humid.held}
        onBusyChange={setReadingAddress} onAddress={(address) => c.setRedeemForm({ humidAddress: address })} />
      <div className="actions">
        <Button variant="primary" disabled={!can || readingAddress || s.humid.busy || !!s.humid.held} onClick={() => void c.sendWithHumid()}>{s.humid.busy ? 'Working…' : 'Send with Humid'}</Button>
        <Hint live>{hint}</Hint>
      </div>
      {can && <p className="warn approval">{burnApproval(t!, t!.units!)}</p>}
      <p className="error" role="alert">{s.humid.error && <Linkified text={s.humid.error} />}</p>
    </section>
  );
}

function BurnStep() {
  const s = useBridge();
  const t = target(s);
  const unburnable = notBurnable(s);
  const error = s.targetError || (unburnable && s.redeemForm.amount.trim() ? unburnable : '');
  const show = !!(t && t.units);
  return (
    <>
      {!show && !error && (
        <p className="help">Enter a recipient and amount to build the burn.</p>
      )}
      {show && (
        <div className="burn">
          <p className="help">Burn <b>{formatUnits(t!.units!, 8)} ({t!.units!.toLocaleString('en')} units)</b> of asset <code className="mono">{t!.assetDisplay}</code>.
            Anyone may submit the proof, but the escrow pays only this recipient or an address they authorize.</p>
          <p className="help">This public, unblinded burn permanently destroys the units and names your Ethereum recipient.</p>
          <CopyLine label="Burn script" value={bytesToHex(t!.burn.scriptPubKey)} />
          <p className="warn"><b>Use this exact script.</b> A wallet's Burn or Destroy button, a different script, or a blinded output
            destroys or locks funds without redemption. Ordinary Send cannot make this burn.</p>
          <HumidBurn />
          <details className="aside-form">
            <summary>Burn from another wallet</summary>
            <p className="help">Create one unblinded output with the amount, asset and script above. The repository's
              <code className="mono"> tools/sg16/liquid-testnet-wallet burn</code> supports this. Check the transaction in step 3.</p>
          </details>
          {t!.isContract && (
            <p className="warn">This recipient is a contract. If it rejects ETH, it must call <code className="mono">redeemTo</code> to redirect the payment.
              If it cannot, the burn cannot be redeemed.</p>
          )}
        </div>
      )}
      <p className="error" role="alert">{error}</p>
    </>
  );
}

export function RedeemPanel({ onClaim }: { onClaim: () => void }) {
  const s = useBridge();
  const c = useController();
  const [amountTouched, setAmountTouched] = useState(false);
  const r = readRedeem(s.redeemForm, s.account);
  const pending = s.journeys.find((j) => actionable(j, 'ready'));
  const waiting = s.journeys.find((j) => actionable(j, 'relay'));
  const unsure = s.journeys.find((j) => j.kind === 'redeem' && ['ready', 'relay'].includes(j.status) && j.lastError);
  const p = readPayTo(s.redeemForm.payTo, s.account);
  const payToError = p.error
    || (p.payTo && pending?.kind === 'redeem' && s.account !== pending.recipient ? 'Connect the burn recipient to redirect payment.' : '');
  const hint = notReady(s)
    || (pending?.kind === 'redeem' ? `Ready: burn ${short(pending.burnTxid)}:${pending.vout}, ${BigInt(pending.units).toLocaleString('en')} units to `
      + `${p.payTo ? `${short(p.payTo)}, as its recipient ${short(pending.recipient)} directs` : short(pending.recipient)}.`
      : waiting?.kind === 'redeem' ? `Relay Liquid to block ${waiting.needed}; the bridge is at ${s.bridge!.lcTip}. Anyone can relay below.`
        : unsure?.kind === 'redeem' ? `Burn ${short(unsure.burnTxid)}:${unsure.vout} could not be checked. See its status below.`
          : 'Look up a confirmed burn in step 3.');

  return (
    <ol className="steps-form">
      <Step n={1} title="Receive on Sepolia">
        <Field label="Ethereum address" placeholder="0x…" value={s.redeemForm.recipient}
          onChange={(e) => c.setRedeemForm({ recipient: e.target.value })}
          error={s.redeemForm.recipient.trim() || s.account ? r.recipientError : undefined}
          help="Defaults to your connected account. Use an address that accepts ETH or can redirect payment." />
        <Field label="Bridge asset amount" placeholder="0.001" inputMode="decimal" unit="units ÷ 10⁸" value={s.redeemForm.amount}
          onChange={(e) => c.setRedeemForm({ amount: e.target.value })} onBlur={() => setAmountTouched(true)}
          error={amountTouched ? r.amountError : undefined} />
      </Step>
      <Step n={2} title="Burn on Liquid">
        <BurnStep />
      </Step>
      <Step n={3} title="Find burn">
        <form className="lookup" onSubmit={(e) => {
          e.preventDefault();
          void c.lookupBurn();
        }}>
          <Field label="Liquid burn transaction ID" placeholder="64 hex characters" value={s.redeemForm.txid}
            onChange={(e) => c.setRedeemForm({ txid: e.target.value })} error={s.lookupError} />
          <Button type="submit">Look up</Button>
        </form>
        <div aria-live="polite">
          {s.found && (
            <table className="found">
              <thead><tr><th scope="col">Output</th><th scope="col">Amount</th><th scope="col">Status</th></tr></thead>
              <tbody>{s.found.map((f) => <tr key={f.vout}><td>{f.vout}</td><td>{f.amount}</td><td>{f.note}</td></tr>)}</tbody>
            </table>
          )}
        </div>
      </Step>
      <Step n={4} title="Prove and redeem">
        <p className="help">The page builds and checks the burn proof, then simulates redemption before asking your wallet to send. Anyone can submit it;
          the escrow pays the burn recipient.</p>
        <details className="aside-form">
          <summary>Redirect payment</summary>
          <Field label="Address to pay" placeholder="0x… (checksummed)" value={s.redeemForm.payTo}
            onChange={(e) => c.setRedeemForm({ payTo: e.target.value })} error={payToError || undefined}
            help={<>Connect the burn recipient to redirect payment with <code className="mono">redeemTo</code>. Leave empty to pay the original recipient.</>} />
        </details>
        <div className="actions">
          <Button variant="primary" disabled={!(ready(s) && pending) || !!payToError || s.redeemBusy} onClick={() => void c.redeem()}>
            {s.redeemBusy ? 'Redeeming…' : 'Redeem'}
          </Button>
          <Hint>{hint}</Hint>
        </div>
        <JourneyList kind="redeem" limit={3} onClaim={onClaim} />
      </Step>
    </ol>
  );
}
