import { BURN_TAG, formatUnits } from '@bridge/core/lib/bridge.js';
import { bytesToHex } from '@bridge/core/lib/bytes.js';
import { useState } from 'react';
import { HUMID_FEE, burnApproval } from '../bridge/approval';
import { useBridge, useController } from '../bridge/context';
import { notBurnable, notReady, ready, target } from '../bridge/derive';
import { readHumid, readPayTo, readRedeem } from '../bridge/forms';
import { short } from '../bridge/format';
import { actionable } from '../bridge/journeys';
import { JourneyList } from './Journeys';
import { Button, CopyLine, Field, Hint, Linkified, Step } from './primitives';

/** Step 2's Humid route: the page builds the burn as a PSET and Humid signs and broadcasts it after showing it. */
function HumidBurn() {
  const s = useBridge();
  const c = useController();
  const [touched, setTouched] = useState(false);
  const t = target(s);
  const h = readHumid(s.redeemForm.humidAddress);
  const can = !!(t && t.units && h.claim);
  const hint = s.humid.note
    || (s.humid.held ? 'Step 2 asks Humid for no other burn while this send is in doubt: check it in step 3 and on the explorer.' : '')
    || (!h.claim ? 'Paste Humid\'s unconfidential address first.'
      : notBurnable(s) || (!(t && t.units) ? 'Fill in step 1 first.' : 'Ready. Humid may ask up to three times; before signing, compare its approval with the line below.'));
  return (
    <section className="wallet-box" aria-labelledby="humid-burn-title">
      <h4 id="humid-burn-title">Send it with Humid</h4>
      <p className="help">If the bridge claimed to your Humid wallet, Humid can make this burn. The page builds it from the public claim and one of Humid's
        tL-BTC coins for a {HUMID_FEE.sats.toString()}-sat fee ({HUMID_FEE.btc} tL-BTC), and Humid shows every output before it signs. Humid 1.1.3's
        released code shows this output with no address and its script in hex, and leaves it unblinded. Start with a small amount.</p>
      <p className="help">Before you start, you need:</p>
      <ul className="help">
        <li>the Humid extension in this browser, unlocked, with Liquid testnet;</li>
        <li>the claim confirmed at Humid's unconfidential address (the deposit shows Claimed);</li>
        <li>at least {HUMID_FEE.minCoin} tL-BTC in Humid, received at its confidential address and confirmed, for the fee and its change.</li>
      </ul>
      <details className="aside-form">
        <summary>What the page hands Humid to sign</summary>
        <ol className="help flow">
          <li><b>Inputs:</b> the claim's open output at Humid's unconfidential address, which the page finds on the public Liquid API because Humid's own coin
            list leaves open coins out; then one confirmed tL-BTC coin from Humid's list, for the fee.</li>
          <li><b>Output 0, the burn:</b> the amount above of the bridge asset, unblinded, to the burn script above. Humid lists a bare <code className="mono">OP_RETURN</code> output
            with an empty address and its script in hex, and leaves it unblinded.</li>
          <li><b>Then:</b> any bridge asset you keep, unblinded, back to the same unconfidential address; the tL-BTC change back to Humid, which blinds it if
            the fee coin was confidential; and the {HUMID_FEE.sats.toString()}-sat fee.</li>
          <li><b>Humid</b> shows these outputs, signs only its own coins and broadcasts. The page then checks that the broadcast is the transaction it built,
            and step 3 tracks it.</li>
        </ol>
        <p className="help">Humid asks separately: to connect this page (once), to share its coins with this page (unless you allowed that when connecting),
          and to sign and send the burn, showing each output first. Only the last moves anything. Each prompt closes by itself after 30 seconds, so read the
          line that appears below the button before you click; if a prompt closes, nothing is sent and you can click again.</p>
        <p className="help">If you redeem less than the claim holds, the rest goes back openly to the same unconfidential address. Humid's balance does not
          show it there, but this panel can send it later.</p>
      </details>
      <Field label="Humid's unconfidential address, which the claim paid" placeholder="tex1q…" value={s.redeemForm.humidAddress}
        onChange={(e) => c.setRedeemForm({ humidAddress: e.target.value })} onBlur={() => setTouched(true)}
        error={touched ? h.error : undefined}
        help="In Humid, open Receive, then the Unconfidential tab. The address of your latest deposit in this browser is filled in." />
      <div className="actions">
        <Button variant="primary" disabled={!can || s.humid.busy || !!s.humid.held} onClick={() => void c.sendWithHumid()}>{s.humid.busy ? 'Working…' : 'Send with Humid'}</Button>
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
        <p className="help">The burn appears here once step 1 has a recipient and an amount. It names the recipient, so it is computed for you and checked
          against the escrow.</p>
      )}
      {show && (
        <div className="burn">
          <p className="help">Burn <b>{formatUnits(t!.units!, 8)} ({t!.units!.toLocaleString('en')} units)</b> of asset <code className="mono">{t!.assetDisplay}</code>.
            Anyone may submit the proof, but the escrow pays only this recipient or an address they authorize.</p>
          <p className="help">The burn is one <b>unconfidential</b> output of that amount whose script is <code className="mono">OP_RETURN</code> and a payload
            naming this bridge, the chain, the escrow and the recipient. No one can ever spend an <code className="mono">OP_RETURN</code> output, so the burn is
            final and anyone can see it, and what it names, on a Liquid explorer.</p>
          <CopyLine label="Burn script" value={bytesToHex(t!.burn.scriptPubKey)} />
          <p className="help">OP_RETURN, then one push of 70 bytes: “{BURN_TAG}” in ASCII, chain id {t!.burn.chainId.toString()} (Sepolia) in 8 bytes, the
            escrow {t!.burn.escrow} and the recipient {t!.burn.recipient}.</p>
          <p className="warn"><b>Burn only with exactly this script.</b> A wallet's Burn or Destroy control, and Elements' <code className="mono">destroyamount</code>,
            make an <code className="mono">OP_RETURN</code> that names no recipient: the units are destroyed and nobody can redeem them. A blinded output cannot be
            redeemed either. The script has no address, so a wallet's ordinary Send cannot make this burn; use Humid below. This page does not sign the Liquid
            transaction.</p>
          <HumidBurn />
          <details className="aside-form">
            <summary>Burn from another wallet</summary>
            <p className="help">Any tool that can build a Liquid transaction with an explicit output to a given script can make this burn: one unblinded output
              of the amount above, of the bridge asset, with the script above. Every other output is up to the wallet. The project's testnet wallet tool
              (<code className="mono">tools/sg16/liquid-testnet-wallet burn</code>) builds it and checks the script against the escrow's answer. With any tool,
              burn a small amount first and check its transaction in step 3 before relying on it. Only a result with confirmations or “ready to redeem” shows a
              usable output.</p>
          </details>
          {t!.isContract && (
            <p className="warn">The recipient is a contract. If it refuses plain ETH, nobody can redeem to it; only that contract, calling
              <code className="mono"> redeemTo</code>, can have the ETH paid elsewhere. Prefer an ordinary account.</p>
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
    || (p.payTo && pending?.kind === 'redeem' && s.account !== pending.recipient ? 'only the burn\'s recipient can redirect it; connect that account' : '');
  const hint = notReady(s)
    || (pending?.kind === 'redeem' ? `Ready: burn ${short(pending.burnTxid)}:${pending.vout}, ${BigInt(pending.units).toLocaleString('en')} units to `
      + `${p.payTo ? `${short(p.payTo)}, as its recipient ${short(pending.recipient)} directs` : short(pending.recipient)}.`
      : waiting?.kind === 'redeem' ? `Waiting for the bridge to relay Liquid up to height ${waiting.needed}; it is at ${s.bridge!.lcTip}. You can relay it yourself below.`
        : unsure?.kind === 'redeem' ? `Burn ${short(unsure.burnTxid)}:${unsure.vout} could not be checked just now; its row below says why.`
          : 'Look up your burn with enough confirmations first (step 3).');

  return (
    <ol className="steps-form">
      <Step n={1} title="Who receives the ETH?">
        <Field label="Ethereum address" placeholder="0x…" value={s.redeemForm.recipient}
          onChange={(e) => c.setRedeemForm({ recipient: e.target.value })}
          error={s.redeemForm.recipient.trim() || s.account ? r.recipientError : undefined}
          help="Defaults to the connected account. It should accept plain ETH; a recipient that refuses it can still redeem from its own account to another address (step 4)." />
        <Field label="Amount to redeem, in bridge asset" placeholder="0.001" inputMode="decimal" unit="units ÷ 10⁸" value={s.redeemForm.amount}
          onChange={(e) => c.setRedeemForm({ amount: e.target.value })} onBlur={() => setAmountTouched(true)}
          error={amountTouched ? r.amountError : undefined} />
      </Step>
      <Step n={2} title="Burn on Liquid">
        <BurnStep />
      </Step>
      <Step n={3} title="Find your send">
        <form className="lookup" onSubmit={(e) => {
          e.preventDefault();
          void c.lookupBurn();
        }}>
          <Field label="Liquid transaction id of your burn" placeholder="64 hex characters" value={s.redeemForm.txid}
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
        <p className="help">The page builds the proof from public Liquid data: the burn transaction, its Merkle branch, and the place of its block among the
          blocks relayed to the bridge. It checks the proof and simulates the call. Only then does it ask your wallet to send.</p>
        <details className="aside-form">
          <summary>Pay the ETH to another address</summary>
          <Field label="Address to pay" placeholder="0x… (checksummed)" value={s.redeemForm.payTo}
            onChange={(e) => c.setRedeemForm({ payTo: e.target.value })} error={payToError || undefined}
            help={<>Only the burn's recipient can redirect it (<code className="mono">redeemTo</code>), so connect that account. This is the way out for a
              recipient that refuses plain ETH. Leave it empty to pay the recipient.</>} />
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
