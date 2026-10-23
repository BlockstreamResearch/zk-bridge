import { formatUnits } from '@bridge/core/lib/bridge.js';
import { bytesToHex } from '@bridge/core/lib/bytes.js';
import { useState } from 'react';
import { useBridge, useController } from '../bridge/context';
import { admission, notReady, ready, relayLag } from '../bridge/derive';
import { readDeposit } from '../bridge/forms';
import { short } from '../bridge/format';
import { JourneyList } from './Journeys';
import { HumidAddressButton } from './HumidAddressButton';
import { Button, Field, Hint, Step, TextAreaField } from './primitives';

function ForkProofForm() {
  const c = useController();
  const [text, setText] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const send = async () => {
    setBusy(true);
    setError('');
    const why = await c.sendForkProof(text);
    setBusy(false);
    if (why) setError(why);
    else setText('');
  };
  return (
    <details className="aside-form">
      <summary>Reopen with a fork proof</summary>
      <TextAreaField label="Proof JSON" rows={4} value={text} onChange={(e) => setText(e.target.value)} error={error}
        placeholder='{ "proof": { "timestamp": … } }'
        help={<>Paste the output of <code className="mono">tools/liquid-relay/fork_proof.py build</code>. The page and escrow check its
          Ethereum beacon root, fork and age. Anyone can submit it; sending costs Sepolia gas.</>} />
      <div className="actions">
        <Button onClick={() => void send()} disabled={busy || !text.trim()}>{busy ? 'Checking…' : 'Check and send'}</Button>
      </div>
    </details>
  );
}

export function DepositPanel({ onClaim }: { onClaim: () => void }) {
  const s = useBridge();
  const c = useController();
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('');
  const [ack, setAck] = useState(false);
  const [readingAddress, setReadingAddress] = useState(false);
  const [touched, setTouched] = useState<ReadonlySet<string>>(new Set());
  const touch = (k: string) => setTouched((t) => new Set(t).add(k));

  const d = readDeposit(recipient, amount);
  const adm = admission(s);
  const open = !!adm?.deposit;
  const verified = !!s.bootstrap?.ok;
  const filled = !!(d.script && d.units);
  const canSend = ready(s) && open && verified && filled && ack && !s.depositBusy && !readingAddress;
  const showRelay = ready(s) && !!adm?.relayReopens && !!s.liquid;
  const showFork = ready(s) && !!adm?.forkReopens;
  const batches = Math.max(1, Math.ceil(relayLag(s) / 100));
  const hint = notReady(s)
    || (!open ? (adm!.relayReopens ? `${adm!.text} Relaying Liquid to its tip takes about ${batches} transaction${batches > 1 ? 's' : ''}.` : adm!.text)
      : !verified ? 'Deposits are off until bootstrap verification passes. See Bridge checks.'
        : !filled ? 'Enter an address and amount.'
          : !ack ? 'Confirm you control the Liquid address.' : `Confirm the deposit in your wallet. Escrow: ${s.instance!.escrow}.`);

  return (
    <ol className="steps-form">
      <Step n={1} title="Receive on Liquid">
        <Field label="Liquid testnet address" placeholder="tex1q… or tex1p…" value={recipient}
          disabled={readingAddress || s.depositBusy}
          onChange={(e) => { setRecipient(e.target.value); setAck(false); }} onBlur={() => touch('recipient')}
          error={touched.has('recipient') ? d.errors.recipient : undefined}
          help="Use an unconfidential address you control: tex1q… or tex1p…, or a standard script in hex. The claim amount is public." />
        <HumidAddressButton value={recipient} disabled={s.depositBusy} onBusyChange={setReadingAddress}
          onAddress={(address) => { setRecipient(address); setAck(false); }} />
        <p className="help">Humid can supply your address. You can also paste one from Receive → Unconfidential.
          Keep tL-BTC in Humid for fees.</p>
      </Step>
      <Step n={2} title="Deposit amount">
        <Field label="Amount in ETH" placeholder="0.001" inputMode="decimal" unit="ETH" value={amount}
          onChange={(e) => setAmount(e.target.value)} onBlur={() => touch('amount')}
          error={touched.has('amount') ? d.errors.amount : undefined}
          help="Minimum 0.001 ETH. One bridge unit = 0.00000001 ETH." />
        {filled && (
          <p className="quote">Lock {formatUnits(d.wei!, 18)} SepETH for {d.units!.toLocaleString('en')} bridge units
            {' '}({formatUnits(d.units!, 8)} in wallets){s.bridge ? ` of asset ${short(s.bridge.assetDisplay)}` : ''}.
            Recipient: {d.address ? short(d.address, 10) : `script ${short(bytesToHex(d.script!), 8)}`}.</p>
        )}
      </Step>
      <Step n={3} title="Review and send">
        <label className="check">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span>I control this address. I understand that anyone, including me, can prove and claim the deposit, and there is no refund.</span>
        </label>
        <div className="actions">
          <Button variant="primary" disabled={!canSend} onClick={() => void c.sendDeposit({ recipient, amount })}>
            {s.depositBusy ? 'Sending…' : 'Send deposit'}
          </Button>
          {showRelay && (
            <Button disabled={s.relaying} onClick={() => void c.relayForDeposits()}>{s.relaying ? 'Relaying…' : 'Relay to reopen deposits'}</Button>
          )}
          <Hint>{hint}</Hint>
        </div>
        {showFork && <ForkProofForm />}
      </Step>
      <Step n={4} title="Track deposit">
        <p className="help">Wait for Ethereum finality, then prove and claim the deposit. Anyone can do these steps; they are not automatic.
          Progress is saved in this browser. <a href="#guide">Guide</a></p>
        <JourneyList kind="deposit" limit={3} onClaim={onClaim} />
      </Step>
    </ol>
  );
}
