import { formatUnits } from '@bridge/ui/lib/bridge.js';
import { bytesToHex } from '@bridge/ui/lib/bytes.js';
import { useState } from 'react';
import { useBridge, useController } from '../bridge/context';
import { admission, notReady, ready, relayLag } from '../bridge/derive';
import { readDeposit } from '../bridge/forms';
import { short } from '../bridge/format';
import { JourneyList } from './Journeys';
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
      <summary>Send a fork proof to reopen deposits</summary>
      <TextAreaField label="Proof JSON" rows={4} value={text} onChange={(e) => setText(e.target.value)} error={error}
        placeholder='{ "proof": { "timestamp": … } }'
        help={<>The output of <code className="mono">tools/liquid-relay/fork_proof.py build</code>, from anyone. Before your wallet is asked, the page checks that
          it reaches the beacon block root Ethereum itself holds for its timestamp (EIP-4788), that it is under the fork the escrow pins, and that it is recent
          enough. The escrow checks it again. Sending it costs gas and reopens deposits for everyone.</>} />
      <div className="actions">
        <Button onClick={() => void send()} disabled={busy || !text.trim()}>{busy ? 'Checking…' : 'Check and send the proof'}</Button>
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
  const [touched, setTouched] = useState<ReadonlySet<string>>(new Set());
  const touch = (k: string) => setTouched((t) => new Set(t).add(k));

  const d = readDeposit(recipient, amount);
  const adm = admission(s);
  const open = !!adm?.deposit;
  const verified = !!s.bootstrap?.ok;
  const filled = !!(d.script && d.units);
  const canSend = ready(s) && open && verified && filled && ack && !s.depositBusy;
  const showRelay = ready(s) && !!adm?.relayReopens && !!s.liquid;
  const showFork = ready(s) && !!adm?.forkReopens;
  const batches = Math.max(1, Math.ceil(relayLag(s) / 100));
  const hint = notReady(s)
    || (!open ? (adm!.relayReopens ? `${adm!.text} Relaying Liquid to its tip takes about ${batches} transaction${batches > 1 ? 's' : ''}.` : adm!.text)
      : !verified ? 'The bridge\'s Liquid bootstrap is not verified (see Bridge checks); deposits stay off.'
        : !filled ? 'Fill in a valid address and amount.'
          : !ack ? 'Confirm you control the Liquid address.' : `Your wallet will ask you to confirm sending to the escrow ${s.instance!.escrow}.`);

  return (
    <ol className="steps-form">
      <Step n={1} title="Where should the bridge asset arrive?">
        <Field label="Liquid testnet address" placeholder="tex1q… or tex1p…" value={recipient}
          onChange={(e) => setRecipient(e.target.value)} onBlur={() => touch('recipient')}
          error={touched.has('recipient') ? d.errors.recipient : undefined}
          help="The unconfidential form of an address from a wallet you control: segwit (tex1q…) or Taproot (tex1p…), or a standard scriptPubKey in hex. The claim pays an explicit output to exactly this script, so its amount is public on Liquid." />
        <p className="warn">The claim pays an explicit (unblinded) output, which not every wallet can spend. With Humid, give the address under Receive, then
          Unconfidential: the Redeem tab can then have Humid spend the claim, which Humid's own Send cannot, given a little tL-BTC in Humid for the fee,
          received at its confidential address. Elements Core is expected to work, but has not been tested here.</p>
      </Step>
      <Step n={2} title="How much SepETH?">
        <Field label="Amount in ETH" placeholder="0.001" inputMode="decimal" unit="ETH" value={amount}
          onChange={(e) => setAmount(e.target.value)} onBlur={() => touch('amount')}
          error={touched.has('amount') ? d.errors.amount : undefined}
          help="Minimum 0.001. Steps of 0.00000001 ETH: one bridge unit each." />
        {filled && (
          <p className="quote">You lock {formatUnits(d.wei!, 18)} SepETH. Once Ethereum finalizes it and an update proves it to Liquid, a claim pays
            {' '}{d.units!.toLocaleString('en')} units ({formatUnits(d.units!, 8)} in wallets) of the bridge asset{s.bridge ? ` ${short(s.bridge.assetDisplay)}` : ''} to
            {' '}{d.address ? short(d.address, 10) : `script ${short(bytesToHex(d.script!), 8)}`}, as an explicit output: the amount is public on Liquid.</p>
        )}
      </Step>
      <Step n={3} title="Review and send">
        <label className="check">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span>I control this Liquid address, and I understand someone must prove and claim my deposit, in practice this instance's operator.</span>
        </label>
        <div className="actions">
          <Button variant="primary" disabled={!canSend} onClick={() => void c.sendDeposit({ recipient, amount })}>
            {s.depositBusy ? 'Sending…' : 'Send deposit'}
          </Button>
          {showRelay && (
            <Button disabled={s.relaying} onClick={() => void c.relayForDeposits()}>{s.relaying ? 'Relaying…' : 'Relay Liquid to reopen deposits'}</Button>
          )}
          <Hint>{hint}</Hint>
        </div>
        {showFork && <ForkProofForm />}
      </Step>
      <Step n={4} title="Track it across">
        <p className="help">Each deposit waits for Ethereum finality (usually 13 to 20 minutes), then for someone, in practice this instance's operator, to prove
          it to Liquid and claim it. With the operator at work that usually takes 30 minutes to 2 hours from sending, but no time is promised. Each row says what
          its deposit is waiting for, and what you can do if that takes longer than usual. Progress is saved in this browser.</p>
        <JourneyList kind="deposit" limit={3} onClaim={onClaim} />
      </Step>
    </ol>
  );
}
