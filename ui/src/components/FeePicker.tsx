import { DEFAULTS } from '@bridge/core/config.js';
import { useId, useRef, useState } from 'react';
import { useBridge, useController } from '../bridge/context';
import { message, short } from '../bridge/format';
import { LIQUID_FAUCET } from '../content/links';
import { Button, ExtLink } from './primitives';

export interface FeeCoin { txid: string; vout: number }

/** A confirmed, explicit coin is necessary because the deployed covenant consumes it in full. */
export function FeePicker({ kind, disabled, onCoin }: {
  kind: 'update' | 'claim'; disabled: boolean; onCoin: (coin: FeeCoin | null) => void;
}) {
  const c = useController();
  const s = useBridge();
  const id = useId();
  const [address, setAddress] = useState(s.redeemForm.humidAddress);
  const [amount, setAmount] = useState('2000');
  const [owned, setOwned] = useState(false);
  const [busy, setBusy] = useState(false);
  const [held, setHeld] = useState(false);
  const [prepared, setPrepared] = useState<FeeCoin | null>(null);
  const [note, setNote] = useState('');
  const [error, setError] = useState('');
  const [coins, setCoins] = useState<(FeeCoin & { sats: bigint })[]>([]);
  const [choice, setChoice] = useState('');
  const run = useRef(0);
  const working = useRef(false);
  const sats = /^\d+$/.test(amount) ? BigInt(amount) : 0n;
  // Above the 0.1 sat/vB relay floor of either spend: a claim weighs about 10.3 kWU, an update 59.1 kWU (1,478 sats).
  const minimum = 2_000n;
  const validAmount = sats >= minimum && sats <= 50_000n;
  const valid = validAmount && address.trim().length > 0;
  const reservations = c.getFeeReservationStatus();
  const clearChoice = () => {
    setCoins([]);
    setChoice('');
    onCoin(null);
  };

  const reset = () => {
    run.current++;
    clearChoice();
    setNote('');
    setError('');
  };

  async function find() {
    if (disabled || working.current || !valid) return;
    const version = ++run.current;
    working.current = true;
    setBusy(true);
    setError('');
    clearChoice();
    setNote('Finding confirmed fee coins…');

    try {
      const found = await c.findFeeCoins(address, sats);
      if (version !== run.current) return;
      setCoins(found);
      if (prepared && found.some((coin) => coin.txid === prepared.txid && coin.vout === prepared.vout)) {
        setHeld(false);
        setPrepared(null);
      }
      setNote(found.length ? 'Choose the coin to spend as the entire fee.' : 'No confirmed coin found. Prepare one below, then check after it confirms.');
    } catch (e) {
      if (version === run.current) {
        setError(message(e));
        setNote('');
      }
    } finally {
      working.current = false;
      setBusy(false);
    }
  }

  async function prepare() {
    if (disabled || working.current || !valid || !owned || held) return;
    working.current = true;
    setBusy(true);
    setError('');
    clearChoice();
    // A previous confirmed preparation must never release a later uncertain send.
    setPrepared(null);

    try {
      const result = await c.prepareFee(address, sats, setNote);
      setNote(`Fee coin sent: ${result.txid}. Check again after confirmation.`);
      setHeld(true);
      setPrepared({ txid: result.txid, vout: result.vout });
    } catch (e) {
      setError(message(e));
      setNote('');
      const failure = e as { sent?: string; txid?: string };
      if (failure?.sent === 'maybe') {
        setHeld(true);
        // Fee preparation always pays its destination at output 0.
        if (failure.txid && /^[0-9a-f]{64}$/.test(failure.txid)) setPrepared({ txid: failure.txid, vout: 0 });
      }
    } finally {
      working.current = false;
      setBusy(false);
    }
  }

  async function recover() {
    if (disabled || working.current || reservations.busy) return;
    working.current = true;
    setBusy(true);
    setError('');
    try {
      const result = await c.recoverFeeReservations();
      if (!result) return;
      clearChoice();
      setNote(`Cleared ${result.released + result.spent} fee reservation(s). ${result.retained} still need checking.`);
      if (result.retained === 0) { setHeld(false); setPrepared(null); }
    } catch (e) {
      setError(message(e));
    } finally {
      working.current = false;
      setBusy(false);
    }
  }

  return <fieldset className="aside-form fee-picker" disabled={disabled || busy || reservations.busy}>
    <legend>Fee coin</legend>
    <div className="field">
      <label htmlFor={`${id}-address`}>Your Humid unconfidential address</label>
      <input id={`${id}-address`} value={address} placeholder="tex1q…" spellCheck={false} autoComplete="off"
        onChange={(e) => { reset(); setAddress(e.target.value); setOwned(false); }} />
    </div>
    <div className="field">
      <label htmlFor={`${id}-amount`}>Fee coin amount (tL-BTC sats)</label>
      <input id={`${id}-amount`} inputMode="numeric" value={amount} onChange={(e) => { reset(); setAmount(e.target.value); }} />
      <p className="help">Find lists coins of at least this amount. Prepare sends exactly this amount.
        The {kind} spends the whole selected coin, up to 50,000 sats; no change.</p>
      {!validAmount && <p className="error">Choose {minimum.toLocaleString('en')}–50,000 sats. The build checks the fee against the transaction's size.</p>}
    </div>
    <div className="actions"><Button disabled={!valid} onClick={() => void find()}>Find fee coins</Button></div>
    <p className="help">Humid's balance may omit this unblinded coin. Find fee coins checks the address directly.</p>
    {coins.length > 0 && <div className="field">
      <label htmlFor={`${id}-coin`}>Confirmed fee coin</label>
      <select id={`${id}-coin`} value={choice} onChange={(e) => {
        setChoice(e.target.value); onCoin(coins.find((coin) => `${coin.txid}:${coin.vout}` === e.target.value) ?? null);
      }}>
        <option value="">Choose a coin</option>
        {coins.map((coin) => <option key={`${coin.txid}:${coin.vout}`} value={`${coin.txid}:${coin.vout}`}>
          {String(coin.sats)} sats · {short(coin.txid)}:{coin.vout}
        </option>)}
      </select>
    </div>}
    <details className="aside-form">
      <summary>Prepare a fee coin with Humid</summary>
      <p className="help">Send {amount || '—'} sats to the address above. This separate transaction costs 500 sats and must confirm first.</p>
      <p className="help">Use Humid on desktop to sign. Fund its Receive → Confidential address with
        {' '}<ExtLink href={LIQUID_FAUCET}>testnet tL-BTC</ExtLink> first.</p>
      {valid && <p className="help approval">Check Humid: output 0 pays {amount} tL-BTC sats to {address.trim()}, the fee is 500 sats,
        and the remaining change returns to Humid. Decline if anything differs.</p>}
      <label className="check"><input type="checkbox" checked={owned} onChange={(e) => setOwned(e.target.checked)} /> I control this address in Humid.</label>
      <div className="actions"><Button disabled={!valid || !owned || held} onClick={() => void prepare()}>Prepare fee coin</Button></div>
      {held && <p className="help">Check Humid activity before preparing another coin. Use Find fee coins after confirmation.</p>}
      {prepared && <p className="help"><ExtLink href={`${DEFAULTS.liquidExplorer}/tx/${prepared.txid}`}>View fee transfer</ExtLink></p>}
      {reservations.pending > 0 && <>
        <p className="help">An interrupted fee transfer has reserved coins. Check Humid activity before releasing them.</p>
        <Button disabled={reservations.busy} onClick={() => void recover()}>Review interrupted preparation</Button>
      </>}
    </details>
    <p className="hint" role="status">{busy ? note || 'Working…' : note}</p>
    <p className="error" role="alert">{error}</p>
  </fieldset>;
}
