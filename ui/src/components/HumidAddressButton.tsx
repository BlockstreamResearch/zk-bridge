import { useEffect, useRef, useState } from 'react';
import { useController } from '../bridge/context';
import { message } from '../bridge/format';
import { Button, Hint } from './primitives';

/** An explicit read, never an automatic replacement of a recipient or a request to sign. */
export function HumidAddressButton({ value, disabled, onAddress, onBusyChange }: {
  value: string;
  disabled?: boolean;
  onAddress: (address: string) => void;
  onBusyChange: (busy: boolean) => void;
}) {
  const c = useController();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const working = useRef(false);
  const generation = useRef(0);

  // Discard replies after edits, a parent lock or unmount. A wallet prompt can outlive the form.
  useEffect(() => () => { generation.current++; }, [value, disabled]);

  async function read() {
    if (disabled || working.current) return;
    const version = ++generation.current;
    working.current = true;
    setBusy(true);
    onBusyChange(true);
    setError('');

    try {
      const address = await c.getHumidAddress();
      if (version === generation.current) onAddress(address);
    } catch (e) {
      if (version === generation.current) setError(message(e));
    } finally {
      working.current = false;
      setBusy(false);
      onBusyChange(false);
    }
  }

  return <>
    <div className="actions">
      <Button disabled={disabled || busy} onClick={() => void read()}>{busy ? 'Reading Humid…' : 'Use Humid address'}</Button>
      {busy && <Hint live>Approve address access in Humid.</Hint>}
    </div>
    {error && <p className="error" role="alert">{error}</p>}
  </>;
}
