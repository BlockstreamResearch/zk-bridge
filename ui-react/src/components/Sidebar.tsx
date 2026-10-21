// The trays under the bridge: what the page checked about the instance, and the Settings that choose where it reads.
// Both are closed disclosures, as on the original page.
import { useState } from 'react';
import { useBridge, useController } from '../bridge/context';
import { checkRows } from '../bridge/derive';
import { Button, Field, Seal } from './primitives';

export function ChecksPanel() {
  const rows = checkRows(useBridge());
  return (
    <section aria-labelledby="checks-title">
      <details className="tray disclosure" id="checks">
        <summary>
          <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
          <span id="checks-title">Bridge checks</span>
        </summary>
        <p className="ledger-key"><Seal ok={true} /> checked by this page <Seal ok={null} /> not checked here</p>
        <ul className="ledger-rows">
          {rows.map((r, i) => (
            <li key={i} data-ok={r.ok === null ? 'none' : String(r.ok)}><Seal ok={r.ok} /><span>{r.text}</span></li>
          ))}
        </ul>
      </details>
    </section>
  );
}

/** The Liquid API and the optional Sepolia RPC. The RPC URL may hold an API key: only its own field ever shows it. */
function SettingsForm() {
  const s = useBridge();
  const c = useController();
  const [esplora, setEsplora] = useState(s.settings.esplora);
  const [ethRpc, setEthRpc] = useState(s.settings.ethRpc ?? '');
  const [errors, setErrors] = useState<{ esplora?: string; ethRpc?: string }>({});
  const [busy, setBusy] = useState(false);
  return (
    <form className="settings-form" onSubmit={async (e) => {
      e.preventDefault();
      setBusy(true);
      setErrors((await c.saveSettings({ esplora, ethRpc })) ?? {});
      setBusy(false);
    }}>
      <Field label="Liquid testnet Esplora API" inputMode="url" value={esplora} onChange={(e) => setEsplora(e.target.value)} error={errors.esplora}
        help="Where the page reads Liquid data: blocks for relaying, burns and the bootstrap. It re-checks every transaction against its txid, and the escrow checks every relayed header." />
      {/* Plain text with a URL keyboard, not type="url": the browser's own validation would stop the form before
          parseSettings, whose error says what is wrong without repeating the URL. */}
      <Field label="Ethereum Sepolia RPC (optional)" inputMode="url" placeholder="Empty: read through your wallet" value={ethRpc}
        onChange={(e) => setEthRpc(e.target.value)} error={errors.ethRpc}
        help="An https JSON-RPC URL, or http on this computer, for every Sepolia read: the escrow, receipts, finality. It is saved only once it answers with Sepolia's chain id, and only in this browser; the page shows it nowhere else, since such URLs often hold an API key. Your wallet still signs and sends every transaction. With it, the page reads the bridge, and Humid can burn, without a connected wallet." />
      <p className="help">The bridge instance itself is fixed by this page's published source; no setting or link changes it.</p>
      <div className="actions">
        <Button type="submit" disabled={busy}>{busy ? 'Checking…' : 'Save'}</Button>
        <Button variant="ghost" onClick={() => void c.resetSettings()}>Use the defaults</Button>
      </div>
    </form>
  );
}

export function SettingsPanel() {
  const { settingsVersion } = useBridge();
  return (
    <details className="tray disclosure" id="settings">
      <summary>
        <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path d="M4 7h9M19 7h1M4 17h3M13 17h7" /><circle cx="16" cy="7" r="2.5" /><circle cx="10" cy="17" r="2.5" /></svg>
        Settings
      </summary>
      <div className="disclosure-body">
        {/* Remounted after each Save or reset, so the fields show what is now in effect. */}
        <SettingsForm key={settingsVersion} />
      </div>
    </details>
  );
}
