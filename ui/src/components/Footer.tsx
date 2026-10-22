import { DEFAULTS } from '@bridge/core/config.js';
import { useBridge } from '../bridge/context';
import { ExtLink } from './primitives';

export function Footer({ onTab }: { onTab: (tab: 'deposit' | 'redeem' | 'activity') => void }) {
  const s = useBridge();
  const inst = s.instance;
  return (
    <footer className="footer shell">
      <nav className="foot-links" aria-label="Bridge sections and explorers">
        {(['deposit', 'redeem', 'activity'] as const).map((t) => (
          <a key={t} href="#main" onClick={(e) => {
            e.preventDefault();
            onTab(t);
          }}>{t[0].toUpperCase() + t.slice(1)}</a>
        ))}
        {inst && <ExtLink href={`${DEFAULTS.ethExplorer}/address/${encodeURIComponent(inst.escrow)}`}>Escrow on Etherscan ↗</ExtLink>}
        {inst && <ExtLink href={`${DEFAULTS.liquidExplorer}/tx/${encodeURIComponent(inst.bootstrap)}`}>Bootstrap on Liquid ↗</ExtLink>}
      </nav>
      <dl className="foot-facts">
        <div><dt>Network</dt><dd>Sepolia ⇄ Liquid testnet</dd></div>
        <div><dt>Escrow</dt><dd><code className="mono">{inst?.escrow ?? '—'}</code></dd></div>
        <div><dt>Bridge asset</dt><dd><code className="mono">{s.bridge?.assetDisplay ?? '—'}</code></dd></div>
        <div><dt>Liquid confirmations</dt><dd>{s.bridge ? String(s.bridge.minConf) : '—'}</dd></div>
        <div><dt>Liquid API</dt><dd><code className="mono">{s.settings.esplora}</code></dd></div>
        {/* Not the URL itself, which may hold an API key. */}
        <div><dt>Sepolia reads</dt><dd>{s.settings.ethRpc ? 'Custom RPC' : 'Your wallet'}</dd></div>
        <div><dt>Instance record</dt><dd><code className="mono">{inst?.record ?? 'none'}</code></dd></div>
      </dl>
      <p>Code: <code className="mono">BridgeEscrow.sol</code>, <code className="mono">LiquidLightClient.sol</code>,
        and the Liquid claim and update covenants in the instance record.</p>
    </footer>
  );
}
