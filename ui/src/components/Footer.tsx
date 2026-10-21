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
        <div><dt>Network</dt><dd>Sepolia ⇄ liquidtestnet</dd></div>
        <div><dt>Escrow</dt><dd><code className="mono">{inst?.escrow ?? '—'}</code></dd></div>
        <div><dt>Bridge asset</dt><dd><code className="mono">{s.bridge?.assetDisplay ?? '—'}</code></dd></div>
        <div><dt>Liquid confirmations</dt><dd>{s.bridge ? String(s.bridge.minConf) : '—'}</dd></div>
        <div><dt>Esplora base URL</dt><dd><code className="mono">{s.settings.esplora}</code></dd></div>
        {/* Not the URL itself, which may hold an API key. */}
        <div><dt>Sepolia reads</dt><dd>{s.settings.ethRpc ? 'The RPC in Settings' : 'Your wallet'}</dd></div>
        <div><dt>Instance record</dt><dd><code className="mono">{inst?.record ?? 'none published yet'}</code></dd></div>
      </dl>
      <p>Contracts: <code className="mono">contracts/solidity/contracts/BridgeEscrow.sol</code> and <code className="mono">contracts/solidity/contracts/LiquidLightClient.sol</code> on
        Sepolia; on Liquid, the claim leaf <code className="mono">contracts/simplicity/simf/claim.simf</code> and the SP1 update leaf that the instance record
        names. Read them before you trust them.</p>
    </footer>
  );
}
