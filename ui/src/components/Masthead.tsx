import type { ReactNode } from 'react';
import { useBridge, useController } from '../bridge/context';
import { type Chip, chips, notice, onSepolia } from '../bridge/derive';
import { REPO, SITE } from '../content/links';
import { Button, ExtLink } from './primitives';

/**
 * Above everything, on any copy of the page but the published site (BridgeState.published): which site that is, and
 * that this copy's instance record does not count. A copy elsewhere may be an older build, serving an older record.
 */
export function SiteNotice() {
  if (useBridge().published) return null;
  return (
    <p className="notice site-notice shell" role="note">
      <span><strong>Unofficial copy.</strong> Its records may be stale; listed stores do not count as published here.
        Use <ExtLink href={SITE}>{SITE.replace(/^https:\/\/|\/$/g, '')}</ExtLink>.
        Source: <ExtLink href={REPO}>{REPO.replace('https://github.com/', '')}</ExtLink>.</span>
    </p>
  );
}

function Reading({ chain, title, chip }: { chain: 'eth' | 'liquid' | 'bridge'; title: string; chip: Chip }) {
  return (
    <li className="stat" data-chain={chain} data-state={chip.state}>
      <p className="stat-label"><span className="dot" aria-hidden="true" />{title}</p>
      <p className="stat-line">
        <span className="stat-value">{chip.value}</span>
        {chip.unit && <span className="stat-unit" data-glyph={chain === 'eth' ? 'Ξ' : 'L'}> {chip.unit}</span>}
      </p>
      <p className="stat-sub">{chip.sub}</p>
    </li>
  );
}

export function Masthead({ onTrust }: { onTrust: () => void }) {
  const s = useBridge();
  const c = useController();
  const connected = !!s.account && onSepolia(s);
  const r = chips(s);
  return (
    <>
      <header className="masthead shell">
        <div className="brand">
          <div className="wordmark-row">
            <h1 className="wordmark">zk-bridge<span className="sr-only">: Sepolia and Liquid testnet</span></h1>
            <span className="badge">Testnet</span>
          </div>
          <p className="tagline" aria-hidden="true">Sepolia <span className="tagline-swap">⇄</span> Liquid</p>
        </div>
        <div className="masthead-actions">
          <a className="textlink" href="#trust" onClick={onTrust}>What you trust
            <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M12 5v14" /><path d="M6 13l6 6 6-6" /></svg>
          </a>
          <Button variant="primary" className="connect" onClick={() => void c.connect()} disabled={connected}>
            {!s.account ? 'Connect wallet' : !onSepolia(s) ? 'Switch to Sepolia' : 'Connected'}
          </Button>
        </div>
      </header>
      <section className="overview shell" aria-labelledby="readings-title">
        <h2 className="eyebrow" id="readings-title">Network overview</h2>
        <ul className="stats readings">
          <Reading chain="eth" title="Ethereum Sepolia" chip={r.eth} />
          <Reading chain="liquid" title="Liquid testnet tip" chip={r.liquid} />
          <Reading chain="bridge" title="Bridge light client" chip={r.bridge} />
        </ul>
      </section>
    </>
  );
}

/**
 * The proof-of-concept slip: what this is, in one paragraph, after a pill in its own column, so no width puts it over
 * the text; then `children`, the What you are trusting disclosure.
 */
export function Slip({ children }: { children: ReactNode }) {
  return (
    <aside className="slip shell" aria-label="Proof of concept">
      <div className="slip-head">
        <span className="pill" data-tone="pending" aria-hidden="true"><span className="dot" />Proof of concept</span>
        <p>
          <strong>Testnet proof of concept. No real value. Unaudited.</strong> Ethereum verifies Liquid's signed blocks;
          Liquid verifies proofs of Ethereum finality. You or anyone else can prove, claim and relay.
          Liquid testnet trusts one signing key. Review the assumptions below before using the bridge.
        </p>
      </div>
      {children}
    </aside>
  );
}

/** The one notice under the route, when something keeps the bridge from full use. */
export function Notice() {
  const text = notice(useBridge());
  if (!text) return null;
  return <p className="notice" role="status">{text}</p>;
}
