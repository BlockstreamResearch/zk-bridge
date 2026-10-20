import type { RefObject } from 'react';
import { useBridge } from '../bridge/context';
import { ASSUMPTIONS, COSTS, HOW_IT_WORKS, SELF_SERVE, SELF_SERVE_NOTE } from '../content/trust';
import { Needs } from './primitives';

export function TrustPanel({ panelRef }: { panelRef: RefObject<HTMLDetailsElement | null> }) {
  const s = useBridge();
  return (
    <section className="trust shell" aria-labelledby="trust-title">
      <details id="trust" ref={panelRef}>
        <summary>
          <span id="trust-title">What you are trusting</span>
          <span className="count" aria-label={`${ASSUMPTIONS.length} points`}>{ASSUMPTIONS.length}</span>
        </summary>
        <div className="trust-body">
          <p className="design"><b>How it works.</b> {HOW_IT_WORKS}</p>
          <div className="trust-columns">
            <div>
              <h3 id="selfserve-title">What you can do yourself</h3>
              <dl className="selfserve" aria-labelledby="selfserve-title">
                {SELF_SERVE.map((a) => (
                  <div key={a.name} data-action={a.name}>
                    <dt>{a.title}</dt>
                    <dd>{a.body}</dd>
                    <dd className="needs"><Needs>{a.needs}</Needs></dd>
                    <dd className="here"><span className="here-label">On this instance</span> {a.here(s)}</dd>
                  </div>
                ))}
              </dl>
              <p className="help">{SELF_SERVE_NOTE}</p>
            </div>
            <div>
              <h3 id="costs-title">Coins and fees</h3>
              <dl className="costs" aria-labelledby="costs-title">
                {COSTS.map((c) => (
                  <div key={c.name} data-cost={c.name}>
                    <dt>{c.title}</dt>
                    <dd>{c.body}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>
          <h3>What you trust</h3>
          <ol className="assumptions">
            {ASSUMPTIONS.map((a) => (
              <li key={a.title}>
                <b>{a.title}</b>
                <p>{a.body}</p>
                <p className="here"><span className="here-label">On this instance</span> {a.here(s)}</p>
              </li>
            ))}
          </ol>
        </div>
      </details>
    </section>
  );
}
