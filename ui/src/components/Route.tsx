// The route of the selected direction, and what each side verifies about the other. Static: the source chain is on
// the left and a fixed arrow points to the destination; it explains, it does not animate progress. Assistive
// technology reads its label, not its parts.

const ROUTES = {
  deposit: {
    label: 'Route: from Ethereum Sepolia (SepETH) to Liquid testnet (the bridge asset). Liquid verifies an SP1 proof that Sepolia finalized the deposit.',
    from: { chain: 'eth', name: 'Ethereum Sepolia', asset: 'Lock SepETH' },
    to: { chain: 'liquid', name: 'Liquid testnet', asset: 'Receive bridge asset' },
    proof: 'Liquid checks a proof of Sepolia finality',
  },
  redeem: {
    label: 'Route: from Liquid testnet (the bridge asset) to Ethereum Sepolia (SepETH). Ethereum verifies Liquid\'s signed block headers and the burn\'s Merkle proof.',
    from: { chain: 'liquid', name: 'Liquid testnet', asset: 'Burn bridge asset' },
    to: { chain: 'eth', name: 'Ethereum Sepolia', asset: 'Receive SepETH' },
    proof: 'Ethereum checks Liquid\'s signed headers',
  },
} as const;

export function Route({ direction }: { direction: 'deposit' | 'redeem' }) {
  const r = ROUTES[direction];
  return (
    <div className="rail" role="img" aria-label={r.label} data-direction={direction}>
      <div className="rail-end rail-from" data-chain={r.from.chain}>
        <span className="rail-role">From</span>
        <span className="rail-chain">{r.from.name}</span>
        <span className="rail-asset">{r.from.asset}</span>
      </div>
      <div className="rail-track"><span className="rail-line" /></div>
      <div className="rail-end rail-to" data-chain={r.to.chain}>
        <span className="rail-role">To</span>
        <span className="rail-chain">{r.to.name}</span>
        <span className="rail-asset">{r.to.asset}</span>
      </div>
      <span className="rail-proof">
        <svg viewBox="0 0 24 24" width="16" height="16"><path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
        {r.proof}
      </span>
    </div>
  );
}
