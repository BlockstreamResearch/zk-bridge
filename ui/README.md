# Bridge interface

This React and TypeScript app builds the static Sepolia and Liquid testnet bridge page. It uses the protocol modules and published instance configuration in `../bridge-core/`. The GitHub Pages workflow tests the app, builds it, and stages its output beside the one instance record.

```sh
# First build the Rust/WASM transaction modules (Rust, LLVM and wasm-pack 0.15.0).
# See tools/browser-builders/README.md for platform setup.
rustup target add wasm32-unknown-unknown
cargo install --locked wasm-pack --version 0.15.0
tools/browser-builders/build.sh
npm ci --prefix ui
npm --prefix ui run check
npm --prefix ui run dev
```

`check` runs the type checker, ESLint, the CSS formatting check, Vitest, and a production build. The app needs Node 20.19 or newer. The development server reads `../bridge-core/config.js`; if `INSTANCE` is null, it shows that no bridge instance has been published. The release workflow refuses to publish that state.

For layout checks without a wallet or live escrow, run `npm --prefix ui run dev:fixture`. Fixture data is included only in that development mode. The release workflow also scans the production assets for its marker. Use `npm --prefix ui run build:fixture` and `npm --prefix ui run screens` to write local screenshots to the ignored `ui/screens/` directory. The same script fails if a page at 1440, 390 or 320 pixels scrolls sideways or has an element past the screen's edge, first as the page loads and then with every tab panel shown and every disclosure open (the `-open` screenshots); `npm --prefix ui run check:layout` runs only that check. Both need Chrome, so `check` does not run them.

The page fixes the bridge instance from `../bridge-core/config.js`. Settings can change the Liquid data API and the Sepolia read-only RPC; they cannot change the escrow or asset. Ethereum transactions require a connected Sepolia wallet. Liquid burns, claims, and updates built for Humid require approval in Humid. The page checks the transaction Humid reports against the Liquid API before showing it as sent. If the result is uncertain, it holds the send and offers another lookup.

The page builds and verifies Liquid updates and claims in Rust/WASM workers, then uses Humid for signing. SP1 proving remains local: `just prove` exports the browser proof bundle. The on-site guide covers that journey; [OPERATOR.md](../OPERATOR.md) covers CLI alternatives, recovery and keeping deposits open. The on-chain verification and trust assumptions are in [CONCEPT.md](../CONCEPT.md) and [contracts/README.md](../contracts/README.md).
