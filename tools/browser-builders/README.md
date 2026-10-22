# Browser transaction builders

These two WASM modules build the existing testnet update and claim transactions. They share their transaction code with the Rust CLIs. The modules construct Elements amount proofs, execute the covenant, enforce its cost and fee limits, and return an unsigned fee input for the wallet to sign. They never access a wallet, contact a server, or broadcast.

The crates remain separate because the generated update leaf uses stock simplicity-lang 0.9 while the claim compiler uses the existing vendored 0.8 dependency.

## Build

Install Rust's `wasm32-unknown-unknown` target, `wasm-pack`, and LLVM clang/llvm-ar with WebAssembly support. From the repository root:

```sh
tools/browser-builders/build.sh
```

Outputs are ignored files under `target/browser-builders/{update,claim}`. Each directory contains `{action}.js`, `{action}_bg.wasm` and TypeScript declarations. The default target is `web`, suitable for Vite and a module worker. Call the module's default initializer before its builder.

Overrides:

- `BROWSER_BUILDERS_OUT`: absolute output directory.
- `BROWSER_BUILDERS_TARGET`: wasm-pack target, default `web`.
- `CC_wasm32_unknown_unknown` and `AR_wasm32_unknown_unknown`: compiler and archiver. The script detects Homebrew LLVM on macOS and otherwise uses PATH.
- `CARGO_TARGET_DIR`: compilation cache directory.

Use a Web Worker: update verification is CPU-intensive. Terminating the worker cancels a build. An application must separately check the live outpoint and fee UTXO again before signing or broadcasting.

## API

`build_update(input_json)` and `build_claim(input_json)` each accept one JSON string and return a JSON string containing `{raw_tx, report}`. Invalid input throws a JavaScript `Error`. Native Rust exposes `build_update_json` and `build_claim_json` as `Result<String, String>`.

Common fields:

```ts
interface CommonInput {
  manifest: object // the deployment manifest, including deployable: true
  state: {
    acc: string // 32-byte hex, as in the CLI state record
    claimed: number[] // ascending unique deposit indices
    claimed_root: string // 32-byte hex
    lc?: string
    head?: number
    header?: string
    committee?: string
  }
  state_tx_hex: string // full previous Elements transaction
  state_vout: number
  fee_tx_hex: string // full previous Elements transaction
  fee_vout: number
}
```

Claim adds `deposits: [number, string][]` and `index: number`. Each deposit is `[units, recipient_script_hex]`, in escrow event order. A prefix must reproduce the state's proven accumulator. Claim accepts an LC-only state containing `lc`, `acc`, `claimed`, and `claimed_root`; it does not need the light-client store.

Update adds `compiled_program: {program_hex: string, witness_hex: string, cmr: string}` and `new_state: object`. The hex fields use Simplicity's canonical program and witness encoding, produced during proof preparation by `sg16-testnet compile-update PROGRAM WITNESS OUT.json`. The decoder checks types and witness encoding; the actual decoded CMR must equal the manifest's update CMR. The browser then prunes against the transaction and runs the same execution checks as the CLI.

`program: string` and `witness: object` remain an alternative input for the existing human-readable `.simpl` text and witness JSON. This parser is slow for full update programs. Use the compiled form in the browser. If both forms are present, the compiled form is used. Both state records require `head`, `header`, `committee`, `acc`, `claimed`, and `claimed_root`.

Example calls using already loaded artifacts:

```js
await claimModule.default()
const { raw_tx, report } = JSON.parse(claimModule.build_claim(JSON.stringify({
  manifest, state, state_tx_hex, state_vout: 0, fee_tx_hex, fee_vout: 1,
  deposits: [[100000, '0014' + '33'.repeat(20)]], index: 0,
})))
// report: {ok:true, txid, successor_state, fee, unsigned_inputs:[1],
//          weight_estimate, cost_mwu, gates_passed, ...}
```

Amounts and indices must be JSON integers. All allowed bridge amounts fit JavaScript's safe integer range. Both builders require an explicit Liquid testnet L-BTC P2WPKH fee input and consume its entire value as the fee. The existing upper fee limit still applies. No change output is possible in either deployed covenant.

Input limits are 64 MiB for the complete JSON string, 8 MiB of hex per previous transaction or compiled-program field, and 10,000 deposits or claimed indices. Witness nesting is limited to 64, with words at most 4096 bits and at most 128 named witnesses. JSON parsing also uses serde_json's depth limit. All live network and manifest identity checks remain the caller's responsibility; a local builder cannot establish chain inclusion, spent status, or which deployment the user intended.

## Proof preparation boundary

The SP1 proof alone is insufficient for the existing generated Simplicity verifier. Its witness includes BN254 MSM and Miller-loop hints and extension-field values calculated by the existing Python proof preparation code. The proof step exports the compiled program and witness plus the successor state; transaction assembly stays in WASM. Compiling is independent of a transaction and does not imply that the proof is valid. The browser executes it against the actual transaction before returning the result.

The witness binds the old LC, accumulator, claimed root, claim-leaf sibling, and the new LC, accumulator, head and execution block/root. It contains no fee input or transaction outpoint. A claim changing the claimed root makes an exported witness stale. Regenerating the witness from the same proof does not require rerunning SP1. The browser must reject a bundle whose old state does not match the live state.

## Tests

Build the native CLIs in their existing documented target directories, generate synthetic fixtures with `python3 tools/sg16/bridge-guest/testnet/test_testnet.py --full`, then run:

```sh
node tools/browser-builders/test.mjs
```

The test executes both actual WASM modules in Node, compares each transaction body, covenant input witness, range proofs, txid and successor state against the CLI, then runs the stock simplicity-lang 0.9 verifier on both transactions. Surjection proofs use fresh secure randomness, so their bytes intentionally differ; both are verified. Failure cases cover malformed JSON, witness shape, program, stale state, replayed/out-of-range deposits and invalid transaction indices. Tests first verify that non-deployable fixture manifests are refused, then explicitly mark an in-memory copy deployable to exercise the same public API with synthetic transactions. No local-test bypass is exported.

Test overrides: `BROWSER_BUILDERS_FIXTURES`, `BROWSER_BUILDERS_OUT`, `BROWSER_BUILDERS_TX_TOOL`, and `BROWSER_BUILDERS_CLAIM_TOOL`. `BROWSER_BUILDERS_ACTIONS=claim` selects only the claim test. `BROWSER_BUILDERS_COMPILED` supplies an already compiled synthetic program; otherwise the test runs the native compiler once. The update test also compares against the original text-built fixture transaction. Test evidence is written to `target/browser-builders-tests/results.json`. The Node test expects modules built with the default `web` target.
