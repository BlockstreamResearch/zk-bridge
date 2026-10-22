#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
output=${BROWSER_BUILDERS_OUT:-"$root/target/browser-builders"}
target=${BROWSER_BUILDERS_TARGET:-web}

# Homebrew LLVM supports wasm; Apple's system clang does not. Linux uses PATH.
if [[ -z "${CC_wasm32_unknown_unknown:-}" ]]; then
  if [[ -x /opt/homebrew/opt/llvm/bin/clang ]]; then
    export CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang
  else
    export CC_wasm32_unknown_unknown=clang
  fi
fi

if [[ -z "${AR_wasm32_unknown_unknown:-}" ]]; then
  if [[ -x /opt/homebrew/opt/llvm/bin/llvm-ar ]]; then
    export AR_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/llvm-ar
  else
    export AR_wasm32_unknown_unknown=llvm-ar
  fi
fi

export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$root/target/browser-builders-cargo"}

for action in update claim; do
  crate=$action
  [[ "$action" != update ]] || crate=tx
  wasm-pack build "$root/tools/sg16/bridge-guest/testnet/$crate" \
    --release --target "$target" --out-dir "$output/$action" --out-name "$action" \
    --no-opt -- --locked
done
