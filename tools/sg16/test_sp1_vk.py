#!/usr/bin/env python3
"""SP1's Groth16 wrapper key, read from sp1-contracts, as a one-input sg16 key.

For every gnark Groth16 verifier found under vendor/sp1-contracts/contracts/src/<version>/ (or --dir):
  - extract the key (sp1.vk_from_gnark_solidity): refuse gnark's commitment extension, detect the G2
    coefficient order by curve and subgroup membership, check every point;
  - report the number of public inputs and the lines of SP1Verifier*.sol that build the inputs and decode
    the proof (to confirm sp1.LAYOUTS by reading, not by assumption);
  - with --fold LAYOUT: fold every input except the public-values digest (placeholder constants unless given)
    and print the predicted cost of the update leaf (bridge-guest/liquid.py) for that key, with a synthetic
    network config and escrow.

    python3 tools/bootstrap-deps.py   # vendor/sp1-helios with the sp1-contracts submodule it pins
    python3 tools/sg16/test_sp1_vk.py [--version v6.1.0] [--fold v6.1.0] [--evidence R.json]
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'bridge-guest'))
from sg16 import fixtures, sp1  # noqa: E402
from sg16.ref import ROOT  # noqa: E402
from groth import bn254 as B  # noqa: E402


def interesting_lines(text):
    keep = re.compile(r'function verifyProof|abi\.decode|inputs\[|uint256\[\d+\]|hashPublicValues|sha256|VERSION'
                      r'|VERIFIER_HASH|exitCode|vkRoot|proofNonce|<< 253', re.I)
    return [f'{i + 1}: {l.rstrip()}' for i, l in enumerate(text.splitlines()) if keep.search(l)]


def function_hash(text, name):
    m = re.search(rf'function {name}\(\).*?return\s+(0x[0-9a-fA-F]+);', text, re.S)
    assert m, f'{name} not found in SP1 wrapper'
    return int(m.group(1), 16)


def main():
    ap = argparse.ArgumentParser()
    # default: the sp1-contracts commit that sp1-helios v1.3.0 pins as its submodule, else a separate clone
    pinned = ROOT / 'vendor' / 'sp1-helios' / 'contracts' / 'lib' / 'sp1-contracts' / 'contracts' / 'src'
    ap.add_argument('--dir', default=str(pinned if pinned.exists()
                                         else ROOT / 'vendor' / 'sp1-contracts' / 'contracts' / 'src'))
    ap.add_argument('--version', help='only this subdirectory, e.g. v6.1.0')
    ap.add_argument('--fold', choices=sorted(sp1.LAYOUTS), help='fold with this layout and predict the program cost')
    ap.add_argument('--program-vkey', type=lambda s: int(s, 0), help='actual SP1 program vkey for folding')
    ap.add_argument('--vk-root', type=lambda s: int(s, 0), help='actual SP1 verifier key root for folding')
    ap.add_argument('--nonce', type=lambda s: int(s, 0), help='fixed proof nonce for folding (SDK default: zero)')
    ap.add_argument('--evidence')
    a = ap.parse_args()
    base = Path(a.dir)
    if not base.exists():
        sys.exit(f'{base} missing: git clone https://github.com/succinctlabs/sp1-contracts vendor/sp1-contracts')
    dirs = [base / a.version] if a.version else sorted(p for p in base.iterdir() if p.is_dir())
    report = {}
    for d in dirs:
        entry = report.setdefault(d.name, {})
        for f in sorted(d.glob('*.sol')):
            text = f.read_text()
            if 'SP1Verifier' in f.name:
                selector = function_hash(text, 'VERIFIER_HASH') >> 224
                root = function_hash(text, 'VK_ROOT')
                if a.vk_root is not None and f.name == 'SP1VerifierGroth16.sol':
                    assert a.vk_root == root, '--vk-root differs from pinned SP1 verifier source'
                entry[f.name] = dict(verifier_selector=f'{selector:08x}', vk_root=hex(root),
                                     lines=interesting_lines(text))
            if 'ALPHA_X' not in text:
                continue
            try:
                vk, notes = sp1.vk_from_gnark_solidity(text)
            except (ValueError, AssertionError, KeyError) as e:
                entry[f.name] = dict(error=f'{type(e).__name__}: {e}')
                print(f'{d.name}/{f.name}: {e}')
                continue
            n = len(vk['ic']) - 1
            info = dict(public_inputs=n, g2_order=notes)
            print(f'{d.name}/{f.name}: commitment-free Groth16 key, {n} public inputs, G2 order {notes}')
            if a.fold:
                order = sp1.LAYOUTS[a.fold][2]
                if n != len(order):
                    info['fold'] = f'layout {a.fold} has {len(order)} inputs, key has {n}'
                else:
                    actual = dict(program_vkey=a.program_vkey, vk_root=a.vk_root, proof_nonce=a.nonce, exit_code=0)
                    use_actual = all(actual[name] is not None for name in order if name != 'public_values_digest')
                    if (any(actual[name] is not None for name in ('program_vkey', 'vk_root', 'proof_nonce'))
                            and not use_actual):
                        ap.error('supply --program-vkey, --vk-root and --nonce together')
                    fixed = actual if use_actual else {name: int.from_bytes(fixtures.h(name), 'big') % B.R
                                                       for name in order if name != 'public_values_digest'}
                    folded = sp1.one_input_key(vk, a.fold, **fixed)
                    import liquid
                    from sg16 import harness
                    k = harness.consts(fixtures.config())
                    _, _, cost = liquid.BridgeGuestVerifier.compile(folded, k,
                                                                    config=fixtures.h('synthetic network config'),
                                                                    escrow=fixtures.h('synthetic escrow')[:20])
                    info['fold'] = dict(layout=a.fold, placeholders=not use_actual,
                                        fixed_values={n: hex(v) for n, v in fixed.items()}, unpadded_cost=cost)
                    print(f'  folded to one input with {"actual" if use_actual else "placeholder"} constants: '
                          f'unpadded program cost {cost:,} mWU')
            entry[f.name] = info
    for d, entry in report.items():
        for name, e in entry.items():
            for line in e.get('lines', []):
                print(f'{d}/{name} {line}')
    if a.evidence:
        with open(a.evidence, 'w') as f:
            json.dump(dict(test='tools/sg16/test_sp1_vk.py', results=report), f, indent=1)


if __name__ == '__main__':
    main()
