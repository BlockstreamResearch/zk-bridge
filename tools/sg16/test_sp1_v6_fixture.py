#!/usr/bin/env python3
"""Check a published SP1 v6.0.0 Groth16 test proof against its real key and the folded key.

This fixture is from the pinned sp1-contracts submodule. It is not a Helios or Sepolia proof, and its
v6.0.0 key is not the v6.1.0 key the update leaf folds; the proof layout is the same (sp1.LAYOUTS).
"""
import argparse
import json
import re
from pathlib import Path

from sg16 import sp1
from sg16.ref import ROOT
from groth import bn254 as B

VERSION = 'v6.0.0'
BASE = ROOT / 'vendor/sp1-helios/contracts/lib/sp1-contracts/contracts'


def constant_bytes(source, name):
    m = re.search(rf'\b{name}\s*=\s*hex"([0-9a-fA-F]+)"', source)
    assert m, f'{name} missing from fixture'
    return bytes.fromhex(m.group(1))


def function_hash(source, name):
    m = re.search(rf'function {name}\(\).*?return\s+(0x[0-9a-fA-F]+);', source, re.S)
    assert m, f'{name} missing from verifier'
    return bytes.fromhex(m.group(1)[2:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--evidence', type=Path)
    args = ap.parse_args()
    wrapper = (BASE / f'src/{VERSION}/SP1VerifierGroth16.sol').read_text()
    key = (BASE / f'src/{VERSION}/Groth16Verifier.sol').read_text()
    fixture = (BASE / 'test/SP1VerifierGroth16V6.sol').read_text()
    m = re.search(r'\bPROGRAM_VKEY\s*=\s*bytes32\((0x[0-9a-fA-F]+)\)', fixture)
    assert m, 'program vkey missing from fixture'
    vkey = int(m.group(1), 16)
    public_values = constant_bytes(fixture, 'PUBLIC_VALUES')
    proof_bytes = constant_bytes(fixture, 'PROOF_BYTES')
    vk, g2_order = sp1.vk_from_gnark_solidity(key)
    assert len(vk['ic']) == 6, 'expected five public inputs'
    selector, header, proof = sp1.decode_proof(proof_bytes, 'v6.1.0')
    expected_selector = function_hash(wrapper, 'VERIFIER_HASH')[:4]
    expected_root = int.from_bytes(function_hash(wrapper, 'VK_ROOT'), 'big')
    assert selector == expected_selector, 'wrong SP1 verifier selector'
    assert header == dict(exit_code=0, vk_root=expected_root, proof_nonce=0), 'unexpected proof header'
    digest = sp1.public_values_digest(public_values)
    fixed = dict(program_vkey=vkey, exit_code=0, vk_root=expected_root, proof_nonce=0)
    inputs = sp1.wrapper_inputs('v6.1.0', public_values_digest=digest, **fixed)
    original = B.groth16_verify(vk, proof, inputs)
    folded = sp1.one_input_key(vk, 'v6.1.0', **fixed)
    folded_valid = B.groth16_verify(folded, proof, [digest])
    wrong_digest_rejected = not B.groth16_verify(folded, proof, [(digest + 1) % B.R])
    assert original and folded_valid and wrong_digest_rejected, 'real proof/folding check failed'
    result = dict(test='tools/sg16/test_sp1_v6_fixture.py', version=VERSION,
                  source='vendor/sp1-helios/contracts/lib/sp1-contracts/contracts/test/SP1VerifierGroth16V6.sol',
                  public_inputs=5, g2_order=g2_order, selector=selector.hex(), vk_root=hex(expected_root),
                  program_vkey=hex(vkey), public_values_digest=hex(digest),
                  original_valid=original, folded_valid=folded_valid,
                  wrong_digest_rejected=wrong_digest_rejected,
                  limitation='SP1 v6.0.0 fixture; not the v6.1.0 Helios key or an Ethereum/Liquid bridge proof')
    if args.evidence:
        args.evidence.write_text(json.dumps(result, indent=1) + '\n')
    print('actual SP1 v6.0.0 proof: original and folded keys accept; changed digest rejected')


if __name__ == '__main__':
    main()
