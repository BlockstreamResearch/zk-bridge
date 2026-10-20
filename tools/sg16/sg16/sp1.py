"""Multi-input Groth16 keys for the one-input sg16 verifier: IC_0 folding, and SP1 key/proof decoding.

Folding.  Groth16 checks e(A, B) = e(alpha, beta) e(L, gamma) e(C, delta) with L = IC_0 + sum_i a_i IC_(i+1).
If input i always takes the same value v (e.g. SP1's program verifying-key hash for our guest), v IC_(i+1)
is a constant point, so the key
    IC'_0 = IC_0 + sum_(fixed i) v_i IC_(i+1),   IC' = [IC'_0] + [IC_(j+1) for the variable j]
gives the same L exactly when the fixed inputs equal the folded values.  A verifier for the folded key
therefore accepts precisely the proofs of statements whose fixed inputs are those constants, and its MSM,
the only part of the verifier whose cost depends on the inputs (8.7 M mWU per 254-bit input), covers only
the variable inputs.  Folding is done when the program is generated; the program keeps one public input.

SP1.  SP1's Groth16 wrapper commits to sha256(public values) with the top three bits cleared
(statement.public_input), the one input the update leaf opens.  The other wrapper inputs (program vkey, exit
code, verifying-key root, proof nonce) are folded.  The v6.1.0 input order and proof-byte layout below are
those of the pinned sp1-contracts source (SP1VerifierGroth16.sol `verifyProof`, read by test_sp1_vk.py).  This
source check does not substitute for verifying an actual SP1 proof against the folded key.
"""
import hashlib
import re

from .ref import REF  # noqa: F401
from . import statement as st
from groth import bn254 as B

MASK = st.MASK


def fold(vk, fixed):
    """(folded key, positions of the variable inputs).  fixed: {input index (0-based): value}."""
    ic = vk['ic']
    n = len(ic) - 1
    for i, v in fixed.items():
        assert 0 <= i < n and 0 <= v < B.R, f'fixed input {i} = {v}'
    acc = ic[0]
    for i, v in sorted(fixed.items()):
        acc = B.g1_add(acc, B.g1_mul(ic[i + 1], v))
    assert acc is not None, 'the folded IC_0 is the point at infinity'
    variable = [j for j in range(n) if j not in fixed]
    return dict(vk, ic=[acc] + [ic[j + 1] for j in variable]), variable


# gnark's exported Solidity verifier stores the key as decimal or hex uint256 constants: ALPHA_X/Y,
# BETA_NEG_X_0/X_1/Y_0/Y_1 (and GAMMA_NEG, DELTA_NEG), CONSTANT_X/Y (IC_0), PUB_i_X/Y (IC_(i+1)).
# beta, gamma, delta are stored negated, because the contract checks e(A,B) e(C,-delta) e(alpha,-beta) e(L,-gamma) = 1.
CONST = re.compile(r'uint256\s+(?:(?:internal|private|public)\s+)?constant\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;')


def solidity_constants(text):
    return {name: int(v, 0) for name, v in CONST.findall(text)}


def _g2(k, prefix):
    """The G2 point of four constants, trying both coefficient orders; exactly one must be a valid
    point of the order-r subgroup (a wrong order gives an off-twist point except with negligible chance)."""
    x0, x1, y0, y1 = (k[f'{prefix}_{c}'] for c in ('X_0', 'X_1', 'Y_0', 'Y_1'))
    found = []
    for name, (x, y) in (('c0 first', (B.Fp2(x0, x1), B.Fp2(y0, y1))), ('c1 first', (B.Fp2(x1, x0), B.Fp2(y1, y0)))):
        if B.g2_on_curve(x, y) and B.g2_in_subgroup((x, y)):
            found.append((name, (x, y)))
    assert len(found) == 1, f'{prefix}: {len(found)} valid coefficient orders'
    return found[0]


def vk_from_gnark_solidity(text):
    """(vk dict for groth.groth16, notes).  Refuses keys with gnark's commitment extension, which adds a
    pairing the sg16 verifier does not implement."""
    if re.search(r'PEDERSEN_G|calldata commitments|commitmentPok|COMMITMENT_KEY', text):
        raise ValueError('gnark commitment extension present: not supported by the one-pairing-product verifier')
    k = solidity_constants(text)
    alpha = (k['ALPHA_X'], k['ALPHA_Y'])
    assert B.g1_on_curve(*alpha), 'alpha'
    notes, pts = {}, {}
    for name in ('BETA_NEG', 'GAMMA_NEG', 'DELTA_NEG'):
        order, pt = _g2(k, name)
        notes[name] = order
        pts[name] = B.g2_neg(pt)
    ic = [(k['CONSTANT_X'], k['CONSTANT_Y'])]
    i = 0
    while f'PUB_{i}_X' in k:
        ic.append((k[f'PUB_{i}_X'], k[f'PUB_{i}_Y']))
        i += 1
    assert all(B.g1_on_curve(*p) for p in ic), 'IC points'
    return dict(alpha=alpha, beta=pts['BETA_NEG'], gamma=pts['GAMMA_NEG'], delta=pts['DELTA_NEG'], ic=ic), notes


def proof_from_words(words):
    """(A, B, C) from the 8 uint256 words of a gnark/EVM Groth16 proof, detecting the G2 coefficient order."""
    assert len(words) == 8
    A, C = (words[0], words[1]), (words[6], words[7])
    assert B.g1_on_curve(*A) and B.g1_on_curve(*C), 'A, C on the curve'
    k = dict(P_X_0=words[2], P_X_1=words[3], P_Y_0=words[4], P_Y_1=words[5])
    _, Bpt = _g2(k, 'P')
    return A, Bpt, C


# Each layout is (selector bytes, header words before the 8 proof words, wrapper input order).
LAYOUTS = {
    # sp1-helios's pinned sp1-contracts v6.1.0/SP1VerifierGroth16.sol, verifyProof lines 64-72.
    'v6.1.0': (4, ['exit_code', 'vk_root', 'proof_nonce'],
               ['program_vkey', 'public_values_digest', 'exit_code', 'vk_root', 'proof_nonce']),
}


def public_values_digest(public_values):
    return int.from_bytes(hashlib.sha256(public_values).digest(), 'big') & MASK


def decode_proof(proof_bytes, layout):
    """(selector, header {name: value}, (A, B, C))."""
    sel, header, _ = LAYOUTS[layout]
    body = proof_bytes[sel:]
    words = [int.from_bytes(body[32 * i:32 * i + 32], 'big') for i in range(len(body) // 32)]
    assert len(body) == 32 * (len(header) + 8), f'{len(body)} bytes after the selector for layout {layout}'
    return proof_bytes[:sel], dict(zip(header, words[:len(header)])), proof_from_words(words[len(header):])


def wrapper_inputs(layout, **values):
    """The wrapper's public inputs in key order, from named values."""
    return [values[name] for name in LAYOUTS[layout][2]]


def one_input_key(vk, layout, **fixed_values):
    """Fold every wrapper input except the public-values digest.  Returns the one-input key."""
    order = LAYOUTS[layout][2]
    assert len(vk['ic']) == len(order) + 1, f'key has {len(vk["ic"]) - 1} inputs, layout {layout} has {len(order)}'
    fixed = {i: fixed_values[name] for i, name in enumerate(order) if name != 'public_values_digest'}
    folded, variable = fold(vk, fixed)
    assert variable == [order.index('public_values_digest')]
    return folded
