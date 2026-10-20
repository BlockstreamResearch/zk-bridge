"""The single Groth16 public input of the update leaf.

SP1's Groth16 wrapper exposes SHA256(public values) with the top three bits cleared (< 2^253 < r) as its
public-values input; the update leaf recomputes that digest from its own constants and the spent state
(bridge-guest/liquid.py) and requires the opened input to equal it.
"""
MASK = 2**253 - 1


def public_input(d):
    """The Groth16 public input of a 32-byte digest."""
    return int.from_bytes(d, 'big') & MASK
