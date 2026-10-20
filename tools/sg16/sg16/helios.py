"""The Liquid bridge state commitments, shared by the update leaf (bridge-guest/liquid.py), the claim crate
(contracts/simplicity/src/claim.rs) and the guest (sg16-bridge-core):

    state UTXO   P2TR(NUMS, {{update leaf, claim leaf}, tapleaf(state_hash)})
    state_hash   SHA256(STATE_TAG || lc || acc || claimed_root)
    lc           SHA256(LC_TAG || be64(head) || header || syncCommitteeHash)
    STATE_TAG    SHA256("liquid-bridge-poc/state")
    LC_TAG       SHA256("liquid-bridge-poc/lc")

lc commits to the light-client store the next proof starts from: the finalized slot, its beacon header root
and the sync committee root.  acc is the escrow's deposit accumulator.  claimed_root is the root of the claimed
tree, a depth-32 SHA-256 sparse Merkle tree indexed by deposit number whose slot i is CLAIMED_LEAF =
SHA256("liquid-bridge-poc/claimed") once deposit i is paid and 32 zero bytes before; it depends only on the set of
paid deposits, not on the order they were paid in.
"""
import hashlib

STATE_TAG = hashlib.sha256(b'liquid-bridge-poc/state').digest()
LC_TAG = hashlib.sha256(b'liquid-bridge-poc/lc').digest()
CLAIMED_LEAF = hashlib.sha256(b'liquid-bridge-poc/claimed').digest()
CLAIMED_DEPTH = 32


def sha(b):
    return hashlib.sha256(b).digest()


def lc(head, header, committee):
    return sha(LC_TAG + head.to_bytes(8, 'big') + header + committee)


def claimed_root(indices):
    """The claimed root of the deposit indices `indices` (integers below 2^32, each at most once)."""
    level = {}
    for i in indices:
        if type(i) is not int or not 0 <= i < 1 << CLAIMED_DEPTH:
            raise ValueError(f'claimed index {i!r} is outside the claimed tree')
        if i in level:
            raise ValueError(f'claimed index {i} is repeated')
        level[i] = CLAIMED_LEAF
    zero = bytes(32)
    for _ in range(CLAIMED_DEPTH):
        level = {j: sha(level.get(2 * j, zero) + level.get(2 * j + 1, zero)) for j in {i >> 1 for i in level}}
        zero = sha(zero + zero)
    return level.get(0, zero)


def state_hash(lc_, acc, claimed_root_):
    assert len(claimed_root_) == 32, 'claimed_root is 32 bytes'
    return sha(STATE_TAG + lc_ + acc + claimed_root_)
