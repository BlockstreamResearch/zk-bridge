"""Liquid update leaf for the sg16 bridge update guest (program/src/main.rs).

The leaf is the Groth16 verifier for the guest's (folded) SP1 key plus these rules over the bridge state
(tools/sg16/sg16/helios.py), opening the guest's fixed 272-byte public values:

    state UTXO   P2TR(NUMS, {{this leaf, claim leaf}, tapleaf(state_hash(lc, acc, claimed_root))})
    transaction  inputs [state, fee]; outputs [successor, explicit fee]; no issuance
    old state    tappath_hash = SHA256(sibling || tapleaf(state_hash(lc, acc, claimed_root)))
                                                                            (witness lc, acc, claimed_root)
    successor    output 0 = P2TR(NUMS, {{tapleaf_hash, sibling}, tapleaf(state_hash(new_lc, new_acc, claimed_root))})
    token        sg16.covenant.token_rules; output 1 is a fee in the fee asset
    binding      public input = SHA256(public values) & (2^253 - 1), the public values being
                   TAG || CONFIG || ESCROW || SLOT_KEY || lc || new_lc || new_acc || exec_root || be64(exec_block) || be64(new_head)
                 with TAG, CONFIG (network), ESCROW and SLOT_KEY compiled in, lc the spent state's.

So a proof is accepted only for the configured network, escrow and slot, only from the state it starts at, and the
successor commits exactly the proven store and accumulator, with the spent state's claimed_root (the claimed tree,
sg16/helios.py) carried unchanged.  The light-client fields themselves never appear on Liquid: the guest commits lc
values computed from the stores it verified.
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg16 import statement as st  # noqa: E402
from sg16.covenant import (BridgeVerifier, NUMS, bind_masked, explicit_asset, ijet, none, p2tr_hash,  # noqa: E402
                           right, sha_chain, token_rules, ujet)
from sg16.helios import STATE_TAG  # noqa: E402
from groth.dsl import ensure, wv, wpair, wbalanced, Tbalanced  # noqa: E402
from groth.sym import E, Sym  # noqa: E402

# Domain tags, as sg16-bridge-core (bridge-guest/core/src/lib.rs) commits them.
UPDATE_TAG = hashlib.sha256(b'liquid-bridge-poc/update').digest()
LC_TAG = hashlib.sha256(b'liquid-bridge-poc/lc').digest()
CONFIG_TAG = hashlib.sha256(b'liquid-bridge-poc/eth-config').digest()

# The update leaf's witness fields, in order (name, bits): one balanced product, read back by sg16-testnet
# `recover` (testnet/tx/src/main.rs `update_fields`) and by bridge-core/lib/update.js `updateFields`.
FIELDS = [('lc', 256), ('acc', 256), ('sibling', 256), ('new_lc', 256), ('new_acc', 256), ('exec_root', 256),
          ('claimed_root', 256), ('exec_block', 64), ('new_head', 64)]


def sha(b):
    return hashlib.sha256(b).digest()


def lc(slot, header, committee):
    return sha(LC_TAG + slot.to_bytes(8, 'big') + header + committee)


def config_hash(genesis_root, forks_encoding):
    return sha(CONFIG_TAG + genesis_root + sha(forks_encoding))


def public_values(config, escrow, slot_key, f):
    """The guest's 272 bytes (sg16-bridge-core UpdateOutputs::encode) for the fields f."""
    pv = (UPDATE_TAG + config + bytes(12) + escrow + slot_key.to_bytes(32, 'big') + f['lc'] + f['new_lc'] + f['new_acc']
          + f['exec_root'] + f['exec_block'].to_bytes(8, 'big') + f['new_head'].to_bytes(8, 'big'))
    assert len(pv) == 272
    return pv


def public_input(config, escrow, slot_key, f):
    return st.public_input(sha(public_values(config, escrow, slot_key, f)))


class BridgeGuestUpdate:
    def __init__(self, be, consts, config, escrow, slot_key=0):
        ensure(len(config) == 32 and len(escrow) == 20, 'config and escrow')
        self.be, self.k, self.config, self.escrow, self.slot_key = be, consts, config, escrow, slot_key

    def checks(self, F, a):
        be = self.be

        def eq32(e, v):
            return be.verify(be.jet('eq_32', be.pair(e, be.const(32, v)), 1))

        def leaf_of(lc_e, acc, claimed_root):
            h = sha_chain(be, [(32, be.const(256, int.from_bytes(STATE_TAG, 'big'))),
                               (32, lc_e), (32, acc), (32, claimed_root)])
            return be.jet('build_tapleaf_simplicity', h, 256)
        u = [
            eq32(ujet(be, 'current_index', 32), 0),
            eq32(ujet(be, 'num_inputs', 32), 2),
            eq32(ujet(be, 'num_outputs', 32), 2),
            none(be, right(be, ijet(be, 'issuance', 0, 3), 2)),
            none(be, right(be, ijet(be, 'issuance', 1, 3), 2)),
            be.verify(right(be, ijet(be, 'output_is_fee', 1, 2), 1)),
            be.verify(be.eq256(explicit_asset(be, 1), be.const(256, int(self.k['fee_asset'], 16)))),
            be.verify(be.eq256(ujet(be, 'tappath_hash', 256),
                               sha_chain(be, [(32, F['sibling']),
                                              (32, leaf_of(F['lc'], F['acc'], F['claimed_root']))]))),
        ]
        covenants = be.jet('build_tapbranch', be.pair(ujet(be, 'tapleaf_hash', 256), F['sibling']), 256)
        new_leaf = leaf_of(F['new_lc'], F['new_acc'], F['claimed_root'])
        key = be.jet('build_taptweak',
                     be.pair(be.const(256, NUMS), be.jet('build_tapbranch', be.pair(covenants, new_leaf), 256)), 256)
        u.append(be.verify(be.eq256(right(be, ijet(be, 'output_script_hash', 0, 257), 256), p2tr_hash(be, key))))
        u += token_rules(be, self.k)
        pv = [(32, be.const(256, int.from_bytes(UPDATE_TAG, 'big'))),
              (32, be.const(256, int.from_bytes(self.config, 'big'))),
              (32, be.const(256, int.from_bytes(self.escrow, 'big'))),
              (32, be.const(256, self.slot_key)),
              (32, F['lc']), (32, F['new_lc']), (32, F['new_acc']), (32, F['exec_root']),
              (8, F['exec_block']), (8, F['new_head'])]
        u.append(bind_masked(be, sha_chain(be, pv), a))
        return be.checks(u)


def _open_scope(be, consts, config, escrow, slot_key, accs, a):
    names = [n for n, _ in FIELDS]
    return be.scope(list(accs) + [a],
                    lambda acc: BridgeGuestUpdate(be, consts, config, escrow, slot_key).checks(
                        dict(zip(names, acc[:-1])), acc[-1]))


def field_type():
    return Tbalanced([f'2^{b}' for _, b in FIELDS])


def field_shape():
    return [E('', b, 0) for _, b in FIELDS]


def field_value(f):
    return wbalanced([wv(b, f[n] if b == 64 else int.from_bytes(f[n], 'big')) for n, b in FIELDS])


def rules_program(consts, config, escrow, slot_key=0):
    """The leaf's rules alone, public input read from the witness (fields, input): fast tests, NOT a bridge."""
    be = Sym(0)
    width = sum(b for _, b in FIELDS) + 256
    be.env[0] = width
    accs = be._unpack('', [field_shape(), E('', 256, 0)])
    body = _open_scope(be, consts, config, escrow, slot_key, accs[0], accs[1])
    be.em.define('w_in', 'witness', f'_ -> ({field_type()} * 2^256)')
    be.em.define('main', f'comp w_in ({body.t})')
    return be.em.text(), 2 * (100 + width) + body.c


def rules_witness(f, x):
    return {'w_in': wpair(field_value(f), wv(256, x))}


class BridgeGuestVerifier(BridgeVerifier):
    """Groth16 verifier for the guest's folded SP1 key with the bridge-guest update opening."""

    def __init__(self, fp, vk, consts, b=None, opened=0, config=None, escrow=None, slot_key=0):
        super().__init__(fp, vk, consts, b=b, opened=opened)
        ensure(config is not None and escrow is not None, 'config and escrow')
        self.config, self.escrow, self.slot_key = config, escrow, slot_key

    def _state_type(self):
        return field_type()

    def _state_shape(self):
        return field_shape()

    def _state_bits(self):
        return sum(b for _, b in FIELDS)

    def _state_value(self, wit):
        return field_value(wit['fields'])

    def _num_state(self, wit):
        return wit['fields']

    def _open(self, be, state, a):
        return _open_scope(be, self.consts, self.config, self.escrow, self.slot_key, state, a)

    def _num_open(self, f, a):
        ensure(a == public_input(self.config, self.escrow, self.slot_key, f),
               'bridge guest public values binding failed')

    def witness_fields(self, proof, inputs, f):
        ensure(inputs[self.opened] == public_input(self.config, self.escrow, self.slot_key, f),
               'opened input is the public-values digest')
        wit = super(BridgeVerifier, self).witness(proof, inputs)
        if wit is None:
            return None
        wit['fields'] = f
        return wit
