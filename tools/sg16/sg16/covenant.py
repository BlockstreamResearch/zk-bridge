"""The update leaf's building blocks on top of simple-groth16: Simplicity expressions for the Elements
introspection the leaf checks, and the Groth16 verifier whose public input those checks open.

The reference verifier binds its single public input to `sig_all_hash` through a Merkle tree whose other
leaves come from the witness, so the transaction rules cannot see what the proof says.  `BridgeVerifier`
instead hands the public input, and fields carried in the witness, to rules computed from introspection
jets; a subclass (bridge-guest/liquid.py `BridgeGuestVerifier`) supplies the fields and the rules through the
_state_* and _open hooks.  Verifier and rules are one program (one taproot leaf), so neither can be satisfied
alone.  The pairing check's Fiat-Shamir transcript hashes the public input word the rules open
(groth/pairing.py `setup`), so the challenges depend on it too.

Token rules (`token_rules`), shared with the claim leaf: the state output holds the bridge asset's only
reissuance token, blinded with one of two public factors A and B that alternate with every spend, and the
constant value commitment 1 * H_token.  Anyone can build the next spend, so a relayer cannot freeze the token
behind a private blinding factor.

Cost model: Sym (groth/sym.py, rust-simplicity 0.9).  Option and Conf values are unwrapped with
`assertl`/`assertr`, whose hidden branch is a `fail` node: cost 100 + kept child, the same before and after
pruning.
"""
from .ref import REF  # noqa: F401
from . import jets  # noqa: F401  (registers the Elements jet costs)
from groth import pairing
from groth.dsl import ensure, wpair, balanced_paths
from groth.fp import Fp
from groth.groth16 import Groth16
from groth.sym import E, Sym, is_sym, SHA_CTX_W

NUMS = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
FAIL = 'fail 0x5347313642524944474546414c4c0001'  # 128-bit entropy of the hidden, never-taken branches


# Sums.  e: Γ -> L + R.  The hidden branch fails, so these assert the injection and return its payload.
def right(be, e, w):
    """The right payload (an Option's Some, a Conf's explicit value) of width w; fails on the left."""
    ensure(e.w >= 1 + w, 'sum width')
    return be.comp(be.pair(e, be.unit()), E('assertr #{' + FAIL + '} (take (iden))', w, 300 + w))


def left(be, e, w):
    """The left payload (a Conf's (prefix bit, x) commitment) of width w; fails on the right."""
    ensure(e.w >= 1 + w, 'sum width')
    return be.comp(be.pair(e, be.unit()), E('assertl (take (iden)) #{' + FAIL + '}', w, 300 + w))


def none(be, e):
    """Unit-typed check that an Option is None."""
    return be.comp(be.pair(e, be.unit()), E('assertl (unit) #{' + FAIL + '}', 0, 200))


def snd(be, e, w):
    return be.comp(e, E('drop (iden)', w, 200 + w))


def ujet(be, name, w):
    """A jet on unit input."""
    return be.jet(name, be.unit(), w)


def ijet(be, name, i, w, bits=32):
    """A jet on a constant index."""
    return be.jet(name, be.const(bits, i), w)


def conf_is(be, e, const):
    """1-bit flag: the (prefix bit, x) value of e equals the constant (bit, x)."""
    cb, cx = const

    def body(acc):
        a = acc[0]
        bit = be.sub(a, 'O', 1)
        return be.and1(bit if cb else be.not1(bit), be.eq256(be.sub(a, 'I', 256), be.const(256, cx)))
    return be.scope([e], body)


def conf_const(consts, name):
    c = consts[name]
    return c['bit'], int(c['x'], 16)


def token_rules(be, consts):
    """Unit checks: the spent token is blinded with public factor A and output 0 with B, or B and A; output
    0's value commitment is the constant 1 * H_token.  Every relayer can build the next reissuance."""
    A, B, V = conf_const(consts, 'token_a'), conf_const(consts, 'token_b'), conf_const(consts, 'token_value')

    def in_asset():
        return left(be, ujet(be, 'current_asset', 258), 257)

    def out_asset():
        return left(be, right(be, ijet(be, 'output_asset', 0, 259), 258), 257)
    out_value = left(be, snd(be, right(be, ijet(be, 'output_amount', 0, 517), 516), 258), 257)
    return [be.verify(be.or1(be.and1(conf_is(be, in_asset(), A), conf_is(be, out_asset(), B)),
                             be.and1(conf_is(be, in_asset(), B), conf_is(be, out_asset(), A)))),
            be.verify(conf_is(be, out_value, V))]


def explicit_asset(be, i):
    return right(be, right(be, ijet(be, 'output_asset', i, 259), 258), 256)


def sha_chain(be, items):
    """SHA-256 of the concatenation of (byte count, expression) items, n in {2, 4, 8, 16, 32}."""
    ctx = be.jet('sha_256_ctx_8_init', be.unit(), SHA_CTX_W)
    for n, x in items:
        ctx = be.jet(f'sha_256_ctx_8_add_{n}', be.pair(ctx, x), SHA_CTX_W)
    return be.jet('sha_256_ctx_8_finalize', ctx, 256)


def p2tr_hash(be, key):
    """SHA256(0x51 0x20 || key): the script hash of a v1 witness program."""
    return sha_chain(be, [(2, be.const(16, 0x5120)), (32, key)])


def bind_masked(be, h, a):
    """Unit check: a equals the 256-bit digest h with its top three bits cleared (as groth16.py `binding`)."""
    def masked(accs):
        hv, av = accs
        top = be.jet('and_8', be.pair(be.sub(hv, 'OOOOO', 8), be.const(8, 0x1f)), 8)
        m = be.pair(be.pair(be.pair(be.pair(be.pair(top, be.sub(hv, 'OOOOI', 8)), be.sub(hv, 'OOOI', 16)),
                                    be.sub(hv, 'OOI', 32)), be.sub(hv, 'OI', 64)), be.sub(hv, 'I', 128))
        return be.verify(be.eq256(av, m))
    return be.scope([h, a], masked)


class BridgeVerifier(Groth16):
    """simple-groth16's verifier with one public input opened by transaction rules.

    Witness node w_in: (main, state); main is the reference layout (public inputs, then -A, B, C, a_c and the
    challenges r, z), and `state` the fields the rules read.  Each loop step's leaf and the quotient Q are
    witness nodes of their own (groth/pairing.py `witness_nodes`).  A subclass gives the fields and the rules
    through the _state_* and _open hooks.  `opened` is the index of the public input the rules open; any other
    inputs (keys with several variable inputs) are only range-checked and hashed into the transcript.

    The program's bytes earn more budget than it costs, so the witness carries no padding."""

    def __init__(self, fp, vk, consts, b=None, opened=0):
        super().__init__(fp, vk, b=b, depth=0)
        ensure(0 <= opened < self.n, 'opened input index')
        self.consts, self.opened = consts, opened

    # hooks: the fields part of the witness, and the rules that open the public input
    def _state_type(self):
        """The Simplicity type of the fields."""
        raise NotImplementedError

    def _state_shape(self):
        """The Sym shape of the fields."""
        raise NotImplementedError

    def _state_bits(self):
        raise NotImplementedError

    def _state_value(self, wit):
        """The witness value of the fields of `wit`."""
        raise NotImplementedError

    def _num_state(self, wit):
        """The fields of `wit` for the numeric model."""
        raise NotImplementedError

    def _open(self, be, state, a):
        """Unit-typed: the rules and the binding of public input `a` (Sym accessors)."""
        raise NotImplementedError

    def _num_open(self, state, a):
        """Numeric model of the binding of public input `a`."""
        raise NotImplementedError

    def main_bits(self):
        return 256 * self.n + pairing.witness_bits()

    def witness_bits(self):
        """The bits of w_in (the other witness nodes are read where they are)."""
        return self.main_bits() + self._state_bits()

    def witness_type(self):
        return f'({super().witness_type()} * {self._state_type()})'

    def witness_value(self, wit):
        """The witness as harness value specs (tools/sg16-harness), by witness node."""
        nodes = super().witness_value(wit)
        nodes['w_in'] = wpair(nodes['w_in'], self._state_value(wit))
        return nodes

    def witness_shape(self):
        return [super().witness_shape()[0], self._state_shape()]

    def num_input(self, wit):
        return [super().num_input(wit)[0], self._num_state(wit)]

    def verify(self, acc):
        be = self.be
        main, state = acc
        a = main[0][self.opened]
        if not is_sym(be):  # numeric model: the fields stand in for the introspection
            self.checks(main)
            self._num_open(state, a)
            return 0
        out = be.with_env(be.proj(balanced_paths(2)[0], self.main_bits()), self.witness_shape()[0], self.checks)
        opened = self._open(be, state, a)
        self.parts['rules and binding'] = opened.c
        return be.checks([out, opened])

    @classmethod
    def compile(cls, vk, consts, b=None, **kw):
        """(program text, generator, predicted cost in mWU).

        The loop state's bounds (pairing.bounds) are a fixed point found on the numeric backend, which the CRT
        arithmetic of every step assumes of its inputs.  Building the program records the bound of each step's
        outputs (pairing.py step_body, qchunk_body, `<name>_out`); they are checked here against the fixed point, so
        that a step whose outputs could exceed what the next step assumes stops the build instead of wrapping.  The
        sampled `<name>_out` values that come with the bounds are dropped first, so that only this build's step bodies
        set the values checked."""
        be = Sym(0)
        b = {k: v for k, v in (b or pairing.bounds()).items() if not k.endswith('_out')}
        g = cls(Fp(be), vk, consts, b=b, **kw)
        body = g.program()
        state = ('N', 'D', 'acc', 'x', 'y', 'qz')
        over = {nm: (g.pc.b.get(nm + '_out'), g.pc.b[nm]) for nm in state
                if not isinstance(g.pc.b.get(nm + '_out'), int) or g.pc.b[nm + '_out'] > g.pc.b[nm]}
        ensure(not over, f'loop-state bounds of the built program exceed their fixed point: {over}')
        be.em.define('w_in', 'witness', f'_ -> {g.witness_type()}')
        be.em.define('main', f'comp w_in ({body.t})')
        return be.em.text(), g, 2 * (100 + g.witness_bits()) + body.c
