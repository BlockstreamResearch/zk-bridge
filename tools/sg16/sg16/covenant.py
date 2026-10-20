"""The update leaf's building blocks on top of simple-groth16: Simplicity expressions for the Elements
introspection the leaf checks, and the Groth16 verifier whose public input those checks open.

The reference verifier binds its single public input to `sig_all_hash` through a Merkle tree whose other
leaves come from the witness, so the transaction rules cannot see what the proof says.  `BridgeVerifier`
instead hands the public input, and fields carried in the witness, to rules computed from introspection
jets; a subclass (bridge-guest/liquid.py `BridgeGuestVerifier`) supplies the fields and the rules through the
_state_* and _open hooks.  Verifier and rules are one program (one taproot leaf), so neither can be satisfied
alone.

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
from groth import bn254
from groth.dsl import ensure, wv, wpair, wbit, wbalanced, Tbalanced, balanced_paths
from groth.fp import Fp, Val
from groth.groth16 import Groth16, PAD_BLOCK, PAD_BLOCK_COST
from groth.miller import N_STEPS, bounds
from groth.sym import E, Sym, words, is_sym, SHA_CTX_W

R = bn254.R
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

    Witness: (main, state[, padding]); main is the reference layout (public inputs, MSM slopes, -A, B, C,
    residue witness, slopes of B), and `state` the fields the rules read.  A subclass gives the fields and the
    rules through the _state_* and _open hooks.  `opened` is the index of the public input the rules open; any
    other inputs (keys with several variable inputs) are only range-checked."""

    def __init__(self, fp, vk, consts, w=5, b=None, pad_blocks=0, opened=0):
        super().__init__(fp, vk, w, b=b, pad_blocks=pad_blocks, depth=0)
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

    def _parts(self):
        return ['main', 'state'] + (['pad'] if self.pad_blocks else [])

    def main_bits(self):
        return 256 * (self.n + self.n * self.nwin + 32) + 2 + 512 * N_STEPS

    def witness_bits(self):
        return self.main_bits() + self._state_bits() + 4096 * self.pad_blocks

    def _main_type(self):
        T = lambda k: Tbalanced(['2^256'] * k)  # noqa: E731
        return (f'(({T(self.n)} * {T(self.n * self.nwin)}) * (({T(8)} * ({T(12)} * {T(12)})) * '
                f'((2 * 2) * {Tbalanced(["(2^256 * 2^256)"] * N_STEPS)})))')

    def witness_type(self):
        parts = dict(main=self._main_type, state=self._state_type, pad=lambda: Tbalanced([PAD_BLOCK] * self.pad_blocks))
        return Tbalanced([parts[p]() for p in self._parts()])

    def witness_value(self, wit):
        W = lambda ws: wbalanced([wv(256, x) for x in ws])  # noqa: E731
        main = wpair(wpair(W(wit['scalars']), W(wit['msm_hints'])),
                     wpair(wpair(W(wit['points']), wpair(W(wit['c']), W(wit['cinv']))),
                           wpair(wpair(wbit(wit['s'] >> 1), wbit(wit['s'] & 1)),
                                 wbalanced([wpair(wv(256, lx), wv(256, ly)) for lx, ly in wit['hints']]))))
        parts = dict(main=lambda: main, state=lambda: self._state_value(wit),
                     pad=lambda: wbalanced([wbalanced([wv(512, 0)] * 8) for _ in range(self.pad_blocks)]))
        return wbalanced([parts[p]() for p in self._parts()])

    def witness_shape(self, pad=True):
        bit = lambda: E('', 1, 0)  # noqa: E731
        main = [[words(self.n), words(self.n * self.nwin)],
                [[words(8), [words(12), words(12)]], [[bit(), bit()], [E('', 512, 0) for _ in range(N_STEPS)]]]]
        parts = dict(main=main, state=self._state_shape(), pad=[E('', 4096, 0) for _ in range(self.pad_blocks)])
        return [parts[p] for p in self._parts() if pad or p != 'pad']

    def num_input(self, wit):
        main = [[wit['scalars'], wit['msm_hints']],
                [[wit['points'], [wit['c'], wit['cinv']]], [[wit['s'] >> 1, wit['s'] & 1], wit['hints']]]]
        parts = dict(main=main, state=self._num_state(wit), pad=[0] * self.pad_blocks)
        return [parts[p] for p in self._parts()]

    def verify(self, acc):
        be, cv = self.be, self.cv
        parts = dict(zip(self._parts(), acc))
        (scalars, msm_hints), _ = parts['main']
        sc = [Val(a, R - 1) for a in scalars]
        if is_sym(be):
            state = cv.msm_sym(sc, be.subtree(msm_hints), self.tables, self.start, self.w, self.nbits)
            self.parts = {'msm': state.c}
            shape = [[E('', 256, 0), E('', 256, 0), words(self.n)], self.witness_shape(pad=False)[0]]
            out = be.with_env(be.pair(state, be.proj(balanced_paths(len(self._parts()))[0], self.main_bits())),
                              shape, self.checks)
            opened = self._open(be, parts['state'], scalars[self.opened])
            self.parts['rules and binding'] = opened.c
            extra = [opened] + (self.consume_padding(parts['pad']) if self.pad_blocks else [])
            return be.checks([out] + extra)
        # numeric model: the fields stand in for the introspection
        hints = [[Val(msm_hints[i * self.nwin + j], 0) for j in range(self.nwin)] for i in range(self.n)]
        (x, y), _ = cv.msm(sc, hints, self.tables, self.start, self.w, self.nbits)
        self._num_open(parts['state'], scalars[self.opened])
        return self.checks([[x.e, y.e, scalars], parts['main']])

    @classmethod
    def compile(cls, vk, consts, w=5, pad_blocks=0, b=None, **kw):
        """(program text, generator, predicted cost in mWU)."""
        be = Sym(0)
        g = cls(Fp(be), vk, consts, w, b=b or bounds(), pad_blocks=pad_blocks, **kw)
        body = g.program()
        be.em.define('w_in', 'witness', f'_ -> {g.witness_type()}')
        be.em.define('main', f'comp w_in ({body.t})')
        return be.em.text(), g, 2 * (100 + g.witness_bits()) + body.c

    @staticmethod
    def padding(cost, program_bytes, witness_bytes, control_bytes=65, margin=512):
        """512-byte padding blocks that make the input's budget, 1000 mWU per witness-stack byte plus 50000,
        cover the cost.  Stack: witness, program, CMR (32), control block and their CompactSize prefixes (13).
        Each block also costs PAD_BLOCK_COST."""
        need = (cost + 999) // 1000 - 50 - (program_bytes + witness_bytes + 32 + control_bytes + 13) + margin
        k = max(0, (need + 511) // 512)
        return k + (k * PAD_BLOCK_COST + 511999) // 512000
