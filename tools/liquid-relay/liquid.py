"""Liquid headers, transactions and block signatures for the Sepolia light client.

contracts/solidity/contracts/LiquidLightClient.sol checks everything on chain; this module builds inputs the contract
accepts and checks them first, so that a relay transaction or a Foundry fixture is known to be
consistent before it is used. Standard library only.

Byte order: hashes are kept in internal order (as serialized and as the contract sees them); explorers
display them reversed. `display()` converts.

Encodings follow Elements 23 (primitives/block.h, primitives/transaction.h, dynafed.h), as the
contract's ElementsParser documents them:
  hash-form header  version u32le (bit 31 set) | prev (32) | merkle root (32) | time u32le | height u32le
                    | current params | proposed params
  signed header     hash-form header | signblock witness (CompactSize count, CompactSize-prefixed items)
  params            0x00 null | 0x01 compact: signblockscript, witness limit u32le, elided root (32)
                    | 0x02 full: signblockscript, witness limit, fedpeg program, fedpegscript,
                      extension space (vector of byte vectors)
  transaction       version | flags | vin | vout | locktime | [witness when flags & 1]
"""
import hashlib

# ---- hashing ----


def sha256(b):
    return hashlib.sha256(b).digest()


def sha256d(b):
    return sha256(sha256(b))


def display(h):
    """The explorer form of an internal-order hash."""
    return h[::-1].hex()


def internal(display_hex):
    b = bytes.fromhex(display_hex.removeprefix('0x'))
    if len(b) != 32:
        raise ValueError('a 32-byte hash is expected')
    return b[::-1]


_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _M64 if n else v


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    """Ethereum's keccak256: Keccak-f[1600], rate 136 bytes, original 0x01 padding (not SHA3-256)."""
    rate = 136
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], 'little')
        a = _keccak_f(a)
    return b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


# ---- secp256k1 ----

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return x, (lam * (p[0] - x) - p[1]) % P


def point_mul(k, p=G):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def decompress(key):
    """The point of a 33-byte compressed key; raises ValueError for anything else."""
    if len(key) != 33 or key[0] not in (2, 3):
        raise ValueError('not a compressed secp256k1 key')
    x = int.from_bytes(key[1:], 'big')
    if x >= P:
        raise ValueError('key x is not a field element')
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if y * y % P != (x * x * x + 7) % P:
        raise ValueError('key x is not on the curve')
    if y & 1 != key[0] & 1:
        y = P - y
    return x, y


def compress(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, 'big')


def eth_address(point):
    return keccak256(point[0].to_bytes(32, 'big') + point[1].to_bytes(32, 'big'))[12:]


def ecdsa_verify(msg32, r, s, point):
    """ECDSA over the 32-byte message as libsecp256k1 reads it (big-endian scalar), as Elements'
    block-signature checker passes the block hash."""
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(msg32, 'big') % N
    w = pow(s, -1, N)
    q = _add(point_mul(z * w % N), point_mul(r * w % N, point))
    return q is not None and q[0] % N == r


def ecdsa_sign(secret, msg32, nonce):
    """Low-S ECDSA with an explicit nonce. For tests only: a reused or guessable nonce leaks the key."""
    r = point_mul(nonce)[0] % N
    s = pow(nonce, -1, N) * (int.from_bytes(msg32, 'big') + r * secret) % N
    if r == 0 or s == 0:
        raise ValueError('bad nonce')
    return r, min(s, N - s)


def parse_der(sig):
    """(r, s) of a strict DER signature without sighash byte (BIP66 rules, as Elements' STRICTENC)."""
    if not 8 <= len(sig) <= 72 or sig[0] != 0x30 or sig[1] != len(sig) - 2 or sig[2] != 0x02:
        raise ValueError('not a strict DER signature')
    rlen = sig[3]
    if 6 + rlen > len(sig) or sig[4 + rlen] != 0x02:
        raise ValueError('not a strict DER signature')
    slen = sig[5 + rlen]
    if 6 + rlen + slen != len(sig):
        raise ValueError('not a strict DER signature')
    r, s = sig[4:4 + rlen], sig[6 + rlen:]
    for v in (r, s):
        if not v or v[0] & 0x80 or (len(v) > 1 and v[0] == 0 and not v[1] & 0x80):
            raise ValueError('DER integer is negative or not minimal')
    return int.from_bytes(r, 'big'), int.from_bytes(s, 'big')


def encode_der(r, s):
    def integer(v):
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = integer(r) + integer(s)
    return b'\x30' + bytes([len(body)]) + body


# ---- serialization primitives ----

class Reader:
    def __init__(self, b, p=0):
        self.b, self.p = b, p

    def take(self, n):
        if self.p + n > len(self.b):
            raise ValueError('truncated')
        out = self.b[self.p:self.p + n]
        self.p += n
        return out

    def u32(self):
        return int.from_bytes(self.take(4), 'little')

    def compact_size(self):
        first = self.take(1)[0]
        if first < 0xfd:
            return first
        width, least = {0xfd: (2, 0xfd), 0xfe: (4, 0x10000), 0xff: (8, 0x100000000)}[first]
        v = int.from_bytes(self.take(width), 'little')
        if v < least:
            raise ValueError('non-minimal CompactSize')
        return v

    def var_bytes(self):
        return self.take(self.compact_size())

    def vector(self):
        return [self.var_bytes() for _ in range(self.compact_size())]

    def done(self):
        return self.p == len(self.b)


def compact_size(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def var_bytes(b):
    return compact_size(len(b)) + b


# ---- headers ----

def _params(r):
    start = r.p
    kind = r.take(1)[0]
    if kind == 0:
        return None
    if kind not in (1, 2):
        raise ValueError('unknown DynaFed params type')
    e = {'kind': kind, 'signblockscript': r.var_bytes(), 'witness_limit': r.u32()}
    if kind == 1:
        e['elided_root'] = r.take(32)
    else:
        e['fedpeg_program'], e['fedpegscript'], e['extension_space'] = r.var_bytes(), r.var_bytes(), r.vector()
    e['raw'] = r.b[start:r.p]
    return e


def parse_header(raw, signed=True):
    """A DynaFed header. With `signed`, `raw` must be the network form ending in the signblock witness;
    otherwise it must be the hash form exactly."""
    r = Reader(raw)
    version = r.u32()
    if not version & 0x80000000:
        raise ValueError('not a DynaFed header')
    h = {'version': version, 'prev': r.take(32), 'merkle_root': r.take(32), 'time': r.u32(), 'height': r.u32()}
    h['current'] = _params(r)
    if h['current'] is None:
        raise ValueError('null current params')
    h['proposed'] = _params(r)
    h['hash_form'] = raw[:r.p]
    h['hash'] = sha256d(h['hash_form'])
    h['witness'] = r.vector() if signed else None
    if not r.done():
        raise ValueError('trailing bytes after the header')
    return h


def parse_witness_script(s):
    """(m, keys) of `<key> OP_CHECKSIG` or `OP_m <key>... OP_n OP_CHECKMULTISIG`, the forms the light
    client accepts, compressed keys only."""
    if len(s) == 35 and s[0] == 0x21 and s[34] == 0xac:
        return 1, [s[1:34]]
    if len(s) < 37 or (len(s) - 3) % 34 or not 0x51 <= s[0] <= 0x60:
        raise ValueError('unsupported witness script')
    n, m = (len(s) - 3) // 34, s[0] - 0x50
    if n > 16 or m > n or s[-2] != 0x50 + n or s[-1] != 0xae:
        raise ValueError('unsupported witness script')
    keys = [s[1 + 34 * i:35 + 34 * i] for i in range(n)]
    if any(k[0] != 0x21 for k in keys):
        raise ValueError('unsupported witness script')
    return m, [k[1:] for k in keys]


def p2wsh(witness_script):
    return b'\x00\x20' + sha256(witness_script)


def tip_signatures(h):
    """The (r, s) pairs the light client needs for signed header `h`, after checking its signblock
    witness the way Elements does for a P2WSH signblockscript: [signature, witness script] for
    `<key> OP_CHECKSIG`, [empty, signatures..., witness script] for OP_CHECKMULTISIG, signatures with
    SIGHASH_ALL, each by a later key than the previous one."""
    w = h['witness']
    if not w:
        raise ValueError('signblock witness is empty')
    script = w[-1]
    if p2wsh(script) != h['current']['signblockscript']:
        raise ValueError('witness script does not match the current signblockscript')
    m, keys = parse_witness_script(script)
    if script[-1] == 0xac:  # OP_CHECKSIG pops no dummy; a witness program must leave a clean stack
        sigs = w[:-1]
    elif w[0] != b'':
        raise ValueError('OP_CHECKMULTISIG witness is not [empty, signatures..., witness script]')
    else:
        sigs = w[1:-1]
    if len(sigs) != m:
        raise ValueError(f'{len(sigs)} signatures for a {m}-of-{len(keys)} script')
    points, out, k = [decompress(key) for key in keys], [], 0
    for sig in sigs:
        if sig[-1:] != b'\x01':
            raise ValueError('block signature without SIGHASH_ALL')
        r, s = parse_der(sig[:-1])
        while k < len(points) and not ecdsa_verify(h['hash'], r, s, points[k]):
            k += 1
        if k == len(points):
            raise ValueError('a block signature matches no remaining key')
        out.append((r, s))
        k += 1
    return out


def federation(witness_script):
    """(witness script, key y coordinates in script order, threshold) for the contract."""
    m, keys = parse_witness_script(witness_script)
    return witness_script, [decompress(k)[1] for k in keys], m


# ---- transactions ----

ASSET, VALUE, NONCE = (33, (0x0a, 0x0b)), (9, (0x08, 0x09)), (33, (0x02, 0x03))


def _skip_commitment(r, field):
    """Elements' CConfidentialCommitment: null, explicit (prefix 1) or a 33-byte commitment."""
    explicit_size, committed = field
    prefix = r.take(1)[0]
    if prefix == 1:
        r.take(explicit_size - 1)
    elif prefix in committed:
        r.take(32)
    elif prefix != 0:
        raise ValueError('unknown commitment prefix')


def txid_form(raw):
    """The serialization a txid hashes: `raw` (with or without witness) parsed whole, cut before the
    witness, flags byte zero."""
    r = Reader(raw)
    r.take(4)
    flags = r.take(1)[0]
    if flags not in (0, 1):
        raise ValueError('unknown transaction flags')
    n_in = r.compact_size()
    for _ in range(n_in):
        r.take(32)
        n = r.u32()
        r.var_bytes()
        r.take(4)
        if n != 0xffffffff and n & 0x80000000:  # asset issuance: nonce, entropy, amount, inflation keys
            r.take(64)
            _skip_commitment(r, VALUE)
            _skip_commitment(r, VALUE)
    n_out = r.compact_size()
    for _ in range(n_out):
        _skip_commitment(r, ASSET)
        _skip_commitment(r, VALUE)
        _skip_commitment(r, NONCE)
        r.var_bytes()
    r.take(4)
    end = r.p
    if flags & 1:
        for _ in range(n_in):  # issuance and inflation range proofs, script witness, peg-in witness
            r.var_bytes(), r.var_bytes(), r.vector(), r.vector()
        for _ in range(n_out):  # surjection proof, range proof
            r.var_bytes(), r.var_bytes()
    if not r.done():
        raise ValueError('trailing bytes after the transaction')
    return raw[:4] + b'\x00' + raw[5:end]


def merkle_root(leaf, branch, position):
    """Bitcoin's block Merkle rule over internal-order hashes, as ElementsParser.merkleRoot."""
    if len(branch) > 32 or position >> len(branch):
        raise ValueError('position does not fit the branch')
    node = leaf
    for i, sibling in enumerate(branch):
        node = sha256d(sibling + node) if (position >> i) & 1 else sha256d(node + sibling)
    return node


# ---- the light client's batch commitment ----

def batch_tree(merkle_roots):
    """(root, levels) of LiquidLightClient's batch tree: keccak256(merkle root) leaves padded with
    zero words to a power of two, nodes keccak256(left || right)."""
    size = 1
    while size < len(merkle_roots):
        size <<= 1
    level = [keccak256(m) for m in merkle_roots] + [bytes(32)] * (size - len(merkle_roots))
    levels = [level]
    while len(level) > 1:
        level = [keccak256(level[2 * j] + level[2 * j + 1]) for j in range(len(level) // 2)]
        levels.append(level)
    return level[0], levels


def batch_path(merkle_roots, index):
    if not 0 <= index < len(merkle_roots):
        raise ValueError('index outside the batch')
    root, levels = batch_tree(merkle_roots)
    return root, [levels[d][(index >> d) ^ 1] for d in range(len(levels) - 1)]


# ---- ABI ----

SUBMIT_HEADERS = 'submitHeaders(bytes[],(bytes32,bytes32)[],bytes,uint256[])'


def _word(n):
    return n.to_bytes(32, 'big')


def _abi_bytes(b):
    return _word(len(b)) + b + bytes(-len(b) % 32)


def _abi_bytes_array(items):
    head, tail = b'', b''
    for item in items:
        head += _word(32 * len(items) + len(tail))
        tail += _abi_bytes(item)
    return _word(len(items)) + head + tail


def encode_submit_headers(headers, sigs, witness_script=b'', key_ys=()):
    """Calldata of LiquidLightClient.submitHeaders(hash-form headers, (r, s) pairs, witness script, key ys)."""
    parts = [
        _abi_bytes_array(headers),
        _word(len(sigs)) + b''.join(_word(r) + _word(s) for r, s in sigs),
        _abi_bytes(witness_script),
        _word(len(key_ys)) + b''.join(_word(y) for y in key_ys),
    ]
    head, tail = b'', b''
    for part in parts:
        head += _word(32 * len(parts) + len(tail))
        tail += part
    return keccak256(SUBMIT_HEADERS.encode())[:4] + head + tail
