"""Pinned network, Sepolia and SP1 parameters of the sg16 Sepolia -> Liquid testnet path, the instance files that
pin one bridge instance each, and independent recomputation of every derived value that can be recomputed
without a node.

Every constant below is a public network, protocol or SP1 value; where it is not derived here, its source is named
next to it.  `load()` reads an instance file; there is no default instance.  `check()` recomputes what can be
recomputed (escrow DOMAIN, empty accumulator, anchor lc, SHA-256 compression self-test) and returns a list of
problems.  Nothing here reads the network.

Byte order: 32-byte Elements hashes (txid, block hash, asset id, entropy) are stored here in DISPLAY order
(as explorers print them) under *_DISPLAY names, and converted with `internal()` to the order in which they are
serialized in transactions and seen by Simplicity jets.  Ethereum values are big-endian as the EVM prints them.
"""
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

# --- Liquid testnet (public network): its genesis block hash and policy asset (tL-BTC)
LIQUID_TESTNET_GENESIS_DISPLAY = 'a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1'
LIQUID_TESTNET_LBTC_DISPLAY = '144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49'
# Liquid v1 (mainnet), named only so that it can be refused.
LIQUID_MAINNET_GENESIS_DISPLAY = '1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003'
# Elements' minimum relay fee rate on Liquid: 0.1 sat/vB (100 sat/kvB).
MIN_RELAY_SAT_PER_KVB = 100
STANDARD_TX_WEIGHT = 400_000

# --- Sepolia (public network): chain id and beacon genesis_validators_root (/eth/v1/beacon/genesis)
SEPOLIA_CHAIN_ID = 11_155_111
SEPOLIA_GENESIS_VALIDATORS_ROOT = 'd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078'
# config = SHA256(SHA256(CONFIG_TAG) || genesis root || SHA256(cbor(forks))),
# CONFIG_TAG = "liquid-bridge-poc/eth-config",
# committed by the guest for the helios Sepolia fork schedule below and compiled into the update leaf.  The CBOR
# is helios's encoding, not re-encoded here, so the value is recorded: the "config" `sg16-bridge-host inputs`
# prints.  None until recorded; assemble.py then refuses to compile the update leaf or accept an artifact.
SEPOLIA_CONFIG = '9136bc64990eb152395e155d2bbf4f93e5ed47c4f20798087974311f65a7c7f4'
SEPOLIA_FORKS = ('genesis 0 0x90000069, altair 50 0x90000070, bellatrix 100 0x90000071, capella 56832 0x90000072, '
                 'deneb 132608 0x90000073, electra 222464 0x90000074, fulu 272640 0x90000075, gloas 353024 0x90000076')
# The accumulator of the empty depth-32 tree, which every escrow starts from (its slot 0 before the first
# deposit); recomputed by `check()`.
EMPTY_ACCUMULATOR = '599a138751eff83dede1626e2b829115daec48df7347335cbe509218d65f59af'
SLOT_KEY = 0
TREE_DEPTH = 32

# --- SP1: the SDK the guest is built with, and the v6.1.0 Groth16 wrapper of the sp1-contracts SP1 Helios v1.3.0
#     pins (vendor/sp1-helios, tools/bootstrap-deps.py)
SP1_SDK = '6.8.1'
SP1_LAYOUT = 'v6.1.0'
SP1_HELIOS_COMMIT = '0dd8749f1e6c2c2302cd92931f8af63a6330af08'
GUEST = 'sg16-bridge-program'
VERIFIER_HASH = '4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696'  # SP1VerifierGroth16.sol v6.1.0
VK_ROOT = '002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352'        # SP1VerifierGroth16.sol v6.1.0
# Every coordinate of the v6.1.0 Groth16Verifier.sol key (decimal, as in the source): alpha, -beta, -gamma, -delta,
# IC_0 and IC_1..IC_5.  The key constants read at run time must be exactly these, names and values, so a swapped
# verifier source cannot change the folded key, not even by negating a point (its negation is on the curve and in
# the subgroup too).
GROTH16_KEY_PINS = dict(
    ALPHA_X=15279411540481963483749982645131486879260751823620651493692884460296130891713,
    ALPHA_Y=15872895802316430142046488442363778159164596024024981740547841316113839677454,
    BETA_NEG_X_0=6145571844528009385227270901181311049451968424667282936975270874464890915386,
    BETA_NEG_X_1=12771786691609444002416405093387705070206640282801320788762089789398249455552,
    BETA_NEG_Y_0=4488883874756188982949192438322346627006627895205628031405236004639323835517,
    BETA_NEG_Y_1=1735169520034591855846686229876971881413094324547255227368057137445726296809,
    GAMMA_NEG_X_0=10857046999023057135944570762232829481370756359578518086990519993285655852781,
    GAMMA_NEG_X_1=11559732032986387107991004021392285783925812861821192530917403151452391805634,
    GAMMA_NEG_Y_0=13392588948715843804641432497768002650278120570034223513918757245338268106653,
    GAMMA_NEG_Y_1=17805874995975841540914202342111839520379459829704422454583296818431106115052,
    DELTA_NEG_X_0=10465707362494635227101096813108413078937487707553051407465224907243675430929,
    DELTA_NEG_X_1=8014260607368773541998918215611927658290278403999176336697043972644519659243,
    DELTA_NEG_Y_0=19389283139277148919245778864125350153699493315071306268776225113374776030523,
    DELTA_NEG_Y_1=16335894885742905444968709132584769120387318573561090701871591658625758958113,
    CONSTANT_X=20281192269339458123687070687118212311775320590888414619062163734024177320592,
    CONSTANT_Y=4733327396113282720944079206751955104965328647794767422434462962576999295035,
    PUB_0_X=6933777020392885277709527453058337947310422411038083362275568070104688005311,
    PUB_0_Y=981134475045095331624771061624185350383934842154508663637397442918499383708,
    PUB_1_X=4994703368938944727583784298191985234033403433117347198670233075674015451426,
    PUB_1_Y=8251219283963080431419977720140972699009004688253176317231536639169726973868,
    PUB_2_X=4290838847096051522936899065591427041691227664160185228987863596451823131267,
    PUB_2_Y=20588566735491008722164159313316540988426258906449040460220495569364391658476,
    PUB_3_X=10868099250506113890234768256645470833285719586092080686774540776807380789751,
    PUB_3_Y=481415511937576118656966359026147167555048629225366340770167496559184060449,
    PUB_4_X=248210862999154995000539012177951057105481472135341820587821789934938975214,
    PUB_4_Y=4435539404843896136682123140600986858809597152596796648926707165831171499457,
)
# The names of the key constants in a gnark Groth16Verifier.sol (sp1.py vk_from_gnark_solidity).
GROTH16_KEY_NAME = r'(ALPHA|BETA_NEG|GAMMA_NEG|DELTA_NEG|CONSTANT|PUB_\d+)_[XY](_[01])?'

# --- Liquid bridge state (contracts/simplicity/src/claim.rs, tools/sg16/sg16/helios.py, sg16-bridge-core)
NUMS = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
STATE_TAG = hashlib.sha256(b'liquid-bridge-poc/state').digest()
LC_TAG = hashlib.sha256(b'liquid-bridge-poc/lc').digest()
# A set slot of the claimed tree: SHA256 of the claimed tag (contracts/simplicity `claimed_leaf`).
CLAIMED_LEAF = hashlib.sha256(b'liquid-bridge-poc/claimed').digest()
TOKEN_BLINDING_TAGS = (b'liquid-bridge-poc/token-blinding/A', b'liquid-bridge-poc/token-blinding/B')
DEPOSIT_TAG = b'liquid-bridge-poc/deposit'
SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# --- Bridge instance: one escrow deployment, the guest that proves its storage, and the anchor its Liquid state
#     starts from.  Each is pinned by an instance file, instances/<name>/instance.json, which every caller names;
#     this module has no default.  The file gives a name and exactly INSTANCE_KEYS, optionally with `sources` (the
#     observation each value comes from), and `check()` recomputes DOMAIN and the anchor lc from it:
#       ESCROW, ESCROW_CODE_HASH, ESCROW_DEPLOY_BLOCK, DEPOSIT_DOMAIN   the escrow, its runtime code hash and DOMAIN()
#       GUEST_ELF_SHA256, PROGRAM_VKEY   the guest ELF and the vkey the SP1 SDK reported for it (not recomputed here)
#       ANCHOR                           the weak-subjectivity checkpoint the first Liquid state commits to
INSTANCE_KEYS = ('ESCROW', 'ESCROW_CODE_HASH', 'ESCROW_DEPLOY_BLOCK', 'DEPOSIT_DOMAIN',
                 'GUEST_ELF_SHA256', 'PROGRAM_VKEY', 'ANCHOR')


@dataclass(frozen=True)
class Instance:
    path: str
    name: str
    escrow: str
    escrow_code_hash: str
    escrow_deploy_block: int
    deposit_domain: str
    guest_elf_sha256: str
    program_vkey: str
    anchor: dict


def load(path):
    """The instance of the file at `path`.  ValueError if the file is not exactly an instance file; `check()` then
    recomputes what the values imply."""
    doc = json.loads(Path(path).read_text())
    if not isinstance(doc, dict):
        raise ValueError(f'{path}: an instance file is a JSON object')
    required, keys = {'name', *INSTANCE_KEYS}, set(doc) - {'sources'}
    if keys != required or not isinstance(doc['name'], str):
        raise ValueError(f'{path}: an instance file gives a name and exactly {", ".join(INSTANCE_KEYS)} '
                         f'(missing {sorted(required - keys)}, '
                         f'unknown {sorted(keys - required)}), plus optional sources')
    if not isinstance(doc['ANCHOR'], dict) or set(doc['ANCHOR']) != {'slot', 'header', 'committee', 'lc'}:
        raise ValueError(f'{path}: ANCHOR gives slot, header, committee and lc')
    return Instance(path=str(path), name=doc['name'], escrow=doc['ESCROW'], escrow_code_hash=doc['ESCROW_CODE_HASH'],
                    escrow_deploy_block=doc['ESCROW_DEPLOY_BLOCK'], deposit_domain=doc['DEPOSIT_DOMAIN'],
                    guest_elf_sha256=doc['GUEST_ELF_SHA256'], program_vkey=doc['PROGRAM_VKEY'],
                    anchor=dict(doc['ANCHOR']))


def sha(b):
    return hashlib.sha256(b).digest()


def internal(display_hex):
    """Display (explorer) hex of a txid, block hash or asset id -> internal (serialized) byte order."""
    return bytes.fromhex(display_hex)[::-1]


def display(internal_bytes):
    return internal_bytes[::-1].hex()


# --- SHA-256 compression without padding, for Elements' "fast Merkle root" (asset entropy and ids).  The round
#     constants are derived (cube and square roots of the first primes), and `_self_test` checks the compression
#     against hashlib on padded single blocks, so a wrong constant cannot pass silently.
def _primes(n):
    out, k = [], 2
    while len(out) < n:
        if all(k % p for p in out if p * p <= k):
            out.append(k)
        k += 1
    return out


def _iroot(n, k):
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y


_P = _primes(64)
_IV = [_iroot(p << 64, 2) & 0xffffffff for p in _P[:8]]
_K = [_iroot(p << 96, 3) & 0xffffffff for p in _P]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def midstate(block):
    """SHA-256 state words (big-endian bytes) after compressing one 64-byte block from the standard IV."""
    assert len(block) == 64
    w = list(struct.unpack('>16I', block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)
    a, b, c, d, e, f, g, h = _IV
    for i in range(64):
        t1 = (h + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g)) + _K[i] + w[i]) & 0xffffffff
        t2 = ((_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xffffffff
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xffffffff, c, b, a, (t1 + t2) & 0xffffffff
    return struct.pack('>8I', *[(x + y) & 0xffffffff for x, y in zip(_IV, (a, b, c, d, e, f, g, h))])


def _self_test():
    for m in (b'', b'abc', bytes(range(55))):
        block = m + b'\x80' + bytes(55 - len(m)) + (8 * len(m)).to_bytes(8, 'big')
        if midstate(block) != sha(m):
            return False
    return True


# --- Elements issuance (Elements issuance.cpp; rust-elements AssetId), all in internal byte order
def asset_entropy(txid_internal, vout, contract_hash=bytes(32)):
    """E = fast_merkle_root(SHA256d(prevout), contract hash), prevout = txid || le32(vout)."""
    prevout_hash = sha(sha(txid_internal + vout.to_bytes(4, 'little')))
    return midstate(prevout_hash + contract_hash)


def asset_id(entropy):
    return midstate(entropy + bytes(32))


def token_id(entropy, confidential_issuance=False):
    """The reissuance token of an issuance whose amount is explicit or null (confidential=False)."""
    return midstate(entropy + bytes([2 if confidential_issuance else 1]) + bytes(31))


def token_blinding(entropy):
    """The two public token blinding factors of the claim crate (shared by the claim and update leaves)."""
    out = [sha(tag + entropy) for tag in TOKEN_BLINDING_TAGS]
    for bf in out:
        assert 0 < int.from_bytes(bf, 'big') < SECP256K1_N, 'token blinding factor is not a valid scalar'
    assert out[0] != out[1]
    return out


# --- Ethereum escrow (contracts/solidity/contracts/BridgeDeposits.sol)
def deposit_domain(chain_id, escrow_hex):
    """DOMAIN() = SHA256(DEPOSIT_TAG || uint256(chain id) || escrow address)."""
    return sha(DEPOSIT_TAG + chain_id.to_bytes(32, 'big') + bytes.fromhex(escrow_hex))


def zero_hashes(depth=TREE_DEPTH):
    z = [bytes(32)]
    for _ in range(depth):
        z.append(sha(z[-1] + z[-1]))
    return z


def accumulator(root, count):
    return sha(root + count.to_bytes(8, 'big'))


def empty_accumulator():
    return accumulator(zero_hashes()[TREE_DEPTH], 0)


def deposit_leaf(domain, index, units, recipient):
    return sha(domain + index.to_bytes(8, 'big') + units.to_bytes(8, 'big') + recipient)


def tree_root(domain, deposits):
    """Root of the depth-32 tree of [(units, recipient)], as BridgeDeposits and claim::DepositTree."""
    z = zero_hashes()
    level = [deposit_leaf(domain, i, u, r) for i, (u, r) in enumerate(deposits)]
    for h in range(TREE_DEPTH):
        level = [sha(level[2 * j] + (level[2 * j + 1] if 2 * j + 1 < len(level) else z[h]))
                 for j in range((len(level) + 1) // 2)]
    return level[0] if level else z[TREE_DEPTH]


# --- Liquid state commitments
def lc(slot, header, committee):
    return sha(LC_TAG + slot.to_bytes(8, 'big') + header + committee)


def claimed_indices(x):
    """The claimed set of a state record, `claimed`: deposit indices below 2^32, strictly ascending, so each is
    listed once and a record has one form. ValueError otherwise."""
    if not isinstance(x, list):
        raise ValueError(f'claimed is a list of deposit indices, not {x!r}')
    if not all(type(i) is int and 0 <= i < 1 << TREE_DEPTH for i in x):
        raise ValueError(f'claimed: each index is an integer below 2^{TREE_DEPTH}')
    if any(a >= b for a, b in zip(x, x[1:])):
        raise ValueError('claimed: indices strictly ascending, each listed once')
    return list(x)


def claimed_root(indices):
    """The root of the depth-32 claimed tree (contracts/simplicity `ClaimedTree`) with slot i set to CLAIMED_LEAF for
    each i of `indices` and the other slots zero.  It depends only on the set."""
    idx = list(indices)
    if not all(type(i) is int for i in idx):
        raise ValueError('claimed: each index is an integer')
    if len(set(idx)) != len(idx):
        raise ValueError('claimed: an index is repeated')
    z = zero_hashes()
    level = {i: CLAIMED_LEAF for i in claimed_indices(sorted(idx))}
    for h in range(TREE_DEPTH):
        level = {j: sha(level.get(2 * j, z[h]) + level.get(2 * j + 1, z[h])) for j in {i >> 1 for i in level}}
    return level.get(0, z[TREE_DEPTH])


def state_hash(lc_, acc, claimed_root_):
    assert len(claimed_root_) == 32, 'claimed_root is 32 bytes'
    return sha(STATE_TAG + lc_ + acc + claimed_root_)


def tagged(tag, msg):
    t = sha(tag.encode())
    return sha(t + t + msg)


def tapleaf_simplicity(cmr):
    """Leaf version 0xbe, script = the 32-byte CMR (or state hash), CompactSize length 0x20."""
    return tagged('TapLeaf/elements', b'\xbe\x20' + cmr)


def tapbranch(a, b):
    lo, hi = sorted([a, b])
    return tagged('TapBranch/elements', lo + hi)


def check(inst):
    """Recompute the derivable pins, the fixed ones and those of instance `inst`.  Returns a list of problems
    (empty: all agree)."""
    problems = []

    def need(cond, what):
        if not cond:
            problems.append(what)
    need(_self_test(), 'SHA-256 compression self-test against hashlib')
    a = inst.anchor
    for name, value, n in (('ESCROW', inst.escrow, 20), ('ESCROW_CODE_HASH', inst.escrow_code_hash, 32),
                           ('DEPOSIT_DOMAIN', inst.deposit_domain, 32),
                           ('GUEST_ELF_SHA256', inst.guest_elf_sha256, 32), ('PROGRAM_VKEY', inst.program_vkey, 32),
                           ('ANCHOR header', a['header'], 32), ('ANCHOR committee', a['committee'], 32),
                           ('ANCHOR lc', a['lc'], 32)):
        need(isinstance(value, str) and len(value) == 2 * n and all(c in '0123456789abcdef' for c in value),
             f'{name}: {n} bytes of lowercase hex')
    for name, value in (('ESCROW_DEPLOY_BLOCK', inst.escrow_deploy_block), ('ANCHOR slot', a['slot'])):
        need(type(value) is int and value >= 0, f'{name}: a non-negative integer')
    need(SEPOLIA_CONFIG is None or (isinstance(SEPOLIA_CONFIG, str) and len(SEPOLIA_CONFIG) == 64
                                    and all(c in '0123456789abcdef' for c in SEPOLIA_CONFIG)),
         'SEPOLIA_CONFIG: 32 bytes of lowercase hex, or None until recorded')
    if problems:
        return problems
    need(deposit_domain(SEPOLIA_CHAIN_ID, inst.escrow).hex() == inst.deposit_domain, 'escrow DOMAIN recomputation')
    need(empty_accumulator().hex() == EMPTY_ACCUMULATOR, 'empty accumulator recomputation')
    need(tree_root(bytes(32), []) == zero_hashes()[TREE_DEPTH], 'empty tree root')
    need(lc(a['slot'], bytes.fromhex(a['header']), bytes.fromhex(a['committee'])).hex() == a['lc'], 'anchor lc')
    need(a['slot'] % 32 == 0, 'anchor slot is an epoch boundary')
    need(int(inst.program_vkey, 16) < 2**253 and int(VK_ROOT, 16) < 2**253, 'SP1 fixed inputs are field elements')
    need(VERIFIER_HASH.startswith('4388a21c'), 'Groth16 selector')
    need(LIQUID_TESTNET_GENESIS_DISPLAY != LIQUID_MAINNET_GENESIS_DISPLAY, 'network separation')
    return problems


# --- Shared protocol vectors, which every implementation of these tags and formulas checks
VECTORS = Path(__file__).resolve().parents[4] / 'vectors' / 'protocol.json'


def vectors(path=VECTORS):
    """Compare this module's tags, lc, token blinding and escrow DOMAIN with the shared protocol vectors.
    Returns a list of problems (empty: all agree); an output not yet recorded is one.

    `claimed_root` and `state_hash` are checked against the vectors' claimed_root and state_hash sections."""
    doc = json.loads(Path(path).read_text())
    tags, problems = {k: t.encode() for k, t in doc['tags'].items()}, []

    def need(cond, what):
        if not cond:
            problems.append(what)

    def word(x):
        return bytes.fromhex(x[2:])

    def expect(section, i, field, got):
        want = doc[section][i][field]
        if want is None:
            problems.append(f'{section}[{i}].{field} is not recorded: '
                            'run node vectors/record.mjs and review the result')
        else:
            need(got == word(want), f'{section}[{i}].{field}')

    need(STATE_TAG == sha(tags['state']) and LC_TAG == sha(tags['lc']) and CLAIMED_LEAF == sha(tags['claimed']),
         'STATE_TAG, LC_TAG and CLAIMED_LEAF are SHA256 of tags.state, tags.lc and tags.claimed')
    need(TOKEN_BLINDING_TAGS == (tags['token_blinding_a'], tags['token_blinding_b']),
         'TOKEN_BLINDING_TAGS = tags.token_blinding_a, _b')
    need(DEPOSIT_TAG == tags['deposit'], 'DEPOSIT_TAG = tags.deposit')
    held = dict(state=STATE_TAG, lc=LC_TAG, claimed=CLAIMED_LEAF)
    for i, c in enumerate(doc['tag_sha256']):
        if c['tag'] in held:
            expect('tag_sha256', i, 'sha256', held[c['tag']])
    for i, c in enumerate(doc['lc']):
        expect('lc', i, 'lc', lc(c['slot'], word(c['header']), word(c['committee'])))
    for i, c in enumerate(doc['claimed_root']):
        expect('claimed_root', i, 'root', claimed_root(c['indices']))
    for i, c in enumerate(doc['state_hash']):
        root = claimed_root(c['indices'])
        expect('state_hash', i, 'claimed_root', root)
        expect('state_hash', i, 'state_hash', state_hash(word(c['lc']), word(c['acc']), root))
    for i, c in enumerate(doc['token_blinding']):
        a, b = token_blinding(word(c['entropy']))
        expect('token_blinding', i, 'a', a)
        expect('token_blinding', i, 'b', b)
    for i, c in enumerate(doc['deposit_domain']):
        expect('deposit_domain', i, 'domain', deposit_domain(c['chain_id'], c['escrow'][2:]))
    need(all(doc[s] for s in ('tag_sha256', 'lc', 'claimed_root', 'state_hash', 'token_blinding', 'deposit_domain')),
         'a case of each section')
    return problems


def instance_state(path):
    """Problems of a published state record (instances/<name>/initial_state.json) under this module's lc, claimed
    set and state_hash; empty if all recompute."""
    s = json.loads(Path(path).read_text())
    word = bytes.fromhex
    problems = []
    if lc(s['head'], word(s['header']), word(s['committee'])) != word(s['lc']):
        problems.append(f'{path}: lc')
    try:
        root = claimed_root(claimed_indices(s.get('claimed')))
    except ValueError as e:
        return problems + [f'{path}: {e}']
    if s.get('claimed_root') != root.hex():
        problems.append(f'{path}: claimed_root is not the root of claimed')
    if state_hash(word(s['lc']), word(s['acc']), root) != word(s['state_hash']):
        problems.append(f'{path}: state_hash')
    return problems


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: pins.py <instances/<name>/instance.json>  (there is no default instance)')
    inst = load(sys.argv[1])
    p = check(inst)
    print(f'instance: {inst.name}')
    if SEPOLIA_CONFIG is None:
        print('SEPOLIA_CONFIG: not recorded; '
              'record the config `sg16-bridge-host inputs` prints before building an update leaf')
    print('\n'.join(p) if p else 'pins: all recomputations agree')
    raise SystemExit(1 if p else 0)
