#!/usr/bin/env python3
"""Offline tests of the checkFork proof builder (beacon.py, fork_proof.py): python3 tools/liquid-relay/test_beacon.py

A real Sepolia (Gloas) light-client finality update, as served (contracts/solidity/test/fixtures/sepolia-finality-update-11381920.json),
is a ProgressiveContainer state: the builder must find that shape from the branch's hashes, check Sepolia's genesis
and the Fulu-to-Gloas fork against the branch's nodes 4 and 10, and give a proof whose root is the header's. Real
Electra mainnet light-client data (fixtures/electra-mainnet-bootstrap.json, fixtures/electra-mainnet-updates.json) checks the header
and sync-committee roots and the branch walk of a 64-leaf state, which checkFork does not hash. Synthetic states,
hashed by a separate recursive merkleization, check both light-client branches, every way the inputs can disagree and
the fork_proof.py commands. contracts/solidity/test/BridgeEscrowForkProof.t.sol runs the same real update through checkFork.
"""
import argparse
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import beacon  # noqa: E402
import fork_proof  # noqa: E402
import liquid as lq  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / 'fixtures'
SEPOLIA_UPDATE = ROOT / 'contracts/solidity/test/fixtures/sepolia-finality-update-11381920.json'


def sha(b):
    return hashlib.sha256(b).digest()


def zero(depth):
    z = bytes(32)
    for _ in range(depth):
        z = sha(z + z)
    return z


def tree(chunks, depth):
    """The root of `chunks` in a depth-`depth` tree, recursively: independent of beacon.merkleize."""
    if not chunks:
        return zero(depth)
    if depth == 0:
        assert len(chunks) == 1
        return chunks[0]
    half = 1 << (depth - 1)
    return sha(tree(chunks[:half], depth - 1) + tree(chunks[half:], depth - 1))


def pad(b):
    return b + bytes(-len(b) % 32)


def chunks(b):
    b = pad(b)
    return [b[i:i + 32] for i in range(0, len(b), 32)]


def le64(n):
    return n.to_bytes(8, 'little')


GENESIS = 1_655_733_600
GVR = bytes.fromhex('d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078')
FULU, GLOAS, GLOAS_EPOCH = bytes.fromhex('90000075'), bytes.fromhex('90000076'), 353_024


def header_json(slot, proposer, parent, state_root, body):
    return {'slot': str(slot), 'proposer_index': str(proposer), 'parent_root': '0x' + parent.hex(),
            'state_root': '0x' + state_root.hex(), 'body_root': '0x' + body.hex()}


def header_tree(slot, proposer, parent, state_root, body):
    return tree([pad(le64(slot)), pad(le64(proposer)), parent, state_root, body], 3)


def bits_of(active):
    """Active-fields bits as their chunk: field i at bit i % 8 of byte i // 8."""
    return sum(1 << i for i in active).to_bytes(32, 'little')


def build_tree(leaves, layout, inactive=()):
    """Every node of a BeaconState tree whose field roots are `leaves`, by generalized index, and each field's
    index. Built recursively from the definitions, independent of beacon.STATE_LAYOUTS: a `containerW` is one
    binary tree of W leaves; a `progressive` state mixes its active-fields bits into a progressive tree, a spine
    whose nodes have a subtree of 1, 4, 16, ... fields on the left and the rest of the spine on the right. A field
    in `inactive` has a zero root and a clear bit."""
    nodes, at = {}, []
    leaves = [bytes(32) if i in inactive else x for i, x in enumerate(leaves)]

    def binary(g, chunks, depth):
        if depth == 0:
            at.extend([g] if chunks else [])
            nodes[g] = chunks[0] if chunks else bytes(32)
        else:
            half = 1 << (depth - 1)
            nodes[g] = sha(binary(2 * g, chunks[:half], depth - 1) + binary(2 * g + 1, chunks[half:], depth - 1))
        return nodes[g]

    def spine(g, chunks, width):
        nodes[g] = (sha(binary(2 * g, chunks[:width], (width - 1).bit_length())
                        + spine(2 * g + 1, chunks[width:], 4 * width))
                    if chunks else bytes(32))
        return nodes[g]

    if layout == 'progressive':
        nodes[3] = bits_of(i for i in range(len(leaves)) if i not in inactive)
        nodes[1] = sha(spine(2, leaves, 1) + nodes[3])
    else:
        binary(1, leaves, int(layout.removeprefix('container')).bit_length() - 1)
    return nodes, at


def path(nodes, g):
    """The branch from node g to the root."""
    out = []
    while g > 1:
        out.append(nodes[g ^ 1])
        g >>= 1
    return out


def api(data):
    return {'data': {k: str(v) if isinstance(v, int) else '0x' + v.hex() for k, v in data.items()}}


SEPOLIA_GENESIS = api({'genesis_time': GENESIS, 'genesis_validators_root': GVR,
                       'genesis_fork_version': bytes.fromhex('90000069')})
GLOAS_FORK = api({'previous_version': FULU, 'current_version': GLOAS, 'epoch': GLOAS_EPOCH})


class Synthetic:
    """A Gloas-era state of 46 fields in a tree of shape `layout`: fields 0 to 4 as a real state after its block
    holds them, a finalized checkpoint at field 20, a sync committee at field 22, and filler. It gives both
    light-client branches."""

    def __init__(self, layout='progressive', slot=GLOAS_EPOCH * 32 + 100, genesis=GENESIS, inactive=()):
        self.slot, self.genesis = slot, genesis
        self.header = (slot, 9, sha(b'attested parent'), None, sha(b'attested body'))
        fields = [pad(le64(genesis)), GVR, pad(le64(slot)), tree([pad(FULU), pad(GLOAS), pad(le64(GLOAS_EPOCH))], 2),
                  header_tree(*self.header[:3], bytes(32), self.header[4])]
        self.finalized = (slot // 32 - 2) * 32
        self.finalized_header = (self.finalized, 3, sha(b'finalized parent'), sha(b'finalized state'),
                                 sha(b'finalized body'))
        checkpoint = sha(pad(le64(self.finalized // 32)) + header_tree(*self.finalized_header))
        self.pubkeys = [bytes([i % 256, i // 256]) * 24 for i in range(512)]
        self.aggregate = b'\xaa' * 48
        committee = sha(tree([tree(chunks(k), 1) for k in self.pubkeys], 9) + tree(chunks(self.aggregate), 1))
        later = [sha(b'field %d' % i) for i in range(5, 46)]
        later[20 - 5], later[22 - 5] = checkpoint, committee
        self.nodes, self.at = build_tree(fields + later, layout, inactive)
        self.header = (*self.header[:3], self.nodes[1], self.header[4])
        self.block_root = header_tree(*self.header)

    def finality_update(self):
        branch = [pad(le64(self.finalized // 32))] + path(self.nodes, self.at[20])
        return {'attested_header': {'beacon': header_json(*self.header)},
                'finalized_header': {'beacon': header_json(*self.finalized_header)},
                'finality_branch': ['0x' + b.hex() for b in branch]}

    def bootstrap(self):
        branch = path(self.nodes, self.at[22])
        return {'header': {'beacon': header_json(*self.header)},
                'current_sync_committee': {'pubkeys': ['0x' + k.hex() for k in self.pubkeys],
                                           'aggregate_pubkey': '0x' + self.aggregate.hex()},
                'current_sync_committee_branch': ['0x' + b.hex() for b in branch]}

    def chain(self):
        return beacon.chain_of(api({'genesis_time': self.genesis, 'genesis_validators_root': GVR}), GLOAS_FORK)

    def timestamp(self):
        return self.genesis + 12 * (self.slot + 1)


class Merkleization(unittest.TestCase):
    def test_against_the_recursive_tree(self):
        leaves = [sha(bytes([i])) for i in range(5)]
        for n in range(6):
            for limit in (None, 5, 8, 2**20):
                count = n if limit is None else limit
                depth = max(count - 1, 0).bit_length()
                if n <= count:
                    self.assertEqual(beacon.merkleize(leaves[:n], limit), tree(leaves[:n], depth), (n, limit))
        with self.assertRaises(ValueError):
            beacon.merkleize(leaves, 4)

    def test_uint64_chunk_is_little_endian(self):
        self.assertEqual(beacon.u64(0x0102), b'\x02\x01' + bytes(30))

    def test_walk_names_every_node(self):
        leaves = [sha(bytes([i])) for i in range(8)]
        nodes = {8 + i: x for i, x in enumerate(leaves)}
        for g in range(7, 0, -1):
            nodes[g] = sha(nodes[2 * g] + nodes[2 * g + 1])
        got = beacon.walk(nodes[13], 13, [nodes[12], nodes[7], nodes[2]])
        self.assertEqual({g: got[g] for g in got}, {g: nodes[g] for g in (13, 12, 6, 7, 3, 2, 1)})
        with self.assertRaises(ValueError):
            beacon.walk(nodes[13], 13, [nodes[12], nodes[7]])

    def test_active_field_bits(self):
        bits = bits_of(range(46))
        self.assertEqual(bits, bytes.fromhex('ffffffffff3f') + bytes(26))
        self.assertTrue(all(beacon.active(bits, i) for i in range(46)))
        self.assertFalse(beacon.active(bits, 46))
        self.assertFalse(beacon.active(bits_of([0, 1, 3]), 2))


class RealSepoliaUpdate(unittest.TestCase):
    """The public Sepolia finality update of attested slot 11381920 (Gloas), byte for byte as served."""

    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(SEPOLIA_UPDATE.read_text())
        cls.lc = cls.doc['data']
        cls.timestamp = GENESIS + 12 * (11_381_920 + 1)

    def test_a_progressive_state(self):
        header, layout, nodes = beacon.light_client_nodes(self.lc)
        self.assertEqual((self.doc['version'], header['slot'], layout), ('gloas', 11_381_920, 'progressive'))
        self.assertEqual(len(self.lc['finality_branch']), 9)
        self.assertEqual(nodes[1],
                         beacon.hex_bytes('0x84096366230b97edf0c6ad997c4165059654fbdf6b13d9dd5257d484209c676c', 32))
        self.assertEqual(nodes[735], beacon.root_of(beacon.header_of(self.lc['finalized_header']['beacon'])))
        self.assertEqual(nodes[734], beacon.u64(11_381_856 // 32))
        self.assertEqual(nodes[4], beacon.u64(GENESIS))
        self.assertEqual(nodes[3], bits_of(range(46)))

    def test_proof_from_sepolia_genesis_and_the_gloas_fork(self):
        p, root = beacon.fork_proof(self.lc, beacon.chain_of(SEPOLIA_GENESIS, GLOAS_FORK), self.timestamp)
        header = beacon.light_client_header(self.lc)
        self.assertEqual(root, beacon.root_of(header))
        self.assertEqual(beacon.proof_root(p), root)
        latest = header_tree(header['slot'], header['proposer_index'], header['parent_root'], bytes(32),
                             header['body_root'])
        self.assertEqual(p['stateBranch'][0], latest)
        self.assertEqual(p['activeFields'], bits_of(range(46)))
        self.assertTrue(fork_proof.effect(p, fork_proof.guest_pin())[0])

    def test_another_fork_or_genesis_is_refused(self):
        fulu = api({'previous_version': bytes.fromhex('90000074'), 'current_version': FULU, 'epoch': 272_640})
        with self.assertRaisesRegex(ValueError, 'node 10'):
            beacon.fork_proof(self.lc, beacon.chain_of(SEPOLIA_GENESIS, fulu), self.timestamp)
        later = api({'genesis_time': GENESIS + 1, 'genesis_validators_root': GVR})
        with self.assertRaisesRegex(ValueError, 'node 4'):
            beacon.fork_proof(self.lc, beacon.chain_of(later, GLOAS_FORK), self.timestamp)


class RealMainnetBranches(unittest.TestCase):
    """Real Electra mainnet light-client data: header and sync-committee roots and the branch walk must reach the
    real state roots, at the generalized indices this module uses for a 64-leaf state."""

    @classmethod
    def setUpClass(cls):
        cls.bootstrap = json.loads((FIXTURES / 'electra-mainnet-bootstrap.json').read_text())['data']
        cls.update = json.loads((FIXTURES / 'electra-mainnet-updates.json').read_text())[0]['data']

    def test_bootstrap_reaches_its_state_root(self):
        header, layout, nodes = beacon.light_client_nodes(self.bootstrap)
        self.assertEqual(header['slot'], 11_800_000)
        self.assertEqual(layout, 'container64')
        self.assertEqual(nodes[1],
                         beacon.hex_bytes('0x54cf61260f686268646e1f733a2c8d03f2bed0117229346259ffc54505b944be', 32))

    def test_finality_update_reaches_its_state_root(self):
        header, layout, nodes = beacon.light_client_nodes(self.update)
        self.assertEqual(layout, 'container64')
        self.assertEqual(nodes[1], header['state_root'])
        # The first node is the finalized checkpoint's epoch: finalized_checkpoint.root is node 169, the epoch 168.
        epoch = int(self.update['finalized_header']['beacon']['slot']) // 32
        self.assertEqual(nodes[168], beacon.u64(epoch))

    def test_two_branches_of_one_state_agree(self):
        header, _, nodes = beacon.light_client_nodes(self.update)
        c = self.update['next_sync_committee']
        leaf = beacon.sync_committee_root([beacon.hex_bytes(k, 48) for k in c['pubkeys']],
                                          beacon.hex_bytes(c['aggregate_pubkey'], 48))
        other = beacon.walk(leaf, 87, [beacon.hex_bytes(b, 32) for b in self.update['next_sync_committee_branch']])
        self.assertEqual(other[1], header['state_root'])
        for g in (3, 4, 5, 10, 11, 20, 21):
            self.assertEqual(other[g], nodes[g], g)

    def test_a_wrong_branch_is_refused(self):
        bad = dict(self.update, finality_branch=list(self.update['finality_branch']))
        bad['finality_branch'][3] = '0x' + '00' * 32
        with self.assertRaises(ValueError):
            beacon.light_client_nodes(bad)

    def test_check_fork_cannot_prove_a_64_leaf_state(self):
        with self.assertRaisesRegex(beacon.UnprovableState, 'container64 BeaconState.*progressive'):
            beacon.fork_proof(self.update, beacon.chain_of(SEPOLIA_GENESIS, GLOAS_FORK), 2**40)


class Layouts(unittest.TestCase):
    """The generalized indices of the BeaconState shapes, against the specification's constants and the recursive
    tree of `build_tree`."""

    def test_spec_constants(self):
        # The consensus specs' light-client gindices: Altair's 105 and 54, Electra's 169 and 86.
        self.assertEqual([beacon.finalized_root_gindex(x) for x in ('container32', 'container64')], [105, 169])
        self.assertEqual([beacon.current_sync_committee_gindex(x) for x in ('container32', 'container64')], [54, 86])

    def test_progressive_indices(self):
        # Field 20 is the 16th of the third subtree (fields 5 to 20, node 22), field 22 the 2nd of the fourth (node 46).
        self.assertEqual(beacon.finalized_root_gindex('progressive'), 735)
        self.assertEqual(beacon.current_sync_committee_gindex('progressive'), 2945)
        # The real Sepolia finality branch has 9 nodes; the 64-leaf tree's has 7.
        self.assertEqual([beacon.finalized_root_gindex(x).bit_length() - 1 for x in ('container64', 'progressive')],
                         [7, 9])
        # The nodes checkFork reads.
        self.assertEqual([beacon.progressive_gindex(i) for i in range(5)], [4, 40, 41, 42, 43])
        self.assertEqual(beacon.progressive_gindex(5) >> 5, 11)

    def test_indices_match_the_recursive_tree(self):
        for n in (1, 2, 5, 6, 21, 22, 38, 85, 86):
            leaves = [sha(b'leaf %d' % i) for i in range(n)]
            for layout, gindex in beacon.STATE_LAYOUTS.items():
                if layout == 'progressive' or n <= int(layout.removeprefix('container')):
                    nodes, at = build_tree(leaves, layout)
                    self.assertEqual([gindex(i) for i in range(n)], at, (layout, n))
                    if n == 38:
                        self.assertEqual(beacon.field_nodes(layout, leaves[:16]).items() - nodes.items(), set(), layout)

    def test_same_length_shapes_are_told_apart_by_hash(self):
        wide = Synthetic('container256')
        lc = wide.finality_update()
        self.assertEqual(len(lc['finality_branch']), 9)
        self.assertEqual(beacon.light_client_nodes(lc)[1], 'container256')
        # A progressive branch under a header whose state is the 256-leaf one reaches nothing.
        mixed_up = dict(Synthetic().finality_update(), attested_header=lc['attested_header'])
        with self.assertRaisesRegex(ValueError, 'does not reach'):
            beacon.light_client_nodes(mixed_up)


class SyntheticState(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Synthetic()

    def test_proof_from_either_light_client_branch(self):
        n = self.s.nodes
        for lc in (self.s.finality_update(), self.s.bootstrap()):
            p, root = beacon.fork_proof(lc, self.s.chain(), self.s.timestamp())
            self.assertEqual(root, self.s.block_root)
            self.assertEqual(beacon.proof_root(p), self.s.block_root)
            self.assertEqual((p['stateBranch'], p['activeFields']), ([n[43], n[11]], n[3]))
            self.assertEqual((p['genesisTime'], p['genesisValidatorsRoot'], p['slot']), (GENESIS, GVR, self.s.slot))
            self.assertEqual((p['previousVersion'], p['currentVersion'], p['epoch']), (FULU, GLOAS, GLOAS_EPOCH))

    def test_inconsistent_inputs_give_no_proof(self):
        s, t = self.s, self.s.timestamp()
        lc = s.finality_update()
        wrong = dict(s.chain(), current_version=bytes.fromhex('90000077'))
        with self.assertRaisesRegex(ValueError, 'node 10'):
            beacon.fork_proof(lc, wrong, t)
        with self.assertRaisesRegex(ValueError, 'node 10'):
            beacon.fork_proof(lc, dict(s.chain(), genesis_validators_root=sha(b'another chain')), t)
        with self.assertRaisesRegex(ValueError, 'node 4'):
            beacon.fork_proof(lc, dict(s.chain(), genesis_time=GENESIS + 12), t)
        # Another slot or proposer is another latest_block_header, under node 10.
        moved = dict(lc, attested_header={'beacon': header_json(s.slot + 1, *s.header[1:])})
        with self.assertRaisesRegex(ValueError, 'node 10'):
            beacon.fork_proof(moved, s.chain(), t + 12)
        other = dict(lc, attested_header={'beacon': header_json(*s.header[:3], sha(b'other'), s.header[4])})
        with self.assertRaisesRegex(ValueError, 'does not reach'):
            beacon.fork_proof(other, s.chain(), t)
        with self.assertRaisesRegex(ValueError, 'timestamp'):
            beacon.fork_proof(lc, s.chain(), GENESIS + 12 * s.slot)

    def test_an_inactive_field_is_unprovable(self):
        # genesis_time retired: its root is zero, which genesis time 0 gives, and only its clear bit tells.
        s = Synthetic(genesis=0, inactive=(0,))
        with self.assertRaisesRegex(beacon.UnprovableState, 'inactive'):
            beacon.fork_proof(s.finality_update(), s.chain(), s.timestamp())
        # A later field retired changes nothing checkFork reads.
        s = Synthetic(inactive=(30,))
        p, root = beacon.fork_proof(s.finality_update(), s.chain(), s.timestamp())
        self.assertEqual(beacon.proof_root(p), root)

    def test_calldata_layout(self):
        p, _ = beacon.fork_proof(self.s.finality_update(), self.s.chain(), self.s.timestamp())
        data = fork_proof.calldata(p)
        words = [data[4 + 32 * i:36 + 32 * i] for i in range(13)]
        self.assertEqual(len(data), 4 + 13 * 32)
        self.assertEqual(data[:4], lq.keccak256(
            b'checkFork((uint64,uint64,bytes32,uint64,bytes4,bytes4,uint64,bytes32[2],bytes32,bytes32[3]))')[:4])
        self.assertEqual(int.from_bytes(words[0], 'big'), self.s.timestamp())
        self.assertEqual(words[2], GVR)
        self.assertEqual(words[4], FULU + bytes(28))
        self.assertEqual(words[5], GLOAS + bytes(28))
        self.assertEqual(words[7:9], p['stateBranch'])
        self.assertEqual(words[9], p['activeFields'])
        self.assertEqual(words[10:13], p['blockBranch'])

    def test_effect_follows_the_contract(self):
        p, _ = beacon.fork_proof(self.s.finality_update(), self.s.chain(), self.s.timestamp())
        pin = fork_proof.guest_pin()
        self.assertEqual(pin, ('gloas', GLOAS, GLOAS_EPOCH))
        self.assertTrue(fork_proof.effect(p, pin)[0])
        self.assertIs(fork_proof.effect(p, ('next', bytes.fromhex('90000077'), GLOAS_EPOCH + 1))[0], None)
        self.assertIs(fork_proof.effect(p, ('older', FULU, 272_640))[0], False)


def selector(signature):
    return lq.keccak256(signature.encode())[:4]


class FakeNodes:
    """Beacon and execution RPCs serving one synthetic state, for fork_proof.build and verify. The fork is served by
    slot only, as some nodes do. Execution block TARGET has the state's EIP-4788 timestamp and names `parent` (the
    state's block root) as its parent beacon block root; the slot before it is missed, and every third slot after
    it, so a block's number is not its slot. Any escrow pins `pin`, and its checkFork answers `answer`, by default
    whether the proof is under that pin. `roots=False` serves no EIP-4788 roots, as after 8,191 slots."""

    TARGET, LATEST = 4_000, 4_030

    def __init__(self, s, pin=(GLOAS, GLOAS_EPOCH), parent=None, answer=None, roots=True):
        self.s, self.pin, self.answer, self.roots = s, pin, answer, roots
        self.parent = s.block_root if parent is None else parent

    def __call__(self, env):
        return self

    def block(self, n):
        k = n - self.TARGET
        t = self.s.timestamp() + 12 * (k + k // 3 if k >= 0 else k - 1)
        parent = self.parent if k == 0 else sha(b'parent %d' % n)
        return {'number': hex(n), 'timestamp': hex(t), 'hash': '0x' + sha(b'block %d' % n).hex(),
                'parentBeaconBlockRoot': '0x' + parent.hex()}

    def request(self, path, accept='application/json', body=None):
        if path == '/eth/v1/beacon/light_client/finality_update':
            return json.dumps({'version': 'gloas', 'data': self.s.finality_update()}).encode()
        if path == '/eth/v1/beacon/genesis':
            return json.dumps(api({'genesis_time': self.s.genesis, 'genesis_validators_root': GVR})).encode()
        if path == f'/eth/v1/beacon/states/{self.s.slot}/fork':
            return json.dumps(GLOAS_FORK).encode()
        raise RuntimeError(f'not served: {path}')

    def call(self, method, params):
        if method == 'eth_getBlockByNumber':
            n = self.LATEST if params[0] == 'latest' else int(params[0], 16)
            return (self.block(n), None) if 0 <= n <= self.LATEST else (None, None)
        to, data = params[0]['to'], bytes.fromhex(params[0]['data'].removeprefix('0x'))
        if to == fork_proof.BEACON_ROOTS:
            if not self.roots:
                return None, {'code': 3, 'message': 'execution reverted'}
            held = self.s.block_root if int.from_bytes(data, 'big') == self.s.timestamp() else bytes(32)
            return '0x' + held.hex(), None
        if data == selector('FORK_VERSION()'):
            return '0x' + (self.pin[0] + bytes(28)).hex(), None
        if data == selector('FORK_EPOCH()'):
            return '0x' + self.pin[1].to_bytes(32, 'big').hex(), None
        # checkFork: every synthetic proof is under Gloas.
        pinned = self.pin == (GLOAS, GLOAS_EPOCH) if self.answer is None else self.answer
        return '0x' + int(pinned).to_bytes(32, 'big').hex(), None


ESCROW = '0x' + '5e' * 20
OLDER = (FULU, 272_640)  # an escrow pinned to the fork before the guest's last


class BuildCommand(unittest.TestCase):
    """fork_proof.py build, offline and verify, against fake RPCs."""

    def run_build(self, s, d=None, nodes=None, escrow=None, pin=None):
        args = argparse.Namespace(block_root=None, escrow=escrow, save_inputs=d, pin=pin)
        with mock.patch.object(fork_proof, 'Endpoint', nodes or FakeNodes(s)):
            return fork_proof.build(args)

    def run_verify(self, nodes, proof_file, write=False):
        with mock.patch.object(fork_proof, 'Endpoint', nodes):
            return fork_proof.verify(argparse.Namespace(proof=proof_file, write=write))

    def test_build_and_offline_agree(self):
        s = Synthetic()
        with tempfile.TemporaryDirectory() as d:
            built = self.run_build(s, d)
            again = fork_proof.offline(argparse.Namespace(inputs=d, pin=None))
        self.assertTrue(built['ok'] and built['pinned'])
        self.assertEqual(built, again)
        self.assertEqual(built['blockRoot'], '0x' + s.block_root.hex())
        self.assertEqual(built['proof']['activeFields'], '0x' + s.nodes[3].hex())
        self.assertEqual(built['pin']['name'], 'gloas')
        # Found by bisection past the missed slots, and checked against its header.
        self.assertEqual(built['executionBlock'],
                         {'number': FakeNodes.TARGET, 'hash': '0x' + sha(b'block %d' % FakeNodes.TARGET).hex()})

    def test_a_header_naming_another_root_gives_no_proof(self):
        s = Synthetic()
        with self.assertRaisesRegex(ValueError, 'another parent beacon block root'):
            self.run_build(s, nodes=FakeNodes(s, parent=sha(b'another root')))

    def test_the_escrow_decides_the_verdict(self):
        s = Synthetic()
        built = self.run_build(s, escrow=ESCROW)
        self.assertEqual((built['pin']['name'], built['pinned'], built['simulation']),
                         ('escrow', True, {'reverted': False, 'pinned': True}))
        self.assertNotIn('warning', built)
        # An escrow pinned to an older fork: the same proof ends its deposits, and the output says so, whatever
        # pins.py holds. Such an escrow does not follow the deployment rule, which the warning names.
        older = self.run_build(s, nodes=FakeNodes(s, pin=OLDER), escrow=ESCROW)
        self.assertEqual((older['pin']['version'], older['pin']['epoch'], older['pinned']),
                         ('0x' + FULU.hex(), OLDER[1], False))
        self.assertIn('ENDS DEPOSITS', older['effect'])
        self.assertIn('guest\'s committed schedule', older['warning'])
        with self.assertRaisesRegex(ValueError, 'not the escrow\'s pin'):
            self.run_build(s, nodes=FakeNodes(s, pin=OLDER), escrow=ESCROW, pin=fork_proof.guest_pin())
        with self.assertRaisesRegex(RuntimeError, 'disagrees'):
            self.run_build(s, nodes=FakeNodes(s, pin=OLDER, answer=True), escrow=ESCROW)

    def test_verify_needs_only_block_headers(self):
        s = Synthetic()
        built = self.run_build(s)
        late = FakeNodes(s, roots=False)  # EIP-4788 no longer holds the root
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'proof.json'
            f.write_text(json.dumps({k: v for k, v in built.items() if k != 'executionBlock'}))
            found = self.run_verify(late, f, write=True)
            self.assertEqual(found['executionBlock'], built['executionBlock'])
            self.assertEqual(json.loads(f.read_text())['executionBlock'], built['executionBlock'])
            self.assertEqual(self.run_verify(late, f)['executionBlock'], built['executionBlock'])
            # A recorded block the chain does not have at that timestamp, a root the proof does not hash to, and
            # a chain whose header names another root are refused.
            f.write_text(json.dumps(dict(built, executionBlock={'number': FakeNodes.TARGET + 1, 'hash': '0x'})))
            with self.assertRaisesRegex(ValueError, 'timestamp'):
                self.run_verify(late, f)
            f.write_text(json.dumps(dict(built, blockRoot='0x' + sha(b'x').hex())))
            with self.assertRaisesRegex(ValueError, 'hashes to'):
                self.run_verify(late, f)
            f.write_text(json.dumps(built))
            with self.assertRaisesRegex(ValueError, 'another parent beacon block root'):
                self.run_verify(FakeNodes(s, parent=sha(b'another root'), roots=False), f)

    def test_a_refused_state_still_saves_its_inputs(self):
        s = Synthetic('container64')
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(beacon.UnprovableState):
                self.run_build(s, d)
            self.assertEqual(json.loads((Path(d) / 'light_client.json').read_text())['data'], s.finality_update())
            self.assertEqual(json.loads((Path(d) / 'fork.json').read_text()), GLOAS_FORK)
            self.assertEqual(json.loads((Path(d) / 'beacon_root.json').read_text())['timestamp'], s.timestamp())
            with self.assertRaises(beacon.UnprovableState):
                fork_proof.offline(argparse.Namespace(inputs=d, pin=fork_proof.guest_pin()))


if __name__ == '__main__':
    unittest.main()
