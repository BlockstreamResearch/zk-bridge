#!/usr/bin/env python3
"""Offline tests of tools/liquid-relay: python3 tools/liquid-relay/test_liquid.py

The real-transaction case reads public Liquid testnet transactions from a local, untracked directory,
target/sg16-testnet-live/; the fixture case re-verifies contracts/solidity/test/fixtures/liquid-testnet-headers.json
independently of Foundry. Each is skipped, with its reason printed, when its file is absent.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import liquid as lq  # noqa: E402
import relay  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
LIVE = ROOT / 'target/sg16-testnet-live'
FIXTURE = ROOT / 'contracts/solidity/test/fixtures/liquid-testnet-headers.json'


def le32(n):
    return n.to_bytes(4, 'little')


def compact(sbs):
    return b'\x01' + lq.var_bytes(sbs) + le32(1416) + bytes(31) + b'\xe1'


def full(sbs, extension=(b'\x02' + bytes(32),)):
    return (b'\x02' + lq.var_bytes(sbs) + le32(1416) + lq.var_bytes(b'\x00\x14' + bytes(20)) + lq.var_bytes(b'\x51')
            + lq.compact_size(len(extension)) + b''.join(lq.var_bytes(e) for e in extension))


def hash_form(prev, height, current, proposed=b'\x00'):
    return (le32(0xa0000000) + prev + lq.sha256(b'txs %d' % height) + le32(1_760_000_000) + le32(height)
            + current + proposed)


def signed(form, witness):
    return form + lq.compact_size(len(witness)) + b''.join(lq.var_bytes(w) for w in witness)


class OneOfOne:
    """A testnet-shaped federation: OP_1 <key> OP_1 OP_CHECKMULTISIG behind P2WSH."""

    def __init__(self, secret):
        self.secret = secret
        self.key = lq.compress(lq.point_mul(secret))
        self.script = b'\x51\x21' + self.key + b'\x51\xae'
        self.sbs = lq.p2wsh(self.script)

    def sign(self, form, nonce=0x777):
        r, s = lq.ecdsa_sign(self.secret, lq.sha256d(form), nonce)
        return signed(form, [b'', lq.encode_der(r, s) + b'\x01', self.script]), (r, s)


class SingleKey(OneOfOne):
    """The light client's other form: <key> OP_CHECKSIG behind P2WSH, signed without a dummy."""

    def __init__(self, secret):
        super().__init__(secret)
        self.script = b'\x21' + self.key + b'\xac'
        self.sbs = lq.p2wsh(self.script)

    def sign(self, form, nonce=0x777):
        r, s = lq.ecdsa_sign(self.secret, lq.sha256d(form), nonce)
        return signed(form, [lq.encode_der(r, s) + b'\x01', self.script]), (r, s)


class Hashes(unittest.TestCase):
    def test_keccak_vectors(self):
        self.assertEqual(lq.keccak256(b'').hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(lq.keccak256(b'abc').hex(), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        self.assertEqual(lq.keccak256(b'The quick brown fox jumps over the lazy dog').hex(),
                         '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15')
        self.assertEqual(lq.keccak256(b'transfer(address,uint256)')[:4].hex(), 'a9059cbb')

    def test_display_order(self):
        self.assertEqual(lq.display(lq.internal('00' * 31 + 'ff')), '00' * 31 + 'ff')
        self.assertEqual(lq.internal('00' * 31 + 'ff')[0], 0xff)
        with self.assertRaises(ValueError):
            lq.internal('00' * 31)


class Secp256k1(unittest.TestCase):
    def test_address_of_key_one(self):
        self.assertEqual(lq.eth_address(lq.G).hex(), '7e5f4552091a69125d5dfcb7b8c2659029395bdf')

    def test_compressed_keys(self):
        for k in (1, 2, 0x1234, lq.N - 1):
            q = lq.point_mul(k)
            self.assertEqual(lq.decompress(lq.compress(q)), q)
        x = next(x for x in range(1, 100) if pow(x ** 3 + 7, (lq.P - 1) // 2, lq.P) != 1)
        for bad in (b'\x02' + x.to_bytes(32, 'big'), b'\x04' + bytes(32), b'\x02' + lq.P.to_bytes(32, 'big'),
                    b'\x02' + bytes(31)):
            with self.assertRaises(ValueError):
                lq.decompress(bad)

    def test_ecdsa(self):
        q, msg = lq.point_mul(0x1234), lq.sha256d(b'header')
        r, s = lq.ecdsa_sign(0x1234, msg, 0x5678)
        self.assertLessEqual(s, lq.N // 2)
        self.assertTrue(lq.ecdsa_verify(msg, r, s, q))
        self.assertTrue(lq.ecdsa_verify(msg, r, lq.N - s, q),
                        'ECDSA is malleable; the light client does not depend on s')
        self.assertFalse(lq.ecdsa_verify(lq.sha256d(b'other'), r, s, q))
        self.assertFalse(lq.ecdsa_verify(msg, r, s, lq.G))
        self.assertFalse(lq.ecdsa_verify(msg, 0, s, q))
        self.assertFalse(lq.ecdsa_verify(msg, r, lq.N, q))

    def test_strict_der(self):
        for r, s in [(1, 2), (2**255, 1), lq.ecdsa_sign(7, bytes(32), 11)]:
            self.assertEqual(lq.parse_der(lq.encode_der(r, s)), (r, s))
        good = lq.encode_der(1, 2)
        bad = [
            bytes.fromhex('300702020001020102'),  # r has a needless leading zero
            bytes.fromhex('3006020180020102'),  # r is negative
            good[:-1],  # truncated
            good + b'\x00',  # trailing byte
            b'\x31' + good[1:],  # not a SEQUENCE
        ]
        for b in bad:
            with self.assertRaises(ValueError, msg=b.hex()):
                lq.parse_der(b)


class Headers(unittest.TestCase):
    def test_cut_and_signature_of_a_testnet_shaped_header(self):
        fed = OneOfOne(0xabc)
        form = hash_form(bytes(32), 2_664_843, compact(fed.sbs))
        raw, (r, s) = fed.sign(form)
        h = lq.parse_header(raw)
        self.assertEqual((h['hash_form'], h['height'], h['hash']), (form, 2_664_843, lq.sha256d(form)))
        self.assertEqual(h['current']['signblockscript'], fed.sbs)
        self.assertIsNone(h['proposed'])
        self.assertEqual(lq.tip_signatures(h), [(r, s)])
        self.assertEqual(lq.parse_header(form, signed=False)['hash'], h['hash'])
        self.assertEqual(lq.federation(fed.script), (fed.script, [lq.decompress(fed.key)[1]], 1))
        with self.assertRaises(ValueError):
            lq.parse_header(raw, signed=False)  # the witness is not part of the hash form
        with self.assertRaises(ValueError):
            lq.parse_header(raw + b'\x00')
        with self.assertRaises(ValueError):
            lq.parse_header(b'\x00\x00\x00\x20' + form[4:] + b'\x00')  # not DynaFed

    def test_witness_rules(self):
        fed, other = OneOfOne(0xabc), OneOfOne(0xdef)
        form = hash_form(bytes(32), 10, compact(fed.sbs))
        _, (r, s) = fed.sign(form)
        sig = lq.encode_der(r, s)
        cases = {
            'no sighash byte': [b'', sig, fed.script],
            'SIGHASH_NONE': [b'', sig + b'\x02', fed.script],
            'missing dummy': [sig + b'\x01', fed.script],
            'other key\'s script': [b'', sig + b'\x01', other.script],
            'other key\'s signature': [b'', lq.encode_der(*lq.ecdsa_sign(0xdef, lq.sha256d(form), 5)) + b'\x01',
                                       fed.script],
            'two signatures': [b'', sig + b'\x01', sig + b'\x01', fed.script],
        }
        for name, witness in cases.items():
            with self.assertRaises(ValueError, msg=name):
                lq.tip_signatures(lq.parse_header(signed(form, witness)))

    def test_single_key_witness_rules(self):
        fed = SingleKey(0xabc)
        form = hash_form(bytes(32), 10, compact(fed.sbs))
        raw, (r, s) = fed.sign(form)
        self.assertEqual(lq.tip_signatures(lq.parse_header(raw)), [(r, s)])
        self.assertEqual(lq.federation(fed.script), (fed.script, [lq.decompress(fed.key)[1]], 1))
        sig = lq.encode_der(r, s)
        cases = {
            'no witness': [],
            'no signature': [fed.script],
            'empty signature': [b'', fed.script],
            'multisig dummy': [b'', sig + b'\x01', fed.script],
            'no sighash byte': [sig, fed.script],
            'SIGHASH_NONE': [sig + b'\x02', fed.script],
            'other key\'s signature': [lq.encode_der(*lq.ecdsa_sign(0xdef, lq.sha256d(form), 5)) + b'\x01', fed.script],
            'two signatures': [sig + b'\x01', sig + b'\x01', fed.script],
            'multisig script of the same key': [sig + b'\x01', OneOfOne(0xabc).script],
        }
        for name, witness in cases.items():
            with self.assertRaises(ValueError, msg=name):
                lq.tip_signatures(lq.parse_header(signed(form, witness)))

    def test_epoch_start_and_vote_params(self):
        fed, nxt = OneOfOne(0xabc), OneOfOne(0x123)
        form = hash_form(bytes(32), 2_664_000, full(fed.sbs), full(nxt.sbs))
        h = lq.parse_header(fed.sign(form)[0])
        self.assertEqual((h['current']['kind'], h['proposed']['kind']), (2, 2))
        self.assertEqual(h['proposed']['signblockscript'], nxt.sbs)
        self.assertEqual(h['proposed']['raw'], full(nxt.sbs))
        self.assertEqual(h['current']['extension_space'], [b'\x02' + bytes(32)])
        with self.assertRaises(ValueError):
            lq.parse_header(fed.sign(hash_form(bytes(32), 1, b'\x00'))[0])  # null current params
        with self.assertRaises(ValueError):
            lq.parse_header(fed.sign(hash_form(bytes(32), 1, b'\x03'))[0])  # unknown params type

    def test_witness_script_forms(self):
        keys = [lq.compress(lq.point_mul(k)) for k in (5, 6, 7)]
        two_of_three = b'\x52' + b''.join(b'\x21' + k for k in keys) + b'\x53\xae'
        self.assertEqual(lq.parse_witness_script(two_of_three), (2, keys))
        self.assertEqual(lq.parse_witness_script(b'\x21' + keys[0] + b'\xac'), (1, keys[:1]))
        single = b'\x21' + keys[0] + b'\xac'
        for bad in (b'\x54' + two_of_three[1:], two_of_three[:-1] + b'\xaf', two_of_three[:-2] + b'\x52\xae',
                    two_of_three[:-1], single[:-1] + b'\xad', b'\x22' + keys[0] + b'\x00\xac',
                    b'\x41' + keys[0] + bytes(32) + b'\xac'):
            with self.assertRaises(ValueError):
                lq.parse_witness_script(bad)


class Transactions(unittest.TestCase):
    REAL = {
        'claim-deposit.hex': '63371b487d1140e07c192d3d0855f48061531970748480baab86ee7bd7ea124f',
        'bootstrap.hex': '6c9d6523f33912f763bcb35103d638c3300cab840e1202cf3b0f15d0f0c811a7',
        'update.hex': '9c7497cfcbca27871f94677fa126d96ad1b86854be5a76c4b6f71d46afed8367',
        'update-deposit.hex': 'd871612215a2a6605102a3da1031fd3682e484e5cc0aeb1fe55d9fb27ae26add',
    }

    @unittest.skipUnless(LIVE.is_dir(), f'{LIVE} (local, untracked) holds the public testnet transactions')
    def test_real_liquid_testnet_txids(self):
        seen = 0
        for name, txid in self.REAL.items():
            path = LIVE / name
            if not path.exists():
                continue
            with self.subTest(name):
                raw = bytes.fromhex(path.read_text().strip())
                form = lq.txid_form(raw)
                self.assertEqual(lq.display(lq.sha256d(form)), txid)
                self.assertEqual(lq.txid_form(form), form, 'the txid form parses as itself')
                with self.assertRaises(ValueError):
                    lq.txid_form(raw + b'\x00')
                with self.assertRaises(ValueError):
                    lq.txid_form(raw[:-1])
                seen += 1
        self.assertGreater(seen, 0, 'no known transaction file present')

    def test_merkle_branches_and_positions(self):
        def tree(leaves, index):
            branch, level = [], leaves
            while len(level) > 1:
                branch.append(level[index ^ 1] if index ^ 1 < len(level) else level[index])
                level = [lq.sha256d(level[j] + (level[j + 1] if j + 1 < len(level) else level[j]))
                         for j in range(0, len(level), 2)]
                index >>= 1
            return level[0], branch
        for n in range(1, 8):
            leaves = [lq.sha256(b'%d %d' % (n, i)) for i in range(n)]
            for i in range(n):
                root, branch = tree(leaves, i)
                self.assertEqual(lq.merkle_root(leaves[i], branch, i), root)
        with self.assertRaises(ValueError):
            lq.merkle_root(bytes(32), [bytes(32)] * 2, 4)


class BatchCommitment(unittest.TestCase):
    def test_paths_open_with_the_contract_rule(self):
        for n in range(1, 10):
            roots = [lq.sha256(b'%d' % i) for i in range(n)]
            root, levels = lq.batch_tree(roots)
            self.assertEqual(len(levels[0]) & (len(levels[0]) - 1), 0, 'padded to a power of two')
            for i in range(n):
                top, path = lq.batch_path(roots, i)
                node, k = lq.keccak256(roots[i]), i
                for sibling in path:  # LiquidLightClient._blockHeight
                    node = lq.keccak256(node + sibling) if k & 1 == 0 else lq.keccak256(sibling + node)
                    k >>= 1
                self.assertEqual((top, node), (root, root))
            with self.assertRaises(ValueError):
                lq.batch_path(roots, n)

    def test_split_stays_inside_epochs(self):
        ranges = relay.split(2_664_803, 2_665_250, 1000, 100)
        self.assertEqual(ranges[0][0], 2_664_803)
        self.assertEqual(ranges[-1][1], 2_665_250)
        for (a, b), (c, _) in zip(ranges, ranges[1:]):
            self.assertEqual(c, b + 1)
        for a, b in ranges:
            self.assertLessEqual(b - a + 1, 100)
            self.assertEqual(a // 1000, b // 1000)
        self.assertIn((2_664_903, 2_664_999), ranges)
        self.assertIn((2_665_000, 2_665_099), ranges)


class Abi(unittest.TestCase):
    def test_submit_headers_layout(self):
        headers, sigs, script, ys = [b'\x01' * 149, b'\x02' * 211], [(3, 4)], b'\x51\x21' + bytes(33) + b'\x51\xae', [5]
        data = lq.encode_submit_headers(headers, sigs, script, ys)
        self.assertEqual(data[:4], lq.keccak256(lq.SUBMIT_HEADERS.encode())[:4])
        args = data[4:]
        word = lambda at: int.from_bytes(args[at:at + 32], 'big')  # noqa: E731

        def dyn_bytes(at):
            return args[at + 32:at + 32 + word(at)]
        a0, a1, a2, a3 = (word(32 * i) for i in range(4))
        self.assertEqual(word(a0), 2)
        self.assertEqual([dyn_bytes(a0 + 32 + word(a0 + 32 + 32 * i)) for i in range(2)], headers)
        self.assertEqual((word(a1), word(a1 + 32), word(a1 + 64)), (1, 3, 4))
        self.assertEqual(dyn_bytes(a2), script)
        self.assertEqual((word(a3), word(a3 + 32)), (1, 5))
        self.assertEqual(len(args) % 32, 0)
        empty = lq.encode_submit_headers(headers, sigs)
        self.assertEqual(int.from_bytes(empty[4 + int.from_bytes(empty[4 + 64:4 + 96], 'big'):][:32], 'big'), 0)


class Fixture(unittest.TestCase):
    @unittest.skipUnless(FIXTURE.exists(), f'{FIXTURE} is written by relay.py fixture')
    def test_fixture_verifies_independently_of_foundry(self):
        f = json.loads(FIXTURE.read_text())
        b = lambda s: bytes.fromhex(s.removeprefix('0x'))  # noqa: E731
        length, h0 = f['epochLength'], f['checkpointHeight']
        self.assertEqual((h0 + 1) % length, 0)
        script = b(f['witnessScript'])
        _, keys = lq.parse_witness_script(script)
        self.assertEqual([lq.decompress(k)[1] for k in keys], [int.from_bytes(b(y), 'big') for y in f['keyY']])
        prev, height = b(f['checkpointHash']), h0 + 1
        roots = {}
        for batch in f['batches']:
            self.assertEqual(batch['firstHeight'], height)
            for raw in batch['headers']:
                h = lq.parse_header(b(raw), signed=False)
                self.assertEqual((h['prev'], h['height']), (prev, height))
                self.assertEqual(h['current']['signblockscript'], lq.p2wsh(script))
                roots[height] = h['merkle_root']
                prev, height = h['hash'], height + 1
            self.assertEqual(prev, b(batch['tipHash']))
            self.assertEqual(lq.display(prev), batch['tipId'])
            self.assertTrue(lq.ecdsa_verify(prev, int.from_bytes(b(batch['sigR']), 'big'),
                                            int.from_bytes(b(batch['sigS']), 'big'), lq.decompress(keys[0])))
        tx = f['tx']
        self.assertEqual(lq.display(lq.sha256d(b(tx['txidForm']))), tx['id'])
        self.assertEqual(lq.merkle_root(b(tx['txid']), [b(x) for x in tx['branch']], tx['position']),
                         roots[tx['height']])


if __name__ == '__main__':
    unittest.main(verbosity=2)
