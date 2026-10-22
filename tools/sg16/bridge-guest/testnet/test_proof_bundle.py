#!/usr/bin/env python3
"""Offline proof export tests. Cryptographic work is stubbed; identity/state/store gates run unchanged.

No proof is generated and no transaction is built, signed or sent. The existing test_testnet.py real-artifact
suite covers the paired proof check and numeric verifier. These tests cover their shared use by both callers, and
the deployment gates they share with bootstrap: the generator source, the key pins, the loop bounds of a built
program and the budget evidence (LoopBounds compiles two small verifiers, seconds each).
"""
import argparse
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import assemble as A
from groth.dsl import CheckFailed


INSTANCE = A.ROOT / 'instances' / 'sepolia-liquid-testnet'


class ProofBundle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='proof-bundle-')
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.inst = A.pins.load(INSTANCE / 'instance.json')
        self.m = A.load_manifest(INSTANCE / 'manifest.json')
        self.state = A.initial_state(self.inst)
        self.new = A.state_record(self.state['head'] + 32, bytes.fromhex('44' * 32), bytes.fromhex('55' * 32),
                                  bytes.fromhex('66' * 32), [], exec_root='77' * 32, exec_block=123)
        self.fields = dict(lc=bytes.fromhex(self.state['lc']), new_lc=bytes.fromhex(self.new['lc']),
                           new_acc=bytes.fromhex(self.new['acc']), exec_root=bytes.fromhex(self.new['exec_root']),
                           exec_block=self.new['exec_block'], new_head=self.new['head'])
        pv = A.liquid.public_values(A.sepolia_config(), bytes.fromhex(self.inst.escrow), A.pins.SLOT_KEY, self.fields)
        self.keys = dict(vkey=int(self.inst.program_vkey, 16), vk_root=int(A.pins.VK_ROOT, 16),
                         selector=bytes.fromhex(A.pins.VERIFIER_HASH)[:4], vk5={}, vk1={})
        self.art = dict(guest=A.pins.GUEST, network='sepolia', sdkVersion=A.pins.SP1_SDK,
                        vkey='0x' + self.inst.program_vkey, proof='0x' + (self.keys['selector'] + bytes(352)).hex(),
                        publicValues='0x' + pv.hex(), public_input=hex(A.statement.public_input(A.pins.sha(pv))),
                        outputs=dict(prev_lc='0x' + self.state['lc'], new_lc='0x' + self.new['lc'],
                                     slot_value='0x' + self.new['acc'], new_head=self.new['head'],
                                     execution_block_number=self.new['exec_block']),
                        successor=dict(slot=self.new['head'], header=self.new['header'], committee=self.new['committee']))
        self.args = argparse.Namespace(instance=INSTANCE / 'instance.json', manifest=self.work / 'manifest.json',
                                       state=self.work / 'state.json', artifact=self.work / 'proof.json',
                                       out=self.work / 'proof.browser.json', store=None)
        # A small program avoids parsing the real 1.6 MB program on each case. The SHA gate remains real.
        self.program = 'test program text'
        (self.work / 'update_leaf.simpl').write_text(self.program)
        cost = self.m['update_leaf']['predicted_cost']
        # The smallest budget the gate accepts for a rehearsal with root's measured program size.
        rehearsal = dict(ok=True, inputs=1, predicted_cost=cost, cost=cost, program_bytes=34_961, witness_bits=7,
                         budget_mwu=cost + 1000 * A.program_variation(34_961, 1), tx_weight=59_087)
        self.m['update_leaf'].update(program='/missing/copied-checkout/update_leaf.simpl',
                                     text_sha256=A.pins.sha(self.program.encode()).hex(), generator=A.GENERATOR,
                                     inputs=1, budget=dict(witness_bits=7, rehearsal=rehearsal))
        self.save()
        self.patch('sp1_keys', return_value=self.keys)
        self.patch('sp1.decode_proof', return_value=(self.keys['selector'],
                   dict(exit_code=0, vk_root=self.keys['vk_root'], proof_nonce=0), 'proof'))
        self.pairings = self.patch('B.groth16_verify', side_effect=lambda key, proof, inputs: inputs[-1] !=
                                  (int(self.art['public_input'], 16) ^ 1))
        self.verifier = Mock()
        self.verifier.witness_fields.side_effect = lambda proof, digest, fields: dict(fields)
        self.verifier.num_input.side_effect = lambda wit: wit
        self.verifier.witness_value.side_effect = lambda wit: {k: v.hex() if isinstance(v, bytes) else v
                                                              for k, v in wit.items()}
        self.patch('update_verifier', return_value=self.verifier)
        self.tool = self.patch('tool', side_effect=self.read_only_tool)
        self.add_store()

    def patch(self, name, **kw):
        p = patch('assemble.' + name, **kw)
        self.addCleanup(p.stop)
        return p.start()

    def save(self):
        for path, value in ((self.args.manifest, self.m), (self.args.state, self.state), (self.args.artifact, self.art)):
            A.write_json(path, value)

    def read_only_tool(self, path, cmd, *args):
        self.assertEqual(cmd, 'compile-update', 'proof export must not build or inspect a transaction')
        self.assertEqual(len(args), 3, 'compiler accepts source, witness and output only')
        program, witness, out = map(Path, args)
        self.assertEqual(program.read_text(), self.program)
        compiled = dict(program_hex=program.read_bytes().hex(), witness_hex=witness.read_bytes().hex(),
                        cmr=self.m['update_leaf']['cmr'])
        A.write_json(out, compiled)
        return 0, dict(ok=True, cmr=compiled['cmr'], program_bytes=program.stat().st_size,
                       witness_bytes=witness.stat().st_size, path=str(out))

    def export(self):
        self.save()
        return A.cmd_export_proof(self.args, A.Gates())

    def test_export_shares_exact_preparation_with_update(self):
        result = self.export()
        bundle = json.loads(self.args.out.read_text())
        self.assertEqual(bundle['schema'], 'zk-bridge/browser-proof')
        self.assertEqual(bundle['program'], self.program)
        self.assertEqual(bytes.fromhex(bundle['compiled_program']['program_hex']).decode(), self.program)
        self.assertEqual(json.loads(bytes.fromhex(bundle['compiled_program']['witness_hex'])), bundle['witness'])
        self.assertEqual(bundle['compiled_program']['cmr'], self.m['update_leaf']['cmr'])
        self.assertEqual(bundle['new_state'], self.new)
        self.assertEqual(bundle['state'], self.state)
        self.assertEqual(bundle['instance']['sepolia']['escrow'], self.inst.escrow)
        self.assertEqual(bundle['successor_store'], self.store)
        self.assertNotIn('txid', json.dumps(bundle))
        self.assertTrue(result['successor_store_included'])
        self.assertEqual(self.pairings.call_count, 3)
        self.verifier.verify.assert_called_once()
        args = argparse.Namespace(**dict(vars(self.args), out=self.work / 'update.hex', state_tx='unused',
                                         state_vout=0, fee_tx='unused', fee_vout=0, local_test=False))
        # Only the final transaction boundary is stubbed for the update caller, with the program size root measured
        # for the real SP1 key (target/groth16-opt/real-proof/report.json).
        with patch.object(A, 'tool_ok', return_value=dict(ok=True, program_bytes=34_957)) as tx:
            A.cmd_update(args, A.Gates())
        self.assertEqual(tx.call_args.args[3], 'update')
        self.assertEqual(json.loads((self.work / 'update.witness.json').read_text()), bundle['witness'])
        self.assertEqual(json.loads((self.work / 'update.new_state.json').read_text()), bundle['new_state'])
        self.assertEqual(self.pairings.call_count, 6)
        self.assertEqual(self.verifier.verify.call_count, 2)

    def test_claims_regenerate_witness_without_changing_proof(self):
        self.export()
        first = json.loads(self.args.out.read_text())
        self.state = A.state_record(self.state['head'], A.b32(self.state['header']), A.b32(self.state['committee']),
                                    A.b32(self.state['acc']), [0, 2])
        self.export()
        second = json.loads(self.args.out.read_text())
        self.assertNotEqual(first['witness'], second['witness'])
        self.assertEqual(first['compiled_program']['program_hex'], second['compiled_program']['program_hex'])
        self.assertNotEqual(first['compiled_program']['witness_hex'], second['compiled_program']['witness_hex'])
        self.assertEqual(second['new_state']['claimed'], [0, 2])
        self.assertEqual(second['new_state']['lc'], first['new_state']['lc'])
        self.assertEqual(second['state']['acc'], first['state']['acc'])

    def refused(self, text):
        with self.assertRaisesRegex(A.Gate, text):
            self.export()
        self.assertFalse(self.args.out.exists())
        self.assertFalse(self.args.out.with_name(self.args.out.name + '.part').exists())

    def test_wrong_instance(self):
        self.m['sepolia']['escrow'] = '88' * 20
        self.refused('manifest = the given instance')

    def test_wrong_artifact(self):
        self.art['vkey'] = '0x1'
        self.refused('program vkey')

    def test_execute_only(self):
        self.art['proof'] = '0x'
        self.refused('not execute-only')

    def test_pairing_failure(self):
        self.pairings.side_effect = None
        self.pairings.return_value = False
        self.refused('BN254 pairing')

    def test_numeric_failure(self):
        self.verifier.witness_fields.side_effect = None
        self.verifier.witness_fields.return_value = None
        self.refused('numeric Groth16')

    def test_advanced_light_client_state(self):
        self.state = copy.deepcopy(self.new)
        self.refused('prev_lc')

    def test_inconsistent_claimed_state(self):
        self.state['claimed'] = [0]
        self.refused('claimed_root')

    def test_inconsistent_state_hash(self):
        self.state['state_hash'] = '11' * 32
        self.refused('recomputes its lc and state hash')

    def test_no_local_test_bypass(self):
        self.m['deployable'] = False
        self.refused('deployable')
        self.m['deployable'] = True
        self.m['update_leaf']['stand_in'] = True
        self.refused('compiled update leaf')

    def test_leaf_of_another_generator_is_refused(self):
        del self.m['update_leaf']['generator']
        self.refused('compiled by simple-groth16')
        self.m['update_leaf']['generator'] = 'simple-groth16 4f787ea07b97e62bd0ba4fa3f9518d52621dcb68'
        self.refused('compiled by simple-groth16')

    def test_unpinned_generator_is_refused(self):
        # An override, an edited tree or another commit (sg16/ref.py inspect): refused, and never named as pinned.
        self.patch('PINNED', new=False)
        self.refused('loaded generator is the pinned')
        self.assertNotEqual(A.loaded_generator(), A.GENERATOR)
        self.assertIn('not pinned', A.loaded_generator())

    def test_leaf_without_budget_for_program_variation_is_refused(self):
        rehearsal = self.m['update_leaf']['budget']['rehearsal']
        rehearsal['budget_mwu'] -= 1
        self.refused('rehearsed input budget')
        rehearsal['budget_mwu'] += 1
        # A spend whose program is larger by the variation would reach standard weight.
        rehearsal['tx_weight'] = A.pins.STANDARD_TX_WEIGHT - A.program_variation(34_961, 1)
        self.refused('rehearsed input budget')
        rehearsal['tx_weight'] = 59_087
        del rehearsal['program_bytes']
        self.refused('rehearsed input budget')

    def test_leaf_without_matching_rehearsal_is_refused(self):
        budget = self.m['update_leaf']['budget']
        budget['rehearsal']['predicted_cost'] -= 1
        self.refused('executed at its predicted cost')
        # Executed at its own prediction, but not the update leaf's cost: the instance's own leaf and its rehearsal
        # predict the same cost (48,884,728 mWU in target/groth16-optimization/repair-real-proof/manifest.json).
        budget['rehearsal']['cost'] -= 1
        self.refused("predicted cost = the update leaf's")
        budget['rehearsal']['cost'] += 1
        budget['rehearsal']['predicted_cost'] += 1
        self.export()
        self.args.out.unlink()
        budget['rehearsal']['inputs'] = 2
        self.refused('1 public input')
        budget['rehearsal']['inputs'] = 1
        self.m['update_leaf']['inputs'] = 2
        self.refused('1 public input')
        self.m['update_leaf']['inputs'] = 1
        budget['witness_bits'] = 8
        self.refused('same witness width')
        del self.m['update_leaf']['budget']
        self.refused('executed at its predicted cost')

    def test_update_refuses_a_spend_unlike_its_rehearsal(self):
        args = argparse.Namespace(**dict(vars(self.args), out=self.work / 'update.hex', state_tx='unused',
                                         state_vout=0, fee_tx='unused', fee_vout=0, local_test=False))
        less = A.program_variation(34_961, 1)
        for size in (34_961 - less - 1, 34_961 + less + 1, None):
            with self.subTest(program_bytes=size), patch.object(A, 'tool_ok', return_value=dict(ok=True,
                                                                                            program_bytes=size)):
                self.save()
                with self.assertRaisesRegex(A.Gate, 'within program_variation'):
                    A.cmd_update(args, A.Gates())
        with patch.object(A, 'tool_ok', return_value=dict(ok=True, program_bytes=34_961 - less)):
            A.cmd_update(args, A.Gates())

    def test_program_bytes_and_cmr_are_checked(self):
        (self.work / 'update_leaf.simpl').write_text('changed')
        self.refused('SHA-256')
        (self.work / 'update_leaf.simpl').write_text(self.program)
        def wrong_cmr(*args):
            code, r = self.read_only_tool(*args)
            r['cmr'] = '00' * 32
            return code, r
        self.tool.side_effect = wrong_cmr
        self.refused('manifest update CMR')

    def test_compiler_failure_does_not_export(self):
        self.tool.side_effect = None
        self.tool.return_value = 3, dict(ok=False, failed_gate='invalid witness')
        self.refused('invalid witness')

    def test_old_compiler_directs_rebuild_without_reproving(self):
        self.tool.side_effect = A.Gate('sg16-testnet compile-update: no JSON output; usage: sg16-testnet ...')
        before = self.args.artifact.read_bytes()
        self.refused('run just tools, then just proof-bundle')
        self.assertEqual(self.args.artifact.read_bytes(), before)

    def test_missing_compiler_output_does_not_reuse_an_old_file(self):
        compiled = self.args.out.with_suffix('.compiled.json')
        A.write_json(compiled, dict(program_hex='00', witness_hex='00', cmr=self.m['update_leaf']['cmr']))
        self.tool.side_effect = None
        self.tool.return_value = 0, dict(ok=True, cmr=self.m['update_leaf']['cmr'])
        self.refused('compiler wrote')
        self.assertFalse(compiled.exists())

    def test_malformed_compiler_output_is_refused(self):
        for changed, fragment in (({'cmr': '00' * 32}, 'manifest update CMR'),
                                  ({'program_hex': '0'}, 'canonical hex'),
                                  ({'witness_hex': 'zz'}, 'canonical hex'),
                                  ({'program_hex': ''}, 'canonical hex'),
                                  ({'witness_hex': None}, 'canonical hex'),
                                  ({'program_hex': '00'}, 'length = compiler report')):
            with self.subTest(changed=changed):
                def bad_output(*args):
                    code, r = self.read_only_tool(*args)
                    out = Path(args[-1])
                    A.write_json(out, dict(json.loads(out.read_text()), **changed))
                    return code, r
                self.tool.side_effect = bad_output
                self.refused(fragment)

    def test_non_object_and_invalid_json_compiler_output(self):
        for text, fragment in (('[]', 'compiler output is an object'), ('not json', 'compiler output JSON')):
            with self.subTest(text=text):
                def bad_output(*args):
                    code, r = self.read_only_tool(*args)
                    Path(args[-1]).write_text(text)
                    return code, r
                self.tool.side_effect = bad_output
                self.refused(fragment)

    def test_export_is_independent_of_state_and_fee_outpoints(self):
        self.export()
        first = json.loads(self.args.out.read_text())
        # These belong to transaction assembly and must never enter proof compilation or the bundle.
        self.args.state_tx = 'unreadable state transaction'
        self.args.fee_tx = 'unreadable fee transaction'
        self.args.state_vout = 123
        self.args.fee_vout = 456
        self.export()
        self.assertEqual(first, json.loads(self.args.out.read_text()))
        self.assertTrue(all(len(call.args) == 5 for call in self.tool.call_args_list))

    def add_store(self):
        self.args.store = self.work / 'proof.store.json'
        self.store = {k: self.new[k] for k in ('head', 'header', 'committee', 'lc')}
        self.store.update(store_cbor='0x1234', about='full successor store', extra={'preserved': True})
        A.write_json(self.args.store, self.store)
        self.patch('HOST_TOOL', new=self.work / 'host')
        A.HOST_TOOL.touch()
        self.host = self.patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0,
                               json.dumps(dict(self.store, matches_state_lc=True)), ''))

    def test_includes_complete_checked_store(self):
        self.export()
        self.assertEqual(json.loads(self.args.out.read_text())['successor_store'], self.store)
        self.assertEqual(self.host.call_args.args[0], [str(A.HOST_TOOL), 'check-store', str(self.args.store),
                                                     '--lc', self.new['lc']])

    def test_store_of_another_successor(self):
        A.write_json(self.args.store, dict(self.store, committee='99' * 32))
        self.refused('store roots')
        self.host.assert_not_called()

    def test_invalid_store_cbor(self):
        self.host.return_value = subprocess.CompletedProcess([], 1, '', 'store_cbor: a Helios light-client store')
        self.refused('store CBOR')

    def test_host_success_without_expected_roots_fails(self):
        self.host.return_value = subprocess.CompletedProcess([], 0, '{}', '')
        self.refused('host checked')


class ProgramVariation(unittest.TestCase):
    def test_natural_codes_match_rust_simplicity(self):
        # encode_natural: 1 -> 0; 2 -> 1 0 0; 16 -> 1 1 1 0 0 00 0000; 2^16 + 1 has 17 + 5 + 3 + 2 + 1 bits.
        self.assertEqual([A.natural_bits(n) for n in (1, 2, 3, 4, 16, 65_537)], [1, 3, 3, 6, 11, 28])

    def test_bound_for_the_measured_leaf(self):
        # One input: 32 windows (6 bits and 31 x 8), 254 case nodes and one leaf code each, and the 8 case nodes of
        # the shared 8-bit digit function.  N <= 2 * (34,961 + 4,096) = 78,114 nodes, codes of at most 28 bits.
        self.assertEqual(len(A.windows(1)), 32)
        self.assertEqual(sum(w for _, _, w in A.windows(1)), 254)
        self.assertEqual(A.program_variation(34_961, 1), ((254 + 32) * 28 + 8 * (260 + 3 * 28) + 7) // 8 + 3)
        self.assertEqual(A.program_variation(34_961, 1), 1348)

    def test_the_real_proof_spend_fits(self):
        # Root's repair run (target/groth16-optimization/repair-real-proof): the instance's own leaf predicts
        # 48,884,728 mWU, its rehearsal ran at that cost with a budget of 53,780,000 mWU, 34,952 program bytes and
        # 59,078 WU; the offline CLI update with a real SP1 proof cost 48,884,728 mWU, with a budget of 53,785,000,
        # 34,957 program bytes and 59,084 WU, at 2,000 sats.
        rehearsal = dict(ok=True, inputs=1, predicted_cost=48_884_728, cost=48_884_728, budget_mwu=53_780_000,
                         program_bytes=34_952, tx_weight=59_078, witness_bits=6272)
        g = A.Gates()
        A.budget_gate(g, rehearsal, dict(cost=48_884_728, inputs=1, witness_bits=6272))
        self.assertTrue(all(r['ok'] for r in g.results))
        # The cost of another config's leaf (the bridge-guest fixture's 48,885,568) is not this rehearsal's.
        with self.assertRaisesRegex(A.Gate, "predicted cost = the update leaf's"):
            A.budget_gate(A.Gates(), rehearsal, dict(cost=48_885_568, inputs=1, witness_bits=6272))
        less = A.program_variation(34_952, 1)
        self.assertLessEqual(abs(34_957 - 34_952), less)
        self.assertLessEqual(48_884_728, 53_785_000 - 1000 * less)
        self.assertLess(59_084 + less, A.pins.STANDARD_TX_WEIGHT)
        self.assertGreaterEqual(2000, A.fee_floor(59_084))


class LoopBounds(unittest.TestCase):
    """covenant.py BridgeVerifier.compile: the built steps' output bounds stay within the loop state's fixed point."""

    def compile(self, b=None):
        vk, _, _ = A.B.groth16_instance(1, seed=5)
        k = dict(token_a=dict(bit=0, x='11' * 32), token_b=dict(bit=1, x='22' * 32),
                 token_value=dict(bit=0, x='33' * 32), fee_asset='44' * 32)
        return A.liquid.BridgeGuestVerifier.compile(vk, k, b=b, opened=0, config=bytes(32), escrow=bytes(20))

    def test_the_built_steps_stay_within_the_fixed_point(self):
        sampled = {k: v for k, v in A.bounds().items() if k.endswith('_out')}
        _, g, _ = self.compile(dict(A.bounds(), **{k: 0 for k in sampled}))
        self.assertEqual(g.n, 1)
        for nm in ('N', 'D', 'acc', 'x', 'y', 'qz'):
            # Set by this build's step bodies: the zeroed sampled values were dropped, so they are not these.
            self.assertGreater(g.pc.b[nm + '_out'], 0, nm)
            self.assertLessEqual(g.pc.b[nm + '_out'], g.pc.b[nm], nm)

    def test_a_bound_below_the_fixed_point_stops_the_build(self):
        # The sampled outputs, which fit the true bounds, are dropped, so only the symbolic steps' own outputs, computed
        # from the halved input bound, can exceed it.
        b = dict(A.bounds())
        b['acc'] //= 2
        with self.assertRaisesRegex(CheckFailed, 'exceed their fixed point'):
            self.compile(b)


class KeyPins(unittest.TestCase):
    def setUp(self):
        self.k = A.sp1.solidity_constants((A.V6 / 'Groth16Verifier.sol').read_text())

    def test_the_vendored_key_is_the_pinned_key(self):
        self.assertEqual(A.key_pin_problems(self.k), [])
        self.assertEqual(A.sp1.vk_from_gnark_solidity((A.V6 / 'Groth16Verifier.sol').read_text())[0], A.pinned_key())
        self.assertEqual(len(A.pins.GROTH16_KEY_PINS), 2 + 3 * 4 + 2 * 6)

    def test_a_negated_point_or_another_input_is_refused(self):
        for name in ('ALPHA_Y', 'BETA_NEG_Y_0', 'PUB_4_Y'):
            with self.subTest(negated=name):
                self.assertEqual(A.key_pin_problems(dict(self.k, **{name: A.B.P - self.k[name]})), [name])
        self.assertEqual(A.key_pin_problems(dict(self.k, PUB_5_X=1, PUB_5_Y=2)), ['PUB_5_X', 'PUB_5_Y'])
        missing = dict(self.k)
        del missing['DELTA_NEG_X_1']
        self.assertEqual(A.key_pin_problems(missing), ['DELTA_NEG_X_1'])


class GeneratorSource(unittest.TestCase):
    """sg16/ref.py inspect: only a vendor checkout whose importable files are the pinned commit's is pinned, whatever
    the index or `git status` says."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='generator-source-')
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / 'simple-groth16'
        (self.repo / 'groth').mkdir(parents=True)
        (self.repo / 'groth' / '__init__.py').write_text('')
        (self.repo / 'groth' / 'groth16.py').write_text('X = 1\n')
        (self.repo / 'tests').mkdir()
        (self.repo / 'tests' / 'test_x.py').write_text('')
        git = lambda *a: subprocess.run(['git', '-C', str(self.repo), *a], check=True, capture_output=True)  # noqa: E731
        self.commit = ['-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false', 'commit', '-q']
        git('init', '-q')
        git('add', '-A')
        git(*self.commit, '-m', 'pin')
        self.pin = git('rev-parse', 'HEAD').stdout.decode().strip()
        self.git = git

    def inspect(self, vendor=None):
        return A.sg16_ref.inspect(self.repo, pin=self.pin, vendor=vendor or self.repo)

    def status(self):
        return self.git('status', '--porcelain', '--untracked-files=all').stdout.decode()

    def refused(self, fragment):
        s = self.inspect()
        self.assertEqual((s['commit'], s['pinned'], s['usable']), (self.pin, False, False), s)
        self.assertTrue(any(fragment in c for c in s['changes']), s['changes'])

    def test_clean_checkout_at_the_pin(self):
        s = self.inspect()
        self.assertTrue(s['pinned'] and s['usable'] and s['changes'] == [] and s['commit'] == self.pin)
        # What Python does not import from the checkout is not compared: bytecode caches, desktop metadata, build
        # output, and files outside the packages.
        (self.repo / 'groth' / '__pycache__').mkdir()
        (self.repo / 'groth' / '__pycache__' / 'groth16.cpython-314.pyc').write_bytes(b'cache')
        (self.repo / 'groth' / '.DS_Store').write_bytes(b'')
        (self.repo / 'build').mkdir()
        (self.repo / 'build' / 'out.txt').write_text('')
        (self.repo / 'tests' / 'scratch.py').write_text('')
        self.assertTrue(self.inspect()['pinned'], self.inspect())

    def test_edited_or_added_source_at_the_pin(self):
        (self.repo / 'groth' / 'groth16.py').write_text('X = 2\n')
        self.refused('groth/groth16.py: differs')
        (self.repo / 'groth' / 'groth16.py').write_text('X = 1\n')
        (self.repo / 'groth' / 'extra.py').write_text('')
        self.refused('groth/extra.py: not in the pinned tree')
        (self.repo / 'groth' / 'extra.py').unlink()
        (self.repo / 'groth' / '__init__.py').unlink()  # groth would still import, as a namespace package
        self.refused('groth/__init__.py: missing')
        (self.repo / 'groth' / '__init__.py').write_text('')
        self.git(*self.commit, '--allow-empty', '-m', 'later')
        self.assertFalse(self.inspect()['pinned'])

    def test_edits_hidden_from_the_index(self):
        # The reproducer: git status is clean while groth16.py runs other code.
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                self.git('update-index', flag, 'groth/groth16.py')
                (self.repo / 'groth' / 'groth16.py').write_text('X = 2\n')
                self.assertEqual(self.status(), '')
                self.refused('groth/groth16.py: differs from the pinned file')
                (self.repo / 'groth' / 'groth16.py').write_text('X = 1\n')
                self.git('update-index', flag.replace('--', '--no-'), 'groth/groth16.py')

    def test_ignored_additions_that_python_imports(self):
        (self.repo / '.git' / 'info' / 'exclude').write_text('groth/shadow.py\ngroth/fp/\njson.py\nhashlib/\n')
        cases = [(self.repo / 'groth' / 'shadow.py', 'groth/shadow.py'),
                 (self.repo / 'groth' / 'fp' / '__init__.py', 'groth/fp/'),
                 (self.repo / 'json.py', 'json.py'),  # first on sys.path: it would shadow the standard json
                 (self.repo / 'hashlib' / '__init__.py', 'hashlib/')]
        for path, fragment in cases:
            with self.subTest(added=fragment):
                path.parent.mkdir(exist_ok=True)
                path.write_text('X = 2\n')
                self.assertEqual(self.status(), '')
                self.refused(fragment)
                path.unlink()
                if path.name == '__init__.py':
                    path.parent.rmdir()
        self.assertTrue(self.inspect()['pinned'])

    def test_a_symbolic_link(self):
        (self.repo / 'groth' / 'link.py').symlink_to(self.repo / 'groth' / 'groth16.py')
        self.refused('groth/link.py: a symbolic link')

    def test_an_object_that_does_not_hash_to_its_name(self):
        import zlib
        path = self.repo / '.git' / 'objects' / self.pin[:2] / self.pin[2:]
        data = zlib.decompress(path.read_bytes())
        path.chmod(0o644)
        path.write_bytes(zlib.compress(data.replace(b'\npin\n', b'\npim\n')))
        # Refused either way: some git versions reject the object while resolving HEAD, others hand it over and
        # inspect finds that it does not hash to its name.
        s = self.inspect()
        self.assertEqual((s['changes'], s['pinned'], s['usable']), (None, False, False), s)
        self.assertTrue(s['error'], s)

    def load(self, **env):
        """Import sg16/ref.py in a fresh interpreter with SG16_REF at the test checkout."""
        code = ('import sys; sys.path.insert(0, sys.argv[1]); from sg16 import ref; '
                'print(ref.PINNED, ref.STATE["usable"], ref.STATE["override"], ref.REF == ref.Path(sys.argv[2]))')
        base = {k: v for k, v in os.environ.items() if k != 'SG16_ALLOW_UNPINNED'}
        return subprocess.run([sys.executable, '-c', code, str(A.ROOT / 'tools' / 'sg16'), str(self.repo.resolve())],
                              capture_output=True, text=True, env=dict(base, SG16_REF=str(self.repo), **env))

    def test_experiments_load_only_on_request_and_never_as_pinned(self):
        (self.repo / 'groth' / 'groth16.py').write_text('X = 2\n')
        r = self.load()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('SG16_ALLOW_UNPINNED=1', r.stdout + r.stderr)
        r = self.load(SG16_ALLOW_UNPINNED='1')
        self.assertEqual((r.returncode, r.stdout.split()), (0, ['False', 'False', 'True', 'True']), r.stderr)

    def test_a_stale_bytecode_cache_does_not_run_on_a_verified_checkout(self):
        import py_compile
        (self.repo / 'groth' / 'user.py').write_text('from .groth16 import X\nY = X + 1\n')
        self.git('add', '-A')
        self.git(*self.commit, '-m', 'user')
        pin = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        # An edit compiled into the cache and undone with its old timestamp: same size, same time, other code.
        source, t = self.repo / 'groth' / 'groth16.py', 1_700_000_000
        source.write_text('X = 2\n')
        os.utime(source, (t, t))
        cache = source.parent / '__pycache__' / f'groth16.{sys.implementation.cache_tag}.pyc'  # whatever the prefix
        py_compile.compile(str(source), cfile=str(cache), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        source.write_text('X = 1\n')
        os.utime(source, (t, t))
        code = ('import sys\nsys.path.insert(0, sys.argv[1])\nfrom sg16 import ref\nverified = {}\n'
                's = ref.inspect(ref.REF, pin=sys.argv[2], vendor=ref.REF, verified=verified)\n'
                'assert s["usable"], s\n'
                'if sys.argv[3] == "verified":\n    ref.install(ref.generator_sources(ref.REF, verified))\n'
                'import groth.groth16, groth.user\nprint(groth.groth16.X, groth.user.Y, groth.groth16.__file__)\n'
                'try:\n    import groth.missing\nexcept ImportError:\n    print("refused")\n')
        base = {k: v for k, v in os.environ.items() if k not in ('SG16_ALLOW_UNPINNED', 'PYTHONPYCACHEPREFIX')}

        def run(mode):
            # An experiment load of the test checkout (it is not at PIN), then the check against its own commit.
            r = subprocess.run([sys.executable, '-c', code, str(A.ROOT / 'tools' / 'sg16'), pin, mode],
                               capture_output=True, text=True,
                               env=dict(base, SG16_REF=str(self.repo), SG16_ALLOW_UNPINNED='1'))
            self.assertEqual(r.returncode, 0, r.stderr)
            return r.stdout.split()
        # Python's own loader runs the stale cache: this is what the deployment path must not do.
        self.assertEqual(run('plain')[:2], ['2', '3'])
        # VerifiedSource runs the checked bytes; relative imports between groth modules work; unverified is refused.
        self.assertEqual(run('verified'), ['1', '2', str(source.resolve()), 'refused'])

    def test_an_override_is_never_pinned(self):
        s = self.inspect(vendor=Path(self.tmp.name) / 'vendor' / 'simple-groth16')
        self.assertTrue(s['usable'])
        self.assertFalse(s['pinned'])

    def test_a_directory_git_cannot_describe(self):
        bare = Path(self.tmp.name) / 'copy'
        (bare / 'groth').mkdir(parents=True)
        (bare / 'groth' / '__init__.py').write_text('')
        (bare / 'groth' / 'groth16.py').write_text('X = 1\n')
        s = A.sg16_ref.inspect(bare, pin=self.pin, vendor=bare)
        self.assertEqual((s['commit'], s['changes'], s['pinned']), (None, None, False))
        self.assertTrue(s['error'])
        # The source hash names the files' bytes, whatever git says.
        self.assertEqual(s['source_sha256'], A.sg16_ref.source_digest(self.repo))

    def test_this_checkout_records_what_it_loaded(self):
        self.assertEqual(A.PINNED, A.GENERATOR_STATE['pinned'])
        self.assertEqual(A.loaded_generator() == A.GENERATOR, A.PINNED)
        if A.GENERATOR_STATE['usable']:  # this process imported groth from the verified bytes, not from caches
            for name in ('groth', 'groth.pairing', 'groth.groth16'):
                self.assertIs(sys.modules[name].__spec__.loader, A.sg16_ref.FINDER, name)


@unittest.skipIf(not A.TX_TOOL.is_file(), 'build the transaction tools with just tools')
class CanonicalCompilation(unittest.TestCase):
    def test_real_compiler_writes_program_and_witness_without_a_transaction(self):
        program = 'w := witness : 1 -> 2\nmain := comp (w) (jet_verify)\n'
        cmr = '8f48edd03b38574898622bfde2ac6484f6bc5b5bbfc5d7c03ccc9858e66130ba'
        with tempfile.TemporaryDirectory(prefix='compiled-proof-') as tmp:
            out = Path(tmp) / 'proof.browser.json'
            compiled = A.compile_browser_proof(A.Gates(), program, {'w': {'bit': 1}}, cmr, out)
            self.assertEqual(compiled['cmr'], cmr)
            self.assertEqual(len(bytes.fromhex(compiled['program_hex'])), 3)
            self.assertEqual(len(bytes.fromhex(compiled['witness_hex'])), 1)


@unittest.skipIf(not A.HOST_TOOL.is_file(), 'build the bridge host with just host')
class StoreContents(unittest.TestCase):
    def test_real_host_checks_cbor_not_only_declared_roots(self):
        new = A.initial_state(A.pins.load(INSTANCE / 'instance.json'))
        path = INSTANCE / 'lc_stores' / f"{new['head']}.json"
        checked = A.successor_store(A.Gates(), path, new)
        self.assertEqual(checked, json.loads(path.read_text()))
        with tempfile.TemporaryDirectory(prefix='proof-store-') as tmp:
            tampered = Path(tmp) / 'store.json'
            A.write_json(tampered, dict(checked, store_cbor='0x00'))
            with self.assertRaisesRegex(A.Gate, 'store CBOR'):
                A.successor_store(A.Gates(), tampered, new)


if __name__ == '__main__':
    unittest.main()
