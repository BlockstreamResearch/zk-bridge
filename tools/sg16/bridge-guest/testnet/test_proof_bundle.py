#!/usr/bin/env python3
"""Offline proof export tests. Cryptographic work is stubbed; identity/state/store gates run unchanged.

No proof is generated and no transaction is built, signed or sent. The existing test_testnet.py real-artifact
suite covers the paired proof check and numeric verifier. These tests cover their shared use by both callers.
"""
import argparse
import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import assemble as A


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
        self.m['update_leaf'].update(program='/missing/copied-checkout/update_leaf.simpl',
                                     text_sha256=A.pins.sha(self.program.encode()).hex())
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
        # Only the final transaction boundary is stubbed for the update caller.
        with patch.object(A, 'tool_ok', return_value=dict(ok=True)) as tx:
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
