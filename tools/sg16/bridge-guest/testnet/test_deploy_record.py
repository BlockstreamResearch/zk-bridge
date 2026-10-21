#!/usr/bin/env python3
"""Offline tests of `just deploy-record`'s Sepolia readback and of the starting store that `just deploy-anchor` and
`just deploy-record` write: python3 tools/sg16/bridge-guest/testnet/test_deploy_record.py

The recipes run from the repository's justfile against stand-ins for cast, curl and sg16-bridge-host on PATH, in a
temporary DEPLOY_WORK and BRIDGE_INSTANCE. No network access; nothing is signed or sent. The constructor values are
those of the current Sepolia deployment and Liquid checkpoint 2,668,999. A synthetic later relay raises lcTipHeight
before deploy-record. The anchor is synthetic and the funding output is reported unspent by the curl stand-in. The
host stand-in reads the anchor inputs as JSON of the bootstrap's slot and roots, and its reconstruct and check-store
recompute lc with pins.lc as the host does.

  - the deployment block's storage is the checkpoint and the current tip has advanced: the record is written, with
    the deployment's code hash, DOMAIN and block (the earlier recipe read only the current tip and refused this)
  - the record gets the anchor's store at lc_stores/<anchor slot>.json, rebuilt by reconstruct --head --lc
    --source <anchor inputs> --offline and read back by check-store, and an lc_preimages.json whose only entry is
    the starting store: the anchor's head and roots and the store, with no update transaction
  - deploy-anchor writes and checks the same store in DEPLOY_WORK
  - refused, with no record: storage at the deployment block that is not the checkpoint or the parameters' depositsEnd;
    an RPC without state at the deployment block (not an archive node); a receipt of another block or a failed
    creation; a deployment block that is not finalized; code now that is not the deployed code; a current tip
    below the checkpoint; a current depositsEnd after the parameters'; anchor inputs that do not give the anchor's
    store; a rebuilt store that does not hash to the anchor lc
  - an existing lc_preimages.json or lc_stores/ in the record is refused and left as it was
  - no output names SEPOLIA_EXECUTION_RPC's value
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pins  # noqa: E402

ROOT = HERE.parents[3]
JUST = shutil.which('just')

ESCROW = '0xa575fCa96F5079E50fFC568C44A65598A35Ee2A8'
DEPLOY_TX = '0xb5288a0cd1276bfd415f007bfb0ce05ce985585e3ea6d70296325de903a584fd'
DEPLOY_BLOCK = 11_957_564
CODE_HASH = '0x16e9013879ca9176cd66f8ae0d1d1670b2e61a0566d9e5a024181a23abd4b71d'
DOMAIN = '0x0ddb071bb90e30a52032cc69e37093d24756355eaf466a3dfc9f66f980d4f083'
ASSET = '0x097c43d4f52775b19edb9e26d536e4b84d8e370ab3abfc1223c0e8bf0d1df7b3'
FUNDING = '936978f0507f60873983ea03fa6d14f4fe9d632a1a16fe273cd033bbbcd46414:1'
CHECKPOINT_HEIGHT = 2_668_999
CHECKPOINT_HASH = '0xf94e71dcf3e7d844454c43fbe2993b23df680178c51d3e14dd7683b472da5c4f'
SIGNBLOCKSCRIPT = '0x3445876b7281e084740f2ec2731ad9b00c50f08a5cfa363b4ada5141539f1c4f'
DEPOSITS_END = 1_795_115_088
TIP_HEIGHT = 2_669_005
TIP_HASH = '0x' + '22' * 32
RPC_SECRET = 'https://sepolia.rpc.invalid/v2/do-not-print-this-key'

FAKE_CAST = r'''#!/usr/bin/env python3
import json, os, sys
s, args = json.load(open(os.environ['FAKE_SEPOLIA'])), sys.argv[1:]
with open(os.environ['FAKE_SEPOLIA'] + '.calls', 'a') as log:
    log.write(json.dumps(args) + '\n')
if os.environ.get('ETH_RPC_URL') != os.environ.get('SEPOLIA_EXECUTION_RPC'):
    sys.exit('Error: ETH_RPC_URL is not SEPOLIA_EXECUTION_RPC')
if args[0] == 'chain-id':
    print(s['chainId'])
elif args[0] == 'receipt':
    print(json.dumps(s['receipt']))
elif args[:2] == ['block', 'finalized']:
    print(json.dumps({'number': hex(s['finalized'])}))
elif args[0] in ('codehash', 'call'):
    block = args[args.index('--block') + 1] if '--block' in args else 'latest'
    if block not in s['states']:
        # As a provider's error may: with the URL, which the recipe must not pass on.
        sys.exit(f'Error: {os.environ["ETH_RPC_URL"]}: error code -32000: missing trie node (block {block})')
    print(s['states'][block]['codeHash' if args[0] == 'codehash' else args[2].split('(')[0]])
else:
    sys.exit(f'fake cast: unexpected {args}')
'''

FAKE_CURL = r'''#!/usr/bin/env python3
import json, sys
path = sys.argv[-1].split('/api/', 1)[1]
if path.endswith('/status'):
    print(json.dumps({'confirmed': True, 'block_height': 1}))
elif '/outspend/' in path:
    print(json.dumps({'spent': False}))
else:
    print(json.dumps({'vout': [{}, {}]}))
'''

FAKE_HOST = r'''#!/usr/bin/env python3
import json, os, sys
sys.path.insert(0, os.environ['FAKE_PINS_DIR'])
import pins
args = sys.argv[1:]
with open(os.environ['FAKE_HOST_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\n')
flag = lambda name: args[args.index(name) + 1]
word = lambda h: bytes.fromhex(h.removeprefix('0x'))
if args[0] == 'vkey':
    print(json.dumps({'elf_sha256': os.environ['DEPLOY_GUEST_ELF_SHA256'], 'vkey': os.environ['DEPLOY_PROGRAM_VKEY']}))
elif args[0] == 'inputs':
    with open(flag('--out'), 'w') as f:
        f.write(os.environ['FAKE_ANCHOR_INPUTS'])
elif args[0] == 'anchor':
    print(os.environ['FAKE_ANCHOR_JSON'])
elif args[0] == 'reconstruct':
    if '--offline' not in args:
        sys.exit('fake host: reconstruct without --offline would read SEPOLIA_CONSENSUS_RPC')
    src = json.load(open(flag('--source')))
    head, header, committee = src['slot'], word(src['header']), word(src['committee'])
    if head != int(flag('--head')) or pins.lc(head, header, committee) != word(flag('--lc')):
        sys.exit('Error: no header and committee pair at the head hashes to the state lc; nothing is written')
    committee = word(os.environ.get('FAKE_STORE_COMMITTEE', committee.hex()))
    doc = {'about': 'stand-in store', 'committee': '0x' + committee.hex(), 'head': head, 'header': '0x' + header.hex(),
           'lc': '0x' + pins.lc(head, header, committee).hex(), 'store_cbor': '0x00'}
    with open(flag('--out'), 'w') as f:
        f.write(json.dumps(doc, indent=2))
    print(json.dumps({'reconstructed': doc, 'out': flag('--out')}))
elif args[0] == 'check-store':
    doc = json.load(open(args[1]))
    lc = pins.lc(doc['head'], word(doc['header']), word(doc['committee']))
    if lc != word(doc['lc']) or lc != word(flag('--lc')):
        sys.exit('Error: the store does not hash to --lc')
    print(json.dumps({'store': args[1], 'head': doc['head'], 'lc': lc.hex(), 'matches_state_lc': True}))
else:
    sys.exit(f'fake host: unexpected {args}')
'''


def word(n):
    return '0x' + format(n, '064x')


def escrow_state(tip_hash, tip_height, end=DEPOSITS_END, code=CODE_HASH):
    return {'codeHash': code, 'DOMAIN': DOMAIN, 'BRIDGE_ASSET': ASSET, 'lcTipHash': tip_hash,
            'lcTipHeight': word(tip_height), 'signblockscriptHash': SIGNBLOCKSCRIPT, 'depositsEnd': word(end)}


def live_chain():
    """Sepolia as deploy-record found it: the constructor's storage at the deployment block, an advanced tip now."""
    return {
        'chainId': 11155111,
        'receipt': {'status': '0x1', 'transactionHash': DEPLOY_TX, 'contractAddress': ESCROW.lower(),
                    'blockNumber': hex(DEPLOY_BLOCK)},
        'finalized': DEPLOY_BLOCK + 40,
        'states': {str(DEPLOY_BLOCK): escrow_state(CHECKPOINT_HASH, CHECKPOINT_HEIGHT),
                   'latest': escrow_state(TIP_HASH, TIP_HEIGHT)},
    }


def anchor():
    header, committee, slot = (pins.sha(b'deploy-record test anchor header'),
                               pins.sha(b'deploy-record test anchor committee'),
                               8192 * 1000)
    return {'slot': slot, 'header': header.hex(), 'committee': committee.hex(),
            'lc': pins.lc(slot, header, committee).hex()}


@unittest.skipIf(JUST is None, 'just is not installed')
@unittest.skipIf(pins.SEPOLIA_CONFIG is None, 'pins.py SEPOLIA_CONFIG is not recorded')
class DeployRecord(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='deploy-record-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin, self.work, self.record = self.tmp / 'bin', self.tmp / 'deploy', self.tmp / 'instances/test-record'
        self.bin.mkdir()
        self.work.mkdir()
        for name, text in (('cast', FAKE_CAST), ('curl', FAKE_CURL), ('sg16-bridge-host', FAKE_HOST)):
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        (self.tmp / 'elf').write_bytes(b'stand-in ELF')
        cp = {'epochLength': 1000, 'height': CHECKPOINT_HEIGHT, 'hash': CHECKPOINT_HASH,
              'signblockscriptKeccak': SIGNBLOCKSCRIPT}
        self.anchor = anchor()
        self.store_rel = f'lc_stores/{self.anchor["slot"]}.json'
        files = {
            'escrow-params.json': {'bridgeAsset': ASSET, 'funding': FUNDING,
                                   'admission': {'depositsEnd': DEPOSITS_END}, 'checkpoint': cp},
            'asset.json': {'result': {'funding': FUNDING, 'bridge_asset_internal': ASSET}},
            'checkpoint.json': {**cp, 'hashId': bytes.fromhex(CHECKPOINT_HASH[2:])[::-1].hex()},
            'simulation.json': {'escrow': ESCROW, 'codeHash': CODE_HASH, 'domain': DOMAIN},
            'deployed.json': {'escrow': ESCROW.lower(), 'transaction': DEPLOY_TX, 'block': DEPLOY_BLOCK},
            'anchor.json': {'network': {'is_sepolia': True, 'config': pins.SEPOLIA_CONFIG}, 'anchor': self.anchor,
                            'storage': [{'address': ESCROW.lower()}]},
            # The stand-in of the bootstrap's proof inputs, from which reconstruct rebuilds the anchor's store.
            'anchor-inputs.cbor': self.anchor,
        }
        for name, doc in files.items():
            (self.work / name).write_text(json.dumps(doc))

    def run_recipe(self, chain, *recipe, **env_extra):
        (self.tmp / 'sepolia.json').write_text(json.dumps(chain))
        env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE_SEPOLIA': str(self.tmp / 'sepolia.json'),
               'FAKE_PINS_DIR': str(HERE), 'FAKE_HOST_LOG': str(self.tmp / 'host.calls'),
               'SEPOLIA_EXECUTION_RPC': RPC_SECRET, 'LIQUID_ESPLORA': 'https://esplora.invalid/api',
               'BRIDGE_INSTANCE': str(self.record), 'BRIDGE_ELF': str(self.tmp / 'elf'), **env_extra}
        env.pop('ETH_RPC_URL', None)
        r = subprocess.run([JUST, f'DEPLOY_WORK={self.work}', f'BRIDGE_HOST_BIN={self.bin / "sg16-bridge-host"}',
                            *(recipe or ['deploy-record'])],
                           cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        self.assertNotIn(RPC_SECRET, r.stdout + r.stderr)
        return r

    def host_calls(self):
        return [json.loads(line) for line in (self.tmp / 'host.calls').read_text().splitlines()]

    def refused(self, chain, fragment, **env_extra):
        r = self.run_recipe(chain, **env_extra)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn(fragment, r.stderr)
        for f in ('instance.json', 'lc_preimages.json', 'lc_stores'):
            self.assertFalse((self.record / f).exists(), f)
        return r

    def assert_rebuilt_offline(self, calls):
        """reconstruct ran on the anchor's head and lc from the anchor inputs alone, and check-store checked it."""
        a, inputs = self.anchor, str(self.work / 'anchor-inputs.cbor')
        rebuilt = [c for c in calls if c[0] == 'reconstruct']
        self.assertEqual(len(rebuilt), 1)
        c = rebuilt[0]
        self.assertEqual((c[c.index('--head') + 1], c[c.index('--lc') + 1], c[c.index('--source') + 1]),
                         (str(a['slot']), a['lc'], inputs))
        self.assertIn('--offline', c)
        self.assertIn(['check-store', str(self.work / 'anchor.store.json'), '--lc', a['lc']], calls)

    def test_relayed_after_deployment_is_recorded(self):
        r = self.run_recipe(live_chain())
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads((self.record / 'instance.json').read_text())
        self.assertEqual((doc['ESCROW'], doc['ESCROW_CODE_HASH'], doc['ESCROW_DEPLOY_BLOCK'], doc['DEPOSIT_DOMAIN']),
                         (ESCROW[2:].lower(), CODE_HASH[2:], DEPLOY_BLOCK, DOMAIN[2:]))
        self.assertIn(f'block {DEPLOY_BLOCK}', r.stdout)
        self.assertIn(f'Liquid height {TIP_HEIGHT}', r.stdout)
        # Every storage read names a block: the deployment block or latest.
        calls = [json.loads(line) for line in (self.tmp / 'sepolia.json.calls').read_text().splitlines()]
        reads = [c for c in calls if c[0] in ('codehash', 'call')]
        self.assertEqual(len(reads), 14)
        self.assertEqual({c[c.index('--block') + 1] for c in reads}, {str(DEPLOY_BLOCK), 'latest'})

    def test_the_record_publishes_the_anchor_store(self):
        r = self.run_recipe(live_chain())
        self.assertEqual(r.returncode, 0, r.stderr)
        a = self.anchor
        store_path = self.record / self.store_rel
        self.assertEqual(store_path.read_bytes(), (self.work / 'anchor.store.json').read_bytes())
        store = json.loads(store_path.read_text())
        self.assertEqual((store['head'], store['header'], store['committee'], store['lc']),
                         (a['slot'], '0x' + a['header'], '0x' + a['committee'], '0x' + a['lc']))
        # The starting store's entry: the anchor's head and roots and the store, and no update transaction, the
        # form bridge-core/test/lc-store.test.js requires of entry 0 at the anchor slot.
        pre = json.loads((self.record / 'lc_preimages.json').read_text())
        self.assertEqual(pre['preimages'], [{'head': a['slot'], 'header': a['header'], 'committee': a['committee'],
                                             'store': self.store_rel}])
        self.assertEqual(sorted(p.name for p in (self.record / 'lc_stores').iterdir()), [f'{a["slot"]}.json'])
        calls = self.host_calls()
        self.assert_rebuilt_offline(calls)
        # The published copy is read back too.
        self.assertIn(['check-store', str(store_path), '--lc', a['lc']], calls)
        self.assertIn('read back: it hashes to the anchor lc', r.stdout)

    def test_existing_light_client_data_is_never_overwritten(self):
        for rel in ('lc_preimages.json', self.store_rel, 'lc_stores/1.json'):
            with self.subTest(rel):
                shutil.rmtree(self.record, ignore_errors=True)
                existing = self.record / rel
                existing.parent.mkdir(parents=True)
                existing.write_text('published before\n')
                r = self.run_recipe(live_chain())
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn('never overwrites published light-client data', r.stderr)
                self.assertEqual(existing.read_text(), 'published before\n')
                self.assertFalse((self.record / 'instance.json').exists())
                self.assertEqual(sorted(str(p.relative_to(self.record)) for p in self.record.rglob('*') if p.is_file()),
                                 [rel])

    def test_anchor_inputs_that_do_not_give_the_anchor_store_are_refused(self):
        (self.work / 'anchor-inputs.cbor').write_text(json.dumps({**self.anchor, 'committee': '33' * 32}))
        self.refused(live_chain(), 'did not rebuild the store of anchor slot')

    def test_a_store_that_does_not_hash_to_the_anchor_lc_is_refused(self):
        self.refused(live_chain(), 'does not hash to the anchor lc', FAKE_STORE_COMMITTEE='44' * 32)

    def test_deploy_anchor_writes_and_checks_the_starting_store(self):
        for f in ('anchor.json', 'anchor-inputs.cbor'):
            (self.work / f).unlink()
        anchor_json = json.dumps({'network': {'is_sepolia': True, 'config': pins.SEPOLIA_CONFIG},
                                  'anchor': self.anchor, 'storage': [{'address': ESCROW.lower()}]})
        r = self.run_recipe(live_chain(), 'deploy-anchor', str(self.anchor['slot']),
                            SEPOLIA_CONSENSUS_RPC='https://beacon.invalid', FAKE_ANCHOR_JSON=anchor_json,
                            FAKE_ANCHOR_INPUTS=json.dumps(self.anchor))
        self.assertEqual(r.returncode, 0, r.stderr)
        store = json.loads((self.work / 'anchor.store.json').read_text())
        self.assertEqual((store['head'], store['lc']), (self.anchor['slot'], '0x' + self.anchor['lc']))
        self.assert_rebuilt_offline(self.host_calls())
        self.assertFalse(self.record.exists())

    def test_storage_at_the_deployment_block_must_be_the_parameters(self):
        for key, value, fragment in (('lcTipHeight', word(TIP_HEIGHT), 'lcTipHeight() at block'),
                                     ('lcTipHash', TIP_HASH, 'lcTipHash() at block'),
                                     ('signblockscriptHash', word(1), 'signblockscriptHash() at block'),
                                     ('depositsEnd', word(DEPOSITS_END - 1), 'depositsEnd() at block'),
                                     ('DOMAIN', word(1), 'DOMAIN()'),
                                     ('BRIDGE_ASSET', word(1), 'BRIDGE_ASSET()'),
                                     ('codeHash', word(1), 'runtime code')):
            with self.subTest(key):
                chain = live_chain()
                chain['states'][str(DEPLOY_BLOCK)][key] = value
                self.refused(chain, fragment)

    def test_an_rpc_without_state_at_the_deployment_block_is_refused(self):
        chain = live_chain()
        del chain['states'][str(DEPLOY_BLOCK)]
        self.refused(chain, 'an archive node')

    def test_the_receipt_must_be_the_deployment(self):
        for key, value in (('blockNumber', hex(DEPLOY_BLOCK + 1)), ('status', '0x0'),
                           ('contractAddress', None), ('transactionHash', '0x' + '11' * 32)):
            with self.subTest(key):
                chain = live_chain()
                chain['receipt'][key] = value
                self.refused(chain, "Sepolia's receipt")

    def test_the_deployment_block_must_be_finalized(self):
        chain = live_chain()
        chain['finalized'] = DEPLOY_BLOCK - 1
        self.refused(chain, f'block {DEPLOY_BLOCK} is finalized')

    def test_current_state_must_follow_from_the_deployment(self):
        for state, fragment in ((escrow_state(TIP_HASH, TIP_HEIGHT, code=word(0)), 'runtime code'),
                                (escrow_state(TIP_HASH, CHECKPOINT_HEIGHT - 1), 'lcTipHeight() now'),
                                (escrow_state(TIP_HASH, TIP_HEIGHT, end=DEPOSITS_END + 1), 'depositsEnd() now')):
            with self.subTest(fragment):
                chain = live_chain()
                chain['states']['latest'] = state
                self.refused(chain, fragment)

    def test_deposits_end_moved_earlier_since_deployment_is_recorded(self):
        chain = live_chain()
        chain['states']['latest'] = escrow_state(TIP_HASH, TIP_HEIGHT, end=DEPOSITS_END - 86_400)
        r = self.run_recipe(chain)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f'moved earlier, to {DEPOSITS_END - 86_400}', r.stdout)

    def test_another_chain_is_refused(self):
        chain = live_chain()
        chain['chainId'] = 1
        self.refused(chain, 'not Sepolia')

    def test_the_deployment_values_are_the_recorded_domain(self):
        self.assertEqual(pins.deposit_domain(pins.SEPOLIA_CHAIN_ID, ESCROW[2:].lower()).hex(), DOMAIN[2:])


if __name__ == '__main__':
    unittest.main()
