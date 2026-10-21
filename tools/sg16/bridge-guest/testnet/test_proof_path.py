#!/usr/bin/env python3
"""Offline tests of the justfile's proof path gates: python3 tools/sg16/bridge-guest/testnet/test_proof_path.py

The recipes run from the repository's justfile against stand-ins on PATH, in temporary work and instance
directories built from instances/sepolia-liquid-testnet, which is only read. No network access; nothing is signed,
proved or sent. Transaction files are read by the real sg16-testnet (`just tools`).

  - `just execute` and `just prove` run the guest only on inputs that start from the recovered state (its head and
    lc), in Sepolia's config, reading slot 0 of the instance's escrow alone; anything else is refused before the
    host's `run`, so stale inputs never cost a proof
  - `just preflight` passes a signed update only once its successor store and lc_preimages.json entry, staged
    locally, are read back byte for byte: for the escrow the published site serves, from that site's record
    (bridge-core/config.js PUBLISHED) and nowhere else; for another escrow, from the public HTTPS URL its operator
    gives. Refused: another URL for the published escrow, no URL or a non-HTTPS URL for another, a store or
    lc_preimages.json that is unpublished or differs, an entry naming another update, a store never staged, and an
    unsigned (Humid) update. preflight never posts anything.
  - a second operator, starting from an empty work directory, takes over after an update that withheld its store:
    `just status` names the store as missing and the next step, `just reconstruct`; it recovers the store only when
    it hashes to the live lc and then completes the state record, which `just inputs` proves from; with the beacon
    data pruned, or a rebuilt file of another lc, nothing is called recovered and `just inputs` refuses;
    `just stage-recovered` records the rebuilt store under the withheld update. Here assemble.py runs for real
    against the record; Esplora, the beacon node, the host and the transaction tool's chain walk are stand-ins (the
    host's checks are its own tests, src/reconstruct.rs an_independent_prover_recovers_a_withheld_store).
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
INSTANCE = ROOT / 'instances' / 'sepolia-liquid-testnet'
ESPLORA = 'https://esplora.invalid/api'
# The justfile reads every txid with the real transaction tool, built by `just tools`.
TX_BIN = ROOT / 'tools' / 'sg16' / 'bridge-guest' / 'target' / 'testnet-tx' / 'release' / 'sg16-testnet'
# The published site's copy of the record (bridge-core/config.js PUBLISHED.site), served here by the stand-in curl.
SITE = 'https://blockstreamresearch.github.io/zk-bridge/instances/sepolia-liquid-testnet'
NODE = shutil.which('node')

# The successor head of a first update, and the state and fee outputs it spends: stand-ins, not chain values.
INITIAL_HEAD = (json.loads((INSTANCE / 'initial_state.json').read_text())['head']
                if (INSTANCE / 'initial_state.json').exists() else 12_000_000)
NEW_HEAD = INITIAL_HEAD + 32
STATE_TXID = pins.sha(b'proof-path test state transaction').hex()
FEE_TXID = pins.sha(b'proof-path test fee transaction').hex()

FAKE_HOST = r'''#!/usr/bin/env python3
import json, os, sys
cmd = sys.argv[1]
if cmd == 'vkey':
    pin = json.load(open(os.path.join(os.environ['BRIDGE_INSTANCE'], 'instance.json')))
    print(json.dumps({'elf_sha256': pin['GUEST_ELF_SHA256'], 'vkey': pin['PROGRAM_VKEY']}))
elif cmd == 'anchor':
    print(open(os.environ['FAKE_ANCHOR']).read())
elif cmd == 'run':
    with open(os.environ['FAKE_HOST_RUNS'], 'a') as log:
        log.write(json.dumps(sys.argv[1:]) + '\n')
    if os.environ.get('FAKE_HOST_KILLED'):
        import signal
        os.kill(os.getpid(), signal.SIGKILL)
else:
    sys.exit(f'fake host: unexpected {sys.argv[1:]}')
'''

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args, url = sys.argv[1:], sys.argv[-1]
with open(os.environ['FAKE_CURL_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\n')
esplora, site = os.environ['LIQUID_ESPLORA'] + '/', os.environ['FAKE_SITE_URL'] + '/'
if url.startswith(esplora):
    path = url[len(esplora):]
    if path.endswith('/hex') and '-w' in args:  # the transaction about to be sent is unknown to Esplora
        print(args[args.index('-w') + 1].replace('%{http_code}', '404'), end='')
    elif path.endswith('/status'):
        print(json.dumps({'confirmed': True, 'block_height': 1}))
    elif '/outspend/' in path:
        print(json.dumps({'spent': False}))
    else:
        sys.exit(f'fake curl: unexpected Esplora {path}')
elif url.startswith(site):
    f = Path(os.environ['FAKE_SITE_DIR']) / url[len(site):]
    if not f.is_file():
        sys.exit('curl: (22) The requested URL returned error: 404')
    sys.stdout.buffer.write(f.read_bytes())
else:
    sys.exit(f'fake curl: unexpected URL {url}')
'''

# bridge-core/test/lc-store.test.js is the ui's own suite; here only its invocation on the instance is recorded.
# With FAKE_REAL_NODE set, every other node call, such as reading bridge-core/config.js, runs that real node;
# without it, none runs and each prints nothing.
FAKE_NODE = r'''#!/usr/bin/env python3
import json, os, sys
if '--test' not in sys.argv[1:] and os.environ.get('FAKE_REAL_NODE'):
    os.execv(os.environ['FAKE_REAL_NODE'], [os.environ['FAKE_REAL_NODE']] + sys.argv[1:])
with open(os.environ['FAKE_NODE_LOG'], 'a') as log:
    log.write(json.dumps([os.environ.get('RECORD_DIR')] + sys.argv[1:]) + '\n')
'''


def txid(path):
    """The Elements txid of a hex file, by sg16-testnet txid, as the justfile's txid_of."""
    r = subprocess.run([str(TX_BIN), 'txid', str(path)], capture_output=True, text=True, timeout=60, check=True)
    return json.loads(r.stdout)['txid']


def stand_ins(tmp, scripts):
    bin_ = tmp / 'bin'
    bin_.mkdir()
    for name, text in scripts.items():
        (bin_ / name).write_text(text)
        (bin_ / name).chmod(0o755)
    return bin_


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@unittest.skipIf(JUST is None, 'just is not installed')
class ProverSetup(unittest.TestCase):
    """The first-run installer uses one pinned local CLI and never changes a system installation."""

    def run_setup(self, version='', docker=True, install=True, installed_version='6.8.1'):
        with tempfile.TemporaryDirectory(prefix='prover-setup-') as tmp:
            tmp = Path(tmp)
            cargo = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['SETUP_LOG'], 'a') as log:
    log.write(json.dumps([args, os.environ.get('SP1_SKIP_PROGRAM_BUILD')]) + '\n')
installed = Path(os.environ['BRIDGE_WORK']) / 'sp1' / 'installed'
if args == ['prove', '--version']:
    version = os.environ['INSTALLED_VERSION'] if installed.exists() else os.environ['INITIAL_VERSION']
    if not version:
        sys.exit(1)
    print('cargo-prove ' + version)
elif args[0] == 'install':
    if os.environ['INSTALL_OK'] != 'yes':
        sys.exit('installation failed')
    installed.parent.mkdir(parents=True, exist_ok=True)
    installed.touch()
elif args[0] != 'build' and args[:2] != ['prove', 'build']:
    sys.exit('unexpected cargo arguments')
'''
            bin_ = stand_ins(tmp, {
                'cargo': cargo, 'go': '#!/bin/sh\nexit 0\n', 'protoc': '#!/bin/sh\nexit 0\n',
                'docker': '#!/bin/sh\nexit ' + ('0' if docker else '1') + '\n',
            })
            env = {**os.environ, 'PATH': f'{bin_}:{os.environ["PATH"]}', 'BRIDGE_WORK': str(tmp / 'work'),
                   'SETUP_LOG': str(tmp / 'log'), 'INITIAL_VERSION': version,
                   'INSTALLED_VERSION': installed_version, 'INSTALL_OK': 'yes' if install else 'no'}
            result = subprocess.run([JUST, 'prover'], cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
            return result, lines(tmp / 'log'), tmp / 'work'

    def test_first_run_installs_pinned_cli_locally_before_building(self):
        result, log, work = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        install = log[1][0]
        self.assertEqual(install, ['install', '--locked', '--git', 'https://github.com/succinctlabs/sp1',
                                  '--rev', 'c84ada1ed5911f28c4d3c9d0ed2f9e6cd7edb824',
                                  '--root', str(work / 'sp1'), '--force', 'sp1-cli'])
        self.assertEqual(log[3][0][0], 'build')
        self.assertEqual(log[3][1], 'true')  # host uses Helios's pinned ELFs
        self.assertEqual(log[4][0][:2], ['prove', 'build'])
        self.assertIn('--docker', log[4][0])
        self.assertIn('v6.8.1', log[4][0])

    def test_matching_cli_is_reused_without_installing(self):
        for version in ('6.8.1', 'sp1 (c84ada1 2026-09-24T18:50:34Z)'):
            with self.subTest(version=version):
                result, log, _ = self.run_setup(version=version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any(args[0] == 'install' for args, _ in log))

    def test_other_cli_version_installs_local_pin(self):
        result, log, _ = self.run_setup(version='6.8.10')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log[1][0][0], 'install')

    def test_unavailable_docker_stops_before_installation(self):
        result, log, _ = self.run_setup(docker=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('start Docker', result.stderr)
        self.assertEqual(log, [])

    def test_failed_or_wrong_installation_never_builds(self):
        for options in ({'install': False}, {'installed_version': '6.9.0'}):
            with self.subTest(options=options):
                result, log, _ = self.run_setup(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(args[0] == 'build' or args[:2] == ['prove', 'build'] for args, _ in log))


@unittest.skipIf(JUST is None, 'just is not installed')
@unittest.skipIf(not (INSTANCE / 'manifest.json').exists(), f'{INSTANCE} is not a deployed record')
class ProofInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='proof-inputs-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = stand_ins(self.tmp, {'sg16-bridge-host': FAKE_HOST})
        self.work = self.tmp / 'work'
        self.work.mkdir()
        # The state `just recover` gives before the first update: the instance's initial state.
        self.state = json.loads((INSTANCE / 'initial_state.json').read_text())
        (self.work / 'state.json').write_text(json.dumps(self.state))
        (self.work / 'inputs.cbor').write_bytes(b'stand-in inputs')
        (self.tmp / 'elf').write_bytes(b'stand-in ELF')
        self.escrow = pins.load(INSTANCE / 'instance.json').escrow

    def summary(self):
        """`sg16-bridge-host anchor` of inputs that fit the state: what each case below edits."""
        s = self.state
        return {
            'anchor': {'slot': s['head'], 'header': '0x' + s['header'], 'committee': '0x' + s['committee'],
                       'lc': '0x' + s['lc']},
            'network': {'is_sepolia': True, 'config': '0x' + pins.SEPOLIA_CONFIG},
            'target_finalized_slot': NEW_HEAD,
            'storage': [{'address': '0x' + self.escrow.upper(),
                         'slots': [{'key': '0x' + '00' * 32, 'value': '0x' + pins.EMPTY_ACCUMULATOR}]}],
        }

    def run_recipe(self, recipe, summary, killed=False):
        (self.tmp / 'anchor.json').write_text(json.dumps(summary))
        env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE_ANCHOR': str(self.tmp / 'anchor.json'),
               'FAKE_HOST_RUNS': str(self.tmp / 'runs'), 'BRIDGE_INSTANCE': str(INSTANCE),
               'BRIDGE_WORK': str(self.work), 'BRIDGE_ELF': str(self.tmp / 'elf')}
        env.pop('BRIDGE_ESCROW', None)
        if killed:
            env['FAKE_HOST_KILLED'] = '1'
        r = subprocess.run([JUST, '--yes', f'BRIDGE_HOST_BIN={self.bin / "sg16-bridge-host"}', recipe],
                           cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        return r, lines(self.tmp / 'runs')

    def test_inputs_from_the_state_execute(self):
        r, runs = self.run_recipe('execute', self.summary())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f'inputs start from the state at slot {self.state["head"]}', r.stdout)
        self.assertEqual([run[:2] for run in runs], [['run', '--elf']])

    def test_proving_starts_only_on_fitting_inputs(self):
        r, runs = self.run_recipe('prove', self.summary())
        # The stand-in host writes no proof, so the artifact check after it refuses; the gate let the run start.
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(len(runs), 1)
        self.assertIn('--prove', runs[0])

    def test_killed_prover_reports_recovery_without_accepting_an_artifact(self):
        r, runs = self.run_recipe('prove', self.summary(), killed=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(len(runs), 1)
        self.assertIn('prover was killed (137)', r.stderr)
        self.assertIn('proof.store.json alone is not a proof', r.stderr)
        self.assertNotIn('proof accepted', r.stdout)

    def test_inputs_that_do_not_fit_are_refused_before_the_guest_runs(self):
        def edit(f):
            s = self.summary()
            f(s)
            return s

        cases = (
            ('another state', lambda s: s['anchor'].update(lc='0x' + '11' * 32), 'the state is at slot'),
            ('another head', lambda s: s['anchor'].update(slot=self.state['head'] - 32), 'the state is at slot'),
            ('another network', lambda s: s['network'].update(is_sepolia=False), 'SEPOLIA_CONFIG'),
            ('another config', lambda s: s['network'].update(config='0x' + '22' * 32), 'SEPOLIA_CONFIG'),
            ('another escrow', lambda s: s['storage'][0].update(address='0x' + '33' * 20), 'alone'),
            ('another slot', lambda s: s['storage'][0]['slots'][0].update(key='0x' + '00' * 31 + '02'), 'alone'),
            ('two slots', lambda s: s['storage'][0]['slots'].append(dict(s['storage'][0]['slots'][0])), 'alone'),
            ('two contracts', lambda s: s['storage'].append(dict(s['storage'][0])), 'alone'),
        )
        for recipe in ('execute', 'prove'):
            for name, f, fragment in cases:
                with self.subTest(recipe=recipe, case=name):
                    r, runs = self.run_recipe(recipe, edit(f))
                    self.assertNotEqual(r.returncode, 0, r.stdout)
                    self.assertIn(fragment, r.stderr)
                    self.assertIn('run just inputs again', r.stderr)
                    self.assertEqual(runs, [])

    def test_missing_inputs_are_refused(self):
        (self.work / 'inputs.cbor').unlink()
        r, runs = self.run_recipe('execute', self.summary())
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('inputs.cbor is missing', r.stderr)
        self.assertEqual(runs, [])


@unittest.skipIf(JUST is None, 'just is not installed')
@unittest.skipIf(not TX_BIN.exists(), f'{TX_BIN} is not built: just tools')
@unittest.skipIf(not (INSTANCE / 'bootstrap.hex').exists(), f'{INSTANCE} has no bootstrap transaction')
@unittest.skipIf(NODE is None, 'node is not installed')
class StorePublication(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='store-publication-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = stand_ins(self.tmp, {'curl': FAKE_CURL, 'node': FAKE_NODE})
        # A copy of the record, as `just stage-store` leaves it for a first update to NEW_HEAD.
        self.record = self.tmp / 'instances' / INSTANCE.name
        shutil.copytree(INSTANCE, self.record)
        self.work = self.tmp / 'work'
        self.work.mkdir()
        # Any real Elements transaction: preflight checks the file's txid, not what it spends.
        self.update = self.work / 'update.signed.hex'
        shutil.copy(INSTANCE / 'bootstrap.hex', self.update)
        self.txid = txid(self.update)
        (self.work / 'update.new_state.json').write_text(json.dumps({'head': NEW_HEAD}))
        self.write_meta('update')
        self.store = f'lc_stores/{NEW_HEAD}.json'
        (self.record / self.store).write_text(json.dumps({'head': NEW_HEAD, 'about': 'stand-in successor store'}))
        pre = json.loads((self.record / 'lc_preimages.json').read_text())
        pre['preimages'].append({'head': NEW_HEAD, 'header': '44' * 32, 'committee': '55' * 32, 'update': self.txid,
                                 'store': self.store})
        (self.record / 'lc_preimages.json').write_text(json.dumps(pre, indent=1) + '\n')
        self.site = self.tmp / 'site'
        self.publish()

    def write_meta(self, kind):
        meta = {'kind': kind, 'txid': self.txid, 'state': STATE_TXID,
                'new_state': str(self.work / 'update.new_state.json'),
                'parents': [STATE_TXID, FEE_TXID]}
        Path(f'{self.update}.meta.json').write_text(json.dumps(meta))

    def publish(self, *names):
        """Copy the record's store and lc_preimages.json (or only `names`) to the stand-in public site."""
        for name in names or (self.store, 'lc_preimages.json'):
            (self.site / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(self.record / name, self.site / name)

    def preflight(self, url=None, site=SITE):
        """`just preflight` of the update with STORE_READBACK_URL `url` (unset for None), the stand-in site at `site`."""
        env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'LIQUID_ESPLORA': ESPLORA,
               'FAKE_SITE_URL': site, 'FAKE_SITE_DIR': str(self.site), 'FAKE_CURL_LOG': str(self.tmp / 'curl'),
               'FAKE_NODE_LOG': str(self.tmp / 'node'), 'FAKE_REAL_NODE': NODE, 'BRIDGE_INSTANCE': str(self.record),
               'BRIDGE_WORK': str(self.work)}
        env.pop('STORE_READBACK_URL', None)
        env.pop('BRIDGE_ESCROW', None)
        if url is not None:
            env['STORE_READBACK_URL'] = url
        r = subprocess.run([JUST, 'preflight', str(self.update)], cwd=ROOT, env=env, capture_output=True, text=True,
                           timeout=120)
        posts = [c for c in lines(self.tmp / 'curl') if '-X' in c or '--data-binary' in c]
        self.assertEqual(posts, [], 'preflight sends nothing')
        return r

    def refused(self, fragment, **kw):
        r = self.preflight(**kw)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn(fragment, r.stderr)
        self.assertNotIn('ready:', r.stdout)

    def test_a_store_published_on_the_published_site_passes(self):
        for url in (None, SITE, SITE + '/'):
            with self.subTest(url=url):
                (self.tmp / 'curl').unlink(missing_ok=True)
                (self.tmp / 'node').unlink(missing_ok=True)
                r = self.preflight(url)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(f'reading the store back from {SITE}\n', r.stdout)
                self.assertIn(f'ready: update {self.txid}', r.stdout)
                # Both files were read back from the site, and the record's own store gate ran on this record.
                reads = [c[-1] for c in lines(self.tmp / 'curl') if c[-1].startswith(SITE)]
                self.assertEqual(sorted(reads), sorted(f'{SITE}/{f}' for f in (self.store, 'lc_preimages.json')))
                self.assertEqual([n[0] for n in lines(self.tmp / 'node')], [str(self.record)])

    def test_the_published_escrow_reads_back_only_from_the_published_site(self):
        for url in ('https://pages.invalid/instances/sepolia-liquid-testnet',
                    'https://kyrylr.github.io/liquid-poc-bridge/instances/sepolia-liquid-testnet',
                    'https://blockstreamresearch.github.io/zk-bridge/instances/other',
                    SITE.replace('https://', 'http://'), str(self.record)):
            with self.subTest(url=url):
                # Even with the files served there.
                self.refused(f'STORE_READBACK_URL is not {SITE}: the page and the next prover', url=url, site=url)

    def test_another_escrow_reads_back_from_its_own_public_https_url(self):
        pins_ = json.loads((self.record / 'instance.json').read_text())
        pins_['ESCROW'] = '0x' + '77' * 20
        (self.record / 'instance.json').write_text(json.dumps(pins_, indent=1) + '\n')
        own = 'https://pages.invalid/instances/sepolia-liquid-testnet'
        r = self.preflight(own, site=own)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f'reading the store back from {own}\n', r.stdout)
        self.refused('set STORE_READBACK_URL', site=own)
        self.refused('public HTTPS URL', url=own.replace('https://', 'http://'), site=own)
        self.refused('public HTTPS URL', url=str(self.record), site=own)

    def test_an_unpublished_store_is_refused(self):
        (self.site / self.store).unlink()
        self.refused(f'the published {self.store} differs')

    def test_a_published_store_that_differs_is_refused(self):
        (self.site / self.store).write_text(json.dumps({'head': NEW_HEAD, 'about': 'another store'}))
        self.refused(f'the published {self.store} differs')

    def test_a_stale_published_lc_preimages_is_refused(self):
        shutil.copy(INSTANCE / 'lc_preimages.json', self.site / 'lc_preimages.json')
        self.refused('the published lc_preimages.json differs')

    def test_an_entry_for_another_update_is_refused(self):
        pre = json.loads((self.record / 'lc_preimages.json').read_text())
        pre['preimages'][-1]['update'] = FEE_TXID
        (self.record / 'lc_preimages.json').write_text(json.dumps(pre, indent=1) + '\n')
        self.publish()
        self.refused(f'naming update {self.txid}')

    def test_an_unstaged_store_is_refused(self):
        (self.record / self.store).unlink()
        self.refused('run: just stage-store')

    def test_an_unsigned_update_has_no_preflight(self):
        self.write_meta('update-unsigned')
        self.refused('no fee signature')


# The chain as Esplora shows it ({txid: {hex, spent_by}}), and the light-client finality update's slot.
FAKE_CHAIN_CURL = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args, url = sys.argv[1:], sys.argv[-1]
with open(os.environ['FAKE_CURL_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\n')
esplora, beacon = os.environ['LIQUID_ESPLORA'] + '/', os.environ['SEPOLIA_CONSENSUS_RPC'] + '/'
chain = json.loads(Path(os.environ['FAKE_CHAIN']).read_text())
if url.startswith(esplora):
    parts = url[len(esplora):].split('/')
    if len(parts) == 3 and parts[0] == 'tx' and parts[2] == 'hex':
        print(chain[parts[1]]['hex'])
    elif len(parts) == 4 and parts[0] == 'tx' and parts[2] == 'outspend' and parts[3] == '0':
        by = chain[parts[1]]['spent_by']
        print(json.dumps({'spent': True, 'txid': by, 'vin': 0, 'status': {'confirmed': True}} if by else {'spent': False}))
    else:
        sys.exit(f'fake curl: unexpected Esplora {url}')
elif url == beacon + 'eth/v1/beacon/light_client/finality_update':
    print(json.dumps({'data': {'finalized_header': {'beacon': {'slot': os.environ['FAKE_FINALIZED']}}}}))
else:
    sys.exit(f'fake curl: unexpected URL {url}')
'''

# sg16-testnet recover: the state the stand-in chain leads to, as the real tool reports a walk through one update.
# Reading a transaction file is left to the real tool.
FAKE_TX = r'''#!/usr/bin/env python3
import os, sys
if sys.argv[1] in ('txid', 'output', 'input'):
    os.execv(os.environ['REAL_TX_BIN'], [os.environ['REAL_TX_BIN'], *sys.argv[1:]])
if sys.argv[1] != 'recover':
    sys.exit(f'fake sg16-testnet: unexpected {sys.argv[1:]}')
print(open(os.environ['FAKE_RECOVER']).read().strip())
'''

# The host's recovery commands. Its real checks (CBOR roots, lc) are the host's own tests; this one compares lc only.
FAKE_RECOVERY_HOST = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['FAKE_HOST_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\n')
flag = lambda name: args[args.index(name) + 1]
norm = lambda h: str(h).lower().removeprefix('0x')
if args[0] == 'reconstruct':
    if os.environ.get('FAKE_BEACON') == 'pruned':
        sys.exit("Error: refused: no header and committee from the sources hash to the Liquid state's lc\n"
                 'not available: light-client update of period 1390: HTTP status client error (404 Not Found)')
    with open(flag('--out'), 'w') as out:
        out.write(open(os.environ['FAKE_STORE']).read())
    print(json.dumps({'matches_state_lc': True}))
elif args[0] == 'check-store':
    if norm(json.load(open(args[1]))['lc']) != norm(flag('--lc')):
        sys.exit('Error: the store file hashes to another lc')
    print(json.dumps({'matches_state_lc': True}))
elif args[0] == 'inputs':
    with open(flag('--out'), 'wb') as out:
        out.write(b'stand-in inputs')
else:
    sys.exit(f'fake host: unexpected {args}')
'''

# bridge-operator: the deposit scan (`bridge-operator deposits`) from FAKE_DEPOSITS. Its real reader is tested in
# tools/bridge-operator/tests; here only the recipe's use of its output is.
FAKE_OPERATOR = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if args[:1] != ['deposits']:
    sys.exit(f'fake bridge-operator: unexpected {args}')
deposits = json.loads(os.environ['FAKE_DEPOSITS'])
with open(args[args.index('--out') + 1], 'w') as out:
    json.dump(deposits, out)
print(json.dumps({'to_block': 1, 'deposits': len(deposits)}))
'''

# The withheld update's successor: a head past the anchor and the roots its store would have.
WITHHELD_HEAD = INITIAL_HEAD + 32
WITHHELD_HEADER = pins.sha(b'withheld-store test successor header')
WITHHELD_COMMITTEE = pins.sha(b'withheld-store test successor committee')
WITHHELD_LC = pins.lc(WITHHELD_HEAD, WITHHELD_HEADER, WITHHELD_COMMITTEE).hex()


@unittest.skipIf(JUST is None, 'just is not installed')
@unittest.skipIf(not TX_BIN.exists(), f'{TX_BIN} is not built: just tools')
class WithheldStore(unittest.TestCase):
    def setUp(self):
        self.assertTrue((INSTANCE / 'bootstrap.hex').is_file(), f'{INSTANCE} has no bootstrap transaction')
        self.tmp = Path(tempfile.mkdtemp(prefix='withheld-store-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = stand_ins(self.tmp, {'curl': FAKE_CHAIN_CURL, 'sg16-testnet': FAKE_TX,
                                        'sg16-bridge-host': FAKE_RECOVERY_HOST, 'bridge-operator': FAKE_OPERATOR,
                                        'node': FAKE_NODE})
        self.record = self.tmp / 'instances' / INSTANCE.name
        shutil.copytree(INSTANCE, self.record)
        self.work = self.tmp / 'work'
        self.rebuilt = self.work / 'reconstructed.store.json'
        # The first operator's update: any Elements transaction other than the bootstrap stands in for it, since
        # the chain walk checks each fetched transaction's txid and the tool's walk is a stand-in.
        boot_hex = ''.join((INSTANCE / 'bootstrap.hex').read_text().split())
        update_hex = '03000000' + boot_hex[8:]
        (self.tmp / 'update.hex').write_text(update_hex)
        self.boot, self.update = txid(INSTANCE / 'bootstrap.hex'), txid(self.tmp / 'update.hex')
        (self.tmp / 'chain.json').write_text(json.dumps({
            self.boot: {'hex': boot_hex, 'spent_by': self.update}, self.update: {'hex': update_hex, 'spent_by': None}}))
        acc = bytes.fromhex(pins.EMPTY_ACCUMULATOR)
        root = pins.claimed_root([])
        state = {'head': WITHHELD_HEAD, 'lc': WITHHELD_LC, 'acc': pins.EMPTY_ACCUMULATOR, 'claimed': [],
                 'claimed_root': root.hex(), 'state_hash': pins.state_hash(bytes.fromhex(WITHHELD_LC), acc, root).hex(),
                 'exec_root': '66' * 32, 'exec_block': 11_960_000}
        (self.tmp / 'recover.json').write_text(json.dumps({
            'ok': True, 'state': state, 'store_known': False, 'outpoint': f'{self.update}:0', 'address': 'stand-in',
            'chain': [{'txid': self.boot, 'kind': 'start'}, {'txid': self.update, 'kind': 'update'}],
            'note': 'stand-in walk through one update'}))
        # What `sg16-bridge-host reconstruct` writes when the public data gives the store.
        (self.tmp / 'store.json').write_text(json.dumps({
            'about': 'stand-in rebuilt store', 'head': WITHHELD_HEAD, 'header': '0x' + WITHHELD_HEADER.hex(),
            'committee': '0x' + WITHHELD_COMMITTEE.hex(), 'lc': '0x' + WITHHELD_LC, 'store_cbor': '0x00'}))
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'LIQUID_ESPLORA': ESPLORA,
                    'SEPOLIA_CONSENSUS_RPC': 'https://beacon.invalid',
                    'SEPOLIA_EXECUTION_RPC': 'https://execution.invalid',
                    'BRIDGE_INSTANCE': str(self.record), 'BRIDGE_WORK': str(self.work),
                    'SG16_TESTNET_TX': str(self.bin / 'sg16-testnet'), 'REAL_TX_BIN': str(TX_BIN),
                    'FAKE_CHAIN': str(self.tmp / 'chain.json'),
                    'FAKE_RECOVER': str(self.tmp / 'recover.json'), 'FAKE_STORE': str(self.tmp / 'store.json'),
                    'FAKE_FINALIZED': str(WITHHELD_HEAD + 64),
                    'FAKE_DEPOSITS': json.dumps([[100_000, '0014' + '33' * 20]]),
                    'FAKE_CURL_LOG': str(self.tmp / 'curl'), 'FAKE_HOST_LOG': str(self.tmp / 'host'),
                    'FAKE_NODE_LOG': str(self.tmp / 'node')}
        for k in ('BRIDGE_HINT', 'BRIDGE_ESCROW', 'FAKE_BEACON'):
            self.env.pop(k, None)

    def just(self, *args, **env):
        r = subprocess.run([JUST, f'BRIDGE_HOST_BIN={self.bin / "sg16-bridge-host"}',
                            f'TX_BIN={self.bin / "sg16-testnet"}', f'OPERATOR_BIN={self.bin / "bridge-operator"}',
                            *args],
                           cwd=ROOT, env={**self.env, **env}, capture_output=True, text=True, timeout=300)
        posts = [c for c in lines(self.tmp / 'curl') if '-X' in c or '--data-binary' in c]
        self.assertEqual(posts, [], 'nothing is sent')
        return r

    def host_calls(self, command):
        return [c for c in lines(self.tmp / 'host') if c[0] == command]

    def state(self):
        return json.loads((self.work / 'state.json').read_text())

    def test_an_independent_operator_recovers_the_store_and_proves_from_it(self):
        self.assertFalse(self.work.exists(), 'the second operator starts with no work directory')
        r = self.just('status', '0')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f'none published for head {WITHHELD_HEAD}, which update {self.update} reached', r.stdout)
        self.assertIn(f'no store is published for the live head {WITHHELD_HEAD}: just reconstruct', r.stdout)
        self.assertIn('deposit #0     final, not proven yet', r.stdout)
        self.assertNotIn('header', self.state())

        r = self.just('reconstruct')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f'recovered: {self.rebuilt} is the store of the live head {WITHHELD_HEAD}', r.stdout)
        self.assertIn(WITHHELD_LC, r.stdout)
        [call] = self.host_calls('reconstruct')
        self.assertEqual(call[call.index('--state') + 1], str(self.work / 'state.json'))
        self.assertIn(str(self.record / 'lc_stores' / f'{INITIAL_HEAD}.json'), call)
        self.assertNotIn('--offline', call)
        self.assertEqual([c[c.index('--lc') + 1] for c in self.host_calls('check-store')], [WITHHELD_LC])
        s = self.state()
        self.assertEqual((s['head'], s['lc'], s['header'], s['committee']),
                         (WITHHELD_HEAD, WITHHELD_LC, WITHHELD_HEADER.hex(), WITHHELD_COMMITTEE.hex()))

        r = self.just('inputs')
        self.assertEqual(r.returncode, 0, r.stderr)
        [call] = self.host_calls('inputs')
        self.assertEqual((call[call.index('--store') + 1], call[call.index('--lc') + 1]),
                         (str(self.rebuilt), WITHHELD_LC))
        self.assertEqual(len(self.host_calls('reconstruct')), 1, 'inputs reconstructs nothing itself')

    def test_pruned_beacon_data_is_never_called_recovered(self):
        r = self.just('reconstruct', FAKE_BEACON='pruned')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('not recovered', r.stderr)
        self.assertIn('404 Not Found', r.stderr)
        self.assertNotIn('recovered:', r.stdout)
        self.assertFalse(self.rebuilt.exists())
        self.assertNotIn('header', self.state())
        r = self.just('inputs')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f'no store for the live head {WITHHELD_HEAD}', r.stderr)
        self.assertIn('Run just reconstruct', r.stderr)
        self.assertEqual(self.host_calls('inputs'), [])

    def test_a_rebuilt_file_of_another_lc_is_not_used(self):
        self.work.mkdir()
        other = json.loads((self.tmp / 'store.json').read_text())
        other['committee'] = '0x' + pins.sha(b'another committee').hex()
        other['lc'] = '0x' + pins.lc(WITHHELD_HEAD, WITHHELD_HEADER, pins.sha(b'another committee')).hex()
        self.rebuilt.write_text(json.dumps(other))
        r = self.just('inputs')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('no published or rebuilt store matches the live head', r.stderr)
        self.assertIn(f'no store for the live head {WITHHELD_HEAD}', r.stderr)
        self.assertEqual(self.host_calls('inputs'), [])

    def test_the_rebuilt_store_is_staged_under_the_withheld_update(self):
        original = json.loads((self.record / 'lc_preimages.json').read_text())['preimages']
        self.assertEqual(self.just('reconstruct').returncode, 0)
        r = self.just('stage-recovered')
        self.assertEqual(r.returncode, 0, r.stderr)
        rel = f'lc_stores/{WITHHELD_HEAD}.json'
        self.assertEqual((self.record / rel).read_bytes(), self.rebuilt.read_bytes())
        pre = json.loads((self.record / 'lc_preimages.json').read_text())['preimages']
        self.assertEqual([e for e in pre if e['head'] != WITHHELD_HEAD], original)
        self.assertEqual([e['head'] for e in pre], sorted(e['head'] for e in pre))
        self.assertEqual([e for e in pre if e['head'] == WITHHELD_HEAD],
                         [{'head': WITHHELD_HEAD, 'header': WITHHELD_HEADER.hex(),
                           'committee': WITHHELD_COMMITTEE.hex(), 'update': self.update, 'store': rel}])
        self.assertIn([str(self.record), '--test', 'bridge-core/test/lc-store.test.js'], lines(self.tmp / 'node'))
        # The record now publishes the store, so recovery uses it and nothing is left to reconstruct or stage.
        r = self.just('reconstruct')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('nothing to reconstruct', r.stdout)
        self.assertNotEqual(self.just('stage-recovered').returncode, 0)


if __name__ == '__main__':
    unittest.main()
