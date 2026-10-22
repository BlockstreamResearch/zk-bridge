#!/usr/bin/env python3
"""Offline tests of how the justfile reads Elements transactions: python3 tools/sg16/bridge-guest/testnet/test_tx_reading.py

Every txid, output and input a recipe reads comes from `sg16-testnet txid`, `output` and `input` (rust-elements),
built by `just tools`. The transaction is the record's real bootstrap, instances/sepolia-liquid-testnet/bootstrap.hex,
which is only read. No network access; nothing is signed or sent.

  - the tool's txid of the bootstrap is the one tools/liquid-relay/liquid.py computes independently; its input 0
    spends the manifest's funding outpoint and issues, and its output 0 is the manifest's state script
  - `just txid` prints that txid, and refuses another expected txid, a file with a byte added or removed and a file
    that is not hex, naming the tool's failed gate; without the tool it says to build it
  - `just deploy-asset`, with the bootstrap standing in for a funding transaction and Esplora and the fee key's
    wallet stood in, accepts the change output, explicit tL-BTC to the fee key, and refuses a confidential output,
    an output to another script and an output past the last, before anything is written
  - `just chain` (under `just status`), with the same stand-in Esplora, reads the public bootstrap, says a failed
    fetch (HTTP 429) is a failed fetch to retry, not a byte mismatch, and refuses a public bootstrap with other bytes
"""
import importlib.util
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
BOOTSTRAP = INSTANCE / 'bootstrap.hex'
TX_BIN = ROOT / 'tools' / 'sg16' / 'bridge-guest' / 'target' / 'testnet-tx' / 'release' / 'sg16-testnet'
ESPLORA = 'https://esplora.invalid/api'

# Esplora as deploy-asset and chain read it: FAKE_TX (one transaction, confirmed, every output unspent).  With
# FAKE_CURL_FAIL set, every request fails as `curl -f` does on an HTTP error, such as Esplora's 429.
FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
url, esplora = sys.argv[-1], os.environ['LIQUID_ESPLORA'] + '/'
if os.environ.get('FAKE_CURL_FAIL'):
    sys.exit(f'curl: (22) The requested URL returned error: {os.environ["FAKE_CURL_FAIL"]}')
tx = json.load(open(os.environ['FAKE_TX']))
parts = url[len(esplora):].split('/') if url.startswith(esplora) else []
if len(parts) < 3 or parts[:2] != ['tx', tx['txid']]:
    sys.exit(f'fake curl: unexpected URL {url}')
if parts[2:] == ['hex']:
    print(tx['hex'])
elif parts[2:] == ['status']:
    print(json.dumps({'confirmed': True, 'block_height': 1}))
elif parts[2] == 'outspend':
    print(json.dumps({'spent': False}))
else:
    sys.exit(f'fake curl: unexpected URL {url}')
'''

# The fee key's address: only its script, FAKE_SPK.
FAKE_WALLET = r'''#!/usr/bin/env python3
import json, os, sys
if sys.argv[1] != 'address':
    sys.exit(f'fake wallet: unexpected {sys.argv[1:]}')
print(json.dumps({'script_pubkey': os.environ['FAKE_SPK']}))
'''


def tool(*args):
    """sg16-testnet's exit code and JSON report."""
    r = subprocess.run([str(TX_BIN), *map(str, args)], capture_output=True, text=True, timeout=60)
    return r.returncode, json.loads(r.stdout)


def liquid_relay():
    spec = importlib.util.spec_from_file_location('liquid_relay', ROOT / 'tools' / 'liquid-relay' / 'liquid.py')
    liquid = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(liquid)
    return liquid


@unittest.skipIf(not TX_BIN.exists(), f'{TX_BIN} is not built: just tools')
@unittest.skipIf(not BOOTSTRAP.exists(), f'{INSTANCE} has no bootstrap transaction')
class Tool(unittest.TestCase):
    def test_the_bootstrap_reads_as_the_manifest_says(self):
        code, r = tool('txid', BOOTSTRAP)
        self.assertEqual(code, 0, r)
        liquid = liquid_relay()
        raw = bytes.fromhex(BOOTSTRAP.read_text().strip())
        self.assertEqual(r['txid'], liquid.display(liquid.sha256d(liquid.txid_form(raw))))

        m = json.loads((INSTANCE / 'manifest.json').read_text())
        code, spend = tool('input', BOOTSTRAP, 0)
        self.assertEqual(code, 0, spend)
        self.assertEqual(spend['txid'], r['txid'])
        self.assertEqual(spend['previous_output'],
                         f"{m['bootstrap']['funding_txid']}:{m['bootstrap']['funding_vout']}")
        self.assertEqual((spend['has_issuance'], spend['is_pegin']), (True, False))

        code, state = tool('output', BOOTSTRAP, 0)
        self.assertEqual(code, 0, state)
        self.assertEqual(state['script_pubkey'], m['state_tree']['script_pubkey'])
        self.assertEqual((state['asset'], state['value'], state['explicit_lbtc']), (None, None, False))
        code, change = tool('output', BOOTSTRAP, 1)
        self.assertEqual(code, 0, change)
        self.assertEqual((change['asset'], change['explicit_lbtc']), (pins.LIQUID_TESTNET_LBTC_DISPLAY, True))

    def test_a_missing_output_or_input_is_a_failed_gate(self):
        n = tool('output', BOOTSTRAP, 0)[1]['outputs']
        code, r = tool('output', BOOTSTRAP, n)
        self.assertEqual(code, 3)
        self.assertIn(f'no output {n}; the transaction has {n}', r['failed_gate'])
        code, r = tool('input', BOOTSTRAP, 1)
        self.assertEqual(code, 3)
        self.assertIn('no input 1; the transaction has 1', r['failed_gate'])


class Recipes(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='tx-reading-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.hex = BOOTSTRAP.read_text().strip()
        self.txid = tool('txid', BOOTSTRAP)[1]['txid']

    def just(self, *args, env=None):
        return subprocess.run([JUST, *args], cwd=ROOT, env={**os.environ, **(env or {})}, capture_output=True,
                              text=True, timeout=120)

    def file(self, name, text):
        (self.tmp / name).write_text(text)
        return str(self.tmp / name)


@unittest.skipIf(JUST is None, 'just is not installed')
@unittest.skipIf(not TX_BIN.exists(), f'{TX_BIN} is not built: just tools')
@unittest.skipIf(not BOOTSTRAP.exists(), f'{INSTANCE} has no bootstrap transaction')
class Txid(Recipes):
    def test_the_txid_of_a_file(self):
        r = self.just('txid', self.file('tx.hex', self.hex + '\n'))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), self.txid)
        r = self.just('txid', self.file('tx.hex', self.hex), self.txid)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_another_transaction_is_refused(self):
        r = self.just('txid', self.file('tx.hex', self.hex), pins.sha(b'another transaction').hex())
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f'holds transaction {self.txid}', r.stderr)

    def test_a_file_that_is_not_one_transaction_is_refused(self):
        for name, text, fragment in (
            ('a byte added', self.hex + '00', 'not an Elements transaction'),
            ('a byte removed', self.hex[:-2], 'not an Elements transaction'),
            ('not hex', self.hex + 'zz', 'hex'),
            ('split', self.hex[:64] + ' ' + self.hex[64:], 'hex'),
        ):
            with self.subTest(name):
                r = self.just('txid', self.file('bad.hex', text))
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('sg16-testnet txid refused', r.stderr)
                self.assertIn(fragment, r.stderr)
                self.assertEqual(r.stdout.strip(), '')

    def test_without_the_tool_it_says_to_build_it(self):
        r = self.just(f'TX_BIN={self.tmp / "missing"}', 'txid', self.file('tx.hex', self.hex))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('run: just tools', r.stderr)


@unittest.skipIf(JUST is None, 'just is not installed')
@unittest.skipIf(not TX_BIN.exists(), f'{TX_BIN} is not built: just tools')
@unittest.skipIf(not BOOTSTRAP.exists(), f'{INSTANCE} has no bootstrap transaction')
class DeployAsset(Recipes):
    def setUp(self):
        super().setUp()
        bin_ = self.tmp / 'bin'
        bin_.mkdir()
        for name, text in (('curl', FAKE_CURL), ('wallet', FAKE_WALLET)):
            (bin_ / name).write_text(text)
            (bin_ / name).chmod(0o755)
        self.wallet = bin_ / 'wallet'
        self.deploy = self.tmp / 'deploy'
        (self.tmp / 'tx.json').write_text(json.dumps({'txid': self.txid, 'hex': self.hex}))
        self.change = tool('output', BOOTSTRAP, 1)[1]
        self.env = {'PATH': f'{bin_}:{os.environ["PATH"]}', 'LIQUID_ESPLORA': ESPLORA,
                    'BRIDGE_WORK': str(self.tmp / 'work'), 'LIQUID_FEE_KEY': self.file('fee.key', 'stand-in key'),
                    'FAKE_TX': str(self.tmp / 'tx.json'), 'FAKE_SPK': self.change['script_pubkey']}

    def deploy_asset(self, vout, **env):
        return self.just(f'DEPLOY_WORK={self.deploy}', f'WALLET_BIN={self.wallet}', 'deploy-asset', self.txid,
                         str(vout), env={**self.env, **env})

    def test_explicit_tlbtc_to_the_fee_key_gives_the_asset(self):
        r = self.deploy_asset(1)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f'funding output: {self.change["value"]} sats of explicit tL-BTC to the fee key', r.stdout)
        report = json.loads((self.deploy / 'asset.json').read_text())
        self.assertEqual(report['result']['funding'], f'{self.txid}:1')
        self.assertEqual((self.tmp / 'work' / 'tx' / f'{self.txid}.hex').read_text().strip(), self.hex)

    def test_other_outputs_are_refused(self):
        n = self.change['outputs']
        for vout, fragment, env in (
            (0, 'the funding output is not explicit tL-BTC', {}),
            (1, 'the funding output does not pay the fee key', {'FAKE_SPK': '0014' + '33' * 20}),
            (n, f'no output {n}; the transaction has {n}', {}),
        ):
            with self.subTest(vout=vout, fragment=fragment):
                r = self.deploy_asset(vout, **env)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(fragment, r.stderr)
                self.assertNotIn('funding output:', r.stdout)
                self.assertFalse((self.deploy / 'asset.json').exists())

    def chain(self, **env):
        return self.just('chain', env={**self.env, **env})

    def test_chain_reads_the_public_bootstrap(self):
        r = self.chain()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f'0 confirmed state spend(s) after bootstrap {self.txid}', r.stdout)

    def test_chain_says_a_failed_fetch_is_not_a_mismatch(self):
        r = self.chain(FAKE_CURL_FAIL='429')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f'could not read the bootstrap {self.txid} from Esplora', r.stderr)
        self.assertIn('retry in a minute', r.stderr)
        self.assertNotIn('differs from', r.stderr)

    def test_chain_refuses_a_public_bootstrap_with_other_bytes(self):
        (self.tmp / 'tx.json').write_text(json.dumps({'txid': self.txid, 'hex': self.hex[:-2] + 'ff'}))
        r = self.chain()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f"Esplora's transaction {self.txid} differs from", r.stderr)


if __name__ == '__main__':
    unittest.main()
