#!/usr/bin/env python3
"""Build BridgeEscrow.checkFork's beacon-state proof for the current Sepolia beacon chain.

  fork_proof.py build [--block-root 0x..] [--escrow 0x..] [--pin VERSION:EPOCH] [--save-inputs DIR] [--out PATH]
      Read a light-client finality update, or with --block-root that block's light-client bootstrap, from the
      beacon API in SEPOLIA_CONSENSUS_RPC, then the chain's genesis and the fork of the state the update's header
      commits to (/eth/v1/beacon/genesis, /eth/v1/beacon/states/{id}/fork); no debug state is read. Find, through
      SEPOLIA_EXECUTION_RPC, the execution block whose EIP-4788 root is that header's root, and check that the
      block's header names the same parentBeaconBlockRoot. Then build and check the proof (beacon.fork_proof) and
      print it as JSON, with checkFork's calldata and that block (executionBlock). With --escrow it also simulates
      checkFork on that escrow with eth_call. --save-inputs keeps the inputs for `offline`, each as soon as it is
      read, so a refused run leaves what it refused. A state in a tree shape checkFork does not hash (see
      beacon.py) is refused: no checkFork proof of it exists.

  fork_proof.py offline --inputs DIR [--pin VERSION:EPOCH] [--out PATH]
      The same proof from saved inputs, without the network. The EIP-4788 root in DIR is what the RPC returned;
      checkFork reads it from the chain itself.

  fork_proof.py verify --proof PATH [--write]
      Check a recorded proof against the chain, at any later time: it must hash to its blockRoot, and the
      execution block with its timestamp (its executionBlock, or found by timestamp) must name that root as
      parentBeaconBlockRoot. That is the root EIP-4788 served for the timestamp. Execution nodes keep block
      headers for good, while EIP-4788 keeps a root for 8,191 slots, so this check does not expire with the
      proof. --write adds the block found to PATH if it records none.

The verdict. With --escrow, the pin is that escrow's FORK_VERSION and FORK_EPOCH, read on chain, and the
simulation must agree with it; a --pin that differs is refused. Without it, --pin defaults to the last fork of the
guest's committed schedule (pins.py SEPOLIA_FORKS), which is what a deployment pins (tools/liquid-relay/README.md).
The output says what sending the proof does: under the pin it moves forkCheckedAt up to the state's slot time;
under a later or different fork it ends deposits for good.

Read-only: nothing here holds a key, signs or broadcasts. The RPC URLs come only from the environment and are
never printed or written, since they may carry API keys.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.append(str(HERE.parents[1] / 'tools/sg16/bridge-guest/testnet'))
import beacon  # noqa: E402
import liquid as lq  # noqa: E402
import pins  # noqa: E402

BEACON_ROOTS = '0x000f3df6d732807ef1319fb7b8bb8522d0beac02'
CHECK_FORK = 'checkFork((uint64,uint64,bytes32,uint64,bytes4,bytes4,uint64,bytes32[2],bytes32,bytes32[3]))'
# How far past the header's slot to look for the execution block that holds its root (a missed slot has none).
SEARCH_SLOTS = 64


def guest_pin():
    """The last fork of the guest's committed schedule: (name, version, epoch)."""
    name, epoch, version = pins.SEPOLIA_FORKS.split(',')[-1].split()
    return name, bytes.fromhex(version.removeprefix('0x')), int(epoch)


def parse_pin(text):
    version, epoch = text.split(':')
    return 'given', beacon.hex_bytes(version, 4), int(epoch)


def hx(b):
    return '0x' + b.hex()


def proof_of(j):
    """A BeaconProof from the `proof` member of this tool's output."""
    def h(k, n):
        return beacon.hex_bytes(j[k], n)

    def nodes(k, n):
        if len(j[k]) != n:
            raise ValueError(f'proof.{k} lists {len(j[k])} nodes, not {n}')
        return [beacon.hex_bytes(b, 32) for b in j[k]]

    return dict(timestamp=int(j['timestamp']), genesisTime=int(j['genesisTime']),
                genesisValidatorsRoot=h('genesisValidatorsRoot', 32), slot=int(j['slot']),
                previousVersion=h('previousVersion', 4), currentVersion=h('currentVersion', 4),
                epoch=int(j['epoch']), stateBranch=nodes('stateBranch', 2), activeFields=h('activeFields', 32),
                blockBranch=nodes('blockBranch', 3))


def calldata(p):
    """checkFork(BeaconProof): a static tuple, so its thirteen words follow the selector in place."""
    word = lambda n: n.to_bytes(32, 'big')  # noqa: E731
    return (lq.keccak256(CHECK_FORK.encode())[:4]
            + word(p['timestamp']) + word(p['genesisTime']) + p['genesisValidatorsRoot'] + word(p['slot'])
            + beacon.chunk(p['previousVersion']) + beacon.chunk(p['currentVersion']) + word(p['epoch'])
            + b''.join(p['stateBranch']) + p['activeFields'] + b''.join(p['blockBranch']))


def effect(p, pin):
    """What checkFork does with `p` on an escrow pinned to `pin`, and whether it is the pinned fork."""
    name, version, epoch = pin
    if p['epoch'] < epoch:
        return None, ('checkFork reverts StaleFork: the state is under a fork older than the pin '
                      f'({name}, epoch {epoch})')
    if p['currentVersion'] == version and p['epoch'] == epoch:
        return True, ('the pinned fork: checkFork moves forkCheckedAt up to the slot time, '
                      'and deposits may stay open until slot time + MAX_FORK_CHECK_AGE')
    return False, ('NOT the pinned fork: checkFork ENDS DEPOSITS FOR GOOD. Sepolia has left the fork the guest proves, '
                   'and this proof shows it; send it only for that reason')


def report(p, root, header_state_root, pin, version, block):
    pinned, what = effect(p, pin)
    slot_time = p['genesisTime'] + p['slot'] * beacon.SECONDS_PER_SLOT
    words = [p['timestamp'], p['genesisTime'], hx(p['genesisValidatorsRoot']), p['slot'], hx(p['previousVersion']),
             hx(p['currentVersion']), p['epoch'], '[' + ','.join(hx(b) for b in p['stateBranch']) + ']',
             hx(p['activeFields']), '[' + ','.join(hx(b) for b in p['blockBranch']) + ']']
    return {
        'ok': True, 'consensusVersion': version,
        'proof': {'timestamp': p['timestamp'], 'genesisTime': p['genesisTime'],
                  'genesisValidatorsRoot': hx(p['genesisValidatorsRoot']), 'slot': p['slot'],
                  'previousVersion': hx(p['previousVersion']), 'currentVersion': hx(p['currentVersion']),
                  'epoch': p['epoch'], 'stateBranch': [hx(b) for b in p['stateBranch']],
                  'activeFields': hx(p['activeFields']), 'blockBranch': [hx(b) for b in p['blockBranch']]},
        'blockRoot': hx(root), 'stateRoot': hx(header_state_root), 'slotTime': slot_time, 'executionBlock': block,
        'pin': {'name': pin[0], 'version': hx(pin[1]), 'epoch': pin[2]}, 'pinned': pinned, 'effect': what,
        'calldata': hx(calldata(p)), 'castArg': '(' + ','.join(str(w) for w in words) + ')',
    }


class Endpoint:
    """An RPC base URL from the environment variable `env`; errors name the variable and path, never the URL."""

    def __init__(self, env):
        self.env, self.base = env, os.environ.get(env, '').rstrip('/')
        if not self.base:
            raise SystemExit(f'set {env}')

    def request(self, path, accept='application/json', body=None):
        headers = {'Accept': accept, 'User-Agent': 'liquid-poc-bridge fork_proof'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.base + path, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f'{self.env} {path or "/"}: HTTP {e.code}') from None
        except OSError as e:
            raise RuntimeError(f'{self.env} {path or "/"}: {type(e).__name__}') from None

    def call(self, method, params):
        """A JSON-RPC call: (result, None) or (None, error)."""
        out = json.loads(self.request(
            '', body=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()))
        return (None, out['error']) if 'error' in out else (out['result'], None)


def eip4788_timestamp(execution, block_root, genesis_time, slot):
    """The timestamp of an execution block after `slot` whose EIP-4788 root is `block_root`."""
    latest, err = execution.call('eth_getBlockByNumber', ['latest', False])
    if err:
        raise RuntimeError(f'latest block: {err}')
    for s in range(slot + 1, slot + 1 + SEARCH_SLOTS):
        t = genesis_time + s * beacon.SECONDS_PER_SLOT
        if t > int(latest['timestamp'], 16):
            break
        result, err = execution.call('eth_call', [{'to': BEACON_ROOTS, 'data': hx(t.to_bytes(32, 'big'))}, 'latest'])
        if not err and result and bytes.fromhex(result.removeprefix('0x')) == block_root:
            return t
    raise RuntimeError('no execution block yet holds this block root in EIP-4788; retry after the next block')


def execution_block(execution, timestamp, root, number=None):
    """The execution block with `timestamp`, as {number, hash}, after checking that its header names `root` as
    parentBeaconBlockRoot, the root EIP-4788 stores for that timestamp. Read at `number` if given, else found by
    bisection over block timestamps."""
    def get(n):
        b, err = execution.call('eth_getBlockByNumber', [n if isinstance(n, str) else hex(n), False])
        if err or not b:
            raise RuntimeError(f'execution block {n}: {err or "not served"}')
        return b

    if number is None:
        latest = get('latest')
        hi, behind = int(latest['number'], 16), int(latest['timestamp'], 16) - timestamp
        if behind < 0:
            raise RuntimeError(f'no execution block has timestamp {timestamp} yet')
        # Blocks are at least a slot apart, so this many blocks back is at or before `timestamp`.
        lo = max(0, hi - behind // beacon.SECONDS_PER_SLOT)
        while lo < hi:
            mid = (lo + hi) // 2
            if int(get(mid)['timestamp'], 16) < timestamp:
                lo = mid + 1
            else:
                hi = mid
        number = lo
    b = get(number)
    if int(b['timestamp'], 16) != timestamp:
        raise ValueError(f'execution block {number} has timestamp {int(b["timestamp"], 16)}, not {timestamp}')
    if beacon.hex_bytes(b.get('parentBeaconBlockRoot') or '', 32) != root:
        raise ValueError(f'execution block {number} names another parent beacon block root than {hx(root)}')
    return {'number': number, 'hash': b['hash']}


def escrow_view(execution, escrow, signature):
    result, err = execution.call('eth_call',
                                 [{'to': escrow, 'data': hx(lq.keccak256(signature.encode())[:4])}, 'latest'])
    if err:
        raise RuntimeError(f'{signature} on the escrow: {err}')
    return bytes.fromhex(result.removeprefix('0x'))


def escrow_pin(execution, escrow):
    """The fork `escrow` pins, read from its FORK_VERSION() and FORK_EPOCH()."""
    version = escrow_view(execution, escrow, 'FORK_VERSION()')[:4]
    epoch = int.from_bytes(escrow_view(execution, escrow, 'FORK_EPOCH()'), 'big')
    return 'escrow', version, epoch


def simulate(execution, escrow, data):
    result, err = execution.call('eth_call', [{'to': escrow, 'data': hx(data)}, 'latest'])
    if err:
        return {'reverted': True, 'error': err}
    return {'reverted': False, 'pinned': int(result, 16) == 1}


def build(args):
    consensus, execution = Endpoint('SEPOLIA_CONSENSUS_RPC'), Endpoint('SEPOLIA_EXECUTION_RPC')

    def save(name, data):
        # Each input is kept as soon as it is read, so data the proof refuses can still be examined offline.
        if args.save_inputs:
            d = Path(args.save_inputs)
            d.mkdir(parents=True, exist_ok=True)
            (d / name).write_bytes(data)

    if args.block_root:
        wanted = beacon.hex_bytes(args.block_root, 32)
        raw = consensus.request(f'/eth/v1/beacon/light_client/bootstrap/{hx(wanted)}')
    else:
        wanted, raw = None, consensus.request('/eth/v1/beacon/light_client/finality_update')
    doc = json.loads(raw)
    save('light_client.json', (json.dumps(doc, indent=1) + '\n').encode())
    header = beacon.light_client_header(doc['data'])
    root = beacon.root_of(header)
    if wanted is not None and root != wanted:
        raise ValueError('the served bootstrap is for another block')
    genesis = json.loads(consensus.request('/eth/v1/beacon/genesis'))
    save('genesis.json', (json.dumps(genesis, indent=1) + '\n').encode())
    try:
        fork = json.loads(consensus.request(f'/eth/v1/beacon/states/{hx(header["state_root"])}/fork'))
    except RuntimeError:
        # Some nodes serve recent states by slot only; fork_proof checks the fork against the state's node 10.
        fork = json.loads(consensus.request(f'/eth/v1/beacon/states/{header["slot"]}/fork'))
    save('fork.json', (json.dumps(fork, indent=1) + '\n').encode())
    chain = beacon.chain_of(genesis, fork)
    timestamp = eip4788_timestamp(execution, root, chain['genesis_time'], header['slot'])
    block = execution_block(execution, timestamp, root)
    save('beacon_root.json', (json.dumps({'timestamp': timestamp, 'root': hx(root), 'executionBlock': block,
                                          'note': 'eth_call to the EIP-4788 contract at the latest block, and the '
                                                  'header of executionBlock'}) + '\n').encode())
    pin = args.pin or guest_pin()
    if args.escrow:
        pin = escrow_pin(execution, args.escrow)
        if args.pin and args.pin[1:] != pin[1:]:
            raise ValueError(f'--pin {hx(args.pin[1])}:{args.pin[2]} is not the escrow\'s pin {hx(pin[1])}:{pin[2]}')
    p, root = beacon.fork_proof(doc['data'], chain, timestamp)
    out = report(p, root, header['state_root'], pin, doc.get('version'), block)
    if args.escrow:
        if pin[1:] != guest_pin()[1:]:
            out['warning'] = (f'the escrow pins {hx(pin[1])}:{pin[2]}, but the guest\'s committed schedule ends at '
                              f'{hx(guest_pin()[1])}:{guest_pin()[2]}; a deployment must pin the latter')
        out['simulation'] = sim = simulate(execution, args.escrow, calldata(p))
        if not sim['reverted'] and sim['pinned'] != out['pinned']:
            raise RuntimeError('the escrow\'s checkFork simulation disagrees with the verdict from its own pin')
    return out


def offline(args):
    d = Path(args.inputs)
    doc = json.loads((d / 'light_client.json').read_text())
    recorded = json.loads((d / 'beacon_root.json').read_text())
    chain = beacon.chain_of(json.loads((d / 'genesis.json').read_text()), json.loads((d / 'fork.json').read_text()))
    p, root = beacon.fork_proof(doc['data'], chain, recorded['timestamp'])
    if hx(root) != recorded['root']:
        raise ValueError('the proof is for another block than the recorded EIP-4788 root')
    header = beacon.light_client_header(doc['data'])
    return report(p, root, header['state_root'], args.pin or guest_pin(), doc.get('version'),
                  recorded.get('executionBlock'))


def verify(args):
    path = Path(args.proof)
    out = json.loads(path.read_text())
    p = proof_of(out['proof'])
    root = beacon.proof_root(p)
    if hx(root) != out['blockRoot']:
        raise ValueError(f'the proof hashes to {hx(root)}, not to its recorded blockRoot {out["blockRoot"]}')
    recorded = out.get('executionBlock')
    block = execution_block(Endpoint('SEPOLIA_EXECUTION_RPC'), p['timestamp'], root, recorded and recorded['number'])
    if recorded and recorded != block:
        raise ValueError(f'the recorded executionBlock {recorded} is not the chain\'s {block}')
    if args.write and not recorded:
        out['executionBlock'] = block
        path.write_text(json.dumps(out, indent=1) + '\n')
    return {'ok': True, 'blockRoot': hx(root), 'timestamp': p['timestamp'], 'executionBlock': block,
            'checked': ('the proof hashes to blockRoot, '
                        'which the header of executionBlock names as parentBeaconBlockRoot')}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--pin', type=parse_pin, help='VERSION:EPOCH; default: the escrow\'s with --escrow, else '
                                                      'pins.py SEPOLIA_FORKS\' last fork')
    common.add_argument('--out', help='also write the JSON here')
    sub = ap.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build', parents=[common])
    b.add_argument('--block-root')
    b.add_argument('--escrow')
    b.add_argument('--save-inputs')
    o = sub.add_parser('offline', parents=[common])
    o.add_argument('--inputs', required=True)
    v = sub.add_parser('verify')
    v.add_argument('--proof', required=True)
    v.add_argument('--write', action='store_true', help='add the execution block found to the proof file')
    args = ap.parse_args()
    try:
        out = {'build': build, 'offline': offline, 'verify': verify}[args.cmd](args)
    except (ValueError, RuntimeError, KeyError, TypeError, IndexError, OSError) as e:
        # Malformed, inconsistent or missing input is a refusal, not a crash. So is a state checkFork cannot
        # prove (beacon.UnprovableState).
        print(json.dumps({'ok': False, 'error': f'{type(e).__name__}: {e}'}))
        sys.exit(3)
    if args.cmd == 'verify':
        print(json.dumps(out, indent=1))
        return
    out['built'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    text = json.dumps(out, indent=1)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text + '\n')
    print(text)


if __name__ == '__main__':
    main()
