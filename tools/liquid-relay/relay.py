#!/usr/bin/env python3
"""Relay public Liquid headers to contracts/solidity/contracts/LiquidLightClient.sol, and write its Foundry fixture.

  relay.py fixture --checkpoint-height H --to T --sign-at h1,...,T --tx TXID [--out PATH]
      Fetch heights H+1 .. T, check that each served header hashes to the id it was fetched by, cut
      the hash forms, check the signblock witness of each batch tip (the --sign-at heights, the last
      being T) and the inclusion of TXID, and write the fixture contracts/solidity/test/LiquidLightClient.t.sol
      reads. H must be the last height of an epoch.

  relay.py batches --tip-height H --tip-hash 0x.. --signblockscript-hash 0x.. --to T --out-dir DIR
      From the light client's stored tip (`cast call <client> "lcTipHeight()"`, "lcTipHash()",
      "signblockscriptHash()"), write one calldata file per submitHeaders call up to T. Batches stay
      inside one epoch and hold at most --batch-size headers. A batch that opens an epoch whose
      signblockscript differs from the stored one carries the new witness script and key ys. Send each
      file in order with `cast send <client> "$(cat DIR/<file>.calldata)"`; batches.json records them.

  relay.py checkpoint --height H
      The constructor checkpoint at H, the last height of an epoch: H's hash, and the next epoch's witness
      script and key ys from block H + 1's checked signblock witness, with a `cast` tuple for BridgeEscrow.

  relay.py blockref --first F --count C --height h
      The BlockRef path of height h in the stored batch with firstHeight F and count C, rebuilt from
      Esplora headers. Compare the printed root with batchAt(i).root; i comes from HeadersAccepted.

Options common to all: --esplora URL (or LIQUID_ESPLORA; default Blockstream's Liquid testnet API),
--epoch-length L (default 1000, Liquid testnet's dynamic_epoch_length), --delay seconds between
requests. Read-only: nothing here holds a key, signs or broadcasts.
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import liquid as lq  # noqa: E402

DEFAULT_ESPLORA = 'https://blockstream.info/liquidtestnet/api'
ROOT = Path(__file__).resolve().parents[2]


class Esplora:
    def __init__(self, base, delay):
        self.base, self.delay = base.rstrip('/'), delay

    def get(self, path):
        last = None
        for attempt in range(4):
            try:
                req = urllib.request.Request(self.base + path, headers={'User-Agent': 'zk-bridge relay'})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = resp.read().decode()
                time.sleep(self.delay)
                return body
            except OSError as e:  # URLError and HTTPError are OSErrors; the base URL holds no secret
                last = e
                time.sleep(1 + 2 * attempt)
        raise RuntimeError(f'GET {path}: {last}')

    def block_hash(self, height):
        return self.get(f'/block-height/{height}').strip()

    def signed_header(self, block_id):
        """The signed header served for `block_id` (display hex), checked to hash to that id."""
        h = lq.parse_header(bytes.fromhex(self.get(f'/block/{block_id}/header').strip()))
        if lq.display(h['hash']) != block_id:
            raise ValueError(f'served header for {block_id} hashes to {lq.display(h["hash"])}')
        return h

    def chain(self, first, last):
        """Signed headers first .. last, walked down from the block at `last` by prev hashes, so the
        result is one hash-linked chain whatever the server returns for other heights."""
        out, block_id = [], self.block_hash(last)
        while True:
            h = self.signed_header(block_id)
            out.append(h)
            if h['height'] == first:
                break
            if h['height'] < first:
                raise ValueError('walked below the first height')
            block_id = lq.display(h['prev'])
            if len(out) % 100 == 0:
                print(f'  fetched {len(out)} headers, now at height {h["height"]}', file=sys.stderr)
        out.reverse()
        for a, b in zip(out, out[1:]):
            if b['prev'] != a['hash'] or b['height'] != a['height'] + 1:
                raise ValueError(f'headers {a["height"]} and {b["height"]} are not parent and child')
        if out[0]['height'] != first or out[-1]['height'] != last:
            raise ValueError('heights do not span the requested range')
        return out


def hx(b):
    return '0x' + b.hex()


def word(n):
    return hx(n.to_bytes(32, 'big'))


def split(first, last, length, size):
    """Consecutive [a, b] ranges covering first .. last, inside epochs, at most `size` long."""
    out, a = [], first
    while a <= last:
        b = min(last, a + size - 1, (a // length + 1) * length - 1)
        out.append((a, b))
        a = b + 1
    return out


def fixture(args, esplora):
    length, h0, top = args.epoch_length, args.checkpoint_height, args.to
    if (h0 + 1) % length:
        raise SystemExit(f'--checkpoint-height {h0} is not the last height of an epoch of {length}')
    tips = sorted({int(x) for x in args.sign_at.split(',')})
    if not tips or tips[-1] != top or tips[0] <= h0:
        raise SystemExit('--sign-at must list heights above the checkpoint ending at --to')
    headers = esplora.chain(h0 + 1, top)
    script = headers[0]['current']['signblockscript']
    if any(h['current']['signblockscript'] != script for h in headers):
        raise SystemExit('the signblockscript changes inside the range; a fixture covers one federation')
    witness_script, ys, m = lq.federation(headers[0]['witness'][-1])
    if lq.p2wsh(witness_script) != script:
        raise SystemExit('the first header\'s witness script is not its signblockscript')
    if m != 1:
        raise SystemExit(f'the fixture format holds one signature per batch, this federation needs {m}')
    batches, start = [], h0 + 1
    for t in tips:
        if start // length != t // length:
            raise SystemExit(f'batch {start} .. {t} crosses an epoch boundary')
        part = headers[start - h0 - 1:t - h0]
        (r, s), = lq.tip_signatures(part[-1])
        batches.append({
            'firstHeight': start, 'headers': [hx(h['hash_form']) for h in part],
            'sigR': word(r), 'sigS': word(s), 'tipHash': hx(part[-1]['hash']), 'tipId': lq.display(part[-1]['hash']),
        })
        start = t + 1

    raw = bytes.fromhex(esplora.get(f'/tx/{args.tx}/hex').strip())
    form = lq.txid_form(raw)
    if lq.display(lq.sha256d(form)) != args.tx:
        raise SystemExit('the served transaction does not hash to --tx')
    proof = json.loads(esplora.get(f'/tx/{args.tx}/merkle-proof'))
    height, position = proof['block_height'], proof['pos']
    branch = [lq.internal(x) for x in proof['merkle']]
    if not h0 < height <= top:
        raise SystemExit(f'--tx is at height {height}, outside the fixture')
    if lq.merkle_root(lq.internal(args.tx), branch, position) != headers[height - h0 - 1]['merkle_root']:
        raise SystemExit('the served Merkle branch does not reach the header\'s Merkle root')

    out = {
        'network': 'liquidtestnet', 'source': esplora.base,
        'fetched': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'note': 'hashes in internal byte order (reverse of explorer display), except tipId and tx.id',
        'epochLength': length, 'checkpointHeight': h0, 'checkpointHash': hx(headers[0]['prev']),
        'checkpointId': lq.display(headers[0]['prev']), 'witnessScript': hx(witness_script),
        'keyY': [word(y) for y in ys],
        'batchCount': len(batches), 'batches': batches,
        'tx': {'id': args.tx, 'txid': hx(lq.internal(args.tx)), 'height': height, 'position': position,
               'branch': [hx(b) for b in branch], 'txidForm': hx(form)},
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps({'ok': True, 'path': str(path), 'headers': len(headers),
                      'batches': [len(b['headers']) for b in batches],
                      'checkpoint': out['checkpointId'], 'tx_height': height}))


def batches(args, esplora):
    length = args.epoch_length
    tip_hash = bytes.fromhex(args.tip_hash.removeprefix('0x'))
    stored = bytes.fromhex(args.signblockscript_hash.removeprefix('0x'))
    if len(tip_hash) != 32 or len(stored) != 32 or args.to <= args.tip_height or args.batch_size < 1:
        raise SystemExit('--tip-hash and --signblockscript-hash are 32 bytes; --to is above --tip-height')
    headers = esplora.chain(args.tip_height + 1, args.to)
    if headers[0]['prev'] != tip_hash:
        raise SystemExit('the header after the stored tip does not extend it: wrong --tip-hash, or a fork')
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for a, b in split(args.tip_height + 1, args.to, length, args.batch_size):
        part = headers[a - args.tip_height - 1:b - args.tip_height]
        current = lq.keccak256(part[0]['current']['signblockscript'])
        witness_script, ys = b'', []
        if a % length == 0 and current != stored:
            # The federation of the new epoch signs its headers; its witness script is in their witnesses.
            witness_script, ys, _ = lq.federation(part[-1]['witness'][-1])
            if lq.keccak256(lq.p2wsh(witness_script)) != current:
                raise SystemExit(f'batch {a}: the tip witness script is not the new signblockscript')
            stored = current
        elif current != stored:
            raise SystemExit(f'batch {a}: the signblockscript changed outside an epoch start')
        sigs = lq.tip_signatures(part[-1])
        data = lq.encode_submit_headers([h['hash_form'] for h in part], sigs, witness_script, ys)
        name = f'batch-{a}-{b}.calldata'
        (out_dir / name).write_text(hx(data) + '\n')
        root, _ = lq.batch_tree([h['merkle_root'] for h in part])
        records.append({'file': name, 'firstHeight': a, 'count': b - a + 1, 'root': hx(root),
                        'tipHash': hx(part[-1]['hash']), 'keyChange': bool(witness_script),
                        'calldataBytes': len(data)})
    (out_dir / 'batches.json').write_text(json.dumps(records, indent=1) + '\n')
    print(json.dumps({'ok': True, 'batches': len(records), 'dir': str(out_dir)}))


def checkpoint(args, esplora):
    """The LiquidLightClient / BridgeEscrow constructor checkpoint at height H, the last block of an epoch: its
    hash, and the witness script and key ys of the next epoch, read from block H + 1's signblock witness and
    checked against that block's current signblockscript and signature.  Both blocks must already exist."""
    length, h = args.epoch_length, args.height
    if (h + 1) % length:
        raise SystemExit(f'--height {h} is not the last height of an epoch of {length}')
    first = esplora.signed_header(esplora.block_hash(h + 1))
    if first['height'] != h + 1:
        raise ValueError('the served header is not at the requested height')
    lq.tip_signatures(first)  # the witness verifies under its own script, as Elements requires
    witness_script, ys, m = lq.federation(first['witness'][-1])
    if lq.p2wsh(witness_script) != first['current']['signblockscript']:
        raise ValueError('the next block\'s witness script is not its signblockscript')
    out = {'epochLength': length, 'height': h, 'hash': hx(first['prev']), 'hashId': lq.display(first['prev']),
           'witnessScript': hx(witness_script), 'keyY': [str(y) for y in ys], 'threshold': m, 'keys': len(ys),
           'signblockscriptKeccak': hx(lq.keccak256(lq.p2wsh(witness_script))),
           # BridgeEscrow(bytes32 bridgeAsset, uint32 minConfirmations, uint32 maxRelayLag,
           #     (uint64,uint64,address,uint32,bytes32,bytes4,uint64) admission,
           #     (uint32,uint32,bytes32,bytes,uint256[]) checkpoint)
           'castTuple': f'({length},{h},{hx(first["prev"])},{hx(witness_script)},[{",".join(str(y) for y in ys)}])',
           'note': 'trust the hash only after comparing it with an independent Liquid node or explorer (assumption L2)'}
    print(json.dumps(out, indent=1))


def blockref(args, esplora):
    if not args.first <= args.height < args.first + args.count:
        raise SystemExit('--height is outside the batch')
    headers = esplora.chain(args.first, args.first + args.count - 1)
    roots = [h['merkle_root'] for h in headers]
    root, path = lq.batch_path(roots, args.height - args.first)
    print(json.dumps({'root': hx(root), 'index': args.height - args.first, 'path': [hx(p) for p in path],
                      'merkleRoot': hx(roots[args.height - args.first])}))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--esplora', default=os.environ.get('LIQUID_ESPLORA', DEFAULT_ESPLORA))
    ap.add_argument('--epoch-length', type=int, default=1000)
    ap.add_argument('--delay', type=float, default=0.05)
    sub = ap.add_subparsers(dest='cmd', required=True)
    f = sub.add_parser('fixture')
    f.add_argument('--checkpoint-height', type=int, required=True)
    f.add_argument('--to', type=int, required=True)
    f.add_argument('--sign-at', required=True)
    f.add_argument('--tx', required=True)
    f.add_argument('--out', default=str(ROOT / 'contracts/solidity/test/fixtures/liquid-testnet-headers.json'))
    b = sub.add_parser('batches')
    b.add_argument('--tip-height', type=int, required=True)
    b.add_argument('--tip-hash', required=True)
    b.add_argument('--signblockscript-hash', required=True)
    b.add_argument('--to', type=int, required=True)
    b.add_argument('--batch-size', type=int, default=100)
    b.add_argument('--out-dir', required=True)
    r = sub.add_parser('blockref')
    r.add_argument('--first', type=int, required=True)
    r.add_argument('--count', type=int, required=True)
    r.add_argument('--height', type=int, required=True)
    c = sub.add_parser('checkpoint')
    c.add_argument('--height', type=int, required=True)
    args = ap.parse_args()
    esplora = Esplora(args.esplora, args.delay)
    try:
        {'fixture': fixture, 'batches': batches, 'blockref': blockref,
         'checkpoint': checkpoint}[args.cmd](args, esplora)
    except (ValueError, RuntimeError, KeyError, TypeError, IndexError) as e:
        # Malformed or unexpected Esplora data (a missing JSON key, a wrong type) is a refusal, not a crash.
        print(json.dumps({'ok': False, 'error': f'{type(e).__name__}: {e}'}))
        sys.exit(3)


if __name__ == '__main__':
    main()
