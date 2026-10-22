#!/usr/bin/env python3
"""The sg16 bridge update guest's public values on Liquid (bridge-guest/liquid.py).

  A. encodings: sg16-bridge-core (Rust, what the guest commits) vs liquid.py for the public values, lc and config;
     liquid.py's and sg16/helios.py's tags, lc, claimed_root and state_hash vs the shared vectors/protocol.json;
  B. the update leaf's rules alone (public input from the witness, NOT a bridge) in complete Elements update
     transactions over the bridge state, whose claimed tree has deposits 2 and 0 paid out of order: honest updates
     accepted; transaction mutations (among them a successor with another claimed root), a wrong input, a proof for
     another network config, escrow or slot, a proof from another starting store and a consistently forged
     accumulator rejected;
  C. --full (minutes): the Groth16 verifier for a folded synthetic five-input key with this opening, same
     transaction: cost, budget, weight;
  D. --artifact PATH: a bridge-guest artifact from `sg16-bridge-host run --prove`: SP1 v6.1.0 selector, exit code
     and VK_ROOT from the pinned sp1-contracts source, the five-input and folded keys accept the proof (reference
     BN254 pairing), and with --harness the real proof is run through the real update leaf in a complete
     transaction rebuilt from the artifact's anchor and successor.  An artifact whose network is not Sepolia is
     labelled so; an execute-only artifact (proof "0x") is refused with exit status 2.

    cargo test --release -p sg16-bridge-core --manifest-path tools/sg16/bridge-guest/Cargo.toml
    cargo build --release -p sg16-bridge-core --features cli --manifest-path tools/sg16/bridge-guest/Cargo.toml
    cargo build --release --manifest-path tools/sg16-harness/Cargo.toml
    python3 tools/sg16/bridge-guest/test_bridge_guest.py [--full] [--artifact A.json [--harness]] [--evidence E.json]
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import liquid  # noqa: E402
from sg16 import fixtures, harness, helios, sp1, statement  # noqa: E402
from sg16.ref import ROOT  # noqa: E402
from groth import bn254 as B  # noqa: E402
from groth.dsl import CheckFailed  # noqa: E402
from groth.fp import Fp  # noqa: E402
from groth.pairing import bounds  # noqa: E402
from groth.sym import Num  # noqa: E402

CORE = Path(os.environ.get('SG16_BRIDGE_CORE', HERE / 'target' / 'release' / 'sg16-bridge-core'))
V6 = ROOT / 'vendor' / 'sp1-helios' / 'contracts' / 'lib' / 'sp1-contracts' / 'contracts' / 'src' / 'v6.1.0'
VECTORS = ROOT / 'vectors' / 'protocol.json'
ESCROW = bytes.fromhex('5f5a1e1b5e0b6c3f0a9d4e2c1b7a8d9e0f1a2b3c')
CONFIG = liquid.config_hash(bytes.fromhex('d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078'),
                            b'synthetic forks encoding')
SEED = 7007


def h(label):
    return fixtures.h(label)


def core(*args):
    out = subprocess.run([str(CORE)] + [str(a) for a in args], capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise SystemExit(f'sg16-bridge-core {args[0]} failed:\n{out.stdout}\n{out.stderr}')
    return json.loads(out.stdout)


def chain(**over):
    """Anchor and successor stores, the update's other values, and the bridge state around them."""
    c = dict(head=8192 * 1000 + 64, header=h('anchor header'), committee=h('anchor committee'),
             new_head=8192 * 1000 + 96, new_header=h('successor header'), sync=h('successor committee'),
             acc=h('accumulator 0'), new_acc=h('accumulator 1'),
             exec_root=h('execution state root'), exec_block=9_100_000, claimed_root=helios.claimed_root([2, 0]),
             sibling=h('claim leaf'))
    c.update(over)
    return c


def fields_of(c):
    return dict(lc=liquid.lc(c['head'], c['header'], c['committee']), acc=c['acc'], sibling=c['sibling'],
                new_lc=liquid.lc(c['new_head'], c['new_header'], c['sync']), new_acc=c['new_acc'],
                exec_root=c['exec_root'], claimed_root=c['claimed_root'], exec_block=c['exec_block'],
                new_head=c['new_head'])


def tx_of(c, old_abf=0):
    """A harness update transaction (tools/sg16-harness src/bridge.rs `Plan`): the harness builds the spent and
    successor states from (head, header, committee, acc, claimed_root) and (new_head, new_header, sync, new_acc,
    the same claimed_root)."""
    t = dict(state_txid=h('state txid').hex(), state_vout=0, fee_txid=h('fee txid').hex(), fee_vout=1, fee_value=4000,
             old_abf=old_abf)
    for name in ('header', 'committee', 'acc', 'claimed_root', 'sibling', 'new_header', 'sync', 'new_acc'):
        t[name] = c[name].hex()
    for name in ('head', 'new_head'):
        t[name] = c[name]
    return t


def contract_return(text, fn):
    m = re.search(r'function\s+' + fn + r'\s*\(\s*\)[^{]*\{\s*return\s+([^;]+);', text)
    return m.group(1).strip() if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--full', action='store_true')
    ap.add_argument('--artifact')
    ap.add_argument('--harness', action='store_true',
                    help='with --artifact: run the real proof through the update leaf')
    ap.add_argument('--evidence')
    a = ap.parse_args()
    report, failures = {}, []

    def check(name, cond, detail=None):
        report[name] = dict(ok=bool(cond), detail=detail)
        print(f'  {"ok " if cond else "BAD"} {name}' + (f' ({detail})' if detail is not None and not cond else ''))
        if not cond:
            failures.append(name)
        return cond

    def finish(code=None):
        if a.evidence:
            with open(a.evidence, 'w') as fh:
                json.dump(dict(test='tools/sg16/bridge-guest/test_bridge_guest.py', results=report, failures=failures),
                          fh, indent=1, default=str)
        print(f'{len(failures)} problem(s)')
        sys.exit(code if code is not None else (1 if failures else 0))

    c = chain()
    f = fields_of(c)
    print('A. encodings (sg16-bridge-core vs liquid.py; liquid.py and helios.py vs vectors/protocol.json)')
    if CORE.exists():
        enc = core('encode', harness.write('bridge_core_encode.json', dict(
            config=CONFIG.hex(), escrow=ESCROW.hex(), slot_key='00' * 32,
            prev_lc=f['lc'].hex(), new_lc=f['new_lc'].hex(), slot_value=f['new_acc'].hex(),
            execution_state_root=f['exec_root'].hex(), execution_block_number=f['exec_block'],
            new_head=f['new_head'])))
        check('public values = Rust UpdateOutputs::encode',
              enc['public_values'] == liquid.public_values(CONFIG, ESCROW, 0, f).hex())
        check('public input = Rust', int(enc['public_input'], 16) == liquid.public_input(CONFIG, ESCROW, 0, f))
        check('lc = Rust', core('lc', c['head'], c['header'].hex(), c['committee'].hex())['lc'] == f['lc'].hex())
        check('lc = sg16/helios.py lc (the state commitment)',
              f['lc'] == helios.lc(c['head'], c['header'], c['committee']))
        check('config = Rust',
              core('config', '00' * 32, b'forks'.hex())['config'] == liquid.config_hash(bytes(32), b'forks').hex())
    else:
        print(f'  ({CORE} missing: cargo build --release -p sg16-bridge-core --features cli '
              f'--manifest-path tools/sg16/bridge-guest/Cargo.toml)')

    vec = json.loads(VECTORS.read_text())
    tag = {k: t.encode() for k, t in vec['tags'].items()}

    def vector(name, got, want):
        if want is None:
            return check(name, False, 'not recorded: run node vectors/record.mjs and review the result')
        return check(name, got == bytes.fromhex(want[2:]))

    check('liquid.py UPDATE_TAG, LC_TAG, CONFIG_TAG = SHA256 of vectors tags.update, lc, eth_config',
          (liquid.UPDATE_TAG, liquid.LC_TAG, liquid.CONFIG_TAG)
          == tuple(liquid.sha(tag[k]) for k in ('update', 'lc', 'eth_config')))
    check('sg16/helios.py STATE_TAG, LC_TAG = SHA256 of vectors tags.state, lc',
          (helios.STATE_TAG, helios.LC_TAG) == (liquid.sha(tag['state']), liquid.sha(tag['lc'])))
    held = dict(state=helios.STATE_TAG, claimed=helios.CLAIMED_LEAF, lc=liquid.LC_TAG, update=liquid.UPDATE_TAG,
                eth_config=liquid.CONFIG_TAG)
    for i, v in enumerate(vec['tag_sha256']):
        vector(f'vectors tag_sha256[{i}] ({v["tag"]}) = liquid.py, helios.py', held[v['tag']], v['sha256'])
    for i, v in enumerate(vec['lc']):
        args = v['slot'], bytes.fromhex(v['header'][2:]), bytes.fromhex(v['committee'][2:])
        vector(f'vectors lc[{i}] = liquid.py lc', liquid.lc(*args), v['lc'])
        vector(f'vectors lc[{i}] = sg16/helios.py lc', helios.lc(*args), v['lc'])
    check('sg16/helios.py CLAIMED_LEAF = SHA256 of vectors tags.claimed',
          helios.CLAIMED_LEAF == liquid.sha(tag['claimed']))
    for i, v in enumerate(vec['claimed_root']):
        vector(f'vectors claimed_root[{i}] = sg16/helios.py claimed_root', helios.claimed_root(v['indices']), v['root'])
    for i, v in enumerate(vec['state_hash']):
        root = helios.claimed_root(v['indices'])
        vector(f'vectors state_hash[{i}].claimed_root = sg16/helios.py claimed_root', root, v['claimed_root'])
        got = helios.state_hash(bytes.fromhex(v['lc'][2:]), bytes.fromhex(v['acc'][2:]), root)
        vector(f'vectors state_hash[{i}] = sg16/helios.py state_hash', got, v['state_hash'])
    for name, bad in (('a repeated index', [1, 1]), ('an index outside the tree', [1 << 32]),
                      ('a negative index', [-1]), ('an index that is not an integer', ['0'])):
        try:
            helios.claimed_root(bad)
            refused = False
        except ValueError:
            refused = True
        check(f'sg16/helios.py claimed_root refuses {name}', refused)

    print('B. the update leaf rules (input from the witness)')
    cfg = dict(fixtures.config(), escrow=ESCROW.hex())
    k = harness.consts(cfg)
    text, est = liquid.rules_program(k, CONFIG, ESCROW)
    prog = harness.write('bridge_guest_rules.simpl', text)
    x = liquid.public_input(CONFIG, ESCROW, 0, f)
    W = liquid.rules_witness
    cases = [dict(name='honest A->B', expect='ok', tx=tx_of(c), mutations=[], witness=W(f, x)),
             dict(name='honest B->A', expect='ok', tx=tx_of(c, 1), mutations=[], witness=W(f, x))]
    for m in ['successor_state_other', 'claimed_changed', 'sibling_other', 'header_other', 'stale_old_state',
              'token_private_abf', 'third_input', 'state_input_second', 'successor_to_attacker', 'path_extra',
              'update_mints', 'input1_issuance', 'fee_asset_other']:
        cases.append(dict(name=m, expect='fail', tx=tx_of(c), mutations=[m], witness=W(f, x)))
    cases += [
        dict(name='wrong public input', expect='fail', tx=tx_of(c), mutations=[], witness=W(f, x ^ 1)),
        dict(name='proof for another network config', expect='fail', tx=tx_of(c), mutations=[],
             witness=W(f, liquid.public_input(liquid.config_hash(bytes(32), b'other network'), ESCROW, 0, f))),
        dict(name='proof for another escrow', expect='fail', tx=tx_of(c), mutations=[],
             witness=W(f, liquid.public_input(CONFIG, bytes.fromhex('11' * 20), 0, f))),
        dict(name='proof for another storage slot', expect='fail', tx=tx_of(c), mutations=[],
             witness=W(f, liquid.public_input(CONFIG, ESCROW, 1, f))),
    ]
    other = fields_of(chain(head=c['head'] - 32, header=h('older header')))
    cases.append(dict(name='proof from another starting store', expect='fail', tx=tx_of(c), mutations=[],
                      witness=W(dict(f, lc=other['lc']),
                                liquid.public_input(CONFIG, ESCROW, 0, dict(f, lc=other['lc'])))))
    forged = chain(new_acc=h('forged accumulator'))
    cases.append(dict(name='consistently forged accumulator', expect='fail', tx=tx_of(forged), mutations=[],
                      witness=W(fields_of(forged), x)))
    _, results = harness.run(prog, dict(config=cfg, cases=cases), name='bridge_guest_rules_cases.json')
    for case, r in zip(cases, results):
        good = r['ok'] == (case['expect'] == 'ok')
        if case['expect'] == 'ok':
            good = good and r['cost'] == est and r['budget_ok'] and r['amounts_valid']
        check(f'{case["name"]}: {"accepted" if case["expect"] == "ok" else "rejected"}', good,
              f'cost {r.get("cost")} vs {est}' if r['ok'] else f'{r.get("stage")}: {str(r.get("error", ""))[:80]}')
    report['rules'] = dict(predicted_cost=est, cases=results)

    def full_run(vk1, proof, finputs, fields, tx, label, config, escrow, slot_key):
        text, gs, est = liquid.BridgeGuestVerifier.compile(vk1, k, config=config, escrow=escrow, slot_key=slot_key)
        prog = harness.write(f'bridge_guest_{label}.simpl', text)
        gn = liquid.BridgeGuestVerifier(Fp(Num()), vk1, k, b=bounds(), config=config, escrow=escrow, slot_key=slot_key)
        wit = gn.witness_fields(proof, finputs, fields)
        if not check(f'{label}: the numeric model builds the witness', wit is not None):
            return
        gn.verify(gn.num_input(wit))
        tampered = dict(wit, points=list(wit['points']))
        tampered['points'][0] ^= 1
        other_q = dict(wit, q=list(wit['q']))
        other_q['q'][0] ^= 1
        for name, w in (('a tampered proof', tampered), ('a tampered quotient', other_q)):
            try:
                gn.verify(gn.num_input(w))
                refused = False
            except CheckFailed:
                refused = True
            check(f'{label}: the numeric model refuses {name}', refused)
        runs = [dict(name=f'{label}: update', expect='ok', tx=tx, mutations=[], witness=gs.witness_value(wit)),
                dict(name=f'{label}: tampered proof', expect='fail', tx=tx, mutations=[],
                     witness=gs.witness_value(tampered)),
                dict(name=f'{label}: tampered quotient', expect='fail', tx=tx, mutations=[],
                     witness=gs.witness_value(other_q)),
                dict(name=f'{label}: successor with another accumulator', expect='fail', tx=tx,
                     mutations=['successor_state_other'], witness=gs.witness_value(wit))]
        header, res = harness.run(prog, dict(config=cfg, cases=runs), name=f'bridge_guest_{label}_cases.json')
        for case, r in zip(runs, res):
            good = r['ok'] == (case['expect'] == 'ok')
            if r['ok']:
                good = good and r['cost'] == est and r['budget_ok'] and r['tx_weight'] < 400000
                print(f'    cost {r["cost"]:,} mWU (predicted {est:,}), program {r["program_bytes"]:,} B, '
                      f'witness {r["witness_bytes"]:,} B, tx weight {r["tx_weight"]:,} WU, cells {r["cells"]:,}')
            check(f'{case["name"]}: {"accepted" if case["expect"] == "ok" else "rejected"}', good, r.get('stage'))
        report[label] = dict(cmr=header['cmr'], predicted_cost=est, parts=gs.parts, cases=res)

    if a.full:
        print('C. Groth16 verifier + update leaf (folded synthetic five-input key)')
        fixed = dict(program_vkey=int.from_bytes(h('bridge guest vkey'), 'big') % B.R, exit_code=0,
                     vk_root=int.from_bytes(h('sp1 vk root'), 'big') % B.R, proof_nonce=0)
        vk5, proof, _ = B.groth16_instance(5, seed=SEED,
                                           inputs=sp1.wrapper_inputs('v6.1.0', public_values_digest=x, **fixed))
        full_run(sp1.one_input_key(vk5, 'v6.1.0', **fixed), proof, [x], f, tx_of(c), 'synthetic', CONFIG, ESCROW, 0)

    if a.artifact:
        print('D. real bridge-guest artifact')
        art = json.loads(Path(a.artifact).read_text())
        if (art.get('proof') or '0x') == '0x':
            print(f'{a.artifact}: execute-only artifact, no Groth16 proof; run sg16-bridge-host run ... --prove')
            failures.append('artifact has no Groth16 proof')
            finish(2)
        network = art.get('network', '')
        report['artifact_network'] = network
        print(f'  network: {network}' + ('' if network == 'sepolia' else '  (NOT a Sepolia bridge update)'))
        check('artifact is from the bridge guest', art.get('guest') == 'sg16-bridge-program')
        sv, gv = (V6 / 'SP1VerifierGroth16.sol').read_text(), (V6 / 'Groth16Verifier.sol').read_text()
        selector = bytes.fromhex(contract_return(sv, 'VERIFIER_HASH')[2:])[:4]
        vk_root = int(contract_return(sv, 'VK_ROOT'), 16)
        vk5, _ = sp1.vk_from_gnark_solidity(gv)
        proof_bytes = bytes.fromhex(art['proof'][2:])
        check('selector = VERIFIER_HASH[:4]', proof_bytes[:4] == selector)
        _, header, proof = sp1.decode_proof(proof_bytes, 'v6.1.0')
        check('exitCode = 0 and vkRoot = VK_ROOT', header['exit_code'] == 0 and header['vk_root'] == vk_root)
        pv = bytes.fromhex(art['publicValues'][2:])
        o = art['outputs']
        config, escrow, slot_key = (bytes.fromhex(o['config'][2:]), bytes.fromhex(o['escrow'][2:]),
                                    int(o['slot_key'], 16))
        anchor, succ = art['inputs']['anchor'], art['successor']
        cr = chain(head=anchor['slot'], header=bytes.fromhex(anchor['header'][2:]),
                   committee=bytes.fromhex(anchor['committee'][2:]),
                   new_head=succ['slot'], new_header=bytes.fromhex(succ['header'][2:]),
                   sync=bytes.fromhex(succ['committee'][2:]),
                   new_acc=bytes.fromhex(o['slot_value'][2:]), exec_root=bytes.fromhex(o['execution_state_root'][2:]),
                   exec_block=o['execution_block_number'], acc=bytes(32), claimed_root=helios.claimed_root([]))
        fr = fields_of(cr)
        check('public values = liquid.py model of the artifact fields',
              pv == liquid.public_values(config, escrow, slot_key, fr))
        digest = statement.public_input(liquid.sha(pv))
        vkey = int(art['vkey'], 16)
        nonce = header['proof_nonce']
        inputs5 = sp1.wrapper_inputs('v6.1.0', program_vkey=vkey, public_values_digest=digest,
                                     exit_code=0, vk_root=vk_root, proof_nonce=nonce)
        t0 = time.time()
        check('five-input key accepts the proof', B.groth16_verify(vk5, proof, inputs5))
        if not check('proof nonce is zero (one variable input after folding)', nonce == 0, hex(nonce)):
            finish()
        vk1 = sp1.one_input_key(vk5, 'v6.1.0', program_vkey=vkey, exit_code=0, vk_root=vk_root, proof_nonce=0)
        check('folded key accepts the proof', B.groth16_verify(vk1, proof, [digest]))
        check('folded key rejects another digest', not B.groth16_verify(vk1, proof, [digest ^ 1]))
        print(f'  pairing checks {time.time() - t0:.0f}s')
        if a.harness:
            full_run(vk1, proof, [digest], fr, tx_of(cr), 'real', config, escrow, slot_key)
    finish()


if __name__ == '__main__':
    main()
