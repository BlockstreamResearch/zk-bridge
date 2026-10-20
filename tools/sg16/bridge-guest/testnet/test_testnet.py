#!/usr/bin/env python3
"""Local tests of tools/sg16/bridge-guest/testnet.  No network access; nothing is signed, funded or broadcast.

The assembly takes its instance only from a named instance file.  The tests write LOCAL TEST instance files for
fictional escrows with a synthetic anchor and run under them.  Real SP1 artifacts are not tracked: A, B and F use
them only when given with --exec-artifact and --proof-artifact, under the instance file --artifact-instance names
(there is no default; F needs it).  G checks every published record under instances/, and says so when there is
none.  B's gate matrix, E and F need the recorded Sepolia config (pins.SEPOLIA_CONFIG), which A checks.

  A. instances and pins: the local instance files recompute (escrow DOMAIN, empty accumulator, anchor lc, SHA-256
     compression); SEPOLIA_CONFIG is recorded; pins.py has no default instance; pins.py's tags and formulas and
     assemble.py's manifest schema are those of vectors/protocol.json; malformed instance files are
     refused; assemble.py refuses a command without --instance, and `pins` takes the escrow from the file; malformed
     hint entries are refused; lc_store refuses a store file of another lc, one whose roots do not hash to it, a
     missing one and one without CBOR; with a withheld store, recover takes the first hint that hashes to the live
     lc (published record, then a rebuilt store), the artifact gates refuse an lc-only state, and stage-recovered
     records the rebuilt store under the update that reached the head, in head order, or writes nothing; a given
     execute-only artifact decodes to its instance's config, escrow, slot, anchor and program vkey
  B. artifact gates: the pinned SP1 v6.1.0 key; with an execute-only artifact, the artifact is refused; each
     identity field changed is refused at its own gate, and so are the same outputs under another instance's escrow;
     a synthetic Groth16 proof (sample toxic waste) is refused by the pinned key
  C. Rust tools: issuance derivation in Python = rust-elements; a LOCAL TEST manifest (synthetic funding
     outpoint, stand-in update CMR, deployable = false); bootstrap refused without --local-test, built with it;
     another outpoint, a fee below the relay floor and a missing, empty or malformed change script refused;
     assemble.py's bootstrap gates re-derive the initial state, claim CMR and state script, and refuse another
     initial state, a claim CMR the source does not compile to and a stand-in leaf outside a local test;
     verify-bootstrap refuses the manifest under another instance file; an invalid token blinding factor refused
     at a gate; `recover` from a bootstrap alone gives its initial state, and refuses another start state or a
     transaction that does not spend the state
  D. claims in any order: synthetic deposits and a state that has paid deposit 2 only; `deposits` lists 0 and 1 as
     claimable; the claim of 0 is satisfied under simplicity-lang 0.8 and decodes and executes again under 0.9;
     `recover` reads the deposit from the claim's witness; a competing claim of 1 from the same output is refused
     once 0 is claimed, and the claim of 1 rebuilt from the successor pays every deposit; duplicates (a paid deposit,
     from the old or the successor state), replays (the same claim again, a stale record against its successor, a
     record hiding a paid deposit) and malformed claimed sets and roots are refused; a deposit past the proven
     count and a missing or malformed --deposit refused; `assemble.py claim --deposit` builds the same transaction
     and successor record and refuses the manifest under another instance file; a wrong deposit list, a
     non-deployable manifest, units the escrow cannot accept, entries that are not scripts, another Liquid genesis
     and an oversized fee input refused; deposit events past the proven block use the proven prefix; a record
     without the light-client store claims the same, one with a wrong lc does not
  E. --full (minutes): a synthetic-key update leaf through the real-transaction update builder after a real
     bootstrap transaction; 0.9 verify; `recover` reads the update's fields from its witness, and `assemble.py
     recover` completes them only with a hint that hashes to the new lc, and with the update's store withheld,
     from a rebuilt store after the published record; another program CMR refused; a tampered proof rejected by
     the leaf
  F. --real (minutes): under the artifact instance file, the REAL-key update leaf (pinned SP1 v6.1.0 key folded
     with that guest's vkey) for the synthetic funding outpoint; its bootstrap; and, with --proof-artifact, a
     real Sepolia Groth16 proof of that instance's first update (from its anchor) through every artifact gate
     (BN254 pairings) and `assemble.py update` into an update transaction spending that bootstrap output,
     re-verified under 0.9.  Only the funding outpoint is fictional, so the manifest stays non-deployable and
     nothing here can be broadcast.
  G. published records: each instances/<name>/initial_state.json is a record of the current claim leaf; each
     instances/<name>/manifest.json was built for its instance file
     and is refused under another; its claim leaf recompiles to the manifest's claim_leaf cmr and source_sha256; `recover` from its
     published bootstrap gives its initial state at the manifest's state address; its lc preimages parse and each
     names its store file (lc_stores/<head>.json) at its head and lc

Build first (README.md):
    cargo build --release --manifest-path tools/sg16-harness/Cargo.toml
    CARGO_TARGET_DIR=tools/sg16/bridge-guest/target/testnet-tx cargo build --release --manifest-path tools/sg16/bridge-guest/testnet/tx/Cargo.toml
    CARGO_TARGET_DIR=tools/sg16/bridge-guest/target/testnet-claim cargo build --release --manifest-path tools/sg16/bridge-guest/testnet/claim/Cargo.toml
    python3 tools/sg16/bridge-guest/testnet/test_testnet.py [--full] [--real] [--artifact-instance I.json]
                                                            [--exec-artifact E.json] [--proof-artifact P.json] [--evidence R.json]
"""
import argparse
import copy
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import assemble as A  # noqa: E402  (also puts bridge-guest and tools/sg16 on the path)
import pins  # noqa: E402
import liquid  # noqa: E402
from sg16 import sp1  # noqa: E402
from sg16.ref import ROOT  # noqa: E402
from groth import bn254 as B  # noqa: E402

WORK = ROOT / 'build' / 'sg16-testnet'
INSTANCES = ROOT / 'instances'
SEED = 7017
CHANGE_SPK = '0014' + '77' * 20
# The synthetic weak-subjectivity checkpoint of the local instance files: an epoch boundary.
ANCHOR_SLOT = 8192 * 1000


def h(label):
    return pins.sha(label.encode())


def synthetic_anchor():
    """An anchor whose lc recomputes, so that pins.check accepts it."""
    header, committee = h('local test anchor header'), h('local test anchor committee')
    return dict(slot=ANCHOR_SLOT, header=header.hex(), committee=committee.hex(),
                lc=pins.lc(ANCHOR_SLOT, header, committee).hex())


def local_instance_doc(label, anchor):
    """A new instance file as an operator writes one, for a fictional escrow."""
    escrow = h(f'{label} escrow')[:20].hex()
    return dict(name=f'LOCAL TEST: {label}, a fictional escrow, never deployed', ESCROW=escrow,
                ESCROW_CODE_HASH=h(f'{label} escrow code').hex(), ESCROW_DEPLOY_BLOCK=0,
                DEPOSIT_DOMAIN=pins.deposit_domain(pins.SEPOLIA_CHAIN_ID, escrow).hex(),
                GUEST_ELF_SHA256=h(f'{label} guest ELF').hex(),
                PROGRAM_VKEY='00' + h(f'{label} program vkey').hex()[2:], ANCHOR=anchor)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--full', action='store_true')
    ap.add_argument('--real', action='store_true')
    ap.add_argument('--artifact-instance', type=Path,
                    help='the instance file the given SP1 artifacts were made for (no default; --real needs it)')
    ap.add_argument('--exec-artifact', type=Path, help="an execute-only artifact of that instance's first update")
    ap.add_argument('--proof-artifact', type=Path, help='a proved artifact of the same inputs')
    ap.add_argument('--evidence', help='also write the JSON report here')
    a = ap.parse_args()
    if (a.real or a.exec_artifact or a.proof_artifact) and not a.artifact_instance:
        ap.error('--real, --exec-artifact and --proof-artifact need --artifact-instance (there is no default instance)')
    report, failures = {}, []

    def check(name, cond, detail=None):
        report[name] = dict(ok=bool(cond), detail=None if cond else str(detail)[:600])
        print(f'  {"ok " if cond else "BAD"} {name}' + ('' if cond or detail is None else f' ({str(detail)[:300]})'))
        if not cond:
            failures.append(name)
        return cond

    def expect_gate(name, fn, fragment):
        try:
            fn()
            ok, got = False, 'no gate failed'
        except A.Gate as e:
            ok, got = fragment in str(e), str(e)
        return check(name, ok, got)

    def run(path, *args):
        code, r = A.tool(path, *args)
        return code, r

    def cli(*args):
        return subprocess.run([sys.executable, str(HERE / 'assemble.py')] + [str(x) for x in args],
                              capture_output=True, text=True, timeout=600)

    WORK.mkdir(parents=True, exist_ok=True)
    config_recorded = pins.SEPOLIA_CONFIG is not None

    print('A. instances and pins')
    local_path = A.write_json(WORK / 'local-instance.json', local_instance_doc('local test', synthetic_anchor()))
    other_path = A.write_json(WORK / 'other-instance.json', local_instance_doc('other local test', synthetic_anchor()))
    local, other_inst = pins.load(local_path), pins.load(other_path)
    for inst in (local, other_inst):
        problems = pins.check(inst)
        check(f'{inst.name}: pins recompute (escrow DOMAIN, empty accumulator, anchor lc, SHA-256 compression)',
              not problems, problems)
    check('SEPOLIA_CONFIG is recorded (the config `sg16-bridge-host inputs` prints); the update leaf compiles it in',
          config_recorded)
    check('pins.py has no default instance', not any(hasattr(pins, k) for k in pins.INSTANCE_KEYS + ('INSTANCE',)))
    problems = pins.vectors()
    check('pins.py = vectors/protocol.json: tags, lc, claimed_root, state_hash, token blinding, escrow DOMAIN',
          not problems, problems)
    check('assemble.py manifest schema = vectors/protocol.json tags.manifest',
          A.SCHEMA == json.loads(pins.VECTORS.read_text())['tags']['manifest'])
    doc, bad_path = json.loads(local_path.read_text()), WORK / 'instance_bad.json'
    for name, bad, fragment in [
        ('an instance file without a name refused', {k: v for k, v in doc.items() if k != 'name'}, "missing ['name']"),
        ('an instance file without an anchor refused', {k: v for k, v in doc.items() if k != 'ANCHOR'},
         "missing ['ANCHOR']"),
        ('an instance file with an unknown pin refused', dict(doc, BRIDGE_ASSET=doc['ESCROW']),
         "unknown ['BRIDGE_ASSET']"),
        ("an instance file whose DOMAIN is another escrow's refused",
         dict(doc, DEPOSIT_DOMAIN=other_inst.deposit_domain),
         "'escrow DOMAIN recomputation'"),
        ('an instance file whose anchor lc does not recompute refused',
         dict(doc, ANCHOR=dict(doc['ANCHOR'], slot=doc['ANCHOR']['slot'] + 32)),
         "'anchor lc'"),
    ]:
        expect_gate(name, lambda bad=bad: A.instance(A.Gates(), A.write_json(bad_path, bad)), fragment)
    expect_gate('a missing instance file refused',
                lambda: A.instance(A.Gates(), WORK / 'no-such-instance.json'), 'No such file')
    r = cli('manifest', '--dry-run', '--out', WORK / 'no-instance')
    check('assemble.py manifest without --instance refused before any work (no default instance)',
          r.returncode == 2 and '--instance' in r.stderr and not (WORK / 'no-instance').exists(), r.stderr[-300:])
    r = cli('pins', '--instance', local_path)
    res = json.loads(r.stdout).get('result', {}) if r.returncode == 0 else {}
    check('assemble.py pins --instance <local instance file>: recomputes; the escrow comes from the file',
          res.get('instance') == local.name and res.get('escrow') == local.escrow, r.stdout[-300:] + r.stderr[-300:])
    for name, hint_doc in [('a hint entry without a committee refused',
                            dict(preimages=[dict(head=1, header='00' * 32)])),
                           ('a hint entry with a short header refused',
                            dict(head=1, header='00' * 31, committee='00' * 32))]:
        expect_gate(name, lambda hint_doc=hint_doc: A.lc_preimages(A.write_json(WORK / 'hint_bad.json', hint_doc)),
                    'each entry gives')
    # A published store file (sg16-bridge-host store/run) lets the next proof start from tracked data (inputs
    # --store) instead of a beacon bootstrap at the head.
    head, header, committee = ANCHOR_SLOT + 64, h('store header'), h('store committee')
    lc_hex = pins.lc(head, header, committee).hex()
    store_doc = dict(head=head, header='0x' + header.hex(), committee='0x' + committee.hex(), lc='0x' + lc_hex,
                     store_cbor='0x00')
    sdir = WORK / 'store-hints'
    store_path = A.write_json(sdir / 'lc_stores' / f'{head}.json', store_doc)
    entry = dict(head=head, header=header.hex(), committee=committee.hex(), store=f'lc_stores/{head}.json')
    hint_path = A.write_json(sdir / 'lc_preimages.json', dict(preimages=[entry]))
    check('a store file is itself a hint: its head and roots parse',
          A.lc_preimages(store_path) == [(head, header, committee)])
    check('lc_store: the entry at the head names its store file',
          A.lc_store(A.Gates(), hint_path, head, lc_hex) == str(store_path))
    check('lc_store: a store file given directly is used as it is',
          A.lc_store(A.Gates(), store_path, head, lc_hex) == str(store_path))
    check('lc_store: no store file named at another head', A.lc_store(A.Gates(), hint_path, head + 32, lc_hex) is None)
    expect_gate('lc_store: a store file of another lc refused',
                lambda: A.lc_store(A.Gates(), hint_path, head, h('another lc').hex()),
                'hashes to the recovered lc')
    A.write_json(sdir / 'other.json', dict(store_doc, committee='0x' + h('another committee').hex()))
    expect_gate("lc_store: a store file whose committee is not the lc's refused",
                lambda: A.lc_store(A.Gates(),
                                   A.write_json(sdir / 'other_hint.json',
                                                dict(preimages=[dict(entry, store='other.json')])),
                                   head, lc_hex),
                'hashes to the recovered lc')
    expect_gate('lc_store: a missing store file refused',
                lambda: A.lc_store(A.Gates(),
                                   A.write_json(sdir / 'missing_hint.json',
                                                dict(preimages=[dict(entry, store='none.json')])),
                                   head, lc_hex),
                'names a published light-client store file')
    A.write_json(sdir / 'no_cbor.json', {k: v for k, v in store_doc.items() if k != 'store_cbor'})
    expect_gate('lc_store: a store file without its CBOR refused',
                lambda: A.lc_store(A.Gates(),
                                   A.write_json(sdir / 'no_cbor_hint.json',
                                                dict(preimages=[dict(entry, store='no_cbor.json')])),
                                   head, lc_hex),
                'head, header, committee, lc and store_cbor')
    withheld_store(sdir, store_doc, store_path, hint_path, head, header, committee, lc_hex, check, expect_gate)
    check('asset entropy depends on the outpoint', pins.asset_entropy(bytes(32), 0) != pins.asset_entropy(bytes(32), 1))
    e0 = pins.asset_entropy(h('outpoint'), 0)
    check('asset, token and confidential-issuance token ids differ',
          len({pins.asset_id(e0), pins.token_id(e0), pins.token_id(e0, True)}) == 3)
    art_inst = None
    if a.artifact_instance:
        try:
            art_inst = A.instance(A.Gates(), a.artifact_instance)
        except A.Gate as e:
            check(f'--artifact-instance {a.artifact_instance}: the instance file loads and its pins recompute',
                  False, e)
    art = json.loads(a.exec_artifact.read_text()) if a.exec_artifact and art_inst else None
    if art:
        o = A.decode_public_values(bytes.fromhex(art['publicValues'][2:]))
        check('real Sepolia execute-only public values decode', o is not None)
        check('their config = pinned Sepolia config', o['config'].hex() == pins.SEPOLIA_CONFIG)
        check("their escrow and slot = the instance's escrow, slot 0",
              o['escrow'].hex() == art_inst.escrow and o['slot_key'] == 0)
        check("their prev_lc = the instance's anchor lc", o['prev_lc'].hex() == art_inst.anchor['lc'])
        check("their program vkey = the instance's guest vkey", art['vkey'][2:] == art_inst.program_vkey)
        succ = art['successor']
        check('their new_lc = lc(successor slot, header, committee)',
              o['new_lc'] == pins.lc(succ['slot'], A.b32(succ['header']), A.b32(succ['committee']))
              and succ['slot'] == o['new_head'])
    else:
        print('  (no --exec-artifact: real-artifact checks skipped)')
    proof_art = json.loads(a.proof_artifact.read_text()) if a.proof_artifact and art_inst else None
    if proof_art and art:
        check('the proved artifact commits the same public values as the execute-only run of the same inputs',
              proof_art['publicValues'] == art['publicValues'] and proof_art['vkey'] == art['vkey'])
    if proof_art:
        try:
            A.check_artifact(A.Gates(), proof_art, A.sp1_keys(A.Gates(), art_inst), art_inst, A.initial_state(art_inst),
                             pairing=False)
            passed = True
        except A.Gate as e:
            passed = e
        check("the real Sepolia proof artifact passes every identity gate against the instance's initial state "
              "(pairings in F)",
              passed is True, passed)

    key_inst = art_inst or local
    print(f'B. artifact gates ({key_inst.name})')
    keys = A.sp1_keys(A.Gates(), key_inst)
    check('pinned SP1 key: VERIFIER_HASH, VK_ROOT and key coordinates match the vendored v6.1.0 source', True)
    check('folded key has one public input', len(keys['vk1']['ic']) == 2)
    s0 = A.initial_state(key_inst)
    if art and not config_recorded:
        print('  (SEPOLIA_CONFIG not recorded: gate matrix skipped)')
    elif art:
        expect_gate('execute-only artifact refused',
                    lambda: A.check_artifact(A.Gates(), art, keys, art_inst, s0), 'not execute-only')
        proof_hex = '0x' + (keys['selector'] + bytes(32 * 11)).hex()

        def fake(**over):
            x = copy.deepcopy(art)
            x['proof'] = proof_hex
            x.update(over)
            return x
        ok_header = dict(exit_code=0, vk_root=keys['vk_root'], proof_nonce=0)
        real_decode = sp1.decode_proof

        def stub(header, proof=None):
            return lambda pb, layout: (pb[:4], dict(header), proof)
        try:
            # decode_proof is stubbed so that the gates after it are reachable without a valid proof
            sp1.decode_proof = stub(ok_header)
            for name, x, fragment in [
                ('artifact of another guest refused', fake(guest='light_client'), 'guest'),
                ('non-Sepolia artifact refused', fake(network='not-sepolia: 0x00'), 'network'),
                ('another program vkey refused', fake(vkey='0x' + '00' * 31 + '01'), 'program vkey'),
                ('wrong Groth16 selector refused', fake(proof='0x' + (bytes(4) + bytes(32 * 11)).hex()), 'selector'),
                ('truncated proof refused', fake(proof='0x' + (keys['selector'] + bytes(32 * 10)).hex()),
                 'proof bytes'),
            ]:
                expect_gate(name, lambda x=x: A.check_artifact(A.Gates(), x, keys, art_inst, s0, pairing=False),
                            fragment)
            for name, hdr, fragment in [('nonzero exit code refused', dict(ok_header, exit_code=1), 'exit code'),
                                        ('another VK root refused', dict(ok_header, vk_root=1), 'vkRoot'),
                                        ('nonzero proof nonce refused', dict(ok_header, proof_nonce=5), 'nonce')]:
                sp1.decode_proof = stub(hdr)
                expect_gate(name, lambda: A.check_artifact(A.Gates(), fake(), keys, art_inst, s0, pairing=False),
                            fragment)
            sp1.decode_proof = stub(ok_header)
            pv = bytes.fromhex(art['publicValues'][2:])

            def with_pv(off, new):
                return fake(publicValues='0x' + (pv[:off] + new + pv[off + len(new):]).hex())
            for name, x, fragment in [
                ('proof for another network config refused', with_pv(32, bytes(32)), 'config'),
                ('proof for another escrow refused', with_pv(76, bytes.fromhex('11' * 20)), 'escrow'),
                ('proof for another storage slot refused', with_pv(96, (1).to_bytes(32, 'big')), 'slot key'),
                ('public values with a forged accumulator refused', with_pv(192, h('forged accumulator')), 'outputs'),
                ('public values with another tag refused', with_pv(0, bytes(32)), 'update tag'),
            ]:
                expect_gate(name, lambda x=x: A.check_artifact(A.Gates(), x, keys, art_inst, s0, pairing=False),
                            fragment)
            expect_gate("the instance's outputs refused under another instance's escrow",
                        lambda: A.check_artifact(A.Gates(), fake(), keys, local, s0, pairing=False), 'instance escrow')
            other = dict(s0, header=h('another anchor header').hex())
            expect_gate('proof from another starting state refused',
                        lambda: A.check_artifact(A.Gates(), fake(), keys, art_inst, other, pairing=False),
                        'prev_lc')
            expect_gate('artifact whose public_input disagrees refused',
                        lambda: A.check_artifact(A.Gates(), fake(public_input='0x01'), keys, art_inst, s0,
                                                 pairing=False),
                        'public_input')
            try:
                A.check_artifact(A.Gates(), fake(), keys, art_inst, s0, pairing=False)
                passed = True
            except A.Gate as e:
                passed = e
            check('the real Sepolia outputs pass every identity gate (proof bytes stubbed, no pairing): '
                  'only the proof is missing',
                  passed is True, passed)
            _, proof_s, _ = B.groth16_instance(5, seed=SEED)
            sp1.decode_proof = stub(ok_header, proof_s)
            expect_gate('a synthetic Groth16 proof (sample toxic waste) is refused by the pinned SP1 v6.1.0 key',
                        lambda: A.check_artifact(A.Gates(), fake(), keys, art_inst, s0, pairing=True),
                        'five-input SP1 key')
        finally:
            sp1.decode_proof = real_decode
    else:
        print('  (no real artifact: gate matrix skipped)')

    print('C. Rust transaction tool')
    m = None
    if not A.TX_TOOL.exists():
        print(f'  ({A.TX_TOOL} missing: C, D, E skipped)')
    else:
        for i, (txid, vout) in enumerate([(h('outpoint a').hex(), 0), (h('outpoint b').hex(), 7)]):
            e = pins.asset_entropy(pins.internal(txid), vout)
            code, r = run(A.TX_TOOL, 'params', txid, vout, '00' * 32, e.hex())
            check(f'issuance derivation {i}: Python = rust-elements (asset, token, outpoint entropy)',
                  code == 0 and r['outpoint_token_matches'] is True
                  and r['asset'] == pins.asset_id(e).hex() and r['token'] == pins.token_id(e).hex(), r)
        code, r = run(A.TX_TOOL, 'params', txid, vout + 1, '00' * 32, e.hex())
        check('another vout does not create the same token', code == 0 and r['outpoint_token_matches'] is False, r)
        fund = WORK / 'funding.hex'
        code, rf = run(A.TX_TOOL, 'synthetic-funding', 50_000, fund)
        check('synthetic funding written', code == 0, rf)
        if not A.CLAIM_TOOL.exists():
            print(f'  ({A.CLAIM_TOOL} missing: manifest, bootstrap, D, E skipped)')
        else:
            mdir = WORK / 'local'
            g = A.Gates()
            try:
                m = A.build_manifest(g, local, mdir, rf['txid'], 0, False,
                                     'LOCAL TEST: synthetic funding outpoint, stand-in update CMR',
                                     update_leaf=dict(cmr=A.STAND_IN_UPDATE_CMR, stand_in=True))
                check('local manifest of a new instance: every gate passed; not deployable',
                      m['deployable'] is False, m.get('label'))
            except A.Gate as e:
                check('local manifest gates', False, e)
            report['manifest_gates'] = g.results
    if m:
        mpath, s0path = mdir / 'manifest.json', mdir / 'initial_state.json'
        boot = WORK / 'bootstrap.hex'
        code, r = run(A.TX_TOOL, 'bootstrap', mpath, s0path, fund, 0, 1000, CHANGE_SPK, boot)
        check('bootstrap refused for a non-deployable manifest without --local-test',
              code == 3 and 'deployable' in r.get('failed_gate', ''), r)
        code, rb = run(A.TX_TOOL, 'bootstrap', mpath, s0path, fund, 0, 1000, CHANGE_SPK, boot, '--local-test')
        check('bootstrap (local test): issuance authority, amount proofs, token constants, state script',
              code == 0 and rb['local_test_only'] is True
              and rb['state_script_pubkey'] == m['state_tree']['script_pubkey'], rb)
        report['bootstrap'] = rb
        fund2 = WORK / 'funding2.hex'
        run(A.TX_TOOL, 'synthetic-funding', 60_000, fund2)
        for name, args, fragment in [
            ('bootstrap from another outpoint refused (it would issue another token)', (fund2, 0, 1000, CHANGE_SPK),
             'funding outpoint'),
            ('bootstrap below the 0.1 sat/vB relay floor refused', (fund, 0, 1, CHANGE_SPK), 'fee covers'),
            ('bootstrap without a change script refused', (fund, 0, 1000, '-'), 'change'),
            ('bootstrap with an empty change script refused (an explicit empty-script output is a fee)',
             (fund, 0, 1000, ''),
             'change script is not empty'),
            ('bootstrap with malformed change-script hex refused at a gate, not a panic', (fund, 0, 1000, '0014zz'),
             'change script'),
        ]:
            code, r = run(A.TX_TOOL, 'bootstrap', mpath, s0path, *args, WORK / 'bootstrap_bad.hex', '--local-test')
            check(name, code == 3 and fragment in r.get('failed_gate', ''), r)

        # assemble.py bootstrap re-derives what the bootstrap commits forever instead of trusting the manifest.
        try:
            A.bootstrap_gates(A.Gates(), local, m, mpath, s0path, True)
            passed = True
        except A.Gate as e:
            passed = e
        check('bootstrap gates: manifest instance, initial state = instance anchor, claim CMR recompiled, '
              'state script rebuilt (local test)',
              passed is True, passed)
        bad_s0 = A.write_json(WORK / 'initial_state_bad.json', dict(json.loads(s0path.read_text()), header='00' * 32))
        expect_gate('bootstrap gates refuse an initial state other than the pinned anchor',
                    lambda: A.bootstrap_gates(A.Gates(), local, m, mpath, bad_s0, True), 'pinned anchor')
        bad_m = copy.deepcopy(m)
        bad_m['claim_leaf']['cmr'] = '00' * 32
        bad_mp = A.write_json(WORK / 'manifest_bad_claim.json', bad_m)
        expect_gate('bootstrap gates refuse a claim CMR the claim source does not compile to',
                    lambda: A.bootstrap_gates(A.Gates(), local, bad_m, bad_mp, s0path, True), 'claim leaf CMR')
        expect_gate('bootstrap gates refuse a stand-in update CMR outside a local test',
                    lambda: A.bootstrap_gates(A.Gates(), local, m, mpath, s0path, False), 'stand-in')
        # The public-bootstrap check anyone can run before depositing (assemble.py verify-bootstrap).
        code, r = run(A.TX_TOOL, 'check-bootstrap', mpath, s0path, boot)
        check('check-bootstrap: the funding outpoint issued one token and no asset into the manifest state UTXO',
              code == 0 and r['state_address'] == m['state_tree']['address']
              and r['bridge_asset_internal'] == m['bootstrap']['asset'], r)
        code, r = run(A.TX_TOOL, 'check-bootstrap', mpath, bad_s0, boot)
        check('check-bootstrap refuses a bootstrap whose output 0 is not the given initial state',
              code == 3 and 'output 0' in r.get('failed_gate', ''), r)
        code, r = run(A.TX_TOOL, 'check-bootstrap', mpath, s0path, fund)
        check('check-bootstrap refuses a transaction that does not spend the funding outpoint',
              code == 3 and 'funding outpoint' in r.get('failed_gate', ''), r)
        # recover: the state a chain of public spends leads to; D and E walk a claim and an update.
        code, r = run(A.TX_TOOL, 'recover', mpath, s0path, boot)
        check('recover from the bootstrap alone: the initial state with its store, at bootstrap output 0',
              code == 0 and r['state']['state_hash'] == m['initial_state']['state_hash'] and r['store_known'] is True
              and r['outpoint'] == rb['state_outpoint'] and r['address'] == m['state_tree']['address'], r)
        code, r = run(A.TX_TOOL, 'recover', mpath, bad_s0, boot)
        check('recover refuses a start state that output 0 does not hold',
              code == 3 and 'given state' in r.get('failed_gate', ''), r)
        code, r = run(A.TX_TOOL, 'recover', mpath, s0path, boot, fund)
        check('recover refuses a transaction that does not spend the state output',
              code == 3 and 'input 0 spends the previous state' in r.get('failed_gate', ''), r)

        def vb(asset, inst=local_path):
            return A.cmd_verify_bootstrap(argparse.Namespace(instance=str(inst), manifest=str(mpath),
                                                             bootstrap_tx=str(boot), escrow_asset=asset,
                                                             local_test=True), A.Gates())
        try:
            vb('0x' + m['bootstrap']['asset'])
            passed = True
        except A.Gate as e:
            passed = e
        check('verify-bootstrap: instance pins recomputed, leaves re-derived, bootstrap checked, escrow asset matches',
              passed is True, passed)
        expect_gate('verify-bootstrap refuses an escrow pinning another asset',
                    lambda: vb('0x' + '00' * 32), 'BRIDGE_ASSET')
        expect_gate('verify-bootstrap refuses the manifest under another instance file',
                    lambda: vb(None, other_path), 'manifest = the given instance')
        bad_m = copy.deepcopy(m)
        bad_m['harness_config']['abf_a'] = 'ff' * 32
        bad_mp = A.write_json(WORK / 'manifest_bad_abf.json', bad_m)
        code, r = run(A.TX_TOOL, 'tree', bad_mp, s0path)
        check('a manifest with an invalid token blinding scalar refused at a gate, not a panic',
              code == 3 and 'harness_config' in r.get('failed_gate', ''), r)

        print('D. claims in any order (script recipients, fee in L-BTC)')
        domain = bytes.fromhex(local.deposit_domain)
        # BridgeDeposits events: the scriptPubKey of an ordinary segwit wallet, a wrapped-segwit wallet and a
        # Taproot key; each deposit commits the script's SHA-256.
        scripts = [bytes.fromhex('0014' + '33' * 20), bytes.fromhex('a914' + '44' * 20 + '87'),
                   bytes.fromhex('5120' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')]
        deposits = [(100_000, scripts[0]), (250_000, scripts[1]), (2_000_000, scripts[2])]

        def events(path, ds):
            return A.write_json(WORK / path, [[u, s.hex()] for u, s in ds])
        acc3 = pins.accumulator(pins.tree_root(domain, [(u, pins.sha(s)) for u, s in deposits]), 3)
        an = local.anchor

        def record(path, claimed, **over):
            rec = A.state_record(an['slot'], A.b32(an['header']), A.b32(an['committee']), acc3, claimed)
            return A.write_json(WORK / path, dict(rec, **over))
        # Deposit 2 is already paid and 0 and 1 are not: claims need not follow deposit order.
        s1p = record('state1.json', [2])
        dp = events('deposits.json', deposits)
        sp, fp = WORK / 'state1_prev.hex', WORK / 'fee_prev.hex'
        code, r = run(A.CLAIM_TOOL, 'synthetic-prevs', mpath, s1p, 1, 20_000, sp, fp)
        check('synthetic state and fee outputs written', code == 0, r)

        def claim(state, deposit, out, *extra, deps=dp, state_tx=sp, fee_tx=fp):
            return run(A.CLAIM_TOOL, 'claim', mpath, state, deps, state_tx, 0, fee_tx, 0, WORK / out,
                       '--deposit', deposit, *extra)

        code, r = run(A.CLAIM_TOOL, 'deposits', mpath, s1p, dp)
        check('deposits: 3 proven, deposit 2 claimed, 0 and 1 claimable',
              code == 0 and r['proven'] == 3 and r['claimed'] == [2] and r['unclaimed'] == [0, 1]
              and [d['claimed'] for d in r['deposits']] == [False, False, True] and r['complete'] is False, r)
        out = WORK / 'claim.hex'
        code, rc = claim(s1p, 0, 'claim.hex', '--local-test')
        check('claim of deposit 0 after deposit 2 (local test): accumulator opened, slot 0 set, leaf satisfied and '
              'executed, amount proofs, pays its committed P2WPKH script',
              code == 0 and rc['deposit']['index'] == 0 and rc['deposit']['units'] == 100_000
              and rc['claimed'] == [0, 2] and rc['unclaimed'] == [1]
              and rc['claimed_root'] == pins.claimed_root([2, 0]).hex()
              and rc['deposit']['script_pubkey'] == scripts[0].hex()
              and rc['successor_state']['claimed'] == [0, 2]
              and rc['successor_state']['state_hash'] == rc['successor_state_hash'], rc)
        report['claim'] = rc
        code, rv = run(A.TX_TOOL, 'verify', out, 0, sp, fp)
        check('claim input decodes and executes under simplicity-lang 0.9 with valid amount proofs',
              code == 0 and rv['internal_key_is_nums'] is True and rv['cost_mwu'] <= rv['budget_mwu'], rv)
        report['claim_verify_0_9'] = rv
        code, r = run(A.TX_TOOL, 'recover', mpath, s1p, sp, out)
        check('recover over a claim: the deposit read from its witness, its slot set, store and accumulator carried, '
              '= the claim successor',
              code == 0 and r['state']['claimed'] == [0, 2] and r['state']['claimed_root'] == rc['claimed_root']
              and r['state']['state_hash'] == rc['successor_state_hash'] and r['chain'][1].get('deposit') == 0
              and r['store_known'] is True and [c['kind'] for c in r['chain']] == ['start', 'claim'], r)
        code, r = run(A.TX_TOOL, 'recover', mpath, s1p, sp, out, out)
        check('replay: recover refuses the same claim again, a spend of an output that is no longer the state',
              code == 3 and 'spend 2' in r.get('failed_gate', ''), r)

        # A competing claim: deposit 1 from the same state output.  Both are valid alone; one spends the output, and
        # the other then spends nothing that exists and must be rebuilt from the successor.
        code, rk = claim(s1p, 1, 'claim_competing.hex', '--local-test')
        check('a competing claim of deposit 1 from the same state output is built', code == 0
              and rk['claimed'] == [1, 2] and rk['txid'] != rc['txid'], rk)
        code, r = run(A.TX_TOOL, 'recover', mpath, s1p, sp, out, WORK / 'claim_competing.hex')
        check('competing claims: once deposit 0 is claimed, the claim of deposit 1 from the old output is refused',
              code == 3 and 'spend 2' in r.get('failed_gate', '') and 'input 0 spends' in r.get('failed_gate', ''), r)
        s2p = A.write_json(WORK / 'state2.json', rc['successor_state'])
        code, r = claim(s2p, 1, 'claim2.hex', '--local-test', state_tx=out)
        check('claim of deposit 1 from the successor of the claim of 0: every proven deposit paid',
              code == 0 and r['claimed'] == [0, 1, 2] and r['unclaimed'] == []
              and r['claimed_root'] == pins.claimed_root([0, 1, 2]).hex(), r)
        code, rv = run(A.TX_TOOL, 'verify', WORK / 'claim2.hex', 0, out, fp)
        check('the second claim decodes and executes under simplicity-lang 0.9', code == 0, rv)
        code, r = run(A.TX_TOOL, 'recover', mpath, s1p, sp, out, WORK / 'claim2.hex')
        check('recover over claims of 0 then 1 after 2: claimed {0, 1, 2}, each deposit named',
              code == 0 and r['state']['claimed'] == [0, 1, 2]
              and [c.get('deposit') for c in r['chain']] == [None, 0, 1], r)
        code, r = run(A.CLAIM_TOOL, 'deposits', mpath, A.write_json(WORK / 'state3.json', r['state']), dp)
        check('deposits: nothing left to claim, claimed_root = the complete root of 3',
              code == 0 and r['unclaimed'] == [] and r['complete'] is True, r)

        # Duplicates: a paid deposit is refused at a gate before anything is built.  (The leaf's own refusal, with the
        # gate bypassed, is the claim tool's Rust test.)
        for name, state, deposit, state_tx in [
                ('a duplicate claim of deposit 2, paid before the state', s1p, 2, sp),
                ('a duplicate claim of deposit 0 from the successor of its claim', s2p, 0, out)]:
            code, r = claim(state, deposit, 'claim_bad.hex', '--local-test', state_tx=state_tx)
            check(f'{name} refused', code == 3 and f'deposit {deposit} is unclaimed' in r.get('failed_gate', ''), r)
        # Replay against the successor: a stale record (deposit 0 not yet paid) cannot spend the output that paid it.
        code, r = claim(s1p, 0, 'claim_bad.hex', '--local-test', state_tx=out)
        check('replay: the claim of deposit 0 from a stale record against its successor output refused',
              code == 3 and 'spent output' in r.get('failed_gate', ''), r)
        # A record that hides a paid deposit, with the root it then has, opens another state, not this output.
        code, r = claim(record('state1_hidden.json', []), 2, 'claim_bad.hex', '--local-test')
        check('a record without its paid deposit 2 cannot claim it again (its root is not the spent output\'s)',
              code == 3 and 'spent output' in r.get('failed_gate', ''), r)

        # Malformed claimed sets and roots are refused, never read as another set.
        root2 = pins.claimed_root([2]).hex()
        for name, over, fragment in [
            ('a non-list claimed field', dict(claimed=1), 'a list of deposit indices'),
            ('a claimed_root of another set', dict(claimed_root=pins.claimed_root([1]).hex()), 'claimed_root'),
            ('a claimed_root of no set', dict(claimed_root=h('not a claimed root').hex()), 'claimed_root'),
            ('no claimed_root', dict(claimed_root=None), 'claimed_root missing'),
            ('a short claimed_root', dict(claimed_root=root2[:62]), 'not 32 bytes'),
            ('claimed indices out of order', dict(claimed=[2, 0], claimed_root=pins.claimed_root([0, 2]).hex()),
             'strictly ascending'),
            ('a repeated claimed index', dict(claimed=[2, 2]), 'strictly ascending'),
            ('a claimed index outside the tree', dict(claimed=[1 << 32]), 'outside the claimed tree'),
        ]:
            bad = dict(json.loads(s1p.read_text()), **over)
            bad = {k: v for k, v in bad.items() if v is not None}
            code, r = claim(A.write_json(WORK / 'state_bad_claimed.json', bad), 0, 'claim_bad.hex', '--local-test')
            check(f'{name} refused by the claim tool', code == 3 and fragment in r.get('failed_gate', ''), r)
            code, r = run(A.TX_TOOL, 'recover', mpath, WORK / 'state_bad_claimed.json', sp)
            check(f'{name} refused by recover', code == 3 and 'claimed' in r.get('failed_gate', ''), r)
        code, r = claim(record('state1_unproven.json', [2, 5]), 0, 'claim_bad.hex', '--local-test')
        check('a record claiming a deposit the accumulator does not prove refused',
              code == 3 and 'every claimed index' in r.get('failed_gate', ''), r)
        code, r = claim(s1p, 3, 'claim_bad.hex', '--local-test')
        check('claim of a deposit past the proven count refused',
              code == 3 and 'deposit 3 is proven' in r.get('failed_gate', ''), r)

        def bare(*flags):
            return subprocess.run([str(x) for x in (A.CLAIM_TOOL, 'claim', mpath, s1p, dp, sp, 0, fp, 0,
                                                    WORK / 'claim_bad.hex', *flags, '--local-test')],
                                  capture_output=True, text=True)
        r = bare()
        check('claim without --deposit refused: there is no default deposit',
              r.returncode == 2 and '--deposit' in r.stderr and not r.stdout, r.stderr)
        r = bare('--deposit', '0x1')
        check('claim with a malformed --deposit refused', r.returncode == 2 and 'not a decimal' in r.stderr, r.stderr)

        s1 = json.loads(s1p.read_text())
        lc_only = A.write_json(WORK / 'state1_lc_only.json',
                               {k: v for k, v in s1.items() if k not in ('head', 'header', 'committee')})
        code, r = claim(lc_only, 0, 'claim_lc_only.hex', '--local-test')
        check('claim from a record without the light-client store (as recover gives after an update): '
              'the same transaction, and an lc-only successor record',
              code == 0 and r['txid'] == rc['txid'] and 'header' not in r['successor_state']
              and r['successor_state']['state_hash'] == rc['successor_state_hash'], r)
        for name, bad_doc, fragment in [
            ("an lc-only record whose lc is not the spent state's refused",
             dict(json.loads(lc_only.read_text()), lc=h('another lc').hex()),
             'spent output'),
            ('a record whose lc is not lc(head, header, committee) refused',
             dict(s1, lc=h('another lc').hex()),
             'lc(head, header, committee)'),
        ]:
            code, r = claim(A.write_json(WORK / 'state1_bad_lc.json', bad_doc), 0, 'claim_bad.hex', '--local-test')
            check(name, code == 3 and fragment in r.get('failed_gate', ''), r)

        def claim_ns(inst, out, deposit=0, state=s1p):
            return argparse.Namespace(instance=str(inst), manifest=str(mpath), state=str(state), deposits=str(dp),
                                      state_tx=str(sp), state_vout=0, fee_tx=str(fp), fee_vout=0,
                                      out=str(out), local_test=True, deposit=deposit)
        try:
            rcli = A.cmd_claim(claim_ns(local_path, WORK / 'claim_cli.hex'), A.Gates())
            passed = (rcli['txid'] == rc['txid']
                      and json.loads(Path(rcli['new_state']).read_text()) == rc['successor_state']) or rcli
        except A.Gate as e:
            passed = e
        check('assemble.py claim --deposit 0 under its instance file: the same claim transaction, re-verified under '
              '0.9, and the successor record written',
              passed is True, passed)
        for name, ns, fragment in [
            ('assemble.py claim refuses the manifest under another instance file',
             claim_ns(other_path, WORK / 'claim_bad.hex'), 'manifest = the given instance'),
            ('assemble.py claim refuses a paid deposit', claim_ns(local_path, WORK / 'claim_bad.hex', 2),
             'deposit 2 is unclaimed'),
            ('assemble.py claim refuses a deposit past the proven count',
             claim_ns(local_path, WORK / 'claim_bad.hex', 3), 'deposit 3 is proven'),
            ('assemble.py claim refuses a non-list claimed field',
             claim_ns(local_path, WORK / 'claim_bad.hex',
                      state=A.write_json(WORK / 'state_seq.json', dict(s1, claimed=1))), 'strictly ascending'),
            ('assemble.py claim refuses a record whose root is not its set',
             claim_ns(local_path, WORK / 'claim_bad.hex',
                      state=A.write_json(WORK / 'state_root.json', dict(s1, claimed=[]))), 'claimed_root'),
        ]:
            expect_gate(name, lambda ns=ns: A.cmd_claim(ns, A.Gates()), fragment)
        try:
            rd = A.cmd_deposits(argparse.Namespace(instance=str(local_path), manifest=str(mpath), state=str(s1p),
                                                   deposits=str(dp)), A.Gates())
            passed = rd['unclaimed'] == [0, 1] or rd
        except A.Gate as e:
            passed = e
        check('assemble.py deposits: Python and the claim tool agree; 0 and 1 claimable', passed is True, passed)
        result = cli('claim', '--instance', local_path, '--manifest', mpath, '--state', s1p, '--deposits', dp,
                     '--state-tx', sp, '--fee-tx', fp, '--fee-vout', 0, '--out', WORK / 'claim_bad.hex', '--local-test')
        check('assemble.py claim without --deposit refused before any work (no default deposit)',
              result.returncode == 2 and '--deposit' in result.stderr, result.stderr[-300:])

        bad = events('deposits_bad.json', [(u + (1 if i == 1 else 0), s) for i, (u, s) in enumerate(deposits)])
        code, r = claim(s1p, 0, 'claim_bad.hex', '--local-test', deps=bad)
        check('claim with a deposit list that does not reproduce the accumulator refused',
              code == 3 and 'accumulator' in r.get('failed_gate', ''), r)
        code, r = claim(s1p, 0, 'claim_bad.hex')
        check('claim refused for a non-deployable manifest without --local-test',
              code == 3 and 'deployable' in r.get('failed_gate', ''), r)
        # A live escrow keeps taking deposits after the block the state proved.
        later = events('deposits_later.json', deposits + [(300_000, bytes.fromhex('0014' + '55' * 20))])
        code, r = claim(s1p, 0, 'claim_later.hex', '--local-test', deps=later)
        check('claim with deposit events past the proven block uses the proven prefix',
              code == 0 and r['deposit']['index'] == 0 and r['deposit']['units'] == 100_000
              and r['txid'] == rc['txid'], r)
        code, r = claim(s1p, 3, 'claim_bad.hex', '--local-test', deps=later)
        check('a listed deposit past the proven block cannot be claimed',
              code == 3 and 'deposit 3 is proven' in r.get('failed_gate', ''), r)
        small = events('deposits_small.json', [(99_999 if i == 2 else u, s) for i, (u, s) in enumerate(deposits)])
        code, r = claim(s1p, 0, 'claim_bad.hex', '--local-test', deps=small)
        check('a deposit list with units the escrow cannot accept refused',
              code == 3 and 'bounds' in r.get('failed_gate', ''), r)
        keyed = A.write_json(WORK / 'deposits_keys.json', [[u, pins.sha(s).hex()] for u, s in deposits])
        code, r = claim(s1p, 0, 'claim_bad.hex', '--local-test', deps=keyed)
        check('claim refuses deposit entries that are not recipient scripts',
              code == 3 and 'recipients' in r.get('failed_gate', ''), r)
        sp_big, fp_big = WORK / 'state1_prev_big.hex', WORK / 'fee_prev_big.hex'
        run(A.CLAIM_TOOL, 'synthetic-prevs', mpath, s1p, 1, 60_000, sp_big, fp_big)
        code, r = claim(s1p, 0, 'claim_bad.hex', '--local-test', state_tx=sp_big, fee_tx=fp_big)
        check('claim refused for a fee input far above the relay floor (the leaf spends it whole as fee)',
              code == 3 and '100x' in r.get('failed_gate', ''), r)
        other = copy.deepcopy(m)
        other['harness_config']['genesis'] = '11' * 32
        op = A.write_json(WORK / 'manifest_other_genesis.json', other)
        code, r = run(A.CLAIM_TOOL, 'claim', op, s1p, dp, sp, 0, fp, 0, WORK / 'claim_bad.hex', '--deposit', 0,
                      '--local-test')
        check('claim refused for a manifest of another Liquid network',
              code == 3 and 'genesis' in r.get('failed_gate', ''), r)

    if a.full and m:
        print('E. synthetic-key update through the real-transaction builder (minutes)')
        if not config_recorded:
            print('  (SEPOLIA_CONFIG not recorded: E skipped)')
        else:
            try:
                synthetic_update(m, mdir, local, fund, boot, check, run, report)
            except A.Gate as e:
                check('synthetic-key update gates', False, e)

    if a.real and m and art_inst:
        print(f'F. {art_inst.name}: real-key update leaf, its bootstrap and a real Sepolia proof (minutes)')
        if not config_recorded:
            print('  (SEPOLIA_CONFIG not recorded: F skipped)')
        else:
            try:
                real_update(art_inst, proof_art, a.proof_artifact, rf, fund, check, run, report)
            except A.Gate as e:
                check('real-key path gates', False, e)

    print('G. published records under instances/')
    records = sorted(p.parent for p in INSTANCES.glob('*/manifest.json'))
    if not records:
        print('  (no instances/<name>/manifest.json: nothing is published yet, G skipped)')
    for record in records:
        published_record(record, other_path, check, expect_gate, run)

    if a.evidence:
        A.write_json(a.evidence,
                     dict(test='tools/sg16/bridge-guest/testnet/test_testnet.py', results=report, failures=failures))
    print(f'{len(failures)} problem(s)')
    sys.exit(1 if failures else 0)


def withheld_store(sdir, store_doc, store_path, hint_path, head, header, committee, lc_hex, check, expect_gate):
    """A: the live head's store was withheld by the update that reached it.  `recover` takes its roots from the
    first hint that hashes to the live lc, the published record before a store another prover rebuilt
    (sg16-bridge-host reconstruct); the artifact gates refuse a state without them; and stage-recovered writes
    the rebuilt store into the record under the update that reached the head, in head order, or nothing."""
    live = dict(head=head, lc=lc_hex)
    stale = A.write_json(sdir / 'stale.json',
                         dict(preimages=[dict(head=head - 32, header=header.hex(), committee=committee.hex())]))
    got = A.fitting_hint(A.Gates(), [stale, store_path], live)
    check('recover hints: a record without the live head is skipped, '
          'and the rebuilt store that hashes to the live lc is used',
          got == (str(store_path), header, committee, str(store_path)), got)
    got = A.fitting_hint(A.Gates(), [hint_path, store_path], live)
    check('recover hints: the published record is used first when it names the store',
          got == (str(hint_path), header, committee, str(store_path)), got)
    bare = A.write_json(sdir / 'bare.json',
                        dict(preimages=[dict(head=head, header=header.hex(), committee=committee.hex())]))
    got = A.fitting_hint(A.Gates(), [bare, store_path], live)
    check('recover hints: a preimage that names no store gives way to one that does',
          got == (str(store_path), header, committee, str(store_path)), got)
    expect_gate('recover hints: refused when no hint hashes to the live lc',
                lambda: A.fitting_hint(A.Gates(), [stale, hint_path], dict(live, lc=h('another lc').hex())),
                A.HINT_GATE)
    lc_only = dict(head=head, lc=lc_hex, acc=pins.EMPTY_ACCUMULATOR, claimed=[],
                   claimed_root=pins.claimed_root([]).hex())
    expect_gate('an lc-only state is refused before any proof is read (reconstruct its store first)',
                lambda: A.check_artifact(A.Gates(), {}, None, None, state=lc_only), 'light-client preimage')

    record, work = WORK / 'stage-recovered' / 'record', WORK / 'stage-recovered' / 'work'
    shutil.rmtree(record.parent, ignore_errors=True)
    anchor = dict(head=ANCHOR_SLOT, header=h('anchor header').hex(), committee=h('anchor committee').hex(),
                  store=f'lc_stores/{ANCHOR_SLOT}.json')
    pending = dict(head=head + 32, header=h('pending header').hex(), committee=h('pending committee').hex(),
                   update=h('pending update').hex(), store=f'lc_stores/{head + 32}.json')
    pre_path = A.write_json(record / 'lc_preimages.json', dict(about='test record', preimages=[anchor, pending]))
    rebuilt = A.write_json(work / 'reconstructed.store.json', store_doc)
    update = h('withheld update').hex()
    state = A.state_record(head, header, committee, A.b32(pins.EMPTY_ACCUMULATOR), [0])
    chain = [[h('bootstrap').hex(), 'start'], [update, 'update'], [h('claim').hex(), 'claim']]
    report = dict(result=dict(state=state, complete=True, lc_store=str(rebuilt), chain=chain))
    want = dict(head=head, header=header.hex(), committee=committee.hex(), update=update,
                store=f'lc_stores/{head}.json')
    got = A.stage_recovered(A.Gates(), record, report, rebuilt)
    pre = json.loads(pre_path.read_text())
    check('stage-recovered: the rebuilt store and an entry naming the update that reached the head, in head order',
          got['added'] is True and (record / want['store']).read_bytes() == rebuilt.read_bytes()
          and [e['head'] for e in pre['preimages']] == [ANCHOR_SLOT, head, head + 32] and pre['preimages'][1] == want
          and pre['about'] == 'test record', pre)
    got = A.stage_recovered(A.Gates(), record, report, rebuilt)
    check('stage-recovered again: nothing added',
          got['added'] is False and json.loads(pre_path.read_text()) == pre, got)

    def files():
        return {p: p.read_bytes() for p in record.rglob('*') if p.is_file()}

    def refuses(name, rep, fragment, edit=None):
        if edit:
            edit()
        before = files()
        expect_gate(name, lambda: A.stage_recovered(A.Gates(), record, rep, rebuilt), fragment)
        check(f'{name}: nothing written', files() == before)
    result = report['result']
    refuses('stage-recovered refuses a state that a published store completed',
            dict(result=dict(result, lc_store=str(record / want['store']))), 'not by a published one')
    refuses('stage-recovered refuses an lc-only state',
            dict(result=dict(result, complete=False)), 'not by a published one')
    refuses('stage-recovered refuses the anchor state, whose store the instance publishes',
            dict(result=dict(result, chain=chain[:1])), 'an update reached the recovered head')
    refuses('stage-recovered refuses a store at another head than the recovered state',
            dict(result=dict(result, state=dict(state, head=head + 32))), 'the store is the recovered head')
    refuses('stage-recovered refuses a record with another entry at the head', report, 'has no other entry',
            edit=lambda: pre_path.write_text(json.dumps(
                dict(pre, preimages=[anchor, dict(want, update=h('another update').hex()), pending]))))
    refuses('stage-recovered refuses a record with another store file at the head', report,
            'is absent or is already this store',
            edit=lambda: (pre_path.write_text(json.dumps(dict(pre, preimages=[anchor, pending]))),
                          (record / want['store']).write_text('{}')))


def synthetic_update(m, mdir, inst, fund, boot, check, run, report):
    """E: a synthetic-key update leaf (NOT the SP1 key) through the real-transaction builder, over a bootstrap
    transaction built by the same tools.  The key has sample toxic waste; this exercises plumbing only."""
    mpath, s0path = mdir / 'manifest.json', mdir / 'initial_state.json'
    k = m['constants']
    config, escrow = A.sepolia_config(), bytes.fromhex(inst.escrow)
    s0m = m['initial_state']
    succ = dict(slot=s0m['head'] + 64, header=h('synthetic successor header'),
                committee=h('synthetic successor committee'))
    fields = dict(lc=A.b32(s0m['lc']), acc=A.b32(s0m['acc']),
                  sibling=pins.tapleaf_simplicity(A.b32(m['claim_leaf']['cmr'])),
                  new_lc=pins.lc(succ['slot'], succ['header'], succ['committee']), new_acc=h('synthetic accumulator 1'),
                  exec_root=h('synthetic execution root'), claimed_root=pins.claimed_root([]),
                  exec_block=11_934_100, new_head=succ['slot'])
    x = liquid.public_input(config, escrow, 0, fields)
    fixed = dict(program_vkey=int(inst.program_vkey, 16), exit_code=0, vk_root=int(pins.VK_ROOT, 16), proof_nonce=0)
    vk5s, proof, _ = B.groth16_instance(5, seed=SEED,
                                        inputs=sp1.wrapper_inputs('v6.1.0', public_values_digest=x, **fixed))
    vk1s = sp1.one_input_key(vk5s, 'v6.1.0', **fixed)
    sdir = WORK / 'synthetic-key'
    sdir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    leaf = A.compile_update_leaf(vk1s, k, sdir, inst)
    leaf.update(stand_in=True, key='SYNTHETIC five-input key with sample toxic waste, folded; NOT the SP1 key')
    check('synthetic-key update leaf compiled', bool(leaf['cmr']), leaf)
    ms = A.build_manifest(A.Gates(), inst, sdir, m['bootstrap']['funding_txid'], 0, False,
                          'LOCAL TEST: synthetic Groth16 key', update_leaf=leaf)
    msp, s0s = sdir / 'manifest.json', sdir / 'initial_state.json'
    check('synthetic-key manifest is not deployable', ms['deployable'] is False)
    boot_s = sdir / 'bootstrap.hex'
    code, rb = run(A.TX_TOOL, 'bootstrap', msp, s0s, fund, 0, 1000, CHANGE_SPK, boot_s, '--local-test')
    check('bootstrap of the synthetic-key tree', code == 0, rb)
    gn = A.update_verifier(dict(vk1=vk1s), k, leaf['pad_blocks'], inst)
    wit = gn.witness_fields(proof, [x], fields)
    if not check('synthetic proof witness builds', wit is not None):
        return
    gn.verify(gn.num_input(wit))
    wpath = A.write_json(sdir / 'update.witness.json', {'w_in': gn.witness_value(wit)})
    npath = A.write_json(sdir / 'new_state.json',
                         A.state_record(succ['slot'], succ['header'], succ['committee'], fields['new_acc'], [],
                                        exec_root=fields['exec_root'].hex(), exec_block=fields['exec_block']))
    fee = sdir / 'fee.hex'
    run(A.TX_TOOL, 'synthetic-funding', 120_000, fee)
    upd = sdir / 'update.hex'
    code, ru = run(A.TX_TOOL, 'update', msp, leaf['program'], wpath, s0s, npath, boot_s, 0, fee, 0, upd, '--local-test')
    check('synthetic-key update: executed over the bootstrap output, within budget and standard weight',
          code == 0 and ru['cost_mwu'] <= ru['budget_mwu'] and ru['weight_estimate'] < pins.STANDARD_TX_WEIGHT, ru)
    report['synthetic_update'] = dict(ru, compile_and_run_seconds=round(time.time() - t0))
    code, rv = run(A.TX_TOOL, 'verify', upd, 0, boot_s, fee)
    check('update input decodes and executes again from the serialized transaction (0.9)', code == 0, rv)
    code, r = run(A.TX_TOOL, 'recover', msp, s0s, boot_s, upd)
    st = r.get('state', {})
    check("recover over an update: new lc and accumulator, head, execution root and block read from its witness; "
          "no store",
          code == 0 and st['lc'] == fields['new_lc'].hex() and st['acc'] == fields['new_acc'].hex()
          and st['head'] == succ['slot'] and st['exec_root'] == fields['exec_root'].hex()
          and st['exec_block'] == fields['exec_block'] and st['claimed'] == []
          and st['claimed_root'] == pins.claimed_root([]).hex()
          and r['store_known'] is False and 'header' not in st
          and [c['kind'] for c in r['chain']] == ['start', 'update'], r)

    def recover(*hints):
        ns = argparse.Namespace(instance=inst.path, manifest=str(msp), bootstrap_tx=str(boot_s), spend=[str(upd)],
                                hint=[str(x) for x in hints], out=str(sdir / 'recovered.json'))
        try:
            return A.cmd_recover(ns, A.Gates())
        except A.Gate as e:
            return str(e)
    got = recover()
    check('assemble.py recover without a hint: an lc-only record, marked incomplete',
          isinstance(got, dict) and got['complete'] is False and got['state']['lc'] == st['lc']
          and 'committee' not in got['state'], got)
    got = recover(npath)
    check("assemble.py recover --hint <the update's successor record>: exactly the record the update builder wrote",
          isinstance(got, dict) and got['complete'] is True and got['state'] == json.loads(npath.read_text()), got)
    bad_hint = A.write_json(sdir / 'bad_hint.json',
                            dict(json.loads(npath.read_text()), committee=h('another committee').hex()))
    got = recover(bad_hint)
    check('a hint that is not the preimage of the recovered lc refused',
          isinstance(got, str) and 'preimage of the recovered lc' in got, got)
    # The update was broadcast without its store: the published record knows only the anchor, so a second prover
    # starts from the store it rebuilt (sg16-bridge-host reconstruct), used only because it hashes to the lc in the
    # update's witness.  The store's CBOR is the host's check (inputs --store, check-store).
    published = A.write_json(sdir / 'record' / 'lc_preimages.json', dict(preimages=[dict(
        head=s0m['head'], header=s0m['header'], committee=s0m['committee'], store=f'lc_stores/{s0m["head"]}.json')]))
    rebuilt = A.write_json(sdir / 'second-prover' / 'reconstructed.store.json', dict(
        head=succ['slot'], header='0x' + succ['header'].hex(), committee='0x' + succ['committee'].hex(),
        lc='0x' + fields['new_lc'].hex(), store_cbor='0x00'))
    got = recover(published)
    check('withheld store: the published record alone does not fit the live head '
          '(just recover then retries without hints)',
          isinstance(got, str) and A.HINT_GATE in got, got)
    got = recover(published, rebuilt)
    check("withheld store: the rebuilt store completes the update builder's record, and the next proof starts from it",
          isinstance(got, dict) and got['complete'] is True and got['state'] == json.loads(npath.read_text())
          and got['hint'] == str(rebuilt) and got['lc_store'] == str(rebuilt), got)
    code, r = run(A.TX_TOOL, 'update', mpath, leaf['program'], wpath, s0path, npath, boot, 0, fee, 0, sdir / 'bad.hex',
                  '--local-test')
    check('a program that is not the manifest update leaf is refused (CMR gate)',
          code == 3 and 'program CMR' in r.get('failed_gate', ''), r)
    tampered = dict(wit, points=list(wit['points']))
    tampered['points'][0] ^= 1
    tpath = A.write_json(sdir / 'tampered.witness.json', {'w_in': gn.witness_value(tampered)})
    code, r = run(A.TX_TOOL, 'update', msp, leaf['program'], tpath, s0s, npath, boot_s, 0, fee, 0, sdir / 'bad.hex',
                  '--local-test')
    check('a tampered proof is rejected by the update leaf',
          code == 3 and 'rejected the spend' in r.get('failed_gate', ''), r)


def real_update(inst, proof_art, proof_path, rf, fund, check, run, report):
    """F: under the instance file the real proof was made for: the real-key update leaf for the synthetic funding
    outpoint and, with that proof of the instance's first update, the update transaction spending that bootstrap
    output.  The funding outpoint is fictional: not deployable, not broadcastable."""
    rdir = WORK / 'real-key'
    rdir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    g = A.Gates()
    mr = A.build_manifest(g, inst, rdir, rf['txid'], 0, False,
                          'LOCAL TEST: fictional funding outpoint, REAL-key update leaf')
    leaf = mr['update_leaf']
    check('real-key update leaf compiled; every manifest gate passed; not deployable (fictional funding)',
          mr['deployable'] is False and not leaf.get('stand_in'), leaf)
    report['real_key_manifest'] = dict(update_cmr=leaf['cmr'], claim_cmr=mr['claim_leaf']['cmr'],
                                       address=mr['state_tree']['address'], pad_blocks=leaf['pad_blocks'],
                                       predicted_cost=leaf['predicted_cost'], text_bytes=leaf['text_bytes'],
                                       compile_seconds=leaf['compile_seconds'], gates=len(g.results))
    mrp, s0r = rdir / 'manifest.json', rdir / 'initial_state.json'
    boot_r = rdir / 'bootstrap.hex'
    code, rb = run(A.TX_TOOL, 'bootstrap', mrp, s0r, fund, 0, 1000, CHANGE_SPK, boot_r, '--local-test')
    check('bootstrap of the real-key tree (local test)', code == 0, rb)
    if not proof_art:
        print('  (no --proof-artifact: real-proof update skipped)')
        return
    g = A.Gates()
    A.check_artifact(g, proof_art, A.sp1_keys(g, inst), inst, json.loads(s0r.read_text()), pairing=True)
    check('real Sepolia proof: every artifact gate including the BN254 pairings',
          all(r['ok'] for r in g.results), g.results)
    fee = rdir / 'fee.hex'
    run(A.TX_TOOL, 'synthetic-funding', 120_000, fee)
    out = rdir / 'update.hex'
    ns = argparse.Namespace(instance=inst.path, manifest=str(mrp), artifact=str(proof_path), state=str(s0r),
                            state_tx=str(boot_r), state_vout=0, fee_tx=str(fee), fee_vout=0,
                            out=str(out), local_test=True)
    ru = A.cmd_update(ns, A.Gates())
    check('real proof -> update transaction spending the bootstrap output: leaf executed, budget, weight, fee floor',
          ru['ok'] is True and ru['cost_mwu'] <= ru['budget_mwu']
          and ru['weight_estimate'] < pins.STANDARD_TX_WEIGHT, ru)
    report['real_update'] = dict(ru, seconds=round(time.time() - t0))
    code, rv = run(A.TX_TOOL, 'verify', out, 0, boot_r, fee)
    check('real update input decodes and executes again from the serialized transaction (0.9)', code == 0, rv)
    report['real_update_verify_0_9'] = rv
    new = json.loads(Path(ru['new_state']).read_text())
    check('successor state = the proven finalized store and the proven accumulator',
          new['head'] == proof_art['successor']['slot'] and '0x' + new['lc'] == proof_art['outputs']['new_lc']
          and '0x' + new['acc'] == proof_art['outputs']['slot_value'], new)
    an = inst.anchor
    other = A.write_json(rdir / 'other_state.json',
                         A.state_record(an['slot'], h('another anchor header'), A.b32(an['committee']),
                                        A.b32(pins.EMPTY_ACCUMULATOR), []))
    try:
        A.cmd_update(argparse.Namespace(**dict(vars(ns), state=str(other), out=str(rdir / 'bad.hex'))), A.Gates())
        got = 'no gate failed'
    except A.Gate as e:
        got = str(e)
    check('the real proof is refused for a state it does not start from', 'prev_lc' in got, got)


def published_record(record, other_path, check, expect_gate, run):
    """G: a published record, instances/<name>/, against its own instance file: the manifest, the claim leaf its
    state tree commits, its bootstrap and its light-client store files."""
    name = record.name
    try:
        inst = A.instance(A.Gates(), record / 'instance.json')
        problem = None
    except A.Gate as e:
        inst, problem = None, e
    if not check(f'{name}: the instance file loads and its pins recompute', inst is not None, problem):
        return
    problems = pins.instance_state(record / 'initial_state.json')
    check(f'{name}: the published initial state is a record of the current claim leaf (claimed set and root)',
          not problems, problems)
    m = json.loads((record / 'manifest.json').read_text())
    try:
        A.manifest_gates(A.Gates(), m, inst)
        passed = True
    except A.Gate as e:
        passed = e
    check(f'{name}: the published manifest was built for its instance file '
          '(networks, escrow, DOMAIN, guest, initial state)',
          passed is True, passed)
    expect_gate(f'{name}: the published manifest refused under another instance file',
                lambda: A.manifest_gates(A.Gates(), m, pins.load(other_path)), 'manifest = the given instance')
    leaf = m.get('claim_leaf', {})
    if A.CLAIM_TOOL.exists():
        code, r = run(A.CLAIM_TOOL, 'cmr', record / 'manifest.json')
        check(f'{name}: the claim leaf recompiles to the manifest claim_leaf cmr and source_sha256',
              code == 0 and (r.get('cmr'), r.get('source_sha256')) == (leaf.get('cmr'), leaf.get('source_sha256')), r)
    else:
        print(f'  ({A.CLAIM_TOOL} missing: {name} claim leaf recompilation skipped)')
    if A.TX_TOOL.exists() and (record / 'bootstrap.hex').is_file():
        code, r = run(A.TX_TOOL, 'recover', record / 'manifest.json', record / 'initial_state.json',
                      record / 'bootstrap.hex')
        check(f'{name}: recover from the published bootstrap gives its initial state at the manifest state address',
              code == 0 and r['state']['state_hash'] == m['initial_state']['state_hash']
              and r['address'] == m['state_tree']['address'], r)
    else:
        print(f'  ({A.TX_TOOL.name} or {name}/bootstrap.hex missing: {name} recovery from its bootstrap skipped)')
    hint = record / 'lc_preimages.json'
    if not hint.is_file():
        print(f'  ({name}/lc_preimages.json absent: its store checks skipped)')
        return
    try:
        heads = [p[0] for p in A.lc_preimages(hint)]
    except A.Gate as e:
        heads = e
    entries = json.loads(hint.read_text()).get('preimages', [])
    anchor = inst.anchor['slot']
    ordered = isinstance(heads, list) and bool(heads) and heads == sorted(set(heads))
    starting = 0
    if ordered and heads[0] == anchor:
        first = entries[0]
        ordered = 'update' not in first and first.get('store') == f'lc_stores/{anchor}.json'
        starting = 1
        later = heads[1:]
    else:
        later = heads if isinstance(heads, list) else []
    check(f'{name}: the lc preimages parse, one per head, with only a named starting store at the anchor',
          ordered and all(head > anchor for head in later) and all('update' in e for e in entries[starting:]), heads)
    stores = []
    for p in entries:
        try:
            stores.append(A.lc_store(A.Gates(), hint, p['head'],
                                     pins.lc(p['head'], A.b32(p['header']), A.b32(p['committee'])).hex()))
        except (A.Gate, KeyError, AssertionError, ValueError) as e:
            stores.append(e)
    check(f'{name}: every lc preimage names its store file, at its head and hashing to its lc',
          stores and all(isinstance(s, str) for s in stores), stores)


if __name__ == '__main__':
    main()
