#!/usr/bin/env python3
"""Assemble Liquid testnet transactions of the sg16 bridge state UTXO from real Sepolia proof artifacts.

Nothing here broadcasts, signs or funds anything.  Every command writes files and a JSON report; a failed gate
stops the command with exit status 3 and names the gate.

    pins                       recompute the pinned Sepolia/Liquid/SP1 values and the instance's (pins.py)
    asset                      the bridge asset and token of a funding outpoint (no instance)
    manifest                   bridge parameters for one bootstrap outpoint: asset and token (independently in
                               Python and in rust-elements), the token constants, the claim leaf (SimplicityHL),
                               the update leaf (Groth16 verifier for the pinned SP1 v6.1.0 key folded with the
                               instance guest's program vkey; minutes), the initial state at the instance anchor,
                               the state tree and its address (two taproot implementations)
    check-artifact             the gates on an `sg16-bridge-host run --prove` artifact (no transaction)
    export-proof               the checked proof, program, witness and successor store for the browser (no transaction)
    bootstrap                  the unsigned issuance transaction creating the first state UTXO
    verify-bootstrap           anyone's check of a public bootstrap against the manifest
    update                     the update transaction from a REAL proof artifact (input 0 complete, fee input unsigned)
    deposits                   the deposits a state proves and which of them it has paid: what `claim` can take
    claim                      the claim transaction for the proven, unclaimed deposit --deposit names, in any order
                               (input 0 complete, fee input unsigned), and the successor's state record
    recover                    the current state record from public transactions alone: the bootstrap, then every
                               update and claim in chain order; an update's light-client store roots from a checked
                               --hint, and the published store file the next proof starts from
    stage-recovered            write a reconstructed store for the live head, which its update never published,
                               into the instance's lc_stores/ and lc_preimages.json (working tree only)

Every command but `asset` takes --instance <instance.json> (instances/<name>/, pins.py): the escrow, guest and
anchor of one bridge instance.  There is no default instance.  The manifest records what it was built from, and
every later command refuses a manifest of another instance.

State UTXO: P2TR(NUMS, {{update leaf, claim leaf}, tapleaf(state_hash(lc, acc, claimed_root))}), holding the bridge
asset's only reissuance token with public blinding factors (the claim crate, liquid.py).  A state record (JSON) is
{head, header, committee, acc, claimed, claimed_root, lc, state_hash[, exec_root, exec_block]}, or the same without
head, header and committee after `recover` walks an update without a store hint: `claimed` lists the deposit
indices already paid, strictly ascending, and `claimed_root` is the root of their claimed tree (pins.claimed_root).
An invalid claimed set or root is refused at a gate. The update leaf is liquid.BridgeGuestVerifier (one leaf: SP1
Groth16 verifier + the bridge-guest rules); the claim leaf is the claim
crate's, compiled by the claim tool.  The update leaf takes the claim leaf's hash from the spent output's control
block, and vice versa, so the pair is fixed by the bootstrap transaction alone: gate it before funding.

The update leaf compiles in the Sepolia config (pins.SEPOLIA_CONFIG); until it is recorded, compiling the leaf and
checking an artifact stop at a gate.

A manifest is `deployable` only if it was built for a real bootstrap outpoint, with the compiled real-key update
leaf, and all gates passed.  The Rust tools refuse non-deployable manifests unless --local-test is given, and
mark their output local-only.  A synthetic proof cannot satisfy the real update leaf: its CMR commits to the
pinned SP1 key, so it differs from any synthetic-key program.

Tools (built separately; see README.md):
    tools/sg16/bridge-guest/target/testnet-tx/release/sg16-testnet            ($SG16_TESTNET_TX)
    tools/sg16/bridge-guest/target/testnet-claim/release/sg16-testnet-claim   ($SG16_TESTNET_CLAIM)
    tools/sg16-harness/target/release/sg16                                    ($SG16_HARNESS)
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1]))
import pins  # noqa: E402
import liquid  # noqa: E402
from sg16 import harness, sp1, statement  # noqa: E402
from sg16 import ref as sg16_ref  # noqa: E402
from sg16.ref import COMMIT, PIN, PINNED, ROOT, SOURCE_SHA256, STATE as GENERATOR_STATE  # noqa: E402
from groth import bn254 as B  # noqa: E402
from groth.fp import Fp  # noqa: E402
from groth.pairing import bounds, windows  # noqa: E402
from groth.sym import Num  # noqa: E402

TARGET = ROOT / 'tools' / 'sg16' / 'bridge-guest' / 'target'
TX_TOOL = Path(os.environ.get('SG16_TESTNET_TX', TARGET / 'testnet-tx' / 'release' / 'sg16-testnet'))
CLAIM_TOOL = Path(os.environ.get('SG16_TESTNET_CLAIM', TARGET / 'testnet-claim' / 'release' / 'sg16-testnet-claim'))
HOST_TOOL = Path(os.environ.get('BRIDGE_HOST_BIN', TARGET / 'release' / 'sg16-bridge-host'))
V6 = ROOT / 'vendor' / 'sp1-helios' / 'contracts' / 'lib' / 'sp1-contracts' / 'contracts' / 'src' / 'v6.1.0'
SCHEMA = 'liquid-bridge-poc/manifest'
DRY_RUN_TXID = pins.sha(b'sg16 testnet dry-run bootstrap outpoint (not a transaction)').hex()
STAND_IN_UPDATE_CMR = pins.sha(b'sg16 testnet stand-in update leaf CMR (local tests only)').hex()
# The generator whose witness layout this checkout writes.  A manifest records the one that compiled its leaf: this
# name only if the loaded generator is the pinned source (sg16/ref.py PINNED), and otherwise its commit and source
# hash marked "not pinned", which generator_gate refuses.
GENERATOR = f'simple-groth16 {PIN}'
# The update leaf's public inputs: SP1's public-values digest, the other wrapper inputs being folded (sp1.py).
INPUTS = 1
# rust-simplicity's encoding of a pruned branch: a 4-bit tag and its 256-bit commitment (bit_encoding/encode.rs).
HIDDEN_BITS = 4 + 256


class Gate(Exception):
    pass


class Gates:
    """Named checks; the first failure raises Gate.  `results` is recorded in every report."""

    def __init__(self):
        self.results = []

    def need(self, name, cond, detail=None):
        self.results.append(dict(gate=name, ok=bool(cond), detail=None if cond else _short(detail)))
        if not cond:
            raise Gate(name + ('' if detail is None else f': {_short(detail)}'))


def _short(x):
    s = str(x)
    return s if len(s) <= 300 else s[:300] + '...'


def b32(x):
    v = bytes.fromhex(x[2:] if x.startswith('0x') else x)
    assert len(v) == 32, 'a 32-byte hex value'
    return v


def write_json(path, doc):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(doc, indent=1, default=str))
    return Path(path)


def tool(path, *args, timeout=7200):
    """(exit status, last JSON line) of a Rust tool.  Status 3 is a failed gate inside the tool."""
    if not path.exists():
        raise Gate(f'{path} missing: build it (README.md)')
    out = subprocess.run([str(path)] + [str(a) for a in args], capture_output=True, text=True, timeout=timeout)
    lines = [json.loads(line) for line in out.stdout.splitlines() if line.startswith('{')]
    if not lines:
        raise Gate(f'{path.name} {args[0]}: no JSON output (exit {out.returncode}): {out.stderr[-1500:]}')
    return out.returncode, lines[-1]


def tool_ok(g, name, path, *args):
    code, r = tool(path, *args)
    g.need(name, code == 0 and r.get('ok') is True, r.get('failed_gate', r))
    return r


def local_test_flag(a):
    """The Rust tools' flag for a local-test run, if this command was given one."""
    return ['--local-test'] if a.local_test else []


def instance(g, path):
    """The instance of the file at `path` (pins.load), once its pins recompute."""
    try:
        inst = pins.load(path)
    except (OSError, ValueError) as e:
        raise Gate(f'instance file: {e}')
    problems = pins.check(inst)
    g.need('instance pins: DOMAIN, empty accumulator, anchor lc and SHA-256 compression recompute',
           not problems, problems)
    return inst


def sepolia_config():
    """The pinned Sepolia config the update leaf compiles in and every artifact must commit."""
    if pins.SEPOLIA_CONFIG is None:
        raise Gate('SEPOLIA_CONFIG is not recorded: record in pins.py the config `sg16-bridge-host inputs` prints')
    return bytes.fromhex(pins.SEPOLIA_CONFIG)


# ---------------------------------------------------------------- state records
def state_lc(s):
    return pins.lc(s['head'], b32(s['header']), b32(s['committee']))


def state_record(head, header, committee, acc, claimed, **extra):
    """The record of a state; `claimed` is the set of paid deposit indices, in any order."""
    lc_ = pins.lc(head, header, committee)
    root = pins.claimed_root(claimed)
    return dict(head=head, header=header.hex(), committee=committee.hex(), acc=acc.hex(), claimed=sorted(claimed),
                claimed_root=root.hex(), lc=lc_.hex(), state_hash=pins.state_hash(lc_, acc, root).hex(), **extra)


def state_claimed(g, s):
    """The claimed set and root of the state record `s`, once they agree."""
    try:
        claimed = pins.claimed_indices(s.get('claimed'))
        root = pins.claimed_root(claimed)
    except ValueError as e:
        claimed, root = None, e
    g.need('the state record lists its paid deposits strictly ascending, below 2^32', claimed is not None, root)
    g.need("the state record's claimed_root is the claimed tree of its paid deposits",
           s.get('claimed_root') == root.hex(), s.get('claimed_root'))
    return claimed, root


def initial_state(inst):
    a = inst.anchor
    return state_record(a['slot'], b32(a['header']), b32(a['committee']), b32(pins.EMPTY_ACCUMULATOR), [])


def initial_state_gate(g, s0, inst):
    """The initial state record `s0` is the one the instance's anchor implies."""
    want = initial_state(inst)
    g.need('initial state = pinned anchor slot, header and committee, empty accumulator, nothing claimed',
           all(s0.get(k) == v for k, v in want.items()), {k: s0.get(k) for k in want if s0.get(k) != want[k]})


# ---------------------------------------------------------------- SP1 key and proof artifact
def contract_return(text, fn):
    m = re.search(r'function\s+' + fn + r'\s*\(\s*\)[^{]*\{\s*return\s+([^;]+);', text)
    return m.group(1).strip().lower() if m else None


def key_pin_problems(constants):
    """The key constants of a Groth16Verifier.sol (`constants`: sp1.solidity_constants) that are not exactly
    pins.GROTH16_KEY_PINS: missing, extra (another public input) or with another value."""
    key = {n: v for n, v in constants.items() if re.fullmatch(pins.GROTH16_KEY_NAME, n)}
    return sorted(n for n in key.keys() | pins.GROTH16_KEY_PINS.keys() if key.get(n) != pins.GROTH16_KEY_PINS.get(n))


def pinned_key():
    """The v6.1.0 key built from the pins alone, with -beta, -gamma, -delta negated back (sp1.py)."""
    k = pins.GROTH16_KEY_PINS
    g2 = lambda p: B.g2_neg((B.Fp2(k[f'{p}_X_0'], k[f'{p}_X_1']), B.Fp2(k[f'{p}_Y_0'], k[f'{p}_Y_1'])))  # noqa: E731
    ic = [(k['CONSTANT_X'], k['CONSTANT_Y'])] + [(k[f'PUB_{i}_X'], k[f'PUB_{i}_Y']) for i in range(5)]
    return dict(alpha=(k['ALPHA_X'], k['ALPHA_Y']), beta=g2('BETA_NEG'), gamma=g2('GAMMA_NEG'), delta=g2('DELTA_NEG'),
                ic=ic)


def sp1_keys(g, inst):
    """The pinned SP1 v6.1.0 Groth16 key, and its one-input fold for the instance's bridge guest."""
    sv, gv = (V6 / 'SP1VerifierGroth16.sol').read_text(), (V6 / 'Groth16Verifier.sol').read_text()
    verifier_hash, vk_root_text = contract_return(sv, 'VERIFIER_HASH'), contract_return(sv, 'VK_ROOT')
    g.need('SP1VerifierGroth16 VERIFIER_HASH = pin', verifier_hash == '0x' + pins.VERIFIER_HASH, verifier_hash)
    g.need('SP1VerifierGroth16 VK_ROOT = pin', vk_root_text == '0x' + pins.VK_ROOT, vk_root_text)
    problems = key_pin_problems(sp1.solidity_constants(gv))
    g.need('Groth16Verifier key constants = pins: every coordinate of every point, and no other key constant',
           not problems, problems)
    vk5, _ = sp1.vk_from_gnark_solidity(gv)
    g.need('parsed v6.1.0 key = the key the pins give', vk5 == pinned_key(), 'the parsed points differ from the pins')
    g.need('Groth16 key has five public inputs (v6.1.0 wrapper)', len(vk5['ic']) == 6, len(vk5['ic']) - 1)
    vkey, vk_root = int(inst.program_vkey, 16), int(pins.VK_ROOT, 16)
    vk1 = sp1.one_input_key(vk5, pins.SP1_LAYOUT, program_vkey=vkey, exit_code=0, vk_root=vk_root, proof_nonce=0)
    return dict(vk5=vk5, vk1=vk1, vkey=vkey, vk_root=vk_root, selector=bytes.fromhex(pins.VERIFIER_HASH)[:4])


def decode_public_values(pv):
    """sg16-bridge-core UpdateOutputs::decode; None if malformed."""
    if len(pv) != 272 or pv[:32] != liquid.UPDATE_TAG or pv[64:76] != bytes(12):
        return None
    w = lambda o: pv[o:o + 32]  # noqa: E731
    u = lambda o: int.from_bytes(pv[o:o + 8], 'big')  # noqa: E731
    return dict(config=w(32), escrow=pv[76:96], slot_key=int.from_bytes(w(96), 'big'), prev_lc=w(128), new_lc=w(160),
                slot_value=w(192), exec_root=w(224), exec_block=u(256), new_head=u(264))


def check_artifact(g, art, keys, inst, state=None, pairing=True):
    """Every gate on a bridge-guest proof artifact.  Returns the decoded outputs, proof and digest."""
    if state is not None:
        g.need('the spent state record has its light-client preimage (header and committee)',
               'header' in state and 'committee' in state,
               'recover gave an lc-only record: no published or reconstructed store matches the live head '
               '(just reconstruct, then just recover)')
    proof_hex = art.get('proof') or '0x'
    g.need('artifact carries a Groth16 proof (not execute-only)', proof_hex not in ('0x', ''),
           'proof "0x": run sg16-bridge-host run --elf <sepolia guest ELF> <inputs.cbor> <out.json> --prove')
    g.need('artifact guest = sg16-bridge-program', art.get('guest') == pins.GUEST, art.get('guest'))
    g.need('artifact network = sepolia', art.get('network') == 'sepolia', art.get('network'))
    g.need('artifact SP1 SDK = 6.8.1', art.get('sdkVersion') == pins.SP1_SDK, art.get('sdkVersion'))
    g.need('program vkey = pinned instance guest vkey', int(art.get('vkey', '0x0'), 16) == keys['vkey'],
           art.get('vkey'))
    proof_bytes = bytes.fromhex(proof_hex[2:])
    g.need('proof bytes = selector + 3 header words + 8 proof words', len(proof_bytes) == 4 + 32 * 11, len(proof_bytes))
    g.need('proof selector = VERIFIER_HASH[:4]', proof_bytes[:4] == keys['selector'], proof_bytes[:4].hex())
    try:
        _, header, proof = sp1.decode_proof(proof_bytes, pins.SP1_LAYOUT)
        on_curve = True
    except AssertionError as e:
        on_curve, header, proof = str(e) or 'not on the curve', None, None
    g.need('proof points are on BN254 (B in the r-torsion subgroup)', on_curve is True, on_curve)
    g.need('wrapper exit code = 0', header['exit_code'] == 0, header['exit_code'])
    g.need('wrapper vkRoot = VK_ROOT', header['vk_root'] == keys['vk_root'], hex(header['vk_root']))
    g.need('wrapper proof nonce = 0 (folded into the key)', header['proof_nonce'] == 0, hex(header['proof_nonce']))
    pv = bytes.fromhex(art['publicValues'][2:])
    o = decode_public_values(pv)
    g.need('public values = 272 bytes with the update tag', o is not None)
    g.need('public values config = pinned Sepolia config', o['config'] == sepolia_config(), o['config'].hex())
    g.need('public values escrow = pinned instance escrow', o['escrow'].hex() == inst.escrow, o['escrow'].hex())
    g.need('public values slot key = 0 (accumulator slot)', o['slot_key'] == pins.SLOT_KEY, o['slot_key'])
    out = art.get('outputs', {})
    g.need('artifact outputs = decoded public values',
           out.get('prev_lc') == '0x' + o['prev_lc'].hex() and out.get('new_lc') == '0x' + o['new_lc'].hex()
           and out.get('slot_value') == '0x' + o['slot_value'].hex() and out.get('new_head') == o['new_head']
           and out.get('execution_block_number') == o['exec_block'])
    succ = art.get('successor', {})
    g.need('new_lc = lc(successor slot, header, committee)',
           succ.get('slot') == o['new_head']
           and o['new_lc'] == pins.lc(o['new_head'], b32(succ['header']), b32(succ['committee'])))
    if state is not None:
        g.need('prev_lc = lc of the spent Liquid state', o['prev_lc'] == state_lc(state), o['prev_lc'].hex())
        g.need('the proven head is newer than the spent state', o['new_head'] > state['head'], o['new_head'])
    digest = statement.public_input(pins.sha(pv))
    g.need('artifact public_input = SHA-256(public values) with the top three bits cleared',
           int(art.get('public_input', '0x0'), 16) == digest)
    if pairing:
        inputs5 = sp1.wrapper_inputs(pins.SP1_LAYOUT, program_vkey=keys['vkey'], public_values_digest=digest,
                                     exit_code=0, vk_root=keys['vk_root'], proof_nonce=0)
        t0 = time.time()
        g.need('pinned five-input SP1 key accepts the proof (BN254 pairing)',
               B.groth16_verify(keys['vk5'], proof, inputs5))
        g.need('folded one-input key accepts the proof', B.groth16_verify(keys['vk1'], proof, [digest]))
        g.need('folded key rejects another digest', not B.groth16_verify(keys['vk1'], proof, [digest ^ 1]))
        print(f'  pairing checks {time.time() - t0:.0f}s')
    return dict(outputs=o, proof=proof, digest=digest, public_values=pv)


# ---------------------------------------------------------------- leaves
def harness_config(entropy, abf, inst):
    """The tools/sg16-harness configuration (src/bridge.rs `Config`) of the bridge asset."""
    return dict(genesis=pins.internal(pins.LIQUID_TESTNET_GENESIS_DISPLAY).hex(), entropy=entropy.hex(),
                fee_asset=pins.internal(pins.LIQUID_TESTNET_LBTC_DISPLAY).hex(), abf_a=abf[0].hex(), abf_b=abf[1].hex(),
                escrow=inst.escrow)


def compile_update_leaf(vk1, consts, out_dir, inst, rehearsal_config=None):
    """liquid.BridgeGuestVerifier for the folded key, with its one public input opened.  Its bytes earn more budget
    than it costs: no padding.  With the harness configuration `rehearsal_config`, also the evidence budget_gate
    checks (budget_rehearsal)."""
    pinned = dict(config=sepolia_config(), escrow=bytes.fromhex(inst.escrow), slot_key=pins.SLOT_KEY)
    if len(vk1['ic']) != INPUTS + 1:
        raise Gate(f'update leaf: the folded key has {len(vk1["ic"]) - 1} public inputs, not {INPUTS}')
    t0 = time.time()
    text, g, est = liquid.BridgeGuestVerifier.compile(vk1, consts, opened=0, **pinned)
    if g.n != INPUTS:
        raise Gate(f'update leaf: compiled with {g.n} public inputs, not {INPUTS}')
    path = Path(out_dir) / 'update_leaf.simpl'
    path.write_text(text)
    # The text form is what tools/sg16-harness `run` parses (test_bridge_guest.py --full runs it there); its CMR is
    # read by the same parser in sg16-testnet.
    code, c = tool(TX_TOOL, 'cmr', path)
    if code != 0 or c.get('ok') is not True:
        raise Gate(f'update leaf CMR: {c}')
    key = (f'SP1 {pins.SP1_LAYOUT} Groth16Verifier.sol (pinned coordinates), folded: program vkey '
           f'{inst.program_vkey}, exit code 0, VK_ROOT, proof nonce 0')
    leaf = dict(cmr=c['cmr'], program=str(path), text_sha256=pins.sha(text.encode()).hex(), text_bytes=len(text),
                generator=loaded_generator(), generator_source_sha256=SOURCE_SHA256, inputs=g.n, predicted_cost=est,
                key=key)
    if rehearsal_config is not None:
        leaf['budget'] = dict(witness_bits=g.witness_bits(),
                              rehearsal=budget_rehearsal(rehearsal_config, inst, out_dir))
    leaf['compile_seconds'] = round(time.time() - t0)
    return leaf


def budget_rehearsal(cfg, inst, out_dir):
    """Spend a leaf like the update leaf in a complete harness update transaction, and report its measured cost,
    budget, sizes and weight.  The leaf has the same generator, constants, config, escrow and slot and one public
    input, and a synthetic five-input key folded like the SP1 key, so that a valid proof exists.  Its predicted
    cost equals the update leaf's: for the real SP1 key, the instance's own leaf and its rehearsal both predict
    48,884,728 mWU (target/groth16-optimization/repair-real-proof/manifest.json), and budget_gate requires the two
    to be equal.  Its program size stands for the update leaf's only as measured: 34,952 bytes against the real
    spend's 34,957 there.  So `update` checks each real spend's program size against this one (program_delta_gate)."""
    consts, config, escrow = harness.consts(cfg), sepolia_config(), bytes.fromhex(inst.escrow)
    h = lambda label: pins.sha(b'sg16 update leaf budget rehearsal: ' + label)  # noqa: E731
    head, new_head = 8192 * 1000 + 64, 8192 * 1000 + 96
    c = dict(header=h(b'header'), committee=h(b'committee'), acc=h(b'accumulator'), claimed_root=pins.claimed_root([]),
             sibling=h(b'claim leaf'), new_header=h(b'successor header'), sync=h(b'successor committee'),
             new_acc=h(b'successor accumulator'))
    fields = dict(lc=liquid.lc(head, c['header'], c['committee']), acc=c['acc'], sibling=c['sibling'],
                  new_lc=liquid.lc(new_head, c['new_header'], c['sync']), new_acc=c['new_acc'],
                  exec_root=h(b'execution root'), claimed_root=c['claimed_root'], exec_block=9_100_000,
                  new_head=new_head)
    x = liquid.public_input(config, escrow, pins.SLOT_KEY, fields)
    fixed = dict(program_vkey=int(inst.program_vkey, 16), exit_code=0, vk_root=int(pins.VK_ROOT, 16), proof_nonce=0)
    vk5, proof, _ = B.groth16_instance(5, seed=7007, inputs=sp1.wrapper_inputs(pins.SP1_LAYOUT, public_values_digest=x,
                                                                                **fixed))
    vk1 = sp1.one_input_key(vk5, pins.SP1_LAYOUT, **fixed)
    if len(vk1['ic']) != INPUTS + 1:
        raise Gate(f'update leaf budget rehearsal: the folded key has {len(vk1["ic"]) - 1} public inputs')
    pinned = dict(config=config, escrow=escrow, slot_key=pins.SLOT_KEY, opened=0)
    text, gs, est = liquid.BridgeGuestVerifier.compile(vk1, consts, **pinned)
    if gs.n != INPUTS:
        raise Gate(f'update leaf budget rehearsal: compiled with {gs.n} public inputs, not {INPUTS}')
    wit = liquid.BridgeGuestVerifier(Fp(Num()), vk1, consts, b=bounds(), **pinned).witness_fields(proof, [x], fields)
    if wit is None:
        raise Gate('update leaf budget rehearsal: the synthetic proof does not verify')
    tx = dict(state_txid=h(b'state txid').hex(), state_vout=0, fee_txid=h(b'fee txid').hex(), fee_vout=1,
              fee_value=4000, old_abf=0, head=head, new_head=new_head, **{k: v.hex() for k, v in c.items()})
    path = Path(out_dir) / 'budget_rehearsal.simpl'
    path.write_text(text)
    case = dict(name='budget rehearsal', expect='ok', tx=tx, mutations=[], witness=gs.witness_value(wit))
    try:
        _, (r,) = harness.run(path, dict(config=cfg, cases=[case]), name='budget_rehearsal_cases.json')
    except SystemExit as e:
        raise Gate(f'update leaf budget rehearsal: the harness failed: {e}') from e
    return dict(ok=r.get('ok') is True, key='synthetic five-input key, folded', inputs=gs.n, predicted_cost=est,
                cost=r.get('cost'), budget_mwu=r.get('budget'), program_bytes=r.get('program_bytes'),
                witness_bytes=r.get('witness_bytes'), tx_weight=r.get('tx_weight'), witness_bits=gs.witness_bits(),
                failure=None if r.get('ok') else f"{r.get('stage')}: {r.get('error')}")


def loader_diagnosis():
    """Why the loaded generator is not pinned, shortest reason first (sg16/ref.py inspect): the check's error, the
    first differences, an override, or another commit."""
    s = GENERATOR_STATE
    if s['error']:
        return f"check failed: {s['error']}"
    if s['changes']:
        return f"{len(s['changes'])} difference(s): {'; '.join(s['changes'][:3])}"
    if s['override']:
        return 'an SG16_REF override'
    return f"at {s['commit']}" if s['commit'] != PIN else 'pinned'


def loaded_generator():
    """The name a manifest records for the loaded generator: GENERATOR only if it is the pinned source."""
    if PINNED:
        return GENERATOR
    return f'simple-groth16 {COMMIT} (not pinned: {loader_diagnosis()}; source sha256 {SOURCE_SHA256})'


def generator_gate(g, leaf):
    """The update leaf and the loaded generator are both the pinned generator, whose witness this checkout writes:
    a clean vendor/simple-groth16 at the pin, not an override or an edited tree (sg16/ref.py inspect)."""
    g.need(f'the loaded generator is the pinned {GENERATOR}, unedited', PINNED, loader_diagnosis())
    g.need(f'manifest update leaf was compiled by {GENERATOR}', leaf.get('generator') == GENERATOR,
           'a leaf from another generator takes another witness: use the checkout that compiled it')


def natural_bits(n):
    """Bits of rust-simplicity's code for the positive integer n (bit_encoding/encode.rs encode_natural): a 1 and the
    bits below the top one of n, then of that bit count, and so on down to 1, then a 0."""
    bits = 1
    while n > 1:
        n = n.bit_length() - 1
        bits += 1 + n
    return bits


def program_variation(program_bytes, inputs):
    """The most bytes by which the pruned programs of two spends of one leaf can differ, for a leaf with `inputs` public
    inputs whose pruned program measured `program_bytes`.  From rust-simplicity's post-order encoding, which names a
    node's children by their distance back (encode_natural) and writes a pruned branch as a hidden node of
    HIDDEN_BITS (bit_encoding/encode.rs).

    Only the public input changes what pruning keeps, and only in the table windows (pairing.py windows, curve.py
    select_const); every other case node takes the same branch in every spend.  Neither choice changes the number of
    nodes, so no distance outside a window's own nodes changes:

      - each bit of a window is a case node of that window's tree, with two subtrees of one shape.  Pruning keeps one
        and writes the other as one hidden node (AssertL or AssertR), so only the order of the two changes: the
        distance to the child written first, one code of at most natural_bits(N) bits in a program of N nodes.  The
        kept leaf, `comp unit <constant>`, also moves within the window, and with it its distance back to the one
        shared `unit` node: one more code per window.
      - the aligned windows share one digit function (curve.py digit_fn), one case node per bit, each
        `case (injl (drop f)) (injr (drop f))` (curve.py:284).  The encoder shares a node with its earlier
        occurrence (EncodeSharing: by identity, a hidden node by commitment), so `drop f` is one node for both
        branches, and the pruner keeps a branch that any of the windows' calls takes.  A branch hidden in one spend
        and kept in another is one `injl` or `injr` node against one hidden node: the same number of nodes, at most
        HIDDEN_BITS more or less, and the codes of the case node's two children and the kept branch's `drop f` move.

    A node takes at least 4 bits, so N is at most 2 per byte; 4,096 bytes of room cover the variation itself.  Add the
    program's last, partial byte and 2 bytes for its witness-stack length prefix, which grows from 3 to 5 bytes at
    2^16 bytes.  This bounds spends of one leaf; it does not bound how two leaves for different keys differ
    (budget_rehearsal), which program_delta_gate measures instead."""
    wins = windows(inputs)
    digits = {w for _, lo, w in wins if w & (w - 1) == 0 and lo % w == 0 and 256 % w == 0}
    code = natural_bits(2 * (program_bytes + 4096))
    bits = (sum(w for _, _, w in wins) + len(wins)) * code + sum(digits) * (HIDDEN_BITS + 3 * code)
    return (bits + 7) // 8 + 1 + 2


def budget_gate(g, rehearsal, leaf):
    """The update leaf fits the input budget of each of its spends, by the measured `rehearsal` (budget_rehearsal).
    `leaf` is {cost, inputs, witness_bits} of the update leaf: regenerated from the instance key where it matters
    most (bootstrap_gates, leaf_shape), the manifest's record otherwise.  The rehearsal spend must have executed at
    its predicted cost, which must be the update leaf's cost, with its one public input and witness width; less
    1,000 mWU per byte of program_variation, its input budget must still cover that cost; and with its program that
    much larger, its transaction must stay below standard weight.  A program byte earns 1,000 mWU of budget and
    weighs 1 WU.  The rehearsal's program size stands for the update leaf's only as measured (budget_rehearsal), so
    each update checks its spend's program size against it (program_delta_gate) and measures the budget of its own
    spend before it is written."""
    r, cost = rehearsal or {}, leaf.get('cost')
    g.need('update leaf budget rehearsal: the spend executed at its predicted cost',
           r.get('ok') is True and r.get('cost') == r.get('predicted_cost'), r)
    g.need('update leaf budget rehearsal: predicted cost = the update leaf\'s',
           isinstance(cost, int) and r.get('predicted_cost') == cost, dict(rehearsal=r.get('predicted_cost'), leaf=cost))
    g.need(f'update leaf and its rehearsal: {INPUTS} public input and the same witness width',
           r.get('inputs') == leaf.get('inputs') == INPUTS and r.get('witness_bits') == leaf.get('witness_bits'),
           dict(rehearsal=dict(inputs=r.get('inputs'), witness_bits=r.get('witness_bits')), leaf=leaf))
    budget, weight, size = r.get('budget_mwu'), r.get('tx_weight'), r.get('program_bytes')
    measured = all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in (cost, budget, weight, size))
    less = program_variation(size, INPUTS) if measured else None
    g.need("update leaf cost <= rehearsed input budget less 1,000 mWU per byte of program_variation, and rehearsed "
           "weight plus that variation below standard weight",
           measured and cost <= budget - 1000 * less and weight + less < pins.STANDARD_TX_WEIGHT,
           dict(cost=cost, budget_mwu=budget, program_bytes=size, variation_bytes=less, tx_weight=weight))


def program_delta_gate(g, leaf, program_bytes):
    """A real spend's pruned program (`program_bytes`, measured by sg16-testnet update) is within program_variation
    of the rehearsal's.  Spends of one leaf always are; a larger difference means the rehearsal, a leaf for another
    key, does not represent this one, and the budget it showed is not evidence for it."""
    r = (leaf.get('budget') or {}).get('rehearsal') or {}
    size = r.get('program_bytes')
    ok = all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in (size, program_bytes))
    less = program_variation(size, INPUTS) if ok else None
    g.need('the spend\'s pruned program is within program_variation of the budget rehearsal\'s',
           ok and abs(program_bytes - size) <= less,
           dict(program_bytes=program_bytes, rehearsal_program_bytes=size, variation_bytes=less))


def recorded_shape(leaf):
    """{cost, inputs, witness_bits} of an update leaf as its manifest records them."""
    return dict(cost=leaf.get('predicted_cost'), inputs=leaf.get('inputs'),
                witness_bits=(leaf.get('budget') or {}).get('witness_bits'))


def leaf_shape(g, m, inst, leaf):
    """{cost, inputs, witness_bits} of the update leaf regenerated for the instance key: the manifest's program text
    must be the pinned generator's output, so budget_gate checks the program's own cost, input count and witness
    width, not recorded numbers.  The record must agree too, as update and export-proof read it."""
    keys = sp1_keys(g, inst)
    text, gen, est = liquid.BridgeGuestVerifier.compile(keys['vk1'], m['constants'], opened=0, config=sepolia_config(),
                                                        escrow=bytes.fromhex(inst.escrow), slot_key=pins.SLOT_KEY)
    g.need("update leaf program = the pinned generator's output for the instance key (SHA-256)",
           pins.sha(text.encode()).hex() == leaf['text_sha256'])
    shape = dict(cost=est, inputs=gen.n, witness_bits=gen.witness_bits())
    g.need('the manifest records the regenerated leaf\'s cost, input count and witness width',
           recorded_shape(leaf) == shape, dict(recorded=recorded_shape(leaf), regenerated=shape))
    return shape


def update_verifier(keys, consts, inst):
    return liquid.BridgeGuestVerifier(Fp(Num()), keys['vk1'], consts, b=bounds(), opened=0,
                                      config=sepolia_config(), escrow=bytes.fromhex(inst.escrow),
                                      slot_key=pins.SLOT_KEY)


# ---------------------------------------------------------------- manifest
def identity(inst):
    """What a manifest records of the instance it was built for and of the fixed pins."""
    liquid_ = dict(network='liquidtestnet', genesis_display=pins.LIQUID_TESTNET_GENESIS_DISPLAY,
                   fee_asset_display=pins.LIQUID_TESTNET_LBTC_DISPLAY)
    sepolia = dict(instance=inst.name, chain_id=pins.SEPOLIA_CHAIN_ID,
                   genesis_validators_root=pins.SEPOLIA_GENESIS_VALIDATORS_ROOT, config=pins.SEPOLIA_CONFIG,
                   forks=pins.SEPOLIA_FORKS, escrow=inst.escrow, escrow_code_hash=inst.escrow_code_hash,
                   deposit_domain=inst.deposit_domain, empty_accumulator=pins.EMPTY_ACCUMULATOR, slot_key=pins.SLOT_KEY)
    sp1_ = dict(sdk=pins.SP1_SDK, layout=pins.SP1_LAYOUT, helios_commit=pins.SP1_HELIOS_COMMIT, guest=pins.GUEST,
                elf_sha256=inst.guest_elf_sha256, program_vkey=inst.program_vkey, verifier_hash=pins.VERIFIER_HASH,
                vk_root=pins.VK_ROOT)
    return dict(liquid=liquid_, sepolia=sepolia, sp1=sp1_)


def manifest_gates(g, m, inst):
    """The manifest was built for `inst`: the leaves, constants and initial state of another instance's manifest
    would be checked against the wrong escrow, guest or anchor."""
    want = dict(identity(inst), initial_state=initial_state(inst))
    differ = {k: m.get(k) for k in want if m.get(k) != want[k]}
    if m.get('harness_config', {}).get('escrow') != inst.escrow:
        differ['harness_config.escrow'] = m.get('harness_config', {}).get('escrow')
    g.need(f'manifest = the given instance ({inst.name}): networks, escrow, DOMAIN, guest and initial state',
           not differ, differ)


def bridge_asset(g, funding_txid_display, funding_vout):
    """(contract hash, entropy, asset, token) of a new issuance at the funding outpoint, computed in Python and
    checked against rust-elements."""
    contract = bytes(32)
    entropy = pins.asset_entropy(pins.internal(funding_txid_display), funding_vout, contract)
    asset, token = pins.asset_id(entropy), pins.token_id(entropy)
    r = tool_ok(g, 'rust-elements: outpoint entropy gives the same token', TX_TOOL, 'params',
                funding_txid_display, funding_vout, contract.hex(), entropy.hex())
    g.need('Python and rust-elements agree on asset and token ids',
           r['asset'] == asset.hex() and r['token'] == token.hex() and r['outpoint_token_matches'] is True, r)
    return contract, entropy, asset, token


def build_manifest(g, inst, out_dir, funding_txid_display, funding_vout, deployable, label, update_leaf=None):
    """inst: from instance(), which has recomputed its pins.  update_leaf None: compile the real-key update leaf and
    rehearse its budget (minutes); a real leaf must pass budget_gate, and a deployable one generator_gate.  A dict
    with stand_in=True: local tests only."""
    contract, entropy, asset, token = bridge_asset(g, funding_txid_display, funding_vout)
    abf = pins.token_blinding(entropy)
    cfg = harness_config(entropy, abf, inst)
    consts = harness.consts(cfg)
    g.need('harness constants: asset, token, fee asset, genesis',
           consts['asset'] == asset.hex() and consts['token'] == token.hex()
           and consts['fee_asset'] == cfg['fee_asset'] and consts['genesis'] == cfg['genesis'])
    bootstrap = dict(funding_txid=funding_txid_display, funding_vout=funding_vout, contract_hash=contract.hex(),
                     entropy=entropy.hex(), asset=asset.hex(), token=token.hex(), asset_display=pins.display(asset),
                     token_display=pins.display(token))
    m = dict(schema=SCHEMA, deployable=False, label=label, **identity(inst), bootstrap=bootstrap,
             harness_config=cfg, constants=consts)
    mpath = Path(out_dir) / 'manifest.json'
    write_json(mpath, m)

    c = tool_ok(g, 'claim leaf compiles (SimplicityHL 0.7.2)', CLAIM_TOOL, 'cmr', mpath)
    g.need('claim leaf token commitments = update leaf constants',
           c['token_a'] == consts['token_a'] and c['token_b'] == consts['token_b']
           and c['token_value'] == consts['token_value'], dict(claim=c, harness=consts))
    g.need('claim leaf asset, entropy and escrow DOMAIN = manifest',
           c['asset'] == asset.hex() and c['entropy'] == entropy.hex() and c['deposit_domain'] == inst.deposit_domain)
    m['claim_leaf'] = dict(cmr=c['cmr'], source_sha256=c['source_sha256'],
                           toolchain='SimplicityHL f3fa882e / rust-simplicity a8896cf9 (tools/bootstrap-deps.py)')
    if update_leaf is None:
        keys = sp1_keys(g, inst)
        update_leaf = compile_update_leaf(keys['vk1'], consts, out_dir, inst, rehearsal_config=cfg)
    real_leaf = not update_leaf.get('stand_in')
    if real_leaf:
        # just compiled here: the record is the generator's own output
        budget_gate(g, (update_leaf.get('budget') or {}).get('rehearsal'), recorded_shape(update_leaf))
        if deployable:
            generator_gate(g, update_leaf)
    m['update_leaf'] = update_leaf

    s0 = initial_state(inst)
    s0path = write_json(Path(out_dir) / 'initial_state.json', s0)
    m['initial_state'] = s0
    write_json(mpath, m)
    t = tool_ok(g, 'state tree: rust-elements TaprootBuilder = harness taproot code', TX_TOOL, 'tree', mpath, s0path)
    leaf_u, leaf_c = pins.tapleaf_simplicity(b32(update_leaf['cmr'])), pins.tapleaf_simplicity(b32(c['cmr']))
    root = pins.tapbranch(pins.tapbranch(leaf_u, leaf_c), pins.tapleaf_simplicity(b32(s0['state_hash'])))
    g.need('state tree merkle root = Python recomputation',
           t['merkle_root'] == root.hex() and t['state_hash'] == s0['state_hash'], t)
    tree_keys = ('script_pubkey', 'address', 'output_key', 'merkle_root', 'update_control', 'claim_control')
    m['state_tree'] = {k: t[k] for k in tree_keys}
    m['deployable'] = bool(deployable and real_leaf)
    m['gates'] = g.results
    write_json(mpath, m)
    return m


def load_manifest(path):
    m = json.loads(Path(path).read_text())
    if m.get('schema') != SCHEMA:
        raise Gate('manifest schema')
    return m


def fee_floor(weight):
    return ((weight + 3) // 4 * pins.MIN_RELAY_SAT_PER_KVB + 999) // 1000


# ---------------------------------------------------------------- commands
def cmd_manifest(a, g):
    if a.dry_run == bool(a.funding_txid):
        raise Gate('give exactly one of --funding-txid/--funding-vout or --dry-run')
    inst = instance(g, a.instance)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if a.dry_run:
        m = build_manifest(g, inst, out, DRY_RUN_TXID, 0, False,
                           'DRY RUN: placeholder bootstrap outpoint, not a transaction')
    else:
        m = build_manifest(g, inst, out, a.funding_txid, a.funding_vout, True,
                           'Manifest only: verify funding and bootstrap on Liquid before use')
    return dict(manifest=str(out / 'manifest.json'), deployable=m['deployable'], address=m['state_tree']['address'],
                update_cmr=m['update_leaf']['cmr'], claim_cmr=m['claim_leaf']['cmr'])


def cmd_asset(a, g):
    """The bridge asset of a funding outpoint, before anything else exists: the escrow pins this id at deployment
    (BridgeEscrow.BRIDGE_ASSET, internal byte order), and its address then goes into the instance file the
    manifest reads.  Python and rust-elements must agree, as in the manifest."""
    _, entropy, asset, token = bridge_asset(g, a.funding_txid, a.funding_vout)
    return dict(funding=f'{a.funding_txid}:{a.funding_vout}', entropy=entropy.hex(),
                bridge_asset_internal='0x' + asset.hex(), bridge_asset_display=pins.display(asset),
                token_display=pins.display(token),
                note='keep the funding output unspent until the bootstrap: another outpoint makes another asset')


def cmd_check_artifact(a, g):
    inst = instance(g, a.instance)
    art = json.loads(Path(a.artifact).read_text())
    state = json.loads(Path(a.state).read_text()) if a.state else None
    r = check_artifact(g, art, sp1_keys(g, inst), inst, state, pairing=not a.no_pairing)
    o = r['outputs']
    return dict(prev_lc=o['prev_lc'].hex(), new_lc=o['new_lc'].hex(), new_acc=o['slot_value'].hex(),
                new_head=o['new_head'], exec_block=o['exec_block'], pairing_checked=not a.no_pairing)


def bootstrap_gates(g, inst, m, mpath, s0path, local_test, creating=False):
    """Re-derive what a bootstrap transaction commits forever instead of trusting the manifest's record of
    it: the manifest's instance, the initial state against the instance anchor, both leaf CMRs, and the state
    script built from them.  A new bootstrap (`creating`), and the check of any leaf that records its generator,
    also regenerate the update leaf with the pinned generator and require its cost to fit the rehearsed budget.  A
    public bootstrap of an older leaf, which records no generator, is checked by its CMR alone."""
    manifest_gates(g, m, inst)
    initial_state_gate(g, json.loads(Path(s0path).read_text()), inst)
    c = tool_ok(g, 'claim leaf recompiles from the manifest parameters', CLAIM_TOOL, 'cmr', mpath)
    g.need('recompiled claim leaf CMR = manifest claim CMR', c['cmr'] == m['claim_leaf']['cmr'], c['cmr'])
    leaf = m['update_leaf']
    if leaf.get('stand_in'):
        g.need('a stand-in update CMR only in a local test', local_test)
    else:
        program = Path(leaf['program'])
        g.need('update leaf program text = the compiled text (SHA-256)',
               pins.sha(program.read_bytes()).hex() == leaf['text_sha256'])
        u = tool_ok(g, 'update leaf program parses', TX_TOOL, 'cmr', program)
        g.need('update leaf CMR recomputed from the program = manifest update CMR', u['cmr'] == leaf['cmr'], u['cmr'])
        if creating or 'generator' in leaf:
            generator_gate(g, leaf)
            shape = leaf_shape(g, m, inst, leaf)
            # Measured again here, not read from the manifest: the leaf is committed forever by this bootstrap.
            with tempfile.TemporaryDirectory(prefix='budget-rehearsal-') as tmp:
                budget_gate(g, budget_rehearsal(m['harness_config'], inst, tmp), shape)
    t = tool_ok(g, 'state tree of the initial state', TX_TOOL, 'tree', mpath, s0path)
    g.need('state script = manifest state tree', t['script_pubkey'] == m['state_tree']['script_pubkey'],
           t['script_pubkey'])


def cmd_verify_bootstrap(a, g):
    """Anyone's check of a public bootstrap against the manifest, before depositing: the leaves and initial state
    re-derived from source and pins (bootstrap_gates), then the transaction itself (sg16-testnet check-bootstrap):
    the funding outpoint issued exactly one token and no asset, into the manifest's state UTXO.  With
    --escrow-asset, the escrow's BRIDGE_ASSET() readback must be that asset."""
    inst = instance(g, a.instance)
    m = load_manifest(a.manifest)
    s0 = Path(a.manifest).parent / 'initial_state.json'
    bootstrap_gates(g, inst, m, a.manifest, s0, a.local_test, creating=False)
    r = tool_ok(g, 'bootstrap transaction issued the only token into the state UTXO', TX_TOOL, 'check-bootstrap',
                a.manifest, s0, a.bootstrap_tx)
    if a.escrow_asset:
        g.need('escrow BRIDGE_ASSET = the asset this bootstrap issued',
               a.escrow_asset.lower().removeprefix('0x') == r['bridge_asset_internal'], r['bridge_asset_internal'])
    return r


def cmd_bootstrap(a, g):
    inst = instance(g, a.instance)
    m = load_manifest(a.manifest)
    s0 = Path(a.manifest).parent / 'initial_state.json'
    bootstrap_gates(g, inst, m, a.manifest, s0, a.local_test, creating=True)
    args = ['bootstrap', a.manifest, s0, a.funding_tx, m['bootstrap']['funding_vout'], a.fee, a.change_spk or '-',
            a.out]
    r = tool_ok(g, 'bootstrap transaction gates (rust-elements)', TX_TOOL, *args, *local_test_flag(a))
    g.need('bootstrap fee covers the 0.1 sat/vB relay floor', a.fee >= fee_floor(r['weight_estimate']),
           r['weight_estimate'])
    return r


def prepare_update(g, inst, m, state, art, local_test=False):
    """The transaction-independent update witness and successor, shared by the CLI and browser export."""
    manifest_gates(g, m, inst)
    leaf = m['update_leaf']
    g.need('manifest has a compiled update leaf', not leaf.get('stand_in') or local_test)
    generator_gate(g, leaf)
    if not leaf.get('stand_in'):
        # The manifest's record, as bootstrap measured it; what admits the update is its own spend's measured budget
        # (sg16-testnet update, the browser builder) and, for `update`, program_delta_gate.
        budget_gate(g, (leaf.get('budget') or {}).get('rehearsal'), recorded_shape(leaf))
    claimed, root = state_claimed(g, state)
    keys = sp1_keys(g, inst)
    r = check_artifact(g, art, keys, inst, state)
    lc_ = state_lc(state)
    g.need('the spent state record recomputes its lc and state hash',
           state.get('lc') == lc_.hex()
           and state.get('state_hash') == pins.state_hash(lc_, b32(state['acc']), root).hex())
    o = r['outputs']
    fields = dict(lc=lc_, acc=b32(state['acc']),
                  sibling=pins.tapleaf_simplicity(b32(m['claim_leaf']['cmr'])), new_lc=o['new_lc'],
                  new_acc=o['slot_value'], exec_root=o['exec_root'], claimed_root=root,
                  exec_block=o['exec_block'], new_head=o['new_head'])
    modelled = liquid.public_values(sepolia_config(), bytes.fromhex(inst.escrow), pins.SLOT_KEY, fields)
    g.need('public values = liquid.py model of the witness fields', modelled == r['public_values'])
    gn = update_verifier(keys, m['constants'], inst)
    wit = gn.witness_fields(r['proof'], [r['digest']], fields)
    g.need('numeric Groth16 model accepts the real proof with the folded key', wit is not None)
    gn.verify(gn.num_input(wit))
    succ = art['successor']
    new = state_record(o['new_head'], b32(succ['header']), b32(succ['committee']), o['slot_value'], claimed,
                       exec_root=o['exec_root'].hex(), exec_block=o['exec_block'])
    return gn.witness_value(wit), new


def cmd_update(a, g):
    inst = instance(g, a.instance)
    m = load_manifest(a.manifest)
    state = json.loads(Path(a.state).read_text())
    art = json.loads(Path(a.artifact).read_text())
    witness, new = prepare_update(g, inst, m, state, art, a.local_test)
    out = Path(a.out)
    wpath = write_json(out.with_suffix('.witness.json'), witness)
    npath = write_json(out.with_suffix('.new_state.json'), new)
    args = ['update', a.manifest, m['update_leaf']['program'], wpath, a.state, npath, a.state_tx, a.state_vout,
            a.fee_tx, a.fee_vout, out]
    t = tool_ok(g, 'update transaction gates and node-like execution', TX_TOOL, *args, *local_test_flag(a))
    if not m['update_leaf'].get('stand_in'):
        program_delta_gate(g, m['update_leaf'], t.get('program_bytes'))
    return dict(t, new_state=str(npath))


def export_program(g, m, manifest_path):
    """Read the pinned program, also allowing a record copied from another checkout."""
    leaf = m['update_leaf']
    path = Path(leaf['program'])
    if not path.is_file():
        path = Path(manifest_path).parent / 'update_leaf.simpl'
    g.need('the pinned update program is available', path.is_file(),
           f"restore {leaf['program']} or place update_leaf.simpl beside the manifest")
    raw = path.read_bytes()
    g.need('update leaf program text = the compiled text (SHA-256)',
           pins.sha(raw).hex() == leaf['text_sha256'])
    return raw.decode('utf-8')


def compile_browser_proof(g, program, witness, cmr, out):
    """Canonical program and witness bytes; no transaction or outpoint enters this compilation."""
    program_path = out.with_suffix('.simpl')
    program_path.parent.mkdir(parents=True, exist_ok=True)
    program_path.write_text(program)
    witness_path = write_json(out.with_suffix('.witness.json'), witness)
    compiled_path = out.with_suffix('.compiled.json')
    compiled_path.unlink(missing_ok=True)
    try:
        r = tool_ok(g, 'update program and witness compile to canonical bytes', TX_TOOL, 'compile-update',
                    program_path, witness_path, compiled_path)
    except Gate as e:
        raise Gate('proof compiler failed; keep proof.json. If compile-update is unavailable, run just tools, '
                   f'then just proof-bundle. No new SP1 proof is needed. Details: {e}') from e
    g.need('compiler wrote canonical program and witness', compiled_path.is_file())
    try:
        compiled = json.loads(compiled_path.read_text())
    except ValueError as e:
        raise Gate(f'compiler output JSON: {e}') from e
    g.need('compiler output is an object', isinstance(compiled, dict))
    g.need('update leaf CMR recomputed from the program = manifest update CMR',
           compiled.get('cmr') == cmr and r.get('cmr') == cmr, compiled.get('cmr'))
    for field in ('program', 'witness'):
        value = compiled.get(field + '_hex')
        g.need(f'compiled {field} is nonempty canonical hex',
               isinstance(value, str) and re.fullmatch(r'(?:[0-9a-f]{2})+', value) is not None)
        g.need(f'compiled {field} length = compiler report', len(value) // 2 == r.get(field + '_bytes'))
    return {k: compiled[k] for k in ('program_hex', 'witness_hex', 'cmr')}


def successor_store(g, path, new):
    """Check both the store's declared roots and its CBOR before sharing the complete file."""
    raw = Path(path).read_bytes()
    store = json.loads(raw)
    norm = lambda x: str(x).lower().removeprefix('0x')
    g.need('successor store roots = the proof successor',
           all(norm(store.get(k)) == norm(new[k]) for k in ('head', 'header', 'committee', 'lc')))
    g.need('the host is available to check the successor store CBOR', HOST_TOOL.is_file(),
           f'{HOST_TOOL} missing: run just host')
    r = subprocess.run([str(HOST_TOOL), 'check-store', str(path), '--lc', new['lc']],
                       capture_output=True, text=True, timeout=120)
    g.need('successor store CBOR hashes to the proof successor lc', r.returncode == 0, r.stderr[-1500:])
    checked = json.loads(r.stdout)
    g.need('the host checked the successor store roots', checked.get('matches_state_lc') is True
           and all(norm(checked.get(k)) == norm(new[k]) for k in ('head', 'header', 'committee', 'lc')))
    g.need('successor store did not change while being checked', Path(path).read_bytes() == raw)
    return store


def cmd_export_proof(a, g):
    inst = instance(g, a.instance)
    m = load_manifest(a.manifest)
    g.need('browser proof uses a deployable manifest', m.get('deployable') is True)
    state = json.loads(Path(a.state).read_text())
    art = json.loads(Path(a.artifact).read_text())
    witness, new = prepare_update(g, inst, m, state, art)
    program = export_program(g, m, a.manifest)
    bundle = dict(schema='zk-bridge/browser-proof',
                  instance=dict(identity(inst), update_cmr=m['update_leaf']['cmr'], claim_cmr=m['claim_leaf']['cmr']),
                  state=state, new_state=new, program=program, witness=witness)
    bundle['successor_store'] = successor_store(g, a.store, new)
    out = Path(a.out)
    bundle['compiled_program'] = compile_browser_proof(g, program, witness, m['update_leaf']['cmr'], out)
    part = out.with_name(out.name + '.part')
    try:
        write_json(part, bundle)
        part.replace(out)
    finally:
        part.unlink(missing_ok=True)
    return dict(bundle=str(out), new_head=new['head'], exec_block=new['exec_block'],
                successor_store_included=True,
                note='Upload this proof bundle in the website update panel. The browser builds the transaction.')


def proven_deposits(g, inst, state, deposits_path):
    """The deposits the state's accumulator proves, [(units, recipient)], recomputed here independently of the claim
    tool.  The escrow keeps taking deposits after the block the state proved, so the event list may be longer than
    the proven tree; the accumulator commits to its count, so at most one prefix can reproduce it."""
    # BridgeDeposits events carry the scriptPubKey, whose SHA-256 is the committed recipient.
    events = [(u, pins.sha(bytes.fromhex(r.removeprefix('0x'))))
              for u, r in json.loads(Path(deposits_path).read_text())]
    domain, acc = bytes.fromhex(inst.deposit_domain), b32(state['acc'])
    proven = [k for k in range(len(events), -1, -1) if pins.accumulator(pins.tree_root(domain, events[:k]), k) == acc]
    g.need('a prefix of the deposit events reproduces the state accumulator', bool(proven), f'{len(events)} events')
    return events[:proven[0]]


def cmd_deposits(a, g):
    """What `claim` can take: every deposit the state proves, and whether its claimed tree has paid it."""
    inst = instance(g, a.instance)
    m = load_manifest(a.manifest)
    manifest_gates(g, m, inst)
    state = json.loads(Path(a.state).read_text())
    claimed, _ = state_claimed(g, state)
    deposits = proven_deposits(g, inst, state, a.deposits)
    r = tool_ok(g, 'the claim tool reads the same proven deposits and claimed set', CLAIM_TOOL, 'deposits',
                a.manifest, a.state, a.deposits)
    g.need('Python and the claim tool agree on the proven count and the claimed set',
           r['proven'] == len(deposits) and r['claimed'] == claimed, r)
    return r


def cmd_claim(a, g):
    inst = instance(g, a.instance)
    m = load_manifest(a.manifest)
    manifest_gates(g, m, inst)
    state = json.loads(Path(a.state).read_text())
    claimed, _ = state_claimed(g, state)
    deposits = proven_deposits(g, inst, state, a.deposits)
    unclaimed = [k for k in range(len(deposits)) if k not in claimed]
    g.need(f'deposit {a.deposit} is proven by the state accumulator', 0 <= a.deposit < len(deposits),
           f'{len(deposits)} proven deposit(s); unclaimed: {unclaimed}')
    g.need(f'deposit {a.deposit} is unclaimed in the state', a.deposit not in claimed,
           f'claimed: {claimed}; unclaimed: {unclaimed}')
    units, _ = deposits[a.deposit]
    g.need("deposit units within the escrow's bounds", 100_000 <= units <= 2_100_000_000_000_000, units)
    args = ['claim', a.manifest, a.state, a.deposits, a.state_tx, a.state_vout, a.fee_tx, a.fee_vout, a.out,
            '--deposit', a.deposit]
    r = tool_ok(g, 'claim transaction gates and execution (SimplicityHL)', CLAIM_TOOL, *args, *local_test_flag(a))
    want = None
    if 'header' in state:
        want = state_record(state['head'], b32(state['header']), b32(state['committee']), b32(state['acc']),
                            claimed + [a.deposit], **{k: state[k] for k in ('exec_root', 'exec_block') if k in state})
    nxt = r['successor_state']
    g.need('the successor record is the state record with the deposit added to its claimed set',
           r['deposit']['index'] == a.deposit and nxt['claimed'] == sorted(claimed + [a.deposit])
           and nxt['claimed_root'] == pins.claimed_root(claimed + [a.deposit]).hex()
           and nxt['state_hash'] == r['successor_state_hash']
           and nxt['state_hash'] == pins.state_hash(b32(nxt['lc']), b32(nxt['acc']), b32(nxt['claimed_root'])).hex()
           and (want is None or nxt == want), nxt)
    v = tool_ok(g, 'claim input decodes and executes under rust-simplicity 0.9 (current jets)', TX_TOOL, 'verify',
                a.out, 0, a.state_tx, a.fee_tx)
    npath = write_json(Path(a.out).with_suffix('.new_state.json'), nxt)
    return dict(r, verify_0_9=v, new_state=str(npath))


def lc_preimages(path):
    """(head, header, committee) candidates in a --hint file: instances/<name>/lc_preimages.json
    ({"preimages": [...]}), one state record, a store file, or `sg16-bridge-host anchor` output
    ({"anchor": {"slot", "header", ...}})."""
    doc = json.loads(Path(path).read_text())
    items = doc['preimages'] if 'preimages' in doc else [doc.get('anchor', doc)]
    try:
        return [(int(x['head'] if 'head' in x else x['slot']), b32(x['header']), b32(x['committee'])) for x in items]
    except (KeyError, TypeError, ValueError, AssertionError) as e:
        raise Gate(f'hint {path}: each entry gives head (or slot), header and committee ({e!r})')


def lc_store(g, hint, head, lc_hex):
    """The light-client store file the next proof can start from (`sg16-bridge-host inputs --store`), if the hint
    is one or its entry at `head` names one ("store", relative to the hint file).  Its head, roots and lc must be
    the recovered state's; the host checks that its CBOR recomputes them.  None if no store is published."""
    doc = json.loads(Path(hint).read_text())
    if 'store_cbor' in doc:
        path = Path(hint)
    else:
        names = [e['store'] for e in doc.get('preimages', []) if e.get('head') == head and 'store' in e]
        if not names:
            return None
        path = Path(hint).parent / names[0]
    g.need('the hint names a published light-client store file', path.is_file(), str(path))
    s = json.loads(path.read_text())
    try:
        fields = (int(s['head']), b32(s['header']), b32(s['committee']), b32(s['lc']), s['store_cbor'])
    except (KeyError, TypeError, ValueError, AssertionError) as e:
        raise Gate(f'store file {path}: head, header, committee, lc and store_cbor ({e!r})')
    g.need('the store file is at the recovered head and hashes to the recovered lc',
           fields[0] == head and fields[3].hex() == lc_hex == pins.lc(*fields[:3]).hex(),
           f'{path}: head {fields[0]}, lc {fields[3].hex()}')
    return str(path)


HINT_GATE = 'a hint is the preimage of the recovered lc: head, finalized header root, sync committee root'


def fitting_hint(g, hints, s):
    """(hint, header, committee, store) of the first of `hints` holding a preimage of the recovered state `s` (its
    lc at its head), preferring one that also names a store file: the published record before a reconstructed
    store, as the caller orders them.  A hint that does not fit is skipped; if none fits, the gate fails."""
    found = None
    for hint in hints:
        fits = [p for p in lc_preimages(hint) if p[0] == s['head'] and pins.lc(*p).hex() == s['lc']]
        if not fits:
            continue
        store = lc_store(g, hint, s['head'], s['lc'])
        if found is None or (store and not found[3]):
            found = (str(hint), fits[0][1], fits[0][2], store)
        if store:
            break
    g.need(HINT_GATE, found, f'head {s["head"]}, lc {s["lc"]}; tried {", ".join(map(str, hints))}')
    return found


def cmd_recover(a, g):
    """The current state from public transactions (sg16-testnet recover): the instance's initial state and its
    bootstrap, then each update and claim that spent the state output, in chain order.  Their witnesses and outputs
    give lc, the accumulator, the claimed set and the head.  An update's lc also commits to the finalized header
    root and sync committee root, which are not on Liquid.  Each --hint offers them; one is used only if it hashes
    to the recovered lc.  Without one after an update the record has lc but no store, which is enough to claim but
    not to update.  The report's lc_store is the store file the next proof starts from, if the hint used names
    one or is one, and `hint` is that hint.  The bootstrap itself is verify-bootstrap's check."""
    inst = instance(g, a.instance)
    m = load_manifest(a.manifest)
    manifest_gates(g, m, inst)
    s0path = Path(a.manifest).parent / 'initial_state.json'
    initial_state_gate(g, json.loads(s0path.read_text()), inst)
    r = tool_ok(g, 'state chain: each spend opens the previous state output with a manifest leaf and recreates the '
                   'state it reveals', TX_TOOL, 'recover', a.manifest, s0path, a.bootstrap_tx, *a.spend)
    s, hint, store = r['state'], None, None
    if a.hint:
        hint, header, committee, store = fitting_hint(g, a.hint, s)
        s = dict(s, header=header.hex(), committee=committee.hex())
    complete = 'header' in s
    claimed, _ = state_claimed(g, s)
    if complete:
        rec = state_record(s['head'], b32(s['header']), b32(s['committee']), b32(s['acc']), claimed,
                           **{k: s[k] for k in ('exec_root', 'exec_block') if k in s})
        g.need('the record recomputes the recovered lc, claimed root and state hash',
               rec['lc'] == s['lc'] and rec['claimed_root'] == s['claimed_root']
               and rec['state_hash'] == s['state_hash'])
    else:
        rec = s
    write_json(a.out, rec)
    note = r['note']
    if not complete:
        note += '; no light-client store: the record can claim, and needs a --hint to update'
    elif not store:
        note += ('; no published store file at this head: the next proof needs a beacon node serving a light-client '
                 'bootstrap for it')
    return dict(state=rec, complete=complete, lc_store=store, hint=hint, outpoint=r['outpoint'], address=r['address'],
                chain=[[c['txid'], c['kind']] for c in r['chain']], out=a.out, note=note)


def stage_recovered(g, record, recovered, store_path):
    """Stage into the instance directory `record` a store at the live head that its update never published:
    lc_stores/<head>.json and its lc_preimages.json entry, naming the update that reached the head, so that later
    provers need neither the beacon data it was rebuilt from nor this work directory.  `recovered` is the report of
    an `assemble.py recover` that this store completed (its lc_store), so the store's roots hash to the lc read
    from Liquid.  Nothing is written unless every gate passes.  Returns the entry, the two files and whether the
    entry was added."""
    res = recovered.get('result', {})
    s = res.get('state', {})
    g.need('the recovered state was completed by this store, not by a published one',
           res.get('complete') is True and res.get('lc_store')
           and Path(res['lc_store']).resolve() == Path(store_path).resolve(),
           f'lc_store {res.get("lc_store")}')
    updates = [txid for txid, kind in res.get('chain', []) if kind == 'update']
    g.need('an update reached the recovered head (the starting store is published with the instance)', updates,
           res.get('chain'))
    raw = Path(store_path).read_bytes()
    st = json.loads(raw)
    norm = lambda h: str(h).lower().removeprefix('0x')  # noqa: E731
    g.need('the store is the recovered head, header, committee and lc',
           (st.get('head'), norm(st.get('header')), norm(st.get('committee')), norm(st.get('lc')))
           == (s['head'], s['header'], s['committee'], s['lc'])
           and pins.lc(s['head'], b32(s['header']), b32(s['committee'])).hex() == s['lc'],
           f'{store_path}: head {st.get("head")}, lc {st.get("lc")}')
    rel = f'lc_stores/{s["head"]}.json'
    dst = Path(record) / rel
    g.need(f'{dst} is absent or is already this store', not dst.exists() or dst.read_bytes() == raw)
    entry = dict(head=s['head'], header=s['header'], committee=s['committee'], update=updates[-1], store=rel)
    pre_path = Path(record) / 'lc_preimages.json'
    pre = json.loads(pre_path.read_text()) if pre_path.exists() else {'preimages': []}
    same = [e for e in pre['preimages'] if e.get('head') == entry['head']]
    g.need(f'{pre_path} has no other entry for head {entry["head"]}', not same or same[0] == entry, same)
    dst.parent.mkdir(exist_ok=True)
    dst.write_bytes(raw)
    if not same:
        pre['preimages'] = sorted(pre['preimages'] + [entry], key=lambda e: e['head'])
        pre_path.write_text(json.dumps(pre, indent=1) + '\n')
    return dict(entry=entry, store=str(dst), lc_preimages=str(pre_path), added=not same)


def cmd_stage_recovered(a, g):
    instance(g, a.instance)
    recovered = json.loads(Path(a.recovered).read_text())
    return stage_recovered(g, Path(a.instance).parent, recovered, a.store)


def cmd_pins(a, g):
    inst = instance(g, a.instance)
    return dict(instance=inst.name, escrow=inst.escrow, anchor_lc=inst.anchor['lc'],
                deposit_domain=inst.deposit_domain, empty_accumulator=pins.EMPTY_ACCUMULATOR,
                sepolia_config=pins.SEPOLIA_CONFIG)


COMMANDS = {
    'pins': cmd_pins,
    'asset': cmd_asset,
    'manifest': cmd_manifest,
    'check-artifact': cmd_check_artifact,
    'export-proof': cmd_export_proof,
    'bootstrap': cmd_bootstrap,
    'verify-bootstrap': cmd_verify_bootstrap,
    'update': cmd_update,
    'deposits': cmd_deposits,
    'claim': cmd_claim,
    'recover': cmd_recover,
    'stage-recovered': cmd_stage_recovered,
}


def parser():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)

    def command(name, needs_instance=True):
        p = sub.add_parser(name)
        p.add_argument('--report', help='also write the JSON report here')
        if needs_instance:
            p.add_argument('--instance', required=True,
                           help='the bridge instance file, instances/<name>/instance.json (there is no default)')
        return p

    command('pins')

    p = command('asset', needs_instance=False)
    p.add_argument('--funding-txid', required=True,
                   help='display hex of the transaction whose output will fund the bootstrap')
    p.add_argument('--funding-vout', type=int, default=0)

    p = command('manifest')
    p.add_argument('--funding-txid', help='display hex of the transaction whose output funds the bootstrap issuance')
    p.add_argument('--funding-vout', type=int, default=0)
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--out', default=str(TARGET / 'testnet'))

    p = command('check-artifact')
    p.add_argument('--artifact', required=True)
    p.add_argument('--state')
    p.add_argument('--no-pairing', action='store_true')

    p = command('export-proof')
    for f in ('--manifest', '--artifact', '--state', '--out'):
        p.add_argument(f, required=True)
    p.add_argument('--store', required=True, help='successor store to verify and include in full')

    p = command('bootstrap')
    p.add_argument('--manifest', required=True)
    p.add_argument('--funding-tx', required=True, help='raw hex of the funding transaction')
    p.add_argument('--fee', type=int, required=True)
    p.add_argument('--change-spk')
    p.add_argument('--out', required=True)
    p.add_argument('--local-test', action='store_true')

    p = command('verify-bootstrap')
    p.add_argument('--manifest', required=True)
    p.add_argument('--bootstrap-tx', required=True, help='raw hex of the public bootstrap transaction')
    p.add_argument('--escrow-asset', help='BridgeEscrow.BRIDGE_ASSET() readback, 0x internal hex')
    p.add_argument('--local-test', action='store_true')

    for name, fields in (('update', ('--manifest', '--artifact', '--state', '--state-tx', '--fee-tx', '--out')),
                         ('claim', ('--manifest', '--state', '--deposits', '--state-tx', '--fee-tx', '--out'))):
        p = command(name)
        for f in fields:
            p.add_argument(f, required=True)
        p.add_argument('--state-vout', type=int, default=0)
        p.add_argument('--fee-vout', type=int, required=True)
        p.add_argument('--local-test', action='store_true')
        if name == 'claim':
            p.add_argument('--deposit', type=int, required=True,
                           help='index of the proven, unclaimed deposit to pay (see `deposits`); there is no default')

    p = command('deposits')
    for f in ('--manifest', '--state', '--deposits'):
        p.add_argument(f, required=True)

    p = command('recover')
    p.add_argument('--manifest', required=True)
    p.add_argument('--bootstrap-tx', required=True, help='raw hex of the public bootstrap transaction')
    p.add_argument('--spend', action='append', default=[],
                   help='raw hex of the next public update or claim, in chain order (repeat)')
    p.add_argument('--hint', action='append', default=[],
                   help='lc preimages: instances/<name>/lc_preimages.json, a state record, a store file (published or '
                        'from sg16-bridge-host reconstruct) or sg16-bridge-host anchor output; repeat to try several, '
                        'in order')
    p.add_argument('--out', required=True, help='where to write the recovered state record')

    p = command('stage-recovered')
    p.add_argument('--recovered', required=True, help='the report of the recover that this store completed')
    p.add_argument('--store', required=True, help='the store file, from sg16-bridge-host reconstruct')
    return ap


def main():
    a = parser().parse_args()
    g = Gates()
    report = dict(command=a.cmd, instance=getattr(a, 'instance', None))
    try:
        report = dict(ok=True, **report, result=COMMANDS[a.cmd](a, g), gates=g.results)
        code = 0
    except (Gate, OSError, ValueError, KeyError, TypeError, AssertionError, subprocess.TimeoutExpired) as e:
        report = dict(ok=False, **report, failed_gate=str(e), gates=g.results)
        code = 3
    print(json.dumps(report, indent=1, default=str))
    if a.report:
        write_json(a.report, report)
    sys.exit(code)


if __name__ == '__main__':
    main()
