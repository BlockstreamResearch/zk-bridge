"""Calls tools/sg16-harness (the `sg16` binary) and parses its JSON lines."""
import json
import os
import subprocess
import time
from pathlib import Path

from .ref import ROOT

SG16 = Path(os.environ.get('SG16_HARNESS', ROOT / 'tools' / 'sg16-harness' / 'target' / 'release' / 'sg16'))
BUILD = Path(os.environ.get('SG16_BUILD', ROOT / 'build' / 'sg16'))


def _call(args, timeout=7200):
    if not SG16.exists():
        raise SystemExit(f'{SG16} missing: cargo build --release --manifest-path tools/sg16-harness/Cargo.toml')
    out = subprocess.run([str(SG16)] + [str(a) for a in args], capture_output=True, text=True, timeout=timeout)
    lines = [json.loads(l) for l in out.stdout.splitlines() if l.startswith('{')]
    if out.returncode != 0 or not lines:
        raise SystemExit(f'sg16 {args[0]} failed ({out.returncode}):\n{out.stdout[-3000:]}\n{out.stderr[-3000:]}')
    return lines


def write(name, doc):
    BUILD.mkdir(parents=True, exist_ok=True)
    path = BUILD / name
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    return path


def consts(config):
    return _call(['consts', write('config.json', config)])[0]


def run(program_path, doc, name='cases.json'):
    """(header, [one result per case]); header has the program CMR and the constants."""
    t0 = time.time()
    lines = _call(['run', program_path, write(name, doc)])
    for r in lines[1:]:
        r.setdefault('wall_seconds', time.time() - t0)
    return lines[0], lines[1:]
