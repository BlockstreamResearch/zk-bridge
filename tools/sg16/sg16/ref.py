"""Locate the pinned simple-groth16 generator and put its `groth` package on sys.path.

simple-groth16 (https://github.com/BlockstreamResearch/simple-groth16) is MIT licensed, Copyright (c) 2026
Blockstream Research.  It is imported, not copied: the BN254 field, tower, curve, Miller-loop, residue-check
and Groth16 layers are used unchanged.  Search order: $SG16_REF, then vendor/simple-groth16 (fetched by
tools/bootstrap-deps.py).  The checkout must be at PIN unless SG16_ALLOW_UNPINNED=1.
"""
import os
import sys
from pathlib import Path

PIN = '4f787ea07b97e62bd0ba4fa3f9518d52621dcb68'
ROOT = Path(__file__).resolve().parents[3]


def _git_head(repo):
    git = Path(repo) / '.git'
    head = (git / 'HEAD').read_text().strip()
    if not head.startswith('ref: '):
        return head
    ref = head[5:]
    if (git / ref).exists():
        return (git / ref).read_text().strip()
    packed = git / 'packed-refs'
    if packed.exists():
        for line in packed.read_text().splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    return None


def locate():
    candidates = [os.environ.get('SG16_REF'), ROOT / 'vendor' / 'simple-groth16']
    for c in candidates:
        if c and (Path(c) / 'groth' / 'groth16.py').exists():
            return Path(c).resolve()
    raise SystemExit('simple-groth16 not found: set SG16_REF or clone it into vendor/simple-groth16 at ' + PIN)


REF = locate()
COMMIT = _git_head(REF)
if COMMIT != PIN and os.environ.get('SG16_ALLOW_UNPINNED') != '1':
    raise SystemExit(f'simple-groth16 at {REF} is at {COMMIT}, expected {PIN}')
if str(REF) not in sys.path:
    sys.path.insert(0, str(REF))
