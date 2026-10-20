#!/usr/bin/env python3
"""Fetch the pinned source dependencies into vendor/ (ignored by git), then verify them.

    python3 tools/bootstrap-deps.py           fetch whatever is missing or at another commit, then verify
    python3 tools/bootstrap-deps.py --check   verify only, without the network

Each dependency is a public git repository at one exact commit. Submodules listed with it are checked out at
the commits that commit records (its gitlinks). A checkout already at its pin is left as it is. One at another
commit is moved only if no tracked file is edited; the script refuses to touch edited files. Untracked files,
such as build output inside a dependency, are ignored.

Verification, the last step of both modes, fails unless every checkout is at its pin with no edited tracked
file and every listed submodule matches its gitlink. A zero exit therefore means vendor/ is what this file
names.
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / 'vendor'

# name: (repository, commit, submodules to check out, what needs it)
DEPS = {
    'SimplicityHL': ('https://github.com/BlockstreamResearch/SimplicityHL.git',
                     'f3fa882e77c221e96e10acde9f0e46e68e69930f', (),
                     'claim crate (contracts/simplicity), Liquid claim tool (tools/sg16/bridge-guest/testnet/claim)'),
    'rust-simplicity': ('https://github.com/BlockstreamResearch/rust-simplicity.git',
                        'a8896cf93ed683d8ae1430371ad7d196ab061fa5', (),
                        'claim crate, Liquid claim tool'),
    'simple-groth16': ('https://github.com/BlockstreamResearch/simple-groth16.git',
                       '4f787ea07b97e62bd0ba4fa3f9518d52621dcb68', (),
                       'Groth16 verifier generator of the update leaf (tools/sg16)'),
    # SP1 Helios v1.3.0. Its sp1-contracts submodule holds the SP1 v6.1.0 Groth16 verifier whose key
    # the update leaf folds.
    'sp1-helios': ('https://github.com/succinctlabs/sp1-helios.git',
                   '0dd8749f1e6c2c2302cd92931f8af63a6330af08', ('contracts/lib/sp1-contracts',),
                   'SP1 bridge guest (tools/sg16/bridge-guest), SP1 Groth16 key of the update leaf (tools/sg16)'),
}


def git(path, *args, capture=True):
    """Runs git in `path` and returns its output unstripped: some formats start with a meaningful space."""
    r = subprocess.run(['git', '-C', str(path), *args], capture_output=capture, text=True)
    if r.returncode != 0:
        raise SystemExit(f'git {" ".join(args)} in {path} failed: {(r.stderr or "see above").strip()}')
    return r.stdout or ''


def head(path):
    r = subprocess.run(['git', '-C', str(path), 'rev-parse', '--verify', '-q', 'HEAD'], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def edited(path):
    """Tracked files that differ from the checked-out commit. Submodules are checked on their own."""
    return git(path, 'status', '--porcelain', '--untracked-files=no', '--ignore-submodules=all').splitlines()


def fetch(name, url, commit, submodules):
    path = VENDOR / name
    if not path.exists():
        VENDOR.mkdir(exist_ok=True)
        git(ROOT, 'init', '-q', str(path))
        git(path, 'remote', 'add', 'origin', url)
    elif not (path / '.git').exists():
        raise SystemExit(f'{path} exists but is not a git checkout; move it away and rerun')
    current = head(path)
    if current != commit:
        if current is not None and edited(path):
            raise SystemExit(f'{path} is at {current} with edited files; refusing to move it to {commit}')
        print(f'{name}: fetching {commit[:12]} from {url}', flush=True)
        git(path, 'fetch', '-q', '--depth', '1', 'origin', commit, capture=False)
        git(path, 'checkout', '-q', '--detach', commit)
    elif not any(child.name != '.git' for child in path.iterdir()):
        # A clone made without checkout points HEAD at the commit but has an empty working tree.
        git(path, 'checkout', '-q', '--detach', '--force', commit)
    for sub in submodules:
        print(f'{name}: checking out submodule {sub}', flush=True)
        git(path, 'submodule', 'update', '--init', '--', sub, capture=False)


def verify(name, commit, submodules):
    path = VENDOR / name
    problems = []
    current = head(path) if (path / '.git').exists() else None
    if current is None:
        return [f'{name}: missing; run python3 tools/bootstrap-deps.py']
    if current != commit:
        problems.append(f'{name}: at {current}, pinned {commit}')
    changes = edited(path)
    if changes:
        problems.append(f'{name}: {len(changes)} edited tracked file(s), e.g. {changes[0].strip()}')
    for sub in submodules:
        # `git submodule status` prefixes '-' (not checked out), '+' (another commit) or 'U' (conflict).
        line = git(path, 'submodule', 'status', '--', sub).rstrip('\n')
        if not line or line[0] != ' ':
            problems.append(f'{name}: submodule {sub} does not match its gitlink: {line or "absent"}')
        elif edited(path / sub):
            problems.append(f'{name}: submodule {sub} has edited tracked files')
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--check', action='store_true', help='verify only; never fetch')
    a = ap.parse_args()
    if not a.check:
        for name, (url, commit, submodules, _) in DEPS.items():
            fetch(name, url, commit, submodules)
    problems = []
    for name, (_, commit, submodules, needed_by) in DEPS.items():
        found = verify(name, commit, submodules)
        problems += found
        if not found:
            print(f'ok  {name:22} {commit[:12]}  {needed_by}')
    if problems:
        print('\n'.join(problems), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
