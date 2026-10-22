"""Locate the pinned simple-groth16 generator and put its `groth` package on sys.path.

simple-groth16 (https://github.com/BlockstreamResearch/simple-groth16) is MIT licensed, Copyright (c) 2026
Blockstream Research.  It is imported, not copied: the BN254 field, polynomial, curve, pairing-check and
Groth16 layers are used unchanged.  Search order: $SG16_REF, then vendor/simple-groth16 (fetched by
tools/bootstrap-deps.py).

A HEAD at PIN is not the pinned source.  Tracked files can be edited and hidden from `git status` by the index
(assume-unchanged, skip-worktree), and ignored files can be added, which Python imports all the same.  So
`inspect` trusts neither the index nor git's object store: from the commit named PIN it reads the commit and its
trees with `git cat-file` and checks that each hashes to its name, then compares the files on disk with those
trees byte for byte (`differences`).  Compared are the checkout's top level, which is first on sys.path, where
every importable module or package must be pinned content, and everything under such a package, groth/ among
them: every pinned file present and byte for byte its blob, no symbolic link, and no importable module or
package added.  Files Python does not import, and `__pycache__` directories, are not compared.

Python's own loader would still run a cached groth/__pycache__/*.pyc in place of a checked file whenever the
source timestamp and size the .pyc records match it, as a .pyc compiled from an edit and left behind does once the
edit is undone with the old timestamp.  So a checkout without difference is imported through VerifiedSource,
first on sys.meta_path: it compiles groth and each of its modules from the bytes the check read, and reads no
.pyc and no file again.

A checkout with any difference, at another commit, or where the check cannot run loads only with
SG16_ALLOW_UNPINNED=1, for experiments, and is imported as Python normally would, caches included.  PINNED, which the deployment gates require (assemble.py
generator_gate), holds only for vendor/simple-groth16 without difference at PIN: an $SG16_REF override is never
PINNED, even at PIN.  SOURCE_SHA256 hashes the groth/*.py files actually loaded, for the record.
"""
import hashlib
import importlib.util
import os
import subprocess
import sys
from importlib.machinery import all_suffixes
from pathlib import Path

PIN = 'a3ac525296ac1706099968f37a575007b89a5bdb'
ROOT = Path(__file__).resolve().parents[3]
VENDOR = ROOT / 'vendor' / 'simple-groth16'
BLOB_MODES = ('100644', '100755')
TREE_MODE = '40000'


class Unverified(Exception):
    """The pinned commit or one of its trees cannot be read, or does not hash to its name."""


def _git(repo, *args, binary=False):
    """git's output in `repo`, or None.  The caller's GIT_* variables, replace refs and fsmonitor are ignored."""
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0')
    try:
        r = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-C', str(repo), *args],
                           capture_output=True, text=not binary, env=env, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def _algorithm(oid):
    return 'sha1' if len(oid) == 40 else 'sha256'


def _object(repo, kind, oid):
    """The content of object `oid`, once it hashes to that name as a `kind` (git's object format)."""
    data = _git(repo, 'cat-file', kind, oid, binary=True)
    if data is None or hashlib.new(_algorithm(oid), f'{kind} {len(data)}\0'.encode() + data).hexdigest() != oid:
        raise Unverified(f'{kind} {oid} is missing or does not hash to its name')
    return data


def _tree(repo, oid):
    """{name: (mode, oid)} of the verified tree `oid`."""
    data, size, out, i = _object(repo, 'tree', oid), hashlib.new(_algorithm(oid)).digest_size, {}, 0
    while i < len(data):
        sp = data.index(b' ', i)
        nul = data.index(b'\0', sp)
        out[os.fsdecode(data[sp + 1:nul])] = (data[i:sp].decode(), data[nul + 1:nul + 1 + size].hex())
        i = nul + 1 + size
    return out


def _blob_id(oid_like, data):
    return hashlib.new(_algorithm(oid_like), f'blob {len(data)}\0'.encode() + data).hexdigest()


def _importable(entry):
    """A top-level entry Python can import from a sys.path directory: a file with an import suffix (source,
    bytecode, extension), or a directory with an __init__ file (a package).  Symbolic links are followed."""
    if entry.is_dir():
        return any(os.path.exists(os.path.join(entry.path, '__init__' + s)) for s in all_suffixes())
    return entry.name.endswith(tuple(all_suffixes()))


def _compare(repo, tree_oid, path, rel, out, verified):
    """Append to `out` how the directory `path` differs from the verified tree `tree_oid`: every pinned entry must be
    present and every pinned file its blob byte for byte; links, and added entries Python could import (modules,
    packages), are differences.  Other added files, such as editor or desktop metadata, are not read by Python.
    The bytes of every file that matches its blob go into `verified`, by path."""
    want, seen = _tree(repo, tree_oid), set()
    for e in sorted(os.scandir(path), key=lambda e: e.name):
        if e.name == '__pycache__' and e.is_dir(follow_symlinks=False):
            continue
        if e.name not in want and not e.is_symlink() and not _importable(e):
            continue
        seen.add(e.name)
        name, (mode, oid) = f'{rel}{e.name}', want.get(e.name, (None, None))
        if e.is_symlink():
            out.append(f'{name}: a symbolic link')
        elif e.is_dir():
            if mode == TREE_MODE:
                _compare(repo, oid, e.path, name + '/', out, verified)
            else:
                out.append(f'{name}/: not in the pinned tree')
        elif mode not in BLOB_MODES:
            out.append(f'{name}: not in the pinned tree')
        else:
            data = Path(e.path).read_bytes()
            if _blob_id(oid, data) != oid:
                out.append(f'{name}: differs from the pinned file')
            else:
                verified[Path(e.path)] = data
    out += [f'{rel}{n}: missing' for n in sorted(set(want) - seen)]


def differences(repo, commit, verified=None):
    """How the checkout `repo` differs from the verified commit `commit` where Python imports from it: its
    importable top-level entries, and everything under its packages (module docstring).  The bytes of the files
    that match go into `verified` (a dict, by path) if given.  Raises Unverified."""
    verified = {} if verified is None else verified
    head = _object(repo, 'commit', commit).split(b'\n', 1)[0]
    if not head.startswith(b'tree '):
        raise Unverified(f'commit {commit} names no tree')
    root, out = _tree(repo, head[5:].decode()), []
    for e in sorted(os.scandir(repo), key=lambda e: e.name):
        # groth/ always: without its __init__.py it would still import, as a namespace package
        if e.name == '.git' or (e.name != 'groth' and not _importable(e)):
            continue
        mode, oid = root.get(e.name, (None, None))
        if e.is_symlink():
            out.append(f'{e.name}: a symbolic link')
        elif e.is_dir():
            if mode == TREE_MODE:
                _compare(repo, oid, e.path, e.name + '/', out, verified)
            else:
                out.append(f'{e.name}/: an importable package not in the pinned tree')
        elif mode not in BLOB_MODES or _blob_id(oid, Path(e.path).read_bytes()) != oid:
            out.append(f'{e.name}: an importable module not in the pinned tree, or another file')
    if root.get('groth', (None,))[0] != TREE_MODE:
        out.append('groth/: not in the pinned tree')
    return out


def source_digest(repo):
    """SHA-256 of the generator's Python files, groth/*.py in name order, each as its name, length and bytes."""
    h = hashlib.sha256()
    for f in sorted((Path(repo) / 'groth').glob('*.py')):
        data = f.read_bytes()
        h.update(f'{f.name}\0{len(data)}\0'.encode() + data)
    return h.hexdigest()


def inspect(repo, pin=PIN, vendor=VENDOR, verified=None):
    """What a checkout of the generator is: {commit, changes, error, override, usable, pinned, source_sha256}.
    commit is git's HEAD if `repo` is the top of its own repository; changes are its differences from that commit
    (None, with the reason in error, if they cannot be established); usable means at `pin` without difference;
    pinned also that `repo` is `vendor`.  `verified`, a dict if given, receives the bytes of the files checked."""
    repo = Path(repo).resolve()
    top = _git(repo, 'rev-parse', '--show-toplevel')
    own = top is not None and Path(top.strip()).resolve() == repo
    head = _git(repo, 'rev-parse', '--verify', '--quiet', 'HEAD^{commit}') if own else None
    commit = head.strip() if head else None
    changes, error = None, None if commit else 'not the top of a git checkout with a commit'
    if commit:
        try:
            changes = differences(repo, commit, verified)
        except (Unverified, OSError, ValueError, UnicodeDecodeError) as e:
            error = str(e)
    usable = commit == pin and changes == []
    override = repo != Path(vendor).resolve()
    return dict(commit=commit, changes=changes, error=error, override=override, usable=usable,
                pinned=usable and not override, source_sha256=source_digest(repo))


def generator_sources(repo, verified):
    """{module name: (path, bytes)} of the groth package among the `verified` files of the checkout `repo`."""
    package = Path(repo).resolve() / 'groth'
    return {('groth' if p.name == '__init__.py' else f'groth.{p.stem}'): (p, data)
            for p, data in verified.items() if p.parent == package and p.suffix == '.py'}


class VerifiedSource:
    """Imports groth and its modules from verified bytes (generator_sources), compiled afresh on every import.  The
    normal path loader would run a __pycache__ .pyc instead whenever its recorded source timestamp and size match
    the file, and would read the file again after the check; this reads neither.  A groth module without verified
    bytes is an import error."""

    def __init__(self, sources):
        self.sources = sources

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] != 'groth':
            return None
        if fullname not in self.sources:
            raise ImportError(f'{fullname} is not among the verified generator sources', name=fullname)
        origin = self.sources[fullname][0]
        spec = importlib.util.spec_from_loader(fullname, self, origin=str(origin), is_package=fullname == 'groth')
        if fullname == 'groth':
            spec.submodule_search_locations = [str(origin.parent)]
        spec.has_location = True
        return spec

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        origin, data = self.sources[module.__name__]
        exec(compile(data, str(origin), 'exec', dont_inherit=True), module.__dict__)


def install(sources):
    """Put a VerifiedSource for `sources` first on sys.meta_path, and return it."""
    finder = VerifiedSource(sources)
    sys.meta_path.insert(0, finder)
    return finder


def locate():
    candidates = [os.environ.get('SG16_REF'), VENDOR]
    for c in candidates:
        if c and (Path(c) / 'groth' / 'groth16.py').exists():
            return Path(c).resolve()
    raise SystemExit('simple-groth16 not found: set SG16_REF or clone it into vendor/simple-groth16 at ' + PIN)


REF = locate()
_verified = {}
STATE = inspect(REF, verified=_verified)
COMMIT, PINNED, SOURCE_SHA256 = STATE['commit'], STATE['pinned'], STATE['source_sha256']
if not STATE['usable'] and os.environ.get('SG16_ALLOW_UNPINNED') != '1':
    found = STATE['error'] or '; '.join(STATE['changes'][:5]) or 'no difference'
    raise SystemExit(f'simple-groth16 at {REF} is at {COMMIT}, expected {PIN} without difference ({found}); '
                     'run python3 tools/bootstrap-deps.py, or set SG16_ALLOW_UNPINNED=1 for an experiment')
# A checkout without difference is imported from the bytes just verified (VerifiedSource); an experiment
# (SG16_ALLOW_UNPINNED=1) is imported as Python normally would, caches included.
FINDER = None
if STATE['usable']:
    early = sorted(m for m in sys.modules if m.split('.')[0] == 'groth')
    if early:
        raise SystemExit(f'groth was imported before sg16/ref.py checked it: {early}')
    FINDER = install(generator_sources(REF, _verified))
if str(REF) not in sys.path:
    sys.path.insert(0, str(REF))
