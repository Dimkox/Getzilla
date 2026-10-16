"""Shared fixtures for Zero-Git tests: synthetic source trees and before/after snapshots."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

# Synthetic, non-functional secret markers assembled at runtime so no real-looking credential
# sits in the repository as one literal.
FAKE_GITHUB_TOKEN = 'ghp_' + 'Z' * 36
FAKE_KEY_MARKER = 'Z2V0emlsbGEtZmFrZS1rZXktbWFya2Vy'
FAKE_PRIVATE_KEY = '-----BEGIN ' + 'PRIVATE KEY-----\n' + FAKE_KEY_MARKER + '\n-----END ' + 'PRIVATE KEY-----\n'
FAKE_AWS_ID = 'AKIA' + 'Q' * 16


def write_tree(root: Path, files: dict[str, bytes | str], executable: tuple[str, ...] = ()) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode('utf-8') if isinstance(content, str) else content
        path.write_bytes(data)
        if relative in executable and os.name == 'posix':
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return root


def tree_state(root: Path) -> dict[str, tuple[str, bytes, int]]:
    """Every entry under root with type, bytes and permission bits (atime excluded)."""
    state: dict[str, tuple[str, bytes, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                state[relative] = ('dir', b'', stat.S_IMODE(info.st_mode))
            elif stat.S_ISLNK(info.st_mode):
                state[relative] = ('link', os.readlink(path).encode(), 0)
            else:
                state[relative] = ('file', path.read_bytes(), stat.S_IMODE(info.st_mode))
    return state


def plan_and_adopt(source: Path, target: Path, state_root: Path, policy=None):
    """Plan with the default (or given) policy and apply it; returns (plan, receipt)."""
    from getzilla.project_adoption import run_adoption
    from getzilla.source_admission import plan_source
    from getzilla.source_models import IngestPolicy
    plan = plan_source(source, target, policy or IngestPolicy())
    receipt = run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=state_root)
    return plan, receipt


def git_objects(repository: Path) -> list[bytes]:
    """Raw contents of every object in a repository (reachable or not)."""
    import subprocess
    listing = subprocess.run(['git', '-C', str(repository), 'cat-file', '--batch-all-objects', '--batch-check'],
                             capture_output=True, check=True).stdout.decode().split('\n')
    contents = []
    for line in listing:
        if not line.strip():
            continue
        oid = line.split()[0]
        contents.append(subprocess.run(['git', '-C', str(repository), 'cat-file', '-p', oid],
                                       capture_output=True, check=True).stdout)
    return contents


def clean_source(root: Path) -> Path:
    return write_tree(root, {
        'README.md': '# demo\n',
        'app/__init__.py': '',
        'app/main.py': 'print("hello")\n',
        'scripts/run.sh': '#!/bin/sh\necho run\n',
        '.env.example': 'API_URL=https://example.invalid\n',
    }, executable=('scripts/run.sh',))
