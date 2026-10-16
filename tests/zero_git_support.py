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
FAKE_PRIVATE_KEY = '-----BEGIN ' + 'PRIVATE KEY-----\nTUlJ\n-----END ' + 'PRIVATE KEY-----\n'
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


def clean_source(root: Path) -> Path:
    return write_tree(root, {
        'README.md': '# demo\n',
        'app/__init__.py': '',
        'app/main.py': 'print("hello")\n',
        'scripts/run.sh': '#!/bin/sh\necho run\n',
        '.env.example': 'API_URL=https://example.invalid\n',
    }, executable=('scripts/run.sh',))
