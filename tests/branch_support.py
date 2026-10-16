"""Isolated Git fixtures for the branch lifecycle tests; never touches the real Getzilla repository."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.branch_lifecycle import MergeProof, RefInfo, RefsSnapshot  # noqa: E402

OID = {name: (str(index) * 40)[:40] for index, name in enumerate('abcdefgh', start=1)}


def env(date: str = '2026-01-01T00:00:00Z') -> dict[str, str]:
    values = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    values.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_AUTHOR_NAME': 't',
                   'GIT_AUTHOR_EMAIL': 't@example.invalid', 'GIT_COMMITTER_NAME': 't',
                   'GIT_COMMITTER_EMAIL': 't@example.invalid', 'GIT_AUTHOR_DATE': date, 'GIT_COMMITTER_DATE': date})
    return values


def git(repo: Path, *args: str, date: str = '2026-01-01T00:00:00Z') -> str:
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True, text=True, check=True,
                          env=env(date)).stdout.strip()


def commit(repo: Path, name: str, text: str, message: str, date: str = '2026-01-01T00:00:00Z') -> str:
    (repo / name).write_text(text, encoding='utf-8')
    git(repo, 'add', name)
    git(repo, 'commit', '-q', '-m', message, date=date)
    return git(repo, 'rev-parse', 'HEAD')


def make_remote(base: Path) -> tuple[Path, dict[str, str]]:
    """Bare remote with: main, merged (ancestor), squashed (tree-equal), unmerged (old date), newer (new date)."""
    work = base / 'work'
    work.mkdir()
    git(work, 'init', '-q', '-b', 'main')
    commit(work, 'a.txt', 'a\n', 'base')
    git(work, 'switch', '-q', '-c', 'merged')
    merged = commit(work, 'm.txt', 'm\n', 'merged work')
    git(work, 'switch', '-q', 'main')
    git(work, 'merge', '-q', '--ff-only', 'merged')
    git(work, 'switch', '-q', '-c', 'squashed')
    commit(work, 's1.txt', '1\n', 's1')
    squashed = commit(work, 's2.txt', '2\n', 's2')
    git(work, 'switch', '-q', 'main')
    git(work, 'merge', '-q', '--squash', 'squashed')
    git(work, 'commit', '-q', '-m', 'squash merge')
    git(work, 'switch', '-q', '-c', 'unmerged', 'HEAD~1')
    unmerged = commit(work, 'old.txt', 'old\n', 'old unmerged work', date='2020-01-01T00:00:00Z')
    git(work, 'switch', '-q', '-c', 'newer', 'main')
    newer = commit(work, 'n.txt', 'n\n', 'newest commit in the repository', date='2030-01-01T00:00:00Z')
    git(work, 'switch', '-q', '-c', 'release/2.2', 'main')
    git(work, 'switch', '-q', 'main')
    remote = base / 'remote.git'
    subprocess.run(['git', 'clone', '-q', '--bare', str(work), str(remote)], check=True, env=env(), capture_output=True)
    oids = {'main': git(remote, 'rev-parse', 'refs/heads/main'), 'merged': merged, 'squashed': squashed,
            'unmerged': unmerged, 'newer': newer}
    return remote, oids


def merged_prs(oids: dict[str, str], merged_at: str = '2026-01-01T00:00:00Z') -> dict[str, dict]:
    return {name: {'state': 'merged', 'head_oid': oids[name], 'merged_at': merged_at} for name in ('merged', 'squashed')}


def synthetic(refs: list[RefInfo], **kwargs) -> RefsSnapshot:
    return RefsSnapshot('main', OID['a'], (RefInfo('main', OID['a']), *refs), **kwargs)


def merged(name: str, oid: str, merged_at: str | None = '2026-01-01T00:00:00Z') -> RefInfo:
    return RefInfo(name, oid, merge_proof=MergeProof('ancestor', OID['a'], merged_at))
