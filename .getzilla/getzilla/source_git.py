"""Local Git baseline in the owned shadow, without hooks, filters, templates or network.

Git runs with no system or global configuration, an empty template, an empty hooks directory,
no filters (blobs are written with `hash-object --no-filters` from the verified bytes), no
signing and no transports. The index is filled from an explicit allowlist (`update-index
--index-info`), never `git add .`, and the written tree is compared entry by entry with the
manifest. Commits are created with `commit-tree`, which runs no hooks.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .source_models import GitIdentity
from .source_snapshot import AdoptionError

AUTHOR_NAME = 'Getzilla Import'
AUTHOR_EMAIL = 'import@getzilla.invalid'


@dataclass(frozen=True)
class GitEntry:
    path: str
    mode: str  # '100644' or '100755'
    content: bytes


@dataclass(frozen=True)
class GitBaselineReceipt:
    identity: GitIdentity
    author: str
    timestamp: str
    message: str

    def to_dict(self) -> dict:
        return {'identity': self.identity.to_dict(), 'author': self.author, 'timestamp': self.timestamp,
                'message': self.message}


class IsolatedGit:
    """Git commands confined to one repository with no ambient configuration or code execution."""

    def __init__(self, work_tree: Path, *, timestamp: str) -> None:
        executable = shutil.which('git')
        if executable is None:
            raise AdoptionError('TOOL_ERROR', 'git is not installed')
        self.git = executable
        self.work_tree = work_tree
        self.timestamp = timestamp
        self._scratch = tempfile.TemporaryDirectory(prefix='getzilla-git-')
        scratch = Path(self._scratch.name)
        (scratch / 'template').mkdir()
        (scratch / 'hooks').mkdir()
        (scratch / 'home').mkdir()
        empty_config = scratch / 'empty.gitconfig'
        empty_config.write_bytes(b'')
        self.template = scratch / 'template'
        self.empty = empty_config
        self.hooks = scratch / 'hooks'
        base = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP') if key in os.environ}
        self.env = {
            **base, 'HOME': str(scratch / 'home'), 'USERPROFILE': str(scratch / 'home'),
            'XDG_CONFIG_HOME': str(scratch / 'home'), 'GIT_CONFIG_NOSYSTEM': '1',
            'GIT_CONFIG_GLOBAL': str(empty_config), 'GIT_ATTR_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
            'GIT_TEMPLATE_DIR': str(self.template), 'LC_ALL': 'C', 'LANG': 'C',
            'GIT_AUTHOR_NAME': AUTHOR_NAME, 'GIT_AUTHOR_EMAIL': AUTHOR_EMAIL, 'GIT_AUTHOR_DATE': timestamp,
            'GIT_COMMITTER_NAME': AUTHOR_NAME, 'GIT_COMMITTER_EMAIL': AUTHOR_EMAIL, 'GIT_COMMITTER_DATE': timestamp,
            'GIT_OPTIONAL_LOCKS': '0',
        }

    def close(self) -> None:
        self._scratch.cleanup()

    def __enter__(self) -> IsolatedGit:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def run(self, *args: str, stdin: bytes | None = None, check: bool = True) -> bytes:
        command = [self.git, '-C', str(self.work_tree),
                   '-c', f'core.hooksPath={self.hooks}', '-c', 'core.fsmonitor=false', '-c', 'core.autocrlf=false',
                   '-c', 'core.safecrlf=false', '-c', 'commit.gpgSign=false', '-c', 'tag.gpgSign=false',
                   '-c', 'gc.auto=0', '-c', 'protocol.allow=never', '-c', f'core.attributesFile={self.empty}',
                   '-c', f'core.excludesFile={self.empty}', '-c', 'init.templateDir=' + str(self.template), *args]
        proc = subprocess.run(command, input=stdin, capture_output=True, env=self.env, check=False, timeout=600)
        if check and proc.returncode != 0:
            raise AdoptionError('TOOL_ERROR', f'git {args[0]} failed: {proc.stderr.decode("utf-8", "replace")[-400:]}')
        return proc.stdout


def blob_oid(content: bytes) -> str:
    return hashlib.sha1(b'blob %d\x00' % len(content) + content).hexdigest()  # nosec B324 - Git object id


def init_repository(git: IsolatedGit) -> None:
    if (git.work_tree / '.git').exists():
        raise AdoptionError('BLOCKED_UNSAFE_SOURCE', 'the shadow already contains Git metadata')
    git.run('init', '-q', f'--template={git.template}', '--initial-branch=main', '--object-format=sha1')


def write_tree(git: IsolatedGit, entries: Sequence[GitEntry], *, replace_index: bool) -> str:
    """Write exactly `entries` (plus the current index when not replacing) and verify the tree."""
    lines: list[bytes] = []
    for entry in entries:
        oid = git.run('hash-object', '-w', '--no-filters', '--stdin', stdin=entry.content).decode().strip()
        if oid != blob_oid(entry.content):
            raise AdoptionError('VERIFICATION_FAILED', f'blob id mismatch for {entry.path}')
        lines.append(f'{entry.mode} {oid}\t{entry.path}\n'.encode('utf-8'))
    if replace_index:
        git.run('read-tree', '--empty')
    git.run('update-index', '--index-info', stdin=b''.join(lines))
    return git.run('write-tree').decode().strip()


def tree_entries(git: IsolatedGit, tree: str) -> dict[str, tuple[str, str]]:
    raw = git.run('ls-tree', '-r', '-z', '--full-tree', tree)
    result: dict[str, tuple[str, str]] = {}
    for record in raw.split(b'\x00'):
        if not record:
            continue
        meta, path = record.split(b'\t', 1)
        mode, kind, oid = meta.decode().split(' ')
        if kind != 'blob':
            raise AdoptionError('VERIFICATION_FAILED', f'unexpected {kind} in tree')
        result[path.decode('utf-8')] = (mode, oid)
    return result


def expect_tree(git: IsolatedGit, tree: str, entries: Iterable[GitEntry]) -> None:
    expected = {entry.path: (entry.mode, blob_oid(entry.content)) for entry in entries}
    if tree_entries(git, tree) != expected:
        raise AdoptionError('VERIFICATION_FAILED', 'Git tree does not equal the approved manifest')


def commit(git: IsolatedGit, tree: str, message: str, parent: str | None = None) -> str:
    args = ['commit-tree', tree, *(['-p', parent] if parent else []), '-F', '-']
    oid = git.run(*args, stdin=message.encode('utf-8')).decode().strip()
    git.run('update-ref', 'refs/heads/main', oid, parent or '0' * 40)
    return oid


def source_commit_message(source_digest: str, admitted: int, excluded: int) -> str:
    kind = 'admitted source baseline' if excluded else 'source baseline'
    return (f'Import {kind} ({admitted} files)\n\n'
            'Created by Getzilla Zero-Git adoption from a folder without Git history.\n\n'
            'Getzilla-Import: zero-git\n'
            f'Getzilla-Source-SHA256: {source_digest}\n'
            'Getzilla-Baseline-Schema: source-baseline-v1\n')


def create_git_baseline(shadow: Path, entries: Sequence[GitEntry], *, source_digest: str, excluded: int,
                        timestamp: str) -> GitBaselineReceipt:
    with IsolatedGit(shadow, timestamp=timestamp) as git:
        init_repository(git)
        tree = write_tree(git, entries, replace_index=True)
        expect_tree(git, tree, entries)
        message = source_commit_message(source_digest, len(entries), excluded)
        oid = commit(git, tree, message)
        if git.run('remote').strip():
            raise AdoptionError('VERIFICATION_FAILED', 'a remote appeared in the shadow repository')
    return GitBaselineReceipt(GitIdentity('sha1', commit_oid=oid, tree_oid=tree),
                              author=f'{AUTHOR_NAME} <{AUTHOR_EMAIL}>', timestamp=timestamp, message=message)
