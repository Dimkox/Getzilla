"""Project ingestion: one canonical baseline for a plain folder, a local Git repository or a fetched snapshot.

`inspect_git_input` reads an existing repository's commit/tree identity without writing to it or
touching the network (`--no-optional-locks`, no fetch, isolated config): dirty, unborn, shallow and
partial-clone states are reported, never repaired. History before the first available commit is
never claimed. `route_ingestion` sends a plain folder to the Zero-Git plan and any Git input to the
existing-history baseline; when the detected and declared kinds disagree it stops instead of
choosing a flow.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .source_models import GitIdentity, IngestPolicy, domain_digest

WORKING_SET_DOMAIN = 'getzilla-git-working-set-v1'
WORKFLOW_IDENTITY_FILES = ('.getzilla/AGBP_SYNC.json', '.getzilla/source-baseline.json')
SOURCE_KINDS = ('folder', 'local_git', 'remote_snapshot')


class IngestionError(ValueError):
    def __init__(self, reason_code: str, message: str = '') -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class IngestionBaseline:
    source_kind: str  # local_git, remote_snapshot
    root: str
    state: str  # clean, dirty, unborn
    identity: GitIdentity
    history: str  # complete, shallow, partial
    working_set_digest: str | None
    earliest_available_commits: tuple[str, ...]
    provenance_limits: tuple[str, ...]
    required_action: str | None = None
    origin: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'getzilla-ingestion-baseline-v1', 'source_kind': self.source_kind,
                'root': self.root, 'state': self.state, 'identity': self.identity.to_dict(), 'history': self.history,
                'working_set_digest': self.working_set_digest,
                'earliest_available_commits': list(self.earliest_available_commits),
                'prehistory': 'not_recorded', 'provenance_limits': list(self.provenance_limits),
                'required_action': self.required_action, 'origin': dict(self.origin)}


def _env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0',
                'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_LAZY_FETCH': '1', 'LC_ALL': 'C'})
    return env


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    command = ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
               '-c', 'protocol.allow=never', '-C', str(root), *args]
    result = subprocess.run(command, capture_output=True, check=False, env=_env())
    if check and result.returncode != 0:
        raise IngestionError('GIT_READ_FAILED', result.stderr.decode('utf-8', 'replace').strip()[:200])
    return result


def _out(root: Path, *args: str) -> str:
    return _git(root, *args).stdout.decode('utf-8', 'surrogateescape').strip()


def git_marker(root: Path) -> str | None:
    """'dir' for a .git directory, 'gitfile' for a worktree/submodule pointer, else None (no link follow)."""
    marker = root / '.git'
    if marker.is_symlink():
        return 'link'
    if marker.is_dir():
        return 'dir'
    if marker.is_file():
        return 'gitfile'
    return None


def enclosing_worktree(root: Path) -> Path | None:
    """The top level of a repository that contains `root` from a parent directory, if any."""
    result = _git(root, 'rev-parse', '--show-toplevel', check=False)
    if result.returncode != 0:
        return None
    top = Path(result.stdout.decode('utf-8', 'surrogateescape').strip())
    return None if top.resolve() == root.resolve() else top


def _working_set_digest(root: Path, status: bytes, policy: IngestPolicy) -> str:
    items = []
    fields = status.split(b'\0')
    index = 0
    while index < len(fields):
        entry = fields[index]
        index += 1
        if not entry:
            continue
        code, path = entry[:2].decode('ascii'), entry[3:].decode('utf-8', 'surrogateescape')
        if code[0] in 'RC':
            index += 1  # skip the rename source
        target = root / path
        digest = None
        if target.is_file() and not target.is_symlink():
            size = target.stat().st_size
            if size > policy.max_file_bytes:
                digest = f'over-limit:{size}'
            else:
                digest = hashlib.sha256(target.read_bytes()).hexdigest()
        elif target.is_symlink():
            digest = 'link:' + hashlib.sha256(os.readlink(target).encode('utf-8', 'surrogateescape')).hexdigest()
        items.append({'path': path, 'status': code, 'sha256': digest})
    return domain_digest(WORKING_SET_DOMAIN, sorted(items, key=lambda item: item['path']))


def inspect_git_input(root: Path, policy: IngestPolicy, *, source_kind: str = 'local_git',
                      origin: Mapping[str, Any] | None = None) -> IngestionBaseline:
    """Read-only identity of an existing repository; never commits, fetches or rewrites history."""
    if source_kind not in ('local_git', 'remote_snapshot'):
        raise IngestionError('UNSUPPORTED_SOURCE_KIND')
    root = Path(root)
    if git_marker(root) not in ('dir', 'gitfile'):
        raise IngestionError('NOT_A_GIT_REPOSITORY')
    if _out(root, 'rev-parse', '--is-bare-repository') == 'true':
        raise IngestionError('BARE_REPOSITORY_HAS_NO_WORKING_SET')
    object_format = _out(root, 'rev-parse', '--show-object-format') or 'sha1'
    limits = []
    head = _git(root, 'rev-parse', '--verify', '--quiet', 'HEAD^{commit}', check=False)
    if head.returncode != 0:
        return IngestionBaseline(source_kind, str(root), 'unborn', GitIdentity(object_format), 'complete', None, (),
                                 ('NO_COMMIT_YET',), 'FIRST_COMMIT_REQUIRES_SEPARATE_FLOW', dict(origin or {}))
    commit_oid = head.stdout.decode().strip()
    tree_oid = _out(root, 'rev-parse', f'{commit_oid}^{{tree}}')
    history = 'complete'
    if _out(root, 'rev-parse', '--is-shallow-repository') == 'true':
        history = 'shallow'
        limits.append('SHALLOW_HISTORY')
    promisor = _git(root, 'config', '--get', 'extensions.partialClone', check=False).stdout.strip()
    if promisor or list((Path(_out(root, 'rev-parse', '--absolute-git-dir')) / 'objects' / 'pack').glob('*.promisor')):
        history = 'partial' if history == 'complete' else history
        limits.append('PARTIAL_CLONE_OBJECTS_MAY_BE_MISSING')
    roots = tuple(_out(root, 'rev-list', '--max-parents=0', commit_oid).split())
    if history != 'complete':
        limits.append('EARLIEST_COMMITS_ARE_A_BOUNDARY_NOT_AN_ORIGIN')
    limits.append('NO_PROVENANCE_BEFORE_EARLIEST_AVAILABLE_COMMIT')
    status = _git(root, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignore-submodules=none').stdout
    state = 'dirty' if status else 'clean'
    digest = _working_set_digest(root, status, policy) if status else None
    return IngestionBaseline(source_kind, str(root), state, GitIdentity(object_format, commit_oid, tree_oid), history,
                             digest, roots, tuple(limits), None, dict(origin or {}))


@dataclass(frozen=True)
class IngestionRoute:
    route: str  # zero_git_plan, existing_git_baseline, blocked
    source_kind: str | None
    root: str
    reasons: tuple[str, ...] = ()
    baseline: IngestionBaseline | None = None
    workflow_identity: Mapping[str, str] = field(default_factory=dict)
    next_command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'getzilla-ingestion-route-v1', 'route': self.route, 'source_kind': self.source_kind,
                'root': self.root, 'reasons': list(self.reasons),
                'baseline': None if self.baseline is None else self.baseline.to_dict(),
                'workflow_identity': dict(self.workflow_identity), 'next_command': self.next_command}


def existing_workflow_identity(root: Path) -> dict[str, str]:
    """Digests of the workflow records already in the project; they are reused, never recreated."""
    found = {}
    for name in WORKFLOW_IDENTITY_FILES:
        path = root / name
        if path.is_file() and not path.is_symlink():
            found[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


def route_ingestion(input_spec: Mapping[str, Any], policy: IngestPolicy) -> IngestionRoute:
    """input_spec: {'path', optional 'kind' (folder/local_git/remote_snapshot), optional 'origin'}."""
    root = Path(input_spec['path'])
    declared = input_spec.get('kind')
    if declared is not None and declared not in SOURCE_KINDS:
        return IngestionRoute('blocked', None, str(root), ('UNKNOWN_INPUT_KIND',))
    if not root.is_dir() or root.is_symlink():
        return IngestionRoute('blocked', declared, str(root), ('INPUT_NOT_A_DIRECTORY',))
    marker = git_marker(root)
    if marker == 'link':
        return IngestionRoute('blocked', declared, str(root), ('GIT_MARKER_IS_A_LINK',))
    parent = None if marker else enclosing_worktree(root)
    detected = 'git' if marker else ('inside_repository' if parent else 'folder')
    if detected == 'inside_repository':
        return IngestionRoute('blocked', declared, str(root), ('INSIDE_PARENT_GIT_WORKTREE',),
                              next_command=f'inspect the enclosing repository {parent} instead')
    if declared == 'folder' and detected == 'git':
        return IngestionRoute('blocked', declared, str(root), ('AMBIGUOUS_INPUT_DECLARED_FOLDER_HAS_GIT',))
    if declared in ('local_git', 'remote_snapshot') and detected == 'folder':
        return IngestionRoute('blocked', declared, str(root), ('AMBIGUOUS_INPUT_DECLARED_GIT_HAS_NO_GIT',))
    if declared == 'remote_snapshot' and not input_spec.get('origin'):
        return IngestionRoute('blocked', declared, str(root), ('REMOTE_SNAPSHOT_WITHOUT_ORIGIN',))
    identity = existing_workflow_identity(root)
    if detected == 'folder':
        return IngestionRoute('zero_git_plan', 'folder', str(root), (), None, identity,
                              'getzilla adopt plan --source <folder> --target <new folder>')
    kind = declared or 'local_git'
    try:
        baseline = inspect_git_input(root, policy, source_kind=kind, origin=input_spec.get('origin'))
    except IngestionError as error:
        return IngestionRoute('blocked', kind, str(root), (error.reason_code,), workflow_identity=identity)
    if baseline.state == 'unborn':
        return IngestionRoute('blocked', kind, str(root), (baseline.required_action,), baseline, identity)
    return IngestionRoute('existing_git_baseline', kind, str(root), baseline.provenance_limits, baseline, identity,
                          'getzilla install-into --plan <repository>')
