"""Inert adapter-removal plans. Publication belongs to the guarded Git updater.

Only generated outputs with exact current ownership are eligible. Shared sources,
legacy helpers and unknown files are never removal candidates. Native settings
lose only exact stock hook groups; retained fragments lose ownership authority.
"""
from __future__ import annotations

import copy
import json
import math
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import harnesses, fsx
from .spec import SpecError, _parse_canonical_json
from .component_state import (
    MANIFEST, STACK_SYNC_RECORD, LEGACY_STACK_SYNC_RECORD, BoundRoot, ComponentStateError,
    ComponentTransaction, FileSnapshot, component_transaction, agent_of, encode_manifest, matches_owned,
    mode_matches, owned_proof, read_keep_contract, read_state, validate_agents,
    validate_manifest_publication, match_kept_local,
)

MAX_NATIVE_BYTES = 262144
NATIVE_CONFIGS = frozenset({'.qwen/settings.json', '.claude/settings.json', '.gemini/settings.json',
                            '.grok/hooks.json', '.codex/hooks.json', '.github/hooks/getzilla.json'})


@dataclass
class RemovalPlan:
    changes: list[tuple[str, bytes | None, str]]
    observations: dict[str, FileSnapshot | None]
    manifest: dict
    removed_agents: tuple[str, ...]
    retained: list[str]
    native_state: str = 'unverified'


def _native(content: bytes) -> dict:
    if len(content) > MAX_NATIVE_BYTES:
        raise ComponentStateError('native configuration exceeds removal bound')
    try:
        value = _parse_canonical_json(content, Path('adapter-native-configuration.json'))
    except SpecError as exc:
        raise ComponentStateError('invalid native configuration for removal') from exc
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is float and not math.isfinite(item):
            raise ComponentStateError('nonfinite native configuration value')
        if type(item) is dict:
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    if type(value) is not dict or type(value.get('hooks', {})) is not dict or len(value.get('hooks', {})) > 64:
        raise ComponentStateError('invalid native hook configuration for removal')
    for event, groups in value.get('hooks', {}).items():
        if type(event) is not str or type(groups) is not list or len(groups) > 1024:
            raise ComponentStateError('invalid native hook groups for removal')
        if any(type(group) is not dict for group in groups):
            raise ComponentStateError('invalid native hook group for removal')
    return value


def _stock_guards(source: BoundRoot, agent: str) -> dict:
    events = harnesses._hook_events(source)
    if agent == 'copilot':
        return harnesses._copilot_hooks(events)['hooks']
    if agent == 'gemini':
        return harnesses._renamed_hooks_block(events, harness=agent, names=harnesses.GEMINI_EVENTS)
    return harnesses._hooks_block(events, harness=agent, milliseconds=agent == 'qwen',
                                  only=harnesses.CODEX_HOOK_EVENTS if agent == 'codex' else None)


def _subtract(content: bytes, expected: bytes, guards: dict) -> bytes | None:
    data = _native(content)
    stock = _native(expected)
    hooks = data.get('hooks', {})
    for event, groups in list(hooks.items()):
        allowed = guards.get(event, [])
        seen = []
        remaining = []
        for group in groups:
            if group in allowed:
                if group in seen:
                    raise ComponentStateError('duplicate managed native hook group requires reconciliation')
                seen.append(group)
            elif any(token in json.dumps(group, ensure_ascii=False) for token in ('.getzilla/hooks/', '.grok/hooks/')):
                raise ComponentStateError('modified or unknown managed native hook requires reconciliation')
            else:
                remaining.append(group)
        if remaining:
            hooks[event] = remaining
        else:
            del hooks[event]
    if not hooks:
        data.pop('hooks', None)
    if not hooks and 'context' in stock and data.get('context') == stock['context']:
        data.pop('context')
    if data == {'version': 1} and stock.get('version') == 1:
        data = {}
    encoded = harnesses._json(data) if data else None
    if encoded is not None and len(encoded) > MAX_NATIVE_BYTES:
        raise ComponentStateError('native configuration output exceeds removal bound')
    return encoded


def codex_retained_configuration(canonical: bytes, overlay: bytes) -> bytes | None:
    """Exact stock removal state admitted by on-demand reactivation."""
    full = harnesses.render_codex_hooks(canonical, overlay)
    guards = harnesses._hooks_block(harnesses._events_from_bytes(canonical), harness='codex',
                                    milliseconds=False, only=harnesses.CODEX_HOOK_EVENTS)
    return _subtract(full, full, guards)


def plan_removal(home: Path, binding: BoundRoot | ComponentTransaction,
                 agents: tuple[str, ...] | None = None) -> RemovalPlan:
    """Build one complete refusal-first plan without writing product or Git state."""
    state = read_state(binding.path, binding=binding)
    selected = state.require_selection()
    requested = selected if agents is None else validate_agents(agents)
    removing = tuple(agent for agent in selected if agent in requested)
    manifest = copy.deepcopy(state.manifest)
    observations = {MANIFEST: binding.read(MANIFEST), STACK_SYNC_RECORD: binding.read(STACK_SYNC_RECORD),
                    LEGACY_STACK_SYNC_RECORD: binding.read(LEGACY_STACK_SYNC_RECORD)}
    if not removing:
        return RemovalPlan([], observations, manifest, (), [])
    with BoundRoot(home) as source:
        outputs = harnesses._render(source, removing)
        # Grok uses native Markdown briefs and a stock config copied by the
        # installer, alongside the renderer's hooks and skill outputs.
        if 'grok' in removing:
            for path in [*source.files('.grok/agents'), '.grok/config.toml']:
                if path.endswith('.md') or path == '.grok/config.toml':
                    snapshot = source.read(path)
                    if snapshot is None:
                        raise ComponentStateError(f'missing canonical Grok source: {path}')
                    outputs[path] = snapshot.content
        guards = {agent: _stock_guards(source, agent) for agent in removing}
    kept, digests = read_keep_contract(binding)
    kept, digests = match_kept_local(kept, digests, {*outputs, MANIFEST})
    changes = []
    retained = []
    # Config first: Codex activation must remain when Entire/custom hooks remain.
    retained_activation = set()
    paths = sorted(outputs, key=lambda path: (path not in NATIVE_CONFIGS, path))
    for path in paths:
        current = binding.read(path, limit=MAX_NATIVE_BYTES) if path in NATIVE_CONFIGS else binding.read(path)
        observations[path] = current
        if current is None:
            continue
        if path in retained_activation:
            retained.append(path)
            continue  # no write; unknown/kept activation is not removal authority
        if path in kept:
            raise ComponentStateError(f'kept adapter output requires reconciliation before removal: {path}')
        if not matches_owned(current, owned_proof(state.manifest, path)):
            raise ComponentStateError(f'adapter ownership bytes/mode conflict before removal: {path}')
        if not mode_matches(current.mode, 0o644):
            raise ComponentStateError(f'custom adapter file mode requires reconciliation before removal: {path}')
        content = None
        if path in NATIVE_CONFIGS:
            content = _subtract(current.content, outputs[path], guards[agent_of(path)])
            if content is not None and path in {'.codex/hooks.json', '.grok/hooks.json'}:
                retained_activation.add(path.removesuffix('hooks.json') + 'config.toml')
        elif current.content != outputs[path] or not mode_matches(current.mode, 0o644):
            raise ComponentStateError(f'custom generated adapter file requires reconciliation before removal: {path}')
        if content is not None:
            retained.append(path)
        if content != current.content:
            changes.append((path, content, '100644' if content is not None else ''))
            for component in manifest['components'].values():
                component.get('owned', {}).pop(path, None)
                if content is None and path in component['files']:
                    component['files'].remove(path)
        elif path in NATIVE_CONFIGS:
            # Exact unchanged foreign-only settings confer no future replacement authority.
            for component in manifest['components'].values():
                component.get('owned', {}).pop(path, None)
    manifest['agents'] = [agent for agent in selected if agent not in removing]
    encoded = encode_manifest(manifest)
    validate_manifest_publication(observations[MANIFEST], encoded, kept, digests)
    changes.append((MANIFEST, encoded, '100644'))
    return RemovalPlan(changes, observations, manifest, removing, sorted(retained))


class UpdateError(RuntimeError):
    pass



def git(cwd: Path, *args: str, data: bytes | None = None,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run git in cwd; output stays bytes when data is given, else text."""
    return subprocess.run(['git', '-C', str(cwd), *args], input=data, capture_output=True,
                          text=data is None, encoding='utf-8' if data is None else None,
                          errors='replace' if data is None else None, env=env, check=False)



def _git_out(cwd: Path, *args: str, data: bytes | None = None, env: dict[str, str] | None = None) -> str:
    proc = git(cwd, *args, data=data, env=env)
    out, err = proc.stdout, proc.stderr
    if isinstance(out, bytes):
        out, err = out.decode('utf-8', 'replace'), err.decode('utf-8', 'replace')
    if proc.returncode != 0:
        raise UpdateError(f"git {args[0]} failed in {cwd}: {(err or out).strip()}")
    return out.strip()



def head_tree(project: Path, ref: str = 'HEAD') -> dict[str, tuple[str, str]]:
    """path -> (mode, object id) for every file and link committed at HEAD."""
    raw = git(project, 'ls-tree', '-r', '-z', '--full-tree', ref, data=b'')
    if raw.returncode != 0:
        raise UpdateError(f'{project} has no commit yet: commit once first')
    tree = {}
    for record in raw.stdout.split(b'\0'):
        if record:
            meta, path = record.split(b'\t', 1)
            mode, _kind, oid = meta.decode().split()
            tree[path.decode('utf-8', 'surrogateescape')] = (mode, oid)
    return tree



def commit_changes(project: Path, changes: list[tuple[str, bytes | None, str]], message: str, *, expected_head: str) -> str:
    """Build the commit in a private index; the work tree and the project's index stay untouched.

    A change with content None removes that path.
    """
    zero = '0' * len(expected_head)
    with tempfile.TemporaryDirectory(prefix='getzilla-update-') as scratch:
        env = {**os.environ, 'GIT_INDEX_FILE': str(Path(scratch) / 'index')}
        _git_out(project, 'read-tree', expected_head, env=env)
        lines = []
        for path, content, mode in changes:
            if content is None:
                lines.append(f'0 {zero}\t{path}')
                continue
            oid = _git_out(project, 'hash-object', '-w', '--stdin', data=content)
            lines.append(f'{mode} {oid}\t{path}')
        _git_out(project, 'update-index', '--index-info', data=('\n'.join(lines) + '\n').encode('utf-8'), env=env)
        tree = _git_out(project, 'write-tree', env=env)
    return _git_out(project, 'commit-tree', tree, '-p', expected_head, '-m', message)



def _require_clean_project(project: Path) -> None:
    top = git(project, 'rev-parse', '--show-toplevel')
    if top.returncode != 0 or os.path.normcase(fsx.system_canonical(top.stdout.strip())) != os.path.normcase(str(project)):
        raise UpdateError(f'{project} is not the root of a Git repository')
    status = _git_out(project, 'status', '--porcelain', '--untracked-files=all',
                      env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0'})
    # The persistent administrative guard is not product content. Every other
    # tracked or untracked change still blocks the update.
    if any(line != '?? .getzilla/runtime/.components.guard.lock' for line in status.splitlines()):
        raise UpdateError(f'{project} has uncommitted changes: commit or stash them first')



def _committed_manifest(project: Path, binding: BoundRoot | ComponentTransaction, head: str,
                        tree: dict[str, tuple[str, str]]):
    state = read_state(project, binding=binding)
    state.require_selection()
    snapshot = binding.read(MANIFEST)
    committed = git(project, 'cat-file', 'blob', f'{head}:{MANIFEST}', data=b'')
    if (tree.get(MANIFEST, ('', ''))[0] != '100644' or committed.returncode != 0
            or snapshot is None or snapshot.content != committed.stdout):
        raise UpdateError('the selected component manifest must be a committed regular file; review and commit it before updating')
    return state, snapshot



def _publish_changes(project: Path, transaction: ComponentTransaction, changes: list, observations: dict,
                     expected_head: str, branch: str, message: str, check_current, *,
                     retained_ignored: frozenset[str] = frozenset()) -> str:
    """Shared guarded Git publication; no direct deletion or new recovery ledger."""
    _git_out(project, 'check-ref-format', '--branch', branch)
    if git(project, 'rev-parse', '--verify', '--quiet', f'refs/heads/{branch}').returncode == 0:
        raise UpdateError(f'branch {branch} already exists in {project}: merge or delete it first')
    # `git switch` overwrites ignored files without asking; an ignored local file on a managed path is work.
    ignored = _git_out(project, 'ls-files', '--others', '--ignored', '--exclude-standard', '--',
                       *(path for path, _, _ in changes))
    if ignored:
        raise UpdateError(f'ignored local files sit on managed paths; move them first: {", ".join(ignored.splitlines())}')
    check_current()
    commit = commit_changes(project, changes, message, expected_head=expected_head)
    check_current()
    # Verify the pinned parent and create an absent branch in one Git ref
    # transaction. A concurrent writer cannot replace an existing update branch.
    commands = f'start\nverify HEAD {expected_head}\ncreate refs/heads/{branch} {commit}\nprepare\ncommit\n'
    _git_out(project, 'update-ref', '--stdin', data=commands.encode('utf-8'))
    try:
        check_current()
    except (UpdateError, ValueError, OSError) as exc:
        raise UpdateError(f'update branch {branch} retained at {commit}; checkout not completed: {exc}') from exc
    switched = git(project, 'switch', '--quiet', branch)
    if switched.returncode != 0:
        raise UpdateError(f'commit is on branch {branch}, but checking it out failed: '
                          f'{switched.stderr.strip()}; run `git switch {branch}`')
    try:
        transaction.check()
        if (_git_out(project, 'rev-parse', 'HEAD') != commit
                or git(project, 'symbolic-ref', '-q', 'HEAD').stdout.strip() != f'refs/heads/{branch}'):
            raise UpdateError('HEAD or branch changed after checkout')
        _require_clean_project(project)
        expected_files = {path: (snapshot.content, snapshot.mode) if snapshot is not None else (None, 0)
                          for path, snapshot in observations.items()}
        expected_files.update({path: (content, 0o755 if mode == '100755' else 0o644)
                               for path, content, mode in changes})
        for path, (content, mode) in expected_files.items():
            snapshot = transaction.read(path)
            if path in retained_ignored and snapshot != observations[path]:
                raise UpdateError(f'retained ignored file changed after checkout: {path}')
            if ((content is None and snapshot is not None)
                    or (content is not None and (snapshot is None or snapshot.content != content
                                                or not mode_matches(snapshot.mode, mode)))):
                raise UpdateError(f'project file differs after checkout: {path}')
        transaction.check()
        if (_git_out(project, 'rev-parse', 'HEAD') != commit
                or git(project, 'symbolic-ref', '-q', 'HEAD').stdout.strip() != f'refs/heads/{branch}'):
            raise UpdateError('HEAD or branch changed while checking the checkout')
    except (UpdateError, ValueError, OSError) as exc:
        raise UpdateError(f'update branch {branch} retained at {commit}; update incomplete after checkout: {exc}') from exc
    return commit



def remove_adapters(home: Path, project: Path, agents: tuple[str, ...] | None = None) -> dict:
    """Remove selected adapters in one guarded Git commit; never operate a live client."""
    from getzilla.on_demand import is_installed_project, is_source_checkout
    project = Path(fsx.system_canonical(project))
    try:
        if is_source_checkout(project) or not is_installed_project(project):
            raise UpdateError('adapter removal requires an installed consumer project, not a source checkout')
        # Refuse before even taking the administrative guard when the plan is unsafe.
        with BoundRoot(project) as binding:
            _require_clean_project(project)
            head = _git_out(project, 'rev-parse', 'HEAD')
            _committed_manifest(project, binding, head, head_tree(project, head))
            plan_removal(home, binding, agents)
        with component_transaction(project) as transaction:
            _require_clean_project(project)
            expected_head = _git_out(project, 'rev-parse', 'HEAD')
            expected_branch = git(project, 'symbolic-ref', '-q', 'HEAD').stdout.strip()
            _committed_manifest(project, transaction, expected_head, head_tree(project, expected_head))
            plan = plan_removal(home, transaction, agents)

            def check_current() -> None:
                transaction.check()
                if (_git_out(project, 'rev-parse', 'HEAD') != expected_head
                        or git(project, 'symbolic-ref', '-q', 'HEAD').stdout.strip() != expected_branch):
                    raise UpdateError('project HEAD or branch changed during adapter removal')
                _require_clean_project(project)
                for path, snapshot in plan.observations.items():
                    if transaction.read(path) != snapshot:
                        raise UpdateError(f'project file changed during adapter removal: {path}')

            check_current()
            branch = None
            commit = expected_head
            if plan.changes:
                branch = 'getzilla-remove-' + expected_head[:12] + '-' + '-'.join(sorted(plan.removed_agents))
                commit = _publish_changes(project, transaction, plan.changes, plan.observations, expected_head,
                                          branch, 'chore: remove Getzilla adapters ' + ', '.join(plan.removed_agents),
                                          check_current)
            return {'removed_agents': list(plan.removed_agents), 'selection': plan.manifest['agents'],
                    'configuration': 'removed' if plan.changes else 'unchanged', 'branch': branch,
                    'commit': commit, 'retained': plan.retained, 'live_client_state': plan.native_state}
    except (ComponentStateError, OSError, ValueError) as exc:
        raise UpdateError(str(exc)) from exc
