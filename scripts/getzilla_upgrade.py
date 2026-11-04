"""getzilla update: bring Getzilla, the current project and the third-party tools up to date.

1. core: Getzilla itself. A checkout on a branch fast-forwards; a detached checkout (what the
   installer makes) moves to the fetched ref. Local changes skip this step; they are never discarded.
2. project: the project around the current folder, or the path given. The managed files of the
   updated Getzilla (the same set `install_into.py --plan` lists) are committed on a new branch
   `getzilla-update-<version>`, which is then checked out. The commit is built in a private Git
   index. A failure before branch publication leaves product files unchanged; a later failure
   reports the retained branch or incomplete checkout. The project must be a clean Git
   work tree with committed v2 adapter selection. Nothing is pushed, nothing is deleted without --retire-legacy, and an up-to-date
   project gets no branch. Paths the
   project keeps (`.getzilla/AGBP_SYNC.json`) are left alone; in AGENTS.md only the managed block
   is replaced. The project's own ruff.toml, bandit.yaml and .coveragerc stay; --retire-legacy also removes
   committed pre-rename files (.grok-stack, scripts/grok_*) once nothing imports the old engine.
3. tools: the third-party tools, through `getzilla_update.py` as before.

`getzilla update` runs all three; `getzilla update core|project|tools` runs one. The tool options
(--only, --status, --if-due, --now, --quiet) keep their old meaning and run step 3 alone.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

HOME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HOME / '.getzilla'))

from getzilla import fsx
from getzilla.component_state import (
    MANIFEST, BoundRoot, ComponentStateError, ComponentTransaction,
    component_transaction, decode_manifest, encode_manifest, matches_owned, mode_matches,
    owned_proof, read_state, record_owned, read_keep_contract, match_kept_local, kept_file_state,
    validate_manifest_publication,
)
from getzilla.harnesses import render_codex_hooks
from getzilla.install_baseline import POLICY_PATHS, load_baseline

TOOL_OPTIONS = ('--only', '--status', '--if-due', '--now', '--quiet')
OWN_OPTIONS = ('--ref', '--no-self', '--no-tools', '--accept-local', '--retire-legacy', '--baseline-release', '--help')
BRANCH_PREFIX = 'getzilla-update-'
# Lint and coverage settings name the project's own paths and rules; Getzilla's copy is only a first default.
PROJECT_CONFIGS = frozenset({'ruff.toml', 'bandit.yaml', '.coveragerc'})
STEPS = {
    'core': 'update only Getzilla itself',
    'project': 'update only the project, on a new branch',
    'tools': 'update only the third-party tools (getzilla_update.py options apply)',
}


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


def update_self(home: Path, ref: str | None) -> str:
    """Move the Getzilla checkout forward; returns a one-line result."""
    if not (home / '.git').exists():
        return f'skip core: {home} is not a Git checkout'
    if _git_out(home, 'status', '--porcelain'):
        return f'skip core: {home} has local changes'
    before = _git_out(home, 'rev-parse', 'HEAD')
    branch = git(home, 'symbolic-ref', '-q', '--short', 'HEAD').stdout.strip()
    if branch and ref is not None:
        raise UpdateError(f'{home} is on branch {branch}: --ref works only for a detached checkout')
    if branch:
        _git_out(home, 'pull', '--ff-only', '--quiet')
    else:
        # Keep a full clone full; only a shallow one (the installer's) fetches shallow.
        shallow = _git_out(home, 'rev-parse', '--is-shallow-repository') == 'true'
        _git_out(home, 'fetch', '--quiet', *(['--depth', '1'] if shallow else []), 'origin', ref or 'main')
        _git_out(home, 'checkout', '--quiet', '--detach', 'FETCH_HEAD')
    after = _git_out(home, 'rev-parse', 'HEAD')
    return 'Getzilla is up to date' if after == before else f'Getzilla updated: {before[:12]} -> {after[:12]}'


def find_project(start: Path, home: Path) -> Path | None:
    """The nearest folder at or above start that carries Getzilla, unless it is Getzilla itself."""
    start = start.resolve()
    for base in (start, *start.parents):
        if (base / '.getzilla').is_dir() or (base / '.grok-stack').is_dir():
            return None if base == home.resolve() else base
    return None


def load_installer(home: Path):
    spec = importlib.util.spec_from_file_location('getzilla_install_into', home / 'scripts/install_into.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module while the class is built
    spec.loader.exec_module(module)
    return module


def merge_agents(installer, existing: bytes | None, block: bytes) -> bytes:
    """Replace only the managed block of the project's AGENTS.md; its own text stays."""
    if existing is None:
        return block
    try:
        text, managed = existing.decode('utf-8'), block.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise UpdateError('AGENTS.md is not UTF-8: convert it first') from exc
    start, end = text.find(installer.MANAGED_START), text.find(installer.MANAGED_END)
    if start < 0 and end < 0:
        return (text.rstrip('\n') + '\n\n' + managed).encode('utf-8') if text.strip() else block
    if start < 0 or end < start:
        raise UpdateError('AGENTS.md has a broken Getzilla managed block: fix its markers first')
    end += len(installer.MANAGED_END)
    if text[end:end + 1] == '\n':
        end += 1
    return (text[:start] + managed + text[end:]).encode('utf-8')


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


def blob_id(content: bytes, object_format: str) -> str:
    # A Git object id, not a security digest.
    digest = hashlib.sha256() if object_format == 'sha256' else hashlib.sha1(usedforsecurity=False)
    digest.update(b'blob %d\0' % len(content) + content)
    return digest.hexdigest()


def accept_local(installer, project: Path, ref: str = 'HEAD') -> tuple[dict[str, str], bytes | None, list[str]]:
    """Digests of the kept paths as committed now: (digests, new sync record or None, accepted paths).

    A kept path with a recorded digest stops the update once its bytes change. `--accept-local`
    records the committed bytes as the project's chosen version instead; it never changes them.
    """
    raw = git(project, 'cat-file', 'blob', f'{ref}:{installer.STACK_SYNC_RECORD}', data=b'')
    if raw.returncode != 0:
        return {}, None, []
    installer._kept_local(project)  # the same shape checks the plan applies
    record = json.loads(raw.stdout.decode('utf-8'))
    digests = dict(record.get('kept_local_sha256', {}))
    accepted = []
    for path, digest in sorted(digests.items()):
        blob = git(project, 'cat-file', 'blob', f'{ref}:{path}', data=b'')
        if blob.returncode != 0:
            continue  # an absent kept path is already allowed
        current = hashlib.sha256(blob.stdout).hexdigest()
        if current != digest:
            digests[path] = current
            accepted.append(path)
    if not accepted:
        return digests, None, []
    record['kept_local_sha256'] = digests
    return digests, (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8'), accepted


# Dated change evidence is a record of its day: it is listed, never rewritten, and never blocks retirement.
HISTORICAL_EVIDENCE = re.compile(r'^(?:engineering|\.getzilla/runtime)/changes/[^/]+/evidence/')


def legacy_report(installer, project: Path, tree: dict[str, tuple[str, str]],
                  incoming: set[str], ref: str = 'HEAD') -> tuple[list[str], list[str], list[str]]:
    """(committed pre-rename paths, project files that import the old engine, old engine paths the sync record keeps).

    Only a pre-rename file whose Getzilla replacement is committed or arrives with this update is
    retired; one without a replacement (a vendored factory the update does not install) stays.
    """
    present = set(tree) | incoming

    def replaced(path: str) -> bool:
        current = installer.legacy_to_current_path(path)
        # The engine may ship as one archive instead of a folder of modules.
        return current in present or (current.startswith(installer.ENGINE_DIR) and installer.ENGINE_ARCHIVE in present)

    retire = sorted(item['path'] for item in installer._legacy_migration(project)
                    if item['path'] in tree and replaced(item['path']))
    retired = set(retire)
    needles = ['-e', 'adaptive_grok', '-e', '.grok-stack/']
    if any(path.startswith('factory/src/adaptive_factory/') for path in retire):
        needles += ['-e', 'adaptive_factory']  # only when the old factory is retired, not while it is the live one
    found = git(project, '-c', 'core.quotepath=off', 'grep', '-l', '-I', '-F', *needles, ref, '--', '*.py')
    importers = sorted({line.split(':', 1)[1] for line in found.stdout.splitlines() if ':' in line} - retired) \
        if found.returncode == 0 else []
    record = git(project, 'cat-file', 'blob', f'{ref}:{installer.LEGACY_STACK_SYNC_RECORD}')
    kept = []
    if record.returncode == 0:
        try:
            kept = sorted(path for path in json.loads(record.stdout).get('kept_local', [])
                          if isinstance(path, str) and path.startswith(installer.LEGACY_STACK_DIR + '/'))
        except (ValueError, AttributeError):
            kept = []
    return retire, importers, kept


def sync_record(installer, project: Path, tree: dict[str, tuple[str, str]], ref: str = 'HEAD') -> bytes | None:
    """The sync record to add when the project has none: the pre-rename one with its paths renamed, or a fresh one."""
    if installer.STACK_SYNC_RECORD in tree:
        return None
    if installer.LEGACY_STACK_SYNC_RECORD not in tree:
        return installer.FRESH_SYNC_RECORD
    record = json.loads(git(project, 'cat-file', 'blob', f'{ref}:{installer.LEGACY_STACK_SYNC_RECORD}').stdout)
    rename = installer.legacy_to_current_path
    record['kept_local'] = [rename(path) for path in record.get('kept_local', [])]
    record['kept_local_sha256'] = {rename(path): digest for path, digest in record.get('kept_local_sha256', {}).items()}
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8')


def planned_changes(installer, home: Path, project: Path,
                    digests: dict[str, str] | None = None,
                    kept_configs: list[str] | None = None, *, expected_head: str | None = None,
                    binding: BoundRoot | ComponentTransaction | None = None,
                    tree: dict[str, tuple[str, str]] | None = None,
                    observations: dict | None = None,
                    baseline: dict | None = None) -> list[tuple[str, bytes, str]]:
    """(path, new bytes, Git mode) for every managed file that differs from the project's HEAD.

    A lint or coverage configuration the project already commits is its own and stays; its path
    goes to kept_configs.
    """
    if binding is None:
        with BoundRoot(project) as bound:
            return planned_changes(installer, home, project, digests, kept_configs,
                                   expected_head=expected_head, binding=bound, tree=tree, observations=observations,
                                   baseline=baseline)
    state = read_state(project, binding=binding)
    selected = state.require_selection()
    manifest = copy.deepcopy(state.manifest)
    expected_head = expected_head or _git_out(project, 'rev-parse', 'HEAD')
    tree = tree if tree is not None else head_tree(project, expected_head)
    selection = installer.PayloadSelection(
        selected,
        factory='factory' in manifest['components'],
        extras=tuple(sorted(set(installer.detect_extras(project)) |
                            {name.split(':', 1)[1] for name in manifest['components'] if name.startswith('extra:')})),
        compliance=tuple(sorted(name.split(':', 1)[1] for name in manifest['components'] if name.startswith('compliance:'))),
        root_shims=installer.has_root_shims(project),
        engine_archive=installer.wants_engine_archive(project),
    )
    payload = installer.build_payload(home, selection=selection)
    if any(entry.path == MANIFEST for entry in payload):
        raise UpdateError('source component state must never enter a consumer payload')
    plan = installer._make_plan(home, project, include_dependencies=False, include_optional=False,
                                selection=selection, payload=payload, accepted_kept_digests=digests)
    if plan['target_state'] != 'directory':
        raise UpdateError(f'{project} is not a plain directory')
    wanted = {entry['path'] for entry in plan['entries']}
    object_format = git(project, 'rev-parse', '--show-object-format').stdout.strip() or 'sha1'
    changes = []
    by_path = {entry.path: entry for entry in payload}
    known = set(by_path) | {path for record in manifest['components'].values() for path in record['files']}
    kept, kept_digests = read_keep_contract(binding)
    kept, kept_digests = match_kept_local(kept, digests if digests is not None else kept_digests, known)
    if observations is not None:
        record = binding.read(installer.STACK_SYNC_RECORD)
        observations[installer.STACK_SYNC_RECORD] = record
        if record is None:
            observations[installer.LEGACY_STACK_SYNC_RECORD] = binding.read(installer.LEGACY_STACK_SYNC_RECORD)
    for path in sorted(kept & known):
        current = binding.read(path)
        if observations is not None:
            observations[path] = current
        try:
            kept_file_state(path, current.content if current else None, None, kept_digests.get(path))
        except ComponentStateError as exc:
            raise installer.UnsafeInstallTarget(str(exc)) from exc
        for record in manifest['components'].values():
            record.get('owned', {}).pop(path, None)
    retained_overlay = binding.read('.grok/codex-hooks.json')
    if observations is not None:
        observations['.grok/codex-hooks.json'] = retained_overlay
    incoming_overlay = by_path.get('.grok/codex-hooks.json')
    codex_hooks = None
    retained_config = None
    if 'codex' in selected:
        canonical = by_path.get('.grok/hooks.json')
        if canonical is None or '.codex/config.toml' not in by_path or '.codex/hooks.json' not in by_path:
            raise UpdateError('incoming Codex activation unit is incomplete')
        overlay = retained_overlay.content if retained_overlay else incoming_overlay.content if incoming_overlay else None
        codex_hooks = render_codex_hooks(canonical.content, overlay)
        existing_config = binding.read('.codex/config.toml')
        if observations is not None:
            observations['.codex/config.toml'] = existing_config
        if existing_config is not None and existing_config.content != by_path['.codex/config.toml'].content:
            config = tomllib.loads(existing_config.content.decode('utf-8'))
            if type(config.get('features')) is not dict or config['features'].get('codex_hooks') is not True:
                raise UpdateError('custom Codex configuration must retain features.codex_hooks = true')
            retained_config = existing_config
        if kept & {'.codex/hooks.json', '.codex/config.toml'}:
            pair = {'.codex/hooks.json': codex_hooks,
                    '.codex/config.toml': retained_config.content if retained_config else by_path['.codex/config.toml'].content}
            for path, content in pair.items():
                current = binding.read(path)
                if observations is not None:
                    observations[path] = current
                if current is None or current.content != content or not mode_matches(current.mode, by_path[path].mode):
                    raise UpdateError(f'kept-local Codex activation requires the complete current pair: {path}')
    for entry in payload:
        if entry.path not in wanted:
            continue
        parts = entry.path.split('/')
        for depth in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:depth])
            committed = tree.get(prefix)
            if committed and (committed[0] == '120000' or depth < len(parts)):
                raise UpdateError(f'refusing to write through a committed link or file: {prefix}')
        current = binding.read(entry.path)
        if observations is not None:
            observations[entry.path] = current
        content = entry.content
        if entry.path == '.grok/codex-hooks.json' and retained_overlay is not None:
            continue  # shared consumer input is never replaced by the source default
        if entry.path == '.codex/config.toml' and retained_config is not None:
            continue
        if entry.path == '.codex/hooks.json' and codex_hooks is not None:
            content = codex_hooks
        initial_agents_block = False
        if entry.path == 'AGENTS.md':
            existing = current.content if current else None
            initial_agents_block = existing is not None and installer.MANAGED_START.encode() not in existing and installer.MANAGED_END.encode() not in existing
            content = merge_agents(installer, existing, content)
        mode = '100755' if entry.mode & 0o111 else '100644'
        if entry.path in PROJECT_CONFIGS and entry.path in tree:
            if kept_configs is not None and (current is None or current.content != content):
                kept_configs.append(entry.path)
            continue
        historical_match = matches_owned(current, baseline.get(entry.path)) if baseline is not None else False
        if (baseline is not None and current is not None and entry.path in POLICY_PATHS
                and not historical_match and current.content != content):
            raise UpdateError(f'custom policy is not a trusted baseline: {entry.path}')
        if (current is not None and (current.content != content or not mode_matches(current.mode, entry.mode))
                and not matches_owned(current, owned_proof(manifest, entry.path))
                and not historical_match and not initial_agents_block):
            raise UpdateError(f'ownership conflict: {entry.path}; preserve or explicitly reconcile the custom file before updating')
        record_owned(manifest, entry.path, content, entry.mode)
        if tree.get(entry.path) != (mode, blob_id(content, object_format)):
            changes.append((entry.path, content, mode))
    encoded = encode_manifest(manifest) if manifest != state.manifest else None
    try:
        validate_manifest_publication(binding.read(MANIFEST), encoded, kept, kept_digests)
    except ComponentStateError as exc:
        raise installer.UnsafeInstallTarget(str(exc)) from exc
    if encoded is not None:
        changes.append((MANIFEST, encoded, '100644'))
    return changes


def version_of(home: Path) -> str:
    try:
        return (home / 'VERSION').read_text(encoding='utf-8').strip() or 'latest'
    except OSError:
        return 'latest'


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


def sync_project(home: Path, project: Path, *, accept: bool = False, retire: bool = False,
                 baseline_release: str | None = None) -> str:
    """Publish target selection and managed bytes in the same private-index commit."""
    project = Path(fsx.system_canonical(project))
    try:
        if baseline_release is not None and (accept or retire):
            raise UpdateError('baseline migration cannot be combined with accept-local or retire-legacy')
        baseline = load_baseline(home, baseline_release, include_runtime_anchors=True) if baseline_release is not None else None
        with BoundRoot(project) as binding:
            _require_clean_project(project)
            head = _git_out(project, 'rev-parse', 'HEAD')
            _committed_manifest(project, binding, head, head_tree(project, head))
        with component_transaction(project) as transaction:
            return _sync_project_locked(home, project, transaction, accept=accept, retire=retire, baseline=baseline)
    except (ComponentStateError, OSError, ValueError) as exc:
        raise UpdateError(str(exc)) from exc


def _sync_project_locked(home: Path, project: Path, transaction: ComponentTransaction, *, accept: bool, retire: bool,
                         baseline: dict | None = None) -> str:
    _require_clean_project(project)
    expected_head = _git_out(project, 'rev-parse', 'HEAD')
    expected_branch = git(project, 'symbolic-ref', '-q', 'HEAD').stdout.strip()
    tree = head_tree(project, expected_head)
    state, original_manifest = _committed_manifest(project, transaction, expected_head, tree)
    observations = {MANIFEST: original_manifest}

    def check_current() -> None:
        transaction.check()
        if (_git_out(project, 'rev-parse', 'HEAD') != expected_head
                or git(project, 'symbolic-ref', '-q', 'HEAD').stdout.strip() != expected_branch):
            raise UpdateError('project HEAD or branch changed during the update; retry from its current state')
        _require_clean_project(project)
        for path, snapshot in observations.items():
            if transaction.read(path) != snapshot:
                raise UpdateError(f'project file changed during the update: {path}')

    check_current()
    if baseline is not None:
        # Legacy sandbox policy remains provenance-sensitive even if a later
        # payload migrates it to a different path. Ledger ownership is insufficient.
        legacy_policy = transaction.read('.grok/config.toml')
        observations['.grok/config.toml'] = legacy_policy
        if legacy_policy is not None and not matches_owned(legacy_policy, baseline.get('.grok/config.toml')):
            raise UpdateError('custom legacy policy is not a trusted baseline: .grok/config.toml')
    installer = load_installer(home)
    kept_configs: list[str] = []
    try:
        digests, record, accepted = accept_local(installer, project, expected_head) if accept else ({}, None, [])
        changes = planned_changes(installer, home, project, digests if accepted else None, kept_configs,
                                  expected_head=expected_head, binding=transaction, tree=tree, observations=observations,
                                  baseline=baseline)
        fresh_record = sync_record(installer, project, tree, expected_head) if record is None else None
        # A fresh empty record alone is not an update: it rides along with the next real change (#215).
        if fresh_record is not None and (changes or fresh_record != installer.FRESH_SYNC_RECORD):
            changes.append((installer.STACK_SYNC_RECORD, fresh_record, '100644'))
        if record is not None:
            # Before the legacy report, so the old record counts as replaced (#215).
            changes.append((installer.STACK_SYNC_RECORD, record, '100644'))
        # The sync history log moves with the record, so the old stack folder can go.
        old_log = installer.LEGACY_STACK_DIR + '/AGBP_SYNC.log.jsonl'
        if old_log in tree and installer.legacy_to_current_path(old_log) not in tree:
            log = git(project, 'cat-file', 'blob', f'{expected_head}:{old_log}', data=b'')
            if log.returncode != 0:
                raise UpdateError(f'cannot read {old_log} from HEAD')
            changes.append((installer.legacy_to_current_path(old_log), log.stdout, tree[old_log][0]))
        legacy, importers, legacy_kept = legacy_report(installer, project, tree, {path for path, _, _ in changes}, expected_head)
    except installer.UnsafeInstallTarget as exc:
        hint = ('; if the current version is the one you want, run `getzilla update --accept-local`'
                if 'no longer matches its declared divergence' in str(exc) else '')
        raise UpdateError(f'{exc}{hint}') from exc
    except json.JSONDecodeError as exc:
        raise UpdateError(f'the pre-rename sync record is not valid JSON: {exc}') from exc
    historical = [path for path in importers if HISTORICAL_EVIDENCE.match(path)]
    importers = [path for path in importers if path not in historical]
    if retire and legacy and (importers or legacy_kept):
        raise UpdateError('the project still depends on the old engine; port these first, then retire it: '
                          + ', '.join(importers + legacy_kept))
    notes = []
    if kept_configs:
        notes.append(f'kept your own {", ".join(sorted(kept_configs))}; Getzilla does not replace them')
    if legacy_kept:
        notes.append('your sync record keeps changed old-engine files, which the new engine does not carry: '
                     + ', '.join(legacy_kept))
    if importers:
        notes.append('these files import the old engine and need porting: ' + ', '.join(importers))
    if historical:
        notes.append(f'{len(historical)} dated evidence file(s) name the old engine; they stay as records of their day')
    unreplaced = [item['path'] for item in installer._legacy_migration(project)
                  if item['path'] in tree and item['path'] not in legacy]
    if unreplaced:
        notes.append(f'{len(unreplaced)} pre-rename file(s) have no Getzilla replacement here and stay, '
                     f'for example {unreplaced[0]}')
    if legacy and retire:
        changes.extend((path, None, '') for path in legacy)
        notes.append(f'removed {len(legacy)} pre-rename file(s)')
    elif legacy:
        notes.append(f'{len(legacy)} pre-rename file(s) remain, for example {legacy[0]}; '
                     'run `getzilla update --retire-legacy` to remove them')
    pending_manifest = next((decode_manifest(content) for path, content, _mode in changes if path == MANIFEST),
                            copy.deepcopy(state.manifest))
    changes = [(path, content, mode) for path, content, mode in changes if path != MANIFEST]
    kept, kept_digests = read_keep_contract(transaction)
    known = {path for path, _content, _mode in changes} | {
        path for component in pending_manifest['components'].values() for path in component['files']}
    kept, kept_digests = match_kept_local(kept, digests if accepted else kept_digests, known)
    for component in pending_manifest['components'].values():
        for path in kept:
            component.get('owned', {}).pop(path, None)
    permitted = []
    for path, content, mode in changes:
        if path not in observations:
            observations[path] = transaction.read(path)
        if path in kept:
            current = observations[path]
            kept_file_state(path, current.content if current else None, content, kept_digests.get(path))
            if (current is None or content is None or current.content != content
                    or not mode_matches(current.mode, 0o755 if mode == '100755' else 0o644)):
                raise UpdateError(f'kept-local path conflicts with the update: {path}')
            continue
        permitted.append((path, content, mode))
        if content is None:
            for component in pending_manifest['components'].values():
                component.get('owned', {}).pop(path, None)
                if path in component['files']:
                    component['files'].remove(path)
        else:
            record_owned(pending_manifest, path, content, 0o755 if mode == '100755' else 0o644)
    changes = permitted
    encoded = encode_manifest(pending_manifest) if pending_manifest != state.manifest else None
    validate_manifest_publication(original_manifest, encoded, kept, kept_digests)
    if encoded is not None:
        changes.append((MANIFEST, encoded, '100644'))
    # Keep ignored, positively owned files outside Git when the incoming bytes
    # and mode already match. Tracking them would remove them on rollback.
    # The original observations remain in check_current and the checkout CAS.
    ignored = set(_git_out(project, 'ls-files', '-z', '--others', '--ignored', '--exclude-standard', '--',
                           *(path for path, _, _ in changes)).split('\0')) - {''} if changes else set()
    retained_ignored = set()
    for path, content, mode in changes:
        if path not in ignored:
            continue
        current = observations[path]
        proved = (matches_owned(current, owned_proof(state.manifest, path))
                  or baseline is not None and matches_owned(current, baseline.get(path)))
        if (proved and content is not None and current.content == content
                and mode_matches(current.mode, 0o755 if mode == '100755' else 0o644)):
            retained_ignored.add(path)
    if ignored - retained_ignored:
        raise UpdateError('ignored local files sit on managed paths; move them first: '
                          + ', '.join(sorted(ignored - retained_ignored)))
    changes = [(path, content, mode) for path, content, mode in changes if path not in retained_ignored]
    if retained_ignored:
        notes.append(f'kept {len(retained_ignored)} unchanged owned ignored file(s) outside Git')
    arriving = sorted(path for path, content, mode in changes
                      if content is not None and path not in tree and (mode == '100755' or path.endswith('.py')))
    if arriving:
        notes.append(f'{len(arriving)} new executable file(s) arrive (hooks and scripts); '
                     'approve or exclude them in your own checks')
    if not changes:
        check_current()
        return '\n'.join([f'{project.name} is up to date', *notes])
    version = version_of(home)
    branch = BRANCH_PREFIX + version
    _git_out(project, 'check-ref-format', '--branch', branch)
    if git(project, 'rev-parse', '--verify', '--quiet', f'refs/heads/{branch}').returncode == 0:
        raise UpdateError(f'branch {branch} already exists in {project}: merge or delete it first')
    check_current()
    commit = commit_changes(project, changes, f'chore: update Getzilla to {version}', expected_head=expected_head)
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
    kept = f'; kept your current {", ".join(accepted)}' if accepted else ''
    return '\n'.join([f'{project.name}: {len(changes)} file(s) updated on branch {branch}{kept}; '
                      'review it and open a pull request', *notes])


def run_tools(home: Path, args: list[str]) -> int:
    return subprocess.run([sys.executable, str(home / 'scripts/getzilla_update.py'), *args], check=False).returncode


def is_tool_option(arg: str) -> bool:
    """A tool option, or an abbreviation argparse accepted before, that is not one of ours."""
    name = arg.split('=')[0]
    if not name.startswith('--') or len(name) < 3:
        return False
    return any(option.startswith(name) for option in TOOL_OPTIONS) and \
        not any(option.startswith(name) for option in OWN_OPTIONS)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    step, rest = (argv[0], argv[1:]) if argv and argv[0] in STEPS else (None, argv)
    if any(arg.split('=')[0] == '--baseline-release' for arg in rest) and (
            step == 'tools' or any(is_tool_option(arg) for arg in rest)):
        argparse.ArgumentParser(prog='getzilla update').error('--baseline-release cannot dispatch tool updates')
    if step == 'tools':
        return run_tools(HOME, rest)
    if step is None and any(is_tool_option(arg) for arg in rest):
        return run_tools(HOME, [arg for arg in rest if arg not in ('--no-self', '--no-tools')])
    parser = argparse.ArgumentParser(
        prog=f"getzilla update{' ' + step if step else ''}", description=__doc__.splitlines()[0],
        epilog='steps: ' + '; '.join(f'`getzilla update {name}` {summary}' for name, summary in STEPS.items()))
    if step != 'core':
        parser.add_argument('--baseline-release', choices=('v2.3.0',),
                            help='recognize exact selected vendor files from the pinned v2.3.0 installation')
        parser.add_argument('project', nargs='?', help='project to update (default: the one around this folder)')
    if step is None or step == 'core':
        parser.add_argument('--ref', help='branch or tag for a detached Getzilla checkout (default: main)')
    if step is None:
        parser.add_argument('--no-self', action='store_true', help='do not update Getzilla itself')
        parser.add_argument('--no-tools', action='store_true', help='do not update third-party tools')
    if step != 'core':
        parser.add_argument('--accept-local', action='store_true',
                            help='keep the committed version of kept files that changed since their digest was recorded')
        parser.add_argument('--retire-legacy', action='store_true',
                            help='also remove the committed pre-rename files (.grok-stack, scripts/grok_*) in the same commit')
    args = parser.parse_args(rest)
    if getattr(args, 'baseline_release', None) and (args.accept_local or args.retire_legacy):
        parser.error('--baseline-release cannot be combined with --accept-local or --retire-legacy')
    if getattr(args, 'baseline_release', None) and step is None and (not args.no_self or not args.no_tools):
        parser.error('--baseline-release requires project mode or both --no-self and --no-tools')
    try:
        if step == 'core':
            print(update_self(HOME, args.ref))
            return 0
        if step is None and not args.no_self:
            print(update_self(HOME, args.ref), flush=True)
            # Steps 2 and 3 run on the code just fetched, not on this process's old copy.
            project = args.project or find_project(Path.cwd(), HOME)
            again = [*([str(project)] if project else []), '--no-self', *(['--no-tools'] if args.no_tools else []),
                     *(['--accept-local'] if args.accept_local else []),
                     *(['--baseline-release', args.baseline_release] if args.baseline_release else []),
                     *(['--retire-legacy'] if args.retire_legacy else [])]
            return subprocess.run([sys.executable, str(HOME / 'scripts/getzilla_upgrade.py'), *again],
                                  check=False).returncode
        project = Path(args.project) if args.project else find_project(Path.cwd(), HOME)
        if project is None:
            print('no project here: run `getzilla update` inside a project to update it too')
        else:
            print(sync_project(HOME, project, accept=args.accept_local, retire=args.retire_legacy,
                               baseline_release=args.baseline_release), flush=True)
    except UpdateError as exc:
        print(f'getzilla update: {exc}', file=sys.stderr)
        return 1
    return 0 if step == 'project' or args.no_tools else run_tools(HOME, [])


if __name__ == '__main__':
    raise SystemExit(main())
