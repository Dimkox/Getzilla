"""Components that are not installed up front are added when they are needed, from the same Getzilla version.

A project gets the core plus the agent it uses. When another agent is set up (`getzilla
setup-agent` inside the project) or a command needs `factory/`, the missing component is copied
from the local Getzilla checkout (`GETZILLA_HOME`), never from the network, and never over an
existing file. Every addition is recorded in `.getzilla/managed-components.json` and shows up in
`git status` like any other change.
"""
from __future__ import annotations

import importlib.util
import copy
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from . import STACK_DIR
from .component_state import (
    MANIFEST, V2, BoundRoot, ComponentStateError, ComponentTransaction,
    FileSnapshot, agent_of, component_transaction, component_of, encode_manifest,
    mode_matches, read_state, record_owned, validate_agents,
    read_keep_contract, match_kept_local, kept_file_state, validate_manifest_publication,
)

# A synced project has the sync record; a fresh install has the core package and no record.
INSTALLED_MARKERS = ('.getzilla/AGBP_SYNC.json', '.getzilla/getzilla/__init__.py')
# Files that only a full Getzilla checkout has: a lean project cannot be the source of components.
SOURCE_MARKERS = ('scripts/install_into.py', 'factory/pyproject.toml')


@dataclass
class Added:
    component: str
    files: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {'component': self.component, 'files': len(self.files), 'kept_existing': self.kept}


def _installer(source: Path):
    spec = importlib.util.spec_from_file_location('getzilla_install_into_on_demand', source / 'scripts' / 'install_into.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def is_source_checkout(path: Path) -> bool:
    return all((path / marker).is_file() for marker in SOURCE_MARKERS)


def getzilla_home() -> Path:
    """The full checkout components come from: $GETZILLA_HOME, this checkout, then ~/Getzilla."""
    candidates = [Path(os.environ['GETZILLA_HOME'])] if os.environ.get('GETZILLA_HOME') else []
    candidates += [STACK_DIR.parent, Path.home() / 'Getzilla']
    for candidate in candidates:
        if is_source_checkout(candidate):
            return candidate
    raise RuntimeError('no full Getzilla checkout found to add components from; set GETZILLA_HOME '
                       'to the folder the installer cloned (default ~/Getzilla)')


def is_installed_project(root: Path) -> bool:
    if not root.exists() and not root.is_symlink():
        return False
    with BoundRoot(root) as binding:
        return any(binding.read(marker) is not None for marker in INSTALLED_MARKERS)


def find_installed_project(start: Path) -> Path | None:
    """Nearest consumer root; a full source checkout is not a consumer project."""
    current = start.absolute()
    for candidate in (current, *current.parents):
        if is_installed_project(candidate):
            return None if is_source_checkout(candidate) else candidate
    return None


def load_manifest(root: Path) -> dict[str, Any]:
    return read_state(root).manifest


def present(root: Path, component: str, source: Path | None = None) -> bool:
    installer = _installer(source or getzilla_home())
    paths = [entry.path for entry in installer.build_payload(source or getzilla_home()) if installer.component_of(entry.path) == component]
    return bool(paths) and all((root / path).exists() for path in paths)


def ensure_components(root: Path, needs: list[str], *, source: Path | None = None) -> list[Added]:
    """Add components under one writer guard; publish selection after file copies.

    A failed or interrupted addition can leave copied files. The old manifest
    remains until its final atomic publication; a retry must be explicit.
    """
    source = source or getzilla_home()
    installer = _installer(source)
    valid = {'factory', *(f'agent:{name}' for name in installer.KNOWN_AGENTS),
             *(f'compliance:{name}' for name in getattr(installer, 'KNOWN_COMPLIANCE', ())),
             *(f'extra:{name}' for name in getattr(installer, 'KNOWN_EXTRAS', ()))}
    for need in needs:
        if type(need) is not str or need not in valid:
            raise ValueError(f'unknown component {need!r}; expected one of {", ".join(sorted(valid))}')
    if not is_installed_project(root):
        raise ComponentStateError(f'{root} is not an installed Getzilla project')
    payload = installer.build_payload(source)
    with BoundRoot(source) as source_binding:
        version = source_binding.read('VERSION')
    source_version = version.content.decode('utf-8').strip() if version else None
    # Validate the whole batch before creating even the administrative guard.
    with BoundRoot(root) as binding:
        _addition_plan(root, needs, payload, binding, source_version)
    with component_transaction(root) as transaction:
        plan = _addition_plan(root, needs, payload, transaction, source_version)
        completed: list[str] = []
        try:
            for entry, expected in plan.operations:
                transaction.write(entry.path, entry.content, entry.mode, expected=expected)
                completed.append(entry.path)
            if plan.manifest_bytes is not None:
                transaction.write(MANIFEST, plan.manifest_bytes, 0o644, expected=plan.original_manifest)
        except (OSError, ValueError) as exc:
            observed = list(completed)
            try:
                for entry, expected in plan.operations:
                    current = transaction.read(entry.path)
                    if expected is None and current is not None and current.content == entry.content:
                        observed.append(entry.path)
                current_manifest = transaction.read(MANIFEST)
                state = 'old manifest retained' if current_manifest == plan.original_manifest else 'manifest publication requires inspection'
            except (OSError, ValueError):
                state = 'binding changed; remaining files and manifest require inspection'
            raise ComponentStateError(f'incomplete component addition; partial files: {sorted(set(observed))}; {state}; {exc}') from exc
        return plan.results


@dataclass
class _AdditionPlan:
    results: list[Added]
    operations: list[tuple[Any, FileSnapshot | None]]
    original_manifest: FileSnapshot | None
    manifest_bytes: bytes | None


def _codex_preflight(binding: BoundRoot | ComponentTransaction, payload: dict[str, Any],
                     kept: frozenset[str]) -> None:
    kept_pair = bool(kept & {'.codex/hooks.json', '.codex/config.toml'})
    for path in ('.codex/hooks.json', '.codex/config.toml'):
        entry = payload.get(path)
        if entry is None:
            raise ComponentStateError(f'Codex source activation unit is incomplete: {path}')
        current = binding.read(path)
        if current is None and kept_pair:
            raise ComponentStateError(f'kept-local Codex activation requires the complete existing pair: {path}')
        if current is not None and (current.content != entry.content or not mode_matches(current.mode, entry.mode)):
            raise ComponentStateError(f'custom Codex activation must be reconciled before adding files: {path}')
    source_overlay = payload.get('.getzilla/config/codex-hooks.json')
    current_overlay = binding.read('.getzilla/config/codex-hooks.json')
    if (current_overlay.content if current_overlay else None) != (source_overlay.content if source_overlay else None):
        raise ComponentStateError('custom Codex canonical overlay must be reconciled before adding files')


def _addition_plan(root: Path, needs: list[str], payload: tuple[Any, ...],
                   binding: BoundRoot | ComponentTransaction, source_version: str | None) -> _AdditionPlan:
    state = read_state(root, binding=binding)
    original_manifest = binding.read(MANIFEST)
    manifest = copy.deepcopy(state.manifest)
    requested_agents = [need.split(':', 1)[1] for need in needs if need.startswith('agent:')]
    scoped_extra = any(need in {'extra:bitrix', 'extra:seo-landing'} for need in needs)
    if requested_agents or scoped_extra:
        agents = tuple(dict.fromkeys((*state.require_selection(), *requested_agents)))
    else:
        agents = state.agents or ()
    if state.kind == 'selected':
        manifest['agents'] = list(agents)
    by_path = {entry.path: entry for entry in payload}
    kept, kept_digests = read_keep_contract(binding)
    kept, kept_digests = match_kept_local(kept, kept_digests, {*by_path, '.getzilla/config/compliance.json'})
    if 'codex' in requested_agents:
        _codex_preflight(binding, by_path, kept)
    results: list[Added] = []
    operations: list[tuple[Any, FileSnapshot | None]] = []
    planned: set[str] = set()
    changed_components: set[str] = set()
    active_extras = {name for name in manifest['components'] if name.startswith('extra:')}

    def remember(entry: Any) -> None:
        if state.kind == 'selected':
            record_owned(manifest, entry.path, entry.content, entry.mode)
        else:
            record = manifest['components'].setdefault(component_of(entry.path), {'files': []})
            record['files'] = sorted(set(record['files']) | {entry.path})

    def preserve(path: str, current: FileSnapshot | None, desired: bytes) -> None:
        status = kept_file_state(path, current.content if current else None, desired, kept_digests.get(path))
        if status == 'absent':
            raise ComponentStateError(f'kept-local path is absent; reconcile it before adding the component: {path}')
        for record in manifest['components'].values():
            record.get('owned', {}).pop(path, None)

    for need in needs:
        added = Added(need)
        manifest['components'].setdefault(need, {'files': []})
        for entry in payload:
            component = component_of(entry.path)
            # A newly selected adapter also gets already opted-in domain skills.
            owner = agent_of(entry.path)
            inherited_extra = need.startswith('agent:') and component in active_extras and owner == need.split(':', 1)[1]
            if component != need and not inherited_extra:
                continue
            if component.startswith('extra:') and owner is not None and owner not in agents:
                continue
            if entry.path in planned:
                continue
            current = binding.read(entry.path)
            if entry.path in kept:
                preserve(entry.path, current, entry.content)
                added.kept.append(entry.path)
                continue
            if current is not None:
                if current.content != entry.content or not mode_matches(current.mode, entry.mode):
                    added.kept.append(entry.path)
                else:
                    remember(entry)
                continue
            operations.append((entry, None))
            planned.add(entry.path)
            added.files.append(entry.path)
            changed_components.add(component)
            remember(entry)
        results.append(added)
    layers = sorted(need.split(':', 1)[1] for need in needs if need.startswith('compliance:'))
    if layers:
        config_path = '.getzilla/config/compliance.json'
        previous = binding.read(config_path)
        try:
            current = json.loads(previous.content) if previous else {'schema_version': 'getzilla-compliance-v1', 'enabled': []}
            if (type(current) is not dict or set(current) != {'schema_version', 'enabled'}
                    or current['schema_version'] != 'getzilla-compliance-v1' or type(current['enabled']) is not list
                    or any(type(item) is not str or item not in {'eu-ai-act'} for item in current['enabled'])):
                raise ValueError('unsupported compliance configuration')
        except (ValueError, UnicodeError) as exc:
            raise ComponentStateError(f'invalid compliance configuration: {exc}') from exc
        content = (json.dumps({'schema_version': 'getzilla-compliance-v1',
                               'enabled': sorted(set(current['enabled']) | set(layers))}, indent=2, sort_keys=True) + '\n').encode()
        # Use the same immutable entry type without importing the source installer again.
        entry = type(payload[0])(config_path, content, 0o644)
        if config_path in kept:
            preserve(config_path, previous, previous.content if previous else content)
            if not set(layers) <= set(current['enabled']):
                raise ComponentStateError('kept-local compliance configuration does not enable the requested layers')
            next(item for item in results if item.component.startswith('compliance:')).kept.append(config_path)
        else:
            if previous is None or previous.content != content:
                operations.append((entry, previous))
                changed_components.add('core')
                remember(entry)
            elif mode_matches(previous.mode, entry.mode):
                remember(entry)
            else:
                next(item for item in results if item.component.startswith('compliance:')).kept.append(config_path)
                for record in manifest['components'].values():
                    record.get('owned', {}).pop(config_path, None)
    for name in changed_components:
        record = manifest['components'][name]
        record['added_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        record['source_version'] = source_version
    encoded = encode_manifest(manifest) if manifest != state.manifest else None
    validate_manifest_publication(original_manifest, encoded, kept, kept_digests)
    return _AdditionPlan(results, operations, original_manifest, encoded)


def adopt_selection(root: Path, agents: tuple[str, ...]) -> dict[str, Any]:
    """Record an explicit complete legacy selection without changing adapter files."""
    agents = validate_agents(agents)
    if not is_installed_project(root):
        raise ComponentStateError(f'{root} is not an installed Getzilla project')

    def plan(binding: BoundRoot | ComponentTransaction) -> tuple[dict, FileSnapshot | None, bytes | None]:
        state = read_state(root, binding=binding)
        original = binding.read(MANIFEST)
        if state.kind == 'selected':
            if state.require_selection() != agents:
                raise ComponentStateError('selection is already established; adoption cannot replace or remove adapters')
            manifest, encoded = state.manifest, None
        else:
            manifest = {**state.manifest, 'schema_version': V2, 'agents': list(agents)}
            encoded = encode_manifest(manifest)
        kept, digests = read_keep_contract(binding)
        validate_manifest_publication(original, encoded, kept, digests)
        return manifest, original, encoded

    with BoundRoot(root) as binding:
        manifest, _original, encoded = plan(binding)
        if encoded is None:
            return manifest
    with component_transaction(root) as transaction:
        manifest, original, encoded = plan(transaction)
        if encoded is not None:
            transaction.write(MANIFEST, encoded, 0o644, expected=original)
        return manifest
