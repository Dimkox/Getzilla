"""Inert adapter-removal plans. Publication belongs to the guarded Git updater.

Only generated outputs with exact current ownership are eligible. Shared sources,
legacy helpers and unknown files are never removal candidates. Native settings
lose only exact stock hook groups; retained fragments lose ownership authority.
"""
from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass
from pathlib import Path

from . import harnesses
from .spec import SpecError, _parse_canonical_json
from .component_state import (
    MANIFEST, STACK_SYNC_RECORD, LEGACY_STACK_SYNC_RECORD, BoundRoot, ComponentStateError,
    ComponentTransaction, FileSnapshot, agent_of, encode_manifest, matches_owned,
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
