"""Incremental update whose output equals a full rebuild.

Only parsing is incremental: a file whose (path, SHA-256) is unchanged and whose extractor and
config are unchanged reuses its ParsedFile. Import and call resolution always run again over the
whole scope, so deleted symbols leave no stale edges and a renamed module (even with equal bytes)
gets its new module identity. A config/extractor change, or a declared change set that does not
match the actual digests, falls back to a full rebuild.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from .builder import build_generation
from .models import GraphGeneration, GraphInput
from .store import GraphStore


def change_set(previous: GraphGeneration, current: GraphInput) -> dict[str, list[str]]:
    old = {item.path: item.sha256 for item in previous.files}
    new = {item.path: item.sha256 for item in current.files}
    return {'added': sorted(set(new) - set(old)), 'deleted': sorted(set(old) - set(new)),
            'modified': sorted(path for path in set(old) & set(new) if old[path] != new[path])}


def update_index(previous: GraphGeneration, current: GraphInput, store: GraphStore, *,
                 declared_changes: Iterable[str] | None = None) -> GraphGeneration:
    actual = change_set(previous, current)
    changed = {path for paths in actual.values() for path in paths}
    recorded = {item.path: item.sha256 for item in previous.files}
    reason = None
    if previous.graph_input.get('config') != current.config.to_dict():
        reason = 'CONFIG_OR_EXTRACTOR_CHANGED'
    elif previous.graph_input.get('source', {}).get('object_format') != current.source.object_format:
        reason = 'OBJECT_FORMAT_CHANGED'
    elif declared_changes is not None and set(declared_changes) != changed:
        reason = 'CHANGE_SET_INCONSISTENT'
    elif any(item.sha256 != recorded.get(path) for path, item in previous.parsed.items()):
        reason = 'CACHE_INCONSISTENT'
    expected = store.active_id()
    if reason is not None:
        generation = build_generation(current)
    else:
        reuse = {(path, item.sha256): item for path, item in previous.parsed.items() if path not in changed}
        generation = build_generation(current, reuse)
    generation = replace(generation, counters={**generation.counters, 'full_rebuild': int(reason is not None),
                                               'full_rebuild_reason': reason})
    store.publish(generation, expected_active=expected)
    return generation
