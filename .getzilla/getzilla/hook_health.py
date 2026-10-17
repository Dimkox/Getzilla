"""Hook health: fail-open hooks keep the agent working, but every time they do it is recorded.

`.grok/hooks/_lib.record_degraded` appends a `HOOK_DEGRADED` event to
`.getzilla/runtime/hook-events.jsonl` whenever a hook lets an action through because its own code
failed (policy not importable, an exception inside the hook). The stop gate shows the count,
verify records it in the receipt, and a high-risk change does not pass pr/release while its route
saw degraded hooks: the policy that should have guarded it did not run.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

EVENTS_NAME = 'hook-events.jsonl'
MAX_EVENTS_READ = 5000


def events_path(root: Path) -> Path:
    return Path(root) / '.getzilla' / 'runtime' / EVENTS_NAME


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def degraded_events(root: Path, since: str | None = None) -> list[dict[str, Any]]:
    """Degraded-hook events, oldest first, optionally only those at or after `since` (ISO time)."""
    path = events_path(root)
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()[-MAX_EVENTS_READ:]
    except OSError:
        return []
    start = _parse_time(since)
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get('kind') != 'HOOK_DEGRADED':
            continue
        when = _parse_time(event.get('ts'))
        if start is not None and (when is None or when < start):
            continue
        events.append(event)
    return events


def route_degraded_events(root: Path, route: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    return degraded_events(root, str(route.get('created_at')) if route and route.get('created_at') else None)


def summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    hooks: dict[str, int] = {}
    for event in events:
        hooks[str(event.get('hook'))] = hooks.get(str(event.get('hook')), 0) + 1
    return {'degraded_events': len(events), 'by_hook': dict(sorted(hooks.items())),
            'last': [{key: event.get(key) for key in ('ts', 'hook', 'error')} for event in events[-5:]]}
