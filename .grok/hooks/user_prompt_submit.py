#!/usr/bin/env python3
from __future__ import annotations

import os
import sys

try:
    from _lib import emit, is_child_payload, prompt_text, read_payload, root_from, run_hook, session_id
    from getzilla.router import is_system_notice, route_context
    from getzilla.continuity import submit
    from getzilla.state import get_active_route, discovered_route
except Exception:
    if os.name != 'nt':
        raise
    # Windows commandWindows has no `|| python3 -c "print('{}')"` fallback chain.
    import traceback
    traceback.print_exc()
    sys.stdout.write('{}\n')
    raise SystemExit(0)


def _named_paths(root, prompt: str) -> str:
    """Real paths of the files a task names, so the agent reads them instead of guessing."""
    try:
        from getzilla.path_hints import prompt_paths
        return '\n\n' + prompt_paths(root, prompt)
    except Exception:
        # Path context is advisory; the route context still goes out.
        return ''


def main() -> None:
    payload = read_payload()
    root = root_from(payload)
    prompt = prompt_text(payload)
    existing = get_active_route(root)
    if is_child_payload(payload):
        context = route_context(existing, root) if existing else ''
    elif existing is None and is_system_notice(prompt):
        # A harness notice is not a task (#185). With no route at all it creates none. A route that this
        # session cannot reuse (another session's, or closed) is replaced as before, so no fallback to it.
        context = ''
    else:
        try:
            route = submit(root, prompt, session_id(payload), event_id=payload.get('event_id'))
            context = route_context(route, root) if route else ''
        except (ValueError, RuntimeError, OSError) as conflict:
            retained = get_active_route(root) or discovered_route(root)
            context = (route_context(retained, root) + '\n\n') if retained else ''
            context += f'Getzilla retained task authority: {conflict}'
    if context:
        hints = _named_paths(root, prompt)
        if len((context + hints).encode('utf-8')) <= 16384:
            context += hints
    emit({
        'hookSpecificOutput': {
            'hookEventName': 'UserPromptSubmit',
            'additionalContext': context,
        }
    })


if __name__ == '__main__':
    run_hook(main, {})
