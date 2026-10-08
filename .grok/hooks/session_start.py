#!/usr/bin/env python3
from __future__ import annotations

import os
import sys

try:
    from _lib import emit, read_payload, root_from, run_hook
    from getzilla.router import route_context
    from getzilla.state import get_active_change, get_active_route
except Exception:
    if os.name != 'nt':
        raise
    # Windows commandWindows has no `|| python3 -c "print('{}')"` fallback chain.
    import traceback
    traceback.print_exc()
    sys.stdout.write('{}\n')
    raise SystemExit(0)


def main() -> None:
    payload = read_payload()
    root = root_from(payload)
    route = get_active_route(root)
    change = get_active_change(root)
    if route:
        extra = f' Active route {route.get("route_id")}. Change: {(change or {}).get("change_id", "none")}.'
        context = route_context(route) + extra
    else:
        context = 'No active route. Submit a development task to classify work.'
    emit({
        'hookSpecificOutput': {
            'hookEventName': 'SessionStart',
            'additionalContext': context,
        }
    })


if __name__ == '__main__':
    run_hook(main, {})
