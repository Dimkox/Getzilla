#!/usr/bin/env python3
"""LIMITED managed local command budget. Other native/provider clients are unsupported."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import task_budget  # noqa: E402
from getzilla.state import require_route_owner  # noqa: E402
from getzilla.util import find_root  # noqa: E402


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'getzilla task-budget: invalid-arguments\n')


def main(argv=None):
    parser = Parser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True, parser_class=Parser)
    init = sub.add_parser('init')
    for name in ('calls', 'failures', 'repeat-failures', 'elapsed-ms', 'deadline-epoch'):
        init.add_argument('--' + name, type=int, required=True)
    for name in ('tokens', 'cpu-ms', 'cost-micros'):
        init.add_argument('--' + name, type=int)
    sub.add_parser('show')
    run = sub.add_parser('run')
    run.add_argument('--operation-id', required=True)
    run.add_argument('--timeout', required=True, type=float)
    run.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    original_route, root = None, None
    try:
        root = find_root()
        if args.action != 'show':
            original_route = require_route_owner(root)
        if args.action == 'init':
            route = original_route
            limits = {name: getattr(args, name) for name in (*task_budget.DIMENSIONS, 'calls', 'failures', 'repeat_failures', 'deadline_epoch')}
            result = task_budget.initialize(root, limits, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
        elif args.action == 'show':
            result = task_budget.inspect(root)
        else:
            command = args.command[1:] if args.command[:1] == ['--'] else args.command
            result = task_budget.execute_local(root, args.operation_id, command, timeout=args.timeout)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 2 if result.get('outcome') == 'unknown' else 1 if result.get('outcome') == 'failed' else 0
    except (OSError, ValueError, RuntimeError, KeyError):
        # No caller input, command, path, environment or child output in errors.
        print(json.dumps({'error': 'budget-operation-refused', 'escalation': 'needs-review',
                          'coverage': 'limited-managed-command'}))
        return 2
    finally:
        if original_route and original_route.get('observation_publication'):
            from getzilla.sprint_lifecycle import flush_after_scope
            flush_after_scope(root, original_route['route_id'])


if __name__ == '__main__':
    raise SystemExit(main())
