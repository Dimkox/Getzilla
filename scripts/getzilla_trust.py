"""Inspect public source facts and control explicitly provisioned local execution."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.supply_chain import audit  # noqa: E402
from getzilla.util import find_root  # noqa: E402


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # Untrusted argument values can contain private data. Emit only a fixed code.
        print(json.dumps({'error': 'invalid-arguments'}))
        raise SystemExit(2)


def main() -> int:
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('audit', help='hash the bounded existing source inventory')
    inspect.add_argument('--json', action='store_true')
    for command in ('provision', 'status', 'stop', 'recover', 'run', 'get', 'cancel'):
        control = commands.add_parser(command)
        control.add_argument('--json', action='store_true')
        if command == 'recover':
            control.add_argument('--expected-revision', type=int, required=True)
            control.add_argument('--expected-source', required=True)
        elif command == 'stop':
            control.add_argument('--reason', choices=('operator_stop', 'compromised_tool', 'tool_unavailable', 'rollback'),
                                 default='operator_stop')
        elif command == 'run':
            control.add_argument('--tool', required=True)
            control.add_argument('--intent', required=True)
            control.add_argument('--timeout', type=int, required=True)
        elif command in {'get', 'cancel'}:
            control.add_argument('execution_id')
    args = parser.parse_args()
    root = find_root()
    if args.command != 'audit':
        from getzilla import execution, execution_store
        try:
            caller = execution.trusted_caller(root, execution_id=args.execution_id if args.command in {
                'get', 'cancel'} else None)
            if args.command == 'provision':
                report = execution.provision(root, caller)
            elif args.command == 'status':
                report = execution.control_status(root, caller)
            elif args.command == 'stop':
                report = execution.stop(root, caller, reason=args.reason)
            elif args.command == 'recover':
                report = execution.recover(root, caller, expected_revision=args.expected_revision,
                                           expected_source=args.expected_source)
            elif args.command == 'get':
                report = execution.get(root, caller, args.execution_id)
            elif args.command == 'cancel':
                from getzilla.managed_execution import Backend
                report = execution.cancel(root, caller, args.execution_id, backend=Backend())
            else:
                from getzilla.managed_execution import run
                report = run(root, caller, tool_id=args.tool, intent_key=args.intent,
                             hard_timeout_seconds=args.timeout)
        except (execution.ExecutionError, execution_store.RegistryError) as error:
            print(json.dumps({'error': error.code}))
            return 2
        except (OSError, ValueError, TypeError, KeyError):
            print(json.dumps({'error': 'execution_control_unavailable'}))
            return 2
        print(json.dumps(report, indent=2))
        return 0 if args.command != 'run' or report['execution_status'] == 'succeeded' else 1
    report = audit(root)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print('Offline source observation; authority: none; external MCP identity: unsupported.')
        for entry in report['sources']:
            print(f"{entry['state']}: {entry['path']}")
    return 0 if report['audit_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
