"""Inspect or execute the project's optional verification tool configuration."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.python_test_runner import RunCancelled, _cancellation
from getzilla.util import find_root
from getzilla.verification_tools import CATALOG, CONFIG, ConfigurationError, load_checks, run_check


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Plan and run optional executable verification tools; no automatic installation.')
    parser.add_argument('action', choices=['catalog', 'plan', 'run'])
    parser.add_argument('--root', type=Path, help='project directory (default: current repository)')
    parser.add_argument('--mode', choices=['fast', 'pr', 'release'], default='pr')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    if args.action == 'catalog':
        payload = {'tools': CATALOG, 'config': CONFIG}
        code = 0
    else:
        root = (args.root or find_root()).resolve()
        try:
            selected = load_checks(root, args.mode)
        except ConfigurationError as exc:
            payload, code = {'status': 'fail', 'error': str(exc)}, 2
        else:
            payload = {'mode': args.mode, 'configured': bool(selected), 'checks': selected, 'status': 'planned' if selected else 'not_configured'}
            code = 0 if selected else 2
            if args.action == 'run' and selected:
                checks = []
                try:
                    with _cancellation() as cancelled:
                        for check in selected:
                            cancelled.check()
                            result = run_check(root, check)
                            checks.append(result)
                            if result['status'] != 'pass':
                                break
                        cancelled.check()
                    code = 0 if all(check['status'] == 'pass' for check in checks) else 1
                except RunCancelled as exc:
                    checks.extend(item for item in exc.checks if isinstance(item, dict))
                    code = exc.code
                payload.update(status='pass' if code == 0 else 'fail', checks=checks,
                               not_executed=[item['id'] for item in selected[len(checks):]])
    if args.json:
        print(json.dumps(payload, ensure_ascii=True, indent=2))
    elif args.action == 'catalog':
        for name, item in CATALOG.items():
            print(f"{name:23} {item['license']:15} {item['format']}")
        print(f'Configure selected tools in {CONFIG}; dependencies belong to the project.')
    elif args.action == 'plan' and 'error' not in payload:
        print(f"{payload['status']}: {len(payload['checks'])} checks for {args.mode}")
        for check in payload['checks']:
            print(f"{check['id']}: {check['tool']} ({check['timeout_seconds']}s), cwd={check['cwd']}")
    else:
        for check in payload.get('checks', []):
            print(f"{check['status'].upper()}: {check['name']}: {check['summary']}")
        print(payload.get('error', payload['status']))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
