from __future__ import annotations

import sys

# The read-only command must also avoid import-cache writes during ordinary startup.
if __name__ == '__main__' and sys.argv[1:2] == ['preflight']:
    sys.dont_write_bytecode = True

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

import argparse
import json

from getzilla.deploy import prepare_deploy
from getzilla.util import find_root

class _UsageError(ValueError):
    pass


class _PreflightParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise _UsageError from None


def _preflight(argv: list[str]) -> int:
    parser = _PreflightParser(prog='getzilla deploy preflight', allow_abbrev=False,
                              description='Observe a local package for review. Grants no execution or DEV readiness.')
    parser.add_argument('--root', required=True, type=Path, help='Explicit root containing the public inputs.')
    parser.add_argument('--manifest', required=True, help='Portable root-relative manifest path.')
    parser.add_argument('--json', action='store_true')
    try:
        args = parser.parse_args(argv)
    except _UsageError:
        print('getzilla deploy preflight: invalid arguments', file=sys.stderr)
        return 2
    from getzilla.deploy_preflight import PreflightError, PreflightReport, prepare_preflight, recheck_preflight
    try:
        observation = prepare_preflight(args.root, args.manifest)
        report = recheck_preflight(args.root, observation, args.manifest)
    except PreflightError as error:
        report = PreflightReport.blocked(error.code)
    except Exception:
        report = PreflightReport.blocked('INTERNAL_ERROR')
    data = report.to_dict()
    if args.json:
        print(json.dumps(data, ensure_ascii=True, indent=2))
    else:
        print('Preflight: ' + data['state'] + '; ' + ', '.join(data['diagnostics']))
    return 0 if data['state'] == 'ready_for_review' else 1


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['preflight']:
        return _preflight(argv[1:])
    parser = argparse.ArgumentParser(description='Prepare human-owned publish commands. Never executes tag, push, or release.')
    parser.add_argument('--record', action='store_true', help='Write a deploy/prepared receipt. Requires production approval.')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    report = prepare_deploy(find_root(), record=args.record)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif report.get('ok'):
        for command in report.get('commands', []):
            print(command)
    else:
        print(report.get('error', 'deploy prepare failed'), file=sys.stderr)
    return 0 if report.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
