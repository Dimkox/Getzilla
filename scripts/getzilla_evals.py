#!/usr/bin/env python3
"""Run offline agent replay evidence or explicitly accept a passing baseline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.agent_evals import EvalError, _parts, accept_baseline, compare, render_text, replay  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    commands = parser.add_subparsers(dest='operation', required=True)
    for name in ('run', 'accept'):
        command = commands.add_parser(name)
        command.add_argument('--manifest', required=True)
        command.add_argument('--outputs', required=True)
        command.add_argument('--baseline', required=name == 'accept')
        command.add_argument('--timeout', type=float, default=10)
        command.add_argument('--json', action='store_true')
        if name == 'accept':
            command.add_argument('--reason', required=True)
            command.add_argument('--scope', required=True)
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        baseline = None
        if args.baseline:
            parts = _parts(args.baseline)
            parent = root
            for part in parts[:-1]:
                parent = parent / part
                if parent.is_symlink():
                    raise EvalError('invalid_path')
            baseline = root / args.baseline
        report = replay(root, args.manifest, args.outputs, timeout_seconds=args.timeout)
        if args.operation == 'accept':
            result = accept_baseline(baseline, report, reason=args.reason, scope=args.scope)
            print(json.dumps(result, sort_keys=True) if args.json else f"ACCEPTED {result['baseline_id']}")
            return 0
        if baseline is not None:
            report['comparison'] = compare(report, baseline)
        print(json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(',', ':')) if args.json else render_text(report))
        return 0 if report['canonical']['status'] == 'pass' and (baseline is None or report['comparison']['status'] == 'pass') else 1
    except (EvalError, OSError) as exc:
        reason = str(exc) if isinstance(exc, EvalError) else 'eval_command_refused'
        print(json.dumps({'status': 'invalid', 'reason': reason, 'release_authority': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
