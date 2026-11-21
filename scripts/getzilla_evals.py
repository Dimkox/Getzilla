#!/usr/bin/env python3
"""Run offline agent replay evidence or explicitly accept a passing baseline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.agent_evals import EvalError, _parts, accept_baseline, attach_comparison, render_text, replay, review_quality  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    commands = parser.add_subparsers(dest='operation', required=True)
    for name in ('run', 'accept', 'quality'):
        command = commands.add_parser(name)
        command.add_argument('--manifest', required=True)
        command.add_argument('--outputs', required=True)
        command.add_argument('--baseline', required=name == 'accept')
        command.add_argument('--timeout', type=float, default=10)
        command.add_argument('--json', action='store_true')
        if name == 'accept':
            command.add_argument('--reason', required=True)
            command.add_argument('--scope', required=True)
        if name == 'quality':
            command.add_argument('--study', required=True)
            command.add_argument('--reviewer-id')
            command.add_argument('--reviewer-generation')
            command.add_argument('--report')
            command.add_argument('--reviewed-context')
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        if args.operation == 'quality':
            values = (args.reviewer_id, args.reviewer_generation, args.report, args.reviewed_context)
            if any(values) and not all(values):
                raise EvalError('incomplete_review_observation')
            observation = dict(zip(('agent_id', 'generation', 'report', 'reviewed_context'), values)) if all(values) else None
            report = review_quality(root, args.manifest, args.outputs, args.study, observation=observation,
                                    timeout_seconds=args.timeout)
            print(json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(',', ':')) if args.json
                  else 'QUALITY ' + report['quality']['status'] + ' (algorithm evidence; human acceptance not observed)')
            return 0 if report['quality']['status'] == 'observed' and not report['quality']['unresolved'] else 1
        baseline = None
        if args.baseline:
            _parts(args.baseline)
            baseline = root / args.baseline
        report = replay(root, args.manifest, args.outputs, timeout_seconds=args.timeout)
        if args.operation == 'accept':
            result = accept_baseline(baseline, report, reason=args.reason, scope=args.scope)
            print(json.dumps(result, sort_keys=True) if args.json else f"ACCEPTED {result['baseline_id']}")
            return 0
        if baseline is not None:
            report = attach_comparison(report, baseline)
        print(json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(',', ':')) if args.json else render_text(report))
        return 0 if report['canonical']['status'] == 'pass' and (baseline is None or report['comparison']['status'] == 'pass') else 1
    except (EvalError, OSError) as exc:
        reason = str(exc) if isinstance(exc, EvalError) else 'eval_command_refused'
        print(json.dumps({'status': 'invalid', 'reason': reason, 'release_authority': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
