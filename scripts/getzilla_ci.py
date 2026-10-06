"""Plan or write a repository's CI/merge gate from its GitHub visibility.

Public repository -> GitHub Actions: ``--write`` renders
``.getzilla/templates/ci/github-actions-verify.yml`` into
``.github/workflows/getzilla-verify.yml``. Private repository -> Trust CI
(the self-hosted ``adaptive-trust-ci`` GitHub App): nothing is written and the
onboarding steps are printed. ``--plan`` only reads. Run it from the Getzilla
checkout with ``--target /path/to/repo`` for another repository.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

STACK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STACK_ROOT / '.getzilla'))

from getzilla import ci_gate  # noqa: E402

EXIT_CODES = {
    'written': 0,
    'unchanged': 0,
    'nothing-to-write': 0,
    'refused': 1,
    'undetermined': 2,
}


def _human(report: dict[str, object]) -> str:
    lines = [
        f"repository: {report['repository'] or '(origin is not a github.com repository)'}",
        f"visibility: {report['visibility']} ({report['visibility_source']}: {report['visibility_detail']})",
        f"gate: {report['gate'] or 'none (pass --visibility public|private)'}",
    ]
    writes = report['writes']
    if isinstance(writes, list) and writes:
        for entry in writes:
            lines.append(
                f"workflow: {entry['path']} [{entry['state']}] {entry['reason']}; template {entry['template']}; "
                f"push branch {entry['push_branch']} ({entry['push_branch_source']})"
            )
    else:
        lines.append('writes: none')
    if 'result' in report:
        lines.append(f"result: {report['result']}")
    steps = report['next_steps']
    if isinstance(steps, list) and steps:
        lines.append('next steps:')
        lines.extend(f'  {index}. {step}' for index, step in enumerate(steps, 1))
    return '\n'.join(lines)


def main(argv: list[str] | None = None, **dependencies: object) -> int:
    """CLI entry; ``dependencies`` (runner, fetch, which) exist for offline tests."""
    parser = argparse.ArgumentParser(
        description='Select the CI/merge gate by repository visibility: public -> GitHub Actions, private -> Trust CI.',
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true', help='read-only: report visibility, gate and planned writes')
    mode.add_argument(
        '--write', action='store_true',
        help='public: create the workflow (never overwrites a different file); private: write nothing',
    )
    parser.add_argument(
        '--visibility', choices=(ci_gate.PUBLIC, ci_gate.PRIVATE),
        help='use this visibility instead of asking GitHub (required when GitHub cannot confirm it)',
    )
    parser.add_argument('--target', default='.', help='repository to configure (default: the current directory)')
    parser.add_argument(
        '--default-branch', dest='branch',
        help='branch whose pushes run the workflow (default: origin/HEAD, otherwise main)',
    )
    parser.add_argument('--json', action='store_true', help='print the report as JSON')
    args = parser.parse_args(argv)
    runner = dependencies.get('runner', ci_gate.run_command)
    options = {key: value for key, value in dependencies.items() if key in {'runner', 'fetch', 'which'}}
    try:
        target = ci_gate.resolve_target_root(Path(args.target), runner=runner)  # type: ignore[arg-type]
        action = ci_gate.apply_gate if args.write else ci_gate.plan_gate
        report = action(
            target, STACK_ROOT, visibility=args.visibility, branch=args.branch, **options,  # type: ignore[arg-type]
        )
    except (ci_gate.CiGateError, OSError) as exc:
        print(f'getzilla_ci: {exc}', file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    else:
        print(_human(report))
    if args.write:
        code = EXIT_CODES.get(str(report.get('result')), 2)
        if code == 1:
            print(f'getzilla_ci: refused to overwrite {ci_gate.WORKFLOW_PATH}', file=sys.stderr)
        elif code == 2:
            print('getzilla_ci: visibility unknown; pass --visibility public|private', file=sys.stderr)
        return code
    return 0 if report['gate'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
