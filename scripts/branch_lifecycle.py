#!/usr/bin/env python3
"""Branch retention report and guarded delete for one local repository (for example a bare remote mirror).

  getzilla branches report --repo DIR --policy policy.json [--pull-requests prs.json] [--partial] [--output plan.json]
  getzilla branches apply  --repo DIR --policy policy.json --plan plan.json --plan-id ID --allow-delete
                           [--pull-requests prs.json]

`report` is the default and changes no ref. `apply` deletes only when the policy has
`deletion_enabled: true`, `--allow-delete` is given, the plan id matches and every ref still has its
planned OID (`git update-ref -d <ref> <expected>`). Nothing here fetches, pushes or calls GitHub;
pull request state comes from a file the caller produced. Exit codes: 0 ok, 2 arguments, 3 blocked,
5 stale plan, 8 error.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.branch_lifecycle import (  # noqa: E402
    BranchLifecycleError, BranchPolicy, BranchRetentionPlan, LocalGitRefBackend, apply_branch_plan,
    build_branch_plan, classify_branches,
)


def _load(path: str | None) -> dict:
    return {} if path is None else json.loads(Path(path).read_text(encoding='utf-8'))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla branches', description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command')
    for name in ('report', 'apply'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--repo', required=True)
        cmd.add_argument('--policy', required=True)
        cmd.add_argument('--pull-requests')
        cmd.add_argument('--partial', action='store_true', help='the pull request listing is incomplete')
    sub.choices['report'].add_argument('--output')
    apply = sub.choices['apply']
    apply.add_argument('--plan', required=True)
    apply.add_argument('--plan-id', required=True)
    apply.add_argument('--allow-delete', action='store_true')
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    now = datetime.now(timezone.utc)
    try:
        policy = BranchPolicy.from_dict(_load(args.policy))
        backend = LocalGitRefBackend(Path(args.repo), policy.default_branch,
                                     pull_requests=_load(args.pull_requests), complete=not args.partial)
        if args.command == 'report':
            inventory = classify_branches(backend.snapshot(), policy)
            plan = build_branch_plan(inventory, policy, now)
            envelope = {'schema': 'getzilla-branches-cli-v1', 'command': 'report', 'inventory': inventory.to_dict(),
                        'plan': plan.to_dict()}
            if args.output:
                Path(args.output).write_text(json.dumps(plan.to_dict(), indent=2) + '\n', encoding="utf-8", newline="\n")
            print(json.dumps(envelope, indent=2))
            return 0
        plan = BranchRetentionPlan.from_dict(_load(args.plan))
        if plan.plan_id != args.plan_id:
            print(json.dumps({'schema': 'getzilla-branches-cli-v1', 'command': 'apply', 'error': 'PLAN_ID_MISMATCH'}))
            return 5
        receipt = apply_branch_plan(plan, backend, policy, capability_granted=args.allow_delete, now=now)
        print(json.dumps({'schema': 'getzilla-branches-cli-v1', 'command': 'apply', 'receipt': receipt.to_dict()},
                         indent=2))
        return 0 if receipt.status in ('applied', 'dry_run') else 3
    except (BranchLifecycleError, KeyError, ValueError) as error:
        print(json.dumps({'schema': 'getzilla-branches-cli-v1', 'command': args.command, 'error': str(error)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
