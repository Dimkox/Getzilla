#!/usr/bin/env python3
"""Mandatory baseline: pinned Superpowers, BMAD and Spec Kit plus security data.

  getzilla baseline status [--project DIR] [--agent NAME]   what is installed and connected (exit 1 if incomplete)
  getzilla baseline apply  --project DIR [--agent NAME]     connect the pinned baseline to a project

`apply` never overwrites an existing file. Installing the user-level part is
`scripts/getzilla_update.py --only baseline`, which the installer always runs.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.baseline import AGENTS, apply_project, detect_agent, inspect  # noqa: E402
from getzilla.updater import home_dir  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla baseline', description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command')
    for name in ('status', 'apply'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--project', type=Path, required=name == 'apply')
        cmd.add_argument('--agent', choices=AGENTS)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    project = args.project.resolve() if args.project else None
    agent = args.agent or (detect_agent(project) if project else None)
    if args.command == 'apply':
        if not project.is_dir():
            print(json.dumps({'ok': False, 'error': f'{project} is not a directory'}))
            return 2
        steps = apply_project(project, agent, home_dir())
        for step in steps:
            print(f'{step.status.upper():4} {step.component}: {step.detail}')
        return 1 if any(step.status == 'fail' for step in steps) else 0
    status = inspect(home_dir(), project, agent)
    print(json.dumps({'agent': agent, **status.to_dict()}, indent=2))
    return 0 if status.complete else 1


if __name__ == '__main__':
    raise SystemExit(main())
