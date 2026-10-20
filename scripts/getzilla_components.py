#!/usr/bin/env python3
"""Components a project gets when it needs them, from the same local Getzilla version.

  getzilla components status [--project DIR]
  getzilla components add agent:<name>|factory|compliance:eu-ai-act [--project DIR]

Existing files are never overwritten; additions are recorded in .getzilla/managed-components.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.on_demand import ensure_components, is_installed_project, load_manifest  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla components', description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command')
    status = sub.add_parser('status')
    status.add_argument('--project', type=Path, default=Path('.'))
    add = sub.add_parser('add')
    add.add_argument('components', nargs='+')
    add.add_argument('--project', type=Path, default=Path('.'))
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    project = args.project.resolve()
    if not is_installed_project(project):
        print(json.dumps({'ok': False, 'error': f'{project} is not a project Getzilla was installed into'}))
        return 2
    if args.command == 'status':
        print(json.dumps(load_manifest(project), indent=2, sort_keys=True))
        return 0
    try:
        results = ensure_components(project, list(args.components), source=ROOT)
    except ValueError as error:
        print(json.dumps({'ok': False, 'error': str(error)}))
        return 2
    print(json.dumps({'ok': True, 'added': [item.to_dict() for item in results]}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
