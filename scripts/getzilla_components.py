#!/usr/bin/env python3
"""Components a project gets when it needs them, from the same local Getzilla version.

  getzilla components status [--project DIR]
  getzilla components add agent:<name>|factory|compliance:eu-ai-act|extra:bitrix|extra:seo-landing [--project DIR]
  getzilla components adopt --agents 'qwen,codex'  (complete legacy selection; '' selects none)

Existing files are never overwritten; additions are recorded in .getzilla/managed-components.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.on_demand import adopt_selection, ensure_components, find_installed_project, is_installed_project  # noqa: E402
from getzilla.component_state import parse_agents, read_state  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla components', description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command')
    status = sub.add_parser('status')
    status.add_argument('--project', type=Path)
    add = sub.add_parser('add')
    add.add_argument('components', nargs='+')
    add.add_argument('--project', type=Path)
    adopt = sub.add_parser('adopt', help='Record a complete legacy selection without changing adapter files.')
    adopt.add_argument('--agents', required=True)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    try:
        explicit = getattr(args, 'project', None)
        project = explicit.absolute() if explicit is not None else find_installed_project(Path.cwd())
        if project is None or not is_installed_project(project):
            raise ValueError(f'{explicit or Path.cwd()} is not a project Getzilla was installed into')
        if args.command == 'status':
            state = read_state(project)
            print(json.dumps({'selection_state': state.kind, **state.manifest}, indent=2, sort_keys=True))
            return 0
        if args.command == 'adopt':
            manifest = adopt_selection(project, parse_agents(args.agents))
            print(json.dumps({'ok': True, 'selection_state': 'selected', **manifest}, indent=2, sort_keys=True))
            return 0
        results = ensure_components(project, list(args.components), source=ROOT)
    except (ValueError, OSError) as error:
        print(json.dumps({'ok': False, 'error': str(error)}))
        return 2
    print(json.dumps({'ok': True, 'added': [item.to_dict() for item in results]}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
