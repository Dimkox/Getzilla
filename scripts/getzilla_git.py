#!/usr/bin/env python3
"""Read the Git platform matrix and inspect a local remote without network access."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.git_platforms import inspect_repository, platform_catalog  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    catalog = commands.add_parser('catalog', help='evidence-qualified platform capabilities')
    catalog.add_argument('--json', action='store_true')
    inspect = commands.add_parser('inspect', help='identify the current remote offline')
    inspect.add_argument('--root', type=Path, default=Path.cwd())
    inspect.add_argument('--remote', default='origin')
    inspect.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = platform_catalog() if args.command == 'catalog' else inspect_repository(args.root, args.remote)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print('getzilla git: cannot inspect this Git worktree or remote', file=sys.stderr)
        return 2
    if args.json or args.command == 'inspect':
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Git platforms — {result['updated_at']} (hosted E2E verification is separate)")
        for entry in result['platforms']:
            print(f"{entry['id']:<23} {entry['status']:<20} {entry['name']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
