#!/usr/bin/env python3
"""Scaffold optional compliance adapters on platforms with descriptor-relative safe creation.

Windows: copy the installed Python or TypeScript template manually. Automatic scaffolding refuses
before writing because the path-based Windows helpers cannot prevent parent replacement races.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import eu_ai_act  # noqa: E402
from getzilla.compliance_scaffold import ScaffoldError, registry_hints, scaffold  # noqa: E402
from getzilla.util import find_root  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('scaffold', description=__doc__)
    command.add_argument('--root', type=Path)
    command.add_argument('--system', required=True)
    command.add_argument('--lang', choices=('python', 'typescript'), required=True)
    args = parser.parse_args(argv)
    root = args.root or find_root()
    if not eu_ai_act.enabled(root):
        print(json.dumps({'ok': False, 'error': 'EU AI Act component not installed; '
                          'run getzilla components add compliance:eu-ai-act'}))
        return 1
    try:
        paths = scaffold(root, args.system, args.lang)
    except (ScaffoldError, OSError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        return 1
    print(json.dumps({'ok': True, 'paths': [str(path) for path in paths],
                      'registry_hints': registry_hints(args.lang)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
