"""Portable source-checkout hook entrypoint, reached through bin/getzilla[.cmd]."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import runpy
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script', required=True)
    parser.add_argument('--harness', required=True,
                        choices=('qwen', 'claude', 'codex', 'gemini', 'copilot', 'grok'))
    args = parser.parse_args(argv)
    if re.fullmatch(r'\.getzilla/hooks/[A-Za-z0-9_]+\.py', args.script) is None:
        parser.error('script must name one canonical project hook')
    cwd = Path.cwd()
    reported = [Path(os.environ[key]) for key in
                ('CLAUDE_PROJECT_DIR', 'QWEN_PROJECT_DIR', 'GEMINI_PROJECT_DIR') if os.environ.get(key)]
    target = next((root / args.script for root in (*reported, cwd, *cwd.parents)
                   if (root / '.getzilla/getzilla/__init__.py').is_file()
                   and (root / args.script).is_file()), None)
    if target is None:
        parser.error('no installed project contains the requested canonical hook')
    sys.path.insert(0, str(target.parent))
    sys.argv = [str(target), '--harness', args.harness]
    runpy.run_path(str(target), run_name='__main__')


if __name__ == '__main__':
    main()
