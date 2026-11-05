#!/usr/bin/env python3
"""Cwd-relative hook entry used by older adaptive.json files.

Dispatches into .getzilla/hooks/<this-file-name>. Does not import a root _lib
(that would point the stack at the parent of the repo). Missing canonical script
denies PreToolUse and leaves observation-only events empty.
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

NAME = Path(__file__).name
ROOT = Path(__file__).resolve().parent
def main(name: str = NAME, root: Path = ROOT) -> None:
    canonical = root / '.getzilla' / 'hooks' / name
    if canonical.is_file():
        hook_dir = str(canonical.parent)
        if hook_dir not in sys.path:
            sys.path.insert(0, hook_dir)
        sys.argv[0] = str(canonical)
        runpy.run_path(str(canonical), run_name='__main__')
        return
    if name == 'pre_tool_use.py':
        sys.stdout.write('{"decision":"deny","reason":"Getzilla canonical policy hook is missing"}\n')
    else:
        sys.stdout.write('{}\n')


if __name__ == '__main__':
    main()
