#!/usr/bin/env python3
"""Optional Entire transport and Trail adapter (no automatic login or session capture)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
sys.path.insert(0, str(ROOT / '.getzilla' / 'integrations'))


def main() -> int:
    try:
        from getzilla_entire.cli import main as run
    except ModuleNotFoundError as exc:
        if exc.name not in {'getzilla_entire', 'getzilla_entire.cli'}:
            raise
        if len(sys.argv) == 1 or sys.argv[1:] in (['--help'], ['-h']):
            print('usage: getzilla entire <status|clone|fetch|push|trails|checks|merge> [options]')
            print(__doc__)
            print('Install with: getzilla components add extra:entire')
            return 0
        print('getzilla entire: install the optional module with: getzilla components add extra:entire', file=sys.stderr)
        return 2
    return run()


if __name__ == '__main__':
    raise SystemExit(main())
