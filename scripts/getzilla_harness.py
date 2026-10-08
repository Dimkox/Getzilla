from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.cursor_rules import RuleError, drift as cursor_drift, write as cursor_write
from getzilla.harnesses import drift, write

parser = argparse.ArgumentParser(
    description=(
        'Render generated CLI harness files from .grok/ and .agents/skills/, '
        'and prompt-only Cursor rules from .getzilla/cursor-rules.json. '
        'Without --write it lists drift and exits 1 when committed files are out of date.'
    ),
)
parser.add_argument('--write', action='store_true', help='Rewrite generated harness files and managed Cursor rules.')
args = parser.parse_args()

try:
    if args.write:
        # Refuse Cursor ownership conflicts before rewriting any other harness.
        cursor_changes = cursor_write(ROOT)
        for line in [*write(ROOT), *cursor_changes]:
            print(line)
        raise SystemExit(0)
    problems = [*drift(ROOT), *cursor_drift(ROOT)]
except (RuleError, OSError) as exc:
    parser.exit(2, f'harness generation: {exc}\n')
for line in problems:
    print(line)
raise SystemExit(1 if problems else 0)
