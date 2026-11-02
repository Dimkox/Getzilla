from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.harnesses import drift, write

parser = argparse.ArgumentParser(
    description=(
        'Render the selected Qwen Code, Claude Code, Codex, Gemini CLI, Copilot CLI and Cursor files '
        'from the canonical .grok/hooks.json, .grok/agents/*.toml, .grok/cursor-rules/*.toml and .agents/skills/. '
        'Without --write it lists drift and exits 1 when the files are out of date. '
        'Full-source regeneration requires --repository-all --write.'
    ),
)
parser.add_argument('--write', action='store_true', help='Rewrite the generated harness files.')
parser.add_argument('--repository-all', action='store_true', help='Explicit full-source generation with the shared ownership ledger.')
args = parser.parse_args()

try:
    if args.write:
        for line in write(ROOT, repository_all=args.repository_all):
            print(line)
        raise SystemExit(0)
    problems = drift(ROOT, repository_all=args.repository_all)
except (ValueError, OSError) as exc:
    parser.exit(2, f'harness generation: {exc}\n')
for line in problems:
    print(line)
raise SystemExit(1 if problems else 0)
