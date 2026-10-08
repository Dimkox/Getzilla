"""Check or install Getzilla's managed, prompt-only Cursor rules."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.cursor_rules import main

if __name__ == '__main__':
    raise SystemExit(main(ROOT))
