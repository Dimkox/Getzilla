#!/usr/bin/env python3
"""Entry point for the optional source-only duplicate scanner."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.duplicates import main  # noqa: E402

if __name__ == '__main__':
    raise SystemExit(main())
