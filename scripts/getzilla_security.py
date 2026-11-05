#!/usr/bin/env python3
"""Run scanner code from this checkout, treating --root only as input data."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.security_cli import main  # noqa: E402

if __name__ == '__main__':
    raise SystemExit(main())
