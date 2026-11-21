#!/usr/bin/env python3
"""Fail-closed aggregation for the existing required linux status."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
from getzilla.ci_admission import main

if __name__ == "__main__":
    raise SystemExit(main())
