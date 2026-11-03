#!/usr/bin/env python3
"""Private lifecycle worker and dead-allocator recovery entrypoint."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
from getzilla.live_lifecycle import main

if __name__ == "__main__":
    raise SystemExit(main())
