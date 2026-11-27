"""Keep Core test discovery's repository import paths bounded."""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_IMPORT_PATHS = (str(_ROOT), str(_ROOT / ".getzilla"))


def pytest_collectreport(report):
    if not report.nodeid.startswith("tests/") or not report.nodeid.endswith(".py"):
        return

    # Pytest and standalone unittest modules prepend these paths during import.
    # Coverage rebuilds its matchers over the entire list every time it changes.
    # The first occurrence determines precedence, including for later imports.
    for path in _IMPORT_PATHS:
        if sys.path.count(path) > 1:
            first = sys.path.index(path) + 1
            sys.path[first:] = [entry for entry in sys.path[first:] if entry != path]
