"""Bounded Factory test collection; unit mode never inherits database bindings."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import unittest

_DATABASE_BINDINGS = (
    "FACTORY_TEST_DATABASE_URL", "FACTORY_FRESH_CLUSTER_DATABASE_URL",
    "FACTORY_TEST_POSTGRES_CONTAINER", "FACTORY_TEST_POSTGRES_CONTAINER_ID",
    "FACTORY_TEST_POSTGRES_NONCE",
    "FACTORY_TEST_POSTGRES_NETWORK_ID", "FACTORY_TEST_POSTGRES_NAMESPACE",
)


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)


def run(root: Path, *, report: Path | None = None) -> int:
    for name in _DATABASE_BINDINGS:
        os.environ.pop(name, None)
    # The checked candidate wins over an editable install from a different tree.
    candidate_paths = [str(root), str(root / "factory/src")]
    sys.path[:0] = candidate_paths
    os.environ["PYTHONPATH"] = os.pathsep.join(candidate_paths + [os.environ.get("PYTHONPATH", "")])
    loader = unittest.TestLoader()
    suite = loader.discover(str(root / "factory/tests"), pattern="test_*.py", top_level_dir=str(root))
    count = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    passed = bool(count and result.testsRun > len(result.skipped)) and result.wasSuccessful() and not loader.errors
    if not count:
        print("Factory unit discovery refused: no test cases collected", file=sys.stderr)
    if report is not None:
        document = {
            "schema_version": 1, "check_id": "factory-unit",
            "status": "pass" if passed else "fail", "collected": count,
            "tests_run": result.testsRun, "executed": result.executed,
            "failures": len(result.failures), "errors": len(result.errors),
            "skipped": [{"id": test.id(), "reason": reason} for test, reason in result.skipped],
            "database_obligations": "not_run_in_unit_mode",
        }
        content = json.dumps(document, sort_keys=True, indent=2).encode()
        if len(content) > 4 * 1024 * 1024:
            raise ValueError("Factory result exceeds evidence bound")
        with report.open("xb") as stream:
            stream.write(content)
    return 0 if passed else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    return run(args.root.resolve(strict=True), report=args.report)


if __name__ == "__main__":
    raise SystemExit(main())

