"""Full Factory discovery with required database/fresh-cluster evidence."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "factory/src"), str(ROOT / ".getzilla")]
from getzilla.factory_tests import RecordedResult


def accepted(result, executed):
    skipped = {test.id() for test, _ in result.skipped}
    return bool(result.testsRun and result.wasSuccessful()
                and any("FreshClusterArtifactAttestorMigrationTests." in name and name not in skipped for name in executed)
                and any("test_postgres_integration." in name and name not in skipped for name in executed)
                and not any("DATABASE_URL" in reason for _, reason in result.skipped))


def main():
    if not os.environ.get("FACTORY_TEST_DATABASE_URL") or not os.environ.get("FACTORY_FRESH_CLUSTER_DATABASE_URL"):
        raise RuntimeError("Both guarded disposable databases are required")
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "factory/tests"), pattern="test_*.py", top_level_dir=str(ROOT))
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    passed = accepted(result, result.executed) and not loader.errors
    path = Path(os.environ["GETZILLA_LIVE_ARTIFACTS"]) / "factory-suite.json"
    payload = {"schema_version": 1, "check_id": "factory-postgres-exit", "status": "pass" if passed else "fail",
               "tests_run": result.testsRun, "executed": result.executed,
               "skipped": [{"id": test.id(), "reason": reason} for test, reason in result.skipped],
               "failures": len(result.failures), "errors": len(result.errors)}
    with path.open("x") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
