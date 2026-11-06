"""Full Factory discovery with required database/fresh-cluster evidence."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "factory/src"), str(ROOT / ".getzilla")]
from functools import partial
from getzilla.factory_tests import RecordedResult, cases, source_census, source_matches, test_id
from getzilla.live_acceptance import factory_suite_status


def main():
    if not os.environ.get("FACTORY_TEST_DATABASE_URL") or not os.environ.get("FACTORY_FRESH_CLUSTER_DATABASE_URL"):
        raise RuntimeError("Both guarded disposable databases are required")
    census = source_census(ROOT)
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "factory/tests"), pattern="test_*.py", top_level_dir=str(ROOT))
    collected = [test_id(test) for test in cases(suite)]
    payload = {"schema_version": 2, "check_id": "factory-postgres-exit", "status": "fail",
               "census": census, "collected_ids": collected, "started": [], "executed": [], "skipped": [],
               "tests_run": 0, "failures": 0, "errors": 0, "loader_errors": len(loader.errors),
               "source_stable": source_matches(ROOT, census)}
    # Discovery is not execution authority for a partial or changed source set.
    if (not loader.errors and collected and len(collected) == len(set(collected))
            and set(collected) == set(census["declared_ids"]) and payload["source_stable"]):
        result = unittest.TextTestRunner(verbosity=2, resultclass=partial(
            RecordedResult, source_root=ROOT, source_paths=census["source_inventory"])).run(suite)
        payload.update(tests_run=result.testsRun, started=result.started, executed=result.executed,
                       skipped=[{"id": test.id(), "reason": reason} for test, reason in result.skipped],
                       failures=len(result.failures) + len(result.expectedFailures) + len(result.unexpectedSuccesses),
                       errors=len(result.errors), source_stable=source_matches(ROOT, census))
    payload["status"] = factory_suite_status(payload, census)
    path = Path(os.environ["GETZILLA_LIVE_ARTIFACTS"]) / "factory-suite.json"
    with path.open("x") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
