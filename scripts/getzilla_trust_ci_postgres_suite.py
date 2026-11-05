"""Machine-readable evidence for the required PostgreSQL component suite."""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", type=Path, required=True,
                        help="read-only Trust CI test source inside the owned acceptance container")
    args = parser.parse_args(argv)
    if not os.environ.get("TRUST_CI_TEST_DATABASE_URL"):
        raise RuntimeError("Required disposable PostgreSQL URL is absent")
    tests = args.tests.resolve(strict=True)
    suite = unittest.TestLoader().discover(str(tests), pattern="test_postgres_integration.py")
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    passed = bool(result.testsRun and result.wasSuccessful() and not result.skipped)
    print(json.dumps({"check_id": "trust-ci-postgres", "status": "pass" if passed else "fail",
                      "tests_run": result.testsRun, "executed": result.executed, "skipped": len(result.skipped),
                      "failures": len(result.failures), "errors": len(result.errors)}))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
