"""Complete source-bound evidence for the required PostgreSQL component suite."""
import ast
import contextlib
import json
import os
from pathlib import Path
import sys
import unittest

LIVE_SUITE_SCHEMA = 'getzilla-live-suite-v1'


class PrivateOutput:
    def write(self, value):
        return len(value)

    def flush(self):
        pass


def main():
    from getzilla.live_acceptance import read_document, valid_binding, record_suite
    from getzilla.live_contracts import source_inventory
    if not os.environ.get("TRUST_CI_TEST_DATABASE_URL"):
        raise RuntimeError("Required disposable PostgreSQL URL is absent")
    tests = Path(__file__).resolve().parent
    root = tests.parents[1]
    binding = read_document(Path(os.environ['GETZILLA_LIVE_BINDING']))
    if not valid_binding(binding) or binding['cell'] != 'trust-ci':
        raise ValueError('Trust suite original invocation is absent')
    before = source_inventory(root, 'trust-ci')
    test_source = tests / 'test_postgres_integration.py'
    declarations = ast.parse(test_source.read_bytes())
    expected = sorted(test_source.stem + '.' + cls.name + '.' + method.name
        for cls in declarations.body if isinstance(cls, ast.ClassDef)
        for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_'))
    loader = unittest.TestLoader()
    private = PrivateOutput()
    with contextlib.redirect_stdout(private), contextlib.redirect_stderr(private):
        suite = loader.discover(str(tests), pattern='test_postgres_integration.py')
        report = record_suite(suite, expected_ids=expected, required_ids=expected,
            loader_errors=loader.errors, binding=binding, source_root=root, source_paths=before,
            source_stable=lambda: source_inventory(root, 'trust-ci') == before, stream=private)
    report['source_inventory'] = before
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'pass' else 1


if __name__ == "__main__":
    sys.exit(main())
