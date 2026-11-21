from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.language_quality.core import run_registry


def benchmark_module():
    spec = importlib.util.spec_from_file_location('lqg_benchmark', ROOT / 'scripts/benchmark_lqg.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'fixture registry requires POSIX and Git')
class ReproducibleFixtureTests(unittest.TestCase):
    def test_all_stacks_exercise_real_registry_adapters_and_shadow_reuse(self):
        from tests.lqg_fixtures import FixtureExecutor, make_fixture
        expected = {'javascript': {'eslint'}, 'kotlin': {'detekt', 'ktlint'},
                    'dart': {'dart_analyzer', 'dart_format'}, 'flutter': {'dart_analyzer', 'dart_format'},
                    'swift': {'swiftlint', 'swiftformat'}, 'mixed': {'eslint', 'detekt', 'ktlint', 'dart_analyzer', 'dart_format', 'swiftlint', 'swiftformat'}, 'python': set()}
        for stack, tools in expected.items():
            with tempfile.TemporaryDirectory() as directory, self.subTest(stack=stack):
                root = Path(directory)
                fixture = make_fixture(root, stack=stack, files=2, packages=1, scope='changed', typed=False)
                backend = FixtureExecutor()
                fresh = run_registry(root, fixture['base'], executor=backend)
                executed = [r for r in fresh if r['execution_performed']]
                self.assertEqual({r['tool_id'] for r in executed}, tools, fresh)
                self.assertTrue(all(r['execution_status'] == 'PASS' for r in executed), executed)
                self.assertTrue(all(set(r['timings_ms']) == {'queue', 'setup', 'execution', 'validation'} for r in executed))
                calls = backend.calls
                warm = run_registry(root, fixture['base'], executor=backend)
                self.assertEqual(backend.calls, calls)
                self.assertEqual({r['tool_id'] for r in warm if r['execution_status'] == 'CACHED_UNVERIFIED'}, tools)
                self.assertTrue(all(r['execution_performed'] is False for r in warm))
                if not tools:
                    self.assertEqual(calls, 0)
                    self.assertEqual({r['execution_status'] for r in fresh}, {'NOT_APPLICABLE'})

    def test_benchmark_records_raw_samples_and_disclaims_sdk_or_ci_qualification(self):
        report = benchmark_module().run_benchmarks(samples=2, quick=True, concurrency=2)
        self.assertEqual(report['evidence_kind'], 'synthetic-fixture-benchmark')
        self.assertEqual(report['real_sdk_smoke'], 'NOT_RUN')
        self.assertEqual(report['external_ci_baseline'], 'unavailable')
        self.assertFalse(report['qualifies_latency_targets'])
        self.assertEqual(report['llm_calls'], 0)
        self.assertTrue(report['cases'])
        for case in report['cases']:
            self.assertEqual(len(case['cold_samples_ms']), 2)
            self.assertEqual(len(case['warm_samples_ms']), 2)
            self.assertGreaterEqual(case['cold_p95_ms'], case['cold_p50_ms'])
            self.assertGreaterEqual(case['warm_p95_ms'], case['warm_p50_ms'])
            self.assertEqual(case['package_install'], 'not_performed')
            self.assertTrue(all(value >= 0 for value in case['cold_samples_ms'] + case['warm_samples_ms']))
            self.assertGreaterEqual(case['traced_peak_bytes'], 0)
            self.assertEqual(len(case['fixture_digest']), 64)
        self.assertEqual(report['concurrent_fixture']['workers'], 2)
        self.assertEqual(report['concurrent_fixture']['fresh_executions'], 2)


if __name__ == '__main__':
    unittest.main()
