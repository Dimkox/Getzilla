"""Reproduce synthetic LQG orchestration timings; never install or run a language SDK."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.cpu_budget import cpu_budget
from getzilla.language_quality.core import run_registry
from tests.lqg_fixtures import FixtureExecutor, make_fixture


def _percentiles(samples):
    return round(statistics.median(samples), 3), sorted(samples)[math.ceil(.95 * len(samples)) - 1]


def _source_identity():
    paths = [ROOT / 'scripts/benchmark_lqg.py', ROOT / 'tests/lqg_fixtures.py']
    paths.extend(sorted((ROOT / '.getzilla/getzilla/language_quality').glob('*.py')))
    paths.extend(sorted((ROOT / '.getzilla/getzilla/language_quality/adapters').glob('*.py')))
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
    head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = bool(subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=normal']))
    return {'head': head, 'dirty': dirty, 'measured_source_digest': digest.hexdigest()}


def run_benchmarks(*, samples=5, quick=False, concurrency=2):
    if os.name != 'posix':
        raise ValueError('synthetic snapshot benchmark requires POSIX')
    if type(samples) is not int or not 2 <= samples <= 30 or type(concurrency) is not int or not 1 <= concurrency <= 6:
        raise ValueError('benchmark bounds are samples 2..30 and concurrency 1..6')
    allocation = cpu_budget(6)
    workers = min(concurrency, allocation.effective)
    matrix = [('javascript-small-untyped', 'javascript', 8, 1, False),
              ('javascript-small-typed', 'javascript', 8, 1, True),
              ('javascript-medium', 'javascript', 150, 1, False),
              ('typescript-monorepo', 'javascript', 50, 4, True),
              ('kotlin', 'kotlin', 8, 1, False), ('dart', 'dart', 8, 1, False),
              ('flutter', 'flutter', 8, 1, False), ('swift', 'swift', 8, 1, False),
              ('mixed', 'mixed', 8, 2, True), ('python', 'python', 8, 1, False)]
    if quick:
        matrix = [('javascript-quick', 'javascript', 2, 1, False)]
    cases = []
    for name, stack, files, packages, typed in matrix:
        for scope in ('changed', 'full'):
            with tempfile.TemporaryDirectory(prefix='lqg-benchmark-') as directory:
                root = Path(directory)
                started = time.perf_counter()
                fixture = make_fixture(root, stack=stack, files=files, packages=packages, scope=scope, typed=typed)
                setup_ms = round((time.perf_counter() - started) * 1000, 3)
                backend = FixtureExecutor()
                cold, warm, cpu = [], [], []
                stages = {'cold': [], 'warm': []}
                tracemalloc.start()
                try:
                    for _ in range(samples):
                        shutil.rmtree(root / '.getzilla/runtime/lqg/cache-v1', ignore_errors=True)
                        for label, measured in (('cold', cold), ('warm', warm)):
                            started = time.perf_counter()
                            cpu_start = time.process_time()
                            results = run_registry(root, fixture['base'], executor=backend)
                            cpu.append(round((time.process_time() - cpu_start) * 1000, 3))
                            measured.append(round((time.perf_counter() - started) * 1000, 3))
                            expected = {'PASS', 'NOT_APPLICABLE'} if label == 'cold' else {'CACHED_UNVERIFIED', 'NOT_APPLICABLE'}
                            if any(result['execution_status'] not in expected for result in results):
                                raise RuntimeError('synthetic fixture did not complete its expected path: ' + str([(r['tool_id'], r['execution_status'], r['summary']) for r in results]))
                            timed = [r['timings_ms'] for r in results if 'timings_ms' in r]
                            stages[label].append({stage: round(max((r[stage] for r in timed), default=0), 3)
                                                  if stage == 'queue' else round(sum(r[stage] for r in timed), 3)
                                                  for stage in ('queue', 'setup', 'execution', 'validation')})
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                cold_p50, cold_p95 = _percentiles(cold)
                warm_p50, warm_p95 = _percentiles(warm)
                cases.append({'name': name, 'requested_scope': scope, **fixture,
                              'fixture_setup_ms': setup_ms, 'cold_samples_ms': cold, 'warm_samples_ms': warm,
                              'cold_p50_ms': cold_p50, 'cold_p95_ms': cold_p95, 'warm_p50_ms': warm_p50, 'warm_p95_ms': warm_p95,
                              'stage_samples_ms': stages, 'process_cpu_samples_ms': cpu,
                              'traced_peak_bytes': peak, 'fresh_executions': backend.calls,
                              'package_install': 'not_performed', 'sdk_setup': 'not_performed'})
    def concurrent(_):
        with tempfile.TemporaryDirectory(prefix='lqg-concurrent-') as directory:
            root = Path(directory)
            fixture = make_fixture(root, stack='javascript', files=8, packages=1, scope='changed', typed=False)
            backend = FixtureExecutor()
            result = run_registry(root, fixture['base'], executor=backend)
            if not any(r['execution_status'] == 'PASS' for r in result):
                raise RuntimeError('concurrent synthetic fixture failed')
            return backend.calls
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        executions = sum(pool.map(concurrent, range(workers)))
    return {'schema_version': 1, 'evidence_kind': 'synthetic-fixture-benchmark',
            'created_at': datetime.now(timezone.utc).isoformat(), 'source': _source_identity(),
            'host': {'platform': platform.platform(), 'python': platform.python_version(), 'cpu_allocation': allocation.to_dict()},
            'sample_count': samples, 'cases': cases,
            'concurrent_fixture': {'workers': workers, 'wall_ms_including_fixture_setup': round((time.perf_counter() - started) * 1000, 3), 'fresh_executions': executions},
            'real_sdk_smoke': 'NOT_RUN', 'external_ci_baseline': 'unavailable', 'qualifies_latency_targets': False,
            'llm_calls': 0, 'measurement_notes': [
                'Real Git discovery, scope, input hashing, argv construction, normalization, evidence and cache use a deterministic injected output producer.',
                'Wall samples include discovery and cache persistence. Queue is the largest wait inside the serial registry; other stage values are sums.',
                'Cold means empty Getzilla cache, not a cold OS page cache. Warm means unverified diagnostic reuse, not fresh SDK execution.',
                'Typed fixtures contain TypeScript syntax; no real typed analyzer, SDK setup, container startup, external CI queue or package install is measured.',
                'Memory is peak Python allocation from tracemalloc, not RSS or container RAM. CPU samples measure this process only.',
                'Small fixture samples do not establish p50/p95 production latency or the 5 percent and 10 percent rollout targets.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=int, default=5)
    parser.add_argument('--concurrency', type=int, default=2)
    parser.add_argument('--quick', action='store_true')
    arguments = parser.parse_args()
    print(json.dumps(run_benchmarks(samples=arguments.samples, quick=arguments.quick, concurrency=arguments.concurrency), indent=2))
