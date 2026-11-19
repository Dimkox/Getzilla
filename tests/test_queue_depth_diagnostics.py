"""NEW handwritten graph diagnostics; no Root project graph or external process."""
from __future__ import annotations

import ast
from contextlib import contextmanager
from dataclasses import asdict, FrozenInstanceError
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import architecture, architecture_fitness as fit


class QueueDepthDiagnosticTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='owned-queue-context-', dir=ROOT / '.getzilla/runtime')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        child = patch('subprocess.Popen', side_effect=AssertionError('unowned child forbidden'))
        child.start()
        self.addCleanup(child.stop)

    def graph(self, count, *, declaration=False):
        name = 'work' if declaration else 'app'
        bodies = {}
        for index in range(count):
            bodies[f'toy.m{index}'] = ((f'from toy.m{index + 1} import {name}\n') if index + 1 < count else
                ('def work():\n    return None\n' if declaration else "import celery\napp = celery.Celery('owned')\n")).encode()
        return self.cache(bodies)

    def cache(self, bodies):
        values = {name: fit._QueueAdapterResolution('prefetched', 'source', sources=(
            (name.replace('.', '/') + '.py', body, name.rpartition('.')[0]),)) for name, body in bodies.items()}
        paths = tuple(sorted(name.replace('.', '/') + '.py' for name in bodies))
        return fit._QueueResolutionCache(tuple(sorted(bodies)), paths, values, {})

    @contextmanager
    def inputs(self, cache):
        sources = {p: body for item in cache.values.values() for p, body, _package in item.sources}
        def read_many(root, diff, paths, side):
            self.assertEqual(root, self.root)
            self.assertIn(side, ('head', 'base'))
            self.assertTrue(set(paths) <= set(sources))
            return {path: sources[path] for path in paths}
        with patch.object(fit, 'read_diff_files', side_effect=read_many):
            yield

    def resolve(self, cache, module='toy.m0', *, side='head', active=None, declaration=False, budget=None):
        with self.inputs(cache):
            return fit._local_queue_resolution(self.root, None, module, side, cache,
                set() if active is None else active, set(), ('',),
                frozenset({'work' if declaration else 'app'}), declaration, budget)

    def refusal(self, boundary):
        if boundary == 'declaration-depth':
            cache = self.cache({'toy.leaf': b'def work():\n    return None\n'})
            active = {f'owned.p{i}' for i in range(8)}
            with self.assertRaises(architecture.ArchitectureError) as caught:
                self.resolve(cache, 'toy.leaf', active=active, declaration=True)
        else:
            cache = self.graph(9)
            if boundary == 'cached-height':
                warm = self.resolve(cache, 'toy.m5')
                self.assertEqual(warm.height, 4)
            with self.assertRaises(architecture.ArchitectureError) as caught:
                self.resolve(cache)
        error = caught.exception
        self.assertIs(type(error), architecture.ArchitectureError)
        self.assertIs(fit.ArchitectureError, architecture.ArchitectureError)
        self.assertEqual(error.args, ('queue adapter depth limit exceeded',))
        self.assertEqual(str(error), 'queue adapter depth limit exceeded')
        self.assertEqual((error.code, error.document, error.line, error.column), ('limit', None, None, None))
        return error

    def context(self, error, boundary):
        context = getattr(error, '_queue_depth_context', None)
        self.assertIsNotNone(context, 'real depth refusal loses its measured boundary context')
        self.assertEqual(context.boundary, boundary)
        self.assertEqual(context.side, 'head')
        self.assertEqual(context.limit, 8)
        self.assertEqual(context.attempted_depth, 9)
        self.assertEqual(tuple(sorted(context.active_modules)), context.active_modules)
        with self.assertRaises(FrozenInstanceError):
            context.limit = 9
        return context

    def test_live_ninth_module_retains_exact_error_and_actual_active_set(self):
        context = self.context(self.refusal('live-depth'), 'live-depth')
        self.assertEqual(context.attempted_module, 'toy.m8')
        self.assertEqual(context.active_count, 8)
        self.assertEqual(context.active_modules, tuple(f'toy.m{i}' for i in range(8)))
        self.assertIsNone(context.cached_height)

    def test_warm_cached_subtree_preserves_its_distinct_height_and_footprint(self):
        context = self.context(self.refusal('cached-height'), 'cached-height')
        self.assertEqual(context.attempted_module, 'toy.m5')
        self.assertEqual(context.active_count, 5)
        self.assertEqual(context.cached_height, 4)
        self.assertEqual(context.cached_count, 4)
        self.assertEqual(context.cached_modules, tuple(f'toy.m{i}' for i in range(5, 9)))

    def test_declaration_leaf_still_charges_one_real_depth(self):
        context = self.context(self.refusal('declaration-depth'), 'declaration-depth')
        self.assertEqual(context.attempted_module, 'toy.leaf')
        self.assertEqual(context.active_count, 8)
        self.assertEqual(context.active_modules, tuple(f'owned.p{i}' for i in range(8)))
        self.assertIsNone(context.cached_height)

    def test_seven_eight_cold_warm_and_cycle_semantics_are_unchanged(self):
        for count in (7, 8):
            cache = self.graph(count)
            for attempt in range(2):
                with self.subTest(count=count, attempt=attempt):
                    budget = fit._QueueBudget('head')
                    result = self.resolve(cache, budget=budget)
                    self.assertEqual(result.state, 'resolved')
                    self.assertEqual(result.height, count)
                    self.assertEqual(result.modules, frozenset(f'toy.m{i}' for i in range(count)))
                    self.assertEqual(len(budget.sources), count)
        cache = self.graph(8)
        active = {f'toy.m{i}' for i in range(8)}
        result = self.resolve(cache, active=active)
        self.assertEqual((result.state, result.reason), ('unsupported', 'cyclic_local_queue_adapter'))
        self.assertFalse(hasattr(result, '_queue_depth_context'))

    def collect(self, error, *, count=1):
        paths = tuple(f'owned/jobs{i:03}.py' for i in range(count))
        python = SimpleNamespace(tree=lambda path: ast.parse('pass'))
        snapshot = SimpleNamespace(rules={'background_job_policies': [{'id': 'TOY-JOBS'}]},
                                   system={'nodes': [], 'edges': []})
        with patch.object(fit, '_python_paths', return_value=paths), \
                patch.object(fit, '_queue_module_inventory', return_value=SimpleNamespace(paths=())), \
                patch.object(fit, '_module_package', return_value=''), \
                patch.object(fit, 'read_diff_file', return_value=b'import owned\n'), \
                patch.object(fit, '_queue_signals', side_effect=error):
            provenance = fit._new_queue_sources(self.root, None, python, ())
            result = fit._background_jobs(self.root, snapshot,
                SimpleNamespace(baseline_introduced=False, changes=()), python, provenance)
        return provenance, result

    def advisory(self, provenance):
        return [json.loads(x.split(': ', 1)[1]) for x in fit._queue_depth_findings(provenance)
                if x.startswith('queue depth context v1: ')]

    def test_privacy_and_overflow_are_explicit_without_truncating_identifiers(self):
        private = 'PRIVATE-CANARY\n'
        for token in (private, 'a' * 97, 'юникод', object()):
            with self.subTest(kind=type(token).__name__):
                error = fit._queue_depth_error('live-depth', token, 'head',
                    {f'owned.m{i}' for i in range(7)} | {private})
                provenance = fit._QueueProvenanceResult('unsupported', 'analysis_limit_exceeded', (),
                    depth_contexts=(('owned/jobs.py', 'head', error._queue_depth_context),))
                encoded = fit._queue_depth_findings(provenance)
                self.assertEqual(len(encoded), 1)
                self.assertNotIn('PRIVATE', encoded[0])
                self.assertLessEqual(len(encoded[0].encode('ascii')), 8192)
                value = self.advisory(provenance)[0]
                self.assertEqual(value['attempted_module'], '<unavailable>')
                self.assertTrue(value['redacted'])
                self.assertEqual(value['active_count'], 8)
        error = fit._queue_depth_error('live-depth', 'owned.next', 'head',
                                      {f'owned.m{i}' for i in range(256)})
        provenance = fit._QueueProvenanceResult('unsupported', 'analysis_limit_exceeded', (),
            depth_contexts=(('owned/jobs.py', 'head', error._queue_depth_context),))
        values = self.advisory(provenance)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]['active_count'], 256)
        self.assertEqual(values[0]['attempted_depth'], 257)
        self.assertEqual(values[0]['active_modules'], [])
        self.assertTrue(values[0]['truncated'])

    def test_forged_contexts_are_not_measurements_or_callback_inputs(self):
        from dataclasses import replace
        context = self.context(self.refusal('live-depth'), 'live-depth')
        calls = []
        class Probe:
            def __eq__(self, other):
                calls.append('unexpected equality callback')
                return False
        variants = [SimpleNamespace(boundary='live-depth'), replace(context, _seal=None),
            replace(context, active_count=0, attempted_depth=1),
            replace(context, active_modules=()), replace(context, attempted_module=Probe())]
        for value in variants:
            with self.subTest(kind=type(value).__name__):
                provenance = fit._QueueProvenanceResult('unsupported', 'analysis_limit_exceeded', (),
                    depth_contexts=(('owned/jobs.py', 'head', value),))
                self.assertEqual(self.advisory(provenance), [])
        self.assertEqual(calls, [])

    def test_sidecar_reaches_both_serializers_and_digest_without_changing_legacy_findings(self):
        error = self.refusal('cached-height')
        provenance, result = self.collect(error, count=70)
        legacy = tuple((f'owned/jobs{i:03}.py', 'head', 'queue adapter depth limit exceeded') for i in range(70))
        self.assertEqual(provenance.limits, legacy)
        self.assertEqual((provenance.state, provenance.reason), ('unsupported', 'analysis_limit_exceeded'))
        self.assertEqual(len(provenance.depth_contexts), 64)
        self.assertEqual(provenance.depth_contexts_omitted, 6)
        self.assertEqual(len(self.advisory(provenance)), 64)
        self.assertIn('queue depth contexts omitted v1: 6', result.findings)
        for path, side, message in legacy:
            self.assertIn(f'analysis limit exceeded ({side}): {path}: {message}', result.findings)
        payload = fit._result_payload(result)
        self.assertEqual(json.loads(json.dumps(payload)), json.loads(json.dumps(asdict(result))))
        plain = fit._QueueProvenanceResult('unsupported', 'analysis_limit_exceeded', (), (), legacy)
        snapshot = SimpleNamespace(rules={'background_job_policies': [{'id': 'TOY-JOBS'}]})
        baseline = fit._background_jobs(self.root, snapshot, None, None, plain)
        self.assertEqual(result.status, baseline.status)
        self.assertEqual(result.applicability, baseline.applicability)
        self.assertEqual(result.rule_ids, baseline.rule_ids)
        self.assertNotEqual(fit._digest({'results': [payload]}),
                            fit._digest({'results': [fit._result_payload(baseline)]}))
        self.assertEqual(fit._QueueProvenanceResult('not_queue', 'none', (), (), (), (), True)[:7],
                         ('not_queue', 'none', (), (), (), (), True))
        self.assertEqual(plain.depth_contexts, ())
        self.assertEqual(fit._queue_depth_findings(plain), ())

    def test_canonical_bounded_cache_sets_and_unavailable_fields(self):
        from dataclasses import replace
        active = {f'p{i}.' + 'a' * 93 for i in range(5)}
        cached = {f'c{i:02}.' + 'b' * 92 for i in range(64)}
        first = fit._queue_depth_error('cached-height', 'owned.next', 'head', active,
                                      cached_height=4, cached_modules=frozenset(cached))
        second = fit._queue_depth_error('cached-height', 'owned.next', 'head', set(reversed(sorted(active))),
                                       cached_height=4, cached_modules=frozenset(reversed(sorted(cached))))
        def project(context):
            return fit._QueueProvenanceResult('unsupported', 'analysis_limit_exceeded', (),
                depth_contexts=(('owned/jobs.py', 'head', context),))
        left = fit._queue_depth_findings(project(first._queue_depth_context))
        self.assertEqual(left, fit._queue_depth_findings(project(second._queue_depth_context)))
        self.assertEqual(len(left), 1)
        self.assertLessEqual(len(left[0].encode('ascii')), 8192)
        measured = self.context(self.refusal('cached-height'), 'cached-height')
        forged = replace(measured, cached_count=None, cached_modules=(), unavailable=False)
        self.assertEqual(self.advisory(project(forged)), [])
        unknown = fit._queue_depth_error('cached-height', 'owned.next', 'head', {'owned.parent'},
                                        cached_height=True, cached_modules=None)
        value = self.advisory(project(unknown._queue_depth_context))[0]
        self.assertIsNone(value['cached_height'])
        self.assertIsNone(value['attempted_depth'])
        self.assertTrue(value['unavailable'])

    def test_optional_diagnostic_faults_preserve_refusal_and_interrupt_identity(self):
        with patch.object(fit, '_queue_depth_token', side_effect=RuntimeError('PRIVATE-FAILURE')):
            error = fit._queue_depth_error('live-depth', 'owned.next', 'head', {'owned.parent'})
        self.assertEqual(error.args, ('queue adapter depth limit exceeded',))
        self.assertIs(type(error), architecture.ArchitectureError)
        self.assertFalse(hasattr(error, '_queue_depth_context'))
        context = self.context(self.refusal('live-depth'), 'live-depth')
        provenance = fit._QueueProvenanceResult('unsupported', 'analysis_limit_exceeded', (),
            depth_contexts=(('owned/jobs.py', 'head', context),))
        with patch.object(fit.json, 'dumps', side_effect=RuntimeError('PRIVATE-RENDER')):
            finding = fit._queue_depth_findings(provenance)
        self.assertEqual(finding, ('queue depth contexts v1: {"unavailable":true}',))
        real_error = self.refusal('live-depth')
        with patch.object(fit, '_queue_depth_context_valid', side_effect=RuntimeError('PRIVATE-CAPTURE')):
            try:
                retained, result = self.collect(real_error)
            except RuntimeError:
                self.fail('optional context validation masked the original limit refusal')
        self.assertEqual(retained.limits, (('owned/jobs000.py', 'head', str(real_error)),))
        self.assertEqual(result.status, 'unsupported')
        for error in (KeyboardInterrupt(), SystemExit(23)):
            with self.subTest(kind=type(error).__name__):
                with patch.object(fit, '_queue_depth_token', side_effect=error), self.assertRaises(type(error)) as caught:
                    fit._queue_depth_error('live-depth', 'owned.next', 'head', set())
                self.assertIs(caught.exception, error)
                with patch.object(fit.json, 'dumps', side_effect=error), self.assertRaises(type(error)) as caught:
                    fit._queue_depth_findings(provenance)
                self.assertIs(caught.exception, error)

    def test_other_errors_missing_sources_and_plain_lookalikes_gain_no_depth_claim(self):
        plain = architecture.ArchitectureError('queue adapter depth limit exceeded', code='limit')
        provenance, result = self.collect(plain)
        self.assertEqual(fit._queue_depth_findings(provenance), ())
        self.assertEqual(provenance.limits, (('owned/jobs000.py', 'head', str(plain)),))
        self.assertEqual(result.status, 'unsupported')
        opaque = fit._UnsupportedQueueCallbackError('PRIVATE-CALLBACK', code='fitness')
        provenance, result = self.collect(opaque)
        self.assertEqual(provenance.limits, ())
        self.assertEqual(provenance.reason, 'queue_provenance_unresolved')
        self.assertNotIn('PRIVATE', json.dumps(asdict(result)))
        cache = self.graph(1)
        missing = self.resolve(cache, module='toy.absent')
        self.assertEqual((missing.state, missing.reason), ('not_queue', 'local_module_missing'))
        with self.inputs(cache), self.assertRaises(architecture.ArchitectureError) as caught:
            fit._local_queue_resolution(self.root, None, 'toy.m0', 'head', cache, set(),
                {f'visited.m{i}' for i in range(64)}, ('',))
        self.assertEqual(str(caught.exception), 'queue adapter module limit exceeded')
        self.assertFalse(hasattr(caught.exception, '_queue_depth_context'))
