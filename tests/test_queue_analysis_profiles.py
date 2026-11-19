"""The reviewed self profile changes resources, never queue proof rules."""
import ast
import hashlib
from unittest.mock import patch
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import architecture_fitness as fit


class QueueAnalysisProfileTests(unittest.TestCase):
    def self_profile(self):
        self.assertTrue(hasattr(fit, '_GETZILLA_SELF_PROFILE'), 'missing distinct reviewed self profile')
        return fit._GETZILLA_SELF_PROFILE

    def test_self_module128_boundary_and_default64_are_independent(self):
        profile = self.self_profile()
        self.assertEqual(fit.MAX_QUEUE_ADAPTER_MODULES, 64)
        for total in (64, 128):
            budget = fit._QueueBudget('head', profile=profile if total == 128 else None)
            for index in range(total):
                budget.source(f'm{index}.py', b'value=1\n')
            self.assertEqual(len(budget.sources), total)
            with self.assertRaises(fit.ArchitectureError) as caught:
                budget.source('overflow.py', b'value=2\n')
            self.assertEqual(caught.exception.queue_refusal['category'], 'modules')
            self.assertEqual(caught.exception.queue_refusal['limit'], total)
            self.assertEqual(caught.exception.queue_refusal['observed'], total + 1)

    def test_self_four_mib_exact_boundary_never_resets_default(self):
        profile = self.self_profile()
        self.assertEqual(fit.MAX_QUEUE_ANALYSIS_BYTES, 2 * 1024 * 1024)
        for limit, selected in ((2 * 1024 * 1024, None), (4 * 1024 * 1024, profile)):
            budget = fit._QueueBudget('head', profile=selected)
            budget.source('owned.py', b'#' * (limit - 1))
            budget.source('tail.py', b'\n')
            self.assertEqual(budget.source_bytes, limit)
            with self.assertRaises(fit.ArchitectureError) as caught:
                budget.source('overflow.py', b'x')
            self.assertEqual(caught.exception.queue_refusal['category'], 'bytes')
            self.assertEqual(caught.exception.queue_refusal['observed'], limit + 1)

    def test_self_warm_footprint_cannot_enter_default_or_other_side(self):
        selected = fit._QueueBudget('head', profile=self.self_profile())
        frame = selected.enter('actual')
        selected.source('owned.py', b'owned=1\n')
        footprint = selected.leave(frame)
        for strict in (fit._QueueBudget('head'), fit._QueueBudget('base', profile=self.self_profile())):
            with self.assertRaises(fit.ArchitectureError):
                strict.merge(footprint)
        replay = fit._QueueBudget('head', profile=self.self_profile())
        replay.merge(footprint)
        self.assertEqual(replay.source_bytes, selected.source_bytes)

    def test_policy_selection_is_source_bound_and_absent_consumer_stays_default(self):
        self.self_profile()
        selected = fit._queue_analysis_profile(ROOT, None, 'head')
        self.assertEqual((selected.name, selected.module_limit, selected.byte_limit), ('getzilla-self-v1', 128, 4194304))
        with tempfile.TemporaryDirectory() as directory:
            consumer = Path(directory)
            self.assertEqual(fit._queue_analysis_profile(consumer, None, 'head').name, 'consumer-v1')
            policy = consumer / 'architecture/queue-analysis-profile.json'
            policy.parent.mkdir()
            policy.write_bytes((ROOT / 'architecture/queue-analysis-profile.json').read_bytes())
            with self.assertRaises(fit.ArchitectureError):
                fit._queue_analysis_profile(consumer, None, 'head')
            policy.write_bytes(b'{"profile":"getzilla-self-v1","modules":999}')
            with self.assertRaises(fit.ArchitectureError):
                fit._queue_analysis_profile(consumer, None, 'head')

    def test_policy_source_is_in_native_verification_binding(self):
        from getzilla.verification_plan import policy_binding
        values = policy_binding(ROOT)
        path = ROOT / 'architecture/queue-analysis-profile.json'
        self.assertTrue(path.is_file(), 'missing reviewed explicit source policy')
        self.assertEqual(values['inputs'].get('architecture/queue-analysis-profile.json'),
                         hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertIn('queue_analysis_profile.py', values['implementation'])

    def test_real128_graph_cold_warm_and129_refusal_keep_tail_proof(self):
        from tests.test_architecture_fitness import GitArchitectureRepo, DIFF, ARCHITECTURE
        from tests.test_architecture_model import _system, _rules
        for count in (128, 129):
            with self.subTest(count=count):
                repo = GitArchitectureRepo(self)
                model = _system()
                model['nodes'][0]['repository_paths'] = ['src']
                repo.model(model, _rules())
                leaves = count - 1
                for index in range(leaves):
                    repo.write_text(f'src/p{index}.py',
                        'from rq import Queue\nvalue = Queue()\n' if index == leaves - 1 else 'value = 1\n')
                repo.write_text('src/use.py', '')
                base = repo.commit('profile real graph baseline')
                source = ''.join(f'from p{i} import value as v{i}\n' for i in range(leaves))
                source += ''.join(f'v{i}.enqueue(job)\n' for i in range(leaves))
                repo.write_text('src/use.py', source)
                head = repo.commit('profile real graph queue tail')
                diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                roots = fit._queue_source_roots(ARCHITECTURE.load_architecture(repo.root))
                # Isolate resource accounting from independently tested native
                # selection; no fixture metadata grants a real self profile.
                with patch.object(fit, '_queue_analysis_profile', return_value=self.self_profile()):
                    cache = fit._queue_module_inventory(repo.root, diff, 'head', roots)
                    observations = []
                    for _ in range(2):
                        budget = fit._QueueBudget('head', profile=cache.profile)
                        if count == 129:
                            with self.assertRaises(fit.ArchitectureError):
                                fit._queue_signals(repo.root, diff, ast.parse(source), 'head', cache, '', roots,
                                    source_path='src/use.py', source=source.encode(), budget=budget)
                        else:
                            result = fit._queue_signals(repo.root, diff, ast.parse(source), 'head', cache, '', roots,
                                source_path='src/use.py', source=source.encode(), budget=budget)
                            self.assertEqual(result.state, 'resolved')
                            self.assertTrue(result.signals)
                            self.assertEqual(len(budget.sources), 128)
                            observations.append((budget.source_bytes, budget.ast_nodes, budget.logical_work))
                    if observations:
                        self.assertEqual(observations[0], observations[1])
                    strict = fit._QueueBudget('head')
                    with self.assertRaisesRegex(fit.ArchitectureError, 'profile'):
                        fit._queue_signals(repo.root, diff, ast.parse(source), 'head', cache, '', roots,
                            source_path='src/use.py', source=source.encode(), budget=strict)

    def test_native_profile_cache_cannot_cross_project_and_policy_tamper_refuses(self):
        selected = fit._queue_analysis_profile(ROOT, None, 'head')
        cache = fit._QueueResolutionCache((), (), {}, {}, selected)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(fit.ArchitectureError, 'profile'):
                fit._queue_signals(root, None, ast.parse('value=1'), 'head', cache, '', ('',),
                    source=b'value=1', budget=fit._QueueBudget('head', profile=selected))
        from tests.test_architecture_fitness import GitArchitectureRepo
        from getzilla import queue_analysis_profile as profiles
        repo = GitArchitectureRepo(self)
        repo.write_bytes(profiles.POLICY_PATH, profiles.POLICY_SOURCE)
        anchor = repo.commit('private exact policy custody fixture')
        with patch.object(profiles, 'SELF_ANCHOR', anchor):
            actual = fit._queue_analysis_profile(repo.root, None, 'head')
            self.assertEqual(actual.name, 'getzilla-self-v1')
            repo.write_bytes(profiles.POLICY_PATH, profiles.POLICY_SOURCE + b' ')
            with self.assertRaisesRegex(fit.ArchitectureError, 'policy'):
                fit._queue_analysis_profile(repo.root, None, 'head')

    def test_arbitrary_resource_profile_is_not_a_caller_limit(self):
        from getzilla.queue_analysis_profile import QueueAnalysisProfile
        for value in ((128, 4194304), QueueAnalysisProfile('getzilla-self-v1', 129, 4194304, ''),
                      QueueAnalysisProfile('consumer-v1', 128, 4194304, '')):
            with self.subTest(value=value), self.assertRaises(fit.ArchitectureError):
                fit._QueueBudget('head', profile=value)

    def test_actual_selector_source_mutation_changes_verification_policy(self):
        from getzilla import queue_analysis_profile as profiles
        from getzilla.verification_plan import policy_binding
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = policy_binding(root)
            raw = (ROOT / '.getzilla/getzilla/queue_analysis_profile.py').read_bytes()
            changed = raw + b'\n# source policy body mutation control\n'
            with patch.object(profiles.__loader__, 'get_data', return_value=changed):
                after = policy_binding(root)
            self.assertEqual(after['implementation']['queue_analysis_profile.py'], hashlib.sha256(changed).hexdigest())
            self.assertNotEqual(before['digest'], after['digest'])

    def test_current_invocation_profile_covers_historical_base_without_policy(self):
        from types import SimpleNamespace
        from getzilla.queue_analysis_profile import SELF_ANCHOR
        head = fit._queue_analysis_profile(ROOT, None, 'head')
        base = fit._queue_analysis_profile(ROOT, SimpleNamespace(base_sha=SELF_ANCHOR), 'base')
        self.assertEqual((head.module_limit, head.byte_limit), (128, 4194304))
        self.assertEqual((base.module_limit, base.byte_limit), (128, 4194304))
        self.assertNotEqual(base.binding, head.binding)
