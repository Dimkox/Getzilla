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
        for strict, reason in ((fit._QueueBudget('head'), 'profile'),
                               (fit._QueueBudget('base', profile=self.self_profile()), 'side')):
            with self.assertRaisesRegex(fit.ArchitectureError, reason):
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
                            with self.assertRaises(fit.ArchitectureError) as caught:
                                fit._queue_signals(repo.root, diff, ast.parse(source), 'head', cache, '', roots,
                                    source_path='src/use.py', source=source.encode(), budget=budget)
                            self.assertEqual(caught.exception.queue_refusal['category'], 'modules')
                            self.assertEqual(caught.exception.queue_refusal['limit'], 128)
                            self.assertEqual(caught.exception.queue_refusal['observed'], 129)
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

    def test_text_recognition_owns_exact_tables_without_policy_dependency(self):
        from getzilla import security_license_texts as texts, security_license_family_conditions as family
        from getzilla import security_license_source_conditions as source, security_license_go_term_variants as variants
        tree = ast.parse((ROOT / '.getzilla/getzilla/security_license_texts.py').read_bytes())
        forbidden = {'security_license_family_conditions', 'security_license_source_conditions',
                     'security_license_go_term_variants'}
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module in forbidden
                             for node in ast.walk(tree)), 'recognition must not import policy evaluators')
        self.assertIs(family.TEXTS, texts._CONDITIONAL_TEXTS)
        self.assertIs(source.TEXTS, texts._SOURCE_CONDITIONAL_TEXTS)
        self.assertIs(variants.FILES, texts._GO_FILES)
        self.assertIs(variants.BUNDLES, texts._GO_BUNDLES)
        self.assertIs(variants.EXPRESSIONS, texts._GO_EXPRESSIONS)

    def test_actual_recognition_and_condition_owners_all_change_policy_on_body_mutation(self):
        import importlib
        from getzilla.verification_plan import policy_binding
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = policy_binding(root)
            for name in ('queue_source_resolution', 'queue_source_scan', 'cpu_budget', 'architecture_metadata', 'security_go_tool_producer', 'security_go_contracts', 'security_go_tool_inputs', 'security_license_texts', 'security_license_family_conditions',
                         'security_license_source_conditions', 'security_license_go_term_variants'):
                with self.subTest(owner=name):
                    module = importlib.import_module('getzilla.' + name)
                    raw = (ROOT / '.getzilla/getzilla' / (name + '.py')).read_bytes()
                    changed = raw + b'\n# actual source body mutation control\n'
                    with patch.object(module.__loader__, 'get_data', return_value=changed):
                        after = policy_binding(root)
                    self.assertEqual(after['implementation'][name + '.py'], hashlib.sha256(changed).hexdigest())
                    self.assertNotEqual(before['digest'], after['digest'])

    def test_go_wire_fields_preserve_closed_factual_validator_projection(self):
        from getzilla.python_source_proof import namespace_is_closed
        source = (ROOT / '.getzilla/getzilla/security_go_tool_inputs.py').read_bytes()
        tree = ast.parse(source)
        self.assertTrue(namespace_is_closed(tree, allow_instrumentation=True, static_import_reads=True,
                                            forbidden_imports=fit._QUEUE_IMPORTS))
        projection = fit._queue_export_slice(tree, frozenset({'verify_family'}))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'security_licenses'
                             for node in ast.walk(projection)))
        from getzilla.security_go_contracts import MODULES_KEY
        self.assertEqual(MODULES_KEY, 'modules')

    def test_go_contract_is_visible_literal_data_and_real_reflection_still_refuses(self):
        from getzilla.python_source_proof import namespace_is_closed
        from getzilla import security_go_contracts as contract, security_go_tool_producer as producer
        tree = ast.parse((ROOT / '.getzilla/getzilla/security_go_contracts.py').read_bytes())
        self.assertTrue(all(isinstance(node, (ast.Assign, ast.Expr)) for node in tree.body))
        self.assertFalse(any(isinstance(node, (ast.FunctionDef, ast.Call, ast.Attribute)) for node in ast.walk(tree)))
        self.assertTrue(any(isinstance(node, ast.Constant) and node.value == 'modules' for node in ast.walk(tree)))
        for source in ('import sys\nvalue=sys.modules\n', 'value=getattr(subject, \"__dict__\")\n'):
            self.assertFalse(namespace_is_closed(ast.parse(source), allow_instrumentation=True,
                                                 static_import_reads=True, forbidden_imports=fit._QUEUE_IMPORTS))
        self.assertIsNone(fit._module_member_demands(ast.parse('value=getattr(subject, name)'), 'subject'))
        old = dict(schema_version=1, kind='go-checker-components/v1', tool_id='owned', release='1',
                   modules={'owned': 'fact'}, source_locks={}, runtime={}, expressions={})
        current = {'schema_version': 1, 'kind': 'go-checker-components/v1', 'tool_id': 'owned', 'release': '1',
                   contract.MODULES_KEY: {'owned': 'fact'}, 'source_locks': {}, 'runtime': {}, 'expressions': {}}
        self.assertEqual(producer.canonical(old), producer.canonical(current))
        source = ast.parse((ROOT / '.getzilla/getzilla/security_go_tool_producer.py').read_bytes())
        self.assertTrue(any(isinstance(node, ast.Dict) and any(isinstance(key, ast.Name)
                             and key.id == 'MODULES_KEY' for key in node.keys) for node in ast.walk(source)))

    def test_copied_policy_in_real_foreign_git_repository_has_no_self_authority(self):
        from tests.test_architecture_fitness import GitArchitectureRepo
        from getzilla.queue_analysis_profile import POLICY_PATH, POLICY_SOURCE
        foreign = GitArchitectureRepo(self)
        foreign.write_bytes(POLICY_PATH, POLICY_SOURCE)
        foreign.commit('foreign copied policy is data only')
        with self.assertRaisesRegex(fit.ArchitectureError, 'Getzilla source ancestry'):
            fit._queue_analysis_profile(foreign.root, None, 'head')

    def test_profile_change_during_analysis_cannot_return_cached_classification(self):
        from types import SimpleNamespace
        selected = self.self_profile()
        cache = fit._QueueResolutionCache((), (), {}, {}, selected)
        with tempfile.TemporaryDirectory() as directory, patch.object(
                fit, '_queue_analysis_profile', side_effect=(selected, fit._CONSUMER_PROFILE)):
            with self.assertRaisesRegex(fit.ArchitectureError, 'profile changed'):
                fit._queue_signals(Path(directory), SimpleNamespace(head_kind='worktree'), ast.parse('value=1'), 'head', cache, '', ('',),
                    source=b'value=1', budget=fit._QueueBudget('head', profile=selected))

    def test_factory_listing_has_no_context_facade_and_keeps_completed_stop_contract(self):
        from getzilla import security_factory_inputs as factory, verification_actions as actions
        from getzilla import python_test_runner as runner
        from getzilla.security_data import SecurityDataError
        tree = ast.parse((ROOT / '.getzilla/getzilla/security_factory_inputs.py').read_bytes())
        selected = fit._queue_export_slice(tree, frozenset({'_app_members'}))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'public_security_context'
                             for node in ast.walk(selected)))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scratch = root / 'scratch'
            scratch.mkdir()
            relative = 'factory/src/getzilla_factory/owned.py'
            path = root / relative
            path.parent.mkdir(parents=True)
            path.write_bytes(b'owned current source')
            environment = {'OWNED': 'exact sanitized environment'}
            completed = runner.ProcessResult(['git'], 0, stdout=relative + '\n')
            with patch('getzilla.python_test_runner.execute', return_value=completed) as execute, \
                    patch('getzilla.security_tools._environment', return_value=environment):
                members = factory._app_members(root, scratch)
            self.assertEqual(members, {'app/getzilla_factory/owned.py': {
                'size': len(path.read_bytes()), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}})
            call = execute.call_args
            self.assertEqual(call.args[0], ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                                           '-C', str(root), 'ls-files', 'factory/src/getzilla_factory'])
            self.assertEqual(call.args[1].parent, scratch)
            self.assertEqual(call.args[2], environment)
            self.assertEqual(call.kwargs, {'timeout': 30})
            for result in (runner.ProcessResult(['git'], 1, stop_metadata=actions.child_stop(1)),
                           runner.ProcessResult(['git'], 124, terminal_state='timed_out',
                               stop_metadata=actions.StopMetadata(decision='deadline', result_policy='limit_124', scope='process')),
                           runner.ProcessResult(['git'], 0, cleanup_error='uncertain', stop_metadata=actions.child_stop(0))):
                with self.subTest(state=result.terminal_state, cleanup=result.cleanup_error), \
                        patch('getzilla.python_test_runner.execute', return_value=result), \
                        patch('getzilla.security_tools._environment', return_value=environment):
                    with self.assertRaisesRegex(SecurityDataError, 'completed Git observation') as caught:
                        factory._app_members(root, scratch)
                    self.assertEqual(actions.stop_details(caught.exception), actions.stop_details(result))
            for error in (OSError('owned failure'), runner.RunCancelled(2, completed)):
                with self.subTest(error=type(error).__name__), \
                        patch('getzilla.python_test_runner.execute', side_effect=error), \
                        patch('getzilla.security_tools._environment', return_value=environment):
                    with self.assertRaises(type(error)) as caught:
                        factory._app_members(root, scratch)
                    self.assertIs(caught.exception, error)

    def test_readonly_metadata_proofs_have_real_owner_and_exact_fit_aliases(self):
        names = {'_instrumentation_targets_closed', '_byte_only_http_imports',
                 '_constructor_only_urllib_imports', '_component_metadata_head', '_trust_ci_metadata_paths'}
        tree = ast.parse((ROOT / '.getzilla/getzilla/architecture_fitness.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.FunctionDef) and node.name in names for node in tree.body),
                         'readonly metadata proof bodies still enlarge the fitness owner')
        from getzilla import architecture_metadata as metadata
        for name in names:
            self.assertIs(getattr(fit, name), getattr(metadata, name))

    def test_changed_source_scan_has_actual_owner_and_canonical_result_types(self):
        tree = ast.parse((ROOT / '.getzilla/getzilla/architecture_fitness.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.FunctionDef) and node.name == '_new_queue_sources'
                             for node in tree.body))
        from getzilla import queue_source_scan as scan
        self.assertIs(fit._new_queue_sources, scan._new_queue_sources)
        self.assertIs(fit._QueueProvenanceResult, scan._QueueProvenanceResult)

    def test_extracted_owner_leaf_first_imports_preserve_fit_identity(self):
        import subprocess
        for first in ('architecture_metadata', 'queue_source_scan', 'queue_source_resolution'):
            code = ("import sys,importlib;sys.path.insert(0,sys.argv[1]);"
                    "importlib.import_module('getzilla.'+sys.argv[2]);"
                    "from getzilla import architecture_fitness as f,architecture_metadata as m,queue_source_scan as s;"
                    "assert f._new_queue_sources is s._new_queue_sources;"
                    "assert f._QueueProvenanceResult is s._QueueProvenanceResult;"
                    "assert f._trust_ci_metadata_paths is m._trust_ci_metadata_paths")
            with self.subTest(first=first):
                result = subprocess.run([sys.executable, '-B', '-c', code, str(ROOT / '.getzilla'), first],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_queue_resolution_and_syntax_have_real_owner_and_exact_patchpoints(self):
        names = {'_queue_return_exports_scoped', '_queue_projected_return',
                 '_call_use_inventory', '_discarded_call_results', '_inventory_use_proof',
                 '_local_queue_resolution', '_local_queue_resolution_impl', '_queue_adapter_names'}
        tree = ast.parse((ROOT / '.getzilla/getzilla/architecture_fitness.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.FunctionDef) and node.name in names for node in tree.body))
        from getzilla import queue_source_resolution as resolver
        for name in names:
            self.assertIs(getattr(fit, name), getattr(resolver, name))
        self.assertIs(fit._QueueBudget, resolver._QueueBudget)
        self.assertIs(fit._QueueResolutionCache, resolver._QueueResolutionCache)

    def test_language_adapter_loader_is_real_owner_with_unchanged_closed_core(self):
        import importlib
        from getzilla.python_source_proof import namespace_is_closed
        from getzilla.language_quality import core, adapters
        tree = ast.parse((ROOT / '.getzilla/getzilla/language_quality/core.py').read_bytes())
        self.assertTrue(namespace_is_closed(tree, allow_instrumentation=True, static_import_reads=True,
                                            forbidden_imports=fit._QUEUE_IMPORTS))
        for name in ('eslint', 'kotlin', 'dart', 'swift'):
            self.assertIs(adapters.load_adapter(name), importlib.import_module(
                'getzilla.language_quality.adapters.' + name))
        for name in ('../foreign', 'os', 'unknown', ''):
            with self.assertRaises(ValueError):
                adapters.load_adapter(name)
        with patch.object(adapters.importlib, 'import_module', side_effect=ImportError('owned missing adapter')):
            with self.assertRaisesRegex(ImportError, 'owned missing adapter'):
                adapters.load_adapter('eslint')
        self.assertIs(core.importlib, adapters.importlib)

    def test_language_loader_and_actual_adapter_bodies_are_source_bound(self):
        import importlib
        from getzilla.verification_plan import policy_binding
        labels = ('language_quality/core.py', 'language_quality/adapters/__init__.py',
                  'language_quality/adapters/eslint.py', 'language_quality/adapters/kotlin.py',
                  'language_quality/adapters/dart.py', 'language_quality/adapters/swift.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = policy_binding(root)
            for label in labels:
                with self.subTest(owner=label):
                    identity = label[:-3].replace('/', '.').removesuffix('.__init__')
                    module = importlib.import_module('getzilla.' + identity)
                    raw = (ROOT / '.getzilla/getzilla' / label).read_bytes()
                    changed = raw + b'\n# exact real adapter body mutation control\n'
                    with patch.object(module.__loader__, 'get_data', return_value=changed):
                        after = policy_binding(root)
                    self.assertEqual(after['implementation'][label], hashlib.sha256(changed).hexdigest())
                    self.assertNotEqual(before['digest'], after['digest'])
