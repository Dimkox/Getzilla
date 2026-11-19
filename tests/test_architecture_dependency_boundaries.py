"""Shared range and policy-loader boundaries retain bounded source analysis."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import sys
import tempfile
import unittest
from types import ModuleType, SimpleNamespace
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.architecture_fitness import _QUEUE_IMPORTS, _queue_export_slice
from getzilla.python_source_proof import namespace_is_closed


class ArchitectureDependencyBoundaryTests(unittest.TestCase):
    def test_bare_module_package_fallback_uses_supplied_paths(self):
        from getzilla import architecture_fitness as fitness
        self.assertEqual(fitness._module_package('tools/standalone.py'), 'tools')
        self.assertEqual(fitness._module_package('owned/standalone.py', ('owned',), ()), '')

    def test_fitness_metadata_exports_exclude_reflective_ast_rewriting(self):
        from getzilla import architecture_fitness as fitness
        tree = ast.parse((ROOT / '.getzilla/getzilla/architecture_fitness.py').read_bytes())
        self.assertTrue(namespace_is_closed(tree, allow_instrumentation=True,
                                           static_import_reads=True, forbidden_imports=_QUEUE_IMPORTS))
        projection = _queue_export_slice(tree, frozenset({'_module_package'}))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'python_source_proof'
                             for node in ast.walk(projection)))
        with mock.patch.object(fitness, 'MAX_QUEUE_ADAPTER_MODULES', 0):
            with self.assertRaises(fitness.ArchitectureError) as captured:
                fitness._QueueBudget('head').source('owned.py', b'x = 1\n')
        self.assertEqual(captured.exception.queue_refusal['category'], 'modules')
        self.assertEqual(captured.exception.queue_refusal['limit'], 0)

    def test_each_split_implementation_owner_mutation_changes_policy_binding(self):
        import importlib
        from getzilla.verification_plan import policy_binding
        owners = ('verification_actions.py', 'git_ranges.py', 'governance_records.py',
                  'security_image_authority.py', 'release_transport.py', 'verification_policy_source.py',
                  'workflow_inputs.py', 'workflow_cas.py', 'workflow_storage.py', 'live_evidence.py',
                  'agent_eval_authoring.py', 'security_license_contracts.py', 'grant_authoring.py',
                  'intake_authoring.py', 'security_publication.py', 'security_windows_publication.py',
                  'verification_scope.py', 'public_security_context.py', 'metrics_journal.py',
                  'architecture_fitness.py', 'python_source_proof.py', 'queue_refusal.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = policy_binding(root)['implementation']
            for name in owners:
                with self.subTest(owner=name):
                    module = importlib.import_module('getzilla.' + name[:-3])
                    raw = (ROOT / '.getzilla/getzilla' / name).read_bytes()
                    changed = raw + b'\n# source policy mutation control\n'
                    with mock.patch.object(module.__loader__, 'get_data', return_value=changed):
                        observed = policy_binding(root)['implementation']
                    self.assertEqual(observed[name], hashlib.sha256(changed).hexdigest())
                    self.assertNotEqual(observed[name], original[name])

    def test_stored_workflow_consumer_excludes_cas_publication(self):
        from getzilla import workflow_artifacts, workflow_cas
        context = workflow_artifacts._cas_context()
        self.assertIs(type(context), workflow_cas._CASContext)
        self.assertIs(context.bound_cas_recovery_sequence, workflow_artifacts._CAS_RECOVERY_SEQUENCE)
        self.assertIs(context.bound_workflowartifacterror, workflow_artifacts.WorkflowArtifactError)
        tree = ast.parse((ROOT / '.getzilla/getzilla/workflow_artifacts.py').read_bytes())
        self.assertTrue(namespace_is_closed(tree, allow_instrumentation=True,
                                           static_import_reads=True, forbidden_imports=_QUEUE_IMPORTS))
        projection = _queue_export_slice(tree, frozenset({'validate_stored_workflow'}))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'workflow_cas'
                             for node in ast.walk(projection)))

    def test_eval_read_consumer_excludes_baseline_and_critic_authoring(self):
        from getzilla import agent_evals, agent_eval_authoring
        for name in ('review_quality', 'accept_baseline'):
            self.assertIs(getattr(agent_evals, name), getattr(agent_eval_authoring, name))
        import subprocess
        for first in ('agent_evals', 'agent_eval_authoring'):
            code = ("import sys;sys.path.insert(0,sys.argv[1]);"
                    "__import__('getzilla.'+sys.argv[2]);"
                    "from getzilla import agent_evals as core,agent_eval_authoring as author;"
                    "assert core.accept_baseline is author.accept_baseline;"
                    "assert core.review_quality is author.review_quality")
            observed = subprocess.run([sys.executable, '-B', '-c', code, str(ROOT / '.getzilla'), first],
                                      capture_output=True, text=True, timeout=10)
            self.assertEqual(observed.returncode, 0, observed.stderr)
        tree = ast.parse((ROOT / '.getzilla/getzilla/agent_evals.py').read_bytes())
        projection = _queue_export_slice(tree, frozenset({'required_suites'}))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'agent_eval_authoring'
                             for node in ast.walk(projection)))

    def test_license_catalog_contract_does_not_import_artifact_evaluation(self):
        from getzilla import security_licenses, security_license_contracts
        for name in ('load_policy', 'artifact_catalog_source', '_license_evidence'):
            self.assertIs(getattr(security_licenses, name), getattr(security_license_contracts, name))
        tree = ast.parse((ROOT / '.getzilla/getzilla/security_license_contracts.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'security_licenses'
                             for node in ast.walk(tree)))
        with self.assertRaises(security_license_contracts.ArtifactError):
            security_license_contracts._policy({})

    def test_live_evidence_consumer_excludes_producer_orchestration(self):
        from getzilla import live_acceptance, live_evidence
        for name in ('valid_binding', 'read_document', 'validate_components', '_held_bytes'):
            self.assertIs(getattr(live_acceptance, name), getattr(live_evidence, name))
        self.assertIs(live_acceptance._ParserObservation, live_evidence._ParserObservation)
        tree = ast.parse((ROOT / '.getzilla/getzilla/verification.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'live_acceptance'
                             for node in ast.walk(tree)))
        self.assertFalse(live_evidence.valid_binding({}))
        import json
        modules = ('live_acceptance', 'disposable_resources', 'factory_tests', 'python_test_runner',
                   'live_lifecycle', 'live_contracts', 'live_evidence', 'verification_policy_source')
        hashes = {}
        for name in modules:
            module = __import__('getzilla.' + name, fromlist=[name])
            hashes[module.__name__] = hashlib.sha256(module.__loader__.get_data(module.__file__)).hexdigest()
        for name in ('trust-ci/tests/run_postgres_suite.py', 'trust-ci/tests/postgres_restart_probe.py'):
            hashes[name] = hashlib.sha256(live_evidence._held_bytes(ROOT / name)).hexdigest()
        expected = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
        self.assertEqual(live_evidence._producer_digest(ROOT, 'trust-ci'), expected)
        with mock.patch.object(live_evidence.__loader__, 'get_data', return_value=b'changed consumer'):
            self.assertNotEqual(live_evidence._producer_digest(ROOT, 'trust-ci'), expected)

    def test_spec_json_pairs_demand_excludes_intake_publication(self):
        tree = ast.parse((ROOT / '.getzilla/getzilla/spec.py').read_bytes())
        self.assertTrue(namespace_is_closed(tree, allow_instrumentation=True,
                                           static_import_reads=True, forbidden_imports=_QUEUE_IMPORTS))
        projection = _queue_export_slice(tree, frozenset({'_pairs_object', '_reject_constant'}))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'intake_publication'
                             for node in ast.walk(projection)))
        from getzilla import spec
        self.assertEqual(spec._pairs_object([('x', 1)]), {'x': 1})
        with self.assertRaises(spec.SpecError):
            spec._pairs_object([('x', 1), ('x', 2)])


    def test_intake_input_demand_does_not_reenter_workflow_compiler(self):
        from getzilla import workflow_artifacts, workflow_inputs
        self.assertIs(workflow_artifacts.WorkflowArtifactError, workflow_inputs.WorkflowArtifactError)
        for name in ('canonical_json', '_strict_json', '_read_regular'):
            self.assertIs(getattr(workflow_artifacts, name), getattr(workflow_inputs, name))
        for name in ('requirements_intake', 'intake_publication'):
            tree = ast.parse((ROOT / ('.getzilla/getzilla/' + name + '.py')).read_bytes())
            self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'workflow_artifacts'
                                 for node in ast.walk(tree)))
        with self.assertRaises(workflow_inputs.WorkflowArtifactError):
            workflow_inputs._strict_json(b'{"x":1,"x":2}', limit=100)
        self.assertEqual(workflow_inputs.canonical_json({'x': 1}), b'{"x":1}\n')

    def test_replay_evaluator_demand_excludes_review_quality_orchestration(self):
        tree = ast.parse((ROOT / '.getzilla/getzilla/agent_evals.py').read_bytes())
        self.assertTrue(namespace_is_closed(tree, allow_instrumentation=True,
                                           static_import_reads=True, forbidden_imports=_QUEUE_IMPORTS))
        projection = _queue_export_slice(tree, frozenset({'required_suites'}))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'review_source'
                             for node in ast.walk(projection)))
        from getzilla import agent_evals
        expected = hashlib.sha256((ROOT / '.getzilla/getzilla/agent_evals.py').read_bytes()).hexdigest()
        self.assertEqual(agent_evals._runner_digest(), expected)
        with mock.patch.dict(agent_evals.__dict__, clear=False):
            del agent_evals.__loader__
            with self.assertRaisesRegex(agent_evals.EvalError, 'runner_source_unavailable'):
                agent_evals._runner_digest()

    def test_plan_ordinary_export_keeps_closed_namespace_and_precise_demand(self):
        tree = ast.parse((ROOT / '.getzilla/getzilla/verification_plan.py').read_bytes())
        self.assertTrue(namespace_is_closed(tree, allow_instrumentation=True,
                                           static_import_reads=True, forbidden_imports=_QUEUE_IMPORTS))
        projection = _queue_export_slice(tree, frozenset({'requested_profiles_from_report'}))
        self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(projection)))
        namespace = {}
        exec(compile(ast.fix_missing_locations(projection), '<selected-plan-export>', 'exec'), namespace)
        self.assertEqual(namespace['requested_profiles_from_report']({'requested_profiles': ['base']}), ['base'])

    def test_architecture_git_ranges_have_no_verifier_implementation_dependency(self):
        tree = ast.parse((ROOT / '.getzilla/getzilla/architecture_diff.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'verification'
                             for node in ast.walk(tree)))
        self.assertIsNotNone(importlib.util.find_spec('getzilla.git_ranges'))
        from getzilla import git_ranges, verification
        self.assertIs(verification.GitRangeBase, git_ranges.GitRangeBase)
        self.assertIs(verification.GitRangeSelection, git_ranges.GitRangeSelection)
        self.assertIs(verification._git_range_selection, git_ranges._git_range_selection)
        self.assertEqual(type(verification.GitRangeSelection()), git_ranges.GitRangeSelection)

    def test_range_qualification_does_not_reenter_the_receipt_facade(self):
        from getzilla import git_ranges, receipts
        self.assertIs(receipts._qualified_architecture_comparison, git_ranges._qualified_architecture_comparison
                      if hasattr(git_ranges, '_qualified_architecture_comparison') else None)
        tree = ast.parse((ROOT / '.getzilla/getzilla/git_ranges.py').read_bytes())
        projection = _queue_export_slice(tree, frozenset({'_git_range_selection'}))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'receipts' and
                             any(alias.name == '_qualified_architecture_comparison' for alias in node.names)
                             for node in ast.walk(projection)))

    def test_owned_process_projection_does_not_expand_history_storage(self):
        tree = ast.parse((ROOT / '.getzilla/getzilla/python_test_runner.py').read_bytes())
        projection = _queue_export_slice(tree, frozenset({'execute'}))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and
                             any(alias.name == 'verification_journal' for alias in node.names)
                             for node in ast.walk(projection)))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.level and node.module is None
                             for node in ast.walk(projection)))
        self.assertIsNotNone(importlib.util.find_spec('getzilla.verification_actions'))
        from getzilla import verification_actions, verification_journal
        self.assertIs(verification_journal.StopMetadata, verification_actions.StopMetadata)
        with verification_journal.activate(type('Run', (), {'writer': None})()) as run:
            self.assertIs(verification_actions.current(), run)
        value = type('Result', (), {'stop_metadata': verification_actions.child_stop(0)})()
        self.assertEqual(verification_journal.stop_details(value)['decision'], 'child_exit')

    def test_plan_scope_selection_has_no_executor_facade_dependency(self):
        tree = ast.parse((ROOT / '.getzilla/getzilla/verification_plan.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'verification'
                             for node in ast.walk(tree)))
        from getzilla import verification, verification_scope
        self.assertIs(verification._changed_file_inventory, verification_scope._changed_file_inventory)
        self.assertIs(verification.select_static_seo_landing_scope, verification_scope.select_static_seo_landing_scope)
        self.assertEqual(verification_scope.python_check_selection(ROOT / 'absent-owned-input'), (False, False))

    def test_source_context_does_not_import_the_security_command_facade(self):
        from getzilla import public_security_context as context, security_cli
        self.assertIs(security_cli.source_binding, getattr(context, 'source_binding', None))
        self.assertIs(security_cli.input_profile, getattr(context, 'input_profile', None))
        tree = ast.parse((ROOT / '.getzilla/getzilla/expanded_security.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'security_cli'
                             for node in ast.walk(tree)))

    def test_governance_summary_demand_excludes_unrelated_fitness_orchestration(self):
        tree = ast.parse((ROOT / '.getzilla/getzilla/governance.py').read_bytes())
        self.assertTrue(namespace_is_closed(tree, allow_instrumentation=True,
                                           static_import_reads=True, forbidden_imports=_QUEUE_IMPORTS))
        projection = _queue_export_slice(tree, frozenset({'governance_summary'}))
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'architecture_fitness'
                             for node in ast.walk(projection)))
        from getzilla import governance, governance_records
        self.assertIs(governance.RuleRecord, governance_records.RuleRecord)
        record = governance.RuleRecord.from_dict({'rule_id': 'owned'})
        document = record.to_dict()
        document['rule_id'] = 'changed'
        self.assertEqual(record.rule_id, 'owned')
        with self.assertRaises(AttributeError):
            record._canonical_document = b'{}'

    def test_process_capture_bound_shares_the_storage_independent_action_owner(self):
        from getzilla import verification_actions as actions, process_limits
        self.assertEqual(process_limits.OUTPUT_LIMIT, 2 * 1024 * 1024)
        self.assertEqual(getattr(actions, 'OUTPUT_LIMIT', None), process_limits.OUTPUT_LIMIT)
        tree = ast.parse((ROOT / '.getzilla/getzilla/python_test_runner.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'process_limits'
                             for node in ast.walk(tree)))

    def test_live_image_authority_has_one_exact_guard_and_seal_owner(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.security_image_authority'))
        from getzilla import security_image_authority as authority, security_image_producer as producer
        from getzilla import security_image_backend as backend, security_oci
        self.assertIs(backend.BackendUnavailable, authority.BackendUnavailable)
        self.assertIs(producer.require_builds, authority.require_builds)
        self.assertIs(producer._MEMBER_SEAL, authority._MEMBER_SEAL)
        self.assertIs(backend._ACTIVE, authority._ACTIVE)
        self.assertEqual((authority.CI_BYTES, authority.CI_MEMORY), (8 * 1024 ** 3, 12 * 1024 ** 3))
        guard = object()
        state = {'source': {'owned': True}, 'run': {'run_id': '1'}, 'native_guard': guard,
                 'ci_uses': {'consumers': []}, 'builds': {}}
        with mock.patch.object(authority, '_GUARD', guard), mock.patch.object(authority, '_LIVE', state):
            self.assertEqual(authority.validate_ci_uses(state['ci_uses'], state['source'], state['run']), state['ci_uses'])
            with mock.patch.object(authority, '_GUARD', object()), self.assertRaises(authority.BackendUnavailable):
                authority.validate_ci_uses(state['ci_uses'], state['source'], state['run'])
        self.assertEqual(security_oci.active_limits(), security_oci.LIMITS)
        tree = ast.parse((ROOT / '.getzilla/getzilla/security_oci.py').read_bytes())
        self.assertTrue(namespace_is_closed(tree, allow_instrumentation=True,
                                           static_import_reads=True, forbidden_imports=_QUEUE_IMPORTS))

    def test_verifier_release_contract_has_no_updater_orchestration_dependency(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.release_transport'))
        from getzilla import release_transport, updater
        self.assertIs(updater._release_fetch, release_transport._release_fetch)
        self.assertIs(updater.OPENGREP_ASSETS, release_transport.OPENGREP_ASSETS)
        self.assertEqual(updater.OPENGREP_VERSION, release_transport.OPENGREP_VERSION)
        with mock.patch.object(release_transport._RELEASE_OPENER, 'open') as opened:
            with self.assertRaises(ValueError):
                release_transport._release_fetch('https://foreign.invalid/asset')
        opened.assert_not_called()
        tree = ast.parse((ROOT / '.getzilla/getzilla/verification.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'updater'
                             for node in ast.walk(tree)))

    def test_factory_source_preparation_uses_the_sealed_context_owner(self):
        from getzilla import public_security_context as context, security_cli
        self.assertIs(security_cli._preparation_step, getattr(context, '_preparation_step', None))
        tree = ast.parse((ROOT / '.getzilla/getzilla/security_factory_inputs.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'security_cli'
                             for node in ast.walk(tree)))
        with self.assertRaises(ValueError) as caught:
            with context._preparation_step('factory-target'):
                raise ValueError('private payload')
        self.assertEqual(security_cli._preparation_fault(caught.exception)['stage'], 'factory-target')
        forged = ValueError('private payload')
        forged._getzilla_preparation = (object(), {'stage': 'factory-target'})
        self.assertEqual(security_cli._preparation_fault(forged), {})

    def test_receipt_metrics_use_the_existing_observation_owner(self):
        from getzilla import route_metrics, metrics_journal
        self.assertIs(route_metrics.record_receipt, getattr(metrics_journal, 'record_receipt', None))
        tree = ast.parse((ROOT / '.getzilla/getzilla/receipts.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'route_metrics'
                             for node in ast.walk(tree)))

    def test_security_stop_consumers_use_action_leaf_without_history_storage(self):
        for name in ('security_cli.py', 'security_tools.py'):
            with self.subTest(name=name):
                tree = ast.parse((ROOT / '.getzilla/getzilla' / name).read_bytes())
                self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module == 'verification_journal'
                                     and any(alias.name in {'retain_stop', 'stop_details', 'updated_stop'}
                                             for alias in node.names) for node in ast.walk(tree)))

    def test_action_observer_alias_shares_only_exact_source_peer_identity(self):
        from getzilla import verification_actions as actions
        path = ROOT / '.getzilla/getzilla/verification_actions.py'
        name = '_getzilla_observer_' + 'a' * 32 + '.verification_actions'

        def load():
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            with mock.patch.dict(sys.modules, {name: module}):
                spec.loader.exec_module(module)
            return module

        alias = load()
        self.assertIs(alias.StopMetadata, actions.StopMetadata)
        self.assertIs(alias._SINK, actions._SINK)
        self.assertIsNot(alias._CURRENT, actions._CURRENT)
        metadata = alias.child_stop(0)
        self.assertEqual(actions.stop_details(SimpleNamespace(stop_metadata=metadata))['decision'], 'child_exit')
        forged = ModuleType('getzilla.verification_actions')
        forged.__file__ = str(path)
        forged.__spec__ = SimpleNamespace(origin='different-source.py')
        forged.StopMetadata, forged._SINK = actions.StopMetadata, actions._SINK
        with mock.patch.dict(sys.modules, {'getzilla.verification_actions': forged}):
            refused = load()
        self.assertIsNot(refused.StopMetadata, actions.StopMetadata)
        self.assertIsNot(refused._SINK, actions._SINK)

    def test_policy_binding_hashes_new_loader_and_shared_range_source(self):
        from getzilla.verification_plan import policy_binding
        with tempfile.TemporaryDirectory() as directory:
            implementation = policy_binding(Path(directory))['implementation']
        for name in ('agent_eval_authoring.py', 'security_license_contracts.py', 'live_evidence.py', 'intake_authoring.py', 'workflow_cas.py', 'workflow_storage.py', 'workflow_inputs.py', 'verification_policy_source.py', 'git_ranges.py', 'verification_actions.py', 'governance_records.py', 'security_image_authority.py', 'release_transport.py'):
            with self.subTest(name=name):
                self.assertIn(name, implementation)
                self.assertEqual(implementation[name], hashlib.sha256(
                    (ROOT / '.getzilla/getzilla' / name).read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
