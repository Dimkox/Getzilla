"""NEW pure obligation/source controls; no project workload or security inventory runs."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import importlib
import importlib.util
import contextlib
import io
from pathlib import Path
import tempfile
import sys
from types import ModuleType
import unittest
from unittest import mock
import zipfile
import zipimport

from getzilla import quality_gates

NOW = datetime(2026, 11, 9, tzinfo=timezone.utc)


class RequiredPlanTests(unittest.TestCase):
    def test_explicit_unconfigured_scenario_cannot_vanish_from_requirement_plan(self):
        api = self.api()
        self.assertTrue(callable(getattr(api, 'declared_check_obligations', None)))
        document = {'acceptance_criteria': [{'id': 'AC-001', 'statement': 'approved public API outcome',
                    'evidence': [{'attestation': 'check:tool:public-api'}]}]}
        rows = api.declared_check_obligations(document)
        self.assertEqual([(row['check_id'], row['requirement_ids'], row['applicability']) for row in rows],
                         [('tool:public-api', ['AC-001'], 'required')])
        with mock.patch.object(api, 'policy_binding', return_value={'digest': 'a' * 64}):
            plan = api.build_required_plan(Path('.'), mode='fast', context={}, source={}, inventory={},
                                          risk={}, selection={}, extra_obligations=rows)
        self.assertTrue(self.gaps(plan, []))
        result = {'name': 'tool:public-api', 'status': 'pass', 'details': []}
        api.bind_result(plan, result)
        self.assertTrue(self.gaps(plan, [result]))
        rows = api.declared_check_obligations(document, available={'tool:public-api'})
        with mock.patch.object(api, 'policy_binding', return_value={'digest': 'a' * 64}):
            plan = api.build_required_plan(Path('.'), mode='fast', context={}, source={}, inventory={},
                                          risk={}, selection={}, extra_obligations=rows)
        result = {'name': 'tool:public-api', 'status': 'pass', 'details': []}
        api.bind_result(plan, result)
        self.assertEqual(self.gaps(plan, [result]), [])
        self.assertEqual(api.declared_check_obligations({'acceptance_criteria': []}), [])

    def test_malformed_and_duplicate_check_declarations_refuse_without_callbacks(self):
        api = self.api()
        for values in (['check:'], ['check:tool:owned', 'check:tool:owned'], ['check:invalid name']):
            spec = {'acceptance_criteria': [{'id': 'AC-001', 'evidence': [{'attestation': value} for value in values]}]}
            with self.subTest(values=values), self.assertRaises(ValueError):
                api.declared_check_obligations(spec)

    def test_claimed_criterion_reference_requires_exact_planned_source_observations(self):
        api = self.api()
        reference = 'tests/test_owned.py::Owned::test_required'
        owned = {'tests/test_owned.py': {'sha256': 'a' * 64, 'module': 'tests.test_owned',
                                       'classes': {'Owned': ['test_required']}, 'functions': []}}
        item = api.obligation('criterion-tests', expected_tests=[reference], evidence={'test_sources': owned})
        with mock.patch.object(api, 'policy_binding', return_value={'digest': 'a' * 64}):
            plan = api.build_required_plan(Path('.'), mode='fast', context={}, source={}, inventory={},
                                          risk={}, selection={}, extra_obligations=[item])
        report = {'schema_version': 1, 'kind': 'criterion-test-execution', 'source': owned,
                  'references': {reference: ['tests.test_owned.Owned.test_required']},
                  'tests': [{'id': 'tests.test_owned.Owned.test_required', 'status': 'pass'}],
                  'verified_references': [reference]}
        result = {'name': 'criterion-tests', 'status': 'pass', 'details': [copy.deepcopy(report)]}
        api.bind_result(plan, result)
        self.assertEqual(self.gaps(plan, [result]), [])
        result['details'][0]['source']['tests/test_owned.py']['sha256'] = 'b' * 64
        self.assertTrue(self.gaps(plan, [result]))

    def test_hydrated_historical_report_is_readable_but_cannot_qualify_without_plan(self):
        from getzilla import receipts
        receipt = {'schema_version': 1, 'route_id': 'owned', 'kind': 'verification', 'status': 'pass',
                   'created_at': NOW.isoformat(), 'tree_fingerprint': 'a' * 64, 'report': None,
                   'details': {'status': 'pass', 'mode': 'fast', 'checks': []}, 'criterion_ids': [],
                   'spec_digest': None, 'spec_fingerprint': None}
        route = {'route_id': 'owned', 'required_evidence': ['verification']}
        with contextlib.ExitStack() as patches:
            patches.enter_context(mock.patch('getzilla.continuity.scope_gaps', return_value=[]))
            patches.enter_context(mock.patch('getzilla.continuity.receipt_context_current', return_value=True))
            for name, value in (('get_receipt', receipt), ('_escalated_evidence', []), ('_waived_evidence', []),
                                ('_active_spec_binding', None), ('active_architecture_binding', None),
                                ('active_governance_binding', None)):
                patches.enter_context(mock.patch.object(receipts, name, return_value=value))
            gaps = receipts.validate_evidence(Path('.'), route, current_fingerprint='a' * 64)
        self.assertTrue(any('required plan' in gap for gap in gaps), gaps)
        self.assertEqual(receipt['details'], {'status': 'pass', 'mode': 'fast', 'checks': []})

    def api(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.verification_plan'),
                             'required plan source contract is absent')
        return importlib.import_module('getzilla.verification_plan')

    def plan(self, *, source=None, required=True, refs=()):
        api = self.api()
        obligation = api.obligation('public-check', required=required,
                                    evidence={} if required else {'kind': 'source-proof', 'empty': True},
                                    expected_tests=list(refs))
        obligation['data_sources'] = [] if source is None else [source]
        with mock.patch.object(api, 'policy_binding', return_value={
                'schema_version': 1, 'digest': '1' * 64, 'inputs': {},
                'implementation': {'owned-policy.py': '2' * 64}}):
            return api.build_required_plan(Path('.'), mode='fast', context={'version': 1, 'variant': 'owned'},
                source={'head': 'a' * 40, 'tree': 'b' * 40, 'fingerprint': 'c' * 64, 'base': ['d' * 40]},
                inventory={'complete': True, 'paths': [], 'digest': 'e' * 64},
                risk={'status': 'complete', 'risk': 'medium'}, selection={'mode': 'fast'},
                extra_obligations=[obligation])

    def result(self, plan, status='pass'):
        result = {'name': 'public-check', 'status': status, 'details': []}
        self.api().bind_result(plan, result)
        return result

    def gaps(self, plan, results, **kwargs):
        return self.api().plan_gaps(plan, results, current_binding=kwargs.pop('binding', plan['binding']),
                                   now_utc=kwargs.pop('now', NOW),
                                   data_source_validator=kwargs.pop('validator', lambda source, **options: True),
                                   **kwargs)

    def test_legacy_quality_gate_defaults_cannot_qualify_new_results(self):
        gate = quality_gates.evaluate_quality_gate(mode='fast', checks=[{'name': 'public-check', 'status': 'pass'}])
        self.assertEqual(gate.status, 'fail')

    def test_duplicate_result_cannot_overwrite_an_earlier_refusal(self):
        gate = quality_gates.evaluate_quality_gate(mode='fast', checks=[
            {'name': 'public-check', 'status': 'fail'}, {'name': 'public-check', 'status': 'pass'}])
        self.assertEqual(gate.status, 'fail')

    def test_plan_result_matrix_refuses_missing_duplicate_skip_unknown_and_stale(self):
        plan = self.plan()
        result = self.result(plan)
        self.assertEqual(self.gaps(plan, [result]), [])
        for results in ([], [result, result], [self.result(plan, 'skip')], [self.result(plan, 'unknown')]):
            with self.subTest():
                self.assertTrue(self.gaps(plan, results))
        current = copy.deepcopy(plan['binding'])
        current['source']['head'] = 'f' * 40
        self.assertTrue(self.gaps(plan, [result], binding=current))

    def test_current_clock_and_trusted_validator_are_mandatory_even_without_feeds(self):
        plan = self.plan()
        self.assertTrue(self.gaps(plan, [self.result(plan)], validator=None))
        self.assertTrue(self.gaps(plan, [self.result(plan)], now=NOW.replace(tzinfo=None)))

    def test_source_proven_not_applicable_is_exact_not_a_generic_skip(self):
        plan = self.plan(required=False)
        result = self.result(plan, 'skip')
        self.assertEqual(self.gaps(plan, [result]), [])
        result['details'][0]['applicability'] = {'kind': 'different-source'}
        self.assertTrue(self.gaps(plan, [result]))

    def test_unknown_required_binding_and_empty_plan_refuse(self):
        api = self.api()
        with self.assertRaises(ValueError):
            api.build_required_plan(Path('.'), mode='fast', context=None, source={}, inventory={},
                                    risk={}, selection={}, extra_obligations=[])

    def test_report_creation_cannot_refresh_source_age(self):
        for age, expected in ((259200, False), (259201, True), (-1, True)):
            source = {'source_id': 'osv:PyPI', 'acquisition': {
                'last_verified_sync_utc': (NOW - timedelta(seconds=age)).isoformat(),
                'retrieval_kind': 'download'}}
            plan = self.plan(source=source)
            result = self.result(plan)
            result['details'].append({'kind': 'security-result', 'family': 'public', 'outcome': 'pass',
                                      'data_sources': [source]})
            with self.subTest(age=age):
                self.assertEqual(bool(self.gaps(plan, [result])), expected)

    def test_trusted_source_refusal_does_not_export_arbitrary_exception_text(self):
        source = {'source_id': 'owned', 'acquisition': {'last_verified_sync_utc': NOW.isoformat()}}
        plan, canary = self.plan(source=source), 'PRIVATE-VALIDATOR-CANARY'
        result = self.result(plan)
        result['details'].append({'kind': 'security-result', 'family': 'public', 'outcome': 'pass', 'data_sources': [source]})
        def refused(*args, **kwargs):
            raise ValueError(canary)
        gaps = self.gaps(plan, [result], validator=refused)
        self.assertTrue(gaps)
        self.assertNotIn(canary, str(gaps))

    def test_missing_or_duplicate_individual_case_cannot_borrow_aggregate_pass(self):
        reference = 'tests/test_owned.py::Owned::test_required'
        plan = self.plan(refs=[reference])
        self.assertTrue(self.gaps(plan, [self.result(plan)]))
        result = {'name': 'public-check', 'status': 'pass', 'details': [{
            'kind': 'criterion-test-execution', 'references': {reference: ['owned.Owned.test_required']},
            'tests': [{'id': 'owned.Owned.test_required', 'status': 'pass'}],
            'verified_references': [reference]}]}
        self.api().bind_result(plan, result)
        self.assertTrue(self.gaps(plan, [result]))
        result['details'][0]['tests'].append(result['details'][0]['tests'][0])
        self.assertTrue(self.gaps(plan, [result]))

    def test_known_archive_loader_hashes_corresponding_source_without_execution(self):
        api = self.api()
        with tempfile.TemporaryDirectory(prefix='plan-loader-') as directory:
            path = Path(directory) / 'policy.zip'
            content = b'PUBLIC_POLICY = 1\n'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('owned_policy.py', content)
            module = ModuleType('owned_policy')
            module.__loader__ = zipimport.zipimporter(str(path))
            module.__file__ = str(path) + '/owned_policy.py'
            self.assertEqual(api._module_source(module), content)
            module.__loader__ = object()
            with self.assertRaises(ValueError):
                api._module_source(module)

    def test_actual_known_engine_source_closure_has_no_missing_or_null_owner(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as directory:
            try:
                binding = api.policy_binding(Path(directory))
            except (ImportError, OSError, ValueError) as error:
                self.fail('actual declared policy source owner is unavailable: ' + type(error).__name__)
        implementation = binding['implementation']
        self.assertIn('stack_toolchains.py', implementation)
        self.assertIn('factory_tests.py', implementation)
        self.assertIn('python_test_runner.py', implementation)
        self.assertTrue(all(isinstance(value, str) and len(value) == 64 for value in implementation.values()))


class CriterionOwnershipTests(unittest.TestCase):
    def api(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.criterion_tests'),
                             'source-owned criterion evidence contract is absent')
        return importlib.import_module('getzilla.criterion_tests')

    def test_unique_owned_case_report_rejects_ghost_duplicate_skip_and_expected_failure(self):
        api = self.api()
        reference = 'tests/test_owned.py::Owned::test_one'
        ownership = {'tests/test_owned.py': {'sha256': 'a' * 64, 'module': 'tests.test_owned',
                                            'classes': {'Owned': ['test_one']}, 'functions': []}}
        report = {'schema_version': 1, 'kind': 'criterion-test-execution',
                  'source': ownership, 'references': {reference: ['tests.test_owned.Owned.test_one']},
                  'tests': [{'id': 'tests.test_owned.Owned.test_one', 'status': 'pass'}]}
        self.assertEqual(api._verified_references(report, [reference], ownership), [reference])
        for field, value in (('tests', report['tests'] * 2),
                             ('tests', [{'id': 'tests.test_owned.Owned.test_one', 'status': 'skip'}]),
                             ('tests', [{'id': 'tests.test_owned.Owned.test_one', 'status': 'expected_failure'}]),
                             ('references', {reference: ['foreign.Owned.test_one']}),
                             ('references', {reference: []})):
            changed = copy.deepcopy(report)
            changed[field] = value
            with self.subTest(field=field):
                self.assertEqual(api._verified_references(changed, [reference], ownership), [])

    def test_actual_new_owned_case_binds_source_and_discards_private_output(self):
        api = self.api()
        with tempfile.TemporaryDirectory(prefix='owned-case-source-') as directory:
            root = Path(directory)
            path = root / 'test_owned_criterion_pure.py'
            path.write_text('import unittest\nclass Owned(unittest.TestCase):\n'
                            '    def test_ok(self):\n        print("PRIVATE-CANARY")\n'
                            '        self.assertTrue(True)\n')
            self.addCleanup(sys.modules.pop, 'test_owned_criterion_pure', None)
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                report = api._execute_references(root, ['test_owned_criterion_pure.py::Owned::test_ok'])
            self.assertIn('source', report)
            self.assertEqual(report['verified_references'], ['test_owned_criterion_pure.py::Owned::test_ok'])
            self.assertNotIn('PRIVATE-CANARY', captured.getvalue())
            self.assertNotIn('PRIVATE-CANARY', str(report))

    def test_imported_foreign_class_cannot_qualify_selected_source(self):
        api = self.api()
        with tempfile.TemporaryDirectory(prefix='owned-case-import-') as directory:
            root = Path(directory)
            (root / 'foreign_criterion_pure.py').write_text('import unittest\nclass Owned(unittest.TestCase):\n'
                                                          '    def test_ok(self): self.assertTrue(True)\n')
            (root / 'test_imported_criterion_pure.py').write_text('from foreign_criterion_pure import Owned\n')
            for name in ('foreign_criterion_pure', 'test_imported_criterion_pure'):
                self.addCleanup(sys.modules.pop, name, None)
            with self.assertRaises(ValueError):
                api._execute_references(root, ['test_imported_criterion_pure.py::Owned::test_ok'])

    def test_archive_safe_driver_command_is_isolated_and_source_bound(self):
        api = self.api()
        self.assertTrue(callable(getattr(api, '_driver_command', None)))
        command = api._driver_command(Path('/owned/result.json'), ['test_owned.py::Owned::test_one'])
        self.assertEqual(command[0], sys.executable)
        self.assertIn('-I', command)
        self.assertIn('-B', command)
        self.assertIn('--driver-sha256', command)
        self.assertNotEqual(command[1], str(Path(api.__file__).resolve()))

    def test_rebound_same_file_method_cannot_borrow_declared_case_identity(self):
        api = self.api()
        with tempfile.TemporaryDirectory(prefix='owned-case-rebound-') as directory:
            root = Path(directory)
            (root / 'test_rebound_criterion_pure.py').write_text(
                'import unittest\nclass Owned(unittest.TestCase):\n'
                '    def test_ok(self): self.fail("original assertion")\n'
                'def replacement(self): self.assertTrue(True)\n'
                'Owned.test_ok = replacement\n')
            self.addCleanup(sys.modules.pop, 'test_rebound_criterion_pure', None)
            with self.assertRaises(ValueError):
                api._execute_references(root, ['test_rebound_criterion_pure.py::Owned::test_ok'])


class CollectedLifecycleRepairTests(unittest.TestCase):
    def test_plain_declared_method_executes_once_for_overlapping_references(self):
        from getzilla import criterion_tests as api
        name = 'test_collected_plain_method'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / (name + '.py')).write_text('import unittest\nCALLS=0\nclass Owned(unittest.TestCase):\n'
                ' def test_required(self):\n  global CALLS\n  CALLS+=1\n  self.assertEqual(CALLS,1)\n')
            self.addCleanup(sys.modules.pop, name, None)
            refs = [name + '.py::Owned', name + '.py::Owned::test_required']
            report = api._execute_references(root, refs)
            self.assertEqual(report['status'], 'pass')
            self.assertEqual(report['verified_references'], sorted(refs))
            self.assertEqual(len(report['tests']), 1)
            self.assertEqual(sys.modules[name].CALLS, 1)

    def test_run_override_cannot_credit_a_body_that_never_executed(self):
        from getzilla import criterion_tests as api
        name = 'test_collected_fake_lifecycle'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / (name + '.py')).write_text('import unittest\nBODY_CALLED=False\nclass Owned(unittest.TestCase):\n'
                ' def test_required(self):\n  global BODY_CALLED\n  BODY_CALLED=True\n  self.fail("owned failing body")\n'
                ' def run(self,result=None):\n  result.startTest(self)\n  result.addSuccess(self)\n  result.stopTest(self)\n  return result\n')
            self.addCleanup(sys.modules.pop, name, None)
            try:
                report = api._execute_references(root, [name + '.py::Owned::test_required'])
            except ValueError:
                self.assertFalse(sys.modules[name].BODY_CALLED)
            else:
                self.assertNotEqual(report['status'], 'pass')
                self.assertEqual(report['verified_references'], [])

    def test_skip_expected_failure_and_missing_method_remain_unverified(self):
        from getzilla import criterion_tests as api
        for case, decorator, body in (('skip', '@unittest.skip("owned")\n ', 'self.assertTrue(True)'),
                                      ('expected', '@unittest.expectedFailure\n ', 'self.fail("owned")'),
                                      ('missing', '', 'self.assertTrue(True)')):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                name = 'test_collected_unverified_' + case
                (root / (name + '.py')).write_text('import unittest\nclass Owned(unittest.TestCase):\n '+decorator+
                    'def test_required(self):\n  '+body+'\n')
                self.addCleanup(sys.modules.pop, name, None)
                method = 'test_absent' if case == 'missing' else 'test_required'
                report = api._execute_references(root, [name + '.py::Owned::' + method])
                self.assertEqual(report['status'], 'fail')
                self.assertEqual(report['verified_references'], [])
