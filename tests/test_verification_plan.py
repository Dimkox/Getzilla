"""A selected test runner is not evidence for an omitted requirement test."""
from __future__ import annotations

import copy
import importlib
import os
import sys
import unittest
from datetime import datetime, timezone

from tests._support import PROJECT, project_copy

sys.path.insert(0, str(PROJECT / '.getzilla'))


class VerificationPlanTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('getzilla.verification_plan')
        except ModuleNotFoundError:
            self.fail('No required verification plan binds dispatch, actual execution and final acceptance.')

    def inputs(self):
        return {
            'mode': 'fast',
            'context': {'version': 1, 'route_id': 'route-fixture', 'logical_task_id': 'task-fixture',
                        'authority_epoch': 0, 'context_revision': 0, 'digest': '1' * 64},
            'source': {'head': 'a' * 40, 'tree': 'b' * 40, 'base': ['c' * 40], 'fingerprint': '2' * 64},
            'inventory': {'complete': True, 'digest': '3' * 64, 'paths': ['src/a.py']},
            'risk': {'risk': 'low', 'rules_digest': '4' * 64},
            'selection': {'delivery_lane': 'light', 'profile': 'full', 'mode': 'fast'},
            'extra_obligations': [{'id': 'AC-001:test-a', 'check_id': 'python-unittest',
                'requirement_ids': ['AC-001'], 'applicability': 'required',
                'reason': 'criterion test', 'evidence': {}, 'expected_tests': ['tests.test_a.Case.test_a'],
                'data_sources': []}],
        }

    def plan(self, root):
        return self.module().build_required_plan(root, **self.inputs())

    def results(self, plan):
        return [{'name': item['check_id'], 'status': 'pass', 'summary': 'executed', 'details': [
            {'schema_version': 1, 'kind': 'required-plan-result', 'plan_digest': plan['digest'],
             'check_id': item['check_id'], 'executed_tests': list(item['expected_tests'])}]}
            for item in plan['obligations']]

    def gaps(self, plan, results, **kwargs):
        return self.module().plan_gaps(plan, results, current_binding=plan['binding'],
            now_utc=datetime(2026, 11, 3, tzinfo=timezone.utc), **kwargs)

    def test_required_check_omission_is_not_covered_by_other_passes(self):
        with project_copy(git=True) as root:
            plan = self.plan(root)
            results = self.results(plan)
            self.assertEqual(self.gaps(plan, results), [])
            self.assertTrue(self.gaps(plan, [item for item in results if item['name'] != 'python-unittest']))

    def test_existing_test_file_or_count_does_not_prove_individual_execution(self):
        with project_copy(git=True) as root:
            plan = self.plan(root)
            results = self.results(plan)
            for item in results:
                if item['name'] == 'python-unittest':
                    item['details'][0]['executed_tests'] = []
                    item['summary'] = '3000 tests passed'
            gaps = self.gaps(plan, results)
            self.assertTrue(any('test' in item['code'] for item in gaps), gaps)

    def test_duplicate_and_wrong_plan_results_do_not_gain_acceptance(self):
        with project_copy(git=True) as root:
            plan = self.plan(root)
            results = self.results(plan)
            self.assertTrue(self.gaps(plan, [*results, copy.deepcopy(results[0])]))
            results[0]['details'][0]['plan_digest'] = 'f' * 64
            self.assertTrue(self.gaps(plan, results))

    def test_current_source_and_policy_binding_are_rechecked(self):
        with project_copy(git=True) as root:
            plan = self.plan(root)
            binding = copy.deepcopy(plan['binding'])
            binding['source']['head'] = 'd' * 40
            self.assertTrue(self.module().plan_gaps(plan, self.results(plan), current_binding=binding,
                now_utc=datetime(2026, 11, 3, tzinfo=timezone.utc)))

    def test_unsubstantiated_not_applicable_is_rejected(self):
        with project_copy(git=True) as root:
            inputs = self.inputs()
            inputs['extra_obligations'][0]['applicability'] = 'not_applicable'
            with self.assertRaises(ValueError):
                self.module().build_required_plan(root, **inputs)

    def test_plan_mutation_and_unknown_or_skipped_status_fail_closed(self):
        with project_copy(git=True) as root:
            plan = self.plan(root)
            changed = copy.deepcopy(plan)
            changed['obligations'][0]['expected_tests'] = []
            self.assertTrue(self.gaps(changed, self.results(plan)))
            for status in ('skip', 'unknown', 'cancelled', 'fail'):
                results = self.results(plan)
                results[0]['status'] = status
                self.assertTrue(self.gaps(plan, results), status)

    def test_data_sources_require_current_real_validator(self):
        with project_copy(git=True) as root:
            inputs = self.inputs()
            inputs['extra_obligations'][0]['data_sources'] = [{'source_id': 'kev', 'content_sha256': 'a' * 64}]
            plan = self.module().build_required_plan(root, **inputs)
            gaps = self.gaps(plan, self.results(plan))
            self.assertTrue(any(item['code'] == 'required-data-source-stale' for item in gaps), gaps)

    def test_security_result_from_a_different_family_cannot_fill_a_required_check(self):
        with project_copy(git=True) as root:
            inputs = self.inputs()
            inputs['extra_obligations'] = [self.module().obligation('security-kev')]
            plan = self.module().build_required_plan(root, **inputs)
            results = self.results(plan)
            detail = {'schema_version': 1, 'kind': 'security-result', 'family': 'known-exploitation',
                      'outcome': 'pass', 'data_sources': []}
            results[0]['details'].append(detail)
            self.assertEqual(self.gaps(plan, results), [])
            detail['family'] = 'licenses'
            self.assertTrue(any(item['code'] == 'required-security-family' for item in self.gaps(plan, results)))

    def test_missing_validator_return_cannot_satisfy_current_source_validation(self):
        with project_copy(git=True) as root:
            inputs = self.inputs()
            source = {'source_id': 'kev', 'content_sha256': 'a' * 64}
            inputs['extra_obligations'] = [{**self.module().obligation('security-kev'), 'data_sources': [source]}]
            plan = self.module().build_required_plan(root, **inputs)
            results = self.results(plan)
            results[0]['details'].append({'schema_version': 1, 'kind': 'security-result', 'family': 'known-exploitation',
                                         'outcome': 'pass', 'data_sources': [source]})
            gaps = self.gaps(plan, results, data_source_validator=lambda _source, **_kwargs: None)
            self.assertTrue(any(item['code'] == 'required-data-source-stale' for item in gaps), gaps)

    def test_quality_gate_consumes_plan_even_in_fast_mode(self):
        from getzilla.quality_gates import evaluate_quality_gate
        with project_copy(git=True) as root:
            plan = self.plan(root)
            try:
                decision = evaluate_quality_gate(mode='fast', checks=[], required_plan=plan,
                    current_binding=plan['binding'], now_utc=datetime(2026, 11, 3, tzinfo=timezone.utc))
            except TypeError:
                self.fail('The fast quality gate does not consume the required verification plan.')
            self.assertEqual(decision.status, 'fail')

    def test_receipt_consumer_refuses_verification_without_plan(self):
        module = self.module()
        with project_copy(git=True) as root:
            self.assertTrue(module.report_gaps(root, {'mode': 'fast', 'status': 'pass', 'checks': []}))

    def test_existing_receipt_admission_rejects_legacy_pass_without_required_plan(self):
        from getzilla import receipts, state
        from tests._support import activate_owned_route
        with project_copy(git=True) as root:
            route = {'route_id': 'fixture-required-plan', 'risk': 'low', 'complexity': 'micro',
                     'required_evidence': ['verification'], 'delivery_expected': True}
            activate_owned_route(root, route)
            receipts.write_receipt(root, 'verification', 'pass', details={'mode': 'fast', 'status': 'pass', 'checks': []})
            gaps = receipts.validate_evidence(root, state.get_active_route(root))
            self.assertTrue(any('required' in gap and 'plan' in gap for gap in gaps), gaps)

    def test_verifier_cannot_ignore_plan_derivation_failure(self):
        from unittest.mock import patch
        from getzilla.verification import verify
        with project_copy(git=True, minimal_runtime=True) as root:
            with patch('getzilla.verification_plan.current_required_plan', side_effect=ValueError('required policy unavailable')):
                report = verify(root, mode='fast', record=False)
            named = {item['name']: item for item in report['checks']}
            self.assertIn('required-plan', named)
            self.assertEqual(named['required-plan']['status'], 'fail')
            self.assertEqual(report['status'], 'fail')

    def test_full_fast_report_is_not_completion_evidence(self):
        from unittest.mock import patch
        with project_copy(git=True) as root:
            inputs = self.inputs()
            inputs['selection'].update(delivery_lane='full', delivery_expected=True)
            plan = self.module().build_required_plan(root, **inputs)
            report = {'mode': 'fast', 'required_plan': plan, 'checks': self.results(plan)}
            with patch('getzilla.verification_plan.current_required_plan', return_value=plan):
                gaps = self.module().report_gaps(root, report)
            self.assertTrue(any(item['code'] == 'required-qualifying-mode' for item in gaps), gaps)


class CriterionExecutionTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('getzilla.criterion_tests')
        except ModuleNotFoundError:
            self.fail('No invocation-owned per-test execution evidence is produced for typed criteria.')

    def fixture(self, root, body):
        directory = root / 'tests'
        directory.mkdir(exist_ok=True)
        (directory / '__init__.py').write_text('')
        (directory / 'test_count.py').write_text(body)

    def test_exact_method_executes_and_deduplicates_overlapping_references(self):
        with project_copy(git=True) as root:
            self.fixture(root, 'import unittest\nclass Count(unittest.TestCase):\n def test_one(self): self.assertEqual(1, 1)\n')
            refs = ['tests/test_count.py', 'tests/test_count.py::Count::test_one']
            result = self.module().run_required_tests(root, refs)
            self.assertEqual(result['status'], 'pass', result)
            detail = result['details'][0]
            self.assertEqual(set(detail['verified_references']), set(refs))
            self.assertEqual(detail['tests'], [{'id': 'tests.test_count.Count.test_one', 'status': 'pass'}])

    def test_empty_file_or_skipped_method_never_proves_criterion(self):
        bodies = [
            'import unittest\n',
            'import unittest\nclass Count(unittest.TestCase):\n @unittest.skip("missing capability")\n def test_one(self): pass\n',
        ]
        for body in bodies:
            with self.subTest(body=body), project_copy(git=True) as root:
                self.fixture(root, body)
                result = self.module().run_required_tests(root, ['tests/test_count.py'])
                self.assertEqual(result['status'], 'fail', result)
                self.assertEqual(result['details'][0].get('verified_references', []), [])

    def test_unrelated_passing_method_does_not_cover_nonexistent_method(self):
        with project_copy(git=True) as root:
            self.fixture(root, 'import unittest\nclass Count(unittest.TestCase):\n def test_other(self): pass\n')
            result = self.module().run_required_tests(root, ['tests/test_count.py::Count::test_missing'])
            self.assertEqual(result['status'], 'fail', result)
            self.assertEqual(result['details'][0].get('verified_references', []), [])

    def test_discoverable_test_file_without_package_initializer_is_supported(self):
        with project_copy(git=True) as root:
            self.fixture(root, 'import unittest\nclass Count(unittest.TestCase):\n def test_one(self): self.assertEqual(2, 2)\n')
            (root / 'tests/__init__.py').unlink()
            result = self.module().run_required_tests(root, ['tests/test_count.py::Count::test_one'])
            self.assertEqual(result['status'], 'pass', result)

    def test_foreign_package_with_same_module_name_cannot_cover_candidate_test(self):
        from unittest.mock import patch
        with project_copy(git=True) as root:
            self.fixture(root, 'import unittest\nclass Count(unittest.TestCase):\n def test_one(self): self.assertEqual(1, 2)\n')
            (root / 'tests/__init__.py').unlink()
            foreign = root / '.getzilla/runtime/scratch/foreign-tests'
            (foreign / 'tests').mkdir(parents=True)
            (foreign / 'tests/__init__.py').write_text('')
            (foreign / 'tests/test_count.py').write_text('import unittest\nclass Count(unittest.TestCase):\n def test_one(self): pass\n')
            with patch.dict(os.environ, {'PYTHONPATH': str(foreign)}):
                result = self.module().run_required_tests(root, ['tests/test_count.py::Count::test_one'])
            self.assertEqual(result['status'], 'fail', result)

    def test_focused_landing_contract_cannot_pass_when_its_only_test_skips(self):
        from getzilla.verification import _focused_landing_contract
        with project_copy(git=True) as root:
            self.fixture(root, 'import unittest\nclass Count(unittest.TestCase):\n @unittest.skip("not available")\n def test_one(self): pass\n')
            result = _focused_landing_contract(root, {'focused_tests': ['tests/test_count.py']})
            self.assertEqual(result.status, 'fail', result)

    def test_expected_failure_cannot_prove_required_behavior(self):
        with project_copy(git=True) as root:
            self.fixture(root, 'import unittest\nclass Count(unittest.TestCase):\n @unittest.expectedFailure\n def test_one(self): self.assertEqual(1, 2)\n')
            result = self.module().run_required_tests(root, ['tests/test_count.py::Count::test_one'])
            self.assertEqual(result['status'], 'fail', result)


if __name__ == '__main__':
    unittest.main()
