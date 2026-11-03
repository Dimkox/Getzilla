"""Exercise the real plan compiler and verifier across native package generations."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from tests._support import PROJECT, prepare_review_source, project_copy, write_current_verification

sys.path.insert(0, str(PROJECT / '.getzilla'))

from getzilla import state, verification_plan  # noqa: E402
from getzilla.spec import canonical_spec_digest  # noqa: E402
from getzilla.util import git_head  # noqa: E402


class NativePlanIntegrationTests(unittest.TestCase):
    def legacy_project(self, root):
        from tests.test_verification_scope import VerifyDocsStateScopeEndToEndTests
        git, base = VerifyDocsStateScopeEndToEndTests()._repo(root)
        package = root / state.get_active_change(root)['path']
        spec_path = package / 'change-spec.yaml'
        spec = json.loads(spec_path.read_text())
        test = root / 'tests/test_required_case.py'
        test.write_text('import unittest\n\n\nclass Required(unittest.TestCase):\n    def test_actual(self):\n        self.assertEqual(2 + 2, 4)\n')
        spec['acceptance_criteria'][0]['evidence'] = [{'test': 'tests/test_required_case.py::Required::test_actual'}]
        spec_path.write_text(json.dumps(spec))
        git('add', '.')
        git('commit', '-qm', 'typed legacy criterion')
        return git, base, spec_path

    def test_real_compiler_retains_legacy_selected_criteria_and_document_binding(self):
        with tempfile.TemporaryDirectory(prefix='plan-legacy-') as directory:
            root = Path(directory)
            _, _, spec_path = self.legacy_project(root)
            plan = verification_plan.current_required_plan(root, mode='pr')
            criterion = next(item for item in plan['obligations'] if item['id'] == 'AC-001:tests')
            self.assertEqual(criterion['expected_tests'], ['tests/test_required_case.py::Required::test_actual'])
            self.assertEqual(criterion['requirement_ids'], ['AC-001'])
            self.assertEqual(plan['binding']['context']['package']['spec_digest'],
                             canonical_spec_digest(json.loads(spec_path.read_text())))
            self.assertEqual(plan['binding']['source']['head'], git_head(root))
            spec = json.loads(spec_path.read_text())
            spec['acceptance_criteria'][0]['statement'] = 'A revised requirement must invalidate prior proof.'
            spec_path.write_text(json.dumps(spec))
            later = verification_plan.current_required_plan(root, mode='pr')
            self.assertNotEqual(plan['binding']['context'], later['binding']['context'])

    def test_legacy_native_verify_executes_exact_criterion_and_rejects_stale_proof(self):
        from getzilla.verification import verify
        with tempfile.TemporaryDirectory(prefix='verify-legacy-') as directory:
            root = Path(directory)
            _, _, spec_path = self.legacy_project(root)
            report = verify(root, mode='pr', record=False)
            self.assertEqual(report['status'], 'pass', report.get('required_plan_error') or
                             [item for item in report['checks'] if item['status'] == 'fail'])
            self.assertEqual(verification_plan.report_gaps(root, report), [])
            criterion = next(item for item in report['checks'] if item['name'] == 'criterion-tests')
            detail = next(item for item in criterion['details'] if item.get('kind') == 'criterion-test-execution')
            self.assertIn('tests/test_required_case.py::Required::test_actual', detail['verified_references'])
            spec = json.loads(spec_path.read_text())
            spec['acceptance_criteria'][0]['statement'] = 'The criterion changed after execution.'
            spec_path.write_text(json.dumps(spec))
            self.assertTrue(verification_plan.report_gaps(root, report))

    def test_modern_attachment_cannot_use_the_legacy_adapter(self):
        from tests.test_task_intent import TaskIntentTests
        with project_copy(git=True) as root:
            route = TaskIntentTests().task(root)
            orphan = {key: value for key, value in route.items() if key != 'change_id'}
            with self.assertRaisesRegex(ValueError, 'not attached'):
                verification_plan._native_obligations(root, 'pr', orphan, {})

    def test_legacy_adapter_rejects_mismatched_identity_and_unsafe_optional_inputs(self):
        with tempfile.TemporaryDirectory(prefix='plan-legacy-fences-') as directory:
            root = Path(directory)
            _, _, spec_path = self.legacy_project(root)
            route = state.get_active_route(root)
            with self.assertRaisesRegex(ValueError, 'does not match'):
                verification_plan._plan_documents(root, {**route, 'change_id': '20261004-different-change'})
            spec = json.loads(spec_path.read_text())
            spec['change_id'] = '20261004-different-change'
            spec_path.write_text(json.dumps(spec))
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                verification_plan._plan_documents(root, route)
            spec['change_id'] = '20261004-scope-fixture'
            spec_path.write_text(json.dumps(spec))
            for name in ('state.json', 'requirements.md'):
                path = spec_path.parent / name
                with self.subTest(name=name):
                    try:
                        path.symlink_to(root / 'absent-input')
                    except (OSError, NotImplementedError) as exc:
                        self.skipTest('symlink creation is unavailable: ' + str(exc))
                    try:
                        with self.assertRaises((OSError, ValueError)):
                            verification_plan._plan_documents(root, route)
                    finally:
                        path.unlink()

    def test_pending_human_intent_invalidates_real_modern_proof_until_answered(self):
        from getzilla import continuity
        from getzilla.task_intent import target_digest
        from getzilla.verification import verify
        from tests.test_package_status import PackageStatusTests
        from tests.test_task_intent import TaskIntentTests
        with project_copy(git=True, minimal_runtime=True, source_only_runtime=True) as root:
            PackageStatusTests().prepare(root, complete=True)
            (root / 'feature.txt').write_text('recoverable fixture work\n')
            prepare_review_source(root)
            report = write_current_verification(root)
            helper = TaskIntentTests()
            question = {'id': 'Q-COMPLETE', 'question': 'Which unfinished work belongs to this result?',
                        'targets': ['AC-001'], 'paths': ['feature.txt'], 'source_ref': 'fixture-human:task'}
            continuity.update_intent(root, helper.request(root, {'kind': 'ask', 'question': question}, 'ask-complete'))
            self.assertTrue(verification_plan.report_gaps(root, report))
            blocked = verify(root, mode='pr', record=False)
            self.assertEqual(blocked['status'], 'fail')
            self.assertTrue(any(item['name'] == 'task-context' and 'Q-COMPLETE' in item['summary']
                                for item in blocked['checks']))
            route = state.get_active_route(root)
            question = route['intent_state']['questions'][0]
            answer = {'text': 'Only the fixture work described by AC-001 belongs to this result.',
                      'source_kind': 'human', 'source_ref': 'fixture-human:event-1',
                      'principal': 'fixture-owner', 'event_id': 'fixture-human:event-1',
                      'target_digest': target_digest(root, route, question)}
            continuity.update_intent(root, helper.request(root, {'kind': 'answer', 'id': 'Q-COMPLETE',
                                                               'answer': answer}, 'answer-complete'))
            refreshed = write_current_verification(root)
            self.assertNotEqual(refreshed['required_plan']['digest'], report['required_plan']['digest'])
            self.assertTrue(verification_plan.report_gaps(root, report), 'answering cannot revive old proof')


if __name__ == '__main__':
    unittest.main()
