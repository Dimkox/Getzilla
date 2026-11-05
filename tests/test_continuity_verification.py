"""Verifier continuity consumers, separate from intake and worker fixtures."""
from __future__ import annotations

import sys
import unittest
from unittest.mock import patch

from tests._support import PROJECT, project_copy

sys.path.insert(0, str(PROJECT / '.getzilla'))
from getzilla import state
from getzilla.router import build_route


class ContinuityVerificationTests(unittest.TestCase):
    def setUp(self):
        state.bind_session(None)

    def tearDown(self):
        state.bind_session(None)

    def submit(self, root, text, **kwargs):
        from getzilla.continuity import submit
        return submit(root, text, 's1', **kwargs)

    def light_route(self, root):
        route = build_route(root, 'Fix a typo in README documentation.', 's1').to_dict()
        state.bind_session('s1')
        state.set_active_route(root, route)
        state.bind_session('s1')
        return route

    def test_verifier_captures_before_work_and_refuses_scope_mutation(self):
        from getzilla import verification
        with project_copy(git=True, minimal_runtime=True) as root:
            self.light_route(root)
            def mutate(*args, **kwargs):
                self.submit(root, 'New acceptance condition while verifier is working.')
                return []
            with patch.object(verification, '_python', side_effect=mutate):
                report = verification.verify(root, mode='fast', record=False)
            context_checks = [item for item in report['checks'] if item['name'] == 'task-context']
            self.assertEqual(len(context_checks), 1)
            self.assertEqual(context_checks[0]['status'], 'fail')
            self.assertNotEqual(report['status'], 'pass')

    def test_verifier_refuses_unavailable_authority_without_recording(self):
        from getzilla import verification
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.light_route(root)
            canonical = root / '.getzilla/runtime/routes' / (route['route_id'] + '.json')
            canonical.write_text('{broken')
            with patch.object(verification, '_python', return_value=[]):
                report = verification.verify(root, mode='fast', record=False)
            self.assertEqual(report['status'], 'fail')
            self.assertTrue(any(item['name'] == 'task-context' and item['status'] == 'fail' for item in report['checks']))
