"""Bounded pure joins for declared costs and the retained human transport CLI."""
from pathlib import Path
from types import SimpleNamespace
import io
import unittest
from unittest import mock

import getzilla
from getzilla import verification_plan
from adaptive_trust_ci import cli, http_response
from tests.test_batch_composition_joins import _Registry, pure


class StageTwoJoinTests(unittest.TestCase):
    def test_declared_cost_interpreter_changes_actual_plan_policy_digest(self):
        content = [b'owned declared-cost implementation']
        def imported(name, package):
            return SimpleNamespace(filename=name.removeprefix('.') + '.py')
        def source(module):
            return content[0] if module.filename == 'cost_guard.py' else module.filename.encode()
        with mock.patch.object(verification_plan, '_POLICY_PATHS', ()), \
                mock.patch.object(verification_plan.importlib, 'import_module', side_effect=imported), \
                mock.patch.object(verification_plan, '_module_source', side_effect=source), \
                mock.patch.object(getzilla, 'STACK_DIR', _Registry()), pure():
            before = verification_plan.policy_binding(Path('owned-stage-two'))
            self.assertIn('cost_guard.py', before['implementation'])
            content[0] = b'owned changed declared-cost implementation'
            after = verification_plan.policy_binding(Path('owned-stage-two'))
            self.assertNotEqual(before['digest'], after['digest'])

    def human_cli(self, status, body):
        # No real approval file/key is read, and no request/process can be made.
        args = SimpleNamespace(command='approval-submit', approval=Path('public-owned-fixture'),
                               url='https://fixture.invalid')
        out, err = io.BytesIO(), io.BytesIO()
        request = []
        def bounded(value):
            request.append(value)
            return status, body
        with mock.patch.object(cli, 'build_parser', return_value=SimpleNamespace(parse_args=lambda _: args)), \
                mock.patch.object(Path, 'read_bytes', return_value=b'public fixture bytes'), \
                mock.patch.object(http_response, 'request_bytes', side_effect=bounded), \
                mock.patch.object(cli.sys, 'stdout', SimpleNamespace(buffer=out, write=lambda _: None)), \
                mock.patch.object(cli.sys, 'stderr', SimpleNamespace(buffer=err)), pure():
            result = cli.main([])
        self.assertEqual(len(request), 1)
        self.assertEqual(request[0].get_method(), 'POST')
        self.assertEqual(request[0].full_url, 'https://fixture.invalid/approvals')
        self.assertEqual(request[0].data, b'public fixture bytes')
        return result, out.getvalue(), err.getvalue()

    def test_human_cli_retains_small_success_through_bounded_transport(self):
        self.assertEqual(self.human_cli(202, b'owned accepted'), (0, b'owned accepted', b''))

    def test_human_cli_retains_primary_error_status_without_retry(self):
        self.assertEqual(self.human_cli(403, b'owned refused'), (1, b'', b'owned refused'))
