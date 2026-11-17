"""Owned mocked diagnostic consumer; never evaluate policy or old test cases."""
import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import ctypes
import tempfile
from types import SimpleNamespace
import unittest

from getzilla import pytest_progress
from getzilla.verification_failure_excerpt import _core_output_excerpt, policy_diagnostic
from tests.test_public_checker_core_api import fixture_guard


class PolicyDiagnosticIdentityTests(unittest.TestCase):
    def test_owned_hook_retains_closed_reason_and_static_case_identity(self):
        scratch = Path(__file__).resolve().parents[1] / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-policy-diagnostic-', dir=scratch) as name:
            owned = Path(name)
            consumer = owned / 'consumer'
            consumer.mkdir()
            outside = owned / 'outside-consumer'
            outside.write_bytes(b'owned inert bytes')
            with fixture_guard(consumer):
                events = []
                worker = object.__new__(pytest_progress._WorkerProgress)
                worker.journal = None
                worker.failure_disabled = worker.failure_overflow = False
                worker.failure_sequence = worker.failure_rows = 0
                worker._failure_append = lambda event: events.append(copy.deepcopy(event))
                cases = (
                    ('test_gh_read_pr_view', 'Policy resource budget exhausted: OWNED_PRIVATE_CANARY', 'budget'),
                    ('test_gh_read_issue_list', 'Owned unclassified refusal OWNED_PRIVATE_CANARY', 'other'),
                )
                nodeids = []
                for method, raw_reason, category in cases:
                    nodeid = 'tests/test_policy_hardening.py::ExternalWriteTests::' + method
                    nodeids.append(nodeid)
                    try:
                        self.assertTrue(False, policy_diagnostic(False, raw_reason))
                    except AssertionError as error:
                        call = SimpleNamespace(excinfo=SimpleNamespace(value=error), when='call')
                    hook = worker.pytest_runtest_makereport(SimpleNamespace(nodeid=nodeid), call)
                    next(hook)
                    with self.assertRaises(StopIteration):
                        next(hook)
                    worker.pytest_runtest_logreport(SimpleNamespace(failed=True, when='call', nodeid=nodeid))
                    self.assertEqual(events[-1].get('diagnostic'), {'decision': 'deny', 'reason': category})
                    self.assertEqual(events[-1]['key'], hashlib.sha256(nodeid.encode('ascii')).hexdigest())
                self.assertEqual(len(events), 2)
                self.assertNotEqual(events[0]['key'], events[1]['key'])
                self.assertTrue(all(event['path'] == 'tests/test_policy_hardening.py' for event in events))
                self.assertNotIn('OWNED_PRIVATE_CANARY', json.dumps(events))
                raw = ('==== FAILURES ====\ntests/test_policy_hardening.py:1: AssertionError: OWNED_RAW_COMMAND\n'
                       '==== short test summary info ====\n' + ''.join(
                           'FAILED ' + nodeid + ' - OWNED_PRIVATE_CANARY\n' for nodeid in nodeids) +
                       '2 failed in 0.01s\n')
                excerpt = _core_output_excerpt(raw, failed=True, pytest_output=True,
                    trusted={'tests/test_policy_hardening.py': (1000, {
                        'ExternalWriteTests::' + method for method, _, _ in cases})})
                identities = next(line for line in excerpt.splitlines() if line.startswith('pytest_failure_ids='))
                self.assertEqual(json.loads(identities.split('=', 1)[1]), nodeids)
                self.assertNotIn('OWNED_RAW_COMMAND', excerpt)
                self.assertNotIn('OWNED_PRIVATE_CANARY', excerpt)
                with self.assertRaisesRegex(AssertionError, 'outside-fixture'):
                    outside.read_bytes()
                for effect in (lambda: subprocess.run(['never-execute']), lambda: socket.socket(),
                               lambda: ctypes.CDLL(None)):
                    with self.assertRaisesRegex(AssertionError, 'effect denied'):
                        effect()
