"""Late input failures refuse after validated observation, without external effects."""
from contextlib import ExitStack
from datetime import datetime, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from adaptive_trust_ci import public_admission as admission
from adaptive_trust_ci import security_bundle as bundle


class LateAdmissionReadTests(unittest.TestCase):
    def evaluate(self, failure):
        selector = admission.Selector('owned/fixture', 1, 1, '1'*40, '2'*40, '3'*40, 1, 1)
        policy = SimpleNamespace(policy_digest='a'*64)
        steps = []
        def read(step, result):
            steps.append(step)
            if step == failure:
                raise FileNotFoundError('private fixture path must not be retained')
            if step == 'source' and failure == 'programming-error':
                raise AssertionError('programming bug must escape')
            return result
        def denied(*args, **kwargs):
            raise AssertionError('unmocked fixture effect')
        core = SimpleNamespace(policy_root='owned-policy',
                               security=SimpleNamespace(_policy_digest=lambda _: read('policy', 'a'*64)))
        authority = SimpleNamespace(security_core=core, as_policy=lambda: policy)
        facts = SimpleNamespace(source_validated=True, blockers=(), content_digest=bundle.digest([]),
                                snapshot_digest=bundle.digest([]), valid_until=None)
        evidence = admission.Evidence({}, {})
        with ExitStack() as stack:
            stack.enter_context(patch.object(admission.bundle, 'parse_bundle', return_value=object()))
            stack.enter_context(patch.object(admission, 'validate_local_inputs', return_value=facts))
            stack.enter_context(patch.object(admission, 'observe', side_effect=lambda *a: read('observation', object())))
            stack.enter_context(patch.object(admission, 'content_manifest', side_effect=lambda *a: read('source', [])))
            stack.enter_context(patch.object(admission, '_snapshot_preflight', side_effect=lambda *a: read('snapshot', [])))
            stack.enter_context(patch.object(admission, '_source_binding', side_effect=lambda *a: read('binding', None)))
            stack.enter_context(patch.object(admission.bundle, 'evaluate_bundle', side_effect=lambda *a, **kw:
                read('decision', SimpleNamespace(consistent=True, reasons=(), valid_until=None))))
            for target in ('builtins.open', 'io.open', 'os.open', 'subprocess.Popen', 'os.system', 'os.fork',
                           'os.posix_spawn', 'socket.socket', 'socket.create_connection', 'ctypes.CDLL', 'ctypes.PyDLL'):
                stack.enter_context(patch(target, denied))
            decision = admission.evaluate(object(), authority, selector, evidence,
                now=datetime(2026, 11, 17, tzinfo=timezone.utc),
                candidate_root='owned-source', snapshot_root='owned-snapshot')
        return decision, steps

    def assert_refusal(self, failure, expected_steps):
        decision, steps = self.evaluate(failure)
        self.assertFalse(decision.eligible)
        self.assertEqual(decision.blockers, ('protected-observation-or-validation-refused',))
        self.assertNotIn('private fixture path', repr(decision))
        self.assertEqual(steps, expected_steps)

    def test_late_source_disappearance_is_a_closed_refusal(self):
        self.assert_refusal('source', ['observation', 'source'])

    def test_late_snapshot_disappearance_is_a_closed_refusal(self):
        self.assert_refusal('snapshot', ['observation', 'source', 'snapshot'])

    def test_late_policy_disappearance_is_a_closed_refusal(self):
        self.assert_refusal('policy', ['observation', 'source', 'snapshot', 'policy'])

    def test_late_programming_error_is_not_swallowed_as_io(self):
        with self.assertRaisesRegex(AssertionError, 'programming bug must escape'):
            self.evaluate('programming-error')

    def test_unchanged_fixture_reaches_the_final_decision_after_every_reread(self):
        decision, steps = self.evaluate(None)
        self.assertTrue(decision.eligible)
        self.assertEqual(steps, ['observation', 'source', 'snapshot', 'policy', 'binding', 'decision'])


if __name__ == '__main__':
    unittest.main()
