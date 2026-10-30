from __future__ import annotations

import json
import multiprocessing
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests.test_model_continuation_state import journal, enabled_policy
from getzilla import codex_continuation as coordinator


def _recovered(root, binding, queue):
    with patch.object(journal.time, 'time', return_value=1000):
        queue.put(coordinator.recover_after_restart(Path(root), binding, 1, 1))


@unittest.skipIf(os.name == 'nt', 'directory fsync is unsupported')
class JournalRecoveryTest(unittest.TestCase):
    def test_unknown_survives_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            with patch.object(journal.time, 'time', return_value=1000):
                journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
                result = journal.recovery_status(root, binding, 1, 1)
            self.assertEqual(result['state'], 'active_unknown')
            self.assertFalse(result['dispatch_permitted'])

    def test_recovery_in_new_process_and_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            path = root / '.getzilla/runtime/model-continuation/journal.json'
            with patch.object(journal.time, 'time', return_value=1000):
                journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
                before = path.read_bytes()
                ctx = multiprocessing.get_context('spawn')
                queue = ctx.Queue()
                process = ctx.Process(target=_recovered, args=(str(root), binding, queue))
                process.start()
                process.join(15)
                if process.is_alive():
                    process.terminate()
                    process.join(5)
                    self.fail('recovery worker timed out')
                self.assertEqual(process.exitcode, 0)
                self.assertEqual(queue.get(timeout=5)['reason'], 'outcome_unknown')
                self.assertEqual(journal.recovery_status(root, binding, 2, 1)['reason'], 'stale_revision')
                self.assertEqual(journal.recovery_status(root, binding, 1, 2)['reason'], 'stale_generation')
                policy['enabled'] = False
                config.write_text(json.dumps(policy), encoding='utf-8')
                self.assertEqual(journal.recovery_status(root, binding, 1, 1)['reason'], 'policy_revoked')
                self.assertEqual(path.read_bytes(), before)
                policy['enabled'] = True
                config.write_text(json.dumps(policy), encoding='utf-8')
                with self.assertRaisesRegex(journal.JournalError, 'binding_mismatch'):
                    journal.recovery_status(root, replace(binding, owner_id='other'), 1, 1)
                with patch.object(journal.time, 'time', return_value=999):
                    self.assertEqual(journal.recovery_status(root, binding, 1, 1)['reason'], 'clock_uncertain')
                with patch.object(journal.time, 'time', return_value=2000):
                    self.assertEqual(journal.recovery_status(root, binding, 1, 1)['reason'], 'deadline_exhausted')
                changed = enabled_policy()
                changed['bounds']['max_requests'] = 2
                config.write_text(json.dumps(changed), encoding='utf-8')
                self.assertEqual(journal.recovery_status(root, binding, 1, 1)['reason'], 'policy_changed')
                config.write_text(json.dumps(policy), encoding='utf-8')
                journal.record_terminal(root, binding, 1, 'terminal1', 'rate_limit')
                self.assertEqual(journal.recovery_status(root, binding, 2, 1)['state'], 'terminal_unknown')
                journal.cancel_chain(root, binding, 2)
                self.assertEqual(journal.recovery_status(root, binding, 3, 1)['state'], 'cancelled')
                path.write_text('{broken', encoding='utf-8')
                with self.assertRaises(journal.JournalError):
                    journal.recovery_status(root, binding, 3, 1)
