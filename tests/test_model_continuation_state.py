from __future__ import annotations

import json
import os
import multiprocessing
import sys
import tempfile
import unittest
from pathlib import Path
from dataclasses import replace
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


def _race(root, binding, results):
    with patch.object(journal.time, 'time', return_value=1000), patch.object(journal, '_qualified_boundary', return_value=True):
        results.put(journal.reserve_next(Path(root), binding, 2, 'process-race', journal.Usage(1, '0.2')))


@unittest.skipIf(os.name == 'nt', 'directory fsync admission is unsupported on Windows')
class ContinuationJournalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / '.getzilla/config/model-continuation.json'
        self.config.parent.mkdir(parents=True)
        self.policy = enabled_policy()
        self.config.write_text(json.dumps(self.policy), encoding='utf-8')
        self.binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
        self.budget = journal.TaskBudget(2, 4, '1.5', 2000)
        clock = patch.object(journal.time, 'time', return_value=1000)
        clock.start()
        self.addCleanup(clock.stop)

    def create(self):
        return journal.create_chain(self.root, self.binding, journal.Usage(1, '0.1'), self.budget)

    def terminal(self, generation=1):
        return journal.record_terminal(self.root, self.binding, generation, 'terminal1', 'rate_limit')

    def reserve(self, revision=2, event='reserve1', cost='0.2'):
        return journal.reserve_next(self.root, self.binding, revision, event, journal.Usage(1, cost))

    def test_original_usage_restart_and_no_production_qualification(self):
        self.assertEqual(self.create()['revision'], 1)
        self.terminal()
        result = self.reserve()
        self.assertEqual(result['reason'], 'adapter_not_qualified')
        state = journal.inspect_chain(self.root, self.binding)
        self.assertEqual(len(state['attempts']), 1)
        self.assertEqual(state['attempts'][0]['cost_micros'], 100000)
        self.assertFalse(result['dispatch_permitted'])

    def test_private_fake_reservation_survives_restart_and_duplicates(self):
        self.create()
        self.terminal()
        with patch.object(journal, '_qualified_boundary', return_value=True):
            first = self.reserve()
            self.assertEqual(first['state'], 'reserved_unknown')
            self.assertEqual(first, self.reserve())
            self.assertEqual(self.reserve(cost='0.3')['reason'], 'conflicting_event')
        state = journal.inspect_chain(self.root, self.binding)
        self.assertEqual(state['generation'], 2)
        self.assertEqual(len(state['attempts']), 2)
        self.assertEqual(state['attempts'][-1]['state'], 'reserved_unknown')

    def test_revocation_stale_callbacks_and_cancellation(self):
        self.create()
        self.terminal()
        self.policy['enabled'] = False
        self.config.write_text(json.dumps(self.policy), encoding='utf-8')
        with patch.object(journal, '_qualified_boundary', return_value=True):
            self.assertEqual(self.reserve()['reason'], 'policy_revoked')
        self.assertEqual(journal.cancel_chain(self.root, self.binding, 2)['state'], 'cancelled')
        self.assertEqual(journal.record_terminal(self.root, self.binding, 1, 'later', 'rate_limit')['reason'], 'chain_stopped')

    def test_missing_journal_is_not_a_fresh_budget(self):
        self.create()
        (self.root / '.getzilla/runtime/model-continuation/journal.json').unlink()
        with self.assertRaisesRegex(journal.JournalError, 'journal_missing'):
            journal.inspect_chain(self.root, self.binding)
        with self.assertRaisesRegex(journal.JournalError, 'journal_missing'):
            self.create()

    def test_decimal_rounding_and_initial_budget(self):
        self.assertEqual(journal.money_micros('0.0000019', ceiling=True), 1)
        self.assertEqual(journal.money_micros('0.0000011', ceiling=False), 2)
        for value in (None, True, 'NaN', 'Infinity', '-1'):
            with self.assertRaises(journal.JournalError):
                journal.money_micros(value, ceiling=False)
        with self.assertRaises(journal.JournalError):
            journal.create_chain(self.root, self.binding, journal.Usage(5, '0.1'), self.budget)

    def test_rejected_first_creation_does_not_prevent_valid_retry(self):
        with self.assertRaisesRegex(journal.JournalError, 'initial_budget_exhausted'):
            journal.create_chain(self.root, self.binding, journal.Usage(5, '0.1'), self.budget)
        self.assertEqual(self.create()['state'], 'active_unknown')

    def test_current_epoch_deadline_is_accepted_and_expires(self):
        now = int(datetime.now(timezone.utc).timestamp())
        self.assertGreater(now, 1_000_000_000)
        budget = replace(self.budget, deadline_epoch=now + 60)
        with patch.object(journal.time, 'time', return_value=now):
            result = journal.create_chain(self.root, self.binding, journal.Usage(1, '0.1'), budget)
            self.assertEqual(result['state'], 'active_unknown')
            self.assertEqual(journal.inspect_chain(self.root, self.binding)['limits']['deadline'], now + 60)
        with patch.object(journal.time, 'time', return_value=now + 60):
            self.assertEqual(self.terminal()['reason'], 'deadline_exhausted')

    def test_deadline_timestamp_has_separate_closed_bound(self):
        for deadline in (True, 1.5, 0, -1, 253402300800, '2000000000'):
            with self.subTest(deadline=deadline), self.assertRaisesRegex(journal.JournalError, 'invalid_task_budget'):
                journal.create_chain(self.root, self.binding, journal.Usage(1, '0.1'),
                                     replace(self.budget, deadline_epoch=deadline))
        with self.assertRaisesRegex(journal.JournalError, 'invalid_task_budget'):
            journal.create_chain(self.root, self.binding, journal.Usage(1, '0.1'),
                                 replace(self.budget, max_requests=1_000_000_001))

    def test_policy_money_preserves_decimal_ceiling(self):
        raw = json.dumps(self.policy).replace('"max_cost_usd": 1.5', '"max_cost_usd": 1.000000999999999999999999')
        self.config.write_text(raw, encoding='utf-8')
        self.create()
        self.assertEqual(journal.inspect_chain(self.root, self.binding)['limits']['cost_micros'], 1000000)

    def test_budgets_bind_original_and_cannot_restart_task(self):
        self.create()
        with self.assertRaisesRegex(journal.JournalError, 'task_already_recorded'):
            journal.create_chain(self.root, replace(self.binding, chain_id='fresh'), journal.Usage(1, '0'), self.budget)
        self.terminal()
        with patch.object(journal, '_qualified_boundary', return_value=True):
            self.assertEqual(self.reserve(cost='1.4000001')['reason'], 'cost_exhausted')
            result = journal.reserve_next(self.root, self.binding, 2, 'requests', journal.Usage(4, '0.1'))
            self.assertEqual(result['reason'], 'requests_exhausted')
            self.reserve()
            self.assertEqual(journal.record_terminal(self.root, self.binding, 1, 'stale', 'rate_limit')['reason'], 'stale_generation')
            journal.record_terminal(self.root, self.binding, 2, 'terminal2', 'rate_limit')
            self.assertEqual(self.reserve(4, 'reserve2')['reason'], 'attempts_exhausted')

    def test_concurrent_identical_events_reserve_once(self):
        self.create()
        self.terminal()
        with patch.object(journal, '_qualified_boundary', return_value=True), ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.reserve(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(len(journal.inspect_chain(self.root, self.binding)['attempts']), 2)

    def test_clock_deadline_binding_and_non_model_failures_stop(self):
        self.create()
        with self.assertRaisesRegex(journal.JournalError, 'binding_mismatch'):
            journal.inspect_chain(self.root, replace(self.binding, checkpoint_digest='d'*64))
        journal.record_terminal(self.root, self.binding, 1, 'test', 'test_failure')
        with patch.object(journal, '_qualified_boundary', return_value=True):
            self.assertEqual(self.reserve()['reason'], 'failure_not_eligible')
            with patch.object(journal.time, 'time', return_value=999):
                self.assertEqual(self.reserve()['reason'], 'clock_uncertain')
            with patch.object(journal.time, 'time', return_value=1120):
                self.assertEqual(self.reserve()['reason'], 'deadline_exhausted')

    def test_publication_error_never_returns_success_or_replays(self):
        self.create()
        self.terminal()
        original = journal.fsx.fsync_dir
        def fail_after_publish(handle):
            raise OSError('SECRET_SENTINEL')
        with patch.object(journal, '_qualified_boundary', return_value=True), patch.object(journal.fsx, 'fsync_dir', side_effect=fail_after_publish):
            with self.assertRaisesRegex(journal.JournalError, '^storage_unavailable$'):
                self.reserve()
        self.assertIs(journal.fsx.fsync_dir, original)
        state = journal.inspect_chain(self.root, self.binding)
        self.assertEqual(state['generation'], 2)
        self.assertEqual(state['attempts'][-1]['state'], 'reserved_unknown')
        self.assertEqual(self.reserve(3, 'another')['reason'], 'outcome_unknown')

    def test_corrupt_and_unsafe_journal_is_not_replaced(self):
        self.create()
        path = self.root / '.getzilla/runtime/model-continuation/journal.json'
        saved = path.read_bytes()
        for content in (b'{', b'{"schema_version":1,"schema_version":1}', b' '*(journal.MAX_BYTES+1)):
            path.write_bytes(content)
            with self.assertRaises(journal.JournalError):
                journal.inspect_chain(self.root, self.binding)
            self.assertEqual(path.read_bytes(), content)
        path.write_bytes(saved)
        path.chmod(0o700)
        with self.assertRaisesRegex(journal.JournalError, 'unsafe_file'):
            journal.inspect_chain(self.root, self.binding)
        path.chmod(0o600)
        alias = path.parent / 'alias'
        os.link(path, alias)
        with self.assertRaisesRegex(journal.JournalError, 'unsafe_file'):
            journal.inspect_chain(self.root, self.binding)
        alias.unlink()
        path.unlink()
        path.symlink_to(self.config)
        with self.assertRaises(journal.JournalError):
            journal.inspect_chain(self.root, self.binding)
        path.unlink()
        os.mkfifo(path, 0o600)
        with self.assertRaises(journal.JournalError):
            journal.inspect_chain(self.root, self.binding)

    def test_recheck_revocation_after_boundary(self):
        self.create()
        self.terminal()
        def revoke(*_):
            self.policy['enabled'] = False
            self.config.write_text(json.dumps(self.policy), encoding='utf-8')
            return True
        with patch.object(journal, '_qualified_boundary', side_effect=revoke):
            self.assertEqual(self.reserve()['reason'], 'policy_revoked')
        self.assertEqual(journal.inspect_chain(self.root, self.binding)['generation'], 1)

    def test_independent_processes_reserve_once(self):
        self.create()
        self.terminal()
        context = multiprocessing.get_context('spawn')
        queue = context.Queue()
        children = [context.Process(target=_race, args=(str(self.root), self.binding, queue)) for _ in range(2)]
        try:
            for child in children:
                child.start()
            results = [queue.get(timeout=15) for _ in children]
            for child in children:
                child.join(timeout=15)
                self.assertEqual(child.exitcode, 0)
            self.assertEqual(results[0], results[1])
            self.assertEqual(len(journal.inspect_chain(self.root, self.binding)['attempts']), 2)
        finally:
            for child in children:
                if child.is_alive():
                    child.terminate()
                    child.join(timeout=5)
            queue.close()

    def test_lock_contention_and_missing_lock_fail_closed(self):
        self.create()
        path = self.root / '.getzilla/runtime/model-continuation/lock'
        with path.open('rb') as locked:
            journal.fsx.lock_file(locked.fileno(), blocking=False)
            try:
                with self.assertRaisesRegex(journal.JournalError, 'lock_busy'):
                    journal.inspect_chain(self.root, self.binding)
            finally:
                journal.fsx.unlock_file(locked.fileno())
        path.unlink()
        with self.assertRaisesRegex(journal.JournalError, 'lock_missing'):
            self.create()

    def test_directory_replacement_during_reservation_fails_closed(self):
        self.create()
        self.terminal()
        directory = self.root / '.getzilla/runtime/model-continuation'
        def replace_directory(*_):
            directory.rename(directory.with_name('retained'))
            directory.mkdir(mode=0o700)
            return True
        with patch.object(journal, '_qualified_boundary', side_effect=replace_directory):
            with self.assertRaisesRegex(journal.JournalError, 'directory_replaced'):
                self.reserve()

    def test_failure_before_replace_leaves_original_reservation_counts(self):
        self.create()
        self.terminal()
        with patch.object(journal, '_qualified_boundary', return_value=True), patch.object(journal.fsx, 'replace_at', side_effect=OSError):
            with self.assertRaisesRegex(journal.JournalError, 'storage_unavailable'):
                self.reserve()
        self.assertEqual(journal.inspect_chain(self.root, self.binding)['generation'], 1)

    def test_capacity_and_policy_change_never_discard_active_chain(self):
        self.create()
        with patch.object(journal, 'MAX_CHAINS', 1):
            with self.assertRaisesRegex(journal.JournalError, 'capacity_exhausted'):
                journal.create_chain(self.root, replace(self.binding, chain_id='chain2', task_id='task2'), journal.Usage(1, '0'), self.budget)
        self.assertEqual(journal.inspect_chain(self.root, self.binding)['generation'], 1)
        self.terminal()
        self.policy['candidates'][1]['provider'] = 'changed'
        self.config.write_text(json.dumps(self.policy), encoding='utf-8')
        self.assertEqual(self.reserve()['reason'], 'policy_changed')

    def test_untrusted_error_text_and_unknown_cost_never_persist(self):
        self.create()
        for category in ('SECRET_SENTINEL prompt text', {}, None):
            with self.assertRaises(journal.JournalError):
                journal.record_terminal(self.root, self.binding, 1, 'event', category)
        for usage in (journal.Usage(1, None), journal.Usage(True, '0'), journal.Usage(1, 0.1)):
            with self.assertRaises(journal.JournalError):
                journal.reserve_next(self.root, self.binding, 1, 'event', usage)
        self.assertNotIn(b'SECRET_SENTINEL', (self.root / '.getzilla/runtime/model-continuation/journal.json').read_bytes())


if __name__ == '__main__':
    unittest.main()
