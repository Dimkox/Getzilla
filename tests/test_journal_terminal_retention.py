"""Owned temporary histories only; exercise terminal retention and real FD locks."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import verification_journal as journal


class TerminalRetentionTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / '.getzilla/runtime/scratch'
        parent.mkdir(parents=True, exist_ok=True)
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='owned-terminal-', dir=parent)))
        self.history = self.root / '.getzilla/runtime/verification-history'

    def incomplete(self, *, held=False):
        run = journal.Run(self.root, 'a' * 64, 'owned-terminal')
        self.assertIsNotNone(run.writer)
        worker = journal.Writer(run.path, run.run_id, 'worker-0', run.nonce)
        worker.record_test_failure('tests/test_owned.py::test_failure', 'call', 'AssertionError')
        worker._omissions['action_omitted'] = True
        worker.emit('call', 'start', nodeid='tests/test_owned.py::test_failure')
        if held:
            self.addCleanup(worker.close)
        else:
            # Model a lost actor without fabricating its missing END.
            worker.disabled = True
            worker.close()
        run.close()
        self.assertEqual(run.status, 'incomplete')
        return run, worker

    def record(self, run):
        return next(row for row in json.loads((self.history / 'registry.json').read_bytes())['runs']
                    if row['run_id'] == run.run_id)

    def inventory(self, path):
        return {p.name: (p.read_bytes(), p.stat().st_mode) for p in path.iterdir()}

    def test_four_incomplete_runs_rotate_without_relabelling_retained_failure(self):
        runs = [self.incomplete()[0] for _ in range(4)]
        before = {run.run_id: self.inventory(run.path) for run in runs[1:]}
        entries = dict(journal.export_entries(self.root))
        report = json.loads(entries['journal/index.json'])
        self.assertEqual(report['run_status'], 'incomplete')
        self.assertEqual(report['first_failure']['status'], 'reported')
        self.assertTrue(report['observation_omissions']['action_omitted'])
        new = journal.Run(self.root, 'b' * 64, 'owned-terminal')
        self.addCleanup(new.close)
        self.assertIsNotNone(new.writer, 'four terminal failures must not disable all future diagnostics')
        self.assertFalse(runs[0].path.exists())
        rows = json.loads((self.history / 'registry.json').read_bytes())['runs']
        self.assertEqual(len(rows), 4)
        self.assertEqual([row['status'] for row in rows], ['incomplete'] * 3 + ['active'])
        for run in runs[1:]:
            self.assertEqual(self.inventory(run.path), before[run.run_id])

    def test_mixed_history_preserves_active_run_and_retires_terminal_only(self):
        active = journal.Run(self.root, None, 'owned-terminal')
        self.addCleanup(active.close)
        terminal = [self.incomplete()[0] for _ in range(3)]
        before = self.inventory(active.path)
        new = journal.Run(self.root, None, 'owned-terminal')
        self.addCleanup(new.close)
        self.assertIsNotNone(new.writer)
        self.assertEqual(self.inventory(active.path), before)
        self.assertFalse(terminal[0].path.exists())
        self.assertEqual(self.record(active)['status'], 'active')

    def test_held_worker_lock_refuses_before_any_unlink_then_unlock_allows_retirement(self):
        run, worker = self.incomplete(held=True)
        before = self.inventory(run.path)
        with self.assertRaises((OSError, ValueError)):
            journal._remove_run(self.history, self.record(run))
        self.assertEqual(self.inventory(run.path), before)
        worker.disabled = True
        worker.close()
        journal._remove_run(self.history, self.record(run))
        self.assertFalse(run.path.exists())

    def test_terminal_header_mismatch_and_unknown_path_preserve_all_files(self):
        for wrong in ('active', 'closed', 'foreign-nonce', 'unknown-file', 'unknown-pid-temp'):
            with self.subTest(wrong=wrong):
                self.root = self.root / wrong
                self.root.mkdir()
                self.history = self.root / '.getzilla/runtime/verification-history'
                run, _ = self.incomplete()
                header_path = run.path / 'index.json'
                header = json.loads(header_path.read_bytes())
                if wrong in ('active', 'closed'):
                    header['status'] = wrong
                elif wrong == 'foreign-nonce':
                    header['nonce'] = 'f' * 32
                else:
                    path = run.path / ('foreign' if wrong == 'unknown-file' else 'worker-0.json.tmp123')
                    path.write_bytes(b'preserve')
                    path.chmod(0o600)
                header_path.write_text(json.dumps(header))
                before = self.inventory(run.path)
                with self.assertRaises((OSError, ValueError)):
                    journal._remove_run(self.history, self.record(run))
                self.assertEqual(self.inventory(run.path), before)

    def test_only_proved_health_publish_temp_is_retired_with_terminal_run(self):
        run, _ = self.incomplete()
        # _publish's exclusive .json.tmp file can survive a short failed write.
        with patch.object(journal.os, 'write', return_value=0):
            handle = journal._directory(run.path)
            try:
                with self.assertRaises(OSError):
                    journal._publish(handle, 'worker-0.json', {'inert': True}, 2048)
            finally:
                journal.fsx.close_dir(handle)
        self.assertTrue((run.path / 'worker-0.json.tmp').exists())
        journal._remove_run(self.history, self.record(run))
        self.assertFalse(run.path.exists())

    def test_closed_health_rule_and_nonterminal_records_are_not_relaxed(self):
        for status in ('closed', 'active', 'unavailable'):
            with self.subTest(status=status):
                run, _ = self.incomplete()
                record = self.record(run)
                record['status'] = status
                header = run.path / 'index.json'
                data = json.loads(header.read_bytes())
                data['status'] = status
                header.write_text(json.dumps(data))
                before = self.inventory(run.path)
                with self.assertRaises((OSError, ValueError)):
                    journal._remove_run(self.history, record)
                self.assertEqual(self.inventory(run.path), before)


if __name__ == '__main__':
    unittest.main()
