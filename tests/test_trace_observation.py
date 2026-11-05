"""Real managed child facts retain the original native claim binding."""
import json
import os
import subprocess
import signal
import select
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import CancelledError
from threading import Event

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'.getzilla'))
from getzilla import state, sprint_lifecycle, task_budget
from getzilla.router import build_route
from getzilla.observation_privacy import load_local
from tests._support import project_copy
try:
    from getzilla import trace_observation
except ImportError:
    trace_observation = None

SESSION = '00000000-0000-4000-8000-000000000001'


class TraceObservationTests(unittest.TestCase):
    def setUp(self):
        saved = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, saved)
        self.addCleanup(os.fchdir, saved)

    def setup_native(self, root, *, enroll=True):
        self.assertIsNotNone(trace_observation, 'actual managed operation collector is missing')
        root.chmod(0o755)
        (root/'.getzilla').chmod(0o755)
        os.chdir(root)
        state.bind_session(SESSION)
        route = build_route(root, 'Fix a README typo.', SESSION).to_dict()
        state.set_active_route(root, route)
        if enroll:
            route = sprint_lifecycle.enroll_trace(root, expected_epoch=0, expected_revision=0)
        limits = {'calls': 3, 'failures': 2, 'repeat_failures': 2, 'deadline_epoch': 2000000000,
                  'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 10000}
        task_budget.initialize(root, limits, 0, route['state_revision'], task_id=route['logical_task_id'])
        return state.get_active_route(root)

    def test_real_spawn_result_and_replay_have_no_raw_payload_or_invented_usage(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.setup_native(root)
            argv = [sys.executable, '-c', 'from pathlib import Path; p=Path("marker"); p.write_text(p.read_text()+"x" if p.exists() else "x"); print("PRIVATE_SENTINEL")']
            result = task_budget.execute_local(root, 'native-one', argv, timeout=1)
            replay = task_budget.execute_local(root, 'native-one', argv, timeout=1)
            self.assertEqual(result['outcome'], 'succeeded')
            self.assertTrue(replay['replayed'])
            self.assertEqual((root/'marker').read_text(), 'x')
            rows = [row for row in load_local(root)['events'] if row.get('event') == 'operation']
            self.assertEqual([row['kind'] for row in rows], ['budget_claimed', 'operation_started', 'operation_finished'])
            self.assertTrue(all(row['logical_task_id'] == route['logical_task_id'] for row in rows))
            self.assertEqual(rows[-1]['outcome'], 'succeeded')
            self.assertGreaterEqual(rows[-1]['elapsed_ns'], 0)
            self.assertNotIn('PRIVATE_SENTINEL', (root/'.getzilla/runtime/metrics.jsonl').read_text())
            self.assertIsNone(task_budget.inspect(root)['observed']['cost_micros'])

    def test_failed_popen_is_a_claim_and_not_a_synthetic_started_span(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            self.setup_native(root)
            real_popen = subprocess.Popen
            def fail_actual(argv, *args, **kwargs):
                if list(argv) == [sys.executable, '--version']:
                    raise OSError('PRIVATE_SENTINEL')
                return real_popen(argv, *args, **kwargs)
            with patch('subprocess.Popen', side_effect=fail_actual), self.assertRaises(OSError):
                task_budget.execute_local(root, 'native-fail', [sys.executable, '--version'], timeout=1)
            # A bare library exception leaves the committed claim pending; an
            # explicit post-cleanup current-owner reconciliation publishes it.
            self.assertEqual([row for row in load_local(root)['events'] if row.get('event') == 'operation'], [])
            self.assertTrue(sprint_lifecycle.deliver(root, state.get_active_route(root)['route_id']))
            rows = [row for row in load_local(root)['events'] if row.get('event') == 'operation']
            self.assertEqual([row['kind'] for row in rows], ['budget_claimed'])
            self.assertEqual(task_budget.inspect(root)['unresolved'], 1)
            self.assertNotIn('PRIVATE_SENTINEL', json.dumps(rows))

    def test_unenrolled_trace_does_not_block_or_repeat_real_effect(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            self.setup_native(root, enroll=False)
            result = task_budget.execute_local(root, 'native-one', [sys.executable, '--version'], timeout=1)
            self.assertEqual(result['outcome'], 'succeeded')
            self.assertEqual(result['observation_coverage'], 'not_enrolled')
            self.assertEqual(task_budget.inspect(root)['calls'], 1)

    def test_actual_a_child_withdrawal_never_retags_or_mutates_b(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route_a = self.setup_native(root)
            route_b = build_route(root, 'Fix a different README typo.', SESSION).to_dict()
            target = [sys.executable, '-c', 'import time; time.sleep(10); open("late-effect","w").close()']
            spawned = Event()
            original_popen = subprocess.Popen
            def observe_popen(argv, *args, **kwargs):
                process = original_popen(argv, *args, **kwargs)
                if list(argv) == target:
                    spawned.set()
                return process
            def execute():
                state.bind_session(SESSION)
                return task_budget.execute_local(root, 'native-a', target, timeout=2)
            with patch('subprocess.Popen', side_effect=observe_popen), ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(execute)
                self.assertTrue(spawned.wait(5))
                state.set_active_route(root, route_b)
                b_path = root/'.getzilla/runtime/routes'/f"{route_b['route_id']}.json"
                before_b = b_path.read_bytes()
                active_before = (root/'.getzilla/runtime/active-route.json').read_bytes()
                pointer_before = (root/'.getzilla/runtime/sessions'/f'{SESSION}.json').read_bytes()
                result = future.result(timeout=8)
            self.assertEqual(result['outcome'], 'unknown')
            self.assertFalse((root/'late-effect').exists())
            self.assertEqual(b_path.read_bytes(), before_b)
            self.assertEqual((root/'.getzilla/runtime/active-route.json').read_bytes(), active_before)
            self.assertEqual((root/'.getzilla/runtime/sessions'/f'{SESSION}.json').read_bytes(), pointer_before)
            original_a = state.canonical_route(root, route_a['route_id'])
            self.assertEqual(original_a['task_budget']['operations']['native-a']['state'], 'running')
            rows = [row for row in load_local(root)['events'] if row.get('operation_id') == 'native-a']
            self.assertTrue(rows)
            self.assertTrue(all(row['logical_task_id'] == route_a['logical_task_id'] for row in rows))

    def test_slow_observer_publication_occurs_only_after_owned_child_reap(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            self.setup_native(root)
            target = [sys.executable, '--version']
            original_popen = subprocess.Popen
            original_publish = trace_observation.publish_observations
            processes, captured = [], []
            def observe_popen(argv, *args, **kwargs):
                process = original_popen(argv, *args, **kwargs)
                if list(argv) == target:
                    processes.append(process)
                return process
            def slow_publish(*args, **kwargs):
                self.assertIsNotNone(processes[0].returncode)
                self.assertEqual(state._TRANSITIONS.get(), ())
                captured.extend(args[2])
                time.sleep(0.1)
                return original_publish(*args, **kwargs)
            begin = time.monotonic_ns()
            with patch('subprocess.Popen', side_effect=observe_popen):
                # The function is imported at the actual executor boundary.
                with patch('getzilla.trace_observation.publish_observations', side_effect=slow_publish):
                    result = task_budget.execute_local(root, 'native-slow-observer', target, timeout=1)
            total = time.monotonic_ns()-begin
            self.assertEqual(result['outcome'], 'succeeded')
            terminal = next(row for row in captured if row['kind'] == 'operation_finished')
            self.assertGreaterEqual(total-terminal['elapsed_ns'], 100_000_000)

    def test_terminal_capture_precedes_settlement_and_keeps_actual_reap_cut(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            self.setup_native(root)
            captured = []
            original_capture = trace_observation.capture_phase
            original_reconcile = task_budget.reconcile
            def observe_capture(*args, **kwargs):
                row = original_capture(*args, **kwargs)
                if args[1] == 'operation_finished':
                    captured.append(row)
                return row
            def observe_settlement(*args, **kwargs):
                self.assertTrue(captured, 'reap observation must freeze before settlement can block')
                return original_reconcile(*args, **kwargs)
            with patch('getzilla.trace_observation.capture_phase', side_effect=observe_capture), patch('getzilla.task_budget.reconcile', side_effect=observe_settlement):
                result = task_budget.execute_local(root, 'native-cut', [sys.executable, '--version'], timeout=1)
            self.assertEqual(result['outcome'], 'succeeded')

    def test_slow_actual_journal_fsync_starts_after_timeout_reap_and_settlement(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            self.setup_native(root)
            journal = (root / '.getzilla/runtime/metrics.jsonl').stat()
            target = [sys.executable, '-c',
                      'from pathlib import Path; import time; Path("fsync-effect").write_text("x"); time.sleep(1)']
            original_popen, original_fsync = subprocess.Popen, os.fsync
            processes, synced = [], []
            def observe_popen(argv, *args, **kwargs):
                process = original_popen(argv, *args, **kwargs)
                if list(argv) == target:
                    processes.append(process)
                return process
            def slow_journal(descriptor):
                info = os.fstat(descriptor)
                if (info.st_dev, info.st_ino) == (journal.st_dev, journal.st_ino):
                    self.assertIsNotNone(processes[0].returncode)
                    self.assertEqual(state._TRANSITIONS.get(), ())
                    self.assertEqual(task_budget.inspect(root)['unresolved'], 0)
                    synced.append(time.monotonic_ns())
                    time.sleep(0.15)
                return original_fsync(descriptor)
            with patch('subprocess.Popen', side_effect=observe_popen), patch('os.fsync', side_effect=slow_journal):
                result = task_budget.execute_local(root, 'fsync-after-reap', target, timeout=0.08)
            self.assertTrue(synced)
            self.assertEqual(result['outcome'], 'failed')
            self.assertEqual(result['observation_coverage'], 'partial')
            self.assertEqual((root / 'fsync-effect').read_text(), 'x')
            self.assertEqual(task_budget.inspect(root)['calls'], 1)
            replay = task_budget.execute_local(root, 'fsync-after-reap', target, timeout=0.08)
            self.assertTrue(replay['replayed'])
            self.assertEqual((root / 'fsync-effect').read_text(), 'x')

    def test_observer_exception_never_abandons_or_repeats_actual_child_effect(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            self.setup_native(root)
            argv = [sys.executable, '-c', 'from pathlib import Path; p=Path("marker"); p.write_text(p.read_text()+"x" if p.exists() else "x")']
            with patch('getzilla.trace_observation.capture_phase', side_effect=RuntimeError('PRIVATE_SENTINEL')):
                result = task_budget.execute_local(root, 'native-observer-error', argv, timeout=1)
            self.assertEqual(result['outcome'], 'succeeded')
            self.assertEqual(result['observation_coverage'], 'partial')
            self.assertEqual((root/'marker').read_text(), 'x')
            replay = task_budget.execute_local(root, 'native-observer-error', argv, timeout=1)
            self.assertTrue(replay['replayed'])
            self.assertEqual((root/'marker').read_text(), 'x')
            self.assertNotIn('PRIVATE_SENTINEL', (root/'.getzilla/runtime/metrics.jsonl').read_text())

    def test_interrupt_and_genuine_cancel_propagate_after_owned_child_cleanup(self):
        for error in (KeyboardInterrupt, SystemExit, CancelledError):
            with self.subTest(error=error.__name__), project_copy(git=True, minimal_runtime=True) as root:
                self.setup_native(root)
                target = [sys.executable, '-c', 'import time; time.sleep(10); open("late-cancel-effect","w").close()']
                processes = []
                original_popen = subprocess.Popen
                def observe_popen(argv, *args, **kwargs):
                    process = original_popen(argv, *args, **kwargs)
                    if list(argv) == target:
                        processes.append(process)
                    return process
                try:
                    with patch('subprocess.Popen', side_effect=observe_popen), patch('getzilla.trace_observation.capture_phase', side_effect=error()):
                        with self.assertRaises(error):
                            task_budget.execute_local(root, 'native-cancel', target, timeout=1)
                    self.assertIsNotNone(processes[0].returncode, 'owned child must be reaped before cancel propagates')
                    self.assertFalse((root/'late-cancel-effect').exists())
                    self.assertEqual(task_budget.inspect(root)['unresolved'], 1)
                finally:
                    for process in processes:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()

    @unittest.skipUnless(hasattr(os, 'fork'), 'native fork unavailable')
    def test_contended_journal_does_not_delay_owned_timeout_or_repeat_effect(self):
        from getzilla import fsx
        with project_copy(git=True, minimal_runtime=True) as root:
            self.setup_native(root)
            ready_read, ready_write = os.pipe()
            release_read, release_write = os.pipe()
            holder = os.fork()
            if holder == 0:
                try:
                    os.close(ready_read)
                    os.close(release_write)
                    descriptor = os.open('.getzilla/runtime/metrics.jsonl', os.O_RDWR)
                    fsx.lock_file(descriptor)
                    os.write(ready_write, b'1')
                    select.select([release_read], [], [], 1.0)
                    fsx.unlock_file(descriptor)
                    os.close(descriptor)
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            os.close(ready_write)
            os.close(release_read)
            try:
                self.assertTrue(select.select([ready_read], [], [], 2)[0])
                self.assertEqual(os.read(ready_read, 1), b'1')
                command = [sys.executable, '-c',
                           'from pathlib import Path; import time; Path("one-effect").write_text("x"); time.sleep(1)']
                before = time.monotonic()
                result = task_budget.execute_local(root, 'contended-journal', command, timeout=0.08)
                elapsed = time.monotonic()-before
                self.assertLess(elapsed, 0.5)
                self.assertEqual(result['outcome'], 'failed')
                self.assertEqual(result['observation_coverage'], 'partial')
                self.assertEqual((root / 'one-effect').read_text(), 'x')
                self.assertEqual(task_budget.inspect(root)['calls'], 1)
                self.assertEqual(task_budget.inspect(root)['unresolved'], 0)
                self.assertEqual(state.get_active_route(root)['observation_publication']['delivery'], {})
            finally:
                try:
                    os.write(release_write, b'x')
                except BrokenPipeError:
                    pass
                os.close(release_write)
                os.close(ready_read)
                _, status = os.waitpid(holder, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)


if __name__ == '__main__':
    unittest.main()
