"""Independent heavy work runs on every verified CPU; serial batches are refused with the parallel command."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import parallel  # noqa: E402
from getzilla import fsx  # noqa: E402
from getzilla.parallel import capacity, expand_each, report, run_batch, serial_batch, serial_refusal  # noqa: E402
from tests._support import project_copy, run_hook  # noqa: E402

XDIST = importlib.util.find_spec('xdist') is not None

def _python_command(script: str) -> str:
    arguments = [sys.executable, '-c', script]
    return subprocess.list2cmdline(arguments) if fsx.WINDOWS else shlex.join(arguments)



def _snapshot(root: Path, workers: int, *, age: float = 0) -> None:
    observed = datetime.fromtimestamp(time.time() - age, timezone.utc).isoformat()
    path = root / parallel.SNAPSHOT
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'chosen_capacity': workers, 'observed_at': observed}), encoding='utf-8')


class CapacityTests(unittest.TestCase):
    def test_fresh_measurement_wins_and_stale_falls_back_to_cpus_minus_reserve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _snapshot(root, 22)
            self.assertEqual(capacity(root), 22)
            _snapshot(root, 22, age=parallel.FRESH_SECONDS + 60)
            with mock.patch.object(parallel, '_allowed_cpus', return_value=28):
                self.assertEqual(capacity(root), 26)
            with mock.patch.object(parallel, '_allowed_cpus', return_value=1):
                self.assertEqual(capacity(root), 1)


class BatchTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_commands_run_concurrently_and_failures_keep_their_tail(self) -> None:
        commands = [f'sleep 0.6 && echo done-{index}' for index in range(4)] + ['echo boom && exit 3']
        started = time.monotonic()
        jobs, folder = run_batch(self.root, commands, workers=5, cwd=self.root)
        wall = time.monotonic() - started
        self.assertLess(wall, 1.8, 'four 0.6 s commands on five workers must overlap')
        self.assertEqual([job.returncode for job in jobs], [0, 0, 0, 0, 3])
        text = report(self.root, jobs, folder, workers=5, wall=wall)
        self.assertIn('4 passed, 1 failed', text)
        self.assertIn('FAIL exit=3', text)
        self.assertIn('boom', text)
        self.assertEqual(len(json.loads((folder / 'summary.json').read_text(encoding='utf-8'))), 5)
        self.assertTrue((folder / '001.log').read_text(encoding='utf-8').endswith('done-0\n'))

    def test_a_refused_command_stops_the_whole_batch(self) -> None:
        marker = self.root / 'ran.txt'
        with mock.patch.object(parallel, 'policy_refusal',
                               side_effect=lambda _root, command, **_context: 'push needs a grant' if 'push' in command else None):
            jobs, folder = run_batch(self.root, [f'touch {marker}', 'git push origin main'], workers=2, cwd=self.root)
        self.assertFalse(marker.exists())
        self.assertIn('nothing ran', report(self.root, jobs, folder, workers=2, wall=0))

    def test_sensitive_commands_are_refused_by_the_real_policy(self) -> None:
        with project_copy(git=True) as root:
            self.assertIsNotNone(parallel.policy_refusal(root, 'git push origin main'))
            self.assertIsNone(parallel.policy_refusal(root, 'echo hello'))

    def test_scanner_policy_uses_the_same_directory_as_the_batch_runner(self) -> None:
        config = self.root / '.getzilla/config'
        config.mkdir(parents=True)
        (config / 'policy.json').write_text('{"secret_read_paths": ["nested/fixture-sensitive.json"]}\n')
        directory = self.root / 'nested'
        directory.mkdir()
        # The injected runner records calls only: no scanner or fixture command executes.
        for operand in ('-cfixture-sensitive.json -- example.py',
                        '--configfile=fixture-sensitive.json -- example.py',
                        '-ofixture-sensitive.json -- example.py', '-- fixture-sensitive.json'):
            runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
            with self.subTest(operand=operand):
                jobs, _ = run_batch(self.root, ['python3 -m bandit ' + operand, 'echo public'],
                                    workers=2, cwd=directory, runner=runner)
                self.assertIsNotNone(jobs[0].refused)
                runner.assert_not_called()
        # Use a real harmless child for the admitted scanner command. The injection
        # checks execution context without installing or executing a scanner.
        runner = mock.Mock(side_effect=lambda _command, **kwargs: fsx.owned_popen('echo public', **kwargs))
        jobs, _ = run_batch(self.root, ['python3 -m bandit -cpublic.yaml -- example.py'],
                            workers=1, cwd=directory, runner=runner)
        self.assertIsNone(jobs[0].refused)
        runner.assert_called_once()
        self.assertEqual(runner.call_args.kwargs['cwd'], directory.resolve())

    def test_skipped_directory_join_refuses_the_entire_batch(self) -> None:
        config = self.root / '.getzilla/config'
        config.mkdir(parents=True)
        (config / 'policy.json').write_text('{"secret_read_paths": ["nested/fixture-sensitive.json"]}\n')
        directory = self.root / 'nested'
        (directory / 'deeper').mkdir(parents=True)
        for separator in ('; ', '\n', ' & '):
            for operand in ('-cfixture-sensitive.json -- example.py',
                            '--configfile=fixture-sensitive.json -- example.py',
                            '-ofixture-sensitive.json -- example.py', '-- fixture-sensitive.json'):
                command = 'false && cd deeper && true' + separator + 'python3 -m bandit ' + operand
                runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
                with self.subTest(command=command):
                    jobs, _ = run_batch(self.root, [command, 'echo public'], workers=2,
                                        cwd=directory, runner=runner)
                    self.assertIsNotNone(jobs[0].refused)
                    runner.assert_not_called()

    def test_each_expands_globs_with_quoted_paths(self) -> None:
        for name in ('test a.php', 'test_b.php', 'other.txt'):
            (self.root / name).write_text('', encoding='utf-8')
        self.assertEqual(expand_each(['test*.php'], 'php -l {}', self.root), ["php -l 'test a.php'", 'php -l test_b.php'])
        self.assertEqual(expand_each(['other.txt'], 'wc -l', self.root), ['wc -l other.txt'])

    def test_cli_exit_codes(self) -> None:
        cli = [sys.executable, str(ROOT / 'scripts' / 'getzilla_par.py'), '-j', '3', '--']
        ok = subprocess.run([*cli, 'echo a', 'echo b', 'echo c'], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn('3 passed, 0 failed', ok.stdout)
        bad = subprocess.run([*cli, 'echo a', 'false'], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1, bad.stdout)

    def test_pipe_capture_works_when_selectors_cannot_register_pipes(self) -> None:
        # Native Windows selectors support sockets, not subprocess pipes.
        import selectors
        command = _python_command("print('portable-output')")
        with mock.patch.object(selectors, 'DefaultSelector', side_effect=OSError('pipe selection unsupported')):
            jobs, _ = run_batch(self.root, [command], workers=1, cwd=self.root)
        self.assertEqual(jobs[0].returncode, 0)
        self.assertEqual(jobs[0].preview.strip(), 'portable-output')

    def test_windows_directory_handles_need_no_posix_directory_flags_or_dir_fd(self) -> None:
        native_open = os.open

        def portable_open(path, flags, *args, **kwargs):
            if 'dir_fd' in kwargs or flags & getattr(os, 'O_DIRECTORY', 0):
                raise OSError('POSIX directory operations unavailable')
            return native_open(path, flags, *args, **kwargs)

        # Exercise the actual fsx WindowsDirectory operations on ordinary files.
        # This does not simulate Win32 Job Objects or qualify junction behavior.
        with mock.patch.object(fsx, 'open_dir', side_effect=lambda path: fsx.WindowsDirectory(str(path), os.lstat(path))), \
                mock.patch.object(os, 'open', side_effect=portable_open):
            jobs, folder = run_batch(self.root, ['echo portable-output'], workers=1, cwd=self.root)
        self.assertEqual(jobs[0].returncode, 0)
        self.assertEqual((folder / '001.log').read_bytes().strip(), b'portable-output')

    def test_missing_windows_process_ownership_backend_refuses_without_execution(self) -> None:
        marker = self.root / 'must-not-run'
        with mock.patch.object(fsx, 'WINDOWS', True), \
                mock.patch.object(fsx, 'process_jobs_supported', return_value=False):
            jobs, folder = run_batch(self.root, [f'echo unsafe > {marker}'], workers=1, cwd=self.root)
        self.assertFalse(marker.exists())
        self.assertEqual(jobs[0].returncode, 125)
        text = report(self.root, jobs, folder, workers=1, wall=0)
        self.assertIn('unsupported', text)
        self.assertLessEqual(len(text.encode()), 32768)

    def test_platform_process_backend_runs_and_reaps_an_ordinary_command(self) -> None:
        processes = []

        def start(command, **kwargs):
            process = fsx.owned_popen(command, **kwargs)
            processes.append(process)
            return process

        jobs, _ = run_batch(self.root, [_python_command("print('ordinary-command')")],
                            workers=1, cwd=self.root, runner=start)
        self.assertEqual(jobs[0].returncode, 0)
        self.assertEqual(jobs[0].preview.strip(), 'ordinary-command')
        self.assertEqual(processes[0].poll(), 0)
        owned = fsx.owned_job(processes[0])
        if fsx.WINDOWS:
            self.assertIsNotNone(owned)
            self.assertEqual(owned.active_processes(), 0)

    def test_invalid_pipe_payload_is_refused_without_enqueue_or_payload_disclosure(self) -> None:
        invoked = []

        def work():
            invoked.append(True)

        for payload in (work, 'synthetic-nonbyte-payload', '', bytearray(b'not-exact-bytes'),
                        b'x' * (parallel.CHUNK_BYTES + 1)):
            processes = []
            streams = []

            def start(command, **kwargs):
                process = fsx.owned_popen(command, **kwargs)
                native = process.stdout

                class Stream:
                    closed = False
                    delivered = False

                    def read(self, size):
                        if not self.delivered:
                            self.delivered = True
                            return payload
                        return native.read(size)

                    def close(self):
                        self.closed = True
                        native.close()

                process.stdout = Stream()
                processes.append(process)
                streams.append(process.stdout)
                return process

            with self.subTest(kind=type(payload).__name__):
                try:
                    jobs, folder = run_batch(self.root, [_python_command('pass')],
                                             workers=1, cwd=self.root, runner=start)
                except (TypeError, ValueError) as error:
                    self.fail(f'nonbyte pipe payload escaped bounded capture: {type(error).__name__}')
                self.assertIn('output read failed', jobs[0].log_error or '')
                self.assertEqual(jobs[0].observed_bytes, 0)
                self.assertEqual(jobs[0].retained_bytes, 0)
                self.assertEqual(jobs[0].preview, '')
                self.assertTrue(streams[0].closed)
                self.assertIsNotNone(processes[0].poll())
                metadata = json.loads((folder / 'summary.json').read_text(encoding='utf-8'))
                self.assertFalse(metadata[0]['complete_output'])
                self.assertLessEqual((folder / 'summary.json').stat().st_size, parallel.RESPONSE_BYTES)
                self.assertNotIn('synthetic-nonbyte-payload', report(self.root, jobs, folder, workers=1, wall=0))
        self.assertEqual(invoked, [])

    def test_exact_chunk_bound_native_bytes_are_retained(self) -> None:
        command = _python_command(f'import os; os.write(1, b"x" * {parallel.CHUNK_BYTES})')
        jobs, folder = run_batch(self.root, [command], workers=1, cwd=self.root)
        self.assertEqual(jobs[0].returncode, 0)
        self.assertIsNone(jobs[0].log_error)
        self.assertEqual(jobs[0].observed_bytes, parallel.CHUNK_BYTES)
        self.assertEqual(jobs[0].retained_bytes, parallel.CHUNK_BYTES)
        self.assertEqual((folder / '001.log').read_bytes(), b'x' * parallel.CHUNK_BYTES)

    @unittest.skipIf(fsx.WINDOWS, 'portable adapter control with POSIX symlink fixture')
    def test_windows_directory_adapter_refuses_a_replaced_parent_before_output_write(self) -> None:
        outside = self.root / 'outside'
        outside.mkdir()
        create = parallel._create_log

        def replace(directory, name):
            if name == '001.log':
                folder = next((self.root / parallel.LOGS).iterdir())
                folder.rename(folder.with_name('moved'))
                folder.symlink_to(outside, target_is_directory=True)
            return create(directory, name)

        with mock.patch.object(fsx, 'open_dir', side_effect=lambda path: fsx.WindowsDirectory(str(path), os.lstat(path))), \
                mock.patch.object(parallel, '_create_log', side_effect=replace):
            jobs, _ = run_batch(self.root, ['echo output'], workers=1, cwd=self.root)
        self.assertEqual(jobs[0].returncode, 0)
        self.assertEqual(jobs[0].retained_bytes, 0)
        self.assertTrue(jobs[0].log_error)
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(fsx.WINDOWS, 'native Windows junction qualification')
    def test_native_windows_junction_log_parent_is_refused_before_execution(self) -> None:
        outside = self.root / 'outside'
        outside.mkdir()
        runtime = self.root / '.getzilla/runtime'
        runtime.mkdir(parents=True)
        linked = subprocess.run(['cmd', '/c', 'mklink', '/J', str(runtime / 'par'), str(outside)],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(linked.returncode, 0, 'controlled junction fixture could not be created')
        marker = self.root / 'must-not-run'
        with self.assertRaises(OSError):
            run_batch(self.root, [_python_command(f"open({str(marker)!r},'w').write('bad')")],
                      workers=1, cwd=self.root)
        self.assertFalse(marker.exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_large_combined_output_is_drained_and_quota_loss_is_reported(self) -> None:
        # Dropping reads after the quota would hang this real producer on a full pipe.
        script = "import os; os.write(1,b'HEAD'+b'x'*200000); os.write(2,b'y'*200000+b'TAIL'); exit(3)"
        command = _python_command(script)
        jobs, folder = run_batch(self.root, [command], workers=1, cwd=self.root, log_quota=8192)
        job = jobs[0]
        self.assertEqual(job.returncode, 3)
        self.assertEqual(job.observed_bytes, 400008)
        self.assertEqual(job.retained_bytes, 8192)
        self.assertEqual(job.dropped_bytes, 391816)
        self.assertTrue(job.truncated)
        data = (folder / '001.log').read_bytes()
        self.assertEqual(len(data), 8192)
        self.assertTrue(data.startswith(b'HEAD'))
        self.assertTrue(data.endswith(b'TAIL'))
        summary = json.loads((folder / 'summary.json').read_text())
        self.assertEqual(summary[0]['observed_bytes'], 400008)
        self.assertFalse(summary[0]['complete_output'])

    def test_preview_and_entire_response_are_utf8_byte_bounded(self) -> None:
        script = "import os; os.write(1,('€'*10000).encode()); exit(7)"
        jobs, folder = run_batch(self.root, [_python_command(script)],
                                 workers=1, cwd=self.root)
        self.assertLessEqual(len(jobs[0].preview.encode('utf-8')), 4096)
        self.assertNotIn('\ufffd', jobs[0].preview)
        text = report(self.root, jobs * 40, folder, workers=1, wall=1, show_all=True)
        self.assertLessEqual(len(text.encode('utf-8')), 32768)
        self.assertIn('response truncated', text)

    def test_quota_is_shared_across_jobs_and_metadata_envelope_is_bounded(self) -> None:
        command = _python_command("import os; os.write(1,b'x'*20000)")
        jobs, folder = run_batch(self.root, [command] * 10, workers=3, cwd=self.root, log_quota=8193)
        self.assertEqual(sum(job.retained_bytes for job in jobs), 8193)
        self.assertEqual(sum(job.dropped_bytes for job in jobs), 191807)
        self.assertLessEqual((folder / 'summary.json').stat().st_size, 32768)
        metadata = json.loads((folder / 'summary.json').read_text())
        self.assertTrue(metadata[-1]['metadata_truncated'])

    def test_credential_label_withholds_preview(self) -> None:
        jobs, folder = run_batch(self.root, ['echo password=synthetic-fixture; exit 1'], workers=1, cwd=self.root)
        text = report(self.root, jobs, folder, workers=1, wall=0)
        self.assertNotIn('synthetic-fixture', text)
        self.assertNotIn('synthetic-fixture', (folder / 'summary.json').read_text())
        self.assertIn('preview withheld', text)

    def test_report_does_not_reopen_logs_or_echo_command_secrets(self) -> None:
        command = "echo visible; password=do-not-print-command; exit 2"
        jobs, folder = run_batch(self.root, [command], workers=1, cwd=self.root)
        jobs[0].log.unlink()
        jobs[0].log.symlink_to('/does/not/exist')
        text = report(self.root, jobs, folder, workers=1, wall=0)
        self.assertIn('visible', text)
        self.assertNotIn('do-not-print-command', text)
        self.assertNotIn('do-not-print-command', (folder / 'summary.json').read_text())

    @unittest.skipIf(fsx.WINDOWS, 'POSIX symlink control; native junction control is separate')
    def test_symlink_log_parent_is_refused_before_execution(self) -> None:
        outside = self.root / 'outside'
        outside.mkdir()
        runtime = self.root / '.getzilla/runtime'
        runtime.mkdir(parents=True)
        (runtime / 'par').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            run_batch(self.root, ['touch marker'], workers=1, cwd=self.root)
        self.assertFalse((self.root / 'marker').exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_write_failure_still_drains_and_reports_missing_artifact(self) -> None:
        create = parallel._create_log

        def fail_log(directory, name):
            if name.endswith('.log'):
                raise OSError(28, 'synthetic disk full')
            return create(directory, name)

        command = _python_command("import os; os.write(1,b'x'*200000)")
        with mock.patch.object(parallel, '_create_log', side_effect=fail_log):
            jobs, folder = run_batch(self.root, [command], workers=1, cwd=self.root)
        self.assertEqual(jobs[0].returncode, 0)
        self.assertEqual(jobs[0].observed_bytes, 200000)
        self.assertEqual(jobs[0].retained_bytes, 0)
        self.assertEqual(jobs[0].dropped_bytes, 200000)
        self.assertIn('errno=28', jobs[0].log_error)
        self.assertIn('complete_output=false', report(self.root, jobs, folder, workers=1, wall=0))

    def test_timeout_kills_descendants_which_hold_the_output_pipe(self) -> None:
        script = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)']); time.sleep(20)"
        started = time.monotonic()
        jobs, _ = run_batch(self.root, [_python_command(script)],
                            workers=1, cwd=self.root, timeout=0.15)
        self.assertEqual(jobs[0].returncode, 124)
        self.assertLess(time.monotonic() - started, 3)

    @unittest.skipIf(fsx.WINDOWS, 'POSIX exec descriptor-closure control')
    def test_timeout_still_applies_after_both_output_descriptors_close(self) -> None:
        script = "import os,time; os.close(1); os.close(2); time.sleep(2)"
        jobs, _ = run_batch(self.root, ['exec ' + _python_command(script)],
                            workers=1, cwd=self.root, timeout=0.1)
        self.assertEqual(jobs[0].returncode, 124)
        self.assertEqual(jobs[0].observed_bytes, 0)
        self.assertIsNone(jobs[0].refused)
        self.assertIsNone(jobs[0].log_error)
        self.assertEqual(jobs[0].log.read_bytes(), b'')

    def test_eof_alive_deadline_stops_before_fallback_wait(self) -> None:
        # No scheduler or policy-preflight time participates in this oracle.
        now = [0.0]
        events = []
        eof = threading.Event()
        readers = []
        clock_calls = [0]

        class ClosedOutput(io.BytesIO):
            def read(self, size=-1):
                readers.append(threading.current_thread())
                return super().read(size)

            def close(self):
                super().close()
                eof.set()

        class Process:
            stdout = ClosedOutput(b'')
            returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout):
                events.append('wait')
                if self.returncode is None:
                    raise AssertionError('fallback wait reached a live process')
                return self.returncode

        def capture_clock():
            clock_calls[0] += 1
            if clock_calls[0] == 1:
                return 0.0  # Capture begins before the actual reader starts.
            self.assertTrue(eof.wait(1), 'closed reader must reach EOF')
            readers[0].join(1)
            self.assertFalse(readers[0].is_alive(), 'real reader must finish')
            # First loop stays before deadline; after EOF a second iteration
            # requires the producer-alive predicate, independently of scheduling.
            now[0] = 0.0 if clock_calls[0] == 2 else 0.1
            if clock_calls[0] > 5:
                raise AssertionError('capture deadline did not stop producer')
            return now[0]

        process = Process()

        def stop(selected, job):
            self.assertIs(selected, process)
            self.assertTrue(process.stdout.closed, 'EOF must precede stop')
            self.assertGreaterEqual(now[0], 0.1, 'stop must come from the expired capture deadline')
            self.assertNotIn('wait', events, 'deadline stop must precede fallback wait')
            events.append('stop')
            process.returncode = -9

        directory = fsx.open_dir(self.root)
        try:
            job = parallel.Job(0, 'inert-public-producer')
            with mock.patch.object(parallel.time, 'monotonic', side_effect=capture_clock), \
                 mock.patch.object(parallel, '_stop_process', side_effect=stop), \
                 mock.patch.object(fsx, 'owned_job', return_value=None):
                parallel._capture(job, directory, self.root, 64, 0.1, lambda *args, **kwargs: process)
        finally:
            fsx.close_dir(directory)
        self.assertEqual(job.returncode, 124)
        self.assertEqual(events, ['stop', 'stop', 'wait'])
        self.assertEqual(job.observed_bytes, 0)
        self.assertIsNone(job.log_error)
        self.assertEqual((self.root / '000.log').read_bytes(), b'')

    @unittest.skipIf(fsx.WINDOWS, 'POSIX SIGINT and process-group control')
    def test_main_thread_interrupt_stops_owned_group_before_returning(self) -> None:
        pidfile = self.root / 'owned-group.json'
        queued_marker = self.root / 'queued-command-ran'
        producer = ("import os,json,time; "
                    f"open({str(pidfile)!r},'w').write(json.dumps([os.getpid(),os.getpgrp()])); "
                    "time.sleep(20)")
        command = shlex.join([sys.executable, '-c', producer])
        queued = shlex.join(['touch', str(queued_marker)])
        wrapper = ("import sys; from pathlib import Path; "
                   f"sys.path.insert(0,{str(ROOT / '.getzilla')!r}); "
                   "from getzilla.parallel import run_batch; "
                   f"root=Path({str(self.root)!r}); "
                   f"run_batch(root,[{command!r},{queued!r}],workers=1,cwd=root)")
        parent = subprocess.Popen([sys.executable, '-c', wrapper], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, start_new_session=True)
        group = None
        try:
            deadline = time.monotonic() + 3
            while not pidfile.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(pidfile.exists(), 'producer did not start')
            pid, group = json.loads(pidfile.read_text())
            parent.send_signal(signal.SIGINT)
            try:
                parent.communicate(timeout=1.5)
            except subprocess.TimeoutExpired:
                self.fail('main cancellation waited for the uncancelled worker')
            self.assertFalse(queued_marker.exists(), 'a queued command ran after cancellation')
            # An orphan may briefly be a zombie until init reaps it. It must not run.
            status = Path(f'/proc/{pid}/stat')
            if status.exists():
                self.assertEqual(status.read_text().split()[2], 'Z')
        finally:
            for owned_group in (parent.pid, group):
                if owned_group is not None:
                    try:
                        os.killpg(owned_group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            parent.communicate(timeout=3)

    @unittest.skipIf(fsx.WINDOWS, 'POSIX retained-directory descriptor control')
    def test_replaced_log_directory_cannot_redirect_writes(self) -> None:
        outside = self.root / 'outside'
        outside.mkdir()
        create = parallel._create_log

        def replace_before_write(directory, name):
            if name == '001.log':
                folder = next((self.root / parallel.LOGS).iterdir())
                folder.rename(folder.with_name('moved'))
                folder.symlink_to(outside, target_is_directory=True)
            return create(directory, name)

        with mock.patch.object(parallel, '_create_log', side_effect=replace_before_write):
            jobs, folder = run_batch(self.root, ['echo own-output'], workers=1, cwd=self.root)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertIn('namespace changed', jobs[0].log_error)
        self.assertIn('own-output', report(self.root, jobs, folder, workers=1, wall=0, show_all=True))


class SerialTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        _snapshot(self.root, 24)

    def advice(self, command: str):
        found = serial_batch(self.root, command, self.root)
        return None if found is None else (found.kind, found.advice)

    def test_chains_of_alike_test_commands_become_one_parallel_batch(self) -> None:
        kind, advice = self.advice('php tests/php/test_a.php && php tests/php/test_b.php && php tests/php/test_c.php')
        self.assertEqual(kind, 'chain')
        self.assertTrue(advice.startswith('getzilla par -j 24 -- '))
        self.assertIn("'php tests/php/test_b.php'", advice)
        self.assertEqual(self.advice('python3 scripts/check_a.py; python3 scripts/check_b.py; python3 scripts/check_c.py')[0], 'chain')

    def test_dependent_or_mixed_chains_are_left_alone(self) -> None:
        for command in ('python3 build.py && python3 package.py && python3 deploy.py',
                        'php tests/a_test.php && php tests/b_test.php',
                        'npm install && npm test && npm run lint',
                        'cd app && php tests/a_test.php && php tests/b_test.php && php tests/c_test.php',
                        'php tests/a_test.php || php tests/b_test.php || php tests/c_test.php'):
            with self.subTest(command=command):
                self.assertIsNone(self.advice(command))

    def test_loops_and_find_exec(self) -> None:
        kind, advice = self.advice('for f in tests/php/test_*.php; do php "$f"; done')
        self.assertEqual(kind, 'loop')
        self.assertEqual(advice, "getzilla par -j 24 --each 'tests/php/test_*.php' -- 'php {}'")
        kind, advice = self.advice('for f in $(ls tests); do bash "$f"; done')
        self.assertEqual(kind, 'loop')
        self.assertIn('--each <glob>', advice)
        self.assertIsNone(self.advice('for f in a b c; do echo "$f"; done'))
        kind, advice = self.advice(r"find tests -name '*_test.php' -exec php {} \;")
        self.assertEqual((kind, advice), ('find-exec', "find tests -name '*_test.php' -print0 | xargs -0 -P 24 -n 1 php"))

    def test_test_runners_forced_into_one_process(self) -> None:
        self.assertEqual(self.advice('npx jest --runInBand')[0], 'runner')
        self.assertIn('-p 24', self.advice('go test -p 1 ./...')[1])
        self.assertIn('--test-threads=1', self.advice('cargo test -- --test-threads=1')[1])
        self.assertIsNone(self.advice('pytest tests/test_one.py'))
        self.assertIsNone(self.advice('python3 -m pytest -n 8 tests'))
        if XDIST:
            self.assertIn('-n 24', self.advice('python3 -m pytest -q tests')[1])
        (self.root / 'vendor' / 'bin').mkdir(parents=True)
        (self.root / 'vendor' / 'bin' / 'paratest').write_text('', encoding='utf-8')
        self.assertIn('paratest -p 24', self.advice('vendor/bin/phpunit tests')[1])

    def test_explicit_serial_small_hosts_and_par_itself_pass(self) -> None:
        chain = 'php tests/test_a.php && php tests/test_b.php && php tests/test_c.php'
        self.assertIsNone(self.advice(f'{parallel.SERIAL} {chain}'))
        self.assertIsNone(self.advice("getzilla par -- 'php tests/test_a.php'"))
        _snapshot(self.root, 2)
        self.assertIsNone(self.advice(chain))

    def test_refusal_names_the_command_and_the_escape_hatch(self) -> None:
        message = serial_refusal(self.root, 'php tests/test_a.php && php tests/test_b.php && php tests/test_c.php', self.root)
        self.assertIn('getzilla par -j 24', message)
        self.assertIn(parallel.SERIAL, message)
        stats = json.loads((self.root / parallel.STATS).read_text(encoding='utf-8'))
        self.assertEqual(stats['chain'], 1)


class HookTests(unittest.TestCase):
    def test_pre_tool_use_refuses_a_serial_batch_and_session_start_reports_capacity(self) -> None:
        with project_copy(git=True) as root:
            _snapshot(root, 12)
            chain = 'php tests/php/test_a.php && php tests/php/test_b.php && php tests/php/test_c.php'
            code, data, stderr = run_hook(root, 'pre_tool_use.py', {
                'cwd': str(root), 'session_id': 'par', 'hook_event_name': 'PreToolUse', 'tool_name': 'exec_command',
                'tool_input': {'cmd': chain, 'workdir': str(root)}})
            self.assertEqual(code, 0, stderr)
            self.assertEqual(data['decision'], 'deny', data)
            self.assertIn('getzilla par -j 12', data['reason'])
            code, data, _ = run_hook(root, 'pre_tool_use.py', {
                'cwd': str(root), 'session_id': 'par', 'hook_event_name': 'PreToolUse', 'tool_name': 'exec_command',
                'tool_input': {'cmd': f'{parallel.SERIAL} {chain}', 'workdir': str(root)}})
            self.assertEqual(data['decision'], 'allow', data)
            code, data, stderr = run_hook(root, 'session_start.py', {'cwd': str(root), 'session_id': 'par',
                                                                     'hook_event_name': 'SessionStart'})
            self.assertEqual(code, 0, stderr)
            self.assertIn('Capacity: 12 worker processes', data['hookSpecificOutput']['additionalContext'])


if __name__ == '__main__':
    unittest.main()
