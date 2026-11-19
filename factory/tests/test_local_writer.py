"""Real child process and Git evidence for the local writer boundary."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from getzilla_factory.execution_contracts import TaskPacketV1
from test_execution_contracts import valid_packet


@unittest.skipUnless(sys.platform == 'linux', 'local writer currently supports Linux')
class LocalWriterTests(unittest.TestCase):
    def setUp(self):
        runtime = Path(__file__).resolve().parents[2] / '.getzilla/runtime'
        runtime.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=runtime)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Local fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.repo / 'answer.py').write_text('def answer():\n    return 0\n')
        (self.repo / 'check.py').write_text('from answer import answer\nassert answer() == 42\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'input')
        self.head = self.git('rev-parse', 'HEAD').strip()
        source = valid_packet()
        source['authority']['exact_base_sha'] = self.head
        source['authority']['exact_head_sha'] = self.head
        source['capability_policy']['allowed_paths'] = ['answer.py']
        source['limits']['wall_seconds'] = 390
        self.packet = TaskPacketV1.from_dict(source)
        self.writer = self.root / 'writer.py'
        self.writer.write_text(
            'import json,sys\nfrom pathlib import Path\n'
            'task=json.load(sys.stdin)\nassert task["packet"]["task_id"] == "task-001"\n'
            'assert task["prompt"] == "Return 42"\n'
            'Path("answer.py").write_text("def answer():\\n    return 42\\n")\n'
        )

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo, text=True, stderr=subprocess.PIPE)

    def runner(self):
        spec = importlib.util.find_spec('getzilla_factory.local_writer')
        self.assertIsNotNone(spec, 'Factory has no real local writer runner')
        from getzilla_factory.local_writer import LocalWriter
        return LocalWriter(self.repo, self.root / 'runs', (sys.executable, str(self.writer)),
                           ((sys.executable, '-B', 'check.py'),))

    def test_writer_changes_only_isolated_worktree_and_retains_tested_patch(self):
        result = self.runner().run(self.packet, 'Return 42')
        self.assertEqual(result.status, 'checks_passed')
        self.assertEqual(result.packet_digest, self.packet.packet_digest)
        self.assertEqual(result.input_head_sha, self.head)
        self.assertNotEqual(result.result_head_sha, self.head)
        self.assertIn(b'+    return 42', result.patch.read_bytes())
        self.assertIn('return 0', (self.repo / 'answer.py').read_text())
        self.assertEqual(self.git('status', '--porcelain'), '')
        saved = json.loads(result.report.read_text())
        self.assertEqual(saved['checks'][0]['returncode'], 0)
        self.assertEqual(saved['workspace_snapshot']['result_head_sha'], result.result_head_sha)
        self.assertEqual(saved['qualification'], 'review_required')

    def test_failing_checks_are_retained_and_never_reported_as_success(self):
        self.writer.write_text(self.writer.read_text().replace('return 42', 'return 41'))
        result = self.runner().run(self.packet, 'Return 42')
        self.assertEqual(result.status, 'checks_failed')
        self.assertNotEqual(json.loads(result.report.read_text())['checks'][0]['returncode'], 0)
        self.assertEqual(self.git('rev-parse', 'HEAD').strip(), self.head)

    def test_same_task_run_is_not_executed_twice(self):
        runner = self.runner()
        first = runner.run(self.packet, 'Return 42')
        second = runner.run(self.packet, 'Return 42')
        self.assertEqual(first.result_head_sha, second.result_head_sha)
        self.assertEqual(first.report, second.report)

    def test_changed_verification_command_cannot_reuse_previous_success(self):
        first = self.runner()
        first.run(self.packet, 'Return 42')
        from getzilla_factory.local_writer import LocalWriter
        different = LocalWriter(self.repo, self.root / 'runs', first.command,
                                ((sys.executable, '-B', 'other-check.py'),))
        with self.assertRaisesRegex(ValueError, 'input'):
            different.run(self.packet, 'Return 42')

    def test_native_child_port_boundary_and_cached_identity(self):
        import socket
        from getzilla_factory.local_writer import LocalWriter
        listeners = [socket.socket() for _ in range(2)]
        for listener in listeners:
            listener.bind(('127.0.0.1', 0))
            listener.listen(2)
            self.addCleanup(listener.close)
        proxy, backend = [listener.getsockname()[1] for listener in listeners]
        self.writer.write_text(self.writer.read_text() +
                               'import socket,errno\n'
                               f's=socket.socket();s.settimeout(2);assert s.connect_ex(("127.0.0.1",{proxy}))==0;s.close()\n'
                               f's=socket.socket();s.settimeout(2);assert s.connect_ex(("127.0.0.1",{backend}))==errno.EACCES;s.close()\n')
        ordinary = self.runner()
        restricted = LocalWriter(self.repo, self.root / 'runs', ordinary.command,
                                 ordinary.checks, tcp_connect_ports=(proxy,))
        self.assertEqual(restricted.run(self.packet, 'Return 42').status, 'checks_passed')
        changed = LocalWriter(self.repo, self.root / 'runs', ordinary.command,
                              ordinary.checks, tcp_connect_ports=(backend,))
        with self.assertRaisesRegex(ValueError, 'input'):
            changed.run(self.packet, 'Return 42')

    def test_timeout_stops_term_resistant_descendant_and_preserves_partial_work(self):
        import os
        import signal
        import time
        pid_file = self.root / 'owned-child.pid'
        child_code = ('import os,signal,time;from pathlib import Path;'
                      'signal.signal(signal.SIGTERM,signal.SIG_IGN);'
                      f'Path({str(pid_file)!r}).write_text(str(os.getpid()));time.sleep(30)')
        self.writer.write_text(
            'import subprocess,sys,time\nfrom pathlib import Path\n'
            'Path("answer.py").write_text("def answer():\\n    return 41\\n")\n'
            f'subprocess.Popen([sys.executable,"-c",{child_code!r}])\n'
            'time.sleep(30)\n')
        packet = self.packet.to_dict()
        packet.pop('packet_digest')
        packet['limits']['wall_seconds'] = 4
        for stage in packet['plan']['stages']:
            stage['wall_seconds'] = 1
        self.packet = TaskPacketV1.from_dict(packet)
        from unittest.mock import patch
        real_killpg = os.killpg
        owned_signals = []
        def signal_owned_group(pgid, number):
            # A live or zombie leader must still be our waitable child before
            # either destructive signal. WNOWAIT deliberately does not reap it.
            os.waitid(os.P_PID, pgid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            owned_signals.append(number)
            return real_killpg(pgid, number)
        try:
            with patch('getzilla_factory.local_writer.os.killpg', side_effect=signal_owned_group):
                result = self.runner().run(self.packet, 'Return 42')
            self.assertEqual(result.status, 'writer_failed')
            self.assertEqual(owned_signals, [signal.SIGTERM, signal.SIGKILL])
            self.assertIn(b'return 41', result.patch.read_bytes())
            pid = int(pid_file.read_text())
            def stopped():
                try:
                    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] == 'Z'
                except FileNotFoundError:
                    return True
            deadline = time.monotonic() + 1
            while not stopped() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(stopped(), 'owned descendant remained live after task timeout')
            self.assertIn('return 0', (self.repo / 'answer.py').read_text())
        finally:
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_out_of_scope_change_is_refused(self):
        self.writer.write_text(self.writer.read_text() + 'Path("outside.py").write_text("bad")\n')
        result = self.runner().run(self.packet, 'Return 42')
        self.assertEqual(result.status, 'scope_violation')
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_cli_runs_a_packet_without_a_server_or_credentials(self):
        from getzilla_factory.cli import main
        packet = self.root / 'packet.json'
        packet.write_text(json.dumps(self.packet.to_dict(include_digest=False)))
        prompt = self.root / 'prompt.txt'
        prompt.write_text('Return 42')
        try:
            code = main(['run-local', '--packet', str(packet), '--prompt-file', str(prompt),
                         '--repository', str(self.repo), '--runtime', str(self.root / 'cli-runs'),
                         '--writer-command', json.dumps([sys.executable, str(self.writer)]),
                         '--check-command', json.dumps([sys.executable, '-B', 'check.py'])])
        except SystemExit as exc:
            self.fail('Factory CLI has no working local runner: ' + str(exc.code))
        self.assertEqual(code, 0)
        self.assertEqual(self.git('status', '--porcelain'), '')


if __name__ == '__main__':
    unittest.main()
