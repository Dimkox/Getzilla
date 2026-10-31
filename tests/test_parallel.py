"""Independent heavy work runs on every verified CPU; serial batches are refused with the parallel command."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import parallel  # noqa: E402
from getzilla.parallel import capacity, expand_each, report, run_batch, serial_batch, serial_refusal  # noqa: E402
from tests._support import project_copy, run_hook  # noqa: E402

XDIST = importlib.util.find_spec('xdist') is not None


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
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
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
