"""Outcome-based loop detection is advisory and cannot replace authorization (#153)."""
from __future__ import annotations

import json
import io
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import session_progress as progress
from getzilla.state import bind_session, set_active_route
from tests import _support
from tests._support import project_copy, run_hook

SOURCE = 'a' * 64
T0 = 1_800_000_000


class RuntimeFixtureTests(unittest.TestCase):
    def test_project_copy_excludes_runtime_before_descending_into_nested_temp(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'
            runtime = source / '.getzilla/runtime'
            nested_temp = runtime / 'tmp'
            nested_temp.mkdir(parents=True)
            (runtime / '.gitkeep').write_text('')
            (runtime / 'private-state').mkdir()
            (runtime / 'private-state/secret').write_text('must not be copied')
            (source / '.getzilla/payload.py').write_text('value = 1\n')
            copytree = shutil.copytree

            def bounded_copy(src, dst, *args, **kwargs):
                # Fail promptly on the old recursive copy, rather than exhausting disk.
                if Path(src) != runtime and Path(src).is_relative_to(runtime):
                    self.fail('project fixture descended into runtime state')
                return copytree(src, dst, *args, **kwargs)

            with patch.object(_support, 'PROJECT', source), patch.object(tempfile, 'tempdir', str(nested_temp)), \
                 patch.object(shutil, 'copytree', side_effect=bounded_copy):
                with project_copy() as fixture:
                    self.assertEqual((fixture / '.getzilla/payload.py').read_text(), 'value = 1\n')
                    self.assertEqual([path.name for path in (fixture / '.getzilla/runtime').iterdir()], ['.gitkeep'])


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='getzilla-progress-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / '.getzilla/runtime').mkdir(parents=True)
        bind_session('session-one')
        self.addCleanup(bind_session, None)
        self.route = {'route_id': 'route-one', 'change_id': 'task-one', 'session_id': 'session-one'}
        set_active_route(self.root, self.route)
        self.scope = progress.scope_id(self.root, 'session-one')
        self.inputs = {'command': 'python3 -m unittest tests.test_example'}
        self.response = {'exit_code': 1, 'output': 'FAIL test_example: expected 2, got 1'}

    def observe(self, number=1, **overrides):
        values = {'root': self.root, 'scope': self.scope, 'inputs': self.inputs, 'cwd': self.root,
                  'response': self.response, 'source': SOURCE, 'event_id': f'call-{number}', 'now': T0 + number}
        values.update(overrides)
        return progress.observe(**values)

    def refuse(self, **overrides):
        values = {'root': self.root, 'scope': self.scope, 'inputs': self.inputs, 'cwd': self.root,
                  'source': SOURCE, 'now': T0 + 10}
        values.update(overrides)
        return progress.refusal(**values)

    def rows(self, **overrides):
        return progress.inspect(self.root, self.scope, now=overrides.get('now', T0 + 10))['loops']

    def trip(self):
        for number in range(1, 4):
            self.observe(number)

    def test_third_failure_warns_and_fourth_unchanged_attempt_is_refused(self):
        for number in (1, 2):
            self.assertIsNone(self.refuse())
            self.assertEqual(self.observe(number), '')
        self.assertIn('3 identical', self.observe(3))
        self.assertIn('progress-inspect', self.refuse())
        self.assertEqual(self.rows()[0]['count'], 3)

    def test_source_success_and_different_error_end_only_the_matching_streak(self):
        self.trip()
        self.assertIsNone(self.refuse(source='b' * 64))
        self.observe(4, source='b' * 64)
        self.assertEqual(self.rows()[0]['count'], 1)
        self.observe(5, source='b' * 64, response={'exit_code': 1, 'stderr': 'different assertion'})
        self.assertEqual(self.rows()[0]['count'], 1)
        self.observe(6, response={'exit_code': 0, 'output': 'failed is just a string'})
        self.assertEqual(self.rows()[0]['count'], 0)
        self.assertIsNone(self.refuse())

    def test_pending_unknown_malformed_and_conflicting_results_do_not_count(self):
        for response in ({}, {'output': 'ERROR'}, {'is_error': True}, {'exit_code': True},
                         {'exit_code': '1'}, {'exit_code': 1, 'exitCode': 0},
                         {'exit_code': 1, 'status': 'running'}, {'exit_code': 1, 'session_id': 123},
                         {'exit_code': 1, 'interrupted': True}, {'exit_code': 1, 'timed_out': True},
                         {'exit_code': 1, 'output': ['not text']}, {'exit_code': 1, 'status': []}):
            with self.subTest(response=response):
                self.assertEqual(self.observe(response=response), '')
                self.assertEqual(self.rows(), [])

    def test_exit_code_aliases_are_explicit_completed_results(self):
        for number, key in enumerate(('exit_code', 'exitCode', 'returncode'), 1):
            self.observe(number, response={key: 2, 'stderr': 'same compiler failure'})
        self.assertEqual(self.rows()[0]['count'], 3)

    def test_only_recognized_single_check_commands_are_eligible(self):
        for command in ('rg missing .', 'git diff --exit-code', 'cat missing', 'sleep 1',
                        'python3 -c pass', 'npm install', 'pytest; echo fail', 'cd app && pytest'):
            with self.subTest(command=command):
                for number in range(3):
                    self.observe(number, inputs={'command': command})
                self.assertIsNone(self.refuse(inputs={'command': command}))
        self.assertEqual(self.rows(), [])
        for number, command in enumerate(('pytest tests', 'npm test', 'npm run lint', 'cargo check',
                                           'go test ./...', 'python -m ruff check .')):
            self.observe(number, inputs={'command': command})
        self.assertEqual(len(self.rows()), 6)

    def test_replayed_event_does_not_inflate_count_or_clear_later_failure(self):
        self.observe(0, response={'exit_code': 0})
        self.trip()
        self.observe(3)
        self.observe(0, response={'exit_code': 0})
        self.assertEqual(self.rows()[0]['count'], 3)

    def test_scope_isolates_sessions_tasks_agents_generations_and_workspaces(self):
        self.trip()
        self.assertIsNone(progress.scope_id(self.root, 'manual'))
        self.assertIsNone(progress.scope_id(self.root, 'unmatched-session'))
        for agent, generation in (('child', None), ('child', 'generation-one'), ('child', 'generation-two')):
            scope = progress.scope_id(self.root, 'session-one', agent, generation)
            self.assertNotEqual(scope, self.scope)
            self.assertIsNone(self.refuse(scope=scope))
        self.assertIsNone(self.refuse(cwd=self.root / 'other'))
        self.assertIsNone(self.refuse(inputs={'command': 'python3 -m unittest tests.other'}))
        set_active_route(self.root, {**self.route, 'route_id': 'route-two'})
        self.assertEqual(progress.scope_id(self.root, 'session-one'), self.scope)
        set_active_route(self.root, {**self.route, 'change_id': 'task-two'})
        self.assertNotEqual(progress.scope_id(self.root, 'session-one'), self.scope)

    def test_unknown_source_warns_without_enforcing_and_expiry_is_not_progress(self):
        for number in range(1, 4):
            warning = self.observe(number, source=None)
        self.assertIn('3 identical', warning)
        self.assertIsNone(self.refuse(source=None))
        self.assertEqual(self.rows()[0]['status'], 'warning')
        self.assertEqual(self.rows(now=T0 + progress.TTL + 20)[0]['status'], 'expired')
        self.assertIsNone(self.refuse(now=T0 + progress.TTL + 20))

    def test_recovery_is_revision_bound_one_shot_and_cannot_reuse_evidence(self):
        self.trip()
        row = self.rows()[0]
        with self.assertRaises(ValueError):
            progress.recover(self.root, self.scope, row['loop_id'], 'b' * 64, 'new-evidence', 'inspected compiler config', now=T0 + 5)
        result = progress.recover(self.root, self.scope, row['loop_id'], row['revision'],
                                  'new-evidence', 'inspected compiler config', now=T0 + 5)
        self.assertTrue(result['retry_available'])
        self.assertIsNone(self.refuse())
        self.assertIsNotNone(self.refuse())
        self.observe(11)
        current = self.rows()[0]
        with self.assertRaises(ValueError):
            progress.recover(self.root, self.scope, current['loop_id'], current['revision'],
                             'new-evidence', 'inspected compiler config', now=T0 + 12)
        with self.assertRaises(ValueError):
            progress.recover(self.root, self.scope, row['loop_id'], row['revision'],
                             'changed-hypothesis', 'check the test fixture instead', now=T0 + 12)
        self.assertEqual(current['count'], 4)

    def test_parallel_completed_events_keep_counts(self):
        with ThreadPoolExecutor(max_workers=7) as pool:
            list(pool.map(self.observe, range(1, 15)))
        self.assertEqual(self.rows(now=T0 + 20)[0]['count'], 14)

    def test_capacity_keeps_blocked_records_and_serialization_contains_no_private_text(self):
        self.inputs = {'command': 'pytest --secret=PRIVATE-COMMAND'}
        self.response['output'] = 'PRIVATE-OUTPUT'
        self.trip()
        with patch.object(progress, 'MAX_RECORDS', 4):
            for number in range(10, 30):
                self.observe(number, inputs={'command': f'pytest tests/test_{number}.py'})
        self.assertIsNotNone(self.refuse(now=T0 + 40))
        raw = (self.root / progress.STATE).read_text()
        self.assertNotIn('PRIVATE', raw)
        self.assertNotIn('session-one', raw)
        self.assertLessEqual(len(json.loads(raw)['records']), 4)
        self.assertLess(len(raw.encode()), progress.MAX_BYTES)

    def test_corrupt_oversized_and_nonregular_state_are_rejected_without_mutation(self):
        path = self.root / progress.STATE
        for raw in ('{bad', '{"version":1,"version":1,"records":{}}', 'x' * (progress.MAX_BYTES + 1)):
            path.write_text(raw)
            with self.assertRaises((ValueError, OSError)):
                self.observe()
            self.assertEqual(path.read_text(), raw)

    @unittest.skipIf(os.name == 'nt', 'POSIX link/FIFO adversarial fixture')
    def test_unsafe_parents_leaves_locks_and_hardlinks_do_not_touch_outside_file(self):
        outside = self.root / 'outside'
        outside.write_text('PRIVATE-OUTSIDE')
        for relative in (progress.STATE, progress.LOCK):
            target = self.root / relative
            target.unlink(missing_ok=True)  # the previous storage probe created its stable lock
            target.symlink_to(outside)
            with self.assertRaises((ValueError, OSError)):
                self.observe()
            target.unlink()
            os.link(outside, target)
            with self.assertRaises((ValueError, OSError)):
                self.observe()
            target.unlink()
            os.mkfifo(target)
            with self.assertRaises((ValueError, OSError)):
                self.observe()
            target.unlink()
        runtime = self.root / '.getzilla/runtime'
        runtime.rename(self.root / 'moved-runtime')
        runtime.symlink_to(self.root / 'moved-runtime', target_is_directory=True)
        with self.assertRaises(OSError):
            self.observe()
        self.assertEqual(outside.read_text(), 'PRIVATE-OUTSIDE')

    def test_failed_atomic_publication_preserves_previous_state(self):
        self.observe(1)
        before = (self.root / progress.STATE).read_bytes()
        with patch.object(progress.fsx, 'replace_at', side_effect=OSError('PRIVATE-FAILURE')):
            with self.assertRaises(OSError):
                self.observe(2)
        self.assertEqual((self.root / progress.STATE).read_bytes(), before)
        self.assertFalse(list((self.root / '.getzilla/runtime').glob('.session-progress-*.tmp')))

    def test_busy_lock_fails_within_bound_and_inspection_does_not_rewrite_state(self):
        self.trip()
        before = (self.root / progress.STATE).read_bytes()
        self.rows()
        self.assertEqual((self.root / progress.STATE).read_bytes(), before)
        with patch.object(progress.fsx, 'lock_file', side_effect=BlockingIOError), patch.object(progress, 'LOCK_TIMEOUT', 0):
            with self.assertRaises(TimeoutError):
                self.observe(4)
        self.assertEqual((self.root / progress.STATE).read_bytes(), before)

    def test_unrelated_success_does_not_reset_failure_and_lazy_fingerprint_is_bounded(self):
        self.trip()
        self.observe(4, inputs={'command': 'pytest tests/other.py'}, response={'exit_code': 0})
        with patch.object(progress, 'tree_fingerprint', return_value=SOURCE) as fingerprint, patch.object(progress, 'git_head', return_value='a' * 40):
            self.assertIsNone(self.refuse(inputs={'command': 'pytest tests/other.py'}, source=None))
            fingerprint.assert_not_called()
            self.assertIsNotNone(self.refuse(source=None))
            fingerprint.assert_called_once_with(self.root)


class ProgressHookTests(unittest.TestCase):
    def test_observer_exception_cannot_skip_policy_or_post_hook_receipt_invalidation(self):
        from getzilla.receipts import get_receipt, write_receipt
        with project_copy(git=True) as root:
            set_active_route(root, {'route_id': 'progress-errors', 'session_id': 'progress-errors'})
            payload = {'cwd': str(root), 'session_id': 'progress-errors', 'tool_name': 'Bash',
                       'tool_input': {'command': 'python3 -m unittest tests.example'}, 'tool_response': {'exit_code': 1}}
            with patch.object(sys, 'path', [str(root / '.grok/hooks'), *sys.path]):
                pre = runpy.run_path(str(root / '.grok/hooks/pre_tool_use.py'))
                post = runpy.run_path(str(root / '.grok/hooks/post_tool_use.py'))
            for command, decision in (('python3 -m unittest tests.example', 'allow'), ('git push origin main', 'deny')):
                results, stderr = [], io.StringIO()
                with patch.object(progress, 'refusal', side_effect=RuntimeError('PRIVATE-OBSERVER')), \
                     patch.object(sys, 'stderr', stderr), \
                     patch.dict(pre['main'].__globals__, {'read_payload': lambda: {**payload, 'tool_input': {'command': command}}, 'emit': results.append}):
                    pre['main']()
                self.assertEqual(results[-1]['decision'], decision, results[-1])
                self.assertNotIn('PRIVATE', str(results) + stderr.getvalue())
            run_hook(root, 'post_tool_use.py', payload)
            bind_session('progress-errors')
            self.addCleanup(bind_session, None)
            write_receipt(root, 'verification', 'pass')
            (root / 'example.py').write_text('changed = True\n')
            results = []
            with patch.object(progress, 'observe', side_effect=RuntimeError('PRIVATE-OBSERVER')), \
                 patch.dict(post['main'].__globals__, {'read_payload': lambda: payload, 'emit': results.append}):
                post['main']()
            self.assertTrue(get_receipt(root, 'progress-errors', 'verification')['stale'])
            self.assertIn('unavailable', str(results))
            self.assertNotIn('PRIVATE', str(results))

    def test_without_git_repeated_failures_warn_but_do_not_stop_source_edits(self):
        # Runtime-backed reviewer scratch may itself be inside another Git repository.
        with project_copy() as root, patch.dict(os.environ, {'GIT_CEILING_DIRECTORIES': str(root.parent)}):
            set_active_route(root, {'route_id': 'no-git', 'session_id': 'no-git'})
            payload = {'cwd': str(root), 'session_id': 'no-git', 'tool_name': 'Bash',
                       'tool_input': {'command': 'python3 -m unittest tests.example'}, 'tool_response': {'exit_code': 1}}
            for number in range(4):
                self.assertEqual(run_hook(root, 'pre_tool_use.py', payload)[1]['decision'], 'allow')
                response = run_hook(root, 'post_tool_use.py', {**payload, 'tool_use_id': str(number)})[1]
            self.assertIn('warning only', response['hookSpecificOutput']['additionalContext'])

    def test_real_hooks_stop_blind_retry_then_allow_changed_source_and_keep_policy(self):
        with project_copy(git=True) as root:
            set_active_route(root, {'route_id': 'progress-hook', 'session_id': 'progress-hook', 'change_id': 'progress-task'})
            payload = {'cwd': str(root), 'session_id': 'progress-hook', 'tool_name': 'exec_command',
                       'tool_input': {'cmd': 'python3 -m unittest tests.example', 'workdir': str(root)},
                       'tool_response': {'exit_code': 1, 'output': 'same assertion'}}
            for number in range(1, 4):
                self.assertEqual(run_hook(root, 'pre_tool_use.py', payload)[1]['decision'], 'allow')
                code, response, stderr = run_hook(root, 'post_tool_use.py', {**payload, 'tool_use_id': str(number)})
                self.assertEqual(code, 0, stderr)
            self.assertIn('3 identical', response['hookSpecificOutput']['additionalContext'])
            self.assertEqual(run_hook(root, 'pre_tool_use.py', payload)[1]['decision'], 'deny')
            (root / 'example.py').write_text('fixed = True\n')
            self.assertEqual(run_hook(root, 'pre_tool_use.py', payload)[1]['decision'], 'allow')
            (root / progress.STATE).write_text('{broken')
            self.assertEqual(run_hook(root, 'pre_tool_use.py', payload)[1]['decision'], 'allow')
            protected = {**payload, 'tool_input': {'cmd': 'git push origin main'}}
            self.assertEqual(run_hook(root, 'pre_tool_use.py', protected)[1]['decision'], 'deny')

    def test_cli_inspection_and_recovery_share_hook_scope_and_hide_invalid_arguments(self):
        with project_copy(git=True) as root:
            set_active_route(root, {'route_id': 'cli-loop', 'session_id': 'cli-loop'})
            scope = progress.scope_id(root, 'cli-loop')
            for number in range(1, 4):
                progress.observe(root, scope, {'command': 'pytest'}, root, {'exit_code': 1}, SOURCE,
                                 event_id=str(number))
            command = [sys.executable, str(ROOT / 'scripts/getzilla_agent.py'), '--root', str(root)]
            result = subprocess.run([*command, 'progress-inspect', '--session-id', 'cli-loop'], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            row = json.loads(result.stdout)['loops'][0]
            retry = subprocess.run([*command, 'progress-recover', '--session-id', 'cli-loop', '--loop-id', row['loop_id'],
                                    '--revision', row['revision'], '--reason', 'changed-hypothesis',
                                    '--evidence', 'PRIVATE-DIAGNOSIS'], text=True, capture_output=True)
            self.assertEqual(retry.returncode, 0, retry.stderr)
            self.assertTrue(json.loads(retry.stdout)['retry_available'])
            self.assertNotIn('PRIVATE', (root / progress.STATE).read_text())
            invalid = subprocess.run([*command, 'progress-recover', '--PRIVATE-MARKER'], text=True, capture_output=True)
            self.assertEqual(invalid.returncode, 2)
            self.assertNotIn('PRIVATE', invalid.stdout + invalid.stderr)
