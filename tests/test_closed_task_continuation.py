"""Exercise implicit continuation and explicit replacement through the user entry points."""
import json
import subprocess
import sys
import unittest

from tests._support import PROJECT, project_copy, run_hook


class ClosedTaskContinuationTests(unittest.TestCase):
    def test_qualified_continuation_after_cancellation_requires_full_new_scope(self):
        with project_copy(git=True) as root:
            def cli(*args):
                return subprocess.run([sys.executable, str(PROJECT / 'scripts/getzilla_route.py'),
                                       '--session', 's1', '--json', *args], cwd=root,
                                      text=True, capture_output=True, timeout=20)

            scope = 'Fix API authentication and database migration. Preserve all acceptance criteria.'
            started = cli('--new-task', scope)
            self.assertEqual(started.returncode, 0, started.stderr)
            original = json.loads(started.stdout)
            cancelled = cli('--cancel')
            self.assertEqual(cancelled.returncode, 0, cancelled.stderr)
            terminal = json.loads(cancelled.stdout)
            record = root / '.getzilla/runtime/routes' / (terminal['route_id'] + '.json')
            before = record.read_bytes()

            code, data, err = run_hook(root, 'user_prompt_submit.py', {
                'cwd': str(root), 'session_id': 's1',
                'prompt': 'Продолжай работу по текущему ТЗ до полного завершения.'})
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(cli('--show').stdout), terminal)
            self.assertIn('--new-task', data['hookSpecificOutput']['additionalContext'])
            refused = cli('Continue the previous task.')
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('--new-task', refused.stderr)

            fresh = cli('--new-task', 'Resume implementation: ' + scope)
            self.assertEqual(fresh.returncode, 0, fresh.stderr)
            successor = json.loads(fresh.stdout)
            self.assertNotEqual(successor['route_id'], terminal['route_id'])
            self.assertEqual(successor['risk'], original['risk'])
            self.assertEqual(record.read_bytes(), before)

    def test_closed_task_reference_and_new_requests(self):
        cases = [('продолжай задачу', True), ('continue the task', True),
                 ('продолжи список покупок на завтра', False), ('continue the README with a FAQ', False)]
        for prompt, refers_to_task in cases:
            with self.subTest(prompt=prompt), project_copy(git=True) as root:
                def cli(*args):
                    return subprocess.run([sys.executable, str(PROJECT / 'scripts/getzilla_route.py'),
                                           '--session', 's1', '--json', *args], cwd=root,
                                          text=True, capture_output=True, timeout=20)

                original = cli('--new-task', 'Document the API.')
                self.assertEqual(original.returncode, 0, original.stderr)
                cancelled = cli('--cancel')
                self.assertEqual(cancelled.returncode, 0, cancelled.stderr)
                closed_id = json.loads(cancelled.stdout)['route_id']
                result = cli(prompt)
                if refers_to_task:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('--new-task', result.stderr)
                    self.assertEqual(json.loads(cli('--show').stdout)['route_id'], closed_id)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    successor = json.loads(result.stdout)
                    self.assertNotEqual(successor['route_id'], closed_id)
                    self.assertEqual(successor['task'], prompt)
