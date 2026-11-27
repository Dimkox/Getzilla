"""Resume a long-running task through the same prompt hook used by an agent."""
import json
import unittest

from tests._support import project_copy, run_hook


class LongTaskContinuationTests(unittest.TestCase):
    def test_long_original_keeps_recent_scope_visible_on_resume(self):
        objective = 'Update the PDF catalogue, cart and guest checkout.'
        scope = objective + '\n' + ('Сверить данные модели. ' * 600)
        early = 'Retain the cart acceptance checks. ' + 'Проверка. ' * 350
        amendment = 'Use the sixth corrected drawing for the guest catalogue.'
        with project_copy(git=True) as root:
            def prompt(text):
                code, data, error = run_hook(root, 'user_prompt_submit.py', {
                    'cwd': str(root), 'session_id': 's1', 'prompt': text})
                self.assertEqual(code, 0, error)
                return data['hookSpecificOutput']['additionalContext']

            prompt(scope)
            prompt(early)
            prompt(amendment)
            runtime = root / '.getzilla/runtime'
            pointer = json.loads((runtime / 'sessions/s1.json').read_bytes())
            record = runtime / 'routes' / (pointer['route_id'] + '.json')
            before = record.read_bytes()
            route = json.loads(before)
            self.assertEqual(route['task'], scope)
            self.assertEqual([item['text'] for item in route['context']['pending']], [early, amendment])

            context = prompt('Продолжай…')
            self.assertIn(objective, context)
            self.assertTrue(amendment in context, 'resume hid the pending scope amendment')
            self.assertIn('Retain the cart acceptance checks.', context)
            for item in route['context']['pending']:
                self.assertIn(item['id'], context)
            self.assertIn('Display omitted', context)
            self.assertIn(f".getzilla/runtime/routes/{pointer['route_id']}.json", context)
            self.assertLessEqual(len(context.encode('utf-8')), 16384)
            self.assertEqual(record.read_bytes(), before)
