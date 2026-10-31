"""#80: short replies keep the task, sessions keep their own route, argv literals are data, and
independent ambiguous denials keep independent circuit-breaker objectives."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import state  # noqa: E402
from tests._support import project_copy, run_hook  # noqa: E402


def prompt(root: Path, session: str, text: str) -> str:
    code, _data, stderr = run_hook(root, 'user_prompt_submit.py', {
        'cwd': str(root), 'session_id': session, 'hook_event_name': 'UserPromptSubmit', 'prompt': text})
    assert code == 0, stderr
    pointer = root / '.getzilla/runtime/sessions' / f'{session}.json'
    if pointer.is_file():
        return json.loads(pointer.read_text(encoding='utf-8'))['route_id']
    return json.loads((root / '.getzilla/runtime/active-route.json').read_text(encoding='utf-8'))['route_id']


def pre(root: Path, session: str, tool: str, tool_input: dict) -> dict:
    code, data, stderr = run_hook(root, 'pre_tool_use.py', {
        'cwd': str(root), 'session_id': session, 'hook_event_name': 'PreToolUse', 'tool_name': tool, 'tool_input': tool_input})
    assert code == 0, stderr
    return data


def denied(data: dict) -> bool:
    return data.get('decision') in {'deny', 'block'} or (data.get('hookSpecificOutput') or {}).get('permissionDecision') == 'deny'


class ShortReplyTests(unittest.TestCase):
    def test_acknowledgements_and_status_questions_keep_the_current_task(self) -> None:
        with project_copy(git=True) as root:
            task = prompt(root, 's1', 'Fix the login timeout bug in the auth module')
            for reply in ('и', 'ну', 'далее', 'дальше', 'и дальше', 'что дальше?', 'ok', 'Чё там ещё не так?',
                          'где результат?', 'статус', 'да', 'продолжай'):
                with self.subTest(reply=reply):
                    self.assertEqual(prompt(root, 's1', reply), task)
            self.assertNotEqual(prompt(root, 's1', 'Add a CSV export to the reports page'), task)


class SessionIsolationTests(unittest.TestCase):
    def test_two_sessions_keep_their_own_route_and_grants(self) -> None:
        with project_copy(git=True) as root:
            subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Example/app.git'], cwd=root, check=True)
            first = prompt(root, 's1', 'Fix the login timeout bug in the auth module')
            state.bind_session(None)
            state.add_approval(root, 'protected-path', 'edit AGENTS.md', 5,
                               actions=['protected-path-write'], resources=['AGENTS.md'])
            second = prompt(root, 's2', 'Write a new landing page for the pricing plans')
            self.assertNotEqual(first, second)
            self.assertEqual(prompt(root, 's1', 'и'), first, 's2 must not replace the route s1 continues')
            for session, expected in (('s1', first), ('s2', second)):
                state.bind_session(session)
                try:
                    self.assertEqual(state.get_active_route(root)['route_id'], expected)
                finally:
                    state.bind_session(None)
            # The exact grant issued under s1's route still serves s1 after s2 routed its own task.
            write = {'file_path': str(root / 'AGENTS.md'), 'content': 'x\n'}
            self.assertFalse(denied(pre(root, 's1', 'Write', write)))
            self.assertTrue(denied(pre(root, 's2', 'Write', write)))


class ArgvLiteralTests(unittest.TestCase):
    def test_paths_and_literals_in_argv_are_not_shell_builtins(self) -> None:
        with project_copy(git=True) as root:
            prompt(root, 's1', 'Fix the login timeout bug in the auth module')
            for command in ('rg TODO .', 'find . -name "*.py"', 'grep -rn "a;b(c)" .', 'ls .'):
                with self.subTest(command=command):
                    data = pre(root, 's1', 'Bash', {'command': command})
                    self.assertNotIn('ambiguous-command-root', json.dumps(data, ensure_ascii=False), data)

    def test_real_dynamic_shell_stays_ambiguous(self) -> None:
        with project_copy(git=True) as root:
            prompt(root, 's1', 'Fix the login timeout bug in the auth module')
            for command in ('. ./env.sh && git push origin main', 'source env.sh && git push origin main',
                            'eval "$CMD" && git push origin main', 'sudo . ./env.sh && git push origin main',
                            "find . -exec sh -c '. ./x' \\; && git push origin main"):
                with self.subTest(command=command):
                    self.assertTrue(denied(pre(root, 's1', 'Bash', {'command': command})))


class GrantRetryTests(unittest.TestCase):
    def test_exact_production_grant_after_denial_allows_only_its_target(self) -> None:
        with project_copy(git=True) as root:
            subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Example/app.git'],
                           cwd=root, check=True)
            prompt(root, 's1', 'Fix the login timeout bug in the auth module')
            command = {'command': 'git push origin fix/x'}
            self.assertTrue(denied(pre(root, 's1', 'Bash', command)))
            self.assertIn('Circuit breaker', json.dumps(pre(root, 's1', 'Bash', command)))
            state.bind_session('s1')
            try:
                state.add_approval(root, 'production', 'push fix/x', 5,
                                   actions=['git-push-branch'], resources=['fix/x'])
            finally:
                state.bind_session(None)
            self.assertFalse(denied(pre(root, 's1', 'Bash', command)))
            self.assertTrue(denied(pre(root, 's1', 'Bash', {'command': 'git push origin fix/y'})))

    def test_a_grant_recorded_after_a_denial_makes_the_retry_a_new_attempt(self) -> None:
        # The breaker stops blind repeats; a retry after a new grant must show the real reason instead.
        tool = 'mcp__x__create_record'
        with project_copy(git=True) as root:
            prompt(root, 's1', 'Fix the login timeout bug in the auth module')
            self.assertTrue(denied(pre(root, 's1', tool, {})))
            repeat = pre(root, 's1', tool, {})
            self.assertIn('Circuit breaker', json.dumps(repeat, ensure_ascii=False))
            (root / '.getzilla/runtime/approvals.json').write_text('[]\n', encoding='utf-8')
            after_grant = pre(root, 's1', tool, {})
            self.assertTrue(denied(after_grant))
            self.assertNotIn('Circuit breaker', json.dumps(after_grant, ensure_ascii=False))


class ObjectiveTests(unittest.TestCase):
    def test_independent_ambiguous_commands_have_independent_objectives(self) -> None:
        with project_copy(git=True) as root:
            prompt(root, 's1', 'Fix the login timeout bug in the auth module')
            first = pre(root, 's1', 'Bash', {'command': 'source a.sh && git push origin main'})
            other = pre(root, 's1', 'Bash', {'command': 'source b.sh && git push origin feature'})
            self.assertTrue(denied(first) and denied(other))
            self.assertNotIn('Circuit breaker', json.dumps(other, ensure_ascii=False))
            cosmetic = pre(root, 's1', 'Bash', {'command': 'source  a.sh &&  git push  origin main'})
            self.assertIn('Circuit breaker', json.dumps(cosmetic, ensure_ascii=False))
            ledger = (root / '.getzilla/runtime').rglob('*denial*')
            for path in ledger:
                if path.is_file():
                    self.assertNotIn('a.sh', path.read_text(encoding='utf-8', errors='replace'))


if __name__ == '__main__':
    unittest.main()
