"""A ';' separator must not be stricter than the equivalent newline (startup CPU step zero)."""
from __future__ import annotations

import contextlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.router import build_route
from tests._support import activate_owned_route
from tests._support import project_copy, run_hook

STEP_ZERO = 'lscpu; lscpu -p=CPU,CORE,SOCKET,ONLINE; nproc --all; nproc; taskset -pc $$; cat /proc/self/cgroup'


class SequentialSeparatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.stack = contextlib.ExitStack()
        cls.root = cls.stack.enter_context(project_copy(git=True))
        cls.other = cls.stack.enter_context(project_copy(git=True))
        for root in (cls.root, cls.other):
            activate_owned_route(root, build_route(root, 'Fix startup capacity step zero', 'seq').to_dict())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stack.close()

    def verdict(self, command: str) -> dict:
        _, result, error = run_hook(self.root, 'pre_tool_use.py', {
            'cwd': str(self.root),
            'session_id': 'seq',
            'tool_name': 'exec_command',
            'tool_input': {'cmd': command, 'workdir': str(self.root)},
        })
        self.assertFalse(error, error)
        return result

    def test_startup_step_zero_sequence_is_allowed(self) -> None:
        result = self.verdict(STEP_ZERO)
        self.assertEqual(result['decision'], 'allow', result)

    def test_semicolon_matches_newline_verdict(self) -> None:
        sequences = (
            ('printf x', 'printf y'),
            ('git status', 'git log -1'),
            ('nproc', 'taskset -pc $$'),
            (f'cd {self.other}', 'git status'),
            (f'cd {self.other}', 'git push origin feature'),
            ('printf x', 'git push origin feature'),
            ('printf x', "python3 -c \"from pathlib import Path; Path('AGENTS.md').write_text('x')\""),
        )
        for first, second in sequences:
            with self.subTest(first=first, second=second):
                semicolon = self.verdict(f'{first}; {second}')
                newline = self.verdict(f'{first}\n{second}')
                self.assertEqual(semicolon.get('decision', 'allow'), newline.get('decision', 'allow'),
                                 json.dumps({'semicolon': semicolon, 'newline': newline}))

    def test_nested_shell_semicolon_matches_newline(self) -> None:
        semicolon = self.verdict("bash -c 'printf x; printf y'")
        newline = self.verdict("bash -c 'printf x\nprintf y'")
        self.assertEqual(semicolon.get('decision', 'allow'), newline.get('decision', 'allow'))
        nested = self.verdict("bash -c 'bash -c printf'")
        self.assertEqual(nested['decision'], 'deny', nested)

    def test_dangerous_work_after_semicolon_stays_denied(self) -> None:
        for command in (
            'printf x; git push origin feature',
            f'cd {self.other}; git push origin feature',
            "printf x; python3 -c \"from pathlib import Path; Path('AGENTS.md').write_text('x')\"",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command)['decision'], 'deny')

    def test_other_control_operators_stay_ambiguous(self) -> None:
        for command in ('printf x | cat', 'printf x || printf y', 'printf x & printf y', '(printf x)',
                        'case x in x) printf x;; esac', 'printf "$(printf x)"'):
            with self.subTest(command=command):
                result = self.verdict(command)
                self.assertEqual(result['decision'], 'deny', result)
                self.assertIn('ambiguous-command-root', result['reason'])


if __name__ == '__main__':
    unittest.main()
