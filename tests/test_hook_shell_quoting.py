"""Offline regressions for shell syntax versus quoted argument data."""
from __future__ import annotations

import contextlib
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla._policy_legacy import _simple_commands, analyze_command_authority
from getzilla.router import build_route
from getzilla.state import set_active_route
from tests._support import project_copy, run_hook


class ShellQuotingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.stack = contextlib.ExitStack()
        cls.root = cls.stack.enter_context(project_copy(git=True))
        cls.other = cls.stack.enter_context(project_copy(git=True))
        # The reads below name README.md; a missing path would be refused by path hints instead.
        for root in (cls.root, cls.other):
            (root / 'README.md').write_bytes(b'allow deny' + bytes([10]))
        for root in (cls.root, cls.other):
            set_active_route(root, build_route(root, 'Fix shell quoting regression', 'quoted-data').to_dict())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stack.close()

    def verdict(self, command: str, **workdirs: str) -> dict:
        _, result, error = run_hook(self.root, 'pre_tool_use.py', {
            'cwd': str(self.root),
            'session_id': self.id() + hashlib.sha256(command.encode()).hexdigest(),
            'tool_name': 'exec_command',
            'tool_input': {'cmd': command, 'workdir': str(self.root), **workdirs},
        })
        self.assertFalse(error, error)
        return result

    def test_quoted_data_reaches_normal_policy(self) -> None:
        commands = (
            "gh api repos/Dimkox/getzilla/commits?per_page=3 --jq '.[] | {sha, date: .commit.committer.date, subject: .commit.message}'",
            "rg -n 'allow|deny' README.md",
            "jq 'map(select(.enabled))' package.json",
            "printf '%s' ';' '|' '||' '(' ')' '&&'",
            r"printf '%s' \; \| \( \) \&\&",
            "printf '%s' '$(literal)' '`literal`'",
            "python3 scripts/getzilla_approve.py protected-path --action protected-path-write --resource tests/example.py --reason 'reviewed; preserve (scope)'",
        )
        for command in commands:
            with self.subTest(command=command):
                result = self.verdict(command)
                self.assertEqual(result['decision'], 'allow', result)
                authority = analyze_command_authority(command)
                self.assertFalse(authority.ambiguous, authority)
                self.assertFalse(authority.actions, authority)

    def test_literal_operator_words_do_not_start_commands(self) -> None:
        for command in ("printf '%s' ';' git push", r"printf '%s' \; git push"):
            with self.subTest(command=command):
                self.assertEqual(_simple_commands(command), [['printf', '%s', ';', 'git', 'push']])

    def test_interpreter_arguments_remain_code_for_write_checks(self) -> None:
        commands = (
            'python3 -c "from pathlib import Path; Path(\'AGENTS.md\').write_text(\'blocked\')"',
            'bash -c "printf \'a;b\' > AGENTS.md"',
            'powershell -Command "git push origin feature"',
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command)['decision'], 'deny')

    def test_explicit_new_worktree_remains_usable_for_quoted_reads(self) -> None:
        result = self.verdict("rg -n 'allow|deny' README.md", workdir=str(self.other))
        self.assertEqual(result['decision'], 'allow', result)

    def test_actual_syntax_and_opaque_wrappers_remain_denied(self) -> None:
        commands = (
            'printf x | cat', '(printf x)',
            'printf x & printf y',
            'printf "$(printf x)"', 'printf "`printf x`"',
            "printf 'unterminated", 'printf trailing\\',
            'bash -c \'bash -c "printf x"\'',
            'command -p printf x', 'env LC_ALL=C printf x',
        )
        for command in commands:
            with self.subTest(command=command):
                result = self.verdict(command)
                self.assertEqual(result['decision'], 'deny', result)
                self.assertIn('ambiguous-command-root', result['reason'])

    def test_quoted_reason_does_not_create_authority(self) -> None:
        result = self.verdict("git push origin feature --push-option='reviewed; preserve scope'")
        self.assertEqual(result['decision'], 'deny', result)
        self.assertNotIn('ambiguous-command-root', result['reason'])
        self.assertIn('exact delegated local grant', result['reason'].lower())

    def test_conflicting_aliases_still_fail_closed(self) -> None:
        result = self.verdict(
            "git push origin feature --push-option='reviewed; preserve scope'", working_directory=str(self.other),
        )
        self.assertEqual(result['decision'], 'deny', result)
        self.assertIn('ambiguous-command-root', result['reason'])

    def test_denial_records_stage_and_implementation_without_argument_values(self) -> None:
        command = "printf 'ledger-private-value' | cat"
        self.assertEqual(self.verdict(command)['decision'], 'deny')
        ledger = json.loads((self.root / '.getzilla/runtime/tool-denials.json').read_text())
        digest = hashlib.sha256(command.encode()).hexdigest()
        entry = next(row for row in ledger['exact'].values() if row['command_sha256'] == digest)
        self.assertEqual(entry['root_failure_sources'], ['command.control-flow'])
        self.assertEqual(entry['command_workdir_sources'], ['command.control-flow', 'workdir'])
        self.assertEqual(entry['hook_implementation']['hook']['path'], str(self.root / '.grok/hooks/pre_tool_use.py'))
        for source in entry['hook_implementation'].values():
            self.assertRegex(source['sha256'], r'^[0-9a-f]{64}$')
        self.assertNotIn('ledger-private-value', json.dumps(ledger))

    def test_denial_redacts_command_root_values(self) -> None:
        command = 'GIT_DIR=/tmp/ledger-private-root git push origin feature'
        self.assertEqual(self.verdict(command)['decision'], 'deny')
        ledger = json.loads((self.root / '.getzilla/runtime/tool-denials.json').read_text())
        self.assertNotIn('ledger-private-root', json.dumps(ledger))


if __name__ == '__main__':
    unittest.main()
