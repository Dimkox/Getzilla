"""Command-policy parser gaps from the PR #62 review (issue #64).

Each deny probe was allowed on 0d88581; each allow probe must stay allowed so the
guard does not turn into a blanket shell ban. Inputs are synthetic hook payloads;
nothing here executes the commands.
"""
from __future__ import annotations

import contextlib
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Iterator
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import fsx  # noqa: E402
from getzilla.policy import evaluate_pre_tool  # noqa: E402
from getzilla.router import build_route  # noqa: E402
from getzilla.state import set_active_route  # noqa: E402
from tests._support import project_copy  # noqa: E402


@contextlib.contextmanager
def github_project() -> Iterator[Path]:
    with project_copy(git=True) as root:
        subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'], cwd=root, check=True)
        set_active_route(root, build_route(root, 'Исправить PHP баг', 's1').to_dict())
        # Synthetic secret material (never real keys).
        (root / 'deploy/tls').mkdir(parents=True)
        (root / 'deploy/tls/server.key').write_text('synthetic\n', encoding='utf-8')
        (root / 'pub').mkdir()
        (root / 'pub/server.key').write_text('synthetic\n', encoding='utf-8')
        (root / 'src').mkdir(exist_ok=True)
        (root / 'src/app.py').write_text('print(1)\n', encoding='utf-8')
        yield root


class _Case(unittest.TestCase):
    root: Path
    _stack: contextlib.ExitStack

    @classmethod
    def setUpClass(cls) -> None:
        cls._stack = contextlib.ExitStack()
        cls.root = cls._stack.enter_context(github_project())

    @classmethod
    def tearDownClass(cls) -> None:
        cls._stack.close()

    def tool(self, tool: str, tool_input: dict) -> tuple[bool, str | None]:
        return evaluate_pre_tool(self.root, {'tool_name': tool, 'tool_input': tool_input})

    def assert_denied(self, commands: tuple[str, ...], fragment: str | None = None) -> None:
        for command in commands:
            with self.subTest(command=command):
                allowed, reason = self.tool('Bash', {'command': command})
                self.assertFalse(allowed, f'{command!r} was allowed')
                if fragment:
                    self.assertIn(fragment, reason or '', command)

    def assert_allowed(self, commands: tuple[str, ...]) -> None:
        for command in commands:
            with self.subTest(command=command):
                allowed, reason = self.tool('Bash', {'command': command})
                self.assertTrue(allowed, f'{command!r} was denied: {reason}')


class AuthorityParserTests(_Case):
    def test_publisher_global_options_before_the_verb(self) -> None:
        self.assert_denied((
            'cargo +stable publish', 'cargo --config net.git-fetch-with-cli=true publish',
            'gem -C /tmp push package.gem', 'poetry -C /tmp publish',
        ))
        self.assert_allowed(('cargo +stable build', 'cargo --config a=b test', 'gem -C /tmp list'))

    def test_long_form_shell_command_options(self) -> None:
        self.assert_denied((
            "script --command 'git push origin main' /dev/null",
            "script --command='git push origin main' /dev/null",
        ))

    def test_quoted_payload_behind_arbitrary_wrapper(self) -> None:
        self.assert_denied((
            "flock /tmp/l -c 'rm --recursive --no-preserve-root /'",
            "flock /tmp/l --command 'rm --recursive /'",
            "somewrapper --run 'rm --recursive /'",
        ), 'destructive')
        self.assert_denied(("flock /tmp/l -c 'git push origin main'",))
        self.assert_allowed(('flock /tmp/l -c make', "grep -rn 'rm -r /' docs", 'git commit -m "rm --recursive / note"'))

    def test_obfuscation_checks_skip_inert_and_quoted_text(self) -> None:
        self.assert_allowed((
            "echo 'git$IFSpush'", "printf '%s' 'git${IFS}push'",
            "git commit -m 'document powershell -enc handling'", 'echo git$IFSpush',
        ))
        self.assert_denied(('git${IFS}push origin main', "git$IFS'push' origin main", 'pwsh -enc ZwBpAHQA'))


class WindowsParserTests(_Case):
    def test_start_process_argument_array_is_consumed(self) -> None:
        with mock.patch.object(fsx, 'WINDOWS', True):
            self.assert_denied((
                "Start-Process gh -ArgumentList 'pr', 'merge', '1'",
                "Start-Process -FilePath git -ArgumentList 'push' , 'origin', 'main'",
            ))

    def test_every_mutating_web_method_is_a_write(self) -> None:
        with mock.patch.object(fsx, 'WINDOWS', True):
            self.assert_denied((
                'Invoke-WebRequest -Method Merge https://example.com/api',
                'Invoke-WebRequest -CustomMethod POST https://example.com/api',
                'irm -Method Default -CustomMethod PURGE https://example.com/api',
            ))
            self.assert_allowed((
                'Invoke-WebRequest -Method Get https://example.com/api',
                'iwr https://example.com/api', 'Invoke-RestMethod -Method Head https://example.com/api',
            ))

    def test_format_matched_by_executable_basename(self) -> None:
        with mock.patch.object(fsx, 'WINDOWS', True):
            self.assert_denied((r'C:\Windows\System32\format.com /q C:', r'"C:\Windows\System32\format.com" /q C:'), 'destructive')


class SecretReadTests(_Case):
    def test_enclosing_secret_directory_wins_over_public_names(self) -> None:
        for path in ('trust-ci/runtime/.ssh/config', 'trust-ci/runtime/authorized_keys', 'secrets/known_hosts'):
            with self.subTest(path=path):
                self.assertFalse(self.tool('Read', {'path': path})[0], path)
        self.assert_denied(('cat trust-ci/runtime/.ssh/config',), 'secret')
        for path in ('home/.ssh/known_hosts', '~/.ssh/config', '.env.example', 'id_rsa.pub'):
            with self.subTest(path=path):
                allowed, reason = self.tool('Read', {'path': path})
                self.assertTrue(allowed, f'{path}: {reason}')

    def test_nonrecursive_robocopy_scans_the_source_directory(self) -> None:
        with mock.patch.object(fsx, 'WINDOWS', True):
            self.assert_denied((r'robocopy pub C:\out', r'xcopy pub C:\out'), 'secret')

    def test_named_select_string_path(self) -> None:
        self.assert_denied((
            'Select-String -Path deploy/tls/server.key -Pattern BEGIN',
            'sls -Pattern BEGIN -LiteralPath deploy/tls/server.key',
        ), 'secret')
        self.assert_allowed(('Select-String -Path src/app.py -Pattern TODO', 'Select-String server.key src/app.py'))

    def test_grep_glob_alternatives_are_expanded(self) -> None:
        for glob in ('{server.key,*.py}', '*.{py,key}'):
            with self.subTest(glob=glob):
                self.assertFalse(self.tool('Grep', {'pattern': 'BEGIN', 'glob': glob})[0], glob)
        allowed, reason = self.tool('Grep', {'pattern': 'x', 'glob': '{*.py,*.md}'})
        self.assertTrue(allowed, reason)


if __name__ == '__main__':
    unittest.main()
