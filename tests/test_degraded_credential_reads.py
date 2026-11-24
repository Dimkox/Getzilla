"""#151: inert descriptors sent to the real canonical hook, never executed tools."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from tests._support import project_copy, run_hook


class DegradedCredentialReadTests(unittest.TestCase):
    def _fixture(self, root: Path, failure: str | None) -> None:
        self.bootstrap_unavailable = failure == '.getzilla/getzilla/fsx.py'
        (root / 'README.md').write_text('synthetic public text\n', encoding='utf-8')
        (root / '.env').write_text('synthetic marker only\n', encoding='utf-8')
        (root / '.env.example').write_text('synthetic template\n', encoding='utf-8')
        (root / 'public-link').symlink_to('.env')
        (root / '-n').symlink_to('.env')
        (root / 'subdir').mkdir()
        if failure:
            (root / failure).write_text('raise ImportError("synthetic unavailable control")\n', encoding='utf-8')

    def _decision(self, root: Path, tool: str, inputs: object) -> str:
        code, output, error = run_hook(root, 'pre_tool_use.py', {
            'cwd': str(root), 'tool_name': tool, 'tool_input': inputs,
        })
        verdict = output.get('decision') or output.get('hookSpecificOutput', {}).get('permissionDecision', 'allow')
        self.assertEqual(code, 2 if self.bootstrap_unavailable and verdict == 'deny' else 0, error)
        self.assertLess(len(error), 1000)
        self.assertLess(len(json.dumps(output)), 2000)
        return output.get('decision') or output.get('hookSpecificOutput', {}).get('permissionDecision', 'allow')

    def test_normal_policy_denies_synthetic_secret_and_allows_public_file(self) -> None:
        with project_copy() as root:
            self._fixture(root, None)
            for tool, inputs in (
                ('Read', {'file_path': '.env'}),
                ('Bash', {'command': 'cat .env'}),
                ('Read', {'file_path': 'public-link'}),
            ):
                with self.subTest(tool=tool, inputs=inputs):
                    self.assertEqual(self._decision(root, tool, inputs), 'deny')
            self.assertEqual(self._decision(root, 'Read', {'file_path': 'README.md'}), 'allow')

    def test_both_import_failures_deny_secret_read_descriptors(self) -> None:
        for failure in ('.getzilla/getzilla/policy.py', '.getzilla/getzilla/fsx.py'):
            with project_copy() as root:
                self._fixture(root, failure)
                descriptors = [
                    ('Read', {'file_path': '.env'}),
                    ('read_file', {'path': 'subdir/../.env'}),
                    ('read_many_files', {'paths': ['README.md', '.env']}),
                    ('view', {'file_path': '.env'}),
                    ('mcp__filesystem__read_file', {'path': '.env'}),
                    ('Read', {'file_path': str(root / '.env')}),
                    ('Read', {'file_path': 'public-link'}),
                    ('Read', {'file_path': '.codex/auth.json'}),
                    ('Read', {'file_path': '.aws/config'}),
                    ('Read', {'file_path': 'trust-ci/runtime/store'}),
                    ('Grep', {'path': '.', 'pattern': 'synthetic'}),
                    ('Read', {}), ('Read', {'file_path': 3}),
                    ('Read', {'file_path': '$UNKNOWN/file'}),
                    ('Read', {'file_path': 'README.md', 'metadata': {'absolute_path': '.env'}}),
                    ('Read', {'file_path': 'README.md', 'file_paths': ['.env']}),
                    ('Read', {'file_path': 'README.md', 'filename': '.env'}),
                ]
                for alias in ('Bash', 'exec_command', 'run_terminal_command', 'local_shell', 'container.exec'):
                    descriptors.append((alias, {'command': 'cat .env'}))
                for command in (
                    '/usr/bin/cat .env', 'env cat .env', 'command cat .env',
                    'env cat README.md',
                    "sh -c 'cat .env'", 'cat public-link', 'cat subdir/../.env',
                    'cat < .env', 'Get-Content .env', 'gc .env',
                    'cat -- README.md -n',
                    'cat "$UNRESOLVED"', 'cat *', 'custom-reader README.md',
                    'less "+!cat .env" README.md',
                    "cat 'unterminated", 'cat README.md; cat .env',
                ):
                    descriptors.append(('Bash', {'command': command}))
                descriptors.extend([('Bash', {}), ('Bash', {'command': ['cat', 3]})])
                for tool, inputs in descriptors:
                    with self.subTest(failure=failure, tool=tool, inputs=inputs):
                        self.assertEqual(self._decision(root, tool, inputs), 'deny')

    def test_degraded_supported_public_reads_and_ordinary_edits(self) -> None:
        for failure in ('.getzilla/getzilla/policy.py', '.getzilla/getzilla/fsx.py'):
            with project_copy() as root:
                self._fixture(root, failure)
                for tool, inputs in (
                    ('Read', {'file_path': 'README.md'}),
                    ('read_file', {'path': 'README.md'}),
                    ('read_many_files', {'paths': ['README.md', '.env.example']}),
                    ('Bash', {'command': 'cat README.md'}),
                    ('Bash', {'command': ['cat', 'README.md']}),
                    ('Bash', {'command': 'head -n 1 README.md'}),
                    ('Bash', {'command': 'git status --short'}),
                    ('Bash', {'command': 'ls'}),
                    ('Bash', {'command': 'cat .env.example'}),
                    ('Write', {'file_path': 'src/app.py', 'content': 'x = 1\n'}),
                ):
                    with self.subTest(failure=failure, tool=tool, inputs=inputs):
                        self.assertEqual(self._decision(root, tool, inputs), 'allow')

    def test_malformed_degraded_payload_is_denied_with_bounded_protocol_output(self) -> None:
        with project_copy() as root:
            self._fixture(root, '.getzilla/getzilla/fsx.py')
            for payload in (
                b'{', b'[]', b'{"tool_name":"Read","tool_input":"bad"}', b'x' * 262145,
                b'[' * 2000 + b']' * 2000,
            ):
                result = subprocess.run(
                    [sys.executable, str(root / '.getzilla/hooks/pre_tool_use.py')], cwd=root,
                    env={**os.environ, 'PYTHONPATH': str(root / '.getzilla')},
                    input=payload, capture_output=True, timeout=10, check=False,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertLess(len(result.stdout), 2000)
                self.assertLess(len(result.stderr), 1000)
                self.assertEqual(json.loads(result.stdout)['decision'], 'deny')

    def test_degraded_checks_every_normal_secret_pattern_and_owner_additions(self) -> None:
        from getzilla.policy import DEFAULT_SECRET_READ
        paths = [pattern.replace('**/', 'nested/').replace('**', 'nested').replace('*', 'fixture')
                 for pattern in DEFAULT_SECRET_READ]
        for failure in ('.getzilla/getzilla/policy.py', '.getzilla/getzilla/fsx.py'):
            with project_copy() as root:
                self._fixture(root, failure)
                (root / '.getzilla/config/policy.json').write_text(
                    json.dumps({'secret_read_paths': ['private-data/**']}), encoding='utf-8',
                )
                for path in [*paths, 'private-data/token.txt']:
                    with self.subTest(failure=failure, path=path):
                        self.assertEqual(self._decision(root, 'Read', {'file_path': path}), 'deny')

    def test_unusable_policy_configuration_does_not_authorize_a_read(self) -> None:
        with project_copy() as root:
            self._fixture(root, '.getzilla/getzilla/fsx.py')
            (root / '.getzilla/config/policy.json').write_text('{', encoding='utf-8')
            self.assertEqual(self._decision(root, 'Read', {'file_path': 'README.md'}), 'deny')

    def test_declared_execution_directory_controls_relative_resolution(self) -> None:
        for failure in ('.getzilla/getzilla/policy.py', '.getzilla/getzilla/fsx.py'):
            with project_copy() as root:
                self._fixture(root, failure)
                (root / 'subdir/README.md').symlink_to('../.env')
                code, output, error = run_hook(root, 'pre_tool_use.py', {
                    'cwd': str(root / 'subdir'), 'tool_name': 'Read',
                    'tool_input': {'file_path': 'README.md'},
                })
                self.assertEqual(code, 2 if self.bootstrap_unavailable else 0, error)
                self.assertEqual(output.get('decision') or output.get('hookSpecificOutput', {}).get('permissionDecision'), 'deny')
