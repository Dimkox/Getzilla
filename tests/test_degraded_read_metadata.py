"""Collected #151 review regressions; hook descriptors stay inert."""
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

FAILURES = ('.getzilla/getzilla/policy.py', '.getzilla/getzilla/fsx.py')


class DegradedReadMetadataTests(unittest.TestCase):
    def fixture(self, root: Path, failure: str | None) -> None:
        (root / 'README.md').write_text('synthetic public text\n', encoding='utf-8')
        (root / '.env').write_text('synthetic no-secret marker\n', encoding='utf-8')
        (root / 'sub').mkdir()
        (root / 'sub/README.md').symlink_to('../.env')
        if failure:
            (root / failure).write_text('raise ImportError("synthetic failed control")\n', encoding='utf-8')

    def decision(self, root: Path, payload: dict) -> str:
        code, output, error = run_hook(root, 'pre_tool_use.py', {'cwd': str(root), **payload})
        self.assertEqual(code, 0, error)
        self.assertLess(len(json.dumps(output)), 2000)
        self.assertLess(len(error), 1000)
        return output.get('decision') or output.get('hookSpecificOutput', {}).get('permissionDecision', 'allow')

    def test_command_and_directory_aliases_require_consistent_evidence(self) -> None:
        for failure in FAILURES:
            with project_copy() as root:
                self.fixture(root, failure)
                cases = [
                    ({'cmd': 'cat .env', 'command': 'cat README.md'}, 'deny'),
                    ({'cmd': 'cat README.md', 'command': 'cat .env'}, 'deny'),
                    ({'cmd': 'cat README.md', 'command': ['cat', 'README.md']}, 'allow'),
                    ({'cmd': ['cat', 'README.md']}, 'deny'),
                    ({'cmd': 'cat README.md', 'workdir': str(root / 'sub'), 'cwd': str(root)}, 'deny'),
                    ({'cmd': 'cat README.md', 'working_directory': str(root / 'sub'), 'workingDirectory': str(root)}, 'deny'),
                    ({'cmd': 'cat README.md', 'directory': str(root / 'sub')}, 'deny'),
                    ({'cmd': 'cat README.md', 'workdir': 'sub'}, 'deny'),
                    ({'cmd': 'cat README.md', 'workdir': str(root), 'cwd': str(root / '.')}, 'allow'),
                    ({'cmd': 'cat README.md', 'workdir': None}, 'deny'),
                ]
                for inputs, expected in cases:
                    with self.subTest(failure=failure, inputs=inputs):
                        self.assertEqual(self.decision(root, {'tool_name': 'exec_command', 'tool_input': inputs}), expected)

    def test_protocol_aliases_cannot_hide_another_requested_read(self) -> None:
        for failure in FAILURES:
            with project_copy() as root:
                self.fixture(root, failure)
                for payload, expected in (
                    ({'tool_name': 'Read', 'toolName': 'Write', 'tool_input': {'file_path': 'README.md'}}, 'deny'),
                    ({'tool_name': 'Read', 'tool_input': {'file_path': 'README.md'}, 'toolInput': {'file_path': '.env'}}, 'deny'),
                    ({'tool_name': 'Read', 'tool_input': {'file_path': 'README.md'}, 'toolArgs': json.dumps({'file_path': '.env'})}, 'deny'),
                    ({'toolName': 'read_file', 'toolArgs': json.dumps({'path': 'README.md'})}, 'allow'),
                    ({'toolName': 'run_shell_command', 'toolArgs': 'cat README.md'}, 'allow'),
                    ({'tool_name': 'Read', 'toolName': 'read_file', 'tool_input': {'path': 'README.md'}}, 'allow'),
                ):
                    with self.subTest(failure=failure, payload=payload):
                        self.assertEqual(self.decision(root, payload), expected)

    def test_path_qualified_executable_identity_is_not_its_basename(self) -> None:
        for failure in FAILURES:
            with project_copy() as root:
                self.fixture(root, failure)
                for command, expected in (
                    ('/usr/bin/cat README.md', 'allow'), ('/bin/cat README.md', 'allow'),
                    ('command cat README.md', 'allow'),
                    (str(root / 'untrusted/cat') + ' README.md', 'deny'),
                    ('./cat README.md', 'deny'), ('untrusted/command cat README.md', 'deny'),
                    (str(root / 'untrusted/git') + ' status --short', 'deny'),
                    ('cat README.md', 'allow'),
                ):
                    with self.subTest(failure=failure, command=command):
                        self.assertEqual(self.decision(root, {'tool_name': 'Bash', 'tool_input': {'command': command}}), expected)

    def test_policy_configuration_requires_a_bounded_regular_file(self) -> None:
        for failure in FAILURES:
            with project_copy() as root:
                self.fixture(root, failure)
                config = root / '.getzilla/config/policy.json'
                for state, expected in (('missing', 'allow'), ('malformed', 'deny'), ('oversize', 'deny'),
                                        ('directory', 'deny'), ('symlink', 'deny'), ('unreadable', 'deny'), ('fifo', 'deny')):
                    if config.is_dir():
                        config.rmdir()
                    elif config.exists() or config.is_symlink():
                        config.unlink()
                    if state == 'malformed':
                        config.write_text('{', encoding='utf-8')
                    elif state == 'oversize':
                        config.write_bytes(b' ' * 65537)
                    elif state == 'directory':
                        config.mkdir()
                    elif state == 'symlink':
                        config.symlink_to(root / 'README.md')
                    elif state == 'unreadable':
                        if os.name != 'posix':
                            continue
                        config.write_text('{}', encoding='utf-8')
                        config.chmod(0)
                    elif state == 'fifo':
                        if not hasattr(os, 'mkfifo'):
                            continue
                        os.mkfifo(config)
                    with self.subTest(failure=failure, state=state):
                        payload = {'cwd': str(root), 'tool_name': 'Read', 'tool_input': {'file_path': 'README.md'}}
                        try:
                            result = subprocess.run(
                                [sys.executable, str(root / '.grok/hooks/pre_tool_use.py')], cwd=root,
                                env={**os.environ, 'PYTHONPATH': str(root / '.getzilla')},
                                input=json.dumps(payload).encode(), capture_output=True, timeout=2, check=False,
                            )
                        except subprocess.TimeoutExpired:
                            self.fail('degraded configuration admission blocked before producing a decision')
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertLess(len(result.stdout), 2000)
                        self.assertLess(len(result.stderr), 1000)
                        self.assertEqual(json.loads(result.stdout)['decision'], expected)
                    if state == 'missing':
                        self.assertEqual(self.decision(root, {'tool_name': 'Read', 'tool_input': {'file_path': '.env'}}), 'deny')

    def test_healthy_policy_resolves_native_workdir_without_rebinding_authority(self) -> None:
        with project_copy() as root:
            self.fixture(root, None)
            self.assertEqual(self.decision(root, {'tool_name': 'exec_command', 'tool_input': {
                'cmd': 'cat README.md', 'workdir': str(root / 'sub'),
            }}), 'deny')
            self.assertEqual(self.decision(root, {'tool_name': 'exec_command', 'tool_input': {
                'cmd': 'cat README.md', 'workdir': str(root),
            }}), 'allow')
            (root / 'private-data').mkdir()
            (root / 'private-data/marker.txt').write_text('synthetic no-secret marker\n', encoding='utf-8')
            (root / 'sub/README.md').unlink()
            (root / 'sub/README.md').symlink_to('../private-data/marker.txt')
            (root / '.getzilla/config/policy.json').write_text(
                json.dumps({'secret_read_paths': ['private-data/**']}), encoding='utf-8',
            )
            self.assertEqual(self.decision(root, {'tool_name': 'exec_command', 'tool_input': {
                'cmd': 'cat README.md', 'workdir': str(root / 'sub'),
            }}), 'deny')
            self.assertEqual(self.decision(root, {'tool_name': 'exec_command', 'tool_input': {
                'cmd': 'cat README.md', 'workdir': str(root),
            }}), 'allow')

    def test_public_filename_exceptions_do_not_override_protected_parent_trees(self) -> None:
        for failure in (None, *FAILURES):
            with project_copy() as root:
                self.fixture(root, failure)
                for path, expected in (
                    ('secrets/known_hosts', 'deny'), ('trust-ci/runtime/key.pub', 'deny'),
                    ('.ssh/known_hosts', 'allow'),
                ):
                    target = root / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text('synthetic no-secret marker\n', encoding='utf-8')
                    with self.subTest(failure=failure, path=path):
                        self.assertEqual(self.decision(root, {'tool_name': 'Read', 'tool_input': {'file_path': path}}), expected)

    def test_posix_system_paths_are_not_windows_executable_evidence(self) -> None:
        # Platform classification fault injection in a real Linux hook process;
        # this does not qualify Windows or a native client.
        with project_copy() as root:
            self.fixture(root, '.getzilla/getzilla/fsx.py')
            hook = root / '.grok/hooks/pre_tool_use.py'
            hook.write_text(hook.read_text(encoding='utf-8').replace(
                'import sys\n', "import sys\nsys.platform = 'win32'\n", 1,
            ), encoding='utf-8')
            self.assertEqual(self.decision(root, {'tool_name': 'Bash', 'tool_input': {
                'command': '/usr/bin/cat README.md',
            }}), 'deny')
            self.assertEqual(self.decision(root, {'tool_name': 'Bash', 'tool_input': {
                'command': 'cat README.md',
            }}), 'allow')
