"""#151 healthy read authority: inert hook requests, synthetic resources only."""
from __future__ import annotations

import json
import shlex
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import _policy_legacy as legacy
from tests._support import project_copy, run_hook

FAULTS = (None, '.getzilla/getzilla/policy.py', '.getzilla/getzilla/fsx.py')


class ReadAuthorityTests(unittest.TestCase):
    def fixture(self, root: Path, fault: str | None) -> Path:
        (root / 'README.md').write_text('synthetic public text\n', encoding='utf-8')
        (root / 'private-data').mkdir()
        (root / 'private-data/marker.txt').write_text('synthetic no-secret marker\n', encoding='utf-8')
        child = root / 'sub'
        child.mkdir()
        (child / 'README.md').symlink_to('../private-data/marker.txt')
        (child / 'PUBLIC.md').write_text('synthetic public text\n', encoding='utf-8')
        (child / '.ssh').mkdir()
        (child / '.ssh/known_hosts').write_text('synthetic public hosts\n', encoding='utf-8')
        (root / '.getzilla/config/policy.json').write_text(
            json.dumps({'secret_read_paths': ['private-data/**']}), encoding='utf-8',
        )
        if fault:
            (root / fault).write_text('raise ImportError("synthetic unavailable policy")\n', encoding='utf-8')
        return child

    def request(self, root: Path, tool: str, inputs: dict) -> str:
        code, output, error = run_hook(root, 'pre_tool_use.py', {
            'cwd': str(root), 'tool_name': tool, 'tool_input': inputs,
        })
        self.assertEqual(code, 0, error)
        self.assertLess(len(json.dumps(output)), 2000)
        self.assertLess(len(error), 1000)
        return output.get('decision') or output.get('hookSpecificOutput', {}).get('permissionDecision', 'allow')

    def test_healthy_and_faulted_conflicting_native_directories_do_not_select_public_root(self) -> None:
        for fault in FAULTS:
            with project_copy() as root:
                child = self.fixture(root, fault)
                for alias in ('cwd', 'working_directory', 'workingDirectory', 'directory'):
                    for workdir, other in ((child, root), (root, child)):
                        with self.subTest(fault=fault, alias=alias, workdir=workdir):
                            self.assertEqual(self.request(root, 'exec_command', {
                                'cmd': 'cat README.md', 'workdir': str(workdir), alias: str(other),
                            }), 'deny')
                self.assertEqual(self.request(root, 'exec_command', {
                    'cmd': 'cat README.md', 'workdir': str(root), 'cwd': str(root / '.'),
                }), 'allow')

    def test_nested_recognized_root_cannot_remove_session_read_protection(self) -> None:
        for fault in FAULTS:
            with project_copy() as root:
                child = self.fixture(root, fault)
                for nested in (False, True):
                    if nested:
                        (child / '.getzilla/config').mkdir(parents=True)
                        (child / '.getzilla/config/policy.json').write_text('{}', encoding='utf-8')
                    for tool, inputs, expected in (
                        ('exec_command', {'cmd': 'cat README.md', 'workdir': str(child)}, 'deny'),
                        ('Read', {'file_path': 'README.md', 'workdir': str(child)}, 'deny'),
                        ('exec_command', {'cmd': 'cat PUBLIC.md', 'workdir': str(child)}, 'allow'),
                        ('Read', {'file_path': str(child / 'PUBLIC.md'), 'workdir': str(child)}, 'allow'),
                        ('exec_command', {'cmd': 'cat .ssh/known_hosts', 'workdir': str(child)}, 'allow'),
                    ):
                        with self.subTest(fault=fault, nested=nested, tool=tool, inputs=inputs):
                            self.assertEqual(self.request(root, tool, inputs), expected)

    def test_omitted_legacy_cwd_stays_root_but_explicit_unknown_read_cwd_refuses(self) -> None:
        with project_copy() as root:
            self.fixture(root, None)
            self.assertIsNone(legacy.shell_secret_reference(root, 'cat README.md', legacy.DEFAULT_SECRET_READ))
            self.assertIsNotNone(legacy.shell_secret_reference(
                root, 'cat README.md', legacy.DEFAULT_SECRET_READ, execution_cwd=None,
            ))
            self.assertIsNone(legacy.shell_secret_reference(
                root, 'echo public', legacy.DEFAULT_SECRET_READ, execution_cwd=None,
            ))

    def test_healthy_sibling_public_policy_and_session_protection_both_apply(self) -> None:
        with project_copy() as root:
            self.fixture(root, None)
            other = root.parent / 'other'
            (other / '.getzilla/config').mkdir(parents=True)
            (other / '.getzilla/config/policy.json').write_text(
                json.dumps({'secret_read_paths': ['other-private/**']}), encoding='utf-8',
            )
            (other / 'PUBLIC.md').write_text('synthetic public text\n', encoding='utf-8')
            (other / 'README.md').symlink_to(root / 'private-data/marker.txt')
            (other / 'other-private').mkdir()
            (other / 'other-private/marker.txt').write_text('synthetic no-secret marker\n', encoding='utf-8')
            (other / 'private-data').mkdir()
            (other / 'private-data/public.txt').write_text('synthetic unrelated public text\n', encoding='utf-8')
            for path, expected in (('PUBLIC.md', 'allow'), ('README.md', 'deny'),
                                   ('other-private/marker.txt', 'deny'), ('private-data/public.txt', 'allow')):
                with self.subTest(path=path):
                    self.assertEqual(self.request(root, 'exec_command', {
                        'cmd': 'cat ' + path, 'workdir': str(other),
                    }), expected)

    def test_implicit_search_keeps_session_policy_and_explicit_public_search_stays_allowed(self) -> None:
        for fault in FAULTS:
            with project_copy() as root:
                child = self.fixture(root, fault)
                (child / '.getzilla/config').mkdir(parents=True)
                (child / '.getzilla/config/policy.json').write_text('{}', encoding='utf-8')
                self.assertEqual(self.request(root, 'Grep', {
                    'pattern': 'synthetic', 'workdir': str(child),
                }), 'deny')
                self.assertEqual(self.request(root, 'Grep', {
                    'pattern': 'synthetic', 'path': str(child / 'PUBLIC.md'), 'workdir': str(child),
                }), 'allow')

    def test_authorized_child_consumer_does_not_borrow_parent_relative_secret_identity(self) -> None:
        with project_copy() as root:
            child = self.fixture(root, None)
            (root / '.getzilla/config/policy.json').write_text(json.dumps({
                'secret_read_paths': [*legacy.DEFAULT_SECRET_READ, 'private-data/**'],
            }), encoding='utf-8')
            (root / '.env').write_text('synthetic parent marker\n', encoding='utf-8')
            (child / '.env').write_text('synthetic child marker\n', encoding='utf-8')
            (child / 'deploy').mkdir()
            script = child / 'deploy/read.py'
            script.write_text('# inert fixture: never executed\n', encoding='utf-8')
            (child / '.getzilla/config').mkdir(parents=True)
            (child / '.getzilla/config/policy.json').write_text('{}', encoding='utf-8')
            (root / '.getzilla/config/project-policy.json').write_text(json.dumps({
                'secret_consumers': [{'script': 'sub/deploy/read.py', 'secrets': ['.env']}],
            }), encoding='utf-8')
            (child / '.getzilla/config/project-policy.json').write_text(json.dumps({
                'secret_consumers': [{'script': 'deploy/read.py', 'secrets': [str(root / '.env'), '.env']}],
            }), encoding='utf-8')
            self.assertEqual(self.request(root, 'exec_command', {
                'cmd': shlex.join(['python3', str(script), '--env', str(root / '.env')]), 'workdir': str(child),
            }), 'allow')
            self.assertEqual(self.request(root, 'exec_command', {
                'cmd': 'python3 deploy/read.py --env .env', 'workdir': str(child),
            }), 'deny')
            self.assertEqual(self.request(root, 'exec_command', {
                'cmd': 'cat ' + str(root / '.env'), 'workdir': str(child),
            }), 'deny')

    def test_off_root_consumer_cannot_treat_an_interpreter_option_as_a_script(self) -> None:
        with project_copy() as root:
            child = self.fixture(root, None)
            (child / '-m').write_text('# inert fixture file\n', encoding='utf-8')
            (root / '.getzilla/config/project-policy.json').write_text(json.dumps({
                'secret_consumers': [{'script': 'sub/-m', 'secrets': [str(root / '.env')]}],
            }), encoding='utf-8')
            self.assertEqual(legacy._consumer_handoffs(
                root, 'python3 -m module --env ' + str(root / '.env'), execution_cwd=child,
            ), {})

    def test_resolved_external_secret_identity_and_public_external_alias_are_distinct(self) -> None:
        for fault in FAULTS:
            with project_copy() as root:
                child = self.fixture(root, fault)
                (root / '.getzilla/config/policy.json').write_text(json.dumps({
                    'secret_read_paths': [*legacy.DEFAULT_SECRET_READ, 'private-data/**'],
                }), encoding='utf-8')
                (child / '.getzilla/config').mkdir(parents=True)
                (child / '.getzilla/config/policy.json').write_text('{}', encoding='utf-8')
                external = root.parent / 'external'
                external.mkdir()
                (external / '.env').write_text('synthetic external marker\n', encoding='utf-8')
                (external / 'PUBLIC.md').write_text('synthetic public text\n', encoding='utf-8')
                (child / 'external-private').symlink_to(external / '.env')
                (child / 'external-public').symlink_to(external / 'PUBLIC.md')
                (child / 'PRIVATE.pub').symlink_to(external / '.env')
                (child / 'PUBLIC.pub').write_text('synthetic public key half\n', encoding='utf-8')
                for path, expected in (('external-private', 'deny'), ('external-public', 'allow')):
                    for tool, inputs in (
                        ('exec_command', {'cmd': 'cat ' + path, 'workdir': str(child)}),
                        ('Read', {'file_path': str(child / path), 'workdir': str(child)}),
                    ):
                        with self.subTest(fault=fault, tool=tool, path=path):
                            self.assertEqual(self.request(root, tool, inputs), expected)
                self.assertEqual(self.request(root, 'exec_command', {
                    'cmd': 'cat *.pub', 'workdir': str(child),
                }), 'deny')
                self.assertEqual(self.request(root, 'exec_command', {
                    'cmd': 'cat PUBLIC.pub', 'workdir': str(child),
                }), 'allow')
