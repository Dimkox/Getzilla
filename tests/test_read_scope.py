"""Inert hook controls for shell cwd state and recursive target scope."""
from __future__ import annotations

import json
import unittest

from getzilla import _policy_legacy as legacy
from tests import test_read_authority as authority
from tests._support import project_copy


class ReadScopeTests(unittest.TestCase):
    def test_inline_directory_changes_cannot_borrow_initial_public_read_scope(self) -> None:
        helper = authority.ReadAuthorityTests()
        for fault in authority.FAULTS:
            with project_copy() as root:
                helper.fixture(root, fault)
                for nested in (False, True):
                    if nested:
                        (root / 'sub/.getzilla/config').mkdir(parents=True)
                        (root / 'sub/.getzilla/config/policy.json').write_text('{"schema_version": 2}', encoding='utf-8')
                    for command in (
                        'cd sub && cat README.md', 'cd sub; cat README.md',
                        'cd sub || cat README.md', '(cd sub && cat README.md)',
                        'cd sub | cat README.md', 'sh -c "cd sub && cat README.md"',
                        'command cd sub && cat README.md', 'cd sub && rg synthetic',
                        'env -C sub cat README.md',
                        'env --chdir=sub cat README.md',
                    ):
                        with self.subTest(fault=fault, nested=nested, command=command):
                            self.assertEqual(helper.request(root, 'exec_command', {
                                'cmd': command, 'workdir': str(root),
                            }), 'deny')
                self.assertEqual(helper.request(root, 'exec_command', {
                    'cmd': 'cat README.md && cat sub/PUBLIC.md', 'workdir': str(root),
                }), 'allow' if fault is None else 'deny')

    def test_external_recursive_targets_are_checked_and_public_file_aliases_stay_public(self) -> None:
        helper = authority.ReadAuthorityTests()
        for fault in authority.FAULTS:
            with project_copy() as root:
                helper.fixture(root, fault)
                (root / '.getzilla/config/policy.json').write_text(json.dumps({
                    'schema_version': 2,
                    'secret_read_paths': legacy.DEFAULT_SECRET_READ,
                }), encoding='utf-8')
                external = root.parent / 'external'
                external.mkdir()
                private = external / 'private'
                private.mkdir()
                (private / 'server.key').write_text('synthetic no-secret marker\n', encoding='utf-8')
                public = external / 'public'
                public.mkdir()
                (public / 'PUBLIC.md').write_text('synthetic public text\n', encoding='utf-8')
                (root / 'private-alias').symlink_to(private, target_is_directory=True)
                (root / 'public-alias').symlink_to(public, target_is_directory=True)
                (root / 'sub/.ssh/known_hosts').unlink()
                (root / 'sub/.ssh/known_hosts').symlink_to(public / 'PUBLIC.md')
                for path in (private, root / 'private-alias', private / 'server.key'):
                    with self.subTest(fault=fault, path=path):
                        self.assertEqual(helper.request(root, 'Grep', {
                            'pattern': 'synthetic', 'path': str(path),
                        }), 'deny')
                for path in (public / 'PUBLIC.md', root / 'sub/.ssh/known_hosts'):
                    for tool, inputs in (
                        ('Read', {'file_path': str(path)}),
                        ('exec_command', {'cmd': 'cat ' + str(path), 'workdir': str(root)}),
                    ):
                        with self.subTest(fault=fault, tool=tool, path=path):
                            self.assertEqual(helper.request(root, tool, inputs), 'allow')
                if fault is None:
                    for path, expected in ((private, 'deny'), (root / 'private-alias', 'deny'),
                                           (public, 'allow'), (root / 'public-alias', 'allow')):
                        with self.subTest(shell_recursive=path):
                            self.assertEqual(helper.request(root, 'exec_command', {
                                'cmd': 'grep -r synthetic ' + str(path), 'workdir': str(root),
                            }), expected)
                    for path in (public, root / 'public-alias'):

                        with self.subTest(path=path):
                            self.assertEqual(helper.request(root, 'Grep', {
                                'pattern': 'synthetic', 'path': str(path),
                            }), 'allow')

    def test_recursive_metadata_errors_and_budgets_refuse_instead_of_skipping(self) -> None:
        from unittest.mock import patch
        with project_copy() as root:
            public = root.parent / 'public'
            public.mkdir()
            (public / 'PUBLIC.md').write_text('synthetic public text\n', encoding='utf-8')
            with patch.object(legacy.os, 'scandir', side_effect=PermissionError('synthetic metadata error')):
                self.assertIsNotNone(legacy.read_secret_reference(
                    root, 'Grep', {'path': str(public)}, legacy.DEFAULT_SECRET_READ,
                ))
            with patch.object(legacy, '_SCAN_ENTRY_LIMIT', 0):
                self.assertIsNotNone(legacy.read_secret_reference(
                    root, 'Grep', {'path': str(public)}, legacy.DEFAULT_SECRET_READ,
                ))

    def test_implicit_recursive_shell_reads_use_the_current_scope(self) -> None:
        with project_copy() as root:
            (root / 'server.key').write_text('synthetic no-secret marker\n', encoding='utf-8')
            (root / 'patterns.txt').write_text('synthetic\n', encoding='utf-8')
            for command in ('rg synthetic', 'grep -r synthetic', 'rg -f patterns.txt', 'grep -r -f patterns.txt'):
                with self.subTest(command=command):
                    self.assertIsNotNone(legacy.shell_secret_reference(root, command, legacy.DEFAULT_SECRET_READ))
            public = root / 'public'
            public.mkdir()
            (public / 'PUBLIC.md').write_text('synthetic public text\n', encoding='utf-8')
            self.assertIsNone(legacy.shell_secret_reference(
                root, 'rg synthetic', legacy.DEFAULT_SECRET_READ, execution_cwd=public,
            ))
