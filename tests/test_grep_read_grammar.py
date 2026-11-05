"""Utility argv controls: no descriptor command or secret contents are executed/read."""
from __future__ import annotations

import json
import shlex
import unittest
from pathlib import Path

from getzilla import _policy_legacy as legacy
from tests import test_read_authority as authority
from tests._support import project_copy


class GrepReadGrammarTests(unittest.TestCase):
    def fixture(self, root: Path, fault: str | None) -> None:
        authority.ReadAuthorityTests().fixture(root, fault)
        (root / '.getzilla/config/policy.json').write_text(json.dumps({
            'secret_read_paths': [*legacy.DEFAULT_SECRET_READ, 'private-data/**'],
        }), encoding='utf-8')
        (root / 'PUBLIC.md').write_text('synthetic public text\n', encoding='utf-8')
        (root / 'patterns.txt').write_text('synthetic\n', encoding='utf-8')
        (root / 'view.txt').symlink_to('private-data/marker.txt')
        (root / 'public').mkdir()
        (root / 'public/PUBLIC.md').write_text('synthetic public text\n', encoding='utf-8')
        (root / 'public/patterns.txt').write_text('synthetic\n', encoding='utf-8')
        (root / 'server.key').write_text('synthetic no-secret marker\n', encoding='utf-8')

    def check(self, root: Path, argv: list[str], expected: str) -> None:
        self.assertEqual(authority.ReadAuthorityTests().request(root, 'exec_command', {
            'cmd': shlex.join(argv), 'workdir': str(root),
        }), expected)

    def test_real_argument_shapes_keep_pattern_files_and_search_targets(self) -> None:
        rows = (
            (['-e', 'synthetic', 'view.txt'], 'deny'),
            (['-esynthetic', 'view.txt'], 'deny'),
            (['-ne', 'synthetic', 'view.txt'], 'deny'),
            (['-nesynthetic', 'view.txt'], 'deny'),
            (['--regexp=synthetic', 'view.txt'], 'deny'),
            (['view.txt', '--regexp', 'synthetic'], 'deny'),
            (['-f', 'view.txt', 'PUBLIC.md'], 'deny'),
            (['-fview.txt', 'PUBLIC.md'], 'deny'),
            (['-nfview.txt', 'PUBLIC.md'], 'deny'),
            (['--file=view.txt', '-e', 'synthetic', 'PUBLIC.md'], 'deny'),
            (['-fpatterns.txt', '-fview.txt', '-esynthetic', 'PUBLIC.md'], 'deny'),
            (['-e', 'synthetic', '-fview.txt', 'PUBLIC.md'], 'deny'),
            (['-e', 'synthetic', '--', 'view.txt'], 'deny'),
            (['-e', 'view.txt', 'PUBLIC.md'], 'allow'),
            (['-eview.txt', 'PUBLIC.md'], 'allow'),
            (['-nesynthetic', 'PUBLIC.md'], 'allow'),
            (['-fpatterns.txt', '-esynthetic', 'PUBLIC.md'], 'allow'),
            (['-nfpatterns.txt', 'PUBLIC.md'], 'allow'),
            (['--file=patterns.txt', '--regexp', 'synthetic', 'PUBLIC.md'], 'allow'),
            (['PUBLIC.md', '-e', 'synthetic'], 'allow'),
            (['-esynthetic', '--', 'PUBLIC.md'], 'allow'),
            (['--unproved-option', 'synthetic', 'PUBLIC.md'], 'deny'),
            (['-e'], 'deny'),
            (['-f'], 'deny'),
        )
        for fault in authority.FAULTS:
            with project_copy() as root:
                self.fixture(root, fault)
                for executable in ('grep', 'rg'):
                    for args, expected in rows:
                        with self.subTest(fault=fault, executable=executable, args=args):
                            self.check(root, [executable, *args], expected if fault is None else 'deny')

    def test_value_payloads_never_supply_recursive_flags_or_lose_implicit_scope(self) -> None:
        with project_copy() as root:
            self.fixture(root, None)
            for args in (
                ['-fpatterns.txt', 'PUBLIC.md'], ['-f', 'patterns.txt', 'PUBLIC.md'],
                ['-efrR', 'PUBLIC.md'], ['-nFefrR', 'PUBLIC.md'],
                ['--label=rrr', '-esynthetic', 'PUBLIC.md'],
            ):
                with self.subTest(args=args):
                    self.check(root, ['grep', *args], 'allow')
            for executable, args in (
                ('grep', ['-rfpatterns.txt']), ('grep', ['-rnf', 'patterns.txt']),
                ('grep', ['--directories=recurse', '-fpatterns.txt']),
                ('grep', ['-drecurse', '-fpatterns.txt']), ('rg', ['-nfpatterns.txt']),
                ('rg', ['-rR', '-esynthetic', 'view.txt']),
            ):
                with self.subTest(executable=executable, args=args):
                    self.check(root, [executable, *args], 'deny')
            self.check(root, ['env', '-C', 'sub', 'grep', '-esynthetic', 'README.md'], 'deny')

    def test_recursive_grep_cannot_drop_git_and_hidden_protected_descendants(self) -> None:
        for fault in authority.FAULTS:
            with project_copy() as root:
                self.fixture(root, fault)
                external = root.parent / 'external'
                (external / '.git').mkdir(parents=True)
                (external / '.git/server.key').write_text('synthetic no-secret marker\n', encoding='utf-8')
                for options in (['-r'], ['-nr'], ['-R'], ['--directories=recurse'], ['-drecurse']):
                    with self.subTest(fault=fault, options=options):
                        self.check(root, ['grep', *options, '-esynthetic', str(external)], 'deny')
                for options in (['--hidden'], ['-uu'], ['--no-ignore', '--hidden']):
                    with self.subTest(fault=fault, options=options):
                        self.check(root, ['rg', *options, '-esynthetic', str(external)], 'deny')
                for executable, options in (('grep', ['-r']), ('rg', [])):
                    with self.subTest(fault=fault, executable=executable):
                        self.check(root, [executable, *options, '-esynthetic', 'public'],
                                   'allow' if fault is None else 'deny')

    def test_long_values_and_end_of_options_preserve_reads(self) -> None:
        with project_copy() as root:
            self.fixture(root, None)
            for executable, args, expected in (
                ('grep', ['--exclude-from=view.txt', '-esynthetic', 'PUBLIC.md'], 'deny'),
                ('grep', ['--exclude-from=patterns.txt', '-esynthetic', 'PUBLIC.md'], 'allow'),
                ('grep', ['-m1', '-A2', '-B3', '-C4', '-esynthetic', 'PUBLIC.md'], 'allow'),
                ('grep', ['-nrm1', '-esynthetic', 'view.txt'], 'deny'),
                ('rg', ['--ignore-file=view.txt', '-esynthetic', 'PUBLIC.md'], 'deny'),
                ('rg', ['-rview.txt', '-esynthetic', 'PUBLIC.md'], 'allow'),
                ('rg', ['-M80', '-j2', '-g*.md', '-esynthetic', 'PUBLIC.md'], 'allow'),
                ('rg', ['--pre=unproved', '-esynthetic', 'PUBLIC.md'], 'deny'),
                ('rg', ['--files', '-g', '*.md'], 'allow'),
                ('grep', ['--', '-synthetic', 'view.txt'], 'deny'),
                ('rg', ['--', '-synthetic', 'view.txt'], 'deny'),
            ):
                with self.subTest(executable=executable, args=args):
                    self.check(root, [executable, *args], expected)

    def test_explicit_directory_exclusions_and_gnu_aliases_keep_separate_file_inputs(self) -> None:
        with project_copy() as root:
            self.fixture(root, None)
            external = root.parent / 'external'
            (external / '.git').mkdir(parents=True)
            (external / '.git/server.key').write_text('synthetic no-secret marker\n', encoding='utf-8')
            self.check(root, ['grep', '-r', '--exclude-dir=.git', '-esynthetic', str(external)], 'allow')
            self.check(root, ['grep', '-r', '--exclude-dir', '.git', '-fview.txt', str(external)], 'deny')
            self.check(root, ['grep', '-r', '--exclude-dir=.git', '-esynthetic',
                              str(external / '.git/server.key')], 'deny')
            for executable in ('egrep', 'fgrep'):
                for args, expected in ((['-nfview.txt', 'PUBLIC.md'], 'deny'),
                                       (['-nfpatterns.txt', 'PUBLIC.md'], 'allow'),
                                       (['-nesynthetic', 'view.txt'], 'deny'),
                                       (['-nesynthetic', 'PUBLIC.md'], 'allow')):
                    with self.subTest(executable=executable, args=args):
                        self.check(root, [executable, *args], expected)
