"""Canonical Git observations use owned ordinary fixtures, never callbacks."""
from contextlib import nullcontext
from pathlib import Path, PureWindowsPath
import os
import subprocess
import tempfile
import unittest
import time
from types import SimpleNamespace
from unittest.mock import patch

from getzilla import architecture_diff as git


class GitReadViewTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'project'
        self.root.mkdir(mode=0o755)
        self.command('init', '-q')
        self.command('config', 'user.name', 'Fixture')
        self.command('config', 'user.email', 'fixture@example.invalid')
        self.command('config', 'gc.auto', '0')
        self.command('config', 'maintenance.auto', 'false')
        (self.root / 'value.txt').write_text('before\n')
        self.command('add', '.')
        self.command('commit', '-qm', 'baseline')
        self.head = self.command('rev-parse', 'HEAD').decode().strip()

    def command(self, *args, root=None):
        return subprocess.run(['git', *args], cwd=root or self.root,
            env=git._git_environment(), capture_output=True, check=True, timeout=10).stdout

    def test_ordinary_darwin_read_resolves_commit_through_checked_objects_directory(self):
        from getzilla import git_read_view
        with patch.object(git_read_view.sys, 'platform', 'darwin'), patch.object(
            git_read_view.fsx, 'held_directory_address', side_effect=AssertionError('unexpected native address')
        ):
            self.assertEqual(git._exact_commit(self.root, self.head, label='base_sha'), self.head)

    def test_worktree_and_info_attributes_cannot_change_canonical_byte_diff(self):
        (self.root / '.gitattributes').write_text('value.txt -diff\n')
        (self.root / '.git/info/attributes').write_text('value.txt -diff\n')
        self.command('add', '.gitattributes')
        self.command('commit', '-qm', 'ordinary attribute data')
        head = self.command('rev-parse', 'HEAD').decode().strip()
        (self.root / 'value.txt').write_text('after!\n')
        result = git._git(self.root, ['diff', '--no-ext-diff', '--no-textconv',
            '--no-renames', '--numstat', head, '--'])
        self.assertEqual(result, b'1\t1\tvalue.txt\n')

    def test_private_child_metadata_keeps_original_head_index_and_registration(self):
        original_index = (self.root / '.git/index').read_bytes()
        original_mtime = (self.root / '.git/index').stat().st_mtime_ns
        original_config = (self.root / '.git/config').read_bytes()
        calls = []
        run = git._run_capped
        def inspect(command, **options):
            if 'status' in command:
                calls.append((list(command), dict(options['env'])))
                directory = next(part.split('=', 1)[1] for part in command if part.startswith('--git-dir='))
                self.assertEqual((Path(directory)/'index').stat().st_mtime_ns, original_mtime)
            return run(command, **options)
        with patch.object(git, '_run_capped', side_effect=inspect):
            self.assertEqual(git._git(self.root, ['status', '--porcelain=v1']), b'')
        self.assertTrue(calls)
        command, environment = calls[-1]
        directories = [part.removeprefix('--git-dir=') for part in command if part.startswith('--git-dir=')]
        self.assertEqual(len(directories), 1)
        self.assertNotEqual(Path(directories[0]), self.root / '.git')
        self.assertTrue(any(part.startswith('--attr-source=') for part in command))
        self.assertEqual(environment['GIT_NO_LAZY_FETCH'], '1')
        self.assertEqual((self.root / '.git/index').read_bytes(), original_index)
        self.assertEqual((self.root / '.git/config').read_bytes(), original_config)

    def test_head_tree_and_linked_worktree_metadata_identity_remain_original(self):
        linked = Path(self.directory.name) / 'linked'
        self.command('worktree', 'add', '-q', '-b', 'linked', str(linked))
        self.assertEqual(git._git(linked, ['rev-parse', 'HEAD']).decode().strip(), self.head)
        for flag in ('--absolute-git-dir', '--git-common-dir'):
            actual = git._git(linked, ['rev-parse', flag]).decode().strip()
            expected = self.command('rev-parse', flag, root=linked).decode().strip()
            self.assertEqual(Path(actual).resolve(), (linked / expected).resolve())
        self.assertEqual(git._git(linked, ['rev-parse', 'HEAD^{tree}']), self.command('rev-parse', 'HEAD^{tree}'))
        (linked / 'value.txt').write_text('after!\n')
        self.assertIn(b' M value.txt', git._git(linked, ['status', '--porcelain=v1']))

    def test_ordinary_remote_symbolic_reference_is_copied(self):
        self.command('symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/heads/main')
        self.assertEqual(git._git(self.root, ['rev-parse', 'HEAD']), self.head.encode()+b'\n')
        self.assertEqual(git._git(self.root, ['symbolic-ref', 'refs/remotes/origin/HEAD']), b'refs/heads/main\n')

    def test_strict_configuration_above_relaxed_graph_limit_is_supported(self):
        config = self.root/'.git/config'
        with config.open('a') as stream:
            for number in range(300):
                stream.write(f'[branch "ordinary-{number}"]\n remote = origin\n merge = refs/heads/ordinary-{number}\n')
        self.assertGreater(config.stat().st_size, 16_384)
        original = config.read_bytes()
        self.assertEqual(git._git(self.root, ['rev-parse', 'HEAD']), self.head.encode()+b'\n')
        self.assertEqual(config.read_bytes(), original)

    def test_merge_tree_matches_real_merge_and_keeps_computed_objects_private(self):
        self.command('checkout', '-qb', 'left')
        (self.root/'left.txt').write_text('left branch\n')
        self.command('add', 'left.txt')
        self.command('commit', '-qm', 'left')
        left = self.command('rev-parse', 'HEAD').decode().strip()
        self.command('checkout', '-qb', 'right', self.head)
        (self.root/'right.txt').write_text('right branch\n')
        self.command('add', 'right.txt')
        self.command('commit', '-qm', 'right')
        right = self.command('rev-parse', 'HEAD').decode().strip()
        def snapshot():
            metadata = self.root/'.git'
            paths = [metadata/'HEAD', metadata/'index', *sorted((metadata/'refs').rglob('*')),
                     *sorted((metadata/'objects').rglob('*'))]
            return {str(path.relative_to(metadata)): path.read_bytes() for path in paths if path.is_file()}
        before = snapshot()
        computed = git.run_git_bounded(self.root, ['merge-tree', '--write-tree', left, right]).strip()
        self.assertRegex(computed, rb'^[a-f0-9]{40}$')
        self.assertEqual(snapshot(), before)
        self.assertEqual(self.command('status', '--porcelain=v1'), b'')
        absent = subprocess.run(['git', 'cat-file', '-e', computed.decode()], cwd=self.root,
            env=git._git_environment(), capture_output=True, timeout=10)
        self.assertNotEqual(absent.returncode, 0, 'computed tree leaked into original object store')
        self.command('merge', '--no-ff', '-qm', 'real merge', 'left')
        expected = self.command('rev-parse', 'HEAD^{tree}').strip()
        self.assertEqual(computed, expected)
        before = snapshot()
        self.assertEqual(git.run_git_bounded(self.root, ['merge-tree', '--write-tree', left, right]).strip(), expected)
        self.assertEqual(snapshot(), before)
        self.assertEqual(self.command('status', '--porcelain=v1'), b'')

    def test_merge_tree_accepts_only_exact_same_format_full_object_ids(self):
        from getzilla.git_read_view import validate_arguments
        for size in (40, 64):
            validate_arguments(['merge-tree', '--write-tree', 'a'*size, 'b'*size])
        malformed = (['merge-tree', '--write-tree', 'HEAD', 'a'*40],
            ['merge-tree', '--write-tree', 'a'*40, 'b'*64],
            ['merge-tree', '--write-tree', 'a'*39, 'b'*40],
            ['merge-tree', '--write-tree', 'A'*40, 'b'*40],
            ['merge-tree', '--write-tree', 'g'*40, 'b'*40],
            ['merge-tree', '--write-tree', 'a'*40, 'b'*40, '--allow-unrelated-histories'],
            ['merge-tree', '--trivial-merge', 'a'*40, 'b'*40],
            ['-c', 'protocol.allow=never', 'merge-tree', '--write-tree', 'a'*40, 'b'*40])
        with patch.object(git, '_run_capped', side_effect=AssertionError('child must not run')):
            for arguments in malformed:
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    git.run_git_read(self.root, arguments)

    @unittest.skipUnless(os.name == 'posix', 'owned symbolic temporary alias fixture')
    def test_private_metadata_normalizes_temporary_parent_alias(self):
        physical = Path(self.directory.name)/'physical-temp'
        physical.mkdir(mode=0o700)
        alias = Path(self.directory.name)/'temporary-alias'
        alias.symlink_to(physical, target_is_directory=True)
        calls = []
        run = git._run_capped
        def inspect(command, **options):
            for part in command:
                if part.startswith('--git-dir='):
                    calls.append(Path(part.split('=', 1)[1]))
            return run(command, **options)
        with patch.object(tempfile, 'tempdir', str(alias)), \
                patch.object(git, '_run_capped', side_effect=inspect):
            self.assertEqual(git._git(self.root, ['rev-parse', 'HEAD']), self.head.encode()+b'\n')
        self.assertTrue(calls)
        self.assertTrue(all(path.parent == physical for path in calls))
        self.assertFalse(list(physical.iterdir()), 'private temporary metadata was retained')

    def test_read_runner_rejects_writes_without_entering_child(self):
        with patch.object(git, '_run_capped', side_effect=AssertionError('child must not run')):
            for arguments in (['config', 'user.name', 'changed'],
                    ['config', '--get', '--file=/tmp/foreign', 'user.name'],
                    ['config', '--get', '-f', '/tmp/foreign', 'user.name'],
                    ['config', '--get', '--global', 'user.name'],
                    ['config', '--get', '--system', 'user.name'],
                    ['diff', '--no-index', '/tmp/one', '/tmp/two']):
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    git.run_git_read(self.root, arguments)
        self.assertEqual(self.command('config', 'user.name'), b'Fixture\n')


class WindowsGitReadPathProjectionTests(unittest.TestCase):
    def test_private_directory_translation_preserves_original_native_identity(self):
        original = SimpleNamespace(root=PureWindowsPath(r'D:\a\Project'),
            git_directory=PureWindowsPath(r'D:\canonical\.git\worktrees\linked'),
            common_directory=PureWindowsPath(r'D:\canonical\.git'))
        view = SimpleNamespace(path=PureWindowsPath(r'C:\Users\Runner\Temp\getzilla-git-read-owned'))
        arguments = ['rev-parse', '--absolute-git-dir', '--show-toplevel', '--is-bare-repository']
        for spelling in ('C:/Users/Runner/Temp/getzilla-git-read-owned',
                         r'C:\Users\Runner\Temp\getzilla-git-read-owned',
                         'c:/users/runner/temp/GETZILLA-GIT-READ-OWNED'):
            with self.subTest(spelling=spelling):
                emitted = spelling.encode()+b'\r\nD:/a/Project\r\nfalse\r\n'
                child = (['git'], {}, (), time.monotonic()+30, original, view)
                with patch.object(git.fsx, 'WINDOWS', True), \
                        patch.object(git, '_read_git_child', return_value=nullcontext(child)), \
                        patch.object(git, '_run_capped', return_value=(0, emitted, b'')):
                    code, output, error = git.run_git_read(original.root, arguments)
                    self.assertEqual(code, 0)
                    self.assertEqual(error, b'')
                    self.assertEqual(output.splitlines()[0], str(original.git_directory).encode())
                    self.assertTrue(git._reported_git_paths_match(output, original.git_directory, original.root))
                    for query, expected in ((['rev-parse', '--git-common-dir'], original.common_directory),
                            (['rev-parse', '--git-path', 'index'], original.git_directory/'index'),
                            (['rev-parse', '--git-path', 'objects'], original.common_directory/'objects')):
                        self.assertEqual(git.run_git_read(original.root, query)[1], str(expected).encode()+b'\n')

    def test_foreign_private_directory_and_similar_prefix_cannot_become_original(self):
        original = SimpleNamespace(root=PureWindowsPath(r'D:\a\Project'),
            git_directory=PureWindowsPath(r'D:\canonical\.git\worktrees\linked'))
        view = SimpleNamespace(path=PureWindowsPath(r'C:\Temp\getzilla-git-read-owned'))
        arguments = ['rev-parse', '--absolute-git-dir', '--show-toplevel', '--is-bare-repository']
        for foreign in ('C:/Temp/getzilla-git-read-owned-foreign', 'C:/elsewhere/getzilla-git-read-owned'):
            emitted = foreign.encode()+b'\nD:/a/Project\nfalse\n'
            child = (['git'], {}, (), time.monotonic()+30, original, view)
            with self.subTest(foreign=foreign), patch.object(git.fsx, 'WINDOWS', True), \
                    patch.object(git, '_read_git_child', return_value=nullcontext(child)), \
                    patch.object(git, '_run_capped', return_value=(0, emitted, b'')):
                output = git.run_git_read(original.root, arguments)[1]
                self.assertEqual(output, emitted)
                self.assertFalse(git._reported_git_paths_match(output, original.git_directory, original.root))
