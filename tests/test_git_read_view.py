"""Canonical Git observations use owned ordinary fixtures, never callbacks."""
from pathlib import Path
import subprocess
import tempfile
import unittest
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
