from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.branch_support import ROOT, commit, env, git

from getzilla import review_snapshot  # noqa: E402
from getzilla.worktree_safety import WorktreeError  # noqa: E402


class ReviewSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        patcher = patch.dict(os.environ, env(), clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root = self.base / 'project'
        self.root.mkdir()
        git(self.root, 'init', '-q', '-b', 'main')
        (self.root / '.gitignore').write_text('.getzilla/runtime/\n')
        git(self.root, 'add', '.gitignore')
        self.first = commit(self.root, 'app.py', 'value = 1\n', 'first')
        self.second = commit(self.root, 'app.py', 'value = 2\n', 'second')
        self.snapshots = self.root / '.getzilla' / 'runtime' / 'snapshots'

    def registered(self) -> list[str]:
        return [line[len('worktree '):] for line in git(self.root, 'worktree', 'list', '--porcelain').splitlines()
                if line.startswith('worktree ')]

    def test_a_snapshot_is_a_private_detached_worktree_removed_once_with_its_marker(self) -> None:
        path = review_snapshot.create(self.root, self.first)
        self.assertEqual(path.parent, self.snapshots)
        self.assertEqual(stat.S_IMODE(os.stat(self.snapshots).st_mode), 0o700)
        self.assertEqual((path / 'app.py').read_text(), 'value = 1\n')
        self.assertEqual(git(path, 'rev-parse', 'HEAD'), self.first)
        marker = json.loads((self.snapshots / f'{path.name}.json').read_text())
        self.assertEqual(marker['commit'], self.first)
        branches = git(self.root, 'branch', '--list')
        (path / 'app.py').write_text('mutant\n')  # reviewer probes are discarded on purpose
        (path / 'probe.py').write_text('x = 1\n')
        self.assertEqual(review_snapshot.remove(self.root, str(path))['result'], 'removed')
        self.assertFalse(path.exists())
        self.assertFalse((self.snapshots / f'{path.name}.json').exists())
        self.assertNotIn(str(path), self.registered())
        self.assertEqual(git(self.root, 'branch', '--list'), branches)
        self.assertEqual(review_snapshot.remove(self.root, str(path))['result'], 'kept')

    def test_a_snapshot_deleted_by_hand_leaves_only_its_marker_to_clean(self) -> None:
        path = review_snapshot.create(self.root, 'HEAD')
        git(self.root, 'worktree', 'remove', '--force', str(path))
        self.assertEqual(review_snapshot.remove(self.root, str(path))['result'], 'absent')
        self.assertFalse((self.snapshots / f'{path.name}.json').exists())

    def test_only_our_own_snapshot_at_its_marked_commit_is_removed(self) -> None:
        task = self.root / '.getzilla' / 'runtime' / 'worktrees' / 'task'
        git(self.root, 'worktree', 'add', '-q', '-b', 'task', str(task))
        moved = review_snapshot.create(self.root, self.first)
        git(moved, 'checkout', '-q', '--detach', self.second)
        unmarked = review_snapshot.create(self.root, self.first)
        (self.snapshots / f'{unmarked.name}.json').unlink()
        locked = review_snapshot.create(self.root, self.first)
        git(self.root, 'worktree', 'lock', str(locked))
        on_branch = self.snapshots / 'on-branch'
        git(self.root, 'worktree', 'add', '-q', '-b', 'on-branch', str(on_branch))
        (self.snapshots / 'on-branch.json').write_text(json.dumps({'schema_version': review_snapshot.SCHEMA,
                                                                    'commit': self.second}))
        cases = [task, self.snapshots / '..' / 'worktrees' / 'task', moved, unmarked, locked, on_branch,
                 self.snapshots / f'{locked.name}.json', self.root]
        for path in cases:
            with self.subTest(path=path):
                result = review_snapshot.remove(self.root, str(path))
                self.assertEqual(result['result'], 'kept', result)
        for path in (task, moved, unmarked, locked, on_branch):
            self.assertTrue(path.is_dir(), path)

    def test_a_snapshot_replaced_by_a_link_never_deletes_the_target(self) -> None:
        path = review_snapshot.create(self.root, self.first)
        victim = self.base / 'victim'
        victim.mkdir()
        (victim / 'data.txt').write_text('unique')
        (victim / '.git').write_text((path / '.git').read_text())  # a forged worktree link
        git(self.root, 'worktree', 'remove', '--force', str(path))
        git(self.root, 'worktree', 'add', '-q', '--detach', str(path), self.first)
        (self.snapshots / f'{path.name}.json').write_text(json.dumps({'schema_version': review_snapshot.SCHEMA,
                                                                      'commit': self.first}))
        moved = self.base / 'moved-snapshot'
        path.rename(moved)
        try:
            path.symlink_to(victim, target_is_directory=True)
        except OSError:
            self.skipTest('symlinks unavailable')
        self.assertEqual(review_snapshot.remove(self.root, str(path))['result'], 'kept')
        self.assertEqual((victim / 'data.txt').read_text(), 'unique')

    def test_a_task_worktree_with_a_forged_marker_is_kept(self) -> None:
        task = self.root / '.getzilla' / 'runtime' / 'worktrees' / 'detached'
        git(self.root, 'worktree', 'add', '-q', '--detach', str(task), self.first)
        self.snapshots.mkdir(parents=True)
        (self.snapshots / 'detached.json').write_text(json.dumps({'schema_version': review_snapshot.SCHEMA,
                                                                  'commit': self.first}))
        self.assertEqual(review_snapshot.remove(self.root, str(task))['result'], 'kept')
        self.assertTrue((task / 'app.py').is_file())

    def test_a_linked_snapshots_folder_is_refused(self) -> None:
        outside = self.base / 'outside'
        outside.mkdir()
        self.snapshots.parent.mkdir(parents=True)
        try:
            self.snapshots.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('symlinks unavailable')
        with self.assertRaises(WorktreeError):
            review_snapshot.create(self.root, 'HEAD')
        self.assertEqual(list(outside.iterdir()), [])

    def test_an_unknown_commit_leaves_no_marker(self) -> None:
        with self.assertRaises(WorktreeError):
            review_snapshot.create(self.root, 'no-such-commit')
        self.assertFalse(self.snapshots.exists() and any(self.snapshots.iterdir()))

    def test_an_option_shaped_revision_is_not_read_as_an_option(self) -> None:
        for revision in ('--all', '--git-dir', '-q'):
            with self.subTest(revision=revision), self.assertRaises(WorktreeError):
                review_snapshot.create(self.root, revision)
        self.assertFalse(self.snapshots.exists() and any(self.snapshots.iterdir()))

    def test_an_annotated_tag_is_peeled_to_its_commit(self) -> None:
        git(self.root, 'tag', '-a', '-m', 'release', 'v1', self.first)
        path = review_snapshot.create(self.root, 'v1')
        marker = json.loads((self.snapshots / f'{path.name}.json').read_text())
        self.assertEqual(marker['commit'], self.first)
        self.assertEqual(review_snapshot.remove(self.root, str(path))['result'], 'removed')

    def test_a_failed_worktree_add_leaves_no_marker(self) -> None:
        real_git = review_snapshot._git

        def failing(root, *args):
            if args[:2] == ('worktree', 'add'):
                raise WorktreeError('worktree add failed')
            return real_git(root, *args)

        with patch('getzilla.review_snapshot._git', side_effect=failing), self.assertRaises(WorktreeError):
            review_snapshot.create(self.root, self.first)
        self.assertEqual(list(self.snapshots.iterdir()), [])

    def test_a_snapshot_made_from_a_task_worktree_lives_under_the_main_worktree(self) -> None:
        task = self.root / '.getzilla' / 'runtime' / 'worktrees' / 'task'
        git(self.root, 'worktree', 'add', '-q', '-b', 'task', str(task))
        path = review_snapshot.create(task, self.first)
        self.assertEqual(path.parent, self.snapshots)
        self.assertFalse((task / '.getzilla' / 'runtime' / 'snapshots').exists())
        self.assertEqual(review_snapshot.remove(task, str(path))['result'], 'removed')

    def test_a_marker_with_another_schema_is_not_an_owner_marker(self) -> None:
        path = review_snapshot.create(self.root, self.first)
        marker = self.snapshots / f'{path.name}.json'
        marker.write_text(json.dumps({'schema_version': 'other', 'commit': self.first}))
        result = review_snapshot.remove(self.root, str(path))
        self.assertEqual((result['result'], result['reason']), ('kept', 'no owner marker'))
        self.assertTrue(path.is_dir())

    @unittest.skipIf(os.name == 'nt', 'POSIX modes')
    def test_an_existing_snapshots_folder_is_made_private(self) -> None:
        self.snapshots.mkdir(parents=True, mode=0o755)
        os.chmod(self.snapshots, 0o755)
        review_snapshot.create(self.root, self.first)
        self.assertEqual(stat.S_IMODE(os.stat(self.snapshots).st_mode), 0o700)

    def test_a_marker_next_to_an_unregistered_folder_is_kept(self) -> None:
        self.snapshots.mkdir(parents=True)
        plain = self.snapshots / 'plain'
        plain.mkdir()
        (plain / 'work.txt').write_text('unique')
        marker = self.snapshots / 'plain.json'
        marker.write_text(json.dumps({'schema_version': review_snapshot.SCHEMA, 'commit': self.first}))
        result = review_snapshot.remove(self.root, str(plain))
        self.assertEqual((result['result'], result['reason']), ('kept', 'not a registered snapshot worktree'))
        self.assertEqual((plain / 'work.txt').read_text(), 'unique')
        self.assertTrue(marker.is_file())

    def test_cli_creates_and_removes_a_snapshot(self) -> None:
        (self.root / '.getzilla').mkdir(exist_ok=True)  # find_root must stop here, not at an outer project
        cli = [sys.executable, str(ROOT / 'scripts' / 'getzilla_cleanup.py'), 'snapshot']
        for remove_first in (True, False):
            with self.subTest(remove_first=remove_first):
                created = json.loads(subprocess.run([*cli, self.second, '--json'], cwd=self.root, capture_output=True,
                                                    text=True, check=True).stdout)
                self.assertEqual(created['result'], 'created')
                path = created['path']
                invalid = subprocess.run([*cli, '--remove', path, 'unexpected'], cwd=self.root,
                                         capture_output=True, text=True)
                self.assertEqual(invalid.returncode, 2)
                self.assertTrue(Path(path).is_dir())
                args = ['--remove', path] if remove_first else [path, '--remove']
                removed = subprocess.run([*cli, *args], cwd=self.root, capture_output=True, text=True)
                self.assertEqual(removed.returncode, 0, removed.stderr)
                self.assertIn('removed:', removed.stdout)
        refused = subprocess.run([*cli, '--remove', str(self.root)], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(refused.returncode, 1)


if __name__ == '__main__':
    unittest.main()
