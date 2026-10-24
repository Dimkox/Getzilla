from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.branch_support import ROOT, commit, env, git

from getzilla.worktree_safety import list_worktrees, plan, remove  # noqa: E402

PROCESS_CHECK = Path('/proc/self/cwd').exists()


class WorktreeSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        patcher = patch.dict(os.environ, env(), clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        origin = self.base / 'origin.git'
        subprocess.run(['git', 'init', '-q', '--bare', '-b', 'main', str(origin)], check=True, env=env())
        self.root = self.base / 'project'
        subprocess.run(['git', 'clone', '-q', str(origin), str(self.root)], check=True, env=env(),
                       capture_output=True)
        git(self.root, 'checkout', '-q', '-b', 'main')
        (self.root / '.gitignore').write_text('.getzilla/runtime/\n__pycache__/\n')
        git(self.root, 'add', '.gitignore')
        commit(self.root, 'app.py', 'value = 1\n', 'base')
        git(self.root, 'push', '-q', 'origin', 'main')
        self.worktrees = self.root / '.getzilla' / 'runtime' / 'worktrees'

    def add(self, name: str, *extra: str) -> Path:
        path = self.worktrees / name
        git(self.root, 'worktree', 'add', '-q', *extra, str(path), 'origin/main')
        return path

    def report(self, path: Path) -> dict:
        return next(item for item in plan(self.root)['worktrees'] if item['path'] == str(path))

    @unittest.skipUnless(PROCESS_CHECK, 'removal needs the /proc process check')
    def test_a_clean_pushed_worktree_is_removed_once_and_its_branch_stays(self) -> None:
        path = self.add('clean', '-b', 'clean')
        self.assertTrue(self.report(path)['removable'])
        self.assertEqual(remove(self.root, str(path))['result'], 'removed')
        self.assertFalse(path.exists())
        self.assertEqual(git(self.root, 'branch', '--list', 'clean'), 'clean')
        self.assertEqual(remove(self.root, str(path))['result'], 'absent')

    def test_changes_untracked_files_and_local_commits_keep_the_worktree(self) -> None:
        tracked = self.add('tracked', '-b', 'tracked')
        (tracked / 'app.py').write_text('value = 2\n')
        staged = self.add('staged', '-b', 'staged')
        (staged / 'new.py').write_text('x = 1\n')
        git(staged, 'add', 'new.py')
        untracked = self.add('untracked', '-b', 'untracked')
        (untracked / 'notes.txt').write_text('unique')
        local = self.add('local', '-b', 'local')
        commit(local, 'app.py', 'value = 3\n', 'local only')
        expected = {tracked: 'tracked or staged', staged: 'tracked or staged', untracked: 'untracked file',
                    local: 'commits not on any remote-tracking ref'}
        for path, reason in expected.items():
            report = self.report(path)
            self.assertFalse(report['removable'], path)
            self.assertTrue(any(reason in item for item in report['reasons']), report['reasons'])
            self.assertEqual(remove(self.root, str(path))['result'], 'kept')
            self.assertTrue(path.is_dir())
        self.assertEqual((untracked / 'notes.txt').read_text(), 'unique')

    @unittest.skipUnless(PROCESS_CHECK, 'removal needs the /proc process check')
    def test_pushed_commits_and_a_pushed_detached_head_are_removable(self) -> None:
        local = self.add('pushed', '-b', 'pushed')
        commit(local, 'app.py', 'value = 4\n', 'pushed later')
        self.assertFalse(self.report(local)['removable'])
        git(local, 'push', '-q', 'origin', 'pushed')
        self.assertTrue(self.report(local)['removable'])
        detached = self.add('detached', '--detach')
        report = self.report(detached)
        self.assertTrue(report['detached'])
        self.assertTrue(report['removable'], report['reasons'])

    @unittest.skipUnless(PROCESS_CHECK, 'removal needs the /proc process check')
    def test_ignored_runtime_state_keeps_the_worktree_but_caches_and_runner_logs_do_not(self) -> None:
        path = self.add('ignored', '-b', 'ignored')
        (path / '__pycache__').mkdir()
        (path / '__pycache__' / 'app.cpython-313.pyc').write_bytes(b'\0')
        (path / '.getzilla' / 'runtime' / 'par' / 'run-1').mkdir(parents=True)
        (path / '.getzilla' / 'runtime' / 'par' / 'run-1' / 'log').write_text('x')
        self.assertTrue(self.report(path)['removable'], self.report(path)['reasons'])
        (path / '.getzilla' / 'runtime' / 'receipts').mkdir()
        (path / '.getzilla' / 'runtime' / 'receipts' / 'r.json').write_text('{}')
        report = self.report(path)
        self.assertFalse(report['removable'])
        self.assertIn('.getzilla/runtime/receipts/r.json', report['valuable_ignored'])

    def test_a_symlink_in_ignored_output_keeps_the_worktree_and_its_target(self) -> None:
        path = self.add('linked', '-b', 'linked')
        outside = self.base / 'precious'
        outside.mkdir()
        (outside / 'work.txt').write_text('unique')
        (path / '.getzilla' / 'runtime' / 'par').mkdir(parents=True)
        try:
            (path / '.getzilla' / 'runtime' / 'par' / 'escape').symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('symlinks unavailable')
        self.assertFalse(self.report(path)['removable'])
        self.assertEqual(remove(self.root, str(path))['result'], 'kept')
        self.assertEqual((outside / 'work.txt').read_text(), 'unique')

    def test_locked_outside_and_main_worktrees_are_never_removable(self) -> None:
        locked = self.add('locked', '-b', 'locked')
        git(self.root, 'worktree', 'lock', str(locked))
        outside = self.base / 'elsewhere'
        git(self.root, 'worktree', 'add', '-q', '-b', 'elsewhere', str(outside), 'origin/main')
        reports = {item['path']: item for item in plan(self.root)['worktrees']}
        self.assertIn('locked by git worktree lock', reports[str(locked)]['reasons'])
        self.assertIn('outside .getzilla/runtime/worktrees', reports[str(outside)]['reasons'])
        self.assertFalse(reports[str(self.root)]['removable'])
        for path in (locked, outside, self.root):
            self.assertEqual(remove(self.root, str(path))['result'], 'kept')
            self.assertTrue(path.is_dir())

    @unittest.skipUnless(PROCESS_CHECK, 'removal needs the /proc process check')
    def test_removal_inspects_again_and_keeps_work_added_after_the_plan(self) -> None:
        path = self.add('late', '-b', 'late')
        self.assertTrue(self.report(path)['removable'])
        (path / 'late.txt').write_text('written after the plan')
        self.assertEqual(remove(self.root, str(path))['result'], 'kept')
        self.assertEqual((path / 'late.txt').read_text(), 'written after the plan')

    @unittest.skipUnless(PROCESS_CHECK, 'removal needs the /proc process check')
    def test_a_plan_from_inside_a_task_worktree_uses_the_main_runtime_folder(self) -> None:
        current = self.add('current', '-b', 'current')
        sibling = self.add('sibling', '-b', 'sibling')
        reports = {item['path']: item for item in plan(current)['worktrees']}
        self.assertTrue(reports[str(sibling)]['removable'], reports[str(sibling)]['reasons'])
        self.assertEqual(reports[str(current)]['reasons'], ['the current worktree'])

    def test_a_worktree_a_process_works_in_is_kept(self) -> None:
        path = self.add('busy', '-b', 'busy')
        previous = os.getcwd()
        os.chdir(path)
        self.addCleanup(os.chdir, previous)
        self.assertIn('a process works in it', self.report(path)['reasons'])

    def test_cli_dry_run_lists_without_removing(self) -> None:
        path = self.add('dry', '-b', 'dry')
        cli = [sys.executable, str(ROOT / 'scripts' / 'getzilla_cleanup.py'), 'worktrees']
        text = subprocess.run(cli, cwd=self.root, capture_output=True, text=True, check=True).stdout
        self.assertIn('dry run', text)
        self.assertTrue(path.is_dir())
        data = json.loads(subprocess.run([*cli, '--json'], cwd=self.root, capture_output=True, text=True,
                                         check=True).stdout)
        self.assertEqual(data['schema_version'], 'getzilla-worktree-plan-v1')
        self.assertEqual(len(data['worktrees']), len(list_worktrees(self.root)))
        self.assertTrue(path.is_dir())


if __name__ == '__main__':
    unittest.main()
