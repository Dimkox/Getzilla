from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
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
        wanted = os.path.realpath(path)  # Git records a linked path resolved
        return next(item for item in plan(self.root)['worktrees'] if os.path.realpath(item['path']) == wanted)

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

    def test_edits_hidden_by_index_bits_keep_the_worktree(self) -> None:
        for flag in ('--skip-worktree', '--assume-unchanged'):
            with self.subTest(flag=flag):
                path = self.add(flag.strip('-'), '-b', flag.strip('-'))
                git(path, 'update-index', flag, 'app.py')
                (path / 'app.py').write_text('value = 99  # unique edit\n')
                self.assertEqual(git(path, 'status', '--porcelain'), '')
                report = self.report(path)
                self.assertIn('app.py', report['hidden_from_status'])
                self.assertEqual(remove(self.root, str(path))['result'], 'kept')
                self.assertEqual((path / 'app.py').read_text(), 'value = 99  # unique edit\n')

    @unittest.skipUnless(PROCESS_CHECK, 'removal needs the /proc process check')
    def test_a_sparse_checkout_without_the_file_on_disk_is_removable(self) -> None:
        path = self.add('sparse', '-b', 'sparse')
        git(path, 'update-index', '--skip-worktree', 'app.py')
        (path / 'app.py').unlink()
        self.assertTrue(self.report(path)['removable'], self.report(path)['reasons'])

    def test_commits_only_a_worktree_ref_or_the_head_reflog_reaches_keep_it(self) -> None:
        kept_ref = self.add('worktree-ref', '--detach')
        commit(kept_ref, 'app.py', 'value = 5\n', 'only in refs/worktree')
        git(kept_ref, 'update-ref', 'refs/worktree/keep', 'HEAD')
        git(kept_ref, 'checkout', '-q', '--detach', 'origin/main')
        # Only refs/worktree reaches that commit now; the reflog worktree is added after the expiry.
        git(kept_ref, 'reflog', 'expire', '--expire=now', '--all')
        reflog = self.add('reflog', '--detach')
        commit(reflog, 'app.py', 'value = 6\n', 'only in the reflog')
        git(reflog, 'checkout', '-q', '--detach', 'origin/main')
        for path in (kept_ref, reflog):
            report = self.report(path)
            self.assertIn('commits not on any remote-tracking ref', report['reasons'], path)
            self.assertEqual(remove(self.root, str(path))['result'], 'kept')

    def test_a_failed_head_reflog_read_keeps_the_worktree(self) -> None:
        from getzilla import worktree_safety
        path = self.add('reflog-error', '-b', 'reflog-error')
        real_git = worktree_safety._git

        def failing(worktree, *args):
            if args[:2] == ('reflog', 'show'):
                raise worktree_safety.WorktreeError('reflog unreadable')
            return real_git(worktree, *args)

        with patch('getzilla.worktree_safety._git', side_effect=failing):
            report = self.report(path)
        self.assertFalse(report['removable'])
        self.assertIn('check failed: reflog unreadable', report['reasons'])

    def test_an_operation_in_progress_keeps_the_worktree(self) -> None:
        path = self.add('merging', '-b', 'merging')
        git_dir = Path(git(path, 'rev-parse', '--absolute-git-dir'))
        (git_dir / 'MERGE_HEAD').write_text(git(path, 'rev-parse', 'HEAD') + '\n')
        self.assertIn('operation in progress: MERGE_HEAD', self.report(path)['reasons'])
        (git_dir / 'MERGE_HEAD').unlink()
        (git_dir / 'sequencer').mkdir()  # a multi-commit cherry-pick between steps
        self.assertIn('operation in progress: sequencer', self.report(path)['reasons'])

    def test_a_bisect_ref_and_a_long_reflog_keep_the_worktree(self) -> None:
        bisect = self.add('bisect', '--detach')
        commit(bisect, 'app.py', 'value = 7\n', 'only in refs/bisect')
        git(bisect, 'update-ref', 'refs/bisect/bad', 'HEAD')
        git(bisect, 'checkout', '-q', '--detach', 'origin/main')
        git(bisect, 'reflog', 'expire', '--expire=now', '--all')
        self.assertIn('commits not on any remote-tracking ref', self.report(bisect)['reasons'])
        long_log = self.add('long-log', '-b', 'long-log')
        git(long_log, 'checkout', '-q', '--detach', 'origin/main')
        with patch('getzilla.worktree_safety.MAX_REFLOG', 1):
            self.assertIn('commits not on any remote-tracking ref', self.report(long_log)['reasons'])

    def test_a_folder_named_like_bytecode_is_not_disposable(self) -> None:
        path = self.add('pyc-folder', '-b', 'pyc-folder')
        exclude = Path(git(path, 'rev-parse', '--path-format=absolute', '--git-common-dir')) / 'info' / 'exclude'
        exclude.parent.mkdir(exist_ok=True)
        exclude.write_text('*.pyc\n')
        (path / 'notes.pyc').mkdir()
        (path / 'notes.pyc' / 'draft.txt').write_text('unique')
        report = self.report(path)
        self.assertEqual(report['hidden_from_status'], [])
        self.assertIn('notes.pyc/draft.txt', report['valuable_ignored'])

    def test_a_linked_worktrees_folder_keeps_everything_under_it(self) -> None:
        real = self.base / 'real-worktrees'
        real.mkdir()
        self.worktrees.parent.mkdir(parents=True)
        try:
            self.worktrees.symlink_to(real, target_is_directory=True)
        except OSError:
            self.skipTest('symlinks unavailable')
        path = self.add('through-link', '-b', 'through-link')
        reasons = self.report(path)['reasons']
        self.assertIn('the worktrees folder or a folder above it is a symlink', reasons)

    def test_unknown_process_state_and_too_many_ignored_files_keep_the_worktree(self) -> None:
        path = self.add('limits', '-b', 'limits')
        with patch('getzilla.worktree_safety._in_use', return_value=None):
            self.assertIn('cannot check for running processes on this platform', self.report(path)['reasons'])
        runtime = path / '.getzilla' / 'runtime' / 'par'
        runtime.mkdir(parents=True)
        for index in range(3):
            (runtime / f'log-{index}').write_text('x')
        (path / '.getzilla' / 'runtime' / 'state.json').write_text('{}')
        with patch('getzilla.worktree_safety.MAX_IGNORED_FILES', 2):
            report = self.report(path)
        self.assertFalse(report['removable'])
        self.assertTrue(any('not all checked' in item for item in report['valuable_ignored']))

    @unittest.skipUnless(PROCESS_CHECK, 'the /proc process scan is Linux only')
    def test_another_process_working_inside_keeps_the_worktree(self) -> None:
        path = self.add('other-process', '-b', 'other-process')
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], cwd=path)
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        self.assertIn('a process works in it', self.report(path)['reasons'])

    @unittest.skipUnless(PROCESS_CHECK, 'the /proc process scan is Linux only')
    def test_a_hidden_process_of_ours_counts_only_when_newer_than_the_worktree(self) -> None:
        from getzilla import worktree_safety
        path = self.add('hidden-process', '-b', 'hidden-process')
        created = worktree_safety._created_at(path)
        self.assertIsNotNone(created)
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        hidden = {str(child.pid)}
        real_readlink = os.readlink

        def denied(target, *args, **kwargs):
            if Path(target).parent.name in hidden:
                raise PermissionError('not dumpable')
            return real_readlink(target, *args, **kwargs)

        with patch('getzilla.worktree_safety.os.readlink', side_effect=denied):
            self.assertIsNone(worktree_safety._in_use(path, created))
            self.assertIn('cannot check for running processes on this platform', self.report(path)['reasons'])
            self.assertIsNone(worktree_safety._in_use(path, None), 'an unknown creation time fails closed')
            hidden.clear()
            hidden.add(str(os.getpid()))  # this test process started before the worktree below
            older = worktree_safety._started_at(Path('/proc') / str(os.getpid()))
            self.assertIsNotNone(older)
            self.assertIs(worktree_safety._in_use(path, older + 60), False)
            self.assertIs(worktree_safety._in_use(path, older + 10), False, 'a 2 s margin, not more')
            with patch('getzilla.worktree_safety._started_at', return_value=None):
                self.assertIsNone(worktree_safety._in_use(path, older + 60), 'an unknown start fails closed')

    @unittest.skipUnless(PROCESS_CHECK, 'the /proc process scan is Linux only')
    def test_a_process_name_with_brackets_does_not_shift_the_start_field(self) -> None:
        from getzilla import worktree_safety
        entry = self.base / 'fake-proc'
        entry.mkdir()
        (entry / 'stat').write_text('123 (x) y (z) w) S ' + ' '.join(['0'] * 18 + ['500', '7']) + '\n')
        boot = next(float(line.split()[1]) for line in Path('/proc/stat').read_text().splitlines()
                    if line.startswith('btime '))
        self.assertEqual(worktree_safety._started_at(entry), boot + 500 / os.sysconf('SC_CLK_TCK'))

    def test_the_creation_time_survives_move_and_repair_and_a_clock_step(self) -> None:
        from getzilla import worktree_safety
        path = self.add('moved', '-b', 'moved')
        git_dir = Path(git(path, 'rev-parse', '--absolute-git-dir'))
        os.utime(git_dir / 'commondir', (1_000_000, 1_000_000))
        os.utime(path, (2_000_000, 2_000_000))
        self.assertEqual(worktree_safety._created_at(path), 1_000_000)  # gitdir rewritten later by a move
        (git_dir / 'commondir').rename(git_dir / 'commondir.saved')
        self.assertIsNone(worktree_safety._created_at(path))
        (git_dir / 'commondir.saved').rename(git_dir / 'commondir')
        future = os.path.getmtime(git_dir / 'gitdir') + 3600
        os.utime(git_dir / 'commondir', (future, future))
        os.utime(git_dir / 'gitdir', (future, future))
        self.assertIsNone(worktree_safety._created_at(path))
        for ahead, trusted in ((5, False), (1, True)):  # a 2 s tolerance for clock ticks, not more
            stamp = time.time() + ahead
            os.utime(git_dir / 'commondir', (stamp, stamp))
            os.utime(git_dir / 'gitdir', (stamp, stamp))
            self.assertEqual(worktree_safety._created_at(path) is not None, trusted, ahead)

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
