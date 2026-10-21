"""`getzilla update`: the project sync writes managed files on a new branch, never over local work."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import getzilla_upgrade as upgrade  # noqa: E402

GIT_ENV = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid',
           'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.invalid'}


def git(project: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(project), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


class ProjectSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.dict(os.environ, {**GIT_ENV, 'GETZILLA_AGENT': 'claude'})
        patcher.start()
        self.addCleanup(patcher.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.project = Path(tmp.name).resolve() / 'project'
        (self.project / '.getzilla').mkdir(parents=True)
        (self.project / 'ruff.toml').write_text('line-length = 80\n', encoding='utf-8')
        (self.project / 'AGENTS.md').write_text('# Project rules\n\nKeep this.\n', encoding='utf-8')
        git(self.project, 'init', '--quiet', '--initial-branch=main')
        self.commit('initial')

    def commit(self, message: str) -> None:
        git(self.project, 'add', '-A')
        git(self.project, 'commit', '--quiet', '-m', message)

    def test_sync_commits_on_a_new_branch_and_is_idempotent(self) -> None:
        result = upgrade.sync_project(ROOT, self.project)
        branch = upgrade.BRANCH_PREFIX + upgrade.version_of(ROOT)
        self.assertIn(branch, result)
        self.assertEqual(git(self.project, 'branch', '--show-current'), branch)
        self.assertEqual(git(self.project, 'status', '--porcelain'), '')
        self.assertEqual(git(self.project, 'rev-list', '--count', 'main'), '1')
        self.assertEqual((self.project / 'scripts/getzilla_route.py').read_bytes(),
                         (ROOT / 'scripts/getzilla_route.py').read_bytes())
        agents = (self.project / 'AGENTS.md').read_text(encoding='utf-8')
        self.assertTrue(agents.startswith('# Project rules\n\nKeep this.\n'))
        self.assertEqual(agents.count('<!-- ADAPTIVE-GROK-PRO:START -->'), 1)
        head = git(self.project, 'rev-parse', 'HEAD')
        self.assertIn('up to date', upgrade.sync_project(ROOT, self.project))
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), head)

    def test_uncommitted_changes_stop_the_sync(self) -> None:
        (self.project / 'notes.txt').write_text('work in progress\n', encoding='utf-8')
        with self.assertRaisesRegex(upgrade.UpdateError, 'uncommitted changes'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'branch', '--show-current'), 'main')
        self.assertFalse((self.project / 'scripts').exists())

    def test_kept_local_paths_are_left_alone(self) -> None:
        local = (self.project / 'ruff.toml').read_bytes()
        record = {'schema_version': 1, 'kept_local': ['ruff.toml'],
                  'kept_local_sha256': {'ruff.toml': hashlib.sha256(local).hexdigest()}}
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps(record), encoding='utf-8')
        self.commit('keep ruff.toml')
        upgrade.sync_project(ROOT, self.project)
        self.assertEqual((self.project / 'ruff.toml').read_bytes(), local)

    def test_existing_update_branch_is_not_reused(self) -> None:
        git(self.project, 'branch', upgrade.BRANCH_PREFIX + upgrade.version_of(ROOT))
        with self.assertRaisesRegex(upgrade.UpdateError, 'already exists'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'branch', '--show-current'), 'main')

    def test_a_failure_before_the_branch_leaves_the_project_unchanged(self) -> None:
        real = upgrade._git_out

        def failing(cwd, *args, **kwargs):
            if args[0] == 'commit-tree':
                raise upgrade.UpdateError('simulated commit failure')
            return real(cwd, *args, **kwargs)

        with mock.patch.object(upgrade, '_git_out', side_effect=failing):
            with self.assertRaisesRegex(upgrade.UpdateError, 'simulated'):
                upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'branch', '--show-current'), 'main')
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')
        self.assertEqual(git(self.project, 'status', '--porcelain'), '')

    @unittest.skipIf(os.name == 'nt', 'POSIX symlinks')
    def test_a_committed_link_is_never_written_through(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            (self.project / 'scripts').symlink_to(outside)
            self.commit('link scripts')
            with self.assertRaises(upgrade.UpdateError):
                upgrade.sync_project(ROOT, self.project)
            self.assertEqual(os.listdir(outside), [])
        self.assertEqual(git(self.project, 'branch', '--show-current'), 'main')

    def test_an_ignored_local_file_on_a_managed_path_is_never_overwritten(self) -> None:
        (self.project / '.gitignore').write_text('bandit.yaml\n', encoding='utf-8')
        self.commit('ignore bandit.yaml')
        (self.project / 'bandit.yaml').write_text('mine\n', encoding='utf-8')
        with self.assertRaisesRegex(upgrade.UpdateError, 'bandit.yaml'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual((self.project / 'bandit.yaml').read_text(encoding='utf-8'), 'mine\n')
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')

    def test_a_subfolder_is_not_a_repository_root(self) -> None:
        (self.project / 'sub/.getzilla').mkdir(parents=True)
        with self.assertRaisesRegex(upgrade.UpdateError, 'not the root'):
            upgrade.sync_project(ROOT, self.project / 'sub')


class HelperTests(unittest.TestCase):
    def test_agents_merge_replaces_only_the_managed_block(self) -> None:
        installer = upgrade.load_installer(ROOT)
        block = f'{installer.MANAGED_START}\nnew\n{installer.MANAGED_END}\n'.encode()
        old = f'top\n{installer.MANAGED_START}\nold\n{installer.MANAGED_END}\nbottom\n'.encode()
        self.assertEqual(upgrade.merge_agents(installer, old, block),
                         f'top\n{installer.MANAGED_START}\nnew\n{installer.MANAGED_END}\nbottom\n'.encode())
        self.assertEqual(upgrade.merge_agents(installer, None, block), block)
        with self.assertRaisesRegex(upgrade.UpdateError, 'broken'):
            upgrade.merge_agents(installer, f'{installer.MANAGED_END}\n'.encode(), block)

    def test_getzilla_itself_is_not_a_project(self) -> None:
        self.assertIsNone(upgrade.find_project(ROOT / 'scripts', ROOT))
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp).resolve()
            (project / '.getzilla').mkdir()
            (project / 'src').mkdir()
            self.assertEqual(upgrade.find_project(project / 'src', ROOT), project)

    def test_tool_options_keep_their_old_meaning(self) -> None:
        with mock.patch.object(upgrade, 'run_tools', return_value=0) as tools, \
                mock.patch.object(upgrade, 'update_self') as update_self:
            self.assertEqual(upgrade.main(['--only', 'osv']), 0)
            self.assertEqual(upgrade.main(['--status']), 0)
            self.assertEqual(upgrade.main(['--stat']), 0)
            self.assertEqual(upgrade.main(['--no-self', '--quiet']), 0)
            self.assertEqual(upgrade.main(['tools', '--only', 'agents']), 0)
        self.assertEqual([call.args[1] for call in tools.call_args_list],
                         [['--only', 'osv'], ['--status'], ['--stat'], ['--quiet'], ['--only', 'agents']])
        update_self.assert_not_called()


class SelfUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.dict(os.environ, GIT_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.origin, self.home, self.work = base / 'origin.git', base / 'home', base / 'work'
        subprocess.run(['git', 'init', '-q', '--bare', '--initial-branch=main', str(self.origin)], check=True)
        subprocess.run(['git', 'clone', '-q', str(self.origin), str(self.work)], check=True,
                       capture_output=True)
        self.push('one')
        subprocess.run(['git', 'clone', '-q', str(self.origin), str(self.home)], check=True)

    def push(self, text: str) -> None:
        (self.work / 'VERSION').write_text(text + '\n', encoding='utf-8')
        git(self.work, 'add', '-A')
        git(self.work, 'commit', '-q', '-m', text)
        git(self.work, 'push', '-q', 'origin', 'HEAD:main')

    def test_branch_fast_forwards_and_detached_follows_the_ref(self) -> None:
        self.push('two')
        self.assertIn('updated', upgrade.update_self(self.home, None))
        self.assertEqual((self.home / 'VERSION').read_text(encoding='utf-8'), 'two\n')
        with self.assertRaisesRegex(upgrade.UpdateError, 'detached'):
            upgrade.update_self(self.home, 'main')
        git(self.home, 'checkout', '-q', '--detach')
        self.push('three')
        self.assertIn('updated', upgrade.update_self(self.home, None))
        self.assertEqual((self.home / 'VERSION').read_text(encoding='utf-8'), 'three\n')
        self.assertEqual(git(self.home, 'rev-parse', '--is-shallow-repository'), 'false')

    def test_local_changes_skip_the_update(self) -> None:
        self.push('two')
        (self.home / 'VERSION').write_text('mine\n', encoding='utf-8')
        self.assertIn('local changes', upgrade.update_self(self.home, None))
        self.assertEqual((self.home / 'VERSION').read_text(encoding='utf-8'), 'mine\n')


if __name__ == '__main__':
    unittest.main()
