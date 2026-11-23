"""Read-only plans never start consumer-controlled Git processes."""
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from tests.test_installer import MODULE, ROOT, _snapshot


class ReadonlyStatusTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='readonly-status-', dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.entry = MODULE.InstallEntry('AGENTS.md', b'owned original\n', 0o644)

    def git(self, root, *arguments):
        environment = {'PATH': os.defpath, 'HOME': str(self.directory),
                       'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
                       'GIT_TERMINAL_PROMPT': '0'}
        subprocess.run(['git', '-C', str(root), *arguments], env=environment,
                       check=True, capture_output=True, timeout=10)

    def repository(self, root):
        root.mkdir(mode=0o700)
        self.git(root, 'init', '-q', '--template=')
        (root / 'AGENTS.md').write_bytes(self.entry.content)
        self.git(root, 'add', 'AGENTS.md')
        self.git(root, '-c', 'maintenance.auto=false', '-c', 'gc.auto=0',
                 '-c', 'user.name=Owned fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-qm', 'owned fixture')

    def plan(self, target):
        return MODULE._make_plan(ROOT, target, include_dependencies=False,
                                 include_optional=False, payload=(self.entry,),
                                 full_payload=(self.entry,), selection=MODULE.PayloadSelection(()))

    def inert_process(self):
        process = MagicMock()
        process.stdout = io.BytesIO(b' M AGENTS.md\0')
        process.communicate.return_value = (b'AGENTS.md\0', b'')
        process.returncode = 0
        process.wait.return_value = 0
        process.__enter__.return_value = process
        process.__exit__.return_value = False
        return process

    def assert_unknown(self, observation):
        self.assertEqual(observation, {'state': 'unknown',
            'reason': 'not-run-for-untrusted-config', 'records': []})

    def test_direct_diagnostic_never_starts_a_consumer_process(self):
        with patch.object(MODULE.subprocess, 'Popen', return_value=self.inert_process()) as started:
            observed = MODULE._consumer_git_status(self.directory)
        started.assert_not_called()
        self.assert_unknown(observed)

    def test_real_plan_preserves_dirty_owned_conflict_and_git_metadata(self):
        target = self.directory / 'consumer'
        self.repository(target)
        ownership = next(entry for entry in MODULE._ownership_payload((self.entry,))
                         if entry.path == MODULE.OWNERSHIP_PATH)
        (target / '.getzilla').mkdir(mode=0o700)
        (target / MODULE.OWNERSHIP_PATH).write_bytes(ownership.content)
        (target / 'AGENTS.md').write_bytes(b'owned modified\n')
        before = _snapshot(target)
        with patch.object(MODULE.subprocess, 'Popen', return_value=self.inert_process()) as started:
            plan = self.plan(target)
        started.assert_not_called()
        self.assert_unknown(plan['consumer_git_status'])
        self.assertEqual(plan['existing_untracked'], [])
        self.assertEqual(plan['existing_untracked_status'],
                         {'state': 'unknown', 'reason': 'not-run-for-untrusted-config'})
        rows = {row['path']: row for row in plan['consumer_inventory']['entries']}
        self.assertEqual(rows['AGENTS.md']['classification'], 'user-change')
        self.assertEqual(rows['AGENTS.md']['action'], 'preserve')
        self.assertEqual(next(row for row in plan['entries'] if row['path'] == 'AGENTS.md')['action'],
                         'preserve-conflict')
        self.assertEqual(plan['quarantine_plan']['action'], 'plan-only')
        self.assertTrue(plan['quarantine_plan']['approval_required'])
        self.assertEqual(plan['quarantine_plan']['entries'], [])
        self.assertEqual(_snapshot(target), before)

    def test_linked_worktree_keeps_common_index_refs_and_config(self):
        repository = self.directory / 'repository'
        self.repository(repository)
        target = self.directory / 'linked'
        self.git(repository, 'worktree', 'add', '-q', '-b', 'consumer', str(target))
        (target / 'AGENTS.md').write_bytes(b'owned modified\n')
        before = _snapshot(self.directory)
        with patch.object(MODULE.subprocess, 'Popen', return_value=self.inert_process()) as started:
            plan = self.plan(target)
        started.assert_not_called()
        self.assert_unknown(plan['consumer_git_status'])
        self.assertEqual(plan['existing_untracked'], [])
        self.assertEqual(plan['existing_untracked_status'],
                         {'state': 'unknown', 'reason': 'not-run-for-untrusted-config'})
        self.assertEqual(plan['target_state'], 'directory')
        self.assertTrue((target / '.git').is_file())
        self.assertEqual(_snapshot(self.directory), before)

    def test_gitless_plan_preserves_files_without_starting_git(self):
        target = self.directory / 'gitless'
        target.mkdir(mode=0o700)
        (target / 'AGENTS.md').write_bytes(b'owned user file\n')
        before = _snapshot(target)
        with patch.object(MODULE.subprocess, 'Popen', return_value=self.inert_process()) as started:
            plan = self.plan(target)
        started.assert_not_called()
        self.assert_unknown(plan['consumer_git_status'])
        self.assertEqual(plan['existing_untracked'], [])
        self.assertEqual(plan['existing_untracked_status'],
                         {'state': 'unknown', 'reason': 'not-run-for-untrusted-config'})
        self.assertEqual(_snapshot(target), before)

    @unittest.skipIf(os.name == 'nt', 'POSIX directory alias fixture')
    def test_directory_alias_never_changes_the_canonical_consumer(self):
        target = self.directory / 'canonical'
        self.repository(target)
        alias = self.directory / 'alias'
        alias.symlink_to(target, target_is_directory=True)
        before = _snapshot(self.directory)
        with patch.object(MODULE.subprocess, 'Popen', return_value=self.inert_process()) as started:
            plan = self.plan(alias)
        started.assert_not_called()
        self.assertNotEqual(plan['consumer_git_status']['state'], 'observed')
        self.assertNotEqual(plan['target_state'], 'directory')
        self.assertEqual(_snapshot(self.directory), before)

    def test_absent_target_is_not_created_and_has_no_observed_status(self):
        target = self.directory / 'absent'
        before = _snapshot(self.directory)
        with patch.object(MODULE.subprocess, 'Popen', return_value=self.inert_process()) as started:
            plan = self.plan(target)
        started.assert_not_called()
        self.assertEqual(plan['consumer_git_status'], {'state': 'absent', 'records': []})
        self.assertFalse(target.exists())
        self.assertEqual(_snapshot(self.directory), before)


if __name__ == '__main__':
    unittest.main()
