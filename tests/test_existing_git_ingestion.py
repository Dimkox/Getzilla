"""I01: existing Git identity is read, never rewritten; no network, no writes, no invented prehistory."""
from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.project_ingestion import IngestionError, inspect_git_input  # noqa: E402
from getzilla.source_models import IngestPolicy  # noqa: E402
from tests.branch_support import commit, env, git  # noqa: E402

POLICY = IngestPolicy()


def tree_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path.rglob('*')):
        stat = item.lstat()
        digest.update(f'{item.relative_to(path)}|{stat.st_size}|{stat.st_mtime_ns}\n'.encode())
        if item.is_file() and not item.is_symlink():
            digest.update(item.read_bytes())
    return digest.hexdigest()


class ExistingGitIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q', '-b', 'main')

    def two_commits(self) -> tuple[str, str]:
        first = commit(self.repo, 'a.txt', 'a\n', 'first')
        return first, commit(self.repo, 'b.txt', 'b\n', 'second')

    def test_clean_git_identity_preserved(self) -> None:
        _, head = self.two_commits()
        before = git(self.repo, 'log', '--format=%H %T')
        baseline = inspect_git_input(self.repo, POLICY)
        self.assertEqual((baseline.state, baseline.history), ('clean', 'complete'))
        self.assertEqual(baseline.identity.commit_oid, head)
        self.assertEqual(baseline.identity.tree_oid, git(self.repo, 'rev-parse', 'HEAD^{tree}'))
        self.assertIsNone(baseline.working_set_digest)
        self.assertEqual(git(self.repo, 'log', '--format=%H %T'), before)

    def test_dirty_worktree_not_equal_to_head_baseline(self) -> None:
        self.two_commits()
        clean = inspect_git_input(self.repo, POLICY)
        (self.repo / 'a.txt').write_text('changed\n', encoding='utf-8')
        dirty = inspect_git_input(self.repo, POLICY)
        self.assertEqual(dirty.state, 'dirty')
        self.assertEqual(dirty.identity, clean.identity)
        self.assertIsNotNone(dirty.working_set_digest)
        (self.repo / 'a.txt').write_text('changed again\n', encoding='utf-8')
        self.assertNotEqual(inspect_git_input(self.repo, POLICY).working_set_digest, dirty.working_set_digest)
        (self.repo / 'new.txt').write_text('untracked\n', encoding='utf-8')
        self.assertEqual(inspect_git_input(self.repo, POLICY).state, 'dirty')

    def test_unborn_git_requires_separate_action(self) -> None:
        (self.repo / 'a.txt').write_text('a\n', encoding='utf-8')
        baseline = inspect_git_input(self.repo, POLICY)
        self.assertEqual(baseline.state, 'unborn')
        self.assertEqual(baseline.required_action, 'FIRST_COMMIT_REQUIRES_SEPARATE_FLOW')
        self.assertIsNone(baseline.identity.commit_oid)
        head = subprocess.run(['git', '-C', str(self.repo), 'rev-parse', '--verify', '--quiet', 'HEAD'],
                              capture_output=True, env=env(), check=False)
        self.assertNotEqual(head.returncode, 0, 'inspection must not create a commit')

    def test_partial_history_marked_unknown(self) -> None:
        self.two_commits()
        shallow = self.base / 'shallow'
        subprocess.run(['git', 'clone', '-q', '--depth', '1', self.repo.as_uri(), str(shallow)], check=True,
                       env=env(), capture_output=True)
        baseline = inspect_git_input(shallow, POLICY, source_kind='remote_snapshot', origin={'url': 'file://fixture'})
        self.assertEqual(baseline.history, 'shallow')
        self.assertIn('SHALLOW_HISTORY', baseline.provenance_limits)
        self.assertIn('EARLIEST_COMMITS_ARE_A_BOUNDARY_NOT_AN_ORIGIN', baseline.provenance_limits)

    def test_first_import_has_no_invented_prehistory(self) -> None:
        first = commit(self.repo, 'a.txt', 'a\n', 'imported')
        record = inspect_git_input(self.repo, POLICY).to_dict()
        self.assertEqual(record['earliest_available_commits'], [first])
        self.assertEqual(record['prehistory'], 'not_recorded')
        self.assertIn('NO_PROVENANCE_BEFORE_EARLIEST_AVAILABLE_COMMIT', record['provenance_limits'])

    def test_local_inspection_has_no_network_or_writes(self) -> None:
        self.two_commits()
        git(self.repo, 'remote', 'add', 'origin', 'https://getzilla.invalid/never-contacted.git')
        (self.repo / 'a.txt').write_text('dirty\n', encoding='utf-8')
        before = tree_digest(self.repo)
        inspect_git_input(self.repo, POLICY)
        self.assertEqual(tree_digest(self.repo), before)
        self.assertFalse(list((self.repo / '.git').glob('*.lock')))

    def test_folder_without_git_rejected(self) -> None:
        folder = self.base / 'plain'
        folder.mkdir()
        with self.assertRaises(IngestionError):
            inspect_git_input(folder, POLICY)


if __name__ == '__main__':
    unittest.main()
