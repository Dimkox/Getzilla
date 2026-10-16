"""I02: one router for plain folders, local Git and fetched snapshots; ambiguity stops routing."""
from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.project_ingestion import route_ingestion  # noqa: E402
from getzilla.source_models import IngestPolicy  # noqa: E402
from tests.branch_support import commit, env, git  # noqa: E402

POLICY = IngestPolicy()


class IngestionRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)

    def repo(self, name: str = 'repo') -> Path:
        path = self.base / name
        path.mkdir()
        git(path, 'init', '-q', '-b', 'main')
        commit(path, 'a.txt', 'a\n', 'first')
        return path

    def test_plain_folder_routes_to_plan(self) -> None:
        folder = self.base / 'plain'
        folder.mkdir()
        (folder / 'app.py').write_text('print(1)\n', encoding='utf-8')
        route = route_ingestion({'path': str(folder)}, POLICY)
        self.assertEqual((route.route, route.source_kind), ('zero_git_plan', 'folder'))
        self.assertIsNone(route.baseline)
        self.assertFalse((folder / '.git').exists())

    def test_gitfile_and_parent_worktree_not_zero_git(self) -> None:
        repo = self.repo()
        linked = self.base / 'linked'
        git(repo, 'worktree', 'add', '-q', str(linked), '-b', 'side')
        self.assertTrue((linked / '.git').is_file())
        route = route_ingestion({'path': str(linked)}, POLICY)
        self.assertEqual(route.route, 'existing_git_baseline')
        self.assertEqual(route.baseline.identity.commit_oid, git(repo, 'rev-parse', 'side'))
        sub = repo / 'src'
        sub.mkdir()
        nested = route_ingestion({'path': str(sub), 'kind': 'folder'}, POLICY)
        self.assertEqual((nested.route, nested.reasons), ('blocked', ('INSIDE_PARENT_GIT_WORKTREE',)))

    def test_fetched_remote_snapshot_uses_existing_history(self) -> None:
        upstream = self.repo('upstream')
        head = git(upstream, 'rev-parse', 'HEAD')
        snapshot = self.base / 'snapshot'
        subprocess.run(['git', 'clone', '-q', upstream.as_uri(), str(snapshot)], check=True, env=env(),
                       capture_output=True)
        route = route_ingestion({'path': str(snapshot), 'kind': 'remote_snapshot',
                                 'origin': {'url': 'file://fixture/upstream', 'fetched_by': 'caller'}}, POLICY)
        self.assertEqual((route.route, route.source_kind), ('existing_git_baseline', 'remote_snapshot'))
        self.assertEqual(route.baseline.identity.commit_oid, head)
        self.assertEqual(route.baseline.origin['url'], 'file://fixture/upstream')
        self.assertEqual(git(snapshot, 'rev-list', '--count', 'HEAD'), '1')

    def test_ambiguous_input_blocks(self) -> None:
        repo = self.repo()
        folder = self.base / 'plain'
        folder.mkdir()
        cases = [({'path': str(repo), 'kind': 'folder'}, 'AMBIGUOUS_INPUT_DECLARED_FOLDER_HAS_GIT'),
                 ({'path': str(folder), 'kind': 'local_git'}, 'AMBIGUOUS_INPUT_DECLARED_GIT_HAS_NO_GIT'),
                 ({'path': str(repo), 'kind': 'remote_snapshot'}, 'REMOTE_SNAPSHOT_WITHOUT_ORIGIN'),
                 ({'path': str(repo), 'kind': 'zip'}, 'UNKNOWN_INPUT_KIND')]
        for spec, reason in cases:
            with self.subTest(reason=reason):
                route = route_ingestion(spec, POLICY)
                self.assertEqual((route.route, route.reasons), ('blocked', (reason,)))
        unborn = self.base / 'unborn'
        unborn.mkdir()
        git(unborn, 'init', '-q')
        self.assertEqual(route_ingestion({'path': str(unborn)}, POLICY).reasons, ('FIRST_COMMIT_REQUIRES_SEPARATE_FLOW',))

    def test_existing_workflow_identity_not_rewritten(self) -> None:
        repo = self.repo()
        record = repo / '.getzilla' / 'AGBP_SYNC.json'
        record.parent.mkdir()
        record.write_text('{"route_id": "43786cadd549"}\n', encoding='utf-8')
        before = record.read_bytes()
        route = route_ingestion({'path': str(repo)}, POLICY)
        self.assertEqual(route.workflow_identity, {'.getzilla/AGBP_SYNC.json': hashlib.sha256(before).hexdigest()})
        self.assertEqual(record.read_bytes(), before)
        self.assertEqual(route.route, 'existing_git_baseline')


if __name__ == '__main__':
    unittest.main()
