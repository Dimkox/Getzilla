"""G10: graph CLI end to end on an ingested project: read-only, source-bound, redacted, conservative."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.cli import main  # noqa: E402
from getzilla.project_ingestion import route_ingestion  # noqa: E402
from getzilla.source_models import IngestPolicy  # noqa: E402
from tests.branch_support import git  # noqa: E402

PROJECT = {
    'app/__init__.py': '',
    'app/core.py': 'SECRET_LIKE = "e2e-literal-never-exported"\ndef compute():\n    return 1\n',
    'app/api.py': 'from app.core import compute\ndef handle():\n    return compute()\n',
    'app/plugins.py': 'def load(registry, name):\n    return registry[name]()\n',
    'app/other.py': 'def unrelated():\n    pass\n',
    'README.md': '# project\n',
}


def tree_digest(path: Path, skip: str = '.git') -> str:
    digest = hashlib.sha256()
    for item in sorted(path.rglob('*')):
        relative = item.relative_to(path).as_posix()
        if relative == skip or relative.startswith(skip + '/'):
            continue
        digest.update(relative.encode())
        if item.is_file():
            digest.update(item.read_bytes())
    return digest.hexdigest()


class GraphEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.project = self.base / 'project'
        for path, text in PROJECT.items():
            target = self.project / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding='utf-8')
        git(self.project, 'init', '-q', '-b', 'main')
        git(self.project, 'add', '-A')
        git(self.project, 'commit', '-q', '-m', 'project')
        self.cache = self.base / 'cache' / 'graph.sqlite'

    def cli(self, *args: str) -> dict:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main([args[0], '--root', str(self.project), '--cache', str(self.cache), *args[1:]])
        self.assertEqual(code, 0, out.getvalue())
        return json.loads(out.getvalue())

    def test_graph_e2e_after_ingestion(self) -> None:
        route = route_ingestion({'path': str(self.project)}, IngestPolicy())
        self.assertEqual(route.route, 'existing_git_baseline')
        build = self.cli('build')
        self.assertEqual(build['counters']['parsed'], 5)
        self.assertEqual(self.cli('status')['status'], 'current')
        export = self.cli('export')['export']
        self.assertEqual(export['graph_input']['source']['commit_oid'], route.baseline.identity.commit_oid)
        self.assertIn('sym:app/api.py::handle', {s['id'] for s in export['symbols']})

    def test_incremental_and_full_exports_equal(self) -> None:
        self.cli('build')
        (self.project / 'app' / 'other.py').write_text('def unrelated():\n    return 2\n', encoding='utf-8')
        incremental = self.cli('build')
        self.assertEqual(incremental['counters']['parsed'], 1)
        exported = self.cli('export')['export']
        self.cache = self.base / 'fresh' / 'graph.sqlite'
        self.cli('build')
        self.assertEqual(self.cli('export')['export'], exported)

    def test_single_leaf_reparse_count_is_one_under_unchanged_config(self) -> None:
        self.cli('build')
        (self.project / 'app' / 'core.py').write_text(PROJECT['app/core.py'] + '\n', encoding='utf-8')
        counters = self.cli('build')['counters']
        self.assertEqual((counters['parsed'], counters['reused'], counters['full_rebuild']), (1, 4, 0))

    def test_unresolved_dynamic_call_widens_impact(self) -> None:
        self.cli('build')
        impact = self.cli('impact', '--changed', 'app/core.py')['impact']
        self.assertIn('app/api.py', impact['affected_files'])
        self.assertIn('app/plugins.py', impact['affected_files'])
        self.assertNotIn('app/other.py', impact['affected_files'])
        self.assertIn('security_checks', impact['required_checks'])

    def test_source_change_invalidates_status(self) -> None:
        self.cli('build')
        (self.project / 'app' / 'new.py').write_text('x = 1\n', encoding='utf-8')
        self.assertEqual(self.cli('status')['status'], 'stale')

    def test_export_redacts_sensitive_data(self) -> None:
        self.cli('build')
        text = json.dumps(self.cli('export'))
        self.assertNotIn('e2e-literal-never-exported', text)
        self.assertNotIn(str(self.base), text)

    def test_original_source_not_written(self) -> None:
        before = tree_digest(self.project)
        git_before = git(self.project, 'rev-parse', 'HEAD'), git(self.project, 'status', '--porcelain')
        self.cli('build')
        self.cli('status')
        self.cli('impact')
        self.assertEqual(tree_digest(self.project), before)
        self.assertEqual((git(self.project, 'rev-parse', 'HEAD'), git(self.project, 'status', '--porcelain')), git_before)

    def test_default_cache_stays_local_state(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(['build', '--root', str(self.project)]), 0)
        self.assertTrue((self.project / '.getzilla' / 'index' / 'graph.sqlite').exists())
        with contextlib.redirect_stdout(io.StringIO()) as status:
            main(['status', '--root', str(self.project)])
        self.assertEqual(json.loads(status.getvalue())['status'], 'current')


if __name__ == '__main__':
    unittest.main()
