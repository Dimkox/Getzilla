from __future__ import annotations
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from tests.branch_support import git

class CiEvidenceTests(unittest.TestCase):
    def test_exports_actual_ci_state_and_allowlisted_logs_only(self):
        from getzilla.ci_evidence import export_evidence
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git(root, 'init', '-q')
            (root / 'source.py').write_text('value = 1\n')
            git(root, 'add', '.')
            git(root, 'commit', '-qm', 'source')
            runtime = root / '.getzilla/runtime'
            runtime.mkdir(parents=True)
            (runtime / 'approvals.json').write_text('secret authorization')
            logs = root / 'logs'
            logs.mkdir()
            (logs / 'core-tests.log').write_text('actual test output')
            (logs / 'approvals.json').write_text('not evidence')
            output = root / 'artifact'
            export_evidence(root, output, logs=logs, job='linux', status='failure', run_id='123')
            files = {item.name for item in output.iterdir()}
            self.assertEqual(files, {'provenance.json', 'state.json', 'core-tests.log'})
            state = json.loads((output / 'state.json').read_text())
            self.assertEqual(state['job_status'], 'failure')
            self.assertEqual(state['local_reviews'], 'not_available_in_ci')
            provenance = json.loads((output / 'provenance.json').read_text())
            self.assertEqual(provenance['head'], git(root, 'rev-parse', 'HEAD'))
            self.assertEqual(provenance['run_id'], '123')

    def test_local_archive_preserves_identity_without_exporting_grants(self):
        from getzilla.ci_evidence import export_local_evidence
        import zipfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git(root, 'init', '-q')
            (root / 'source.py').write_text('value = 1\n')
            git(root, 'add', '.')
            git(root, 'commit', '-qm', 'source')
            runtime = root / '.getzilla/runtime'
            package = runtime / 'changes/test'
            (package / 'evidence').mkdir(parents=True)
            (runtime / 'active-route.json').write_text(json.dumps({'route_id': 'test'}))
            (runtime / 'active-change.json').write_text(json.dumps({'change_id': 'test', 'path': '.getzilla/runtime/changes/test'}))
            (package / 'state.json').write_text('{"status":"reviewing"}')
            (package / 'human-gates.json').write_text('not portable authority')
            (package / 'evidence/code-review.md').write_text('review')
            (runtime / 'approvals.json').write_text('private grant')
            output = runtime / 'exports/test.zip'
            export_local_evidence(root, output)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()), {'manifest.json', 'route.json', 'change/state.json', 'change/evidence/code-review.md'})
                manifest = json.loads(archive.read('manifest.json'))
                self.assertEqual(manifest['head'], git(root, 'rev-parse', 'HEAD'))
                self.assertEqual(manifest['route_id'], 'test')
                self.assertEqual(len(manifest['files']), 3)

    def test_ci_export_refuses_existing_directory_with_unselected_files(self):
        from getzilla.ci_evidence import export_evidence
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git(root, 'init', '-q')
            (root / 'source.py').write_text('value = 1\n')
            git(root, 'add', '.')
            git(root, 'commit', '-qm', 'source')
            output = root / 'artifact'
            output.mkdir()
            (output / 'approvals.json').write_text('not selected')
            with self.assertRaises((ValueError, FileExistsError)):
                export_evidence(root, output, logs=root, job='test', status='success', run_id='1')
