from __future__ import annotations
import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from tests.branch_support import git

class CiEvidenceTests(unittest.TestCase):
    def test_archive_exports_exact_referenced_immutable_verification_blob(self):
        from getzilla.ci_evidence import export_local_evidence
        from getzilla.receipts import MAX_RECEIPT_BYTES, write_receipt
        from tests._support import activate_owned_route
        import zipfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git(root, 'init', '-q')
            (root / '.gitignore').write_text('.getzilla/runtime/\n')
            (root / 'app.py').write_text('value = 1\n')
            git(root, 'add', '.')
            git(root, 'commit', '-qm', 'source')
            activate_owned_route(root, {'route_id': 'selected', 'required_evidence': ['verification']})
            receipt_path = write_receipt(root, 'verification', 'pass',
                                         details={'output': 'actual check output\n' * (MAX_RECEIPT_BYTES // 10)})
            envelope = json.loads(receipt_path.read_bytes())
            reference = envelope['details']['_verification_report']
            blob = root / reference['path']
            expected = blob.read_bytes()
            self.assertEqual(hashlib.sha256(expected).hexdigest(), reference['sha256'])
            unrelated = blob.parent / ('0' * 64 + '.json')
            unrelated.write_text('unreferenced report')
            other = root / '.getzilla/runtime/receipts/other/reports/private.json'
            other.parent.mkdir(parents=True)
            other.write_text('other route')
            output = root / '.getzilla/runtime/exports/selected.zip'
            export_local_evidence(root, output)
            with zipfile.ZipFile(output) as archive:
                name = f'receipts/reports/{reference["sha256"]}.json'
                self.assertEqual(archive.read(name), expected)
                self.assertEqual(json.loads(archive.read('receipts/verification.json')), envelope)
                self.assertEqual(set(archive.namelist()), {'manifest.json', 'route.json', 'receipts/verification.json', name})
                manifest = json.loads(archive.read('manifest.json'))
                self.assertEqual(next(row['sha256'] for row in manifest['files'] if row['path'] == name), reference['sha256'])
                self.assertEqual(manifest['head'], git(root, 'rev-parse', 'HEAD'))

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
