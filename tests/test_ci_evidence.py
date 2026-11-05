from __future__ import annotations
import json
import hashlib
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from tests.branch_support import git

class CiEvidenceTests(unittest.TestCase):
    def setUp(self):
        previous = os.umask(0o022)
        self.addCleanup(os.umask,previous)

    def admit_private_fixture(self, root):
        saved = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, saved)
        self.addCleanup(os.fchdir, saved)
        os.chdir(root)
        root.chmod(0o755)
        (root / '.getzilla').chmod(0o755)
        runtime = root / '.getzilla/runtime'
        runtime.chmod(0o700)
        for path in runtime.rglob('*'):
            if path.is_dir():
                path.chmod(0o700)
            elif path.is_file():
                path.chmod(0o600)

    def test_archive_exports_exact_referenced_immutable_verification_blob(self):
        from getzilla.ci_evidence import export_local_evidence
        from getzilla.receipts import MAX_RECEIPT_BYTES, write_receipt
        from tests._support import activate_owned_route
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
            self.admit_private_fixture(root)
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
            self.admit_private_fixture(root)
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

    def test_legacy_bundle_does_not_export_new_or_unknown_route_fields(self):
        from getzilla.ci_evidence import export_local_evidence
        import zipfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git(root, 'init', '-q')
            (root / 'source.py').write_text('value=1\n')
            git(root, 'add', '.')
            git(root, 'commit', '-qm', 'source')
            runtime = root / '.getzilla/runtime'
            runtime.mkdir(parents=True)
            record = {'route_id': 'test', 'task': 'controlled legacy scope',
                'observation_publication': {'value': 'PRIVATE_TRACE_SENTINEL'},
                'sprint': {'value': 'PRIVATE_TRACE_SENTINEL'},
                'future_field': {'value': 'PRIVATE_TRACE_SENTINEL'},
                'repo': {'future_trace': 'PRIVATE_TRACE_SENTINEL'}}
            (runtime / 'active-route.json').write_text(json.dumps(record))
            self.admit_private_fixture(root)
            output = runtime / 'exports/legacy.zip'
            export_local_evidence(root, output)
            with zipfile.ZipFile(output) as archive:
                projected = json.loads(archive.read('route.json'))
                self.assertEqual(projected, {'route_id': 'test', 'task': 'controlled legacy scope'})
                self.assertNotIn('PRIVATE_TRACE_SENTINEL', archive.read('route.json').decode())
                self.assertEqual(json.loads(archive.read('manifest.json'))['trace_metadata'], 'excluded')

    def test_unqualified_bundle_context_refuses_before_any_metadata_bytes(self):
        from getzilla.ci_evidence import export_local_evidence
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch('getzilla.trace_storage._NativeRoot.read', side_effect=AssertionError('metadata read before qualification')) as reader:
                with self.assertRaises(ValueError):
                    export_local_evidence(root, root / 'unavailable.zip')
            reader.assert_not_called()
            self.assertFalse((root / 'unavailable.zip').exists())

    def test_bundle_parent_replacement_never_reopens_the_root_hint(self):
        from getzilla.ci_evidence import export_local_evidence
        from getzilla.trace_storage import _NativeRoot
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / 'shared'
            root = parent / 'project'
            root.mkdir(parents=True)
            git(root, 'init', '-q')
            (root / 'source.py').write_text('value=1\n')
            git(root, 'add', '.')
            git(root, 'commit', '-qm', 'source')
            runtime = root / '.getzilla/runtime'
            runtime.mkdir(parents=True)
            (runtime / 'active-route.json').write_text('{"route_id":"original"}')
            self.admit_private_fixture(root)
            parent.chmod(0o775)
            moved = parent.with_name('moved')
            changed = []
            read = _NativeRoot.read
            def replacing(anchor, relative, *args, **kwargs):
                raw = read(anchor, relative, *args, **kwargs)
                if str(relative) == '.getzilla/runtime/active-route.json' and not changed:
                    changed.append(True)
                    parent.rename(moved)
                    foreign = root / '.getzilla/runtime'
                    foreign.mkdir(parents=True)
                    (foreign / 'active-route.json').write_text('FOREIGN_SENTINEL')
                return raw
            with patch.object(_NativeRoot, 'read', replacing):
                with self.assertRaisesRegex(ValueError,'native_trace_source_unavailable'):
                    export_local_evidence(root, runtime / 'exports/original.zip')
            self.assertEqual(changed, [True])
            self.assertEqual((root / '.getzilla/runtime/active-route.json').read_text(), 'FOREIGN_SENTINEL')
            self.assertFalse((root / '.getzilla/runtime/exports').exists())
            self.assertFalse((moved / 'project/.getzilla/runtime/exports/original.zip').exists())
