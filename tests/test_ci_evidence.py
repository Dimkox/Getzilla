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
    def test_live_export_rejects_missing_manifest_and_omits_unselected_authority(self):
        from getzilla import ci_evidence
        self.assertTrue(hasattr(ci_evidence, 'export_live_evidence'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'observations'
            source.mkdir()
            with self.assertRaises(ValueError):
                ci_evidence.export_live_evidence(source, root / 'missing')
            payload = b'actual test output'
            (source / 'command.log').write_bytes(payload)
            (source / 'private-grants.json').write_text('do not export')
            (source / 'manifest.json').write_text(json.dumps({'schema': 'getzilla-live-acceptance-v1',
                'files': [{'path': 'command.log', 'sha256': hashlib.sha256(payload).hexdigest()}]}))
            with self.assertRaisesRegex(ValueError, 'binding'):
                ci_evidence.export_live_evidence(source, root / 'unbound')
            from getzilla.live_contracts import ci_binding
            manifest = json.loads((source / 'manifest.json').read_bytes())
            manifest['binding'] = ci_binding(head='a'*40, tree='b'*40, run_id='123', attempt='1',
                                             cell='factory', producer_sha256='c'*64)
            (source / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8', newline='\n')
            ci_evidence.export_live_evidence(source, root / 'export')
            self.assertEqual({path.name for path in (root / 'export').iterdir()}, {'manifest.json', 'command.log'})
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

    def _failed_native_export(self, cut):
        from getzilla.ci_evidence import export_local_evidence
        from getzilla import fsx
        from unittest.mock import patch
        base = Path(__file__).resolve().parents[1]/'.getzilla/runtime'
        with tempfile.TemporaryDirectory(prefix='inert-native-export-',dir=base) as temporary:
            root = Path(temporary)
            git(root,'init','-q')
            git(root,'-c','maintenance.auto=false','-c','gc.auto=0','commit','--allow-empty','-qm','public fixture')
            runtime = root/'.getzilla/runtime'
            runtime.mkdir(parents=True)
            (runtime/'active-route.json').write_text('{"route_id":"public"}\n')
            self.admit_private_fixture(root)
            output = runtime/'exports/failed.zip'
            original_unlink,cuts = fsx.unlink_at,[]
            foreign = b'foreign inert fixture\n'
            def replace_output():
                replacement = output.with_name('foreign.zip')
                replacement.write_bytes(foreign)
                replacement.chmod(0o600)
                os.replace(replacement,output)
                cuts.append(output.stat().st_ino)
            def failed(*_args,**_kwargs):
                if cut == 'before-selection':
                    replace_output()
                raise OSError('inert archive write failure')
            def final_unlink(parent,name):
                self.assertEqual(name,output.name)
                if cut == 'final-cut':
                    replace_output()
                return original_unlink(parent,name)
            with patch('zipfile.ZipFile.writestr',side_effect=failed):
                with patch.object(fsx,'unlink_at',side_effect=final_unlink) as cleanup:
                    with self.assertRaisesRegex(OSError,'inert archive write failure'):
                        export_local_evidence(root,output)
                if cut == 'final-cut' and cuts:
                    self.assertTrue(output.exists(),'cleanup deleted the final-cut foreign replacement')
                    self.assertEqual(output.read_bytes(),foreign)
                    self.assertEqual(output.stat().st_ino,cuts[0])
                self.assertEqual(cleanup.call_count,0,'failed native export attempted pathname deletion')
            self.assertTrue(output.exists(),'failed native output must be retained as unavailable')
            before,identity = output.read_bytes(),output.stat().st_ino
            if cut == 'before-selection':
                self.assertEqual(before,foreign)
                self.assertEqual(identity,cuts[0])
            names = set(output.parent.iterdir())
            with patch('zipfile.ZipFile.writestr',side_effect=AssertionError('same-path retry wrote an archive')):
                for _ in range(3):
                    with self.assertRaises(FileExistsError):
                        export_local_evidence(root,output)
            self.assertEqual(output.read_bytes(),before)
            self.assertEqual(output.stat().st_ino,identity)
            self.assertEqual(set(output.parent.iterdir()),names)

    def test_native_failed_export_retains_owned_partial_and_bounds_same_path_retry(self):
        self._failed_native_export('owned')

    def test_native_failed_export_preserves_foreign_replacement_before_selection(self):
        self._failed_native_export('before-selection')

    def test_native_failed_export_has_no_final_pathname_cleanup_cut(self):
        self._failed_native_export('final-cut')

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
            git(root, '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '-qm', 'source')
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
            git(root, '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '-qm', 'source')
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
            git(root, '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '-qm', 'source')
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
            git(root, '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '-qm', 'source')
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
            git(root, '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '-qm', 'source')
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
            git(root, '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '-qm', 'source')
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
