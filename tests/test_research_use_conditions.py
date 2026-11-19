"""Exact private research scope and real held-file custody, never model runs."""
from pathlib import Path
import hashlib
import json
import os
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


class ResearchCatalogTests(unittest.TestCase):
    def test_fixed_catalog_manifest_and_subjects(self):
        from getzilla.security_research_catalog import load_catalog, MANIFEST_PATH, PROFILE
        from getzilla.security_license_exceptions import validate_exceptions
        value = load_catalog()
        self.assertEqual(value['profile'], PROFILE)
        self.assertEqual(len(value['wheels']), 29)
        self.assertEqual(len(value['inspection_wheels']), 2)
        self.assertEqual(set(value['models']), {'minilm', 'bge_m3'})
        self.assertEqual(value['models']['bge_m3']['external_files'][0]['path'], 'onnx/model.onnx_data')
        self.assertNotIn('Constant_7_attr__value', [x['path'] for x in value['models']['bge_m3']['external_files']])
        entries = value['dependency_exceptions']
        self.assertEqual(len(validate_exceptions(entries)), 29)
        for row in entries:
            self.assertEqual(row['subject']['manifest'], MANIFEST_PATH)
            self.assertEqual(row['subject']['distribution'], 'internal')
            self.assertEqual(row['subject']['usage'], 'retrieval-research')

    def test_unknown_catalog_fields_duplicates_and_changed_bytes_refuse(self):
        from getzilla.security_research_catalog import _decode, load_catalog
        from getzilla.security_artifacts import ArtifactError
        value = load_catalog()
        for data in (b'{"schema_version":1,"schema_version":1}',
                     json.dumps({**value, 'allow_all': True}).encode()):
            with self.subTest(data=data[:40]), self.assertRaises(ArtifactError):
                _decode(data)

    def test_catalog_stream_is_bounded_before_hash(self):
        from unittest.mock import patch
        from getzilla import security_research_catalog as catalog
        from getzilla.security_artifacts import ArtifactError
        class Stream:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, count):
                self.count = count
                return b'x' * count
        stream = Stream()
        with patch.object(catalog, 'files') as resource:
            resource.return_value.joinpath.return_value.open.return_value = stream
            with self.assertRaises(ArtifactError):
                catalog.catalog_bytes()
        self.assertEqual(stream.count, catalog.MAX_CATALOG_BYTES + 1)

    def test_actual_catalog_resources_survive_relocated_sdk_zip(self):
        import subprocess
        import zipfile
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as temporary:
            archive = Path(temporary) / 'inert-sdk.zip'
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
                for path in (ROOT / '.getzilla/getzilla').rglob('*'):
                    if path.suffix in {'.py', '.json'} and '__pycache__' not in path.parts:
                        output.write(path, 'getzilla/' + path.relative_to(ROOT / '.getzilla/getzilla').as_posix())
            script = ('import sys;sys.path.insert(0,sys.argv[1]);'
                      'from getzilla.security_research_catalog import load_catalog,image_conditions;'
                      'assert len(load_catalog()["wheels"])==29;assert len(image_conditions()["packages"])==105;'
                      'assert not {"numpy","onnxruntime","tokenizers","torch"}&set(sys.modules);print("actual-sdk-catalog-ok")')
            result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script, str(archive)],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'actual-sdk-catalog-ok')

    def test_research_exception_never_matches_other_use_target_or_artifact(self):
        from getzilla.security_research_catalog import load_catalog
        from getzilla.security_license_exceptions import validate_exceptions
        from getzilla.security_artifacts import ArtifactError
        entry = load_catalog()['dependency_exceptions'][0]
        for key, other in [('distribution', 'redistributed'), ('usage', 'runtime'),
                           ('abi', 'cpython-313-x86_64-linux-gnu'),
                           ('profile', 'ordinary'), ('artifact_sha256', '0' * 64)]:
            changed = {'condition_profile': entry['condition_profile'],
                       'subject': {**entry['subject'], key: other}}
            with self.subTest(key=key), self.assertRaises(ArtifactError):
                validate_exceptions([changed])


class HeldResearchTermsTests(unittest.TestCase):
    def setUp(self):
        if os.name != 'posix':
            self.skipTest('fixed POSIX held-custody research controller profile; other platforms fail closed')
    def test_actual_complete_terms_and_current_custody(self):
        from getzilla.retrieval.research_use_conditions import _HeldTerms
        from getzilla.security_artifacts import ArtifactError
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            raw = b'Actual complete tiny fixture grant.\n'
            (root / 'LICENSE').write_bytes(raw)
            (root / 'LICENSE').chmod(0o400)
            pins = {'LICENSE': (hashlib.sha256(raw).hexdigest(), len(raw))}
            with _HeldTerms(root, pins) as held:
                self.assertEqual(held.observe(), {'LICENSE': raw})
                held.check()
                replacement = root / 'new'
                replacement.write_bytes(raw)
                replacement.chmod(0o400)
                replacement.replace(root / 'LICENSE')
                with self.assertRaises(ArtifactError):
                    held.check()

    def test_supplement_limits_links_mutability_and_missing_notice_refuse(self):
        from getzilla.retrieval.research_use_conditions import _HeldTerms
        from getzilla.security_artifacts import ArtifactError
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            for requirements in ({str(i): ('0' * 64, 1) for i in range(5)},
                                 {'large': ('0' * 64, 262145)},
                                 {'absent': ('0' * 64, 1)}):
                with self.subTest(requirements=requirements), self.assertRaises(ArtifactError):
                    with _HeldTerms(root, requirements) as held:
                        held.observe()
            (root / 'real').write_bytes(b'x')
            (root / 'link').symlink_to('real')
            for name in ('real', 'link'):
                if name == 'real':
                    (root / name).chmod(0o666)
                with self.subTest(name=name), self.assertRaises(ArtifactError):
                    with _HeldTerms(root, {name: (hashlib.sha256(b'x').hexdigest(), 1)}) as held:
                        held.observe()

    def test_writable_intermediate_term_parent_cannot_qualify(self):
        from getzilla.retrieval.research_use_conditions import _HeldTerms
        from getzilla.security_artifacts import ArtifactError
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            (root / 'writable/leaf').mkdir(parents=True)
            path = root / 'writable/leaf/LICENSE'
            path.write_bytes(b'fixture')
            path.chmod(0o400)
            (root / 'writable').chmod(0o777)
            with self.assertRaises(ArtifactError):
                with _HeldTerms(root, {'writable/leaf/LICENSE': (hashlib.sha256(b'fixture').hexdigest(), 7)}) as held:
                    held.observe()

    def test_no_caller_dict_or_default_native_imports(self):
        from getzilla.retrieval.research_use_conditions import check_public_research_use, ResearchUseConditionsRef
        from getzilla.security_artifacts import ArtifactError
        with self.assertRaises((ArtifactError, TypeError)):
            ResearchUseConditionsRef()
        with self.assertRaises(ArtifactError):
            check_public_research_use({'allowed': True})
        with self.assertRaises(ArtifactError):
            check_public_research_use(object.__new__(ResearchUseConditionsRef))
        self.assertFalse({'onnxruntime', 'tokenizers', 'torch', 'numpy'} & set(sys.modules))

    def test_software_unregistered_empty_directory_and_ancestor_change_refuse(self):
        from getzilla.retrieval.research_use_conditions import _SoftwareCut
        from getzilla.security_artifacts import ArtifactError
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            (root / 'package').mkdir()
            (root / 'package/file.py').write_bytes(b'# not imported')
            expected = {'package/file.py': (14, hashlib.sha256(b'# not imported').hexdigest())}
            held = _SoftwareCut(root, expected)
            self.addCleanup(held.close)
            held.check()
            (root / 'unknown').mkdir()
            with self.assertRaises(ArtifactError):
                held.check()

    def test_actual_owner_tiny_roundtrip_extracted_or_archive_only_and_stale(self):
        from getzilla.retrieval import research_use_conditions as use
        from getzilla.security_artifacts import ArtifactError
        from tests.research_use_support import research_use_fixture
        for software in (False, True):
            with self.subTest(software=software), research_use_fixture(software=software) as (root, path, composition):
                ref = use._require_public_research_use(root, path, composition)
                self.addCleanup(use.close_public_research_use, ref)
                projection = use._check_public_research_use(ref, composition)
                self.assertEqual(projection['root'], root)
                self.assertEqual(projection['preparation_state'],
                                 'extracted-software-held' if software else 'archive-custody-source-use-admitted')
                self.assertFalse(projection['native_sdk_closure_complete'])
                with self.assertRaises(ArtifactError):
                    use.check_public_research_use(ref)
                if software:
                    extra = root / '.getzilla/runtime/use-fixture/software/unregistered.py'
                    extra.write_text('# never imported')
                    with self.assertRaises(ArtifactError):
                        use._check_public_research_use(ref, composition)

                else:
                    use.close_public_research_use(ref)
                    with self.assertRaises(ArtifactError):
                        use._check_public_research_use(ref, composition)

    def test_closed_registration_and_disabled_module_refuse_before_admission(self):
        from getzilla.retrieval import research_use_conditions as use
        from getzilla.security_artifacts import ArtifactError
        from tests.research_use_support import research_use_fixture
        with research_use_fixture() as (root, path, composition):
            target = root / path
            original = json.loads(target.read_text())
            for changed in ({**original, 'allow_execution': True},
                            {**original, 'schema_version': True},
                            {**original, 'artifact_root': '../elsewhere'}):
                target.write_text(json.dumps(changed))
                with self.subTest(changed=changed), self.assertRaises(ArtifactError):
                    use._require_public_research_use(root, path, composition)
        with research_use_fixture(enabled=False) as (root, path, composition):
            with self.assertRaises(ArtifactError):
                use._require_public_research_use(root, path, composition)
