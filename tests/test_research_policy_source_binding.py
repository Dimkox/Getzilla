"""Actual trusted research helper/resource bytes participate in policy binding."""
import ast
import hashlib
import importlib
import io
from pathlib import Path
import tempfile
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import security_research_catalog as catalog
from getzilla.security_artifacts import ArtifactError
from getzilla.verification_plan import policy_binding

OWNERS = ('security_research_catalog.py', 'retrieval/research_use_conditions.py',
          'retrieval/public_study_manifest.py', 'retrieval/study_onnx_worker.py',
          'security_license_exceptions.py',
          'security_license_supplements.py')
RESOURCES = (('research_conditions_v1.json', 'catalog_bytes'),
             ('research_image_conditions_v1.json', 'image_conditions_bytes'))


class ResearchPolicySourceBindingTests(unittest.TestCase):
    def test_actual_helper_body_bytes_change_native_policy_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = policy_binding(root)
            for name in OWNERS:
                with self.subTest(owner=name):
                    module = importlib.import_module('getzilla.' + name[:-3].replace('/', '.'))
                    tree = ast.parse((ROOT / '.getzilla/getzilla' / name).read_bytes())
                    if name == 'retrieval/study_onnx_worker.py':
                        contract = next(node for node in tree.body
                                        if isinstance(node, ast.ClassDef) and node.name == 'ModelContract')
                        function = next(node for node in contract.body
                                        if isinstance(node, ast.FunctionDef) and node.name == '__post_init__')
                    else:
                        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
                    function.body.insert(0, ast.parse("raise RuntimeError('owned source mutation')").body[0])
                    changed = (ast.unparse(ast.fix_missing_locations(tree)) + '\n').encode()
                    with patch.object(module.__loader__, 'get_data', return_value=changed):
                        after = policy_binding(root)
                    self.assertEqual(after['implementation'][name], hashlib.sha256(changed).hexdigest())
                    self.assertNotEqual(before['digest'], after['digest'])

    def test_actual_bounded_reader_bytes_not_declared_hash_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = policy_binding(root)
            for name, reader in RESOURCES:
                with self.subTest(resource=name):
                    raw = getattr(catalog, reader)()
                    self.assertEqual(before['implementation'][name], hashlib.sha256(raw).hexdigest())
                    changed = raw + b'\n'
                    with patch.object(catalog, reader, return_value=changed):
                        after = policy_binding(root)
                    self.assertEqual(after['implementation'][name], hashlib.sha256(changed).hexdigest())
                    self.assertNotEqual(before['digest'], after['digest'])

    def test_real_resource_reader_rejects_changed_package_data_at_binding(self):
        files = catalog.files
        for name, reader in RESOURCES:
            with self.subTest(resource=name), tempfile.TemporaryDirectory() as directory:
                changed = getattr(catalog, reader)() + b'\n'
                def resource(package):
                    actual = files(package)
                    return SimpleNamespace(joinpath=lambda selected: SimpleNamespace(
                        open=lambda mode: io.BytesIO(changed)) if selected == name else actual.joinpath(selected))
                with patch.object(catalog, 'files', side_effect=resource):
                    with self.assertRaises(ArtifactError):
                        policy_binding(Path(directory))

    def test_exact_project_manifest_input_bytes_change_policy_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / catalog.MANIFEST_PATH
            path.parent.mkdir(parents=True)
            raw = (ROOT / catalog.MANIFEST_PATH).read_bytes()
            path.write_bytes(raw)
            before = policy_binding(root)
            self.assertEqual(before['inputs'][catalog.MANIFEST_PATH], hashlib.sha256(raw).hexdigest())
            path.write_bytes(raw + b'\n')
            after = policy_binding(root)
            self.assertNotEqual(before['digest'], after['digest'])

    def test_absent_subject_resources_stay_absent_with_current_checker_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bound = policy_binding(root)
            for path in (catalog.MANIFEST_PATH, catalog.CATALOG_PATH,
                         '.getzilla/getzilla/research_image_conditions_v1.json'):
                self.assertIsNone(bound['inputs'][path])
                self.assertFalse((root / path).exists())
            for name, reader in RESOURCES:
                self.assertEqual(bound['implementation'][name],
                                 hashlib.sha256(getattr(catalog, reader)()).hexdigest())

    def test_fresh_binding_never_imports_optional_native_model_sdks(self):
        code = """
import sys
sys.path.insert(0, sys.argv[1])
class DenyNative:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'numpy', 'torch', 'transformers', 'tokenizers',
                'sentence_transformers', 'onnxruntime', 'safetensors'}:
            raise AssertionError('native model import during source binding: ' + fullname)
sys.meta_path.insert(0, DenyNative())
from getzilla.verification_policy_source import implementation_source_binding
result = implementation_source_binding()
assert 'retrieval/study_onnx_worker.py' in result
assert 'research_conditions_v1.json' in result
"""
        result = subprocess.run([sys.executable, '-B', '-c', code, str(ROOT / '.getzilla')],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
