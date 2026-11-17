"""NEW owned inventory joins. No default source, scanner or process execution."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W / '.getzilla'))
from getzilla import expanded_security as security
from getzilla import security_inventory as inventory
from getzilla import security_licenses  # preload before the closed fixture boundary
from getzilla import security_oci

ACTIVE = None


def audit(event, args):
    if ACTIVE is None:
        return
    if event.startswith(('subprocess.', 'socket.')) or event in {'os.system', 'os.posix_spawn'}:
        raise AssertionError('native/network operation denied')
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        value = os.path.abspath(os.fsdecode(args[0]))
        if not value.startswith(str(ACTIVE) + os.sep):
            raise AssertionError('outside owned fixture read denied')


sys.addaudithook(audit)


class NativeOCIConsumersTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(security_licenses.load_policy))
        parent = W / '.getzilla/runtime/scratch/new-native-oci-fixtures'
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.tmp = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.reference = 'example.invalid/owned@sha256:' + 'a' * 64

    def run_owned(self, action):
        global ACTIVE
        ACTIVE = self.root
        try:
            return action()
        finally:
            ACTIVE = None

    def binding(self, source, platform='linux/amd64'):
        return dict(manifest='Dockerfile', line=1, source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                    source_reference='${OWNED_IMAGE}', reference=self.reference, platform=platform)

    def collect(self, source, platform='linux/amd64'):
        (self.root / 'Dockerfile').write_text(source)
        with patch.object(inventory, '_tracked_files', return_value=['Dockerfile']):
            return self.run_owned(lambda: inventory.collect_inventory(
                self.root, image_bindings=[self.binding(source, platform)]))

    def test_literal_from_platform_cannot_be_replaced_by_catalog(self):
        source = 'FROM --platform=linux/amd64 ${OWNED_IMAGE}\n'
        wrong = self.collect(source, 'linux/arm64')
        self.assertFalse(wrong['complete'], wrong)
        self.assertTrue(any(row['code'] == 'image-selection-platform-mismatch' for row in wrong['gaps']))
        correct = self.collect(source)
        self.assertTrue(correct['complete'], correct['gaps'])
        self.assertEqual(correct['images'][0]['platform'], 'linux/amd64')

    def test_unresolved_unsupported_and_duplicate_from_platform_refuse(self):
        for value in ('$BUILDPLATFORM', 'windows/amd64', 'linux/amd64 --platform=linux/arm64'):
            with self.subTest(value=value):
                result = self.collect('FROM --platform=' + value + ' ${OWNED_IMAGE}\n')
                self.assertFalse(result['complete'], result)
                self.assertTrue(any(row['code'] == 'unresolved-image-platform' for row in result['gaps']))

    def catalog(self):
        source = 'FROM --platform=linux/amd64 ${OWNED_IMAGE}\n'
        current = self.collect(source)
        catalog = dict(schema_version=1, inventory_sha256=current['digest'],
                       records=[dict(reference=self.reference, platform='linux/amd64', layout=str(self.root/'layout'))],
                       source_bindings=[self.binding(source)])
        path = self.root / 'catalog.json'
        path.write_text(json.dumps(catalog))
        profile = dict(security_oci.LIMITS, images=[self.reference], platform='linux/amd64')
        return catalog, path, dict(GETZILLA_SECURITY_IMAGE_ARTIFACTS=str(path),
                                   GETZILLA_SECURITY_IMAGE_PROFILE=json.dumps(profile))

    def test_all_native_default_consumers_forward_fresh_selected_source(self):
        catalog, path, env = self.catalog()
        seen = []

        class StopBeforeProducer(Exception):
            pass

        def owned_collector(root, **kwargs):
            self.assertEqual(root, self.root)
            seen.append(kwargs.get('image_bindings'))
            raise StopBeforeProducer

        def owned_read(root, name, maximum):
            self.assertEqual(root / name, path)
            raw = path.read_bytes()
            self.assertLessEqual(len(raw), maximum)
            return raw

        calls = [security.security_obligations, security.known_vulnerability_report,
                 security.known_vulnerability_check, security.run_checks]
        binding = dict(database='owned', source_id='artifact-license-catalog', source_url='owned',
                       content_sha256='b'*64, payload_size=1, acquisition={}, coverage={})
        with patch.object(security, 'collect_inventory', side_effect=owned_collector), \
                patch('getzilla.security_artifacts.read_file', side_effect=owned_read):
            for function in calls:
                with self.subTest(consumer=function.__name__):
                    with self.assertRaises(StopBeforeProducer):
                        self.run_owned(lambda: function(self.root, environ=env))
                    self.assertEqual(seen[-1], catalog['source_bindings'])
            with self.assertRaises(StopBeforeProducer):
                self.run_owned(lambda: security.validate_data_source(binding, root=self.root, environ=env))
            self.assertEqual(seen[-1], catalog['source_bindings'])
            with patch.dict(os.environ, env):
                with self.assertRaises(StopBeforeProducer):
                    self.run_owned(lambda: security.security_obligations(self.root))
                self.assertEqual(seen[-1], catalog['source_bindings'])

    def test_selected_inventory_rereads_catalog_and_current_source(self):
        self.assertTrue(callable(getattr(security, 'selected_inventory', None)), 'missing shared current selection reader')
        catalog, path, env = self.catalog()

        def owned_read(root, name, maximum):
            self.assertEqual(root / name, path)
            raw = path.read_bytes()
            self.assertLessEqual(len(raw), maximum)
            return raw

        with patch.object(inventory, '_tracked_files', return_value=['Dockerfile']), \
                patch('getzilla.security_artifacts.read_file', side_effect=owned_read):
            current = self.run_owned(lambda: security.selected_inventory(self.root, environ=env))
            self.assertEqual(current['digest'], catalog['inventory_sha256'])
            path.write_text(json.dumps(dict(catalog, inventory_sha256='f'*64)))
            with self.assertRaises(ValueError):
                self.run_owned(lambda: security.selected_inventory(self.root, environ=env))
            path.write_text(json.dumps(catalog))
            (self.root / 'Dockerfile').write_text('FROM --platform=linux/arm64 ${OWNED_IMAGE}\n')
            with self.assertRaises(ValueError):
                self.run_owned(lambda: security.selected_inventory(self.root, environ=env))


if __name__ == '__main__':
    unittest.main(verbosity=2)
