"""Owned NPM data proof controls; never install or execute packages."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
MIT = json.loads((ROOT / 'tests/fixtures/security-license-texts.json').read_text())['MIT']['text'].encode()


class NpmSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def world(self, vendor=False, sha1=False):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.security_action_npm'), 'missing NPM source-data reader')
        from getzilla import security_action_npm as npm
        files = {'package/package.json': json.dumps(dict(name='owned', version='1.0.0', license='MIT')).encode(),
                 'package/LICENSE': MIT, 'package/index.js': b'/* inert owned bytes */',
                 'package/dist/esm/package.json': b'{"type":"module"}'}
        if vendor:
            files['package/vendor/other/package.json'] = b'{"name":"other","version":"2.0.0","license":"MIT"}'
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for path, body in files.items():
                member = tarfile.TarInfo(path)
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
        raw = stream.getvalue()
        url = 'https://registry.npmjs.org/owned/-/owned-1.0.0.tgz'
        sri512 = 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode()
        sri = 'sha1-' + base64.b64encode(hashlib.sha1(raw).digest()).decode() if sha1 else sri512
        (self.root / 'owned.tgz').write_bytes(raw)
        source = dict(url=url, path='owned.tgz', sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), strong_metadata=None, acquired_at="2026-11-18T00:00:00+00:00")
        expected = [dict(name='owned', version='1.0.0', resolved=url, integrity=sri)]
        metadata = dict(name='owned', version='1.0.0', dist=dict(tarball=url, integrity=sri512))
        return npm, source, expected, metadata

    def test_complete_owned_source_and_ancillary_module_type_metadata_qualify(self):
        npm, source, expected, metadata = self.world()
        result = npm.verify_source(self.root, source, expected)
        self.assertEqual(len(result['components']), 1)
        self.assertEqual(result['components'][0]['expression'], 'MIT')
        self.assertEqual(result['bound_bytes'], source['bytes'])
        self.assertIn('package/LICENSE', result['members'])

    def test_sha1_needs_exact_official_metadata_and_matching_sha512(self):
        npm, source, expected, metadata = self.world(sha1=True)
        with self.assertRaises(ValueError):
            npm.verify_source(self.root, source, expected)
        raw = json.dumps(metadata).encode()
        (self.root / 'metadata.json').write_bytes(raw)
        source['strong_metadata'] = dict(url='https://registry.npmjs.org/owned/1.0.0', path='metadata.json',
                                         sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        self.assertEqual(len(npm.verify_source(self.root, source, expected)['components']), 1)
        for change in ('origin', 'hash', 'sri'):
            altered = copy.deepcopy(source)
            if change == 'origin':
                altered['strong_metadata']['url'] = 'https://evil.invalid/owned/1.0.0'
            elif change == 'hash':
                altered['sha256'] = '0' * 64
            else:
                expected[0]['integrity'] = 'sha1-' + 'A' * 28
            with self.subTest(change=change), self.assertRaises(ValueError):
                npm.verify_source(self.root, altered, expected)

    def test_vendor_component_cannot_inherit_root_mit_license(self):
        npm, source, expected, metadata = self.world(vendor=True)
        with self.assertRaises(ValueError):
            npm.verify_source(self.root, source, expected)
