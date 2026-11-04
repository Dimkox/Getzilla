from __future__ import annotations

import copy
import hashlib
import http.client
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from getzilla import security_license_acquisition as acquisition
from getzilla.security_artifacts import ArtifactError
from getzilla.security_licenses import evaluate_artifacts
from tests.test_security_licenses import NOW, POLICY, dependency, inventory, wheel


def registry(payload: bytes, *, filename='example-1.0.0-py3-none-any.whl', url=None) -> bytes:
    return json.dumps({'info': {'name': 'example', 'version': '1.0.0'}, 'urls': [{
        'filename': filename, 'url': url or f'https://files.pythonhosted.org/packages/aa/bb/{filename}',
        'digests': {'sha256': hashlib.sha256(payload).hexdigest()}, 'packagetype': 'bdist_wheel', 'yanked': False,
    }]}).encode()


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dep = dependency()
        self.inventory = inventory(self.dep)
        self.payload = wheel()
        self.calls = []

    def fetch(self, url, *, maximum):
        self.calls.append((url, maximum))
        return registry(self.payload) if url.endswith('/json') else self.payload

    def acquire(self, **options):
        return acquisition.acquire_pypi([self.dep], self.root, inventory_digest=self.inventory['digest'],
                                        fetch=options.pop('fetch', self.fetch), now=NOW, **options)

    def test_exact_index_and_artifact_are_saved_without_install_or_execution(self):
        with mock.patch('subprocess.run', side_effect=AssertionError('execution forbidden')):
            result = self.acquire()
        self.assertEqual(result['inventory_digest'], self.inventory['digest'])
        self.assertEqual(result['last_verified_sync_utc'], NOW.isoformat())
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[0][0], 'https://pypi.org/pypi/example/1.0.0/json')
        self.assertEqual(evaluate_artifacts(self.inventory, self.root, POLICY, now=NOW)['status'], 'pass')

    def test_wrong_hash_foreign_url_and_ambiguous_wheel_leave_previous_manifest(self):
        self.acquire()
        previous = (self.root / 'manifest.json').read_bytes()
        baseline = json.loads(registry(self.payload))
        for mode in ('hash', 'url', 'ambiguous', 'yanked'):
            index = copy.deepcopy(baseline)
            if mode == 'hash':
                index['urls'][0]['digests']['sha256'] = '0' * 64
            if mode == 'url':
                index['urls'][0]['url'] = 'https://attacker.invalid/payload.whl'
            if mode == 'ambiguous':
                index['urls'].append({**index['urls'][0], 'filename': 'example-1.0.0-py2.py3-none-any.whl'})
            if mode == 'yanked':
                index['urls'][0]['yanked'] = True
            def fetch(url, *, maximum):
                if 'attacker.invalid' in url:
                    self.fail('foreign origin reached fetch')
                return json.dumps(index).encode() if url.endswith('/json') else self.payload
            with self.subTest(mode=mode), self.assertRaises(ArtifactError):
                self.acquire(fetch=fetch)
            self.assertEqual((self.root / 'manifest.json').read_bytes(), previous)

    def test_platform_selection_needs_observed_target(self):
        filename = 'example-1.0.0-cp312-cp312-manylinux_2_17_x86_64.whl'
        def fetch(url, *, maximum):
            return registry(self.payload, filename=filename) if url.endswith('/json') else self.payload
        with self.assertRaises(ArtifactError):
            self.acquire(fetch=fetch)
        self.dep['artifact_filename'] = filename
        self.inventory = inventory(self.dep)
        self.assertEqual(self.acquire(fetch=fetch)['records'][0]['filename'], filename)

    def test_saved_index_and_destination_links_cannot_escape_selected_directory(self):
        elsewhere = self.root / 'elsewhere'
        elsewhere.mkdir()
        (self.root / 'indexes').symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises(ArtifactError):
            self.acquire()
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertFalse((self.root / 'manifest.json').exists())

    def test_fetch_boundary_enforces_actual_byte_budget_even_with_injected_fetch(self):
        with mock.patch.object(acquisition, 'MAX_INDEX_BYTES', 20), self.assertRaises(ArtifactError):
            self.acquire()
        self.assertFalse((self.root / 'manifest.json').exists())

    def test_transitive_requirements_are_not_claimed_resolved_by_direct_pin_download(self):
        self.payload = wheel(requires=['transitive>=1'])
        self.acquire()
        result = evaluate_artifacts(self.inventory, self.root, POLICY, now=NOW)
        self.assertEqual(result['status'], 'fail')
        self.assertIn('license-transitive-coverage', {value['code'] for value in result['gaps']})

    def test_unsupported_ecosystem_is_a_manifest_gap(self):
        result = acquisition.acquire_pypi([dependency(ecosystem='npm')], self.root,
            inventory_digest=self.inventory['digest'], fetch=lambda *args, **kwargs: self.fail('unexpected network'), now=NOW)
        self.assertEqual(result['records'], [])
        self.assertTrue(result['gaps'])


class NetworkBoundaryTests(unittest.TestCase):
    def test_foreign_redirect_is_rejected_before_network(self):
        handler = acquisition._FixedOriginRedirect()
        request = acquisition.urllib.request.Request('https://pypi.org/pypi/example/1.0.0/json')
        with self.assertRaises(ArtifactError):
            handler.redirect_request(request, None, 302, '', {}, 'https://evil.invalid/x')

    def test_default_fetch_refuses_candidate_url_and_bounded_response_overflow(self):
        with mock.patch('urllib.request.build_opener') as opener:
            for url in ('http://pypi.org/pypi/example/1/json', 'https://evil.invalid/x',
                        'https://files.pythonhosted.org:443/packages/x', 'https://files.pythonhosted.org/packages/../x'):
                with self.subTest(url=url), self.assertRaises(ArtifactError):
                    acquisition.bounded_default(url, maximum=10)
            opener.assert_not_called()

        class Response(io.BytesIO):
            status = 200
            headers = {'Content-Length': '11', 'Content-Encoding': 'identity'}
            def geturl(self):
                return 'https://pypi.org/pypi/example/1.0.0/json'
        opener = mock.Mock()
        opener.open.return_value = Response(b'12345678901')
        with mock.patch('urllib.request.build_opener', return_value=opener), self.assertRaises(ArtifactError):
            acquisition.bounded_default('https://pypi.org/pypi/example/1.0.0/json', maximum=10)

    def test_default_fetch_handles_unannounced_overflow_truncation_and_positive_body(self):
        class Response(io.BytesIO):
            status = 200
            headers = {}
            def geturl(self):
                return 'https://pypi.org/pypi/example/1.0.0/json'
        for body, expected in ((b'{}', b'{}'), (b'12345678901', None)):
            opener = mock.Mock()
            opener.open.return_value = Response(body)
            with mock.patch('urllib.request.build_opener', return_value=opener):
                if expected is None:
                    with self.assertRaises(ArtifactError):
                        acquisition.bounded_default('https://pypi.org/pypi/example/1.0.0/json', maximum=10)
                else:
                    self.assertEqual(acquisition.bounded_default('https://pypi.org/pypi/example/1.0.0/json', maximum=10), expected)
        opener.open.return_value = Response(b'')
        opener.open.return_value.read1 = mock.Mock(side_effect=http.client.IncompleteRead(b'partial'))
        with mock.patch('urllib.request.build_opener', return_value=opener), self.assertRaises(ArtifactError):
            acquisition.bounded_default('https://pypi.org/pypi/example/1.0.0/json', maximum=10)


if __name__ == '__main__':
    unittest.main()
