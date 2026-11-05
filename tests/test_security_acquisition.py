"""Fixed-origin acquisition contracts; transport is an inert public stand-in."""
from __future__ import annotations

import importlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from tests.test_security_data import archive, record

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)
URL = 'https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip'


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        try:
            self.acquisition = importlib.import_module('getzilla.security_acquisition')
        except ModuleNotFoundError:
            self.acquisition = None
        self.assertIsNotNone(self.acquisition, 'native qualified OSV acquisition is missing')
        self.payload = archive([record()])

    def test_raw_bytes_bad_status_or_origin_are_not_acquisition(self):
        module = self.acquisition
        good = module.FetchResult(self.payload, URL, URL, 200)
        self.assertEqual(module._body(good, URL), self.payload)
        for response in (self.payload, module.FetchResult(self.payload, URL, URL, 404),
                         module.FetchResult(self.payload, URL, 'http://public.invalid/data', 200),
                         module.FetchResult(self.payload, URL, 'https://other.invalid/data', 200),
                         module.FetchResult(self.payload, 'https://public.invalid/data', URL, 200)):
            with self.subTest(response=type(response).__name__), self.assertRaises(module.SecurityDataError):
                module._body(response, URL)

    def test_fixed_transport_checks_length_encoding_and_total_clock(self):
        module = self.acquisition
        class Response(io.BytesIO):
            status = 200
            def __init__(self, payload, headers):
                super().__init__(payload)
                self.headers = headers
            def read1(self, length):
                return self.read(length)
            def geturl(self):
                return URL
        for headers in ({'Content-Length': str(len(self.payload) + 1)}, {'Content-Encoding': 'gzip'},
                        {'Content-Length': '-1'}):
            response = Response(self.payload, headers)
            with self.subTest(headers=headers), patch.object(module.urllib.request, 'build_opener') as build:
                build.return_value.open.return_value = response
                with self.assertRaises(module.SecurityDataError):
                    module.fetch_public(URL)
        with patch.object(module.urllib.request, 'build_opener') as build, \
                patch.object(module.time, 'monotonic', side_effect=[0, 91]):
            build.return_value.open.return_value = Response(self.payload, {})
            with self.assertRaises(module.SecurityDataError):
                module.fetch_public(URL)

    def test_refresh_uses_qualified_bytes_and_preserves_failure_snapshot(self):
        module = self.acquisition
        self.assertTrue(callable(getattr(module, 'refresh_osv', None)), 'OSV-only native refresh is missing')
        from getzilla import security_data
        with tempfile.TemporaryDirectory(prefix='osv-public-acquisition-') as temporary:
            root = Path(temporary).resolve() / 'database'
            good = module.FetchResult(self.payload, URL, URL, 200)
            results = module.refresh_osv(root, ['PyPI'], fetch=lambda _url: good, now=NOW)
            self.assertEqual([r['status'] for r in results], ['pass'])
            before = (root / 'PyPI/snapshot.json').read_bytes()
            invalid = module.FetchResult(b'public incomplete archive', URL, URL, 200)
            failed = module.refresh_osv(root, ['PyPI'], fetch=lambda _url: invalid, now=NOW)
            self.assertEqual([r['status'] for r in failed], ['fail'])
            self.assertEqual((root / 'PyPI/snapshot.json').read_bytes(), before)
            self.assertEqual(security_data.read_snapshot(root, 'osv:PyPI', now=NOW)[0], self.payload)

    def test_osv_refresh_does_not_activate_other_feeds(self):
        module = self.acquisition
        self.assertTrue(callable(getattr(module, 'refresh_osv', None)), 'OSV-only native refresh is missing')
        with tempfile.TemporaryDirectory(prefix='osv-public-origins-') as temporary:
            called = []
            def fetch(url):
                called.append(url)
                return module.FetchResult(self.payload, url, url, 200)
            results = module.refresh_osv(Path(temporary).resolve() / 'database', ['PyPI'], fetch=fetch, now=NOW)
            self.assertEqual(called, [URL])
            self.assertEqual(len(results), 1)


if __name__ == '__main__':
    unittest.main()
