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


class QueryAcquisitionTests(unittest.TestCase):
    def setUp(self):
        from getzilla import security_acquisition, security_osv_query
        from tests.test_known_vulns import _repo
        self.module, self.query = security_acquisition, security_osv_query
        temporary, self.root = _repo({'requirements.txt': 'public-package==1.0.0\n'})
        self.addCleanup(temporary.cleanup)
        self.database = self.root / 'public-query-store'

    def transport(self, method, url, body, deadline, maximum):
        return self.query.QueryResponse(method, url, body, b'{"results":[{}]}', 200, url)

    def test_actual_structural_zero_does_not_acquire_or_publish(self):
        (self.root / 'requirements.txt').unlink()
        with patch.object(self, 'transport', side_effect=AssertionError('zero objects acquired')) as transport:
            result = self.module.refresh_query(self.root, self.database, transport=transport, now=NOW)
        self.assertEqual(result['status'], 'skip', result)
        self.assertFalse(self.database.exists())
        transport.assert_not_called()

    def test_query_transport_binds_fixed_method_url_and_remaining_bytes(self):
        import time
        fetch = getattr(self.module, 'fetch_osv_request', None)
        self.assertTrue(callable(fetch), 'bounded fixed OSV query transport is missing')
        class Response(io.BytesIO):
            status = 200
            def __init__(self, body, headers, url):
                super().__init__(body)
                self.headers, self.url = headers, url
            def geturl(self):
                return self.url
            def read1(self, length):
                return self.read(length)
        url, body = self.query.QUERY_URL, b'{"results":[{}]}'
        with patch.object(self.module.urllib.request, 'build_opener') as build:
            response = Response(body, {'Content-Length': str(len(body))}, url)
            build.return_value.open.return_value = response
            result = fetch('POST', url, b'{"queries":[]}', time.monotonic() + 10, len(body))
            self.assertEqual(result.body, body)
            self.assertEqual(result.request, b'{"queries":[]}')
            response = Response(body, {'Content-Length': str(len(body))}, url)
            build.return_value.open.return_value = response
            with patch.object(response, 'read1', wraps=response.read1) as read:
                with self.assertRaises(self.module.SecurityDataError):
                    fetch('POST', url, b'{}', time.monotonic() + 10, 1)
                read.assert_not_called()
        for method, endpoint in [('GET', url), ('POST', 'https://other.invalid/v1/querybatch'),
                                 ('GET', self.query.DETAIL_URL + '../public'), ('POST', url + '?extra=1')]:
            with self.subTest(method=method, endpoint=endpoint), self.assertRaises(self.module.SecurityDataError):
                fetch(method, endpoint, b'{}', time.monotonic() + 10, 1024)

    def test_refresh_queries_publish_same_store_and_preserve_old_on_current_input_change(self):
        from getzilla import security_data
        refresh = getattr(self.module, 'refresh_query', None)
        self.assertTrue(callable(refresh), 'explicit qualified query acquisition is missing')
        result = refresh(self.root, self.database, transport=self.transport, now=NOW)
        self.assertEqual(result['status'], 'pass', result)
        pointer = self.database / 'queries/native/snapshot.json'
        before = pointer.read_bytes()
        original = security_data._SnapshotStore.write
        def write(store, parts, payload):
            result = original(store, parts, payload)
            if parts[-1] == '.publication-pending.json':
                (self.root / 'requirements.txt').write_text('public-package==2.0.0\n', encoding='utf-8')
            return result
        with patch.object(security_data._SnapshotStore, 'write', write):
            result = refresh(self.root, self.database, transport=self.transport, now=NOW)
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(pointer.read_bytes(), before)
        self.assertEqual(security_data.read_snapshot(self.database, self.query.SOURCE_ID, now=NOW)[1]['acquisition']['last_verified_sync_utc'], NOW.isoformat())

    def test_absolute_deadline_expiring_during_staging_keeps_old_pointer(self):
        from getzilla import security_data
        self.assertEqual(self.module.refresh_query(self.root, self.database, transport=self.transport, now=NOW)['status'], 'pass')
        pointer = self.database / 'queries/native/snapshot.json'
        before = pointer.read_bytes()
        before_payload = security_data.read_snapshot(self.database, self.query.SOURCE_ID, now=NOW)[0]
        original, monotonic = security_data._SnapshotStore.write, [0.0]
        def write(store, parts, payload):
            result = original(store, parts, payload)
            if parts[-1] == '.publication-pending.json':
                monotonic[0] = 181.0
            return result
        with patch.object(self.module.time, 'monotonic', side_effect=lambda: monotonic[0]), \
                patch.object(security_data._SnapshotStore, 'write', write):
            result = self.module.refresh_query(self.root, self.database, transport=self.transport, now=NOW)
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(pointer.read_bytes(), before)
        self.assertEqual(security_data.read_snapshot(self.database, self.query.SOURCE_ID, now=NOW)[0], before_payload)

    def test_transport_primary_exits_are_not_relabelled_as_refresh_failures(self):
        class PublicExit(BaseException):
            pass
        for kind in (KeyboardInterrupt, SystemExit, PublicExit):
            def transport(*args):
                raise kind()
            with self.subTest(kind=kind), self.assertRaises(kind):
                self.module.refresh_query(self.root, self.database, transport=transport, now=NOW)
        self.assertFalse(self.database.exists())


if __name__ == '__main__':
    unittest.main()
