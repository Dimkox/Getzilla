"""Owned data-only controls; no network or actual hosted qualification."""

from datetime import datetime, timezone
import errno
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_go_tool_inputs as reader
from getzilla.security_artifacts import ArtifactError

NOW = datetime(2026, 11, 19, 0, 0, tzinfo=timezone.utc)


class GoToolProducerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def producer(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.security_go_tool_producer'),
                             'missing joined checker tool source producer')
        from getzilla import security_go_tool_producer
        return security_go_tool_producer

    def test_missing_sources_keep_both_required_uses_without_live_or_scratch_authority(self):
        producer = self.producer()
        calls = []
        def unavailable(url, maximum):
            calls.append((url, maximum))
            raise OSError(errno.ENETUNREACH, 'PRIVATE_MARKER')
        from getzilla import security_image_producer as images
        before = images._LIVE
        result = producer.prepare_tools(ROOT, self.root, inventory_digest='a' * 64,
                                        now=NOW, fetch=unavailable)
        self.assertEqual(result['status'], 'incomplete-source-inputs')
        self.assertEqual(result['inventory'], reader.checker_inventory(ROOT))
        self.assertEqual(result['parent_inventory_sha256'], 'a' * 64)
        self.assertEqual(result['records'], [])
        self.assertEqual({gap['role'] for gap in result['gaps']}, {'trivy', 'buildkit'})
        self.assertTrue(all(gap['stage'] in {'archive', 'release'} for gap in result['gaps']))
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(url.startswith('https://') for url, _ in calls))
        self.assertIs(images._LIVE, before)
        self.assertNotIn('PRIVATE_MARKER', str(result))

    def test_default_transport_rejects_foreign_origins_before_opening_a_socket(self):
        producer = self.producer()
        for url in ('http://127.0.0.1/source', 'https://api.github.com.evil.test/source',
                    'https://user:password@api.github.com/source', 'https://proxy.golang.org/a/../b.zip'):
            with self.subTest(url=url), mock.patch('http.client.HTTPSConnection') as connection:
                with self.assertRaises(ArtifactError):
                    producer.fetch_public(url, 1024)
                connection.assert_not_called()

    def test_cache_revalidates_immutable_bytes_and_preserves_original_fetch_clock(self):
        producer = self.producer()
        url = 'https://raw.githubusercontent.com/golang/go/go1.25.5/LICENSE'
        original = NOW.timestamp() - 3600
        def fetch(source, maximum):
            return b'owned inert bytes', dict(requested_url=source, fetched_at=original, status=200)
        with producer.Store(self.root, now=NOW, fetch=fetch) as store:
            body, fact = store.get(url, 1024, stage='runtime', roles=['trivy'])
        self.assertEqual(body, b'owned inert bytes')
        self.assertEqual(fact['fetched_at'], original)
        with producer.Store(self.root, now=NOW, fetch=lambda *_:self.fail('fresh cache fetched again')) as store:
            cached, fact = store.get(url, 1024, stage='runtime', roles=['trivy'])
        self.assertEqual(cached, body)
        self.assertEqual(fact['fetched_at'], original)
        path = self.root / fact['body']['path']
        path.write_bytes(b'altered')
        with producer.Store(self.root, now=NOW, fetch=lambda *_:self.fail('corrupt cache was hidden')) as store:
            with self.assertRaises(ArtifactError):
                store.get(url, 1024, stage='runtime', roles=['trivy'])


if __name__ == '__main__':
    unittest.main()
