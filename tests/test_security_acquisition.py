from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from getzilla.security_acquisition import FetchResult, refresh_feeds
from getzilla.security_data import SOURCE_URLS, SecurityDataError, read_snapshot
from tests.test_security_intelligence import epss_payload, kev_payload

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='security-acquisition-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def fetch(self, url):
        payload = kev_payload() if url == SOURCE_URLS['kev'] else epss_payload()
        return FetchResult(payload, url, url, 200)

    def test_refresh_publishes_only_validated_fixed_origin_payloads(self):
        reports = refresh_feeds(self.root, [], fetch=self.fetch, now=NOW)
        self.assertEqual([item['source_id'] for item in reports], ['kev', 'epss'])
        payload, evidence = read_snapshot(self.root, 'kev', now=NOW)
        self.assertEqual(payload, kev_payload())
        self.assertEqual(evidence['coverage']['record_count'], 1)
        self.assertEqual(evidence['acquisition']['last_verified_sync_utc'], NOW.isoformat())

    def test_invalid_refresh_keeps_original_snapshot_age_and_bytes(self):
        refresh_feeds(self.root, [], fetch=self.fetch, now=NOW)
        before = (self.root / 'feeds/kev/snapshot.json').read_bytes()

        def bad(url):
            return FetchResult(kev_payload(count=2), url, url, 200)

        reports = refresh_feeds(self.root, [], fetch=bad, now=NOW)
        self.assertTrue(all(item['status'] == 'fail' for item in reports))
        self.assertEqual((self.root / 'feeds/kev/snapshot.json').read_bytes(), before)

    def test_callback_bytes_wrong_origin_and_no_body_revalidation_cannot_publish(self):
        for response in (kev_payload(), FetchResult(kev_payload(), 'https://invalid.example/catalog', SOURCE_URLS['kev'], 200),
                         FetchResult(kev_payload(), SOURCE_URLS['kev'], 'https://foreign.invalid/kev', 200),
                         FetchResult(kev_payload(), SOURCE_URLS['kev'], 'https://www.cisa.gov:444/feed', 200),
                         FetchResult(kev_payload(), SOURCE_URLS['kev'], SOURCE_URLS['kev'], 304)):
            with self.subTest(response=type(response).__name__):
                reports = refresh_feeds(self.root, [], fetch=lambda _url: response, now=NOW)
                self.assertTrue(all(item['status'] == 'fail' for item in reports))
                with self.assertRaises(SecurityDataError):
                    read_snapshot(self.root, 'kev', now=NOW)


if __name__ == '__main__':
    unittest.main()
