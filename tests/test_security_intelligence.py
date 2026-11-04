"""A current transport receipt cannot make malformed or old intelligence clean."""
from __future__ import annotations

import gzip
import json
import unittest
from datetime import datetime, timezone

from getzilla.security_intelligence import IntelligenceError, enrich_findings, validate_epss, validate_kev

NOW = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)


def kev_payload(*, count=1, entries=None, released='2020-01-01T00:00:00Z'):
    record = {
        'cveID': 'CVE-2026-12345', 'vendorProject': 'Fixture', 'product': 'Fixture',
        'vulnerabilityName': 'Fixture issue', 'dateAdded': '2020-01-01',
        'shortDescription': 'Synthetic fixture', 'requiredAction': 'Apply correction',
        'dueDate': '2020-02-01', 'knownRansomwareCampaignUse': 'Unknown',
    }
    return json.dumps({'catalogVersion': '2026.11.03', 'dateReleased': released,
                       'count': count, 'vulnerabilities': [record] if entries is None else entries}).encode()


def epss_payload(date='2026-11-03', rows='CVE-2026-12345,0.25,0.8\n'):
    return gzip.compress((f'#model_version:v2026.06.15,score_date:{date}\ncve,epss,percentile\n' + rows).encode())


class IntelligenceTests(unittest.TestCase):
    def test_kev_accepts_old_event_release_but_rejects_incomplete_count(self):
        catalog = validate_kev(kev_payload(), now=NOW)
        self.assertIn('CVE-2026-12345', catalog['records'])
        self.assertEqual(catalog['record_count'], 1)
        with self.assertRaises(IntelligenceError):
            validate_kev(kev_payload(count=2), now=NOW)

    def test_kev_rejects_duplicate_or_invalid_record_including_nonmatching_rows(self):
        data = json.loads(kev_payload())
        for entries in ([*data['vulnerabilities'], *data['vulnerabilities']], [{'cveID': 'CVE-2026-12345'}]):
            with self.subTest(entries=entries), self.assertRaises(IntelligenceError):
                validate_kev(kev_payload(count=len(entries), entries=entries), now=NOW)
        with self.assertRaises(IntelligenceError):
            validate_kev(kev_payload(released='2026-11-04T00:00:00Z'), now=NOW)

    def test_empty_or_duplicate_key_catalog_is_not_no_known_exploits(self):
        for payload in (kev_payload(count=0, entries=[]), b'{"count":1,"count":0}'):
            with self.subTest(payload=payload), self.assertRaises(IntelligenceError):
                validate_kev(payload, now=NOW)

    def test_epss_forecast_clock_inclusive_boundary_and_no_local_refresh_escape(self):
        exact = datetime(2026, 11, 3, 0, tzinfo=timezone.utc)
        self.assertEqual(validate_epss(epss_payload('2026-10-31'), now=exact)['record_count'], 1)
        too_late = datetime(2026, 11, 3, 0, 0, 1, tzinfo=timezone.utc)
        for payload, clock in ((epss_payload('2026-10-31'), too_late),
                               (epss_payload('2026-11-04'), NOW)):
            with self.subTest(clock=clock), self.assertRaises(IntelligenceError):
                validate_epss(payload, now=clock)

    def test_epss_rejects_missing_header_duplicate_id_nonfinite_and_truncated_gzip(self):
        cases = [gzip.compress(b'cve,epss,percentile\nCVE-2026-12345,0.1,0.2\n'),
                 epss_payload(rows='CVE-2026-12345,nan,0.2\n'),
                 epss_payload(rows='CVE-2026-12345,0.1,1.1\n'),
                 epss_payload(rows='CVE-2026-12345,0.1,0.2\nCVE-2026-12345,0.3,0.4\n'),
                 epss_payload()[:-4], epss_payload(rows='')]
        for payload in cases:
            with self.subTest(payload=payload[:50]), self.assertRaises(IntelligenceError):
                validate_epss(payload, now=NOW)

    def test_missing_epss_row_is_unknown_and_low_score_never_suppresses_vulnerability(self):
        findings = [
            {'id': 'GHSA-fixture', 'aliases': ['CVE-2026-12345', 'CVE-2026-54321'], 'package': 'fixture'},
            {'id': 'MAL-2026-fixture', 'aliases': [], 'package': 'other'},
        ]
        enriched = enrich_findings(findings, validate_kev(kev_payload(), now=NOW),
                                   validate_epss(epss_payload(rows='CVE-2026-12345,0.0,0.0\n'), now=NOW))
        self.assertEqual(len(enriched), 2)
        first = enriched[0]['intelligence']
        self.assertTrue(first['CVE-2026-12345']['known_exploited'])
        self.assertEqual(first['CVE-2026-12345']['epss'], 0.0)
        self.assertIsNone(first['CVE-2026-54321']['epss'])
        self.assertEqual(first['CVE-2026-54321']['epss_state'], 'unknown')
        self.assertEqual(enriched[1]['intelligence'], {})
        self.assertEqual(enriched[1]['enrichment_reason'], 'no-cve-alias')
        self.assertEqual(findings[0].keys(), {'id', 'aliases', 'package'})


if __name__ == '__main__':
    unittest.main()
