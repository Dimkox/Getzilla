from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from getzilla.security_cli import REQUIRED_CHECKS, finalize_report

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


class SecurityCliTests(unittest.TestCase):
    def report(self):
        source = {'head_sha': 'a' * 40, 'tree_sha': 'b' * 40,
                  'checker_sha': 'c' * 40, 'checker_tree_sha': 'd' * 40,
                  'candidate_clean': True, 'checker_clean': True, 'same_project': True}
        checks = [{'name': name, 'status': 'pass', 'summary': 'observed', 'details': [{
            'kind': 'security-result', 'schema_version': 1, 'outcome': 'pass', 'data_sources': []}]} for name in REQUIRED_CHECKS]
        return source, checks

    def test_whole_report_requires_unique_complete_checks_and_unchanged_clean_source(self):
        source, checks = self.report()
        self.assertEqual(finalize_report(source, source, checks, 'e' * 64, 'f' * 64, now=NOW)['status'], 'pass')
        for altered in (checks[:-1], checks + [checks[0]], checks + [{'name': 'unknown', 'status': 'pass'}]):
            with self.subTest(count=len(altered)):
                self.assertEqual(finalize_report(source, source, altered, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')
        for key, value in (('head_sha', '9' * 40), ('candidate_clean', False), ('checker_clean', False), ('same_project', False)):
            after = {**source, key: value}
            self.assertEqual(finalize_report(source, after, checks, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')

    def test_skip_needs_structural_na_proof_for_this_inventory(self):
        source, checks = self.report()
        checks[1]['status'] = 'skip'
        self.assertEqual(finalize_report(source, source, checks, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')
        checks[1]['details'][0].update(outcome='not_applicable', applicability_evidence={
            'complete': True, 'inventory_sha256': 'e' * 64, 'reason': 'complete-inventory-no-objects'})
        self.assertEqual(finalize_report(source, source, checks, 'e' * 64, 'f' * 64, now=NOW)['status'], 'pass')
        checks[1]['details'][0]['applicability_evidence']['inventory_sha256'] = '0' * 64
        self.assertEqual(finalize_report(source, source, checks, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')

    def test_expiry_is_the_earliest_source_or_forecast_and_never_future_renewed(self):
        source, checks = self.report()
        acquisition = {'last_verified_sync_utc': NOW.isoformat(),
                       'source_published_at': (NOW - timedelta(hours=48)).isoformat()}
        checks[1]['details'][0]['data_sources'] = [{'source_id': 'epss', 'acquisition': acquisition}]
        result = finalize_report(source, source, checks, 'e' * 64, 'f' * 64, now=NOW)
        self.assertEqual(result['valid_until_utc'], (NOW + timedelta(hours=24)).isoformat())
        stale = copy.deepcopy(checks)
        stale[1]['details'][0]['data_sources'][0]['acquisition']['source_published_at'] = (NOW - timedelta(hours=73)).isoformat()
        self.assertEqual(finalize_report(source, source, stale, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')
        future = copy.deepcopy(checks)
        future[1]['details'][0]['data_sources'][0]['acquisition']['last_verified_sync_utc'] = (NOW + timedelta(seconds=1)).isoformat()
        self.assertEqual(finalize_report(source, source, future, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')


if __name__ == '__main__':
    unittest.main()
