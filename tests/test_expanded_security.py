from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from getzilla.expanded_security import known_vulnerability_report, run_checks, security_obligations, validate_data_source
from getzilla.security_data import SecurityDataError, osv_coverage, publish_snapshot
from getzilla.security_intelligence import validate_epss, validate_kev
from tests.test_security_intelligence import epss_payload, kev_payload

NOW = datetime(2026, 11, 3, 0, tzinfo=timezone.utc)


class ExpandedSecurityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='expanded-security-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.db = self.root / '.getzilla/runtime/security-data'

    def feed(self, name, payload, coverage):
        return publish_snapshot(self.db, name, payload,
                                acquisition={'last_verified_sync_utc': NOW.isoformat(), 'retrieval_kind': 'download'},
                                coverage=coverage, now=NOW)

    def osv(self, *, identifier='GHSA-fixture', aliases=None):
        record = {'id': identifier, 'modified': '2026-11-01T00:00:00Z', 'aliases': aliases or [],
                  'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'sample'}, 'versions': ['1.0.0']}]}
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as bundle:
            bundle.writestr(identifier + '.json', json.dumps(record))
        payload = out.getvalue()
        self.feed('osv:PyPI', payload, osv_coverage(payload, 'PyPI'))

    def test_complete_no_objects_has_structured_na_but_unknown_inventory_is_required(self):
        (self.root / 'readme.md').write_text('fixture')
        checks = {item['name']: item for item in run_checks(self.root, now=NOW)}
        self.assertEqual(checks['security-inventory']['status'], 'pass')
        self.assertEqual(checks['security-licenses']['details'][0]['outcome'], 'not_applicable')
        (self.root / 'requirements.txt').write_text('unresolved>=1\n')
        obligations = security_obligations(self.root, now=NOW)
        self.assertTrue(all(item['applicability'] == 'required' for item in obligations))

    def test_fresh_acquisition_does_not_hide_old_epss_prediction_or_bad_kev_count(self):
        (self.root / 'requirements.txt').write_text('sample==1.0.0\n')
        self.osv()
        old_epss = epss_payload('2026-10-30')
        coverage = {'scopes': ['CVE'], 'complete': True, 'record_count': 1, 'schema': 'first-epss-csv-v1'}
        self.feed('epss', old_epss, coverage)
        self.feed('kev', kev_payload(count=2), {'scopes': ['CVE'], 'complete': True, 'record_count': 2, 'schema': 'cisa-kev-v1'})
        checks = {item['name']: item for item in run_checks(self.root, now=NOW)}
        self.assertEqual(checks['security-epss']['status'], 'fail')
        self.assertEqual(checks['security-kev']['status'], 'fail')

    def test_kev_and_malicious_hits_are_not_accepted_by_an_old_generic_waiver(self):
        (self.root / 'requirements.txt').write_text('sample==1.0.0\n')
        config = self.root / '.getzilla/config'
        config.mkdir(parents=True)
        (config / 'known-vulnerabilities.json').write_text(json.dumps({'accept': [
            {'id': 'MAL-2026-fixture', 'reason': 'old generic waiver', 'expires': '2026-12-01'}]}))
        self.osv(identifier='MAL-2026-fixture', aliases=['CVE-2026-12345'])
        self.feed('kev', kev_payload(), validate_kev(kev_payload(), now=NOW)['coverage'])
        self.feed('epss', epss_payload(), validate_epss(epss_payload(), now=NOW)['coverage'])
        checks = {item['name']: item for item in run_checks(self.root, now=NOW)}
        self.assertEqual(checks['security-kev']['status'], 'fail')
        self.assertEqual(checks['security-malicious-packages']['status'], 'fail')
        sources = checks['security-kev']['details'][0]['data_sources']
        self.assertEqual({item['source_id'] for item in sources}, {'kev', 'osv:PyPI'})
        plan = next(item for item in security_obligations(self.root, now=NOW) if item['check_id'] == 'security-kev')
        self.assertEqual(sources, plan['data_sources'])

    def test_final_consumption_rechecks_exact_source_and_clock(self):
        (self.root / 'requirements.txt').write_text('sample==1.0.0\n')
        self.feed('kev', kev_payload(), validate_kev(kev_payload(), now=NOW)['coverage'])
        obligations = security_obligations(self.root, now=NOW)
        descriptor = next(item for item in obligations if item['check_id'] == 'security-kev')['data_sources'][0]
        self.assertTrue(validate_data_source(descriptor, root=self.root, now=NOW + timedelta(hours=72)))
        with self.assertRaises(SecurityDataError):
            validate_data_source(descriptor, root=self.root, now=NOW + timedelta(hours=72, seconds=1))
        changed = json.loads(kev_payload())
        changed['catalogVersion'] = 'replacement'
        self.feed('kev', json.dumps(changed).encode(), validate_kev(kev_payload(), now=NOW)['coverage'])
        with self.assertRaises(SecurityDataError):
            validate_data_source(descriptor, root=self.root, now=NOW)

    def test_missing_feed_has_an_explicit_plan_obligation_and_cannot_validate(self):
        (self.root / 'requirements.txt').write_text('sample==1.0.0\n')
        obligation = next(item for item in security_obligations(self.root, now=NOW) if item['check_id'] == 'security-epss')
        self.assertEqual(obligation['applicability'], 'required')
        self.assertTrue(obligation['data_sources'][0]['unavailable'])
        with self.assertRaises(SecurityDataError):
            validate_data_source(obligation['data_sources'][0], root=self.root, now=NOW)

    def test_qualifying_vulnerability_scan_never_treats_unresolved_inventory_as_clean(self):
        (self.root / 'requirements.txt').write_text('other>=1\n')
        with mock.patch.dict('os.environ', {'GETZILLA_OSV_ONLINE': '1'}):
            report = known_vulnerability_report(self.root, now=NOW)
        self.assertEqual(report['status'], 'fail')
        self.assertEqual(report['reason_code'], 'inventory-incomplete')

    @unittest.skipUnless(os.name == 'posix', 'qualified descriptor snapshot backend')
    def test_configured_database_alias_does_not_erase_the_snapshot_boundary(self):
        (self.root / 'requirements.txt').write_text('sample==2.0.0\n')
        self.osv()
        self.assertEqual(known_vulnerability_report(self.root, now=NOW)['status'], 'pass')
        physical = next(item for item in security_obligations(self.root, now=NOW)
                        if item['check_id'] == 'known-vulnerabilities')['data_sources'][0]
        alias = self.root / 'database-alias'
        alias.symlink_to(self.db, target_is_directory=True)
        environment = {'GETZILLA_SECURITY_DB': str(alias)}
        report = known_vulnerability_report(self.root, environ=environment, now=NOW)
        self.assertEqual(report['status'], 'fail')
        self.assertEqual(report['reason_code'], 'data-unavailable')
        with self.assertRaises(SecurityDataError):
            validate_data_source(physical, root=self.root, environ=environment, now=NOW)

    def test_native_verifier_retains_findings_beyond_its_display_limit_and_source_proof(self):
        from getzilla.verification import _known_vulnerabilities
        (self.root / 'requirements.txt').write_text('sample==1.0.0\n')
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            for index in range(205):
                identifier = f'GHSA-fixture-{index}'
                archive.writestr(identifier + '.json', json.dumps({
                    'id': identifier, 'modified': '2026-11-01T00:00:00Z',
                    'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'sample'}, 'versions': ['1.0.0']}]}))
        payload = out.getvalue()
        self.feed('osv:PyPI', payload, osv_coverage(payload, 'PyPI'))
        with mock.patch('getzilla.expanded_security._clock', return_value=NOW):
            result = _known_vulnerabilities(self.root)
        self.assertEqual(result.status, 'fail')
        structured = result.details[0]
        self.assertEqual(structured['family'], 'vulnerabilities')
        self.assertEqual(len(structured['findings']), 205)
        self.assertEqual(len(result.details[1:]), 200)
        planned = next(item for item in security_obligations(self.root, now=NOW)
                       if item['check_id'] == result.name)
        self.assertEqual(structured['data_sources'], planned['data_sources'])
        self.assertTrue(validate_data_source(structured['data_sources'][0], root=self.root, now=NOW))

    @unittest.skipUnless(os.name == 'posix', 'qualified descriptor snapshot backend')
    def test_isolated_cli_preserves_named_database_path_for_the_real_reader(self):
        from getzilla.security_cli import evaluate
        (self.root / 'requirements.txt').write_text('sample==2.0.0\n')
        self.osv()
        alias = self.root / 'database-alias'
        alias.symlink_to(self.db, target_is_directory=True)
        source = {'head_sha': 'a' * 40, 'tree_sha': 'b' * 40, 'checker_sha': 'c' * 40,
                  'checker_tree_sha': 'd' * 40, 'candidate_clean': True, 'checker_clean': True,
                  'same_project': True}
        # Only Git identity is a fixture; inventory, snapshot readers and all
        # selected local producers execute normally. This creates no receipt.
        with mock.patch('getzilla.security_cli.source_binding', return_value=source):
            report = evaluate(self.root, alias, self.root / 'artifacts', self.root / 'tools', now=NOW)
        known = next(item for item in report['checks'] if item['name'] == 'known-vulnerabilities')
        self.assertEqual(known['status'], 'fail')
        self.assertEqual(known['details'][0]['outcome'], 'blocked')


if __name__ == '__main__':
    unittest.main()
