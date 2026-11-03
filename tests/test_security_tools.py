from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from getzilla.security_data import SecurityDataError
from getzilla.security_tools import image_report, trivy_database_source, validate_tool_report, scan_secrets

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)
IMAGE = 'postgres@sha256:' + 'a' * 64


class SecurityToolTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='security-tools-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def database(self, *, downloaded=NOW, published=NOW):
        folder = self.root / 'cache/db'
        folder.mkdir(parents=True, exist_ok=True)
        (folder / 'trivy.db').write_bytes(b'fixture database: interpretation is checked by actual Trivy')
        (folder / 'metadata.json').write_text(json.dumps({
            'Version': 2, 'DownloadedAt': downloaded.isoformat(), 'UpdatedAt': published.isoformat()}))

    def report(self):
        return {'SchemaVersion': 2, 'ArtifactType': 'container_image', 'ArtifactName': IMAGE,
                'Metadata': {'RepoDigests': [IMAGE], 'ImageID': 'sha256:' + 'b' * 64,
                             'OS': {'Family': 'alpine', 'Name': '3.23'}},
                'Results': [{'Target': IMAGE, 'Class': 'os-pkgs', 'Type': 'alpine',
                             'Packages': [{'Name': 'openssl', 'Version': '3.1.0'}],
                             'Vulnerabilities': []}]}

    def test_image_zero_exit_empty_or_foreign_report_is_not_a_scan(self):
        for value in ({}, {**self.report(), 'Results': []},
                      {**self.report(), 'Metadata': {'RepoDigests': ['foreign@sha256:' + 'c' * 64]}}):
            with self.subTest(value=value), self.assertRaises(SecurityDataError):
                image_report(value, IMAGE)
        self.assertEqual(image_report(self.report(), IMAGE)['package_count'], 1)

    def test_image_findings_include_low_and_unfixed_cve_and_exact_image_id_is_checked(self):
        value = self.report()
        value['Results'][0]['Vulnerabilities'] = [
            {'VulnerabilityID': 'CVE-2026-12345', 'PkgName': 'openssl', 'InstalledVersion': '3.1.0',
             'Severity': 'LOW', 'FixedVersion': ''}]
        result = image_report(value, IMAGE, expected_image_id='sha256:' + 'b' * 64)
        self.assertEqual(result['findings'][0]['id'], 'CVE-2026-12345')
        self.assertEqual(result['findings'][0]['severity'], 'LOW')
        with self.assertRaises(SecurityDataError):
            image_report(value, IMAGE, expected_image_id='sha256:' + 'c' * 64)

    def test_trivy_download_and_payload_publication_have_independent_72h_limits(self):
        self.database()
        proof = trivy_database_source(self.root, now=NOW + timedelta(hours=72))
        self.assertEqual(proof['content_sha256'], hashlib.sha256((self.root / 'cache/db/trivy.db').read_bytes()).hexdigest())
        with self.assertRaises(SecurityDataError):
            trivy_database_source(self.root, now=NOW + timedelta(hours=72, microseconds=1))
        self.database(downloaded=NOW, published=NOW - timedelta(hours=73))
        with self.assertRaises(SecurityDataError):
            trivy_database_source(self.root, now=NOW)
        self.database(downloaded=NOW + timedelta(seconds=1))
        with self.assertRaises(SecurityDataError):
            trivy_database_source(self.root, now=NOW)

    def test_trivy_invalid_metadata_does_not_gain_freshness_from_file_mtime(self):
        self.database()
        (self.root / 'cache/db/metadata.json').write_text('{"Version":2,"Version":2}')
        with self.assertRaises(SecurityDataError):
            trivy_database_source(self.root, now=NOW)

    def test_sast_requires_actual_nonzero_coverage_without_parse_errors(self):
        good = {'results': [], 'errors': [], 'paths': {'scanned': ['src/app.py']}}
        self.assertEqual(validate_tool_report('opengrep', good, ['src/app.py'])['outcome'], 'pass')
        for report in ({}, {**good, 'paths': {'scanned': []}},
                       {**good, 'errors': [{'level': 'error', 'type': 'ParseError'}]},
                       {**good, 'errors': [{'level': 'warn', 'type': 'PartialParsing'}]},
                       {**good, 'errors': [{'level': 'warn', 'type': 'Syntax error'}]},
                       {**good, 'errors': [{'level': 'info', 'type': 'Timeout'}]},
                       {**good, 'errors': [None]}):
            with self.subTest(report=report), self.assertRaises(SecurityDataError):
                validate_tool_report('opengrep', report, ['src/app.py'])
        bandit = {'errors': [], 'results': [], 'metrics': {'_totals': {'loc': 1}, 'src/app.py': {'loc': 1}}}
        self.assertEqual(validate_tool_report('bandit', bandit, ['src/app.py'])['outcome'], 'pass')
        uncovered = copy.deepcopy(bandit)
        uncovered['metrics'].pop('src/app.py')
        with self.assertRaises(SecurityDataError):
            validate_tool_report('bandit', uncovered, ['src/app.py'])

    def test_misconfiguration_requires_target_coverage_and_nonfailure_results(self):
        report = {'SchemaVersion': 2, 'Results': [{'Target': 'Dockerfile', 'Class': 'config',
                  'MisconfSummary': {'Successes': 8, 'Failures': 0, 'Exceptions': 0},
                  'Misconfigurations': []}]}
        self.assertEqual(validate_tool_report('trivy-config', report, ['Dockerfile'])['outcome'], 'pass')
        with self.assertRaises(SecurityDataError):
            validate_tool_report('trivy-config', report, ['Dockerfile', 'service/Dockerfile'])

    def test_secret_values_are_not_returned_and_unreadable_inputs_block(self):
        assignment = 'pass' + 'word'
        placeholder = 'this-is-a-fixture-password'
        (self.root / 'app.py').write_text(f'{assignment} = "{placeholder}"\n')
        with mock.patch('getzilla.security_tools.dispositions.Dispositions', autospec=True) as policy:
            policy.return_value.secret.return_value = None
            report = scan_secrets(self.root, ['app.py'], trusted_root=self.root)
        self.assertEqual(report['outcome'], 'finding')
        self.assertNotIn('this-is-a-fixture-password', json.dumps(report))
        blocked = scan_secrets(self.root, ['missing.py'], trusted_root=self.root)
        self.assertEqual(blocked['outcome'], 'blocked')


if __name__ == '__main__':
    unittest.main()
