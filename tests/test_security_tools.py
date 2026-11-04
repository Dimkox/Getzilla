from __future__ import annotations

import ast
import base64
import codecs
import copy
import hashlib
import json
import struct
import tempfile
import unittest
import zlib
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

    def test_supported_source_encodings_keep_the_same_secret_finding(self):
        sentinel = 'only-public-test-content'
        assignment = 'pass' + 'word = ' + repr(sentinel) + '\n'
        for name, data in (
            ('app.py', ('# café\n' + assignment).encode()),
            ('app.py', ('# coding: latin-1\n# café\n' + assignment).encode('latin-1')),
            ('worker', ('#!/usr/bin/env python3\n# coding: latin-1\n# café\n' + assignment).encode('latin-1')),
            ('config.ps1', codecs.BOM_UTF16_LE + assignment.encode('utf-16-le')),
            ('config.ps1', codecs.BOM_UTF16_BE + assignment.encode('utf-16-be')),
            ('config.txt', codecs.BOM_UTF32_LE + assignment.encode('utf-32-le')),
        ):
            with self.subTest(name=name, digest=hashlib.sha256(data).hexdigest()):
                (self.root / name).write_bytes(data)
                if name in {'app.py', 'worker'}:
                    ast.parse(data)  # Parse the source bytes without executing the fixture.
                result = scan_secrets(self.root, [name], trusted_root=self.root)
                self.assertEqual(result['outcome'], 'finding')
                self.assertEqual([item['rule'] for item in result['findings']], ['generic-secret'])
                self.assertNotIn(sentinel, json.dumps(result))
                self.assertEqual(result['binary_inputs'], [])

    def test_unknown_or_corrupt_source_blocks_without_requesting_a_custom_codec(self):
        requested = []

        def observe(name):
            requested.append(name)
            return None

        codecs.register(observe)
        self.addCleanup(codecs.unregister, observe)
        for name, data in (
            ('job.py', b'# coding: getzilla-probe-unknown\nprint(1)\n'),
            ('job.py', b'\x00# coding: latin-1\n\xff'),
            ('config.yaml', b'name: a\xff'),
            ('Dockerfile', b'\x00FROM scratch\n'),
            ('script', b'#!/bin/sh\n# \xff\n'),
            ('ambiguous.bin', b'\x00\xffdata'),
            ('impostor.png', b'\xffnot a PNG'),
            ('broken.ps1', codecs.BOM_UTF16_LE + b'\x00'),
        ):
            with self.subTest(name=name, digest=hashlib.sha256(data).hexdigest()):
                (self.root / name).write_bytes(data)
                result = scan_secrets(self.root, [name], trusted_root=self.root)
                self.assertEqual(result['outcome'], 'blocked')
                self.assertTrue(result['gaps'])
                self.assertEqual(result['binary_inputs'], [])
        self.assertNotIn('getzilla_probe_unknown', requested)

    def test_binary_asset_is_disclosed_while_known_source_cannot_use_its_signature(self):
        pixel = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+mGz8AAAAASUVORK5CYII=')
        for name, expected in [('pixel.png', 'pass'), ('module.py', 'blocked')]:
            with self.subTest(name=name):
                (self.root / name).write_bytes(pixel)
                result = scan_secrets(self.root, [name], trusted_root=self.root)
                self.assertEqual(result['outcome'], expected)
                if name == 'pixel.png':
                    self.assertEqual(result['binary_inputs'][0]['sha256'], hashlib.sha256(pixel).hexdigest())
                else:
                    self.assertFalse(result['binary_inputs'])

    def test_plain_text_with_asset_signature_still_gets_one_redacted_finding(self):
        sentinel = 'only-public-asset-fixture'
        assignment = 'pass' + 'word = ' + repr(sentinel) + '\n'
        for suffix, identifier in (('gif', 'GIF89a'), ('woff2', 'wOF2')):
            with self.subTest(suffix=suffix):
                name = 'source.' + suffix
                raw = (identifier + ' = 1\n' + assignment).encode()
                ast.parse(raw)
                (self.root / name).write_bytes(raw)
                result = scan_secrets(self.root, [name], trusted_root=self.root)
                self.assertEqual(result['outcome'], 'finding')
                self.assertEqual([f['rule'] for f in result['findings']], ['generic-secret'])
                self.assertFalse(result['binary_inputs'])
                self.assertNotIn(sentinel, json.dumps(result))

    def test_real_png_metadata_is_scanned_for_visible_patterns(self):
        def chunk(kind, content):
            return (struct.pack('>I', len(content)) + kind + content
                    + struct.pack('>I', zlib.crc32(kind + content)))

        header = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
        sentinel = 'only-public-pixel-metadata'
        assignment = ('pass' + 'word = ' + repr(sentinel)).encode()
        for note, expected in ((b'pixel only', 'pass'), (assignment, 'finding')):
            with self.subTest(expected=expected):
                raw = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) + chunk(b'tEXt', b'Comment\0' + note)
                       + chunk(b'IDAT', zlib.compress(b'\0\0\0\0')) + chunk(b'IEND', b''))
                (self.root / 'pixel.png').write_bytes(raw)
                result = scan_secrets(self.root, ['pixel.png'], trusted_root=self.root)
                self.assertEqual(result['outcome'], expected)
                self.assertEqual(len(result['findings']), int(expected == 'finding'))
                self.assertEqual(result['binary_inputs'][0]['sha256'], hashlib.sha256(raw).hexdigest())
                if expected == 'finding':
                    self.assertEqual(result['findings'][0]['byte_offset'], raw.index(assignment))
                self.assertNotIn(sentinel, json.dumps(result))

    def test_visible_bytes_in_unknown_source_and_wide_text_are_not_lost(self):
        sentinel = 'only-public-visible-byte-fixture'
        assignment = ('pass' + 'word = ' + repr(sentinel)).encode()
        wide = codecs.BOM_UTF16_LE + '# text\n'.encode('utf-16-le') + assignment
        wide += b' ' * (len(wide) % 2)
        for raw, expected in ((b'\x00\xff\n' + assignment, 'blocked'), (wide, 'finding')):
            with self.subTest(expected=expected):
                (self.root / 'metadata.txt').write_bytes(raw)
                result = scan_secrets(self.root, ['metadata.txt'], trusted_root=self.root)
                self.assertEqual(result['outcome'], expected)
                self.assertEqual([f['rule'] for f in result['findings']], ['generic-secret'])
                self.assertEqual(result['findings'][0]['byte_offset'], raw.index(assignment))
                self.assertEqual(bool(result['gaps']), expected == 'blocked')
                self.assertNotIn(sentinel, json.dumps(result))


if __name__ == '__main__':
    unittest.main()
