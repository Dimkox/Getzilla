"""Decision-relevant OSV aliases must survive acquisition and final consumption."""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from getzilla import expanded_security, security_data
from getzilla.architecture_diff import _git_command, _git_environment
from getzilla import security_osv_snapshot as known_vulns
from getzilla.security_acquisition import FetchResult, refresh_feeds
from tests.test_security_intelligence import NOW, epss_payload, kev_payload

MISSING = object()
ADVISORY = 'GHSA-alias-contract-fixture'
CVE = 'CVE-2026-12345'
INVALID = (CVE, {}, 1, True, [1], [None], [{}])
RAW_ONLY = ([''], [' '])
INVALID_DECISION = ['CVE-2026-12345\n']


def record(aliases=MISSING):
    value = {'id': ADVISORY, 'modified': '2026-11-03T00:00:00Z', 'affected': [{
        'package': {'ecosystem': 'PyPI', 'name': 'sample'}, 'versions': ['1.0.0'],
    }]}
    if aliases is not MISSING:
        value['aliases'] = aliases
    return value


def archive(aliases=MISSING):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr(zipfile.ZipInfo(ADVISORY + '.json', date_time=(2026, 11, 3, 12, 0, 0)),
                        json.dumps(record(aliases)))
    return buffer.getvalue()


def refresh(database, aliases=MISSING):
    payloads = {security_data.SOURCE_URLS['osv:PyPI']: archive(aliases),
                security_data.SOURCE_URLS['kev']: kev_payload(),
                security_data.SOURCE_URLS['epss']: epss_payload()}
    return refresh_feeds(database, ['PyPI'],
        fetch=lambda url: FetchResult(payloads[url], url, url, 200), now=NOW)


class OnlineAliasTests(unittest.TestCase):
    def query(self, aliases=MISSING):
        def fetch(url, body):
            if url.endswith('/querybatch'):
                return json.dumps({'results': [{'vulns': [{'id': ADVISORY}]}]}).encode()
            self.assertTrue(url.endswith('/vulns/' + ADVISORY))
            return json.dumps(record(aliases)).encode()
        dependency = known_vulns.Dependency('PyPI', 'sample', '1.0.0', 'requirements.txt')
        return known_vulns.query_online([dependency], fetch=fetch)[0]

    def test_online_preserves_valid_optional_aliases_without_coercion(self):
        for value, expected in ((MISSING, []), (None, []), ([], []), ([CVE, 'x_fixture:2026_1'], [CVE, 'x_fixture:2026_1'])):
            with self.subTest(value=value):
                self.assertEqual(self.query(value).aliases, expected)
        for value in INVALID:
            with self.subTest(value=value), self.assertRaisesRegex(known_vulns.VulnerabilityError, 'aliases'):
                self.query(value)
        for value in RAW_ONLY:
            finding = self.query(value)
            self.assertEqual(finding.raw_aliases, value)
            self.assertEqual(finding.aliases, [])
        with self.assertRaisesRegex(known_vulns.VulnerabilityError, 'decision identifier'):
            self.query(INVALID_DECISION)


@unittest.skipUnless(security_data.DESCRIPTOR_IO_AVAILABLE, 'snapshot I/O requires qualified POSIX directory descriptors')
class SnapshotAliasTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='getzilla-alias-contract-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / '.getzilla/runtime/security-data'

    def test_malformed_refresh_preserves_previous_pointer_and_aliases(self):
        self.assertTrue(all(item['status'] == 'pass' for item in refresh(self.database, [CVE])))
        pointer = self.database / 'PyPI/snapshot.json'
        previous = pointer.read_bytes()
        for value in INVALID:
            with self.subTest(value=value):
                results = {item['source_id']: item for item in refresh(self.database, value)}
                self.assertEqual(results['osv:PyPI']['status'], 'fail')
                self.assertIn('aliases', str(results['osv:PyPI']))
                self.assertEqual(pointer.read_bytes(), previous)
                payload, _ = security_data.read_snapshot(self.database, 'osv:PyPI', now=NOW)
                self.assertEqual(payload, archive([CVE]))
        for value in (MISSING, None, [], [CVE, 'x_fixture:2026_1']):
            with self.subTest(valid=value):
                self.assertTrue(all(item['status'] == 'pass' for item in refresh(self.database, value)))
        for value in (*RAW_ONLY, INVALID_DECISION):
            self.assertTrue(all(item['status'] == 'pass' for item in refresh(self.database, value)))
            self.assertEqual(security_data.read_snapshot(self.database, 'osv:PyPI', now=NOW)[0], archive(value))
        with self.assertRaises(known_vulns.VulnerabilityError):
            known_vulns.query_offline([known_vulns.Dependency('PyPI','sample','1.0.0','requirements.txt')],
                                      self.database, now=NOW)

    def test_consumer_revalidates_malformed_preexisting_snapshot_with_matching_hashes(self):
        self.assertTrue(all(item['status'] == 'pass' for item in refresh(self.database, [CVE])))
        pointer = self.database / 'PyPI/snapshot.json'
        original = json.loads(pointer.read_text(encoding='utf-8'))
        for value in INVALID:
            with self.subTest(value=value):
                payload = archive(value)
                digest = hashlib.sha256(payload).hexdigest()
                # Simulate old, coherently hashed producer output in this private fixture.
                # Do not patch the real publication or consumption validators.
                (self.database / '.snapshots/sha256' / digest).write_bytes(payload)
                manifest = dict(original, content_sha256=digest, payload_size=len(payload))
                pointer.write_text(json.dumps(manifest), encoding='utf-8', newline='\n')
                with self.assertRaisesRegex(security_data.SecurityDataError, 'aliases'):
                    security_data.read_snapshot(self.database, 'osv:PyPI', now=NOW)
        pointer.write_text(json.dumps(original), encoding='utf-8', newline='\n')
        self.assertEqual(security_data.read_snapshot(self.database, 'osv:PyPI', now=NOW)[0], archive([CVE]))
        payload = archive(INVALID_DECISION)
        digest = hashlib.sha256(payload).hexdigest()
        (self.database / '.snapshots/sha256' / digest).write_bytes(payload)
        pointer.write_text(json.dumps(dict(original, content_sha256=digest, payload_size=len(payload))))
        self.assertEqual(security_data.read_snapshot(self.database, 'osv:PyPI', now=NOW)[0], payload)
        with self.assertRaises(known_vulns.VulnerabilityError):
            known_vulns.query_offline([known_vulns.Dependency('PyPI','sample','1.0.0','requirements.txt')],
                                      self.database, now=NOW)

    def test_ordinary_exception_does_not_hide_kev_or_turn_malformed_source_into_no_match(self):
        wrong_osv = self.root / 'invalid-osv-store'
        wrong_security = self.root / 'invalid-security-store'
        wrong_osv.mkdir(mode=0o700)
        wrong_security.mkdir(mode=0o700)
        for label, osv, security in (('absent', None, None), ('empty', '', ''),
                                     ('owned-osv', str(wrong_osv), ''),
                                     ('owned-security', '', str(wrong_security))):
            with self.subTest(selector=label), mock.patch.dict(
                    os.environ, {'GETZILLA_OSV_DB': '', 'GETZILLA_SECURITY_DB': ''}):
                for key, value in (('GETZILLA_OSV_DB', osv), ('GETZILLA_SECURITY_DB', security)):
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
                self.check_ordinary_exception_and_kev(self.root / label)

    def check_ordinary_exception_and_kev(self, parent):
        for name, aliases in (('valid', [CVE]), ('malformed', CVE)):
            with self.subTest(case=name):
                root = parent / name
                root.mkdir(parents=True)
                (root / 'requirements.txt').write_text('sample==1.0.0\n', encoding='utf-8', newline='\n')
                config = root / '.getzilla/config'
                config.mkdir(parents=True)
                (config / 'known-vulnerabilities.json').write_text(json.dumps({'accept': [{
                    'id': ADVISORY, 'reason': 'synthetic ordinary exception', 'expires': '2026-12-01',
                }]}), encoding='utf-8', newline='\n')
                # An actual tiny Git root isolates fixtures beneath a canonical
                # runtime from the enclosing repository's source-root guard.
                def git(*arguments):
                    return subprocess.run(_git_command(list(arguments), safe_directory=root),
                        cwd=root, env=_git_environment(), stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, check=True, timeout=10).stdout
                git('init', '-q', '--template=')
                (root / '.git/info').mkdir(exist_ok=True)
                self.assertEqual(Path(os.fsdecode(git('rev-parse', '--show-toplevel')).strip()).resolve(), root.resolve())
                paths = ['requirements.txt', '.getzilla/config/known-vulnerabilities.json']
                git('add', '--', *paths)
                git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    '-c', 'maintenance.auto=false', 'commit', '-qm', 'Pin the owned alias fixture')
                tree = git('rev-parse', 'HEAD^{tree}').decode().strip()
                self.assertEqual(set(git('ls-tree', '-r', '--name-only', tree).decode().splitlines()), set(paths))
                refresh(root / '.getzilla/runtime/security-data', aliases)
                checks = {item['name']: item for item in expanded_security.run_checks(root, environ={}, now=NOW)}
                kev = checks['security-kev']
                epss = checks['security-epss']
                self.assertEqual(kev['status'], 'fail')
                if name == 'valid':
                    ordinary = expanded_security.known_vulnerability_report(root, environ={}, now=NOW)
                    self.assertEqual(ordinary['status'], 'pass', ordinary.get('gaps', ordinary.get('summary')))
                    self.assertEqual(ordinary['dependencies'], 1)
                    self.assertEqual(len(ordinary['accepted']), 1)
                    self.assertEqual(len(kev['details'][0]['findings']), 1)
                    self.assertEqual(epss['details'][0]['findings'][0]['intelligence'][CVE]['epss'], 0.25)
                else:
                    self.assertTrue(kev['details'][0]['gaps'])
                    self.assertEqual(epss['status'], 'fail')
                    self.assertTrue(epss['details'][0]['gaps'])


if __name__ == '__main__':
    unittest.main()
