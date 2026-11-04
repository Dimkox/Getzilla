from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import security_osv_snapshot as KV  # noqa: E402
from getzilla import security_data as SD  # noqa: E402

JINJA = {
    'id': 'GHSA-h5c8-rqwp-cp95',
    'aliases': ['CVE-2024-22195'],
    'summary': 'Jinja vulnerable to HTML attribute injection',
    'affected': [{
        'package': {'ecosystem': 'PyPI', 'name': 'Jinja2'},
        'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '3.1.3'}]}],
        'database_specific': {'severity': 'MODERATE'},
    }],
}
LODASH = {
    'id': 'GHSA-jf85-cpcp-j695',
    'aliases': ['CVE-2019-10744'],
    'summary': 'Prototype pollution in lodash',
    'database_specific': {'severity': 'CRITICAL'},
    'affected': [{
        'package': {'ecosystem': 'npm', 'name': 'lodash'},
        'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '4.17.12'}]}],
        'versions': ['4.17.11'],
    }],
}
WITHDRAWN = {'id': 'GHSA-gone', 'withdrawn': '2026-01-01T00:00:00Z',
             'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'jinja2'}, 'versions': ['2.11.0']}]}


def _git(root: Path) -> None:
    subprocess.run(['git', 'init', '-q'], cwd=root, check=True)


def _repo(files: dict[str, str]) -> tuple[tempfile.TemporaryDirectory, Path]:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    _git(root)
    return tmp, root


def _archive(records: list[dict]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as bundle:
        for record in records:
            bundle.writestr(f"{record['id']}.json", json.dumps(record))
    return output.getvalue()


def _mirror(root: Path, ecosystem: str, records: list[dict], *, acquired: datetime | None = None) -> None:
    acquired = acquired or datetime.now(timezone.utc)
    SD.publish_snapshot(root, f'osv:{ecosystem}', _archive(records),
                        acquisition={'last_verified_sync_utc': acquired.isoformat(), 'retrieval_kind': 'download'},
                        coverage={'scopes': [ecosystem], 'complete': True,
                                  'record_count': len(records), 'schema': 'osv-1'}, now=acquired)


MANIFESTS = {
    'requirements.txt': 'Jinja2==2.11.0  # pinned\nrequests>=2\n-e .\nflask[async]==3.0.0 ; python_version>"3"\n',
    'web/package-lock.json': json.dumps({'lockfileVersion': 3, 'packages': {
        '': {'name': 'web', 'version': '1.0.0'},
        'node_modules/lodash': {'version': '4.17.11'},
        'node_modules/@scope/pkg': {'version': '2.0.0'},
        'node_modules/linked': {'link': True},
    }}),
    'svc/go.mod': 'module example.com/svc\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n)\nrequire github.com/a/b v1.2.3\n',
    'rs/Cargo.lock': '[[package]]\nname = "local"\nversion = "0.1.0"\n\n[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
    'php/composer.lock': json.dumps({'packages': [{'name': 'guzzlehttp/guzzle', 'version': 'v7.4.0'}],
                                     'packages-dev': [{'name': 'x/y', 'version': 'dev-main'}]}),
    'rb/Gemfile.lock': 'GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n      nested (>= 1)\n    nokogiri (1.13.0-x86_64-linux)\n\nPLATFORMS\n  ruby\n',
    'py/uv.lock': '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "anyio"\nversion = "4.0.0"\nsource = { registry = "https://pypi.org/simple" }\n',
    'py/pyproject.toml': '[project]\nname = "app"\ndependencies = ["fastapi==0.100.0", "uvicorn>=0.20"]\n[project.optional-dependencies]\ntest = ["httpx==0.27.0"]\n',
    'tests/fixtures/requirements.txt': 'Jinja2==2.0\n',
}


class CollectTests(unittest.TestCase):
    def test_every_supported_manifest_yields_exact_pins_only(self) -> None:
        tmp, root = _repo(MANIFESTS)
        with tmp:
            deps, manifests = KV.collect_dependencies(root)
        found = {(item.ecosystem, item.name, item.version) for item in deps}
        self.assertEqual(found, {
            ('PyPI', 'Jinja2', '2.11.0'), ('PyPI', 'flask', '3.0.0'),
            ('npm', 'lodash', '4.17.11'), ('npm', '@scope/pkg', '2.0.0'),
            ('Go', 'golang.org/x/net', '0.17.0'), ('Go', 'github.com/a/b', '1.2.3'),
            ('crates.io', 'smallvec', '1.6.0'),
            ('Packagist', 'guzzlehttp/guzzle', '7.4.0'),
            ('RubyGems', 'rack', '2.2.3'), ('RubyGems', 'nokogiri', '1.13.0'),
            ('PyPI', 'anyio', '4.0.0'),
            ('PyPI', 'fastapi', '0.100.0'), ('PyPI', 'httpx', '0.27.0'),
        })
        self.assertNotIn('tests/fixtures/requirements.txt', manifests)

    def test_build_system_exact_pins_keep_manifest_provenance(self) -> None:
        tmp, root = _repo({'pyproject.toml': '[build-system]\nrequires = ["setuptools==75.8.0", "wheel>=0.40"]\n[project]\ndependencies = ["httpx==0.28.1", "setuptools==75.8.0"]\n[project.optional-dependencies]\ntest = ["pytest==8.3.0"]\n'})
        with tmp:
            deps, manifests = KV.collect_dependencies(root)
        self.assertEqual(manifests, ['pyproject.toml'])
        self.assertEqual({(item.name, item.version, item.manifest) for item in deps}, {
            ('setuptools', '75.8.0', 'pyproject.toml'), ('httpx', '0.28.1', 'pyproject.toml'),
            ('pytest', '8.3.0', 'pyproject.toml'),
        })
        self.assertEqual(len(deps), 3)

    def test_build_only_backend_pin_is_collected(self) -> None:
        tmp, root = _repo({'pyproject.toml': '[build-system]\nrequires = ["setuptools==75.8.0"]\n'})
        with tmp:
            deps, manifests = KV.collect_dependencies(root)
        self.assertEqual([(item.name, item.version, item.manifest) for item in deps],
                         [('setuptools', '75.8.0', 'pyproject.toml')])
        self.assertEqual(manifests, ['pyproject.toml'])

    def test_current_backend_pins_are_in_the_audit_inventory(self) -> None:
        dependencies, _ = KV.collect_dependencies(ROOT)
        for manifest in ('factory/pyproject.toml', 'delivery/pyproject.toml', 'trust-ci/pyproject.toml'):
            self.assertIn(KV.Dependency('PyPI', 'setuptools', '84.1.0', manifest), dependencies)

    def test_malformed_build_requirements_fail_closed(self) -> None:
        for value in ('"setuptools==84.0.0"', '7', 'true', '["setuptools==84.0.0", 7]'):
            tmp, root = _repo({'pyproject.toml': '[build-system]\nrequires = ' + value + '\n'})
            with tmp, self.subTest(value=value), self.assertRaises(KV.VulnerabilityError):
                KV.collect_dependencies(root)

    def test_unparseable_manifest_fails_closed(self) -> None:
        tmp, root = _repo({'package-lock.json': '{not json'})
        with tmp, self.assertRaisesRegex(KV.VulnerabilityError, 'cannot parse package-lock.json'):
            KV.collect_dependencies(root)


class OfflineTests(unittest.TestCase):
    def test_ecosystem_wildcard_evaluates_each_pinned_name_and_version(self):
        def row(eco, package, introduced, fixed):
            return {'package': {'name': package, 'ecosystem': eco}, 'ranges': [
                {'type': 'SEMVER', 'events': [{'introduced': introduced}, {'fixed': fixed}]}]}

        wildcard = {'id': 'OSV-WILDCARD', 'affected': [row('npm', '*', '0', '2.0.0')]}
        foreign = {'id': 'OSV-OTHER', 'affected': [row('PyPI', '*', '0', '9.0.0'),
                                                   row('npm', 'other', '0', '9.0.0')]}
        deps = [KV.Dependency('npm', name, version, 'package-lock.json') for name, version in
                [('first', '1.2.3'), ('second', '1.9.0'), ('first', '2.0.0')]]
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder)
            _mirror(database, 'npm', [wildcard, foreign])
            found = KV.query_offline(deps, database)
            self.assertEqual([(f.dependency.name, f.dependency.version, f.vuln_id, f.fixed) for f in found],
                             [('first', '1.2.3', 'OSV-WILDCARD', ['2.0.0']),
                              ('second', '1.9.0', 'OSV-WILDCARD', ['2.0.0'])])
            wildcard['affected'][0]['ranges'][0]['type'] = 'ECOSYSTEM'
            _mirror(database, 'npm', [wildcard])
            with self.assertRaisesRegex(KV.VulnerabilityError, 'unsupported OSV range semantics'):
                KV.query_offline(deps, database)

    def test_qualified_registry_matching_needs_dependency_source_identity(self):
        def record(identifier, ecosystem, name):
            return {'id': identifier, 'affected': [{'package': {'name': name, 'ecosystem': ecosystem},
                                                     'versions': ['1.0.0']}]}
        default = record('DEFAULT', 'Packagist', 'other/package')
        custom = record('CUSTOM', 'Packagist:https://packages.drupal.org/8', 'Drupal/Example')
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder)
            _mirror(database, 'Packagist', [default, custom])
            dep = KV.Dependency('Packagist', 'drupal/example', '1.0.0', 'composer.lock')
            with self.assertRaisesRegex(KV.VulnerabilityError, 'registry identity'):
                KV.query_offline([dep], database)
            with self.assertRaisesRegex(KV.VulnerabilityError, 'registry identity'):
                KV._describe(custom, dep)
            dep = KV.Dependency('Packagist', 'other/package', '1.0.0', 'composer.lock')
            self.assertEqual([finding.vuln_id for finding in KV.query_offline([dep], database)], ['DEFAULT'])
            custom['affected'][0]['package']['name'] = '*'
            _mirror(database, 'Packagist', [default, custom])
            with self.assertRaisesRegex(KV.VulnerabilityError, 'registry identity'):
                KV.query_offline([dep], database)

    def test_old_nonempty_legacy_archive_requires_refresh(self) -> None:
        tmp, root = _repo({'requirements.txt': 'safe-package==1.0\n'})
        with tmp, tempfile.TemporaryDirectory() as db:
            archive = Path(db) / 'PyPI/all.zip'
            archive.parent.mkdir(parents=True)
            archive.write_bytes(_archive([JINJA]))
            old = (datetime.now(timezone.utc) - timedelta(hours=73)).timestamp()
            os.utime(Path(db) / 'PyPI/all.zip', (old, old))
            with self.assertRaisesRegex(KV.VulnerabilityError, 'refresh'):
                KV.scan(root, environ={'GETZILLA_OSV_DB': db})

    def test_valid_old_snapshot_is_blocked_but_exact_72_hours_is_accepted(self) -> None:
        now = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
        tmp, root = _repo({'requirements.txt': 'safe-package==1.0\n'})
        with tmp, tempfile.TemporaryDirectory() as db:
            _mirror(Path(db), 'PyPI', [JINJA], acquired=now - timedelta(hours=72))
            report = KV.scan(root, environ={'GETZILLA_OSV_DB': db}, now=now)
            self.assertEqual(report['status'], 'pass')
            self.assertEqual(report['source_evidence'][0]['age_seconds'], 259200)
            with self.assertRaisesRegex(KV.VulnerabilityError, 'stale'):
                KV.scan(root, environ={'GETZILLA_OSV_DB': db}, now=now + timedelta(seconds=1))

    def test_one_fresh_ecosystem_does_not_mask_another_stale_snapshot(self) -> None:
        now = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
        tmp, root = _repo({'requirements.txt': 'Jinja2==4.0.0\n',
                           'package-lock.json': json.dumps({'packages': {'node_modules/lodash': {'version': '5.0.0'}}})})
        with tmp, tempfile.TemporaryDirectory() as db:
            _mirror(Path(db), 'PyPI', [JINJA], acquired=now)
            _mirror(Path(db), 'npm', [LODASH], acquired=now - timedelta(hours=73))
            with self.assertRaisesRegex(KV.VulnerabilityError, 'osv:npm.*stale'):
                KV.scan(root, environ={'GETZILLA_OSV_DB': db}, now=now)

    def test_semver_prerelease_before_fixed_release(self) -> None:
        affected = {
            'package': {'ecosystem': 'npm', 'name': 'example'},
            'ranges': [{'type': 'SEMVER', 'events': [
                {'introduced': '0'}, {'fixed': '1.0.0'},
            ]}],
        }
        self.assertTrue(KV._in_ranges('1.0.0-rc.1', affected))
        self.assertFalse(KV._in_ranges('1.0.0', affected))

    def test_offline_mirror_matches_ranges_and_enumerated_versions(self) -> None:
        tmp, root = _repo({'requirements.txt': 'jinja2==2.11.0\nJinja2==3.1.3\n',
                           'package-lock.json': json.dumps({'packages': {'node_modules/lodash': {'version': '4.17.11'}}})})
        with tmp, tempfile.TemporaryDirectory() as db:
            _mirror(Path(db), 'PyPI', [JINJA, WITHDRAWN])
            _mirror(Path(db), 'npm', [LODASH])
            report = KV.scan(root, environ={'GETZILLA_OSV_DB': db})
        self.assertEqual(report['status'], 'fail')
        hits = {(item['package'], item['version'], item['id']) for item in report['findings']}
        self.assertEqual(hits, {('jinja2', '2.11.0', 'GHSA-h5c8-rqwp-cp95'), ('lodash', '4.17.11', 'GHSA-jf85-cpcp-j695')})
        jinja = next(item for item in report['findings'] if item['package'] == 'jinja2')
        self.assertEqual((jinja['severity'], jinja['fixed'], jinja['aliases']), ('MODERATE', ['3.1.3'], ['CVE-2024-22195']))
        lodash = next(item for item in report['findings'] if item['package'] == 'lodash')
        self.assertEqual(lodash['severity'], 'CRITICAL')

    def test_build_backend_advisories_detect_old_pin_and_exclude_fixed_pin(self) -> None:
        records = [
            {'id': advisory, 'database_specific': {'severity': severity}, 'affected': [{
                'package': {'ecosystem': 'PyPI', 'name': 'setuptools'},
                'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': fixed}]}],
            }]}
            for advisory, severity, fixed in (
                ('GHSA-5rjg-fvgr-3xxf', 'HIGH', '78.1.1'),
                ('GHSA-h35f-9h28-mq5c', 'MODERATE', '83.0.0'),
            )
        ]
        for version in ('75.8.0', '84.0.0'):
            tmp, root = _repo({'pyproject.toml': '[build-system]\nrequires = ["setuptools==' + version + '"]\n'})
            with tmp, tempfile.TemporaryDirectory() as database, self.subTest(version=version):
                _mirror(Path(database), 'PyPI', records)
                report = KV.scan(root, environ={'GETZILLA_OSV_DB': database})
            expected = {'HIGH', 'MODERATE'} if version == '75.8.0' else set()
            self.assertEqual({item['severity'] for item in report['findings']}, expected)
            self.assertEqual(report['status'], 'fail' if expected else 'pass')

    def test_missing_ecosystem_archive_fails_closed(self) -> None:
        tmp, root = _repo({'requirements.txt': 'jinja2==2.11.0\n'})
        with tmp, tempfile.TemporaryDirectory() as db, self.assertRaisesRegex(KV.VulnerabilityError, 'PyPI/all.zip'):
            KV.scan(root, environ={'GETZILLA_OSV_DB': db})

    def test_range_edges(self) -> None:
        affected = {'package': {'ecosystem': 'PyPI'}, 'ranges': [
            {'type': 'ECOSYSTEM', 'events': [{'introduced': '1.0'}, {'fixed': '1.5'}]},
            {'type': 'ECOSYSTEM', 'events': [{'introduced': '2.0'}, {'last_affected': '2.3'}]},
        ]}
        for version, expected in (('0.9', False), ('1.0', True), ('1.4.9', True), ('1.5', False),
                                  ('2.0', True), ('2.3', True), ('2.3.1', False), ('10.0', False)):
            with self.subTest(version=version):
                self.assertEqual(KV._in_ranges(version, affected), expected)
        open_ended = {'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '3.0.0'}]}]}
        self.assertTrue(KV._in_ranges('9.9.9', open_ended))
        self.assertFalse(KV._in_ranges('2.9.9', open_ended))
        with self.assertRaises(KV.VulnerabilityError):
            KV._in_ranges('1.0', {'ranges': [{'type': 'GIT', 'events': [{'introduced': '0'}]}]})

    def test_semver_precedence_and_build_metadata(self) -> None:
        ordered = ['1.0.0-2', '1.0.0-11', '1.0.0-alpha', '1.0.0-alpha.1',
                   '1.0.0-beta', '1.0.0-rc.1', '1.0.0']
        for low, high in zip(ordered, ordered[1:]):
            affected = {'ranges': [{'type': 'SEMVER', 'events': [
                {'introduced': '0'}, {'fixed': high}]}]}
            with self.subTest(low=low, high=high):
                self.assertTrue(KV._in_ranges(low, affected))
                self.assertFalse(KV._in_ranges(high, affected))
        affected = {'ranges': [{'type': 'SEMVER', 'events': [
            {'introduced': '0'}, {'fixed': '1.0.0+001'}]}]}
        self.assertFalse(KV._in_ranges('1.0.0+other', affected))

    def test_invalid_semver_refuses_instead_of_guessing(self) -> None:
        affected = {'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}]}]}
        for version in ('1.0', '01.0.0', '1.0.0-01', '1.0.0-a..b', 'v1.0.0', '1.0.0+'):
            with self.subTest(version=version), self.assertRaises(KV.VulnerabilityError):
                KV._in_ranges(version, affected)

    def test_pypi_qualified_subset_ordering(self) -> None:
        pairs = [('1.0rc1', '1.0'), ('1.0.dev1', '1.0a1'), ('1.0a1', '1.0b1'),
                 ('1.0b1', '1.0rc1'), ('1.0', '1.0.post1'), ('1.0.post1.dev1', '1.0.post1'),
                 ('9999', '1!0.1'), ('1.0', '1.0+abc'), ('1.0+abc', '1.0+abc.1'),
                 ('1.0+abc', '1.0+1'), ('1.0a1.dev1', '1.0a1'),
                 ('1.0a1', '1.0a1.post1.dev1'), ('1.0a1.post1.dev1', '1.0a1.post1')]
        for low, high in pairs:
            affected = {'package': {'ecosystem': 'PyPI'}, 'ranges': [
                {'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': high}]}]}
            with self.subTest(low=low, high=high):
                self.assertTrue(KV._in_ranges(low, affected))
                self.assertFalse(KV._in_ranges(high, affected))
        for left, right in [('1.0', '1.0.0'), ('1.0+ABC', '1.0+abc')]:
            self.assertTrue(KV._in_ranges(left, {'package': {'ecosystem': 'PyPI'}, 'versions': [right]}))

    def test_unsupported_pypi_spelling_is_explicit(self) -> None:
        for version in ('v1.0', '1.0c1', '1.0-1', '1.0_preview1', ' 1.0'):
            with self.subTest(version=version), self.assertRaises(KV.VulnerabilityError):
                KV._in_ranges(version, {'package': {'ecosystem': 'PyPI'}, 'ranges': [
                    {'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}]}]})

    def test_unsorted_events_have_same_semantics(self) -> None:
        affected = {'ranges': [{'type': 'SEMVER', 'events': [
            {'fixed': '2.0.0'}, {'introduced': '1.0.0'}]}]}
        self.assertTrue(KV._in_ranges('1.5.0', affected))
        self.assertFalse(KV._in_ranges('2.0.0', affected))

    def test_limit_is_an_exclusive_union_guard(self) -> None:
        affected = {'ranges': [{'type': 'SEMVER', 'events': [
            {'limit': '2.0.0'}, {'introduced': '0'}, {'limit': '3.0.0'}]}]}
        self.assertTrue(KV._in_ranges('2.5.0', affected))
        self.assertFalse(KV._in_ranges('3.0.0', affected))
        affected['ranges'][0]['events'].append({'limit': '*'})
        self.assertTrue(KV._in_ranges('4.0.0', affected))

    def test_malformed_or_unknown_ranges_cannot_be_clean(self) -> None:
        ranges = [None, {}, [{'type': 'SEMVER', 'events': []}],
                  [{'type': 'SEMVER', 'events': [{'fixed': '1.0.0'}]}],
                  [{'type': 'SEMVER', 'events': [{'introduced': '0', 'fixed': '1.0.0'}]}],
                  [{'type': 'SEMVER', 'events': [{'introduced': 0}]}],
                  [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'unknown': '2.0.0'}]}],
                  [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '1.0.0'}, {'last_affected': '2.0.0'}]}],
                  [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}]}],
                  [{'type': 'GIT', 'events': [{'introduced': '0'}]}]]
        for value in ranges:
            with self.subTest(ranges=value), self.assertRaises(KV.VulnerabilityError):
                KV._in_ranges('1.0.0', {'package': {'ecosystem': 'Maven'}, 'ranges': value})

    def test_enumerated_hit_is_positive_but_miss_does_not_hide_unknown_range(self) -> None:
        affected = {'package': {'ecosystem': 'Maven'}, 'versions': ['1.0.0'],
                    'ranges': [{'type': 'GIT', 'events': [{'introduced': '0'}]}]}
        self.assertTrue(KV._in_ranges('1.0.0', affected))
        with self.assertRaises(KV.VulnerabilityError):
            KV._in_ranges('1.0.1', affected)


class OnlineTests(unittest.TestCase):
    def test_online_batch_hit_describes_only_applicable_wildcard_rows(self):
        def row(eco, introduced, fixed, severity):
            return {'package': {'name': '*', 'ecosystem': eco}, 'ranges': [
                {'type': 'SEMVER', 'events': [{'introduced': introduced}, {'fixed': fixed}]}],
                'database_specific': {'severity': severity}}

        record = {'id': 'OSV-WILDCARD', 'affected': [row('npm', '3.0.0', '4.0.0', 'LOW'),
                  row('PyPI', '0', '6.0.0', 'LOW'), row('npm', '0', '2.0.0', 'HIGH')]}
        def fetch(url, body):
            value = {'results': [{'vulns': [{'id': record['id']}]}]} if body is not None else record
            return json.dumps(value).encode()

        dep = KV.Dependency('npm', 'first', '1.2.3', 'package-lock.json')
        hit, = KV.query_online([dep], fetch=fetch)
        self.assertEqual((hit.fixed, hit.severity), (['2.0.0'], 'HIGH'))
        record['affected'][-1]['ranges'][0]['type'] = 'ECOSYSTEM'
        with self.assertRaisesRegex(KV.VulnerabilityError, 'unsupported OSV range semantics'):
            KV.query_online([dep], fetch=fetch)

    def test_online_batches_paginate_and_fetch_details(self) -> None:
        calls: list[tuple[str, dict | None]] = []

        def fetch(url: str, body: bytes | None) -> bytes:
            payload = json.loads(body) if body else None
            calls.append((url, payload))
            if url.endswith('/querybatch'):
                queries = payload['queries']
                if any('page_token' in item for item in queries):
                    return json.dumps({'results': [{'vulns': [{'id': 'PYSEC-2021-66'}]}]}).encode()
                return json.dumps({'results': [
                    {'vulns': [{'id': JINJA['id']}], 'next_page_token': 'p2'} if item['package']['name'] == 'Jinja2' else {}
                    for item in queries
                ]}).encode()
            vuln_id = url.rsplit('/', 1)[1]
            if vuln_id == JINJA['id']:
                return json.dumps(JINJA).encode()
            return json.dumps({'id': vuln_id, 'aliases': ['CVE-2020-28493'], 'affected': []}).encode()

        tmp, root = _repo({'requirements.txt': 'Jinja2==2.11.0\nsafe-lib==1.0\n'})
        with tmp:
            report = KV.scan(root, environ={'GETZILLA_OSV_ONLINE': '1'}, fetch=fetch)
        self.assertEqual(report['status'], 'fail')
        self.assertEqual(sorted(item['id'] for item in report['findings']), ['GHSA-h5c8-rqwp-cp95', 'PYSEC-2021-66'])
        first = calls[0][1]['queries']
        self.assertEqual({item['package']['ecosystem'] for item in first}, {'PyPI'})
        self.assertEqual(calls[1][1]['queries'], [{'package': {'name': 'Jinja2', 'ecosystem': 'PyPI'},
                                                   'version': '2.11.0', 'page_token': 'p2'}])

    def test_network_failure_fails_closed(self) -> None:
        def fetch(url: str, body: bytes | None) -> bytes:
            raise OSError('unreachable')

        tmp, root = _repo({'requirements.txt': 'Jinja2==2.11.0\n'})
        with tmp, self.assertRaisesRegex(KV.VulnerabilityError, 'OSV query failed'):
            KV.scan(root, environ={'GETZILLA_OSV_ONLINE': '1'}, fetch=fetch)


class PolicyTests(unittest.TestCase):
    def test_without_a_source_nothing_is_contacted_and_the_check_skips(self) -> None:
        def fetch(url: str, body: bytes | None) -> bytes:
            raise AssertionError('no network without opt-in')

        tmp, root = _repo({'requirements.txt': 'Jinja2==2.11.0\n'})
        with tmp:
            report = KV.scan(root, environ={}, fetch=fetch)
        self.assertEqual(report['status'], 'skip')
        self.assertIn('GETZILLA_OSV_ONLINE', report['summary'])
        tmp, root = _repo({'README.md': 'x'})
        with tmp:
            self.assertEqual(KV.scan(root, environ={'GETZILLA_OSV_ONLINE': '1'}, fetch=fetch)['status'], 'skip')

    def test_acceptance_is_by_id_or_alias_and_expires(self) -> None:
        config = {'accept': [{'id': 'CVE-2024-22195', 'reason': 'template input is trusted', 'expires': '2026-12-31'}]}
        tmp, root = _repo({'requirements.txt': 'Jinja2==2.11.0\n',
                           KV.CONFIG_PATH: json.dumps(config)})
        with tmp, tempfile.TemporaryDirectory() as db:
            _mirror(Path(db), 'PyPI', [JINJA])
            before = KV.scan(root, environ={'GETZILLA_OSV_DB': db}, today=date(2026, 12, 31))
            after = KV.scan(root, environ={'GETZILLA_OSV_DB': db}, today=date(2027, 1, 1))
        self.assertEqual(before['status'], 'pass')
        self.assertEqual(before['accepted'][0]['accepted_until'], '2026-12-31')
        self.assertEqual(after['status'], 'fail')

    def test_invalid_configuration_is_rejected(self) -> None:
        for config in ({'accept': [{'id': 'X', 'reason': '', 'expires': '2026-01-01'}]},
                       {'accept': [{'id': 'X', 'reason': 'r', 'expires': 'soon'}]},
                       {'accept': [{'id': 'X'}]},
                       {'exclude': 'tests/**'}):
            tmp, root = _repo({KV.CONFIG_PATH: json.dumps(config)})
            with tmp, self.subTest(config=config), self.assertRaises(KV.VulnerabilityError):
                KV.load_config(root)










class DownloadTests(unittest.TestCase):
    def test_compatibility_export_failure_reports_the_committed_snapshot_path(self) -> None:
        replace = SD.os.replace

        def fail_export(source, destination, **kwargs):
            if Path(destination).name == 'all.zip':
                raise OSError('compatibility export unavailable')
            replace(source, destination, **kwargs)

        with tempfile.TemporaryDirectory() as db, mock.patch.object(SD.os, 'replace', side_effect=fail_export):
            written = KV.download_database(Path(db), ['PyPI'], fetch=lambda url, body: _archive([JINJA]))
            self.assertTrue(all(Path(path).is_file() for path in written), written)
            payload, evidence = SD.read_snapshot(Path(db), 'osv:PyPI')
            self.assertEqual(evidence['coverage']['record_count'], 1)
            self.assertTrue(payload.startswith(b'PK'))

    def test_download_writes_verified_archives_atomically(self) -> None:
        urls: list[str] = []

        def fetch(url: str, body: bytes | None) -> bytes:
            urls.append(url)
            return _archive([JINJA if '/PyPI/' in url else LODASH])

        with tempfile.TemporaryDirectory() as db:
            written = KV.download_database(Path(db), ['PyPI', 'npm'], fetch=fetch)
            self.assertEqual([Path(item).relative_to(db).as_posix() for item in written], ['PyPI/all.zip', 'npm/all.zip'])
            for ecosystem in ('PyPI', 'npm'):
                payload, evidence = SD.read_snapshot(Path(db), f'osv:{ecosystem}', required_scope={ecosystem})
                self.assertEqual(payload, (Path(db) / ecosystem / 'all.zip').read_bytes())
                self.assertEqual(evidence['coverage']['record_count'], 1)
            self.assertFalse(list(Path(db).rglob('*.partial')))
        self.assertEqual(urls, [f'{KV.OSV_BUCKET}/PyPI/all.zip', f'{KV.OSV_BUCKET}/npm/all.zip'])
        with tempfile.TemporaryDirectory() as db, self.assertRaises(KV.VulnerabilityError):
            KV.download_database(Path(db), ['Hex'], fetch=fetch)  # an ecosystem Getzilla does not download


if __name__ == '__main__':
    unittest.main()
