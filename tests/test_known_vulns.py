from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import known_vulns as KV  # noqa: E402

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


def _mirror(root: Path, ecosystem: str, records: list[dict]) -> None:
    target = root / ecosystem / 'all.zip'
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, 'w') as bundle:
        for record in records:
            bundle.writestr(f"{record['id']}.json", json.dumps(record))


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

    def test_unparseable_manifest_fails_closed(self) -> None:
        tmp, root = _repo({'package-lock.json': '{not json'})
        with tmp, self.assertRaisesRegex(KV.VulnerabilityError, 'cannot parse package-lock.json'):
            KV.collect_dependencies(root)


class OfflineTests(unittest.TestCase):
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

    def test_missing_ecosystem_archive_fails_closed(self) -> None:
        tmp, root = _repo({'requirements.txt': 'jinja2==2.11.0\n'})
        with tmp, tempfile.TemporaryDirectory() as db, self.assertRaisesRegex(KV.VulnerabilityError, 'PyPI/all.zip'):
            KV.scan(root, environ={'GETZILLA_OSV_DB': db})

    def test_range_edges(self) -> None:
        affected = {'ranges': [{'type': 'ECOSYSTEM', 'events': [
            {'introduced': '1.0'}, {'fixed': '1.5'}, {'introduced': '2.0'}, {'last_affected': '2.3'}]}]}
        for version, expected in (('0.9', False), ('1.0', True), ('1.4.9', True), ('1.5', False),
                                  ('2.0', True), ('2.3', True), ('2.3.1', False), ('10.0', False)):
            with self.subTest(version=version):
                self.assertEqual(KV._in_ranges(version, affected), expected)
        open_ended = {'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '3.0.0'}]}]}
        self.assertTrue(KV._in_ranges('9.9.9', open_ended))
        self.assertFalse(KV._in_ranges('2.9.9', open_ended))
        self.assertFalse(KV._in_ranges('1.0', {'ranges': [{'type': 'GIT', 'events': [{'introduced': '0'}]}]}))


class OnlineTests(unittest.TestCase):
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


class QualityGateTests(unittest.TestCase):
    def test_only_the_two_explicit_skip_reasons_are_admitted(self) -> None:
        from types import SimpleNamespace

        from getzilla.quality_gates import required_check_refused

        def result(status: str, summary: str) -> SimpleNamespace:
            return SimpleNamespace(name='known-vulnerabilities', status=status, summary=summary)

        for summary in ('no pinned dependencies in lockfiles or requirements',
                        '34 pinned dependencies not checked: set GETZILLA_OSV_DB or GETZILLA_OSV_ONLINE=1'):
            self.assertFalse(required_check_refused(result('skip', summary), mode='pr'))
        self.assertTrue(required_check_refused(result('skip', 'OSV unavailable'), mode='pr'))
        self.assertTrue(required_check_refused(result('fail', '1 known vulnerabilities'), mode='pr'))
        self.assertFalse(required_check_refused(result('fail', '1 known vulnerabilities'), mode='fast'))


class DownloadTests(unittest.TestCase):
    def test_download_writes_verified_archives_atomically(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as bundle:
            bundle.writestr('A.json', json.dumps(JINJA))
        urls: list[str] = []

        def fetch(url: str, body: bytes | None) -> bytes:
            urls.append(url)
            return buffer.getvalue()

        with tempfile.TemporaryDirectory() as db:
            written = KV.download_database(Path(db), ['PyPI', 'npm'], fetch=fetch)
            self.assertEqual([Path(item).relative_to(db).as_posix() for item in written], ['PyPI/all.zip', 'npm/all.zip'])
            self.assertFalse(list(Path(db).rglob('*.partial')))
        self.assertEqual(urls, [f'{KV.OSV_BUCKET}/PyPI/all.zip', f'{KV.OSV_BUCKET}/npm/all.zip'])
        with tempfile.TemporaryDirectory() as db, self.assertRaises(KV.VulnerabilityError):
            KV.download_database(Path(db), ['Maven'], fetch=fetch)


if __name__ == '__main__':
    unittest.main()
