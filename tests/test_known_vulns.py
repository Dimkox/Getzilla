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


def _legacy_mirror(root: Path, ecosystem: str, records: list[dict]) -> None:
    target = root / ecosystem / 'all.zip'
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, 'w') as bundle:
        for record in records:
            bundle.writestr(f"{record['id']}.json", json.dumps(record))


def _mirror(root: Path, ecosystem: str, records: list[dict]) -> None:
    """A labelled public synthetic acquired source, through production contracts."""
    from datetime import datetime, timezone
    from getzilla.security_acquisition import FetchResult, _body
    from getzilla.security_data import SOURCE_URLS, osv_coverage, publish_snapshot
    content = io.BytesIO()
    with zipfile.ZipFile(content, 'w') as bundle:
        for item in records:
            bundle.writestr(item['id'] + '.json', json.dumps(item))
    source_id = f'osv:{ecosystem}'
    url = SOURCE_URLS[source_id]
    payload = _body(FetchResult(content.getvalue(), url, url, 200), url)
    current = datetime.now(timezone.utc)
    publish_snapshot(root, source_id, payload,
        acquisition={'last_verified_sync_utc': current.isoformat(), 'retrieval_kind': 'download',
                     'producer': 'synthetic-public-known-vulns'},
        coverage=osv_coverage(payload, ecosystem), now=current)


def _tampered_mirror(root: Path, ecosystem: str, records: list[dict]) -> None:
    """Intentionally forge public fixture bytes/metadata to test reader refusal."""
    import hashlib
    seed = {'id': 'PUBLIC-SEED', 'affected': [{'package': {'ecosystem': ecosystem, 'name': 'public-seed'}, 'versions': ['1.0.0']}]}
    _mirror(root, ecosystem, [seed])
    content = io.BytesIO()
    with zipfile.ZipFile(content, 'w') as bundle:
        for item in records:
            bundle.writestr(item['id'] + '.json', json.dumps(item))
    payload = content.getvalue()
    digest = hashlib.sha256(payload).hexdigest()
    (root / '.snapshots/sha256' / digest).write_bytes(payload)
    pointer = root / ecosystem / 'snapshot.json'
    document = json.loads(pointer.read_text(encoding='utf-8'))
    document.update(content_sha256=digest, payload_size=len(payload))
    document['coverage']['record_count'] = len(records)
    pointer.write_text(json.dumps(document), encoding='utf-8')


MANIFESTS = {
    'requirements.txt': 'Jinja2==2.11.0  # pinned\nrequests>=2\n-e .\nflask[async]==3.0.0 ; python_version>"3"\n',
    'web/package-lock.json': json.dumps({'lockfileVersion': 3, 'packages': {
        '': {'name': 'web', 'version': '1.0.0'},
        'node_modules/lodash': {'version': '4.17.11'},
        'node_modules/@scope/pkg': {'version': '2.0.0'},
        'node_modules/linked': {'link': True},
    }}),
    'svc/go.mod': 'module example.com/svc\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n)\nrequire github.com/a/b v1.2.3\n',
    'rs/Cargo.toml': '[package]\nname="local"\nversion="0.1.0"\n[dependencies]\nsmallvec="1"\n',
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
        affected = {'ranges': [{'type': 'ECOSYSTEM', 'events': [
            {'introduced': '1.0'}, {'fixed': '1.5'}]}, {'type': 'ECOSYSTEM', 'events': [
            {'introduced': '2.0'}, {'last_affected': '2.3'}]}]}
        for version, expected in (('0.9', False), ('1.0', True), ('1.4.9', True), ('1.5', False),
                                  ('2.0', True), ('2.3', True), ('2.3.1', False), ('10.0', False)):
            with self.subTest(version=version):
                self.assertEqual(KV._in_ranges(version, affected, ecosystem='PyPI'), expected)
        open_ended = {'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '3.0.0'}]}]}
        self.assertTrue(KV._in_ranges('9.9.9', open_ended))
        self.assertFalse(KV._in_ranges('2.9.9', open_ended))
        with self.assertRaises(KV.VulnerabilityError):
            KV._in_ranges('1.0', {'ranges': [{'type': 'GIT', 'events': [{'introduced': '0'}]}]})


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
            dependencies, _ = KV.collect_dependencies(root)
            findings = KV.query_online(dependencies, fetch=fetch)
        # An observation helper retains pagination; it is not a qualified scan.
        self.assertEqual(sorted(item.vuln_id for item in findings), ['GHSA-h5c8-rqwp-cp95', 'PYSEC-2021-66'])
        first = calls[0][1]['queries']
        self.assertEqual({item['package']['ecosystem'] for item in first}, {'PyPI'})
        self.assertEqual(calls[1][1]['queries'], [{'package': {'name': 'Jinja2', 'ecosystem': 'PyPI'},
                                                   'version': '2.11.0', 'page_token': 'p2'}])

    def test_network_failure_fails_closed(self) -> None:
        def fetch(url: str, body: bytes | None) -> bytes:
            raise OSError('unreachable')

        tmp, root = _repo({'requirements.txt': 'Jinja2==2.11.0\n'})
        with tmp, self.assertRaisesRegex(KV.VulnerabilityError, 'OSV query failed'):
            dependencies, _ = KV.collect_dependencies(root)
            KV.query_online(dependencies, fetch=fetch)


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


class VerifierDetailTests(unittest.TestCase):
    def test_findings_render_package_advisory_and_manifest_for_the_text_report(self) -> None:
        # scripts/getzilla_verify.py prints "{severity} {path}: {message}" for each detail.
        from unittest.mock import patch
        from getzilla import verification
        finding = KV.Finding(
            dependency=KV.Dependency('PyPI', 'jinja2', '3.1.2', 'requirements.txt'),
            vuln_id='GHSA-h5c8-rqwp-cp95', aliases=['CVE-2024-22195'],
            summary='Jinja vulnerable to HTML attribute injection', severity='MODERATE', fixed=['3.1.3'],
        )
        report = {'status': 'fail', 'summary': '1 known vulnerabilities in 1 pinned packages (OSV API)',
                  'findings': [finding.to_dict()], 'accepted': []}
        with patch.object(verification, 'scan_known_vulnerabilities', return_value=report):
            result = verification._known_vulnerabilities(ROOT)
        self.assertEqual(result.status, 'fail')
        [detail] = result.details
        self.assertEqual(detail['severity'], 'MODERATE')
        self.assertEqual(detail['path'], 'requirements.txt')
        self.assertEqual(
            detail['message'],
            'jinja2==3.1.2 GHSA-h5c8-rqwp-cp95 (CVE-2024-22195): '
            'Jinja vulnerable to HTML attribute injection; fixed in 3.1.3',
        )
        self.assertEqual(detail['package'], 'jinja2')
        self.assertEqual(detail['id'], 'GHSA-h5c8-rqwp-cp95')


class QualityGateTests(unittest.TestCase):
    def test_only_the_no_pins_skip_reason_is_admitted(self) -> None:
        from types import SimpleNamespace

        from getzilla.quality_gates import required_check_refused

        def result(status: str, summary: str) -> SimpleNamespace:
            return SimpleNamespace(name='known-vulnerabilities', status=status, summary=summary)

        self.assertFalse(required_check_refused(
            result('skip', 'no pinned dependencies in lockfiles or requirements'), mode='pr'))
        self.assertTrue(required_check_refused(
            result('skip', '34 pinned dependencies not checked: set GETZILLA_OSV_DB or GETZILLA_OSV_ONLINE=1'), mode='pr'))
        self.assertTrue(required_check_refused(result('skip', 'OSV unavailable'), mode='pr'))
        self.assertTrue(required_check_refused(result('fail', '1 known vulnerabilities'), mode='pr'))
        self.assertFalse(required_check_refused(result('fail', '1 known vulnerabilities'), mode='fast'))


class OfflineSkipGateTests(unittest.TestCase):
    def test_unchecked_pinned_dependencies_refuse_pr_and_release(self) -> None:
        # Without GETZILLA_OSV_DB/GETZILLA_OSV_ONLINE the scan is a no-op; a pr/release gate
        # must not pass on it (#32). Repositories without pins stay admitted.
        from types import SimpleNamespace

        from getzilla.quality_gates import required_check_refused

        tmp, root = _repo({'requirements.txt': 'Jinja2==2.11.0\n'})
        with tmp:
            report = KV.scan(root, environ={})
        unchecked = SimpleNamespace(name='known-vulnerabilities', status=report['status'], summary=report['summary'])
        self.assertEqual(unchecked.status, 'skip')
        for mode in ('pr', 'release'):
            with self.subTest(mode=mode):
                self.assertTrue(required_check_refused(unchecked, mode=mode))
        self.assertFalse(required_check_refused(unchecked, mode='fast'))
        empty = SimpleNamespace(name='known-vulnerabilities', status='skip',
                                summary='no pinned dependencies in lockfiles or requirements')
        self.assertFalse(required_check_refused(empty, mode='pr'))


class DownloadTests(unittest.TestCase):
    def test_download_writes_verified_archives_atomically(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as bundle:
            bundle.writestr('A.json', json.dumps(JINJA))
        urls: list[str] = []

        def fetch(url: str, body: bytes | None):
            from getzilla.security_acquisition import FetchResult
            urls.append(url)
            content = io.BytesIO()
            with zipfile.ZipFile(content, 'w') as bundle:
                bundle.writestr('public.json', json.dumps(JINJA if '/PyPI/' in url else LODASH))
            return FetchResult(content.getvalue(), url, url, 200)

        with tempfile.TemporaryDirectory() as db:
            written = KV.download_database(Path(db), ['PyPI', 'npm'], fetch=fetch)
            self.assertEqual([Path(item).relative_to(db).as_posix() for item in written], ['PyPI/snapshot.json', 'npm/snapshot.json'])
            self.assertFalse(list(Path(db).rglob('*.partial')))
        self.assertEqual(urls, [f'{KV.OSV_BUCKET}/PyPI/all.zip', f'{KV.OSV_BUCKET}/npm/all.zip'])
        with tempfile.TemporaryDirectory() as db, self.assertRaises(KV.VulnerabilityError):
            KV.download_database(Path(db), ['Hex'], fetch=fetch)  # an ecosystem Getzilla does not download


class AliasShapeTests(unittest.TestCase):
    def test_describe_preserves_only_closed_identifier_lists(self) -> None:
        dependency = KV.Dependency('PyPI', 'Jinja2', '2.11.0', 'requirements.txt')
        self.assertEqual(KV._describe({'id': 'PUBLIC-1'}, dependency).aliases, [])
        self.assertEqual(KV._describe({'id': 'PUBLIC-1', 'aliases': []}, dependency).aliases, [])
        self.assertEqual(KV._describe({'id': 'PUBLIC-1', 'aliases': ['x_CUSTOM:1', 'CVE-2024-22195']}, dependency).aliases,
                         ['CVE-2024-22195', 'x_CUSTOM:1'])
        for aliases in ('CVE-2024-22195', {}, [''], ['CVE-2024-22195,'],
                        [' CVE-2024-22195 '], [3], ('CVE-2024-22195',)):
            with self.subTest(aliases=aliases), self.assertRaisesRegex(KV.VulnerabilityError, 'OSV aliases'):
                KV._describe({'id': 'PUBLIC-1', 'aliases': aliases}, dependency)

    def test_online_detail_aliases_refuse_instead_of_partial_findings(self) -> None:
        dependency = KV.Dependency('PyPI', 'Jinja2', '2.11.0', 'requirements.txt')
        for aliases in ('CVE-2024-22195', ['CVE-2024-22195,']):
            def fetch(url, body):
                return json.dumps({'results': [{'vulns': [{'id': JINJA['id']}]}]} if body is not None
                                  else {**JINJA, 'aliases': aliases}).encode()
            with self.subTest(aliases=aliases), self.assertRaisesRegex(KV.VulnerabilityError, 'OSV aliases'):
                KV.query_online([dependency], fetch=fetch)

    def test_offline_validates_aliases_before_package_or_withdrawn_filter(self) -> None:
        dependency = KV.Dependency('PyPI', 'Jinja2', '2.11.0', 'requirements.txt')
        for record in ({**JINJA, 'aliases': 'CVE-2024-22195'},
                       {'id': 'PUBLIC-unrelated', 'aliases': 'CVE-2024-22195', 'affected': []},
                       {**WITHDRAWN, 'aliases': ['CVE-2024-22195,']}):
            with tempfile.TemporaryDirectory() as raw:
                _tampered_mirror(Path(raw), 'PyPI', [JINJA, {**record, 'id': 'PUBLIC-malformed'}])
                with self.subTest(record=record['id']), self.assertRaisesRegex(KV.VulnerabilityError, 'OSV aliases'):
                    KV.query_offline([dependency], Path(raw))

    def test_alias_exception_cannot_hide_malformed_data_from_scan_or_cli(self) -> None:
        config = {'accept': [{'id': JINJA['id'], 'reason': 'public synthetic exception', 'expires': '2027-01-01'}]}
        tmp, root = _repo({'requirements.txt': 'Jinja2==2.11.0\n', KV.CONFIG_PATH: json.dumps(config)})
        with tmp:
            mirror = root / 'public-mirror'
            _mirror(mirror, 'PyPI', [JINJA])
            valid = KV.scan(root, environ={'GETZILLA_OSV_DB': str(mirror)}, today=date(2026, 11, 5))
            self.assertEqual(valid['status'], 'pass')
            self.assertEqual(valid['accepted'][0]['aliases'], ['CVE-2024-22195'])
            _tampered_mirror(mirror, 'PyPI', [{**JINJA, 'aliases': 'CVE-2024-22195'}])
            with self.assertRaisesRegex(KV.VulnerabilityError, 'OSV aliases'):
                KV.scan(root, environ={'GETZILLA_OSV_DB': str(mirror)}, today=date(2026, 11, 5))
            process = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_vulns.py'), '--db', str(mirror), '--json'],
                                     cwd=root, env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                                     capture_output=True, text=True, timeout=20)
            self.assertEqual(process.returncode, 2)
            self.assertIn('OSV aliases', process.stderr)
            self.assertNotIn('Traceback', process.stderr)
            self.assertNotIn('"status": "pass"', process.stdout)


class CargoCoverageTests(unittest.TestCase):
    REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'

    @staticmethod
    def lock(name='app', version='0.1.0', source=None):
        return '[[package]]\nname = ' + json.dumps(name) + '\nversion = ' + json.dumps(version) + '\n' + (
            '' if source is None else 'source = ' + json.dumps(source) + '\n')

    def test_registry_and_manifest_owned_local_packages_remain_valid(self):
        files = {'Cargo.toml': '[package]\nname="app"\nversion="0.1.0"\n[dependencies]\nsmallvec="1"\n',
                 'Cargo.lock': self.lock() + self.lock('smallvec', '1.6.0', self.REGISTRY)}
        tmp, root = _repo(files)
        with tmp:
            dependencies, manifests = KV.collect_dependencies(root)
        self.assertEqual([(d.ecosystem, d.name, d.version) for d in dependencies], [('crates.io', 'smallvec', '1.6.0')])
        self.assertIn('Cargo.lock', manifests)

    def test_explicit_workspace_members_and_inherited_version_are_local(self):
        files = {'Cargo.toml': '[workspace]\nmembers=["core", "application"]\n[workspace.package]\nversion="0.1.0"\n[workspace.dependencies]\nsmallvec="1"\ncore={path="core"}\n',
                 'core/Cargo.toml': '[package]\nname="core"\nversion.workspace=true\n[dependencies]\nsmallvec.workspace=true\n',
                 'application/Cargo.toml': '[package]\nname="application"\nversion="0.1.0"\n[dependencies]\ncore.workspace=true\n',
                 'Cargo.lock': self.lock('core') + self.lock('application') + self.lock('smallvec', '1.6.0', self.REGISTRY)}
        tmp, root = _repo(files)
        with tmp:
            try:
                dependencies, _ = KV.collect_dependencies(root)
            except KV.VulnerabilityError as error:
                self.fail(f'qualified workspace inheritance refused: {error}')
        self.assertEqual([(d.name, d.version) for d in dependencies], [('smallvec', '1.6.0')])

    def test_nonregistry_and_unresolved_declarations_are_explicit_incomplete(self):
        ordinary = '[package]\nname="app"\nversion="0.1.0"\n'
        cases = {
            'git': {'Cargo.toml': ordinary + '[dependencies]\nexternal={git="https://example.invalid/public"}\n',
                    'Cargo.lock': self.lock() + self.lock('external', '1.0.0', 'git+https://example.invalid/public#'+'a'*40)},
            'path': {'Cargo.toml': ordinary+'[dependencies]\nexternal={path="vendor/external"}\n',
                     'vendor/external/Cargo.toml': '[package]\nname="external"\nversion="1.0.0"\n',
                     'Cargo.lock': self.lock()+self.lock('external', '1.0.0')},
            'ambiguous': {'Cargo.toml': ordinary, 'Cargo.lock': self.lock()+self.lock('unknown', '1.0.0')},
            'custom-registry': {'Cargo.lock': self.lock('external', '1.0.0', 'registry+https://example.invalid/index')},
            'missing-lock': {'Cargo.toml': ordinary+'[dependencies]\nexternal="1"\n'},
            'missing-pin': {'Cargo.toml': ordinary+'[dependencies]\nexternal="1"\n', 'Cargo.lock': self.lock()},
            'malformed': {'Cargo.lock': 'package=[7]\n'},
            'override': {'Cargo.toml': ordinary+'[patch.crates-io]\nexternal={path="vendor/external"}\n', 'Cargo.lock': self.lock()},
        }
        cases['mixed'] = {**cases['git'], 'Cargo.lock': cases['git']['Cargo.lock'] + self.lock('smallvec', '1.6.0', self.REGISTRY)}
        for label, files in cases.items():
            tmp, root = _repo(files)
            with tmp, self.subTest(case=label), self.assertRaisesRegex(KV.VulnerabilityError, 'Cargo'):
                KV.scan(root, environ={})

    def test_unknown_workspace_and_external_source_cannot_claim_member_identity(self):
        for extra, source in (('members=["core/*"]', None), ('members=["core"]', 'git+https://example.invalid/public#'+'a'*40)):
            files = {'Cargo.toml': '[workspace]\n'+extra+'\n',
                     'core/Cargo.toml': '[package]\nname="core"\nversion="0.1.0"\n',
                     'Cargo.lock': self.lock('core', source=source)}
            tmp, root = _repo(files)
            with tmp, self.subTest(source=source), self.assertRaisesRegex(KV.VulnerabilityError, 'Cargo'):
                KV.collect_dependencies(root)

    def test_actual_cli_refuses_git_without_a_database_and_preserves_registry_positive(self):
        files = {'Cargo.toml': '[package]\nname="app"\nversion="0.1.0"\n[dependencies]\nexternal={git="https://example.invalid/public"}\n',
                 'Cargo.lock': self.lock()+self.lock('external', '1.0.0', 'git+https://example.invalid/public#'+'a'*40)}
        tmp, root = _repo(files)
        with tmp:
            command = [sys.executable, str(ROOT/'scripts/getzilla_vulns.py'), '--json']
            env = {'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}
            refused = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(refused.returncode, 2)
            self.assertIn('Cargo', refused.stderr)
            self.assertNotIn('Traceback', refused.stderr)
            (root/'Cargo.toml').write_text('[package]\nname="app"\nversion="0.1.0"\n[dependencies]\nsmallvec="1"\n', encoding='utf-8')
            (root/'Cargo.lock').write_text(self.lock()+self.lock('smallvec', '1.6.0', self.REGISTRY), encoding='utf-8')
            _mirror(root/'public-db', 'crates.io', [{'id': 'PUBLIC-UNRELATED', 'affected': [
                {'package': {'ecosystem': 'crates.io', 'name': 'public-other-package'}, 'versions': ['1.0.0']}]}])
            accepted = subprocess.run([*command, '--db', str(root/'public-db')], cwd=root, env=env,
                                      capture_output=True, text=True, timeout=20)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(json.loads(accepted.stdout)['status'], 'pass')
            self.assertEqual(json.loads(accepted.stdout)['dependencies'], 1)


class CargoAdmissionTests(unittest.TestCase):
    def test_inherited_version_requires_boolean_true(self) -> None:
        files = {'Cargo.toml': '[workspace]\nmembers=["core"]\n[workspace.package]\nversion="0.1.0"\n',
                 'core/Cargo.toml': '[package]\nname="core"\nversion.workspace=1\n',
                 'Cargo.lock': CargoCoverageTests.lock('core')}
        tmp, root = _repo(files)
        with tmp, self.assertRaisesRegex(KV.VulnerabilityError, 'Cargo'):
            KV.collect_dependencies(root)

    def test_unreadable_lock_cannot_become_no_dependencies_skip(self) -> None:
        tmp, root = _repo({'Cargo.toml': '[package]\nname="app"\nversion="0.1.0"\n',
                           'public-lock': CargoCoverageTests.lock()})
        with tmp:
            (root/'Cargo.lock').symlink_to(root/'public-lock')
            with self.assertRaisesRegex(KV.VulnerabilityError, 'Cargo'):
                KV.scan(root, environ={})

    def test_standalone_cargo_parser_cannot_silently_discard_nonregistry_entries(self) -> None:
        for source in (None, 'git+https://example.invalid/public#'+'a'*40, 'registry+https://example.invalid/index'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                list(KV.MANIFESTS['Cargo.lock'][1](CargoCoverageTests.lock('external', '1.0.0', source)))


class NullAliasCompatibilityTests(unittest.TestCase):
    def test_schema_null_is_absent_without_mutating_record(self) -> None:
        record = {**JINJA, 'aliases': None}
        try:
            finding = KV._describe(record, KV.Dependency('PyPI', 'Jinja2', '2.11.0', 'requirements.txt'))
        except KV.VulnerabilityError as error:
            self.fail(f'schema-valid null aliases refused: {error}')
        self.assertEqual(finding.aliases, [])
        self.assertIsNone(record['aliases'])

    def test_online_null_details_preserve_the_ordinary_finding(self) -> None:
        def fetch(url, body):
            return json.dumps({'results': [{'vulns': [{'id': JINJA['id']}]}]} if body is not None
                              else {**JINJA, 'aliases': None}).encode()
        try:
            findings = KV.query_online([KV.Dependency('PyPI', 'Jinja2', '2.11.0', 'requirements.txt')], fetch=fetch)
        except KV.VulnerabilityError as error:
            self.fail(f'schema-valid online null refused: {error}')
        self.assertEqual([(finding.vuln_id, finding.aliases) for finding in findings], [(JINJA['id'], [])])

    def test_actual_offline_cli_reports_null_finding_instead_of_data_refusal(self) -> None:
        tmp, root = _repo({'requirements.txt': 'Jinja2==2.11.0\n'})
        with tmp:
            mirror = root/'public-db'
            _mirror(mirror, 'PyPI', [{**JINJA, 'aliases': None}])
            result = subprocess.run([sys.executable, str(ROOT/'scripts/getzilla_vulns.py'), '--db', str(mirror), '--json'],
                                    cwd=root, env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'fail')
            self.assertEqual([(finding['id'], finding['aliases']) for finding in report['findings']], [(JINJA['id'], [])])




class QualifiedNativeTests(unittest.TestCase):
    def test_unqualified_online_scan_and_cli_refuse_before_acquisition(self):
        import contextlib
        import runpy
        from unittest.mock import patch
        from getzilla import util
        temporary, root = _repo({'requirements.txt': 'public-package==1.0.0\n'})
        with temporary:
            with self.subTest(consumer='scan'), patch.object(KV, 'query_online', return_value=[]) as query:
                with self.assertRaisesRegex(KV.VulnerabilityError, 'online|qualified'):
                    KV.scan(root, environ={'GETZILLA_OSV_ONLINE': '1'})
                query.assert_not_called()
            with self.subTest(consumer='CLI'), patch.object(KV, 'query_online', return_value=[]) as query, \
                    patch.object(util, 'find_root', return_value=root), \
                    patch.object(sys, 'argv', ['getzilla_vulns.py', '--online', '--json']), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    runpy.run_path(str(ROOT / 'scripts/getzilla_vulns.py'), run_name='__main__')
                self.assertEqual(stopped.exception.code, 2)
                query.assert_not_called()

    def test_malformed_policy_errors_are_typed_and_opaque(self):
        temporary, root = _repo({'README.md': 'public fixture\n'})
        with temporary:
            policy = root / KV.CONFIG_PATH
            policy.parent.mkdir(parents=True)
            for content in ('{"PUBLIC_POLICY_SENTINEL":1,"PUBLIC_POLICY_SENTINEL":2}',
                            '{"exclude":' + '[' * 1500 + '0' + ']' * 1500 + '}'):
                policy.write_text(content, encoding='utf-8')
                with self.assertRaises(KV.VulnerabilityError) as refused:
                    KV.load_config(root)
                self.assertNotIn('PUBLIC_POLICY_SENTINEL', str(refused.exception))

    def test_query_rechecks_source_after_actual_matching(self):
        from datetime import timedelta
        from unittest.mock import patch
        from getzilla import security_data
        temporary, root = _repo({'requirements.txt': 'Jinja2==2.11.0\n'})
        with temporary:
            database = root / 'public-database'
            now = self.qualified(root, database)
            original, clock = KV._in_ranges, security_data._clock
            current = [now]
            def match(*args, **kwargs):
                current[0] = now + timedelta(seconds=259201)
                return original(*args, **kwargs)
            with patch.object(KV, '_in_ranges', match), \
                    patch.object(security_data, '_clock', side_effect=lambda supplied: clock(current[0] if supplied is None else supplied)):
                with self.assertRaises(KV.VulnerabilityError):
                    KV.scan(root, environ={'GETZILLA_OSV_DB': str(database)})

    def test_inventory_mutation_during_query_cannot_publish_old_proof(self):
        from unittest.mock import patch
        temporary, root = _repo({'requirements.txt': 'Jinja2==2.11.0\n'})
        with temporary:
            database = root / 'public-database'
            now = self.qualified(root, database)
            original = KV._in_ranges
            def match(*args, **kwargs):
                (root / 'requirements.txt').write_text('Jinja2==3.1.4\n', encoding='utf-8')
                return original(*args, **kwargs)
            with patch.object(KV, '_in_ranges', match), self.assertRaises(KV.VulnerabilityError):
                KV.scan(root, environ={'GETZILLA_OSV_DB': str(database)}, now=now)

    def test_same_policy_bytes_on_a_replacement_inode_do_not_reuse_old_proof(self):
        import os
        temporary, root = _repo({'README.md': 'public empty project\n', KV.CONFIG_PATH: '{"accept":[],"exclude":[]}'})
        with temporary:
            report = KV.scan(root, environ={})
            replacement = root / 'public-new-policy'
            replacement.write_bytes((root / KV.CONFIG_PATH).read_bytes())
            os.replace(replacement, root / KV.CONFIG_PATH)
            with self.assertRaises(KV.VulnerabilityError):
                KV.recheck_report(root, report, environ={})

    def test_hardlinked_policy_cannot_establish_source_applicability(self):
        import os
        temporary, root = _repo({'README.md': 'public empty project\n', KV.CONFIG_PATH: '{"accept":[]}'})
        with temporary:
            os.link(root / KV.CONFIG_PATH, root / 'public-policy-link')
            with self.assertRaises(KV.VulnerabilityError):
                KV.scan(root, environ={})

    def test_public_collector_rejects_hardlinked_manifest_before_content_use(self):
        import os
        temporary, root = _repo({'requirements.txt': 'public-package==1.0.0\n'})
        with temporary:
            os.link(root / 'requirements.txt', root / 'public-second-link')
            with self.assertRaisesRegex(KV.VulnerabilityError, 'inventory'):
                KV.collect_dependencies(root)

    def qualified(self, root, database):
        from getzilla import security_data
        from datetime import datetime, timezone
        now = datetime(2026, 11, 5, tzinfo=timezone.utc)
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, 'w') as bundle:
            bundle.writestr('public.json', json.dumps(JINJA))
        raw = payload.getvalue()
        security_data.publish_snapshot(database, 'osv:PyPI', raw,
            acquisition={'last_verified_sync_utc': now.isoformat(), 'retrieval_kind': 'download'},
            coverage=security_data.osv_coverage(raw, 'PyPI'), now=now)
        return now

    def test_legacy_empty_zip_cannot_establish_clean_scan(self):
        temporary, root = _repo({'requirements.txt': 'public-package==1.0.0\n'})
        with temporary, tempfile.TemporaryDirectory() as database:
            _legacy_mirror(Path(database), 'PyPI', [])
            with self.assertRaises(KV.VulnerabilityError):
                KV.scan(root, environ={'GETZILLA_OSV_DB': database})

    def test_unresolved_dependency_cannot_be_an_empty_skip(self):
        temporary, root = _repo({'requirements.txt': 'public-package>=1\n'})
        with temporary, self.assertRaisesRegex(KV.VulnerabilityError, 'inventory|incomplete|unresolved'):
            KV.scan(root, environ={})

    def test_structural_empty_scan_retains_inventory_proof(self):
        temporary, root = _repo({'README.md': 'public no-dependency project\n'})
        with temporary:
            report = KV.scan(root, environ={})
        self.assertEqual(report['status'], 'skip')
        self.assertTrue(report.get('inventory', {}).get('complete'), 'empty applicability needs source inventory proof')
        self.assertEqual(report['inventory']['objects'], [])

    def test_bytes_only_fetch_cannot_mint_acquisition_time(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as bundle:
            bundle.writestr('public.json', json.dumps(JINJA))
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(KV.VulnerabilityError):
            KV.download_database(Path(temporary) / 'database', ['PyPI'], fetch=lambda _url, _body: output.getvalue())

    def test_final_consumer_rechecks_clock_policy_inventory_and_configured_source(self):
        from datetime import timedelta
        temporary, root = _repo({'requirements.txt': 'Jinja2==3.1.3\n'})
        with temporary:
            database = root / 'public-database'
            now = self.qualified(root, database)
            environ = {'GETZILLA_OSV_DB': str(database)}
            report = KV.scan(root, environ=environ, now=now)
            check = getattr(KV, 'recheck_report', None)
            self.assertTrue(callable(check), 'actual final-consumption source recheck is missing')
            check(root, report, environ=environ, now=now)
            with self.assertRaises(KV.VulnerabilityError):
                check(root, report, environ=environ, now=now + timedelta(seconds=259201))
            with self.assertRaises(KV.VulnerabilityError):
                check(root, report, environ={}, now=now)
            (root / 'requirements.txt').write_text('Jinja2==3.1.4\n', encoding='utf-8')
            with self.assertRaises(KV.VulnerabilityError):
                check(root, report, environ=environ, now=now)
            (root / 'requirements.txt').write_text('Jinja2==3.1.3\n', encoding='utf-8')
            (root / KV.CONFIG_PATH).parent.mkdir(parents=True)
            (root / KV.CONFIG_PATH).write_text(json.dumps({'exclude': []}), encoding='utf-8')
            with self.assertRaises(KV.VulnerabilityError):
                check(root, report, environ=environ, now=now)

    def test_final_consumer_rejects_substantive_and_source_proof_substitution(self):
        import copy
        temporary, root = _repo({'requirements.txt': 'Jinja2==2.11.0\n'})
        with temporary:
            database = root / 'public-database'
            now = self.qualified(root, database)
            environ = {'GETZILLA_OSV_DB': str(database)}
            report = KV.scan(root, environ=environ, now=now)
            check = getattr(KV, 'recheck_report', None)
            self.assertTrue(callable(check), 'actual final-consumption source recheck is missing')
            forged = copy.deepcopy(report)
            forged['findings'] = []
            forged['status'] = 'pass'
            with self.assertRaises(KV.VulnerabilityError):
                check(root, forged, environ=environ, now=now)
            forged = copy.deepcopy(report)
            forged['source_evidence'] = []
            with self.assertRaises(KV.VulnerabilityError):
                check(root, forged, environ=environ, now=now)

    def test_native_verifier_carries_actual_source_proof_to_final_boundary(self):
        import inspect
        from getzilla import verification
        self.assertIn('evidence', inspect.signature(verification._known_vulnerabilities).parameters,
                      'native verifier discards the actual security source report')
        temporary, root = _repo({'README.md': 'public empty applicability\n'})
        with temporary:
            evidence = {}
            result = verification._known_vulnerabilities(root, evidence=evidence)
            self.assertEqual(result.status, 'skip')
            self.assertEqual(evidence['dependencies'], 0)
            self.assertTrue(evidence['inventory']['complete'])

    def test_native_cli_rechecks_before_emitting_report(self):
        import contextlib
        import runpy
        from unittest.mock import patch
        from getzilla import util
        temporary, root = _repo({'README.md': 'public empty applicability\n'})
        called, output = [], io.StringIO()
        original = KV.recheck_report
        def check(*args, **kwargs):
            called.append(True)
            return original(*args, **kwargs)
        with temporary, patch.object(util, 'find_root', return_value=root), \
                patch.object(KV, 'recheck_report', side_effect=check), \
                patch.object(sys, 'argv', ['getzilla_vulns.py', '--json']), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(str(ROOT / 'scripts/getzilla_vulns.py'), run_name='__main__')
        self.assertEqual(stopped.exception.code, 0)
        self.assertTrue(called, 'CLI emitted evidence without final source consumption check')

class QualifiedQueryNativeTests(unittest.TestCase):
    def setUp(self):
        temporary, self.root = _repo({'requirements.txt': 'public-package==1.0.0\n'})
        self.addCleanup(temporary.cleanup)
        self.database = self.root / 'public-query-store'

    @staticmethod
    def transport(method, url, body, deadline, maximum):
        from getzilla.security_osv_query import QueryResponse
        answer = {'results': [{} for _ in json.loads(body)['queries']]}
        return QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)

    def test_current_query_scan_and_recheck_are_read_only(self):
        from unittest.mock import patch
        from getzilla import security_acquisition
        result = security_acquisition.refresh_query(self.root, self.database, transport=self.transport)
        self.assertEqual(result['status'], 'pass', result)
        environment = {'GETZILLA_OSV_DB': str(self.database), 'GETZILLA_OSV_ONLINE': '1'}
        with patch.object(security_acquisition, 'refresh_query', side_effect=AssertionError('implicit acquisition')):
            try:
                report = KV.scan(self.root, environ=environment)
            except KV.VulnerabilityError:
                self.fail('native scan cannot consume the current qualified query snapshot')
            self.assertEqual(report['source_mode'], 'query')
            self.assertEqual(report['status'], 'pass')
            KV.recheck_report(self.root, report, environ=environment)
        with self.assertRaises(KV.VulnerabilityError):
            KV.recheck_report(self.root, report, environ={**environment, 'GETZILLA_OSV_ONLINE': '0'})
        (self.root / 'requirements.txt').write_text('public-package==2.0.0\n', encoding='utf-8')
        with self.assertRaises(KV.VulnerabilityError):
            KV.scan(self.root, environ=environment)

    def test_explicit_cli_acquires_then_uses_same_read_only_consumer(self):
        import contextlib
        import runpy
        from unittest.mock import patch
        from getzilla import security_acquisition, util
        actual, calls = security_acquisition.refresh_query, []
        def refresh(root, database):
            calls.append((root, database))
            return actual(root, database, transport=self.transport)
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(security_acquisition, 'refresh_query', refresh), \
                patch.object(util, 'find_root', return_value=self.root), \
                patch.object(sys, 'argv', ['getzilla_vulns.py', '--online', '--db', str(self.database), '--json']), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(str(ROOT / 'scripts/getzilla_vulns.py'), run_name='__main__')
        self.assertEqual(stopped.exception.code, 0, errors.getvalue())
        self.assertEqual(calls, [(self.root, self.database)])
        self.assertEqual(json.loads(output.getvalue())['source_mode'], 'query')

    def test_configured_query_cli_reads_without_explicit_refresh(self):
        import contextlib
        import os
        import runpy
        from unittest.mock import patch
        from getzilla import security_acquisition, util
        self.assertEqual(security_acquisition.refresh_query(self.root, self.database, transport=self.transport)['status'], 'pass')
        output = io.StringIO()
        with patch.object(security_acquisition, 'refresh_query', side_effect=AssertionError('implicit CLI refresh')), \
                patch.dict(os.environ, {'GETZILLA_OSV_DB': str(self.database), 'GETZILLA_OSV_ONLINE': '1'}), \
                patch.object(util, 'find_root', return_value=self.root), \
                patch.object(sys, 'argv', ['getzilla_vulns.py', '--json']), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(str(ROOT / 'scripts/getzilla_vulns.py'), run_name='__main__')
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(json.loads(output.getvalue())['source_mode'], 'query')

    def test_query_positive_cannot_be_range_filtered_into_clean(self):
        from unittest.mock import patch
        from getzilla import security_acquisition
        from getzilla.security_osv_query import QueryResponse
        from tests.test_security_osv_query import detail, ID, MODIFIED
        def transport(method, url, body, deadline, maximum):
            answer = {'results': [{'vulns': [{'id': ID, 'modified': MODIFIED}]}]} if method == 'POST' else detail()
            return QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)
        self.assertEqual(security_acquisition.refresh_query(self.root, self.database, transport=transport)['status'], 'pass')
        with patch.object(KV, '_in_ranges', return_value=False):
            try:
                report = KV.scan(self.root, environ={'GETZILLA_OSV_DB': str(self.database), 'GETZILLA_OSV_ONLINE': '1'})
            except KV.VulnerabilityError:
                self.fail('native scan does not admit a qualified query finding')
        self.assertEqual(report['status'], 'fail')
        self.assertEqual([finding['id'] for finding in report['findings']], [ID])


if __name__ == '__main__':
    unittest.main()
