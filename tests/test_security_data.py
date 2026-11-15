"""Snapshot contract: bytes, acquisition, exact coverage and an atomic pointer."""
from __future__ import annotations

import hashlib
import io
import json
import os
import shlex
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_data as SD  # noqa: E402

NOW = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)


def osv_bytes(ecosystem: str = 'PyPI', *, name: str = 'example', version: str = '1.0.0') -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_STORED) as archive:
        archive.writestr(zipfile.ZipInfo('OSV-1.json', date_time=(2026, 1, 1, 0, 0, 0)), json.dumps({'id': 'OSV-1', 'affected': [{
            'package': {'ecosystem': ecosystem, 'name': name}, 'versions': [version],
        }]}))
    return output.getvalue()


def publish(database: Path, *, acquired: datetime = NOW, payload: bytes | None = None,
            source_id: str = 'osv:PyPI') -> dict:
    return SD.publish_snapshot(database, source_id, payload if payload is not None else osv_bytes(),
                               acquisition={'last_verified_sync_utc': acquired.isoformat(),
                                            'retrieval_kind': 'download'},
                               coverage={'scopes': ['PyPI'], 'complete': True,
                                         'record_count': 1, 'schema': 'osv-1'}, now=acquired)


@unittest.skipUnless(SD.DESCRIPTOR_IO_AVAILABLE, 'snapshot I/O requires qualified POSIX directory descriptors')
class SnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.database = self.root / 'database'

    def test_inclusive_72_hour_boundary_uses_verified_sync(self) -> None:
        publish(self.database)
        for seconds in (0, 259199, 259200):
            with self.subTest(seconds=seconds):
                payload, evidence = SD.read_snapshot(self.database, 'osv:PyPI',
                                                     now=NOW + timedelta(seconds=seconds), required_scope={'PyPI'})
                self.assertEqual(payload, osv_bytes())
                self.assertEqual(evidence['age_seconds'], seconds)
        with self.assertRaisesRegex(SD.SecurityDataError, 'stale'):
            SD.read_snapshot(self.database, 'osv:PyPI', now=NOW + timedelta(seconds=259201))

    def test_future_unknown_and_naive_clocks_fail(self) -> None:
        publish(self.database)
        for clock in (NOW - timedelta(seconds=1), NOW.replace(tzinfo=None), 'unknown'):
            with self.subTest(clock=clock), self.assertRaises(SD.SecurityDataError):
                SD.read_snapshot(self.database, 'osv:PyPI', now=clock)
        pointer = self.database / 'PyPI/snapshot.json'
        original = json.loads(pointer.read_text())
        for timestamp in ('unknown', '2026-11-03T12:00:00', None, 0):
            edited = json.loads(json.dumps(original))
            edited['acquisition']['last_verified_sync_utc'] = timestamp
            pointer.write_text(json.dumps(edited))
            with self.subTest(timestamp=timestamp), self.assertRaises(SD.SecurityDataError):
                SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)

    def test_copy_keeps_original_acquisition_and_age(self) -> None:
        old = NOW - timedelta(hours=71)
        original = publish(self.database, acquired=old)
        destination = self.root / 'copy'
        copied = SD.copy_snapshot(self.database, destination, 'osv:PyPI', now=NOW)
        self.assertEqual(copied['acquisition'], original['acquisition'])
        payload, evidence = SD.read_snapshot(destination, 'osv:PyPI', now=NOW)
        self.assertEqual(evidence['age_seconds'], 255600)
        self.assertEqual(payload, osv_bytes())
        for path in destination.rglob('*'):
            if path.is_file():
                os.utime(path, (NOW.timestamp(), NOW.timestamp()))
        with self.assertRaisesRegex(SD.SecurityDataError, 'stale'):
            SD.read_snapshot(destination, 'osv:PyPI', now=NOW + timedelta(hours=2))

    def test_copy_of_stale_nonempty_snapshot_refuses_and_keeps_destination(self) -> None:
        publish(self.database, acquired=NOW - timedelta(hours=73))
        destination = self.root / 'copy'
        publish(destination)
        before = (destination / 'PyPI/snapshot.json').read_bytes()
        with self.assertRaisesRegex(SD.SecurityDataError, 'stale'):
            SD.copy_snapshot(self.database, destination, 'osv:PyPI', now=NOW)
        self.assertEqual((destination / 'PyPI/snapshot.json').read_bytes(), before)

    def test_digest_size_source_and_coverage_are_validated(self) -> None:
        publish(self.database)
        pointer = self.database / 'PyPI/snapshot.json'
        original = json.loads(pointer.read_text())
        edits = [('content_sha256', '0' * 64), ('payload_size', 1), ('source_id', 'osv:npm'),
                 ('source_url', 'https://example.invalid/changed'), ('schema_version', 99)]
        for field, value in edits:
            document = json.loads(json.dumps(original))
            document[field] = value
            pointer.write_text(json.dumps(document))
            with self.subTest(field=field), self.assertRaises(SD.SecurityDataError):
                SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)
        for field, value in [('record_count', 0), ('record_count', True), ('complete', False),
                             ('scopes', ['npm']), ('schema', 'unknown')]:
            document = json.loads(json.dumps(original))
            document['coverage'][field] = value
            pointer.write_text(json.dumps(document))
            with self.subTest(field=field, value=value), self.assertRaises(SD.SecurityDataError):
                SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)

    def test_reader_uses_verified_immutable_bytes_not_mutable_export(self) -> None:
        publish(self.database)
        (self.database / 'PyPI/all.zip').write_bytes(b'changed compatibility export')
        payload, _ = SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)
        self.assertEqual(payload, osv_bytes())
        digest = hashlib.sha256(payload).hexdigest()
        (self.database / '.snapshots/sha256' / digest).write_bytes(b'tampered object')
        with self.assertRaises(SD.SecurityDataError):
            SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)

    def test_wrong_missing_or_incomplete_ecosystem_is_not_coverage(self) -> None:
        with self.assertRaises(SD.SecurityDataError):
            publish(self.database, payload=osv_bytes('npm'))
        publish(self.database)
        with self.assertRaises(SD.SecurityDataError):
            SD.read_snapshot(self.database, 'osv:PyPI', now=NOW, required_scope={'npm'})
        with self.assertRaisesRegex(SD.SecurityDataError, 'refresh'):
            SD.read_snapshot(self.database, 'osv:npm', now=NOW)

    def test_invalid_refresh_preserves_previous_pointer_and_payload(self) -> None:
        publish(self.database)
        pointer = self.database / 'PyPI/snapshot.json'
        previous = pointer.read_bytes()
        empty = io.BytesIO()
        with zipfile.ZipFile(empty, 'w'):
            pass
        for payload in (b'', b'PK\x03\x04partial', empty.getvalue(), osv_bytes('npm')):
            with self.subTest(payload=payload[:16]), self.assertRaises(SD.SecurityDataError):
                publish(self.database, payload=payload)
            self.assertEqual(pointer.read_bytes(), previous)
            self.assertEqual(SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)[0], osv_bytes())

    def test_malformed_withdrawal_cannot_hide_an_active_advisory(self) -> None:
        for withdrawn in (True, 1, 'unknown', '2026-11-03T12:00:00'):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                archive.writestr('OSV-1.json', json.dumps({'id': 'OSV-1', 'withdrawn': withdrawn, 'affected': [{
                    'package': {'ecosystem': 'PyPI', 'name': 'example'}, 'versions': ['1.0.0'],
                }]}))
            with self.subTest(withdrawn=withdrawn), self.assertRaises(SD.SecurityDataError):
                publish(self.database, payload=output.getvalue())

    def test_atomic_pointer_failure_keeps_old_snapshot(self) -> None:
        publish(self.database)
        before = (self.database / 'PyPI/snapshot.json').read_bytes()
        replace = SD.os.replace

        def fail_pointer(source, destination, **kwargs):
            if Path(destination).name == 'snapshot.json':
                raise OSError('simulated interruption before pointer commit')
            replace(source, destination, **kwargs)

        with mock.patch.object(SD.os, 'replace', side_effect=fail_pointer), self.assertRaises(SD.SecurityDataError):
            publish(self.database, acquired=NOW + timedelta(hours=1), payload=osv_bytes(version='2.0.0'))
        self.assertEqual((self.database / 'PyPI/snapshot.json').read_bytes(), before)
        self.assertEqual(SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)[0], osv_bytes())
        self.assertFalse(list(self.database.rglob('*.partial')))

    def test_legacy_raw_zip_never_supplies_freshness(self) -> None:
        archive = self.database / 'PyPI/all.zip'
        archive.parent.mkdir(parents=True)
        archive.write_bytes(osv_bytes())
        with self.assertRaisesRegex(SD.SecurityDataError, r'python3 scripts/getzilla_security.py --root ROOT --database DIR'):
            SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)

    def test_recovery_command_drives_the_explicit_strict_refresh_entrypoint(self):
        from getzilla import security_cli
        from getzilla.security_acquisition import FetchResult, refresh_feeds
        from tests.test_security_intelligence import epss_payload, kev_payload
        with self.assertRaises(SD.SecurityDataError) as caught:
            SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)
        command = str(caught.exception).split('refresh with ', 1)[1].split(' on a network-enabled host', 1)[0]
        arguments = shlex.split(command)
        self.assertEqual(arguments[:2], ['python3', 'scripts/getzilla_security.py'])
        (self.root / 'requirements.txt').write_text('example==1.0.0\n')
        locations = {'ROOT':str(self.root), 'DIR':str(self.database),
                     'ARTIFACTS':str(self.root/'artifacts'), 'TOOLS':str(self.root/'tools'),
                     'REPORT':str(self.root/'report.json'), 'PROFILE':str(self.root/'profile.json')}
        declared_profile = {'fixture': 'explicit dispatch-only profile'}
        security_cli._atomic(Path(locations['PROFILE']), json.dumps(declared_profile).encode())
        def prepare(args, profile):
            self.assertEqual(profile, declared_profile)
            self.assertEqual(args.input_profile, Path(locations['PROFILE']))
            self.assertTrue(args.refresh)
            def fetch(url):
                body = (osv_bytes() if url == SD.SOURCE_URLS['osv:PyPI'] else
                        kev_payload() if url == SD.SOURCE_URLS['kev'] else epss_payload())
                return FetchResult(body,url,url,200)
            from getzilla.security_inventory import collect_inventory
            ecosystems = sorted({d['ecosystem'] for d in collect_inventory(args.root)['dependencies']})
            reports = refresh_feeds(args.database,ecosystems,fetch=fetch,now=NOW) if args.refresh else []
            passed = len(reports)==3 and all(r['status']=='pass' for r in reports)
            return {'kind':'public-security-input-preparation', 'status':'prepared' if passed else 'unavailable',
                    'qualification':'UNVERIFIED', 'scan_outcomes':[]}
        with mock.patch.object(security_cli,'_supervised_preparation',side_effect=prepare):
            self.assertEqual(security_cli.main([locations.get(value,value) for value in arguments[2:]]),0)
        payload, evidence = SD.read_snapshot(self.database,'osv:PyPI',now=NOW)
        self.assertEqual(payload,osv_bytes())
        self.assertEqual(evidence['acquisition']['last_verified_sync_utc'],NOW.isoformat())

    def test_arbitrary_source_ids_never_select_files(self) -> None:
        for source_id in ('../outside', 'osv:../../outside', 'osv:Hex', 'https://example.invalid'):
            with self.subTest(source_id=source_id), self.assertRaises(SD.SecurityDataError):
                SD.read_snapshot(self.database, source_id, now=NOW)
        self.assertFalse(self.database.exists())

    def test_oversize_metadata_is_rejected_before_replacing_pointer(self) -> None:
        acquisition = {'last_verified_sync_utc': NOW.isoformat(), 'retrieval_kind': 'download'}
        coverage = {'scopes': ['CVE'], 'complete': True, 'record_count': 0, 'schema': 'kev-1'}
        SD.publish_snapshot(self.database, 'kev', b'{"vulnerabilities":[]}',
                            acquisition=acquisition, coverage=coverage, now=NOW)
        pointer = self.database / 'feeds/kev/snapshot.json'
        original = pointer.read_bytes()
        with self.assertRaises(SD.SecurityDataError):
            SD.publish_snapshot(self.database, 'kev', b'{"vulnerabilities":[]}', acquisition=acquisition,
                                coverage={**coverage, 'scopes': ['x' * 70000]}, now=NOW)
        self.assertEqual(pointer.read_bytes(), original)
        _, evidence = SD.read_snapshot(self.database, 'kev', now=NOW)
        self.assertEqual(evidence['payload_validation'], 'source-evaluator-required')


class OsvCompatibilityTests(unittest.TestCase):
    @staticmethod
    def archive(*records):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for i, record in enumerate(records):
                archive.writestr(f'record-{i}.json', json.dumps(record))
        return output.getvalue()

    @staticmethod
    def active_record():
        return {'id': 'GHSA-public-null-fixture', 'modified': '2026-11-03T00:00:00Z', 'affected': [{
            'package': {'ecosystem': 'PyPI', 'name': 'sample'}, 'versions': ['1.0.0'],
        }]}

    def accepted(self, operation):
        try:
            return operation()
        except SD.SecurityDataError as exc:
            self.fail(f'valid nullable OSV field refused: {exc}')

    def test_nullable_alias_helper_returns_fresh_lists_without_truthiness_coercion(self):
        for fields in ({}, {'aliases': None}, {'aliases': []}, {'aliases': ['CVE-2026-12345']}):
            with self.subTest(fields=fields):
                record = dict(self.active_record(), **fields)
                first = self.accepted(lambda: SD.osv_aliases(record))
                second = self.accepted(lambda: SD.osv_aliases(record))
                self.assertEqual(first, fields.get('aliases') or [])
                self.assertIsNot(first, second)
                self.assertIsNot(first, record.get('aliases'))
        for value in (False, 0, '', 'CVE-2026-12345', {}, [None], ['CVE-2026-12345', 1], [','], [' ']):
            with self.subTest(malformed=value), self.assertRaises(SD.SecurityDataError):
                SD.osv_aliases(dict(self.active_record(), aliases=value))

    def test_nullable_aliases_pass_strict_zip_but_malformed_aliases_refuse(self):
        for fields in ({}, {'aliases': None}, {'aliases': []}, {'aliases': ['CVE-2026-12345']}):
            with self.subTest(fields=fields):
                payload = self.archive(dict(self.active_record(), **fields))
                self.assertEqual(self.accepted(lambda: SD.osv_coverage(payload, 'PyPI'))['record_count'], 1)
        for value in (False, 0, '', 'CVE-2026-12345', {}, [None], ['CVE-2026-12345', 1], [','], [' ']):
            with self.subTest(malformed=value), self.assertRaises(SD.SecurityDataError):
                SD.osv_coverage(self.archive(dict(self.active_record(), aliases=value)), 'PyPI')

    def test_nullable_aliases_reach_injected_query_consumer_without_network(self):
        from getzilla import security_osv_snapshot as osv
        dependency = osv.Dependency('PyPI', 'sample', '1.0.0', 'requirements.txt')
        def query(record):
            calls = []
            def fetch(url, body):
                calls.append(url)
                return json.dumps({'results': [{'vulns': [{'id': record['id']}]}]}
                                  if url.endswith('/querybatch') else record).encode()
            answer = osv.query_online([dependency], fetch=fetch)
            self.assertEqual(len(calls), 2)
            return answer[0]
        for fields in ({}, {'aliases': None}, {'aliases': []}, {'aliases': ['CVE-2026-12345']}):
            with self.subTest(fields=fields):
                try:
                    answer = query(dict(self.active_record(), **fields))
                except osv.VulnerabilityError as exc:
                    self.fail(f'valid nullable OSV aliases refused by query: {exc}')
                self.assertEqual(answer.aliases, fields.get('aliases') or [])
        for value in (False, 0, '', 'CVE-2026-12345', {}, [None], ['CVE-2026-12345', 1], [','], [' ']):
            with self.subTest(malformed=value), self.assertRaises(osv.VulnerabilityError):
                query(dict(self.active_record(), aliases=value))

    def test_withdrawn_nullable_affected_passes_coverage_and_production_body_validator(self):
        active = self.active_record()
        withdrawn = {'id': 'GHSA-public-withdrawn', 'withdrawn': '2026-11-03T01:00:00Z'}
        for fields in ({}, {'affected': []}, {'affected': None}):
            with self.subTest(fields=fields):
                payload = self.archive(active, dict(withdrawn, **fields))
                coverage = self.accepted(lambda: SD.osv_coverage(payload, 'PyPI'))
                self.assertEqual(coverage['record_count'], 2)
                document = {'schema_version': 1, 'source_id': 'osv:PyPI',
                            'source_url': SD.SOURCE_URLS['osv:PyPI'],
                            'content_sha256': hashlib.sha256(payload).hexdigest(), 'payload_size': len(payload),
                            'acquisition': {'last_verified_sync_utc': NOW.isoformat(), 'retrieval_kind': 'download'},
                            'coverage': coverage}
                self.accepted(lambda: SD._validate(document, payload, 'osv:PyPI', now=NOW,
                                                   required_scope={'PyPI'}))
        for value in (False, 0, '', 'malformed', {}, [None], [{}]):
            with self.subTest(malformed=value), self.assertRaises(SD.SecurityDataError):
                SD.osv_coverage(self.archive(active, dict(withdrawn, affected=value)), 'PyPI')
        for value in (None, False, 0, 'unknown', '2026-11-03T01:00:00'):
            with self.subTest(withdrawn=value), self.assertRaises(SD.SecurityDataError):
                SD.osv_coverage(self.archive(active, dict(withdrawn, withdrawn=value, affected=None)), 'PyPI')
        for fields in ({}, {'affected': []}, {'affected': None}):
            record = dict(active)
            record.pop('affected')
            record.update(fields)
            with self.subTest(active_without_coverage=fields), self.assertRaises(SD.SecurityDataError):
                SD.osv_coverage(self.archive(record), 'PyPI')
        with self.assertRaises(SD.SecurityDataError):
            SD.osv_coverage(self.archive(dict(withdrawn, affected=None)), 'PyPI')

    def test_supplementary_git_row_needs_named_coverage_in_same_record(self):
        named = {'package': {'ecosystem': 'npm', 'name': 'phoenix'}, 'versions': ['1.0.0']}
        git = {'ranges': [{'type': 'GIT', 'repo': 'https://github.com/phoenixframework/phoenix',
                           'events': [{'introduced': '0'}, {'fixed': 'a' * 40}]}], 'versions': ['v1.0.0']}
        good = {'id': 'EEF-CVE-2026-56812', 'affected': [git, named]}
        self.assertEqual(SD.osv_coverage(self.archive(good), 'npm')['record_count'], 1)
        for bad in ([git], [git, {'package': {'name': 'phoenix', 'ecosystem': 'Hex'}, 'versions': ['1']}],
                    [git, {**named, 'versions': [], 'ranges': [{}]}], [named, {}], [named, {'package': None, **git}],
                    [named, {'ranges': [{'type': 'GIT', 'events': [{'introduced': '0'}]}]}],
                    [named, {**git, 'ranges': [{**git['ranges'][0], 'events': [{'introduced': 'bogus'}]}]}],
                    [named, {**git, 'ranges': [{**git['ranges'][0], 'type': 'SEMVER'}]}],
                    [named, {**git, 'ranges': [{**git['ranges'][0], 'repo': 'not a URL'}]}]):
            with self.subTest(bad=bad), self.assertRaises(SD.SecurityDataError):
                SD.osv_coverage(self.archive(good, {'id': 'OTHER', 'affected': bad}), 'npm')

    def test_registry_qualified_record_does_not_prove_default_registry_coverage(self):
        def record(identifier, ecosystem):
            return {'id': identifier, 'affected': [{'package': {'name': 'drupal/example', 'ecosystem': ecosystem},
                                                     'versions': ['1.0.0']}]}
        default = record('DEFAULT', 'Packagist')
        custom = record('DRUPAL-CONTRIB-2017-082', 'Packagist:https://packages.drupal.org/8')
        self.assertEqual(SD.osv_coverage(self.archive(default, custom), 'Packagist')['record_count'], 2)
        with self.assertRaises(SD.SecurityDataError):
            SD.osv_coverage(self.archive(custom), 'Packagist')
        for suffix in ('', 'not-url', 'https://host/a/../b', 'https://host/path/', 'https://host/a?auth=secret'):
            with self.subTest(suffix=suffix), self.assertRaises(SD.SecurityDataError):
                SD.osv_coverage(self.archive(default, record('OTHER', 'Packagist:' + suffix)), 'Packagist')

    def test_invalid_member_has_bounded_non_disclosing_location(self):
        private = 'private-example-value-' * 600
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr(private + '.json', json.dumps({'id': private, 'aliases': [',']}))
        with self.assertRaisesRegex(SD.SecurityDataError, 'aliases') as exc:
            SD.osv_coverage(out.getvalue(), 'npm')
        message = str(exc.exception)
        self.assertIn(hashlib.sha256((private + '.json').encode()).hexdigest(), message)
        self.assertIn(hashlib.sha256(private.encode()).hexdigest(), message)
        self.assertNotIn('private-example-value', message)
        self.assertLess(len(message), 400)


@unittest.skipUnless(SD.DESCRIPTOR_IO_AVAILABLE, 'descriptor-bound filesystem attack controls require qualified POSIX')
class SnapshotBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.database = self.root / 'database'
        self.outside = self.root / 'outside'
        self.outside.mkdir()
        (self.outside / 'marker').write_bytes(b'outside bytes must stay unchanged')

    def test_source_ancestor_link_cannot_write_pointer_or_export_outside(self):
        self.database.mkdir()
        (self.database / 'PyPI').symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(SD.SecurityDataError):
            publish(self.database)
        self.assertEqual(sorted(path.name for path in self.outside.iterdir()), ['marker'])
        self.assertEqual((self.outside / 'marker').read_bytes(), b'outside bytes must stay unchanged')

    def test_source_ancestor_link_is_not_accepted_by_reader_or_mirror(self):
        publish(self.database)
        source = self.database / 'PyPI'
        moved = self.outside / 'PyPI'
        source.rename(moved)
        source.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(SD.SecurityDataError):
            SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)
        destination = self.root / 'mirror'
        with self.assertRaises(SD.SecurityDataError):
            SD.copy_snapshot(self.database, destination, 'osv:PyPI', now=NOW)
        self.assertFalse(destination.exists())

    def test_object_ancestor_links_are_refused_for_publish_and_read(self):
        for relative in ('.snapshots', '.snapshots/sha256'):
            with self.subTest(relative=relative):
                database = self.root / relative.replace('/', '-')
                publish(database)
                selected = database / relative
                moved = self.outside / relative.replace('/', '-')
                selected.rename(moved)
                selected.symlink_to(moved, target_is_directory=True)
                before = {path.relative_to(moved).as_posix(): path.read_bytes() for path in moved.rglob('*') if path.is_file()}
                with self.assertRaises(SD.SecurityDataError):
                    SD.read_snapshot(database, 'osv:PyPI', now=NOW)
                with self.assertRaises(SD.SecurityDataError):
                    publish(database, payload=osv_bytes(version='2.0.0'))
                after = {path.relative_to(moved).as_posix(): path.read_bytes() for path in moved.rglob('*') if path.is_file()}
                self.assertEqual(after, before)

    def test_database_root_and_requested_path_ancestors_are_not_resolved_through_links(self):
        actual = self.outside / 'actual'
        publish(actual)
        self.database.symlink_to(actual, target_is_directory=True)
        parent_link = self.root / 'parent-link'
        parent_link.symlink_to(self.outside, target_is_directory=True)
        for selected in (self.database, parent_link / 'actual'):
            with self.subTest(selected=selected):
                before = (actual / 'PyPI/snapshot.json').read_bytes()
                with self.assertRaises(SD.SecurityDataError):
                    SD.read_snapshot(selected, 'osv:PyPI', now=NOW)
                with self.assertRaises(SD.SecurityDataError):
                    publish(selected, payload=osv_bytes(version='2.0.0'))
                self.assertEqual((actual / 'PyPI/snapshot.json').read_bytes(), before)

    def test_root_exchange_after_manifest_read_is_detected(self):
        publish(self.database)
        replacement = self.root / 'replacement'
        publish(replacement)
        displaced = self.root / 'displaced'
        decode = SD._json
        exchanged = False

        def exchange(raw):
            nonlocal exchanged
            result = decode(raw)
            if result.get('source_id') == 'osv:PyPI' and not exchanged:
                exchanged = True
                self.database.rename(displaced)
                replacement.rename(self.database)
            return result

        with mock.patch.object(SD, '_json', side_effect=exchange), self.assertRaises(SD.SecurityDataError):
            SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)
        self.assertTrue(exchanged)

    def test_directory_exchange_between_lstat_and_open_is_detected(self):
        publish(self.database)
        source = self.database / 'PyPI'
        replacement = self.root / 'replacement'
        replacement.mkdir()
        (replacement / 'snapshot.json').write_bytes((source / 'snapshot.json').read_bytes())
        opening = SD.fsx.open_dir_at
        exchanged = False

        def exchange(parent, name, **kwargs):
            nonlocal exchanged
            if name == 'PyPI' and not exchanged:
                exchanged = True
                source.rename(self.root / 'displaced-source')
                replacement.rename(source)
            return opening(parent, name, **kwargs)

        with mock.patch.object(SD.fsx, 'open_dir_at', side_effect=exchange), self.assertRaises(SD.SecurityDataError):
            SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)
        self.assertTrue(exchanged)

    def test_reader_rejects_leaf_links_and_special_files_without_following_or_blocking(self):
        for mode in ('pointer-link', 'object-link', 'pointer-fifo'):
            database = self.root / mode
            publish(database)
            target = database / ('PyPI/snapshot.json' if mode.startswith('pointer') else
                                 '.snapshots/sha256/' + hashlib.sha256(osv_bytes()).hexdigest())
            saved = self.outside / mode
            target.rename(saved)
            if mode.endswith('fifo'):
                os.mkfifo(target)
            else:
                target.symlink_to(saved)
            before = saved.read_bytes()
            with self.subTest(mode=mode), self.assertRaises(SD.SecurityDataError):
                SD.read_snapshot(database, 'osv:PyPI', now=NOW)
            self.assertEqual(saved.read_bytes(), before)

    def test_group_writable_snapshot_tree_is_an_explicit_refusal(self):
        publish(self.database)
        for target in (self.database, self.database / 'PyPI', self.database / '.snapshots/sha256'):
            original = target.stat().st_mode & 0o777
            target.chmod(original | 0o020)
            try:
                with self.subTest(target=target), self.assertRaisesRegex(SD.SecurityDataError, 'not writable by group/others'):
                    SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)
            finally:
                target.chmod(original)

    def test_nonsticky_writable_ancestor_is_refused_before_publication(self):
        unsafe = self.root / 'shared-parent'
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o777)
        database = unsafe / 'database'
        with self.assertRaisesRegex(SD.SecurityDataError, 'not writable by group/others'):
            publish(database)
        self.assertFalse(database.exists())

    def test_regular_file_exchange_or_inplace_mutation_during_validation_is_detected(self):
        validate = SD._validate
        for mode in ('pointer-exchange', 'object-exchange', 'object-inplace'):
            database = self.root / mode
            publish(database)
            pointer = database / 'PyPI/snapshot.json'
            target = pointer if mode == 'pointer-exchange' else database / '.snapshots/sha256' / hashlib.sha256(osv_bytes()).hexdigest()

            def mutate(*args, **kwargs):
                result = validate(*args, **kwargs)
                if mode.endswith('exchange'):
                    replacement = self.root / 'changed-file'
                    replacement.write_bytes(target.read_bytes())
                    os.replace(replacement, target)
                else:
                    metadata = target.stat()
                    target.write_bytes(target.read_bytes())
                    os.utime(target, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1))
                return result

            with self.subTest(mode=mode), mock.patch.object(SD, '_validate', side_effect=mutate), self.assertRaises(SD.SecurityDataError):
                SD.read_snapshot(database, 'osv:PyPI', now=NOW)

    def test_commit_race_does_not_replace_an_unrelated_symlink_target(self):
        publish(self.database)
        (self.outside / 'snapshot.json').write_bytes(b'outside pointer')
        (self.outside / 'all.zip').write_bytes(b'outside export')
        replace = SD.os.replace
        exchanged = False

        def exchange(source, destination, **kwargs):
            nonlocal exchanged
            if Path(destination).name == 'snapshot.json' and not exchanged:
                exchanged = True
                # Plant an identically named source in the redirect target. A
                # path-based rename would then overwrite the unrelated pointer.
                if kwargs:
                    descriptor = os.open(source, os.O_RDONLY, dir_fd=kwargs['src_dir_fd'])
                    with os.fdopen(descriptor, 'rb') as stream:
                        raw = stream.read()
                else:
                    raw = Path(source).read_bytes()
                (self.outside / Path(source).name).write_bytes(raw)
                (self.database / 'PyPI').rename(self.root / 'displaced-source')
                (self.database / 'PyPI').symlink_to(self.outside, target_is_directory=True)
            return replace(source, destination, **kwargs)

        with mock.patch.object(SD.os, 'replace', side_effect=exchange), self.assertRaises(SD.SecurityDataError):
            publish(self.database, payload=osv_bytes(version='2.0.0'))
        self.assertTrue(exchanged)
        self.assertEqual((self.outside / 'snapshot.json').read_bytes(), b'outside pointer')
        self.assertEqual((self.outside / 'all.zip').read_bytes(), b'outside export')

    def test_mirror_destination_link_cannot_mutate_outside(self):
        publish(self.database, acquired=NOW - timedelta(hours=71))
        destination = self.root / 'mirror'
        destination.mkdir()
        (destination / 'PyPI').symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(SD.SecurityDataError):
            SD.copy_snapshot(self.database, destination, 'osv:PyPI', now=NOW)
        self.assertEqual(sorted(path.name for path in self.outside.iterdir()), ['marker'])


class SnapshotCapabilityTests(unittest.TestCase):
    def test_missing_descriptor_capability_refuses_io_without_creating_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / 'database'
            with mock.patch.object(SD, 'DESCRIPTOR_IO_AVAILABLE', False, create=True):
                for operation in (lambda: publish(database),
                                  lambda: SD.read_snapshot(database, 'osv:PyPI', now=NOW),
                                  lambda: SD.copy_snapshot(database, database / 'mirror', 'osv:PyPI', now=NOW)):
                    with self.subTest(operation=operation), self.assertRaisesRegex(SD.SecurityDataError, 'descriptor|POSIX'):
                        operation()
            self.assertFalse(database.exists())

    def test_structural_no_dependency_result_needs_no_snapshot_filesystem(self):
        from getzilla.security_osv_snapshot import scan
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(SD, 'DESCRIPTOR_IO_AVAILABLE', False, create=True):
            root = Path(temporary)
            result = scan(root, environ={'GETZILLA_OSV_DB': str(root / 'absent')}, now=NOW)
            self.assertEqual(result['status'], 'skip')
            self.assertEqual(result['dependencies'], 0)
            self.assertFalse((root / 'absent').exists())


if __name__ == '__main__':
    unittest.main()
