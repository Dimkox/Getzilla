"""Qualified OSV storage uses public archives and owned disposable directories."""
from __future__ import annotations

import errno
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)


def record(identifier='PUBLIC-1', ecosystem='PyPI'):
    return {'id': identifier, 'aliases': ['CVE-2026-0001'], 'affected': [
        {'package': {'ecosystem': ecosystem, 'name': 'public-other-package'}, 'versions': ['1.0.0']}]}


def archive(records):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as bundle:
        for index, item in enumerate(records):
            bundle.writestr(f'public-{index}.json', json.dumps(item))
    return output.getvalue()


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        try:
            self.data = importlib.import_module('getzilla.security_data')
        except ModuleNotFoundError:
            self.data = None
        self.assertIsNotNone(self.data, 'native qualified snapshot store is missing')
        self.temporary = tempfile.TemporaryDirectory(prefix='osv-public-store-')
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name).resolve()
        self.database = self.parent / 'database'
        self.payload = archive([record()])

    def publish(self, payload=None, acquired=NOW, database=None):
        payload = self.payload if payload is None else payload
        return self.data.publish_snapshot(self.database if database is None else database, 'osv:PyPI', payload,
            acquisition={'last_verified_sync_utc': acquired.isoformat(), 'retrieval_kind': 'download'},
            coverage=self.data.osv_coverage(payload, 'PyPI'), now=NOW)

    def test_inclusive_age_and_exact_bytes(self):
        self.publish(acquired=NOW - timedelta(seconds=259200))
        payload, proof = self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW, required_scope={'PyPI'})
        self.assertEqual(payload, self.payload)
        self.assertEqual(proof['age_seconds'], 259200)
        for current in (NOW + timedelta(seconds=1), NOW - timedelta(seconds=259201)):
            with self.subTest(current=current), self.assertRaises(self.data.SecurityDataError):
                self.data.read_snapshot(self.database, 'osv:PyPI', now=current)

    def test_unknown_future_and_stale_time_refuse(self):
        for value in (None, 'unknown', (NOW + timedelta(seconds=1)).isoformat(),
                      (NOW - timedelta(seconds=259201)).isoformat()):
            with self.subTest(value=value), self.assertRaises(self.data.SecurityDataError):
                self.data.publish_snapshot(self.database, 'osv:PyPI', self.payload,
                    acquisition={'last_verified_sync_utc': value, 'retrieval_kind': 'download'},
                    coverage=self.data.osv_coverage(self.payload, 'PyPI'), now=NOW)
        self.assertFalse(self.database.exists())

    def test_legacy_archive_cannot_qualify_by_mtime_or_copy(self):
        folder = self.database / 'PyPI'
        folder.mkdir(parents=True)
        (folder / 'all.zip').write_bytes(self.payload)
        os.utime(folder / 'all.zip', (NOW.timestamp(), NOW.timestamp()))
        with self.assertRaises(self.data.SecurityDataError):
            self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW)

    def test_empty_wrong_and_corrupt_archive_refuse(self):
        for payload in (archive([]), archive([record(ecosystem='npm')]), b'public invalid ZIP', self.payload[:-12]):
            with self.subTest(size=len(payload)), self.assertRaises(self.data.SecurityDataError):
                self.data.osv_coverage(payload, 'PyPI')

    def test_alias_and_source_coverage_are_rederived(self):
        malformed = record()
        malformed['aliases'] = 'CVE-2026-0001'
        with self.assertRaises(self.data.SecurityDataError):
            self.data.osv_coverage(archive([malformed]), 'PyPI')
        coverage = self.data.osv_coverage(self.payload, 'PyPI')
        for changed in ({**coverage, 'record_count': 2}, {**coverage, 'complete': False}):
            with self.subTest(coverage=changed), self.assertRaises(self.data.SecurityDataError):
                self.data.publish_snapshot(self.database, 'osv:PyPI', self.payload,
                    acquisition={'last_verified_sync_utc': NOW.isoformat(), 'retrieval_kind': 'download'},
                    coverage=changed, now=NOW)

    def test_copy_retains_original_acquisition_clock(self):
        acquired = NOW - timedelta(hours=1)
        self.publish(acquired=acquired)
        destination = self.parent / 'copy'
        self.data.copy_snapshot(self.database, destination, 'osv:PyPI', now=NOW)
        payload, proof = self.data.read_snapshot(destination, 'osv:PyPI', now=NOW)
        self.assertEqual(payload, self.payload)
        self.assertEqual(datetime.fromisoformat(proof['acquisition']['last_verified_sync_utc']), acquired)

    def test_expiration_during_staging_never_switches_pointer(self):
        self.publish()
        pointer = self.database / 'PyPI/snapshot.json'
        before = pointer.read_bytes()
        original, original_clock = self.data._SnapshotStore.write, self.data._clock
        current = [NOW]
        def write(store, parts, payload, **kwargs):
            result = original(store, parts, payload, **kwargs)
            if parts[-1] == '.publication-pending.json':
                current[0] += timedelta(seconds=1)
            return result
        with patch.object(self.data._SnapshotStore, 'write', write), \
                patch.object(self.data, '_clock', side_effect=lambda supplied: original_clock(current[0] if supplied is None else supplied)):
            with self.assertRaises(self.data.SecurityDataError):
                self.data.publish_snapshot(self.database, 'osv:PyPI', archive([record('PUBLIC-2')]),
                    acquisition={'last_verified_sync_utc': (NOW - timedelta(seconds=259200)).isoformat(),
                                 'retrieval_kind': 'download'},
                    coverage=self.data.osv_coverage(self.payload, 'PyPI'))
        self.assertEqual(pointer.read_bytes(), before)
        self.assertEqual(self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW)[0], self.payload)

    def test_final_metadata_confirmation_refuses_expiry_replacement_and_pending(self):
        self.publish(acquired=NOW - timedelta(seconds=259200))
        _, proof = self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW)
        check = getattr(self.data, 'confirm_snapshots', None)
        self.assertTrue(callable(check), 'joint final source custody and age confirmation is missing')
        check(self.database, [proof], now=NOW)
        with self.assertRaises(self.data.SecurityDataError):
            check(self.database, [proof], now=NOW + timedelta(seconds=1))
        pointer = self.database / 'PyPI/snapshot.json'
        raw = pointer.read_bytes()
        pointer.unlink()
        pointer.write_bytes(raw)
        with self.assertRaises(self.data.SecurityDataError):
            check(self.database, [proof], now=NOW)

    def test_copy_uses_live_clock_instead_of_freezing_start_time(self):
        self.publish(acquired=NOW - timedelta(seconds=259200))
        original, original_clock = self.data.read_snapshot, self.data._clock
        current = [NOW]
        def read(*args, **kwargs):
            result = original(*args, **kwargs)
            current[0] += timedelta(seconds=1)
            return result
        destination = self.parent / 'copy-expired'
        with patch.object(self.data, 'read_snapshot', read), \
                patch.object(self.data, '_clock', side_effect=lambda supplied: original_clock(current[0] if supplied is None else supplied)):
            with self.assertRaises(self.data.SecurityDataError):
                self.data.copy_snapshot(self.database, destination, 'osv:PyPI')
        self.assertFalse((destination / 'PyPI/snapshot.json').exists())

    def test_definite_precommit_failure_keeps_old_pointer_and_bytes(self):
        self.publish()
        pointer = self.database / 'PyPI/snapshot.json'
        before = pointer.read_bytes()
        original = self.data.fsx.replace_at
        def fail_pointer(source_parent, source, target_parent, target):
            if target == 'snapshot.json':
                raise OSError(errno.EIO, 'public precommit failure')
            return original(source_parent, source, target_parent, target)
        with patch.object(self.data.fsx, 'replace_at', side_effect=fail_pointer):
            with self.assertRaises(self.data.SecurityDataError):
                self.publish(archive([record('PUBLIC-2')]))
        self.assertEqual(pointer.read_bytes(), before)
        self.assertEqual(self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW)[0], self.payload)

    def test_supported_publishers_serialize_without_waiting_or_switching(self):
        self.publish()
        pointer = self.database / 'PyPI/snapshot.json'
        before = pointer.read_bytes()
        self.assertTrue(callable(getattr(self.data._SnapshotStore, 'lock_publication', None)),
                        'supported publishers need an owned nonblocking serialization lock')
        with self.data._SnapshotStore(self.database) as owner:
            owner.lock_publication()
            with self.assertRaises(self.data.SecurityDataError):
                self.publish(archive([record('PUBLIC-CONTENDING')]))
        self.assertEqual(pointer.read_bytes(), before)
        self.publish(archive([record('PUBLIC-NEXT')]))

    def test_post_pointer_failure_is_durable_unknown(self):
        self.publish()
        original = self.data._SnapshotStore.write
        def uncertain(store, parts, payload):
            original(store, parts, payload)
            if parts[-1] == 'snapshot.json':
                raise OSError(errno.EIO, 'public postcommit failure')
        with patch.object(self.data._SnapshotStore, 'write', uncertain):
            with self.assertRaisesRegex(self.data.SecurityDataError, 'commit_unknown'):
                self.publish(archive([record('PUBLIC-2')]))
        with self.assertRaisesRegex(self.data.SecurityDataError, 'unknown|reconcil'):
            self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW)

    def test_post_pointer_primary_exits_survive_with_unknown_retained(self):
        class PublicExit(BaseException):
            pass
        original = self.data._SnapshotStore.write
        for index, kind in enumerate((KeyboardInterrupt, SystemExit, PublicExit)):
            database = self.parent / f'public-primary-{index}'
            def interrupted(store, parts, payload):
                original(store, parts, payload)
                if parts[-1] == 'snapshot.json':
                    raise kind()
            observed = None
            with patch.object(self.data._SnapshotStore, 'write', interrupted):
                try:
                    self.publish(database=database)
                except BaseException as error:
                    observed = type(error)
            self.assertIs(observed, kind, 'publication replaced the primary exit with an ordinary refresh failure')
            with self.assertRaisesRegex(self.data.SecurityDataError, 'commit_unknown'):
                self.data.read_snapshot(database, 'osv:PyPI', now=NOW)

    def test_compatibility_export_error_does_not_relabel_commit(self):
        original = self.data._SnapshotStore.write
        def refuse_export(store, parts, payload):
            if parts[-1] == 'all.zip':
                raise OSError(errno.EIO, 'public export failure')
            return original(store, parts, payload)
        with patch.object(self.data._SnapshotStore, 'write', refuse_export):
            proof = self.publish()
        self.assertEqual(proof['publication_outcome'], 'committed')
        self.assertIn('compatibility_export_warning', proof)
        self.assertEqual(self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW)[0], self.payload)

    def test_linked_ancestry_never_writes_outside(self):
        outside = self.parent / 'outside'
        outside.mkdir()
        sentinel = outside / 'public-sentinel'
        sentinel.write_bytes(b'public untouched')
        self.database.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(self.data.SecurityDataError):
            self.publish()
        self.assertEqual(sentinel.read_bytes(), b'public untouched')
        self.assertEqual(sorted(p.name for p in outside.iterdir()), ['public-sentinel'])

    def test_replaced_pointer_or_object_refuses_without_following(self):
        proof = self.publish()
        object_path = self.database / '.snapshots/sha256' / proof['content_sha256']
        original = object_path.read_bytes()
        object_path.unlink()
        foreign = self.parent / 'public-foreign'
        foreign.write_bytes(original)
        object_path.symlink_to(foreign)
        with self.assertRaises(self.data.SecurityDataError):
            self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW)
        self.assertEqual(foreign.read_bytes(), original)

    def test_hardlinked_input_is_not_owned_custody(self):
        proof = self.publish()
        object_path = self.database / '.snapshots/sha256' / proof['content_sha256']
        os.link(object_path, self.parent / 'public-other-link')
        with self.assertRaises(self.data.SecurityDataError):
            self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW)

    def test_archive_census_limit_precedes_zipfile_materialization(self):
        payload = archive([record(), record('PUBLIC-2')])
        with patch.object(self.data, 'MAX_ARCHIVE_MEMBERS', 1), \
                patch.object(self.data.zipfile, 'ZipFile', side_effect=AssertionError('unbounded materialization')) as constructor:
            with self.assertRaises(self.data.SecurityDataError):
                self.data.osv_coverage(payload, 'PyPI')
        constructor.assert_not_called()

    def test_remaining_read_budget_refuses_before_first_content_read(self):
        self.publish()
        original_read = self.data.os.read
        with patch.object(self.data, 'MAX_STORE_READ_BYTES', 1), \
                patch.object(self.data.os, 'read', wraps=original_read) as reading:
            with self.assertRaises(self.data.SecurityDataError):
                self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW)
        reading.assert_not_called()

    def test_real_clock_is_rechecked_after_payload_read(self):
        self.publish(acquired=NOW - timedelta(seconds=259200))
        original_read, original_clock = self.data._SnapshotStore.read, self.data._clock
        current = [NOW]
        def read(store, parts, maximum):
            payload = original_read(store, parts, maximum)
            if len(parts) == 3 and parts[:2] == ('.snapshots', 'sha256'):
                current[0] += timedelta(seconds=1)
            return payload
        with patch.object(self.data._SnapshotStore, 'read', read), \
                patch.object(self.data, '_clock', side_effect=lambda supplied: original_clock(current[0] if supplied is None else supplied)):
            with self.assertRaises(self.data.SecurityDataError):
                self.data.read_snapshot(self.database, 'osv:PyPI')

    def test_pending_publication_appearing_during_read_refuses_old_proof(self):
        self.publish()
        original = self.data._SnapshotStore.read
        def read(store, parts, maximum):
            payload = original(store, parts, maximum)
            if parts[:2] == ('.snapshots', 'sha256'):
                (self.database / 'PyPI/.publication-pending.json').write_bytes(b'public pending fixture')
            return payload
        with patch.object(self.data._SnapshotStore, 'read', read), self.assertRaises(self.data.SecurityDataError):
            self.data.read_snapshot(self.database, 'osv:PyPI', now=NOW)

    def test_withdrawn_schema_null_fields_do_not_create_false_missing_coverage(self):
        withdrawn = {'id': 'PUBLIC-WITHDRAWN', 'withdrawn': '2026-01-01T00:00:00Z',
                     'aliases': None, 'affected': None}
        try:
            proof = self.publish(archive([record(), withdrawn]))
        except self.data.SecurityDataError:
            self.fail('schema-valid withdrawn null affected/aliases were refused')
        self.assertEqual(proof['coverage']['record_count'], 2)

    def test_named_unknown_ranges_cannot_hide_behind_exact_versions(self):
        unknown = record()
        unknown['affected'][0]['ranges'] = [{'type': 'GIT', 'repo': 'https://example.invalid/public/repository',
                                          'events': [{'introduced': '0'}, {'fixed': 'a' * 40}]}]
        malformed = record()
        malformed['affected'][0]['ranges'] = [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0', 'fixed': '2'}]}]
        for item in (unknown, malformed):
            with self.subTest(kind=item['affected'][0]['ranges'][0]['type']), self.assertRaises(self.data.SecurityDataError):
                self.data.osv_coverage(archive([item]), 'PyPI')

    def test_named_npm_with_separate_git_supplement_is_supported(self):
        item = record(ecosystem='npm')
        item['affected'].append({'ranges': [{'type': 'GIT', 'repo': 'https://example.invalid/public/repository',
                                           'events': [{'introduced': '0'}, {'fixed': 'a' * 40}]}]})
        proof = self.data.osv_coverage(archive([item]), 'npm')
        self.assertEqual(proof['scopes'], ['npm'])
        self.assertEqual(proof['record_count'], 1)
