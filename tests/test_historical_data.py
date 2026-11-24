"""Exact historical source-data classification, not an archive execution permit."""
from __future__ import annotations

import gzip
from pathlib import Path
import shutil
import sys
import unittest

from tests import test_review_plan as support
from tests.branch_support import git

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import historical_data as history


class HistoricalReconciliationTests(unittest.TestCase):
    setUp = support.ReviewPlanTests.setUp
    write = support.ReviewPlanTests.write
    commit = support.ReviewPlanTests.commit
    route = support.ReviewPlanTests.route
    reconcile = support.ReviewPlanTests.reconcile

    def publish(self, *, ancestry=True, mutate=None):
        # Keep the historical publication inside the fixture's own object store.
        git(self.root, '-c', 'fetch.unpackLimit=100000', 'fetch', '--no-tags', '--depth=1',
            ROOT.as_uri(), history.PUBLICATION)
        shutil.copytree(ROOT / history.PREFIX, self.root / history.PREFIX)
        if mutate:
            mutate()
        git(self.root, 'add', '.')
        tree = git(self.root, 'write-tree')
        args = ['commit-tree', tree, '-p', self.base]
        if ancestry:
            args.extend(('-p', history.PUBLICATION))
        commit = git(self.root, *args, '-m', 'historical evidence fixture')
        git(self.root, 'update-ref', 'HEAD', commit)
        self.route()

    def incomplete(self):
        result = self.reconcile()
        self.assertEqual(result['risk_assessment']['status'], 'incomplete')
        self.assertIn('BINARY_OR_UNKNOWN_INVENTORY', result['risk_assessment']['gaps'])
        return result

    def test_actual_reconciliation_catalogues_original_source_without_lowering_review(self):
        self.publish()
        result = self.reconcile()
        assessment = result['risk_assessment']
        self.assertEqual(assessment['status'], 'complete', assessment['gaps'])
        self.assertEqual((result['risk'], assessment['profile_candidate']), ('high', 'full'))
        self.assertEqual(set(result['review_agents']),
                         {'code_reviewer', 'security_reviewer', 'data_reviewer', 'release_reviewer'})
        self.assertIn({'rule': 'HISTORICAL_SOURCE_DATA', 'path': history.SOURCE_PATH, 'risk': 'high'}, assessment['reasons'])
        for name in ('candidate.bundle', 'initial-vectors.npy', 'source-graph.sqlite', 'vectors.npy'):
            self.assertIn({'rule': 'BINARY_FILE', 'path': history.PREFIX + '/artifacts/' + name, 'risk': 'high'}, assessment['reasons'])
        source = next(row['catalogue'] for row in assessment['historical_data']['sources'] if row['catalogue'])
        self.assertEqual((source['publication_commit'], source['publication_tree']),
                         (history.PUBLICATION, history.PUBLICATION_TREE))
        self.assertEqual((source['sha256'], source['bytes']), (history.SOURCE_SHA256, history.SOURCE_SIZE))
        self.assertEqual(len(source['members']), 72)
        self.assertFalse(source['execution_authority'])
        self.assertFalse(source['archive_extracted'])
        self.assertEqual(git(self.root, 'rev-parse', 'HEAD:' + history.PREFIX), history.PUBLICATION_TREE)

    def test_same_bytes_without_original_commit_ancestry_remain_incomplete(self):
        self.publish(ancestry=False)
        result = self.incomplete()
        self.assertIn('INVALID_HISTORICAL_SOURCE_DATA', result['risk_assessment']['gaps'])

    def test_tampered_binary_and_ascii_substitution_are_both_incomplete(self):
        for replacement in (b'not an archive', (ROOT / history.SOURCE_PATH).read_bytes()[:-1] + b'x'):
            with self.subTest(kind=replacement[:12]):
                self.setUp()
                self.publish(mutate=lambda: (self.root / history.SOURCE_PATH).write_bytes(replacement))
                self.incomplete()

    def test_missing_original_provenance_document_is_incomplete(self):
        self.publish(mutate=lambda: (self.root / history.PREFIX / 'SHA256SUMS.json').unlink())
        self.incomplete()

    def test_added_unknown_archive_neighbor_does_not_inherit_the_catalogue(self):
        self.publish(mutate=lambda: (self.root / history.PREFIX / 'artifacts/neighbour.tar.gz').write_bytes(
            (ROOT / history.SOURCE_PATH).read_bytes()))
        self.incomplete()

    def test_renamed_original_archive_is_not_admitted(self):
        self.publish(mutate=lambda: (self.root / history.SOURCE_PATH).rename(
            self.root / history.PREFIX / 'renamed-source.tar.gz'))
        self.incomplete()

    def test_runtime_source_archive_cannot_reuse_historical_identity(self):
        self.write('current/source.tar.gz', 'placeholder')
        (self.root / 'current/source.tar.gz').write_bytes((ROOT / history.SOURCE_PATH).read_bytes())
        self.commit()
        self.route()
        result = self.incomplete()
        self.assertNotIn('historical_data', result['risk_assessment'])


class HistoricalArchiveFormatTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / history.SOURCE_PATH).read_bytes()
        self.body = gzip.decompress(self.raw)

    def compressed(self, body):
        return gzip.compress(bytes(body), mtime=0)

    def header(self, body, offset, *, name=None, kind=None):
        if name is not None:
            body[offset:offset + 100] = name.encode().ljust(100, b'\0')
        if kind is not None:
            body[offset + 156:offset + 157] = kind
        body[offset + 148:offset + 156] = b' ' * 8
        checksum = sum(body[offset:offset + 512])
        body[offset + 148:offset + 156] = f'{checksum:06o}\0 '.encode()

    def test_complete_original_members_are_inert_bounded_catalogue_rows(self):
        rows = history.source_members(self.raw)
        self.assertEqual(len(rows), 72)
        self.assertEqual(sum(row['bytes'] for row in rows), 135624)
        self.assertEqual(sum(row['kind'] == 'source_file' for row in rows), 60)

    def test_truncated_gzip_extra_stream_and_trailing_bytes_refuse(self):
        base = self.compressed(self.body)
        for raw in (self.raw[:-1], base + b'junk', base + gzip.compress(b'', mtime=0)):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                history.source_members(raw)

    def test_decompression_and_member_payload_bounds_refuse(self):
        with self.assertRaises(ValueError):
            history.source_members(gzip.compress(bytes(1024 * 1024), mtime=0))

    def test_declared_oversize_payload_refuses(self):
        body = bytearray(self.body)
        body[1024 + 124:1024 + 136] = b'00004000000\0'
        self.header(body, 1024, kind=b'0')
        with self.assertRaises(ValueError):
            history.source_members(self.compressed(body))

    def test_missing_parent_directory_closure_refuses(self):
        body = bytearray(self.body)
        self.header(body, 1024, name='itsdangerous-2.2.0/renamed-root')
        with self.assertRaisesRegex(ValueError, 'PARENT_CLOSURE'):
            history.source_members(self.compressed(body))

    def test_nonzero_tar_trailer_refuses(self):
        body = bytearray(self.body)
        body[-1] = 1
        with self.assertRaises(ValueError):
            history.source_members(self.compressed(body))

    def test_parent_traversal_absolute_names_links_and_devices_refuse(self):
        for name, kind in (('../outside', b'5'), ('/outside', b'5'), ('itsdangerous-2.2.0', b'2'),
                           ('itsdangerous-2.2.0', b'3')):
            with self.subTest(name=name, kind=kind):
                body = bytearray(self.body)
                self.header(body, 1024, name=name, kind=kind)
                with self.assertRaises(ValueError):
                    history.source_members(self.compressed(body))

    def test_pax_name_override_and_corrupt_header_refuse(self):
        body = bytearray(self.body)
        body[512:512 + 28] = b'28 path=../../outside' + b' ' * 7 + b'\n'
        with self.assertRaises(ValueError):
            history.source_members(self.compressed(body))
        body = bytearray(self.body)
        body[1024] ^= 1
        with self.assertRaises(ValueError):
            history.source_members(self.compressed(body))


class HistoricalGitCustodyTests(unittest.TestCase):
    write = HistoricalReconciliationTests.write
    commit = HistoricalReconciliationTests.commit
    route = HistoricalReconciliationTests.route
    publish = HistoricalReconciliationTests.publish

    def setUp(self):
        HistoricalReconciliationTests.setUp(self)
        self.publish()

    # Reuse only fixture methods, not the parent class's reconciliation tests.
    def _during_validation(self, mutation):
        from unittest import mock
        original = history.source_members
        def changed(raw):
            rows = original(raw)
            mutation()
            return rows
        with mock.patch.object(history, 'source_members', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'HISTORICAL_GIT_CUSTODY'):
                history.issue170_source(self.root, 'HEAD')

    def test_git_configuration_replacement_during_decode_refuses(self):
        import os
        path = self.root / '.git/config'
        replacement = path.with_name('config-replacement')
        def replace():
            replacement.write_bytes(path.read_bytes())
            os.replace(replacement, path)
        self._during_validation(replace)

    def test_head_change_during_decode_refuses(self):
        self._during_validation(lambda: git(self.root, 'update-ref', 'HEAD', self.base))

    def test_object_content_replacement_after_size_before_body_refuses(self):
        import os
        import zlib
        from unittest import mock
        raw = (ROOT / history.SOURCE_PATH).read_bytes()
        oid = history.SOURCE_BLOB
        path = self.root / '.git/objects' / oid[:2] / oid[2:]
        self.assertTrue(path.is_file())
        original = history._git
        def read(root, arguments, **options):
            if arguments == ['cat-file', 'blob', oid]:
                changed = bytearray(raw)
                changed[-1] ^= 1
                replacement = path.with_name('replacement')
                replacement.write_bytes(zlib.compress(b'blob ' + str(len(changed)).encode() + b'\0' + changed))
                os.replace(replacement, path)
            return original(root, arguments, **options)
        with mock.patch.object(history, '_git', side_effect=read), self.assertRaises(ValueError):
            history.issue170_source(self.root, 'HEAD')

    def test_source_root_replacement_during_decode_refuses(self):
        backup = self.root.with_name(self.root.name + '-original')
        def replace():
            self.root.rename(backup)
            self.addCleanup(shutil.rmtree, backup)
            shutil.copytree(backup, self.root)
        self._during_validation(replace)

    def test_deadline_expiry_after_read_does_not_admit_the_catalogue(self):
        from unittest import mock
        original_operation, scopes = history._GitOperation, []
        def operation(root):
            scope = original_operation(root)
            scopes.append(scope)
            return scope
        with mock.patch.object(history, '_GitOperation', side_effect=operation):
            self._during_validation(lambda: setattr(scopes[0], '_deadline', 0))

    def test_every_read_shares_one_scope_and_exact_blob_caps(self):
        from unittest import mock
        original, calls = history._git, []
        def read(root, arguments, **options):
            calls.append((arguments, options['limit'], options['_scope']))
            return original(root, arguments, **options)
        with mock.patch.object(history, '_git', side_effect=read):
            source = history.issue170_source(self.root, 'HEAD')
        self.assertEqual(source['sha256'], history.SOURCE_SHA256)
        self.assertEqual(len({id(row[2]) for row in calls}), 1)
        from getzilla.architecture_diff import _guarded_git_arguments
        self.assertTrue(all(_guarded_git_arguments(args, None) for args, _, _ in calls))
        self.assertEqual([(args[2], cap) for args, cap, _ in calls if args[:2] == ['cat-file', 'blob']],
                         [(history.SOURCE_BLOB, history.SOURCE_SIZE), (history.MANIFEST_BLOB, 12201)])
        self.assertTrue(all(0 < cap <= history.SOURCE_SIZE for _, cap, _ in calls))

    def test_mismatched_object_size_refuses_before_payload_read(self):
        from unittest import mock
        original, payload_reads = history._git, []
        def read(root, arguments, **options):
            if arguments[:3] == ['ls-tree', '-l', '-z'] and arguments[-1] == history.SOURCE_PATH:
                return original(root, arguments, **options).replace(
                    str(history.SOURCE_SIZE).encode() + b'\t', str(history.SOURCE_SIZE + 1).encode() + b'\t')
            if arguments[:2] == ['cat-file', 'blob']:
                payload_reads.append(arguments)
            return original(root, arguments, **options)
        with mock.patch.object(history, '_git', side_effect=read), self.assertRaisesRegex(ValueError, 'GIT_BOUNDS'):
            history.issue170_source(self.root, 'HEAD')
        self.assertFalse(payload_reads)

    def test_bounded_git_payload_overflow_refuses(self):
        from unittest import mock
        original = history._git
        def read(root, arguments, **options):
            if arguments == ['cat-file', 'blob', history.SOURCE_BLOB]:
                options['limit'] = history.SOURCE_SIZE - 1
            return original(root, arguments, **options)
        with mock.patch.object(history, '_git', side_effect=read), self.assertRaisesRegex(ValueError, 'GIT_CUSTODY'):
            history.issue170_source(self.root, 'HEAD')
