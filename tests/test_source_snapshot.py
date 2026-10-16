"""Z08 verified snapshot after admission; Z09 owned shadow that never touches the original."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import source_snapshot  # noqa: E402
from getzilla.source_admission import plan_source  # noqa: E402
from getzilla.source_models import IngestPolicy  # noqa: E402
from getzilla.source_shadow import materialize_shadow  # noqa: E402
from getzilla.source_snapshot import AdoptionError, create_snapshot, object_path  # noqa: E402
from tests.zero_git_support import FAKE_GITHUB_TOKEN, clean_source, tree_state, write_tree  # noqa: E402


class _Case(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix='zg-snapshot-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = clean_source(self.base / 'src')
        self.store = self.base / 'state' / 'store'
        self.plan = plan_source(self.source, self.base / 'out', IngestPolicy())
        self.assertEqual(self.plan.status, 'PLAN_READY', self.plan.blockers)

    def stored_files(self) -> list[Path]:
        objects = self.store / 'objects'
        return [path for path in objects.rglob('*') if path.is_file()] if objects.exists() else []


class SnapshotTests(_Case):
    def test_no_snapshot_before_scan_pass(self) -> None:
        source = write_tree(self.base / 'bad', {'a.py': f'K = "{FAKE_GITHUB_TOKEN}"'})
        plan = plan_source(source, self.base / 'out2', IngestPolicy())
        with self.assertRaises(AdoptionError) as caught:
            create_snapshot(plan, source, self.store, quiesced=True)
        self.assertEqual(caught.exception.reason_code, 'PLAN_NOT_READY')
        self.assertEqual(self.stored_files(), [])

    def test_changed_secret_bytes_never_written_even_temporarily(self) -> None:
        # The same size, a secret now: digest check refuses before any write.
        original = (self.source / 'app/main.py').read_bytes()
        replacement = (f'K="{FAKE_GITHUB_TOKEN}"'.encode()[:len(original)]).ljust(len(original), b' ')
        (self.source / 'app/main.py').write_bytes(replacement)
        writes: list[bytes] = []
        real_write = os.write

        def watch(descriptor, data):
            writes.append(bytes(data))
            return real_write(descriptor, data)

        with mock.patch.object(source_snapshot.os, 'write', side_effect=watch), self.assertRaises(AdoptionError) as caught:
            create_snapshot(self.plan, self.source, self.store, quiesced=True)
        self.assertEqual(caught.exception.reason_code, 'STALE_PLAN')
        self.assertFalse(any(FAKE_GITHUB_TOKEN[:12].encode() in chunk for chunk in writes))
        for path in self.stored_files():
            self.assertNotIn(FAKE_GITHUB_TOKEN[:12].encode(), path.read_bytes())

    def test_memory_limit_blocks_without_plaintext_spool(self) -> None:
        source = write_tree(self.base / 'big', {'big.txt': 'x' * 2000, 'a.txt': 'a'})
        policy = IngestPolicy(max_buffered_file_bytes=1000, max_total_buffer_bytes=1000)
        plan = plan_source(source, self.base / 'out3', policy)
        with self.assertRaises(AdoptionError) as caught:
            create_snapshot(plan, source, self.store, quiesced=True)
        self.assertEqual(caught.exception.reason_code, 'BUFFER_LIMIT')
        self.assertFalse(any(path.stat().st_size == 2000 for path in self.stored_files()))

    def test_one_byte_drift_invalidates_plan(self) -> None:
        (self.source / 'README.md').write_text('# demO\n', encoding='utf-8')
        with self.assertRaises(AdoptionError) as caught:
            create_snapshot(self.plan, self.source, self.store, quiesced=True)
        self.assertEqual(caught.exception.reason_code, 'STALE_PLAN')

    def test_mutation_during_copy_fails(self) -> None:
        real_store = source_snapshot._store_object
        calls = []

        def mutate(store, entry, content):
            calls.append(entry.path)
            real_store(store, entry, content)
            if len(calls) == 1:
                (self.source / 'new-file.txt').write_text('appeared', encoding='utf-8')

        with mock.patch.object(source_snapshot, '_store_object', side_effect=mutate), self.assertRaises(AdoptionError) as caught:
            create_snapshot(self.plan, self.source, self.store, quiesced=True)
        self.assertEqual(caught.exception.reason_code, 'STALE_PLAN')

    def test_quiescence_required(self) -> None:
        with self.assertRaises(AdoptionError) as caught:
            create_snapshot(self.plan, self.source, self.store, quiesced=False)
        self.assertEqual(caught.exception.reason_code, 'QUIESCENCE_REQUIRED')

    def test_store_content_rehash_matches(self) -> None:
        receipt = create_snapshot(self.plan, self.source, self.store, quiesced=True)
        import hashlib
        for entry in receipt.entries:
            self.assertEqual(hashlib.sha256(object_path(self.store, entry.sha256).read_bytes()).hexdigest(), entry.sha256)
        self.assertEqual(receipt.consistency['mode'], 'quiesced_two_pass')

    def test_excluded_secret_not_in_snapshot(self) -> None:
        write_tree(self.source, {'.env': f'TOKEN={FAKE_GITHUB_TOKEN}\n'})
        plan = plan_source(self.source, self.base / 'out4', IngestPolicy(exclude=('.env',)))
        create_snapshot(plan, self.source, self.store, quiesced=True)
        for path in self.stored_files():
            self.assertNotIn(FAKE_GITHUB_TOKEN.encode(), path.read_bytes())

    def test_modified_existing_store_entry_rejected(self) -> None:
        receipt = create_snapshot(self.plan, self.source, self.store, quiesced=True)
        victim = object_path(self.store, receipt.entries[0].sha256)
        os.chmod(victim, 0o600)
        victim.write_bytes(b'tampered' + b'x' * max(0, receipt.entries[0].size - 8))
        with self.assertRaises(AdoptionError) as caught:
            create_snapshot(self.plan, self.source, self.store, quiesced=True)
        self.assertEqual(caught.exception.reason_code, 'STORE_OBJECT_MODIFIED')


class ShadowTests(_Case):
    def setUp(self) -> None:
        super().setUp()
        self.receipt = create_snapshot(self.plan, self.source, self.store, quiesced=True)

    def test_shadow_matches_snapshot(self) -> None:
        shadow = materialize_shadow(self.receipt, self.store, self.base / 'shadow', self.source)
        self.assertEqual(shadow.files, len(self.receipt.entries))
        self.assertEqual((self.base / 'shadow/app/main.py').read_bytes(), (self.source / 'app/main.py').read_bytes())

    def test_original_unchanged(self) -> None:
        before = tree_state(self.source)
        materialize_shadow(self.receipt, self.store, self.base / 'shadow', self.source)
        self.assertEqual(tree_state(self.source), before)

    def test_target_appearing_is_not_overwritten(self) -> None:
        existing = self.base / 'shadow'
        existing.mkdir()
        (existing / 'foreign.txt').write_text('keep', encoding='utf-8')
        with self.assertRaises(FileExistsError):
            materialize_shadow(self.receipt, self.store, existing, self.source)
        self.assertEqual(sorted(path.name for path in existing.iterdir()), ['foreign.txt'])

    def test_source_target_alias_rejected(self) -> None:
        with self.assertRaises(AdoptionError):
            materialize_shadow(self.receipt, self.store, self.source / 'inner-shadow', self.source)
        self.assertFalse((self.source / 'inner-shadow').exists())

    def test_shadow_files_do_not_share_mutable_identity_with_source(self) -> None:
        materialize_shadow(self.receipt, self.store, self.base / 'shadow', self.source)
        for entry in self.receipt.entries:
            left = (self.source / entry.path).stat()
            right = (self.base / 'shadow' / entry.path).stat()
            self.assertNotEqual((left.st_dev, left.st_ino), (right.st_dev, right.st_ino))
        (self.base / 'shadow/README.md').write_text('changed', encoding='utf-8')
        self.assertEqual((self.source / 'README.md').read_text(encoding='utf-8'), '# demo\n')

    def test_insufficient_space_does_not_publish_target(self) -> None:
        real_write = os.write

        def full(descriptor, data):
            raise OSError(28, 'No space left on device')

        import getzilla.source_shadow as shadow_module
        with mock.patch.object(shadow_module.os, 'write', side_effect=full), self.assertRaises(OSError):
            materialize_shadow(self.receipt, self.store, self.base / 'shadow', self.source)
        del real_write
        self.assertFalse((self.base / 'out').exists())


if __name__ == '__main__':
    unittest.main()
