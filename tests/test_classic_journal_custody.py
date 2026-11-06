"""Owned public fixtures for the classic journal read boundary."""
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import metrics_journal as journal
from getzilla.route_metrics import summarize
from getzilla.route_metrics import counters


class ClassicJournalCustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.old = Path.cwd()
        self.addCleanup(os.chdir, self.old)
        os.chdir(self.root)
        (self.root / '.getzilla/runtime').mkdir(parents=True, mode=0o700)
        self.path = self.root / journal.PATH
        self.path.write_text(json.dumps({'at': '2026-11-06T00:00:00Z', 'event': 'route', 'route_id': 'public-a'}) + '\n')
        self.path.chmod(0o600)

    def test_private_legacy_journal_retains_observations(self):
        rows = journal.load(self.root)
        self.assertEqual([r['route_id'] for r in rows], ['public-a'])

    def test_public_journal_is_unknown_before_any_bytes(self):
        self.path.chmod(0o644)
        with patch.object(journal.os, 'read', wraps=os.read) as read:
            rows = journal.load(self.root)
        self.assertFalse(getattr(rows, 'available', True))
        self.assertEqual(read.call_count, 0)
        self.assertIsNone(summarize(rows)['routes'])

    def test_existing_regular_read_entrypoint_enforces_same_boundary(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            with journal.regular(self.root, journal.PATH):
                self.fail('unsafe journal admitted')

    def test_private_runtime_required_before_any_bytes(self):
        self.path.parent.chmod(0o755)
        with patch.object(journal.os, 'read', wraps=os.read) as read:
            rows = journal.load(self.root)
        self.assertFalse(getattr(rows, 'available', True))
        self.assertEqual(read.call_count, 0)

    def test_other_cwd_cannot_admit_a_named_root(self):
        os.chdir(self.old)
        with patch.object(journal.os, 'read', wraps=os.read) as read:
            rows = journal.load(self.root)
        self.assertFalse(getattr(rows, 'available', True))
        self.assertEqual(read.call_count, 0)

    def test_missing_journal_is_unknown_not_empty_census(self):
        self.path.unlink()
        self.assertIsNone(summarize(journal.load(self.root))['routes'])

    def test_hardlink_is_unavailable(self):
        os.link(self.path, self.path.with_name('other'))
        self.assertFalse(getattr(journal.load(self.root), 'available', True))

    def test_symlink_and_fifo_are_rejected_before_read(self):
        for kind in ('symlink', 'fifo'):
            with self.subTest(kind=kind):
                self.path.unlink()
                if kind == 'symlink':
                    self.path.symlink_to('missing-public-canary')
                else:
                    os.mkfifo(self.path, 0o600)
                with patch.object(journal.os, 'read', wraps=os.read) as read:
                    self.assertFalse(journal.load(self.root).available)
                self.assertEqual(read.call_count, 0)

    def test_mutation_during_read_discards_all_observations(self):
        original = os.read
        seen = []

        def mutate(descriptor, maximum):
            seen.append(descriptor)
            raw = original(descriptor, maximum)
            if len(seen) == 1:
                with self.path.open('ab') as output:
                    output.write(b'changed')
            return raw

        with patch.object(journal.os, 'read', side_effect=mutate):
            self.assertFalse(journal.load(self.root).available)
        with self.assertRaises(OSError):
            os.fstat(seen[0])

    def test_unrelated_reused_descriptor_is_not_closed(self):
        from getzilla.trace_storage import LocalRead
        other = self.root / 'public-other'
        other.write_text('public fixture')
        reader = LocalRead(self.root)
        _, (descriptor,) = reader.git_location()
        os.close(descriptor)
        replacement = os.open(other, os.O_RDONLY)
        try:
            self.assertEqual(replacement, descriptor)
            reader.close()
            self.assertEqual(os.read(replacement, 64), b'public fixture')
        finally:
            os.close(replacement)

    def test_cwd_switch_restore_during_leaf_open_still_reads_a(self):
        other = self.root / 'other'
        other.mkdir()
        original = os.open

        def switch(name, flags, *args, **kwargs):
            if name == 'metrics.jsonl':
                os.chdir(other)
                try:
                    return original(name, flags, *args, **kwargs)
                finally:
                    os.chdir(self.root)
            return original(name, flags, *args, **kwargs)

        with patch.object(os, 'open', side_effect=switch):
            self.assertEqual(journal.load(self.root)[0]['route_id'], 'public-a')

    def test_foreign_owner_metadata_refuses_before_read(self):
        from getzilla import trace_storage
        original = os.fstat

        def foreign(descriptor):
            info = original(descriptor)
            if stat.S_ISREG(info.st_mode):
                values = list(info)
                values[4] = info.st_uid + 1
                return os.stat_result(values)
            return info

        import stat
        with patch.object(trace_storage.os, 'fstat', side_effect=foreign), patch.object(os, 'read', wraps=os.read) as read:
            self.assertFalse(journal.load(self.root).available)
        self.assertEqual(read.call_count, 0)

    def test_live_reader_cross_thread_and_closed_refuse(self):
        from getzilla.trace_storage import LocalRead, ReadUnavailable
        with LocalRead(self.root) as reader:
            result = []

            def use():
                try:
                    reader.read(journal.PATH, journal.MAX_BYTES)
                except ReadUnavailable:
                    result.append('unavailable')

            worker = threading.Thread(target=use)
            worker.start()
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result, ['unavailable'])
        with self.assertRaises(ReadUnavailable):
            reader.read(journal.PATH, journal.MAX_BYTES)

    def test_reused_numeric_thread_id_does_not_extend_reader_lifetime(self):
        from getzilla import trace_storage
        with trace_storage.LocalRead(self.root) as reader:
            owner_ident = threading.get_ident()
            result = []
            ready, release, finished = threading.Event(), threading.Event(), threading.Event()

            def use():
                actual_thread = threading.current_thread()
                proxy = SimpleNamespace(get_ident=lambda: owner_ident, current_thread=lambda: actual_thread)
                try:
                    with patch.object(trace_storage, 'threading', proxy):
                        ready.set()
                        if not release.wait(2):
                            result.append('scheduler-timeout')
                            return
                        try:
                            reader.read(journal.PATH, journal.MAX_BYTES)
                        except trace_storage.ReadUnavailable:
                            result.append('unavailable')
                        else:
                            result.append('admitted')
                finally:
                    finished.set()

            worker = threading.Thread(target=use)
            worker.start()
            ready_seen = ready.wait(2)
            join_error = None
            try:
                if ready_seen:
                    try:
                        worker.join(0.05)  # Exercise main join while the worker's patch is active.
                    except RuntimeError:
                        join_error = 'RuntimeError'
            finally:
                release.set()
                finished_seen = finished.wait(2)
                if finished_seen:
                    worker.join(2)
            self.assertTrue(ready_seen)
            self.assertTrue(finished_seen)
            self.assertFalse(worker.is_alive())
            self.assertIsNone(join_error)
            self.assertEqual(result, ['unavailable'])

    def test_reader_cannot_be_relabelled_as_another_project(self):
        from getzilla.trace_storage import LocalRead
        other = self.root / 'other'
        other.mkdir()
        with LocalRead(self.root) as reader, patch.object(os, 'read', wraps=os.read) as read:
            self.assertFalse(journal.load(other, reader=reader).available)
        self.assertEqual(read.call_count, 0)

    def test_same_reader_counter_and_source_legacy_positives(self):
        from getzilla.trace_storage import LocalRead
        counter = self.path.with_name('path-hints.json')
        counter.write_text('{"hinted":4}')
        counter.chmod(0o600)
        subprocess.run(['git', 'init', '-q', '-b', 'work'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '--allow-empty', '-qm', 'public'], cwd=self.root, check=True)
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root).decode().strip()
        with LocalRead(self.root) as reader:
            self.assertEqual(counters(self.root, reader=reader), {'path_hints': {'hinted': 4}})
            self.assertEqual(journal.inventory(self.root, head, head, reader=reader)['commits'], 0)
            reader.check()

    def test_actual_git_child_uses_held_root_during_cwd_switch_restore(self):
        from getzilla.trace_storage import LocalRead
        from getzilla import project_ingestion
        subprocess.run(['git', 'init', '-q', '-b', 'work'], cwd=self.root, check=True)
        other = self.root / 'public-b'
        other.mkdir()
        real = subprocess.run
        observed = []

        def switch(command, **kwargs):
            os.chdir(other)
            try:
                result = real(command, **kwargs)
                observed.append(result.returncode)
                return result
            finally:
                os.chdir(self.root)

        with LocalRead(self.root) as reader:
            location, descriptors = reader.git_location()
            with patch.object(project_ingestion.subprocess, 'run', side_effect=switch):
                result = project_ingestion._git(location, 'rev-parse', '--is-inside-work-tree',
                                                check=False, _pass_fds=descriptors)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), b'true')
            self.assertEqual(observed, [0])
            reader.check()

    def test_replacement_after_read_is_unavailable_and_preserves_foreign_leaf(self):
        original = os.read
        replacement = self.path.with_name('public-replacement')
        replacement.write_bytes(b'public-foreign-canary')
        replacement.chmod(0o600)
        inode = replacement.stat().st_ino
        replaced = False

        def replace(descriptor, maximum):
            nonlocal replaced
            raw = original(descriptor, maximum)
            if not replaced:
                replaced = True
                os.replace(replacement, self.path)
            return raw

        with patch.object(os, 'read', side_effect=replace):
            self.assertFalse(journal.load(self.root).available)
        self.assertEqual(self.path.stat().st_ino, inode)
        self.assertEqual(self.path.read_bytes(), b'public-foreign-canary')

    def test_real_cli_unknown_has_no_canary_and_private_positive(self):
        cli = Path(__file__).resolve().parents[1] / 'scripts/getzilla_report.py'
        command = [sys.executable, str(cli), '--json', '--since', 'all']
        positive = json.loads(subprocess.check_output(command, cwd=self.root))
        self.assertEqual(positive['routes'][0]['route_id'], 'public-a')
        self.path.chmod(0o644)
        raw = subprocess.check_output(command, cwd=self.root)
        self.assertNotIn(b'public-a', raw)
        unknown = json.loads(raw)
        self.assertIsNone(unknown['routes'])
        self.assertIsNone(unknown['counters'])

    def test_missing_counter_cannot_be_printed_as_zero(self):
        counter = self.path.with_name('parallel-guard.json')
        counter.write_text('{"chain":2}')
        counter.chmod(0o600)
        cli = ROOT / 'scripts/getzilla_report.py'
        text = subprocess.check_output([sys.executable, str(cli), '--since', 'all'], cwd=self.root).decode()
        self.assertNotIn('0 refused', text)
        data = json.loads(subprocess.check_output([sys.executable, str(cli), '--since', 'all', '--json'], cwd=self.root))
        self.assertIsNotNone(data.get('counter_observations'))
        self.assertFalse(data['counter_observations']['complete'])
        self.assertEqual(data['counter_observations']['gaps'], ['counter observation unavailable: path_hints'])
