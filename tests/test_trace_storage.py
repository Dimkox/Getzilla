"""The trace boundary pins the actual project CWD, never its writable parent."""
import os
import tempfile
import unittest
import json
import subprocess
from unittest import mock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))


class NativeStorageTests(unittest.TestCase):
    def setUp(self):
        self.saved = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.saved)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(os.fchdir, self.saved)
        self.parent = Path(self.temp.name) / 'shared'
        self.parent.mkdir(mode=0o775)
        self.parent.chmod(0o775)
        self.root = self.parent / 'project'
        (self.root / '.getzilla/runtime').mkdir(parents=True)
        self.root.chmod(0o755)
        (self.root / '.getzilla').chmod(0o755)
        (self.root / '.getzilla/runtime').chmod(0o700)
        self.journal = self.root / '.getzilla/runtime/metrics.jsonl'
        self.journal.write_bytes(b'original\n')
        self.journal.chmod(0o600)
        os.chdir(self.root)

    def test_shared_parent_does_not_supply_descendant_authority(self):
        from getzilla.trace_storage import native_root
        with native_root(self.root) as anchor:
            self.assertEqual(anchor.read('.getzilla/runtime/metrics.jsonl'), b'original\n')
            anchor.write('.getzilla/runtime/result.json', b'closed\n')
        self.assertEqual(self.parent.stat().st_mode & 0o777, 0o775)
        self.assertEqual((self.root / '.getzilla/runtime/result.json').stat().st_mode & 0o777, 0o600)

    def test_public_source_uses_exact_frozen_modes_before_any_bytes(self):
        from getzilla.trace_storage import native_root
        path = self.root/'source.txt'
        path.write_bytes(b'owned-source')
        with native_root(self.root) as anchor:
            for mode in (0o444,0o644,0o555,0o755):
                path.chmod(mode)
                self.assertEqual(anchor.read('source.txt', public_source=True), b'owned-source')
            for mode in (0o600,0o640,0o744,0o664):
                path.chmod(mode)
                with mock.patch('os.read', side_effect=AssertionError('private bytes read')):
                    with self.assertRaises(ValueError):
                        anchor.read('source.txt', public_source=True)
            path.chmod(0o644)
            os.link(path, path.with_name('source-alias.txt'))
            with mock.patch('os.read', side_effect=AssertionError('hardlinked bytes read')):
                with self.assertRaises(ValueError):
                    anchor.read('source.txt', public_source=True)

    def test_public_source_mode_loss_during_chunked_read_refuses(self):
        from getzilla.trace_storage import native_root
        path = self.root/'source.txt'
        path.write_bytes(b'x'*100_000)
        path.chmod(0o644)
        original, calls = os.read, []
        def changing(descriptor, size):
            raw = original(descriptor,size)
            calls.append(len(raw))
            if len(calls) == 1:
                path.chmod(0o600)
            return raw
        with native_root(self.root) as anchor:
            with mock.patch('os.read', side_effect=changing):
                with self.assertRaises(ValueError):
                    anchor.read('source.txt', public_source=True)
        self.assertEqual(calls, [65536])

    def test_root_descriptor_and_metadata_stay_on_actual_resource_after_parent_move(self):
        from getzilla.trace_storage import native_root
        expected = self.journal.stat()
        with native_root(self.root) as anchor:
            descriptor = anchor.duplicate_root_fd()
            try:
                self.parent.rename(self.parent.with_name('moved'))
                (self.root/'.getzilla/runtime').mkdir(parents=True)
                (self.root/'.getzilla/runtime/metrics.jsonl').write_bytes(b'foreign')
                info = anchor.stat('.getzilla/runtime/metrics.jsonl')
                self.assertEqual((info.st_dev,info.st_ino),(expected.st_dev,expected.st_ino))
                self.assertEqual((anchor.root_info().st_dev,anchor.root_info().st_ino),anchor.identity)
                opened = os.stat('.getzilla/runtime/metrics.jsonl',dir_fd=descriptor,follow_symlinks=False)
                self.assertEqual((opened.st_dev,opened.st_ino),(expected.st_dev,expected.st_ino))
            finally:
                os.close(descriptor)

    def test_actual_privacy_consumer_uses_the_cwd_anchor_under_shared_parent(self):
        from getzilla.observation_privacy import load_local, revalidate_local
        self.journal.write_bytes(b'{"event":"route","route_id":"PRIVATE_SENTINEL"}\n')
        source = load_local(self.root)
        self.assertEqual(source['access'], 'local_owner')
        self.assertEqual(source['events'], [{'event': 'route'}])
        self.assertTrue(revalidate_local(self.root, source))
        os.chdir(self.parent)
        denied = load_local(self.root)
        self.assertEqual(denied['events'], [])
        self.assertIsNone(denied['input_digest'])
        self.assertFalse(revalidate_local(self.root, source))

    def test_replaced_outer_parent_cannot_redirect_pinned_reads_or_replace(self):
        from getzilla.trace_storage import native_root
        with native_root(self.root) as anchor:
            moved = self.parent.with_name('moved')
            self.parent.rename(moved)
            foreign = self.root / '.getzilla/runtime'
            foreign.mkdir(parents=True)
            sentinel = foreign / 'metrics.jsonl'
            sentinel.write_bytes(b'FOREIGN_SENTINEL')
            self.assertEqual(anchor.read('.getzilla/runtime/metrics.jsonl'), b'original\n')
            anchor.write('.getzilla/runtime/metrics.jsonl', b'owned replacement\n')
            self.assertEqual(sentinel.read_bytes(), b'FOREIGN_SENTINEL')
            self.assertEqual((moved / 'project/.getzilla/runtime/metrics.jsonl').read_bytes(), b'owned replacement\n')
            with self.assertRaises((ValueError, OSError)):
                with native_root(self.root):
                    self.fail('a fresh mismatched hint must refuse')

    def test_root_mode_subdirectory_and_serialized_handle_cannot_qualify(self):
        from getzilla.trace_storage import native_root
        self.root.chmod(0o775)
        with self.assertRaises(ValueError):
            with native_root(self.root):
                pass
        self.root.chmod(0o755)
        os.chdir('.getzilla')
        with self.assertRaises(ValueError):
            with native_root(self.root):
                pass
        with self.assertRaises((TypeError, ValueError)):
            with native_root({'fd': self.saved, 'uid': os.getuid()}):
                pass

    def test_changed_descendant_and_file_types_refuse(self):
        from getzilla.trace_storage import native_root
        with native_root(self.root) as anchor:
            for mode in (0o644, 0o700):
                self.journal.chmod(mode)
                with self.assertRaises(ValueError):
                    anchor.read('.getzilla/runtime/metrics.jsonl')
            self.journal.chmod(0o600)
            self.journal.unlink()
            target = self.root / 'target'
            target.write_bytes(b'private')
            target.chmod(0o600)
            self.journal.symlink_to(target)
            with self.assertRaises((ValueError, OSError)):
                anchor.read('.getzilla/runtime/metrics.jsonl')
            self.journal.unlink()
            os.link(target, self.journal)
            with self.assertRaises(ValueError):
                anchor.read('.getzilla/runtime/metrics.jsonl')
            self.journal.unlink()
            self.journal.write_bytes(b'owned')
            self.journal.chmod(0o600)
            (self.root / '.getzilla/runtime').chmod(0o755)
            with self.assertRaises(ValueError):
                anchor.write('.getzilla/runtime/result.json', b'must refuse')

    def test_canonical_cas_uses_one_anchor_without_path_helpers(self):
        from getzilla import state
        from getzilla.trace_storage import native_root
        route_id = 'a'*12
        relative = f'.getzilla/runtime/routes/{route_id}.json'
        route = {'route_id': route_id, 'task': 'controlled fixture', 'status': 'routed'}
        with native_root(self.root) as anchor:
            anchor.write(relative, json.dumps(route).encode())
            with mock.patch('getzilla.package_status.read_package_file', side_effect=AssertionError('path fallback')):
                self.assertEqual(state.canonical_route(self.root, route_id, anchor=anchor), route)
                with state.task_transition(self.root, anchor=anchor):
                    changed = {**route, 'status': 'fixture-only'}
                    result = state._commit_route(self.root, changed, expected=route, anchor=anchor)
                self.assertEqual(result, changed)
                self.assertEqual(json.loads(anchor.read(relative)), changed)

    def test_canonical_cas_after_parent_replacement_preserves_foreign_root(self):
        from getzilla import state
        from getzilla.trace_storage import native_root
        route_id = 'a'*12
        relative = f'.getzilla/runtime/routes/{route_id}.json'
        route = {'route_id': route_id, 'task': 'controlled fixture', 'status': 'routed'}
        with native_root(self.root) as anchor:
            anchor.write(relative, json.dumps(route).encode())
            moved = self.parent.with_name('moved')
            self.parent.rename(moved)
            foreign = self.root / '.getzilla/runtime/routes'
            foreign.mkdir(parents=True)
            sentinel = foreign / (route_id + '.json')
            sentinel.write_bytes(b'FOREIGN_CANONICAL_SENTINEL')
            with mock.patch('pathlib.Path.exists', side_effect=AssertionError('path exists fallback')):
                with state.task_transition(self.root, anchor=anchor):
                    result = state._commit_route(self.root, {**route, 'status': 'fixture-only'}, expected=route, anchor=anchor)
            self.assertEqual(result['status'], 'fixture-only')
            self.assertEqual(sentinel.read_bytes(), b'FOREIGN_CANONICAL_SENTINEL')
            self.assertEqual(json.loads(anchor.read(relative))['status'], 'fixture-only')

    def test_git_source_uses_actual_inherited_cwd_after_parent_rename(self):
        from getzilla.trace_storage import native_root
        subprocess.run(['git', 'init', '-q'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.com',
                        '-c', 'maintenance.auto=false', 'commit', '--allow-empty', '-qm', 'fixture'],
                       cwd=self.root, check=True)
        with native_root(self.root) as anchor:
            expected = anchor.git_source()
            self.parent.rename(self.parent.with_name('moved'))
            self.root.mkdir(parents=True)
            self.assertEqual(anchor.git_source(), expected)
            self.assertEqual(set(expected), {'head', 'tree'})
            self.assertTrue(all(len(value) in {40, 64} for value in expected.values()))
            os.chdir(self.root)
            with self.assertRaises(ValueError):
                anchor.git_source()

    def test_descendant_swap_during_read_refuses_before_return(self):
        from getzilla.trace_storage import native_root
        old_read = os.read
        changed = []
        with native_root(self.root) as anchor:
            def swapping(descriptor, size):
                raw = old_read(descriptor, size)
                if raw and not changed:
                    changed.append(True)
                    runtime = self.root / '.getzilla/runtime'
                    runtime.rename(runtime.with_name('old-runtime'))
                    runtime.mkdir(mode=0o700)
                    path = runtime / 'metrics.jsonl'
                    path.write_bytes(b'FOREIGN_SENTINEL')
                    path.chmod(0o600)
                return raw
            with mock.patch('os.read', side_effect=swapping), self.assertRaises(ValueError):
                anchor.read('.getzilla/runtime/metrics.jsonl')
            self.assertEqual(changed, [True])
            self.assertEqual(self.journal.read_bytes(), b'FOREIGN_SENTINEL')

    def test_anchored_cas_rejects_an_actual_stale_expected_record(self):
        from getzilla import state
        from getzilla.trace_storage import native_root
        route_id = 'a'*12
        relative = f'.getzilla/runtime/routes/{route_id}.json'
        route = {'route_id': route_id, 'task': 'controlled fixture', 'status': 'routed'}
        with native_root(self.root) as anchor:
            anchor.write(relative, json.dumps(route).encode())
            first = state._commit_route(self.root, {**route, 'status': 'first-cut'}, expected=route, anchor=anchor)
            with self.assertRaises(ValueError):
                state._commit_route(self.root, {**route, 'status': 'stale-overwrite'}, expected=route, anchor=anchor)
            self.assertEqual(state.canonical_route(self.root, route_id, anchor=anchor), first)

    def test_an_anchor_cannot_be_relabelled_as_another_project_argument(self):
        from getzilla import state
        from getzilla.trace_storage import native_root
        route_id = 'a'*12
        route = {'route_id': route_id, 'task': 'controlled fixture'}
        with native_root(self.root) as anchor:
            anchor.write(f'.getzilla/runtime/routes/{route_id}.json', json.dumps(route).encode())
            other = self.root.with_name('other-project')
            other.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                state.canonical_route(other, route_id, anchor=anchor)

    def test_legacy_journal_reader_refuses_before_reading_unqualified_bytes(self):
        from getzilla import metrics_journal
        self.journal.parent.chmod(0o755)
        with mock.patch('getzilla.metrics_journal.os.read', side_effect=AssertionError('unsafe mixed journal read')):
            result = metrics_journal.load(self.root)
        self.assertFalse(result.available)
        self.assertTrue(result.gaps)


if __name__ == '__main__':
    unittest.main()
