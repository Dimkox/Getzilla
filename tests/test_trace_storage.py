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
            anchor.write('.getzilla/runtime/active-route.json', b'{"fixture":"closed"}\n')
        self.assertEqual(self.parent.stat().st_mode & 0o777, 0o775)
        self.assertEqual((self.root / '.getzilla/runtime/active-route.json').stat().st_mode & 0o777, 0o600)

    def test_snapshot_append_preserves_foreign_replacement_at_actual_write(self):
        from getzilla.trace_storage import native_root
        leaf = self.journal.with_name('active-route.json')
        leaf.write_bytes(b'{}\n')
        leaf.chmod(0o600)
        real_write, cuts = os.write, []
        def replaced(descriptor,raw):
            if not cuts:
                other = leaf.with_name('foreign-replacement')
                other.write_bytes(b'{"foreign_fixture":true}\n')
                other.chmod(0o600)
                os.replace(other,leaf)
                cuts.append(leaf.stat().st_ino)
            return real_write(descriptor,raw)
        with native_root(self.root) as anchor,mock.patch('os.write',side_effect=replaced):
            with self.assertRaises((ValueError,OSError)):
                anchor.write('.getzilla/runtime/active-route.json',b'{"new_fixture":true}\n')
        self.assertEqual(leaf.read_bytes(),b'{"foreign_fixture":true}\n')
        self.assertEqual(leaf.stat().st_ino,cuts[0])

    def test_native_marker_never_removes_existing_foreign_named_leaf(self):
        from getzilla.trace_storage import native_root,native_lock,held_guard
        leaf = self.journal.with_name('.task-transition.lock')
        leaf.write_bytes(b'foreign-public-marker\n')
        leaf.chmod(0o600)
        original = leaf.stat().st_ino
        with native_root(self.root) as anchor:
            with native_lock(anchor,'task-transition',0.2):
                held_guard(anchor,'task-transition')
        self.assertTrue(leaf.exists(),'native marker cleanup removed a foreign leaf')
        self.assertEqual(leaf.read_bytes(),b'foreign-public-marker\n')
        self.assertEqual(leaf.stat().st_ino,original)

    def test_anonymous_native_marker_keeps_actual_legacy_guard_contention(self):
        from getzilla.trace_storage import native_root,native_lock
        marker = self.journal.with_name('.task-transition.lock')
        self.assertFalse(marker.exists())
        script = self.root/'legacy-guard-fixture.py'
        script.write_text('import sys\nfrom pathlib import Path\n'
                          'sys.path.insert(0,sys.argv[2])\n'
                          'from getzilla import state\n'
                          'try:\n'
                          '    with state.runtime_lock(Path(sys.argv[1]),"task-transition",timeout=0.05):\n'
                          '        raise SystemExit(3)\n'
                          'except TimeoutError:\n'
                          '    raise SystemExit(0)\n')
        project = Path(__file__).resolve().parents[1]
        with native_root(self.root) as anchor:
            with native_lock(anchor,'task-transition',0.5):
                child = subprocess.run([sys.executable,str(script),str(self.root),str(project/'.getzilla')],
                                       capture_output=True,timeout=2,check=False)
                self.assertEqual(child.returncode,0,child.stderr)
                self.assertFalse(marker.exists())
        self.assertFalse(marker.exists())

    def test_native_unlink_is_unsupported_before_any_leaf_effect(self):
        from getzilla.trace_storage import native_root
        from getzilla import fsx
        leaf = self.journal.with_name('active-change.json')
        leaf.write_bytes(b'{}\n')
        leaf.chmod(0o600)
        with native_root(self.root) as anchor,mock.patch.object(fsx,'unlink_at',side_effect=AssertionError('pathname deletion')):
            with self.assertRaisesRegex(ValueError,'native_trace_unlink_unsupported'):
                anchor.unlink('.getzilla/runtime/active-change.json')
        self.assertEqual(leaf.read_bytes(),b'{}\n')

    def test_native_snapshots_and_later_ordinary_updates_keep_same_canonical_object(self):
        from getzilla.trace_storage import native_root
        from getzilla import state
        relative = '.getzilla/runtime/routes/'+'a'*12+'.json'
        first = {'route_id':'a'*12,'task':'fixture','status':'routed'}
        second = {**first,'status':'fixture-second'}
        third = {**first,'status':'fixture-third'}
        with native_root(self.root) as anchor:
            anchor.write(relative,json.dumps(first).encode())
            identity = (self.root/relative).stat().st_ino
            prefix = (self.root/relative).read_bytes()
            anchor.write(relative,json.dumps(second).encode())
            self.assertEqual(state.canonical_route(self.root,'a'*12,anchor=anchor),second)
        self.assertEqual(state.canonical_route(self.root,'a'*12),second)
        physical = (self.root/relative).read_bytes()
        self.assertTrue(physical.startswith(prefix))
        state.durable_json(self.root,self.root/relative,third)
        self.assertEqual((self.root/relative).stat().st_ino,identity)
        self.assertTrue((self.root/relative).read_bytes().startswith(physical))
        self.assertEqual(state.canonical_route(self.root,'a'*12),third)

    def test_identical_native_pointer_retries_do_not_consume_physical_history(self):
        from getzilla.trace_storage import native_root
        leaf = self.journal.with_name('active-change.json')
        payload = b'{"fixture":"same immutable bytes"}\n'
        with native_root(self.root) as anchor:
            anchor.write('.getzilla/runtime/active-change.json',payload)
            original = leaf.read_bytes()
            for _ in range(12):
                anchor.write('.getzilla/runtime/active-change.json',payload)
            self.assertEqual(leaf.read_bytes(),original)
            self.assertEqual(anchor.read('.getzilla/runtime/active-change.json'),payload)

    def test_partial_snapshot_is_retained_but_never_read_as_committed_metadata(self):
        from getzilla.trace_storage import native_root
        leaf = self.journal.with_name('active-route.json')
        original = b'{"fixture":"original"}\n'
        leaf.write_bytes(original)
        leaf.chmod(0o600)
        identity = leaf.stat().st_ino
        real_sync, calls = os.fsync, []
        def interrupted(descriptor):
            if os.fstat(descriptor).st_ino == identity:
                calls.append(True)
                raise OSError('synthetic prepared-frame durability failure')
            return real_sync(descriptor)
        with native_root(self.root) as anchor:
            with mock.patch('os.fsync',side_effect=interrupted):
                with self.assertRaises(OSError):
                    anchor.write('.getzilla/runtime/active-route.json',b'{"fixture":"new"}\n')
            self.assertEqual(calls,[True])
            self.assertEqual(leaf.stat().st_ino,identity)
            self.assertTrue(leaf.read_bytes().startswith(original))
            with self.assertRaisesRegex(ValueError,'native_state_snapshot_invalid'):
                anchor.read('.getzilla/runtime/active-route.json')
            before = leaf.read_bytes()
            with self.assertRaisesRegex(ValueError,'native_state_snapshot_invalid'):
                anchor.write('.getzilla/runtime/active-route.json',b'{"fixture":"retry"}\n')
            self.assertEqual(leaf.read_bytes(),before)

    def test_replacement_between_metadata_selection_and_open_is_never_written(self):
        from getzilla.trace_storage import native_root
        from getzilla import fsx
        leaf = self.journal.with_name('active-route.json')
        leaf.write_bytes(b'{}\n')
        leaf.chmod(0o600)
        real_open, cuts = fsx.open_at, []
        def replaced(parent,name,flags,*args,**kwargs):
            if name == leaf.name and flags & os.O_RDWR and not cuts:
                other = leaf.with_name('foreign-before-open')
                other.write_bytes(b'{"foreign_fixture":true}\n')
                other.chmod(0o600)
                os.replace(other,leaf)
                cuts.append(leaf.stat().st_ino)
            return real_open(parent,name,flags,*args,**kwargs)
        with native_root(self.root) as anchor,mock.patch.object(fsx,'open_at',side_effect=replaced):
            with self.assertRaisesRegex(ValueError,'native_state_snapshot_changed'):
                anchor.write('.getzilla/runtime/active-route.json',b'{"new_fixture":true}\n')
        self.assertEqual(leaf.read_bytes(),b'{"foreign_fixture":true}\n')
        self.assertEqual(leaf.stat().st_ino,cuts[0])

    def test_changed_restored_metadata_during_snapshot_read_refuses_before_append(self):
        from getzilla.trace_storage import native_root
        leaf = self.journal.with_name('active-route.json')
        original = b'{"fixture":"original"}\n'
        leaf.write_bytes(original)
        leaf.chmod(0o600)
        inode = leaf.stat().st_ino
        real_read,cuts = os.read,[]
        def restored(descriptor,size):
            raw = real_read(descriptor,size)
            if os.fstat(descriptor).st_ino == inode and raw and not cuts:
                leaf.write_bytes(b'{}\n')
                leaf.write_bytes(original)
                cuts.append(True)
            return raw
        with native_root(self.root) as anchor,mock.patch('os.read',side_effect=restored):
            with self.assertRaisesRegex(ValueError,'native_state_snapshot_changed'):
                anchor.write('.getzilla/runtime/active-route.json',b'{"new_fixture":true}\n')
        self.assertEqual(cuts,[True])
        self.assertEqual(leaf.read_bytes(),original)

    def test_snapshot_limit_and_hardlink_refuse_before_mutating_original(self):
        from getzilla.trace_storage import native_root
        leaf = self.journal.with_name('active-change.json')
        original = b'{"fixture":"'+b'x'*3800+b'"}\n'
        leaf.write_bytes(original)
        leaf.chmod(0o600)
        with native_root(self.root) as anchor:
            with self.assertRaisesRegex(ValueError,'native_state_snapshot_limit'):
                anchor.write('.getzilla/runtime/active-change.json',b'{}\n')
            self.assertEqual(leaf.read_bytes(),original)
            os.link(leaf,leaf.with_name('hardlinked-private-fixture'))
            with mock.patch('os.read',side_effect=AssertionError('hardlink bytes read')):
                with self.assertRaises(ValueError):
                    anchor.write('.getzilla/runtime/active-change.json',b'{}\n')
        self.assertEqual(leaf.read_bytes(),original)

    def test_ordinary_probe_preserves_legacy_0644_but_never_writes_framed_0644(self):
        from getzilla import state
        from getzilla.trace_storage import native_root
        leaf = self.journal.with_name('active-route.json')
        leaf.write_bytes(b'{"fixture":"legacy"}\n')
        leaf.chmod(0o644)
        state.durable_json(self.root,leaf,{'fixture':'ordinary update'})
        self.assertEqual(json.loads(leaf.read_bytes()),{'fixture':'ordinary update'})
        with native_root(self.root) as anchor:
            anchor.write('.getzilla/runtime/active-route.json',b'{"fixture":"native"}\n')
        framed = leaf.read_bytes()
        leaf.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'native_state_snapshot_changed'):
            state.durable_json(self.root,leaf,{'fixture':'must refuse'})
        self.assertEqual(leaf.read_bytes(),framed)
        for malformed in (b'{}\nGETZILLA_STATE_SNAPSHOT_V',b'{"a":1,"a":2}',b'broken'):
            leaf.write_bytes(malformed)
            with self.assertRaises(ValueError):
                state.durable_json(self.root,leaf,{'fixture':'must refuse'})
            self.assertEqual(leaf.read_bytes(),malformed)

    def test_workflow_active_change_reader_decodes_same_private_object(self):
        from getzilla.trace_storage import native_root
        from getzilla.workflow_artifacts import load_runtime_authority
        original = {'change_id':'original','path':'.getzilla/runtime/changes/original'}
        latest = {'change_id':'latest','path':'.getzilla/runtime/changes/latest'}
        with native_root(self.root) as anchor:
            anchor.write('.getzilla/runtime/active-change.json',json.dumps(original).encode())
            anchor.write('.getzilla/runtime/active-change.json',json.dumps(latest).encode())
        leaf = self.journal.with_name('active-change.json')
        before = leaf.read_bytes()
        self.assertEqual(load_runtime_authority(self.root,'change'),latest)
        self.assertEqual(leaf.read_bytes(),before)

    def test_absent_posix_owner_capability_preserves_only_unframed_legacy_writes(self):
        from getzilla import state,fsx
        from getzilla.trace_storage import native_root
        leaf = self.journal.with_name('active-route.json')
        leaf.write_bytes(b'{"fixture":"legacy"}\n')
        leaf.chmod(0o600)
        with mock.patch.object(fsx,'effective_uid',return_value=None):
            state.durable_json(self.root,leaf,{'fixture':'ordinary update'})
        self.assertEqual(json.loads(leaf.read_bytes()),{'fixture':'ordinary update'})
        with native_root(self.root) as anchor:
            anchor.write('.getzilla/runtime/active-route.json',b'{"fixture":"native"}\n')
        before = leaf.read_bytes()
        with mock.patch.object(fsx,'effective_uid',return_value=None),mock.patch.object(fsx,'replace_at',side_effect=AssertionError('unsupported framed replacement')):
            with self.assertRaisesRegex(ValueError,'native_state_snapshot_platform_unsupported'):
                state.durable_json(self.root,leaf,{'fixture':'must refuse'})
        self.assertEqual(leaf.read_bytes(),before)
        damaged = b'{}\nGETZILLA_STATE_SNAPSHOT_V'
        leaf.write_bytes(damaged)
        with mock.patch.object(fsx,'effective_uid',return_value=None),mock.patch.object(fsx,'replace_at',side_effect=AssertionError('damaged framed replacement')):
            with self.assertRaises(ValueError):
                state.durable_json(self.root,leaf,{'fixture':'must refuse'})
        self.assertEqual(leaf.read_bytes(),damaged)

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
        original = self.journal.with_name('active-route.json')
        original.write_bytes(b'{"fixture":"original"}\n')
        original.chmod(0o600)
        with native_root(self.root) as anchor:
            moved = self.parent.with_name('moved')
            self.parent.rename(moved)
            foreign = self.root / '.getzilla/runtime'
            foreign.mkdir(parents=True)
            sentinel = foreign / 'metrics.jsonl'
            sentinel.write_bytes(b'FOREIGN_SENTINEL')
            self.assertEqual(anchor.read('.getzilla/runtime/metrics.jsonl'), b'original\n')
            anchor.write('.getzilla/runtime/active-route.json', b'{"fixture":"owned replacement"}\n')
            self.assertEqual(sentinel.read_bytes(), b'FOREIGN_SENTINEL')
            self.assertEqual(anchor.read('.getzilla/runtime/active-route.json'), b'{"fixture":"owned replacement"}\n')
            self.assertTrue((moved / 'project/.getzilla/runtime/active-route.json').read_bytes().startswith(b'{"fixture":"original"}\n'))
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

    def test_git_source_preserves_strict_graph_refusal_after_parent_rename(self):
        from getzilla.trace_storage import native_root
        before = os.umask(0o022)
        try:
            subprocess.run(['git', 'init', '-q'], cwd=self.root, check=True)
            subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.com',
                            '-c', 'maintenance.auto=false', 'commit', '--allow-empty', '-qm', 'fixture'],
                           cwd=self.root, check=True)
        finally:
            os.umask(before)
        with native_root(self.root) as anchor:
            expected = anchor.git_source()
            self.parent.rename(self.parent.with_name('moved'))
            self.root.mkdir(parents=True)
            with mock.patch('subprocess.Popen',side_effect=AssertionError('foreign Git child')):
                with self.assertRaisesRegex(ValueError,'native_trace_source_unavailable'):
                    anchor.git_source()
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
