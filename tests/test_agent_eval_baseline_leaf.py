"""Public disposable baseline leaves must survive mutation-cut replacements."""
from __future__ import annotations

import os
import errno
import json
import hashlib
from pathlib import Path
import sys
import unittest
import subprocess
import select
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import agent_evals as ev  # noqa: E402
from tests import test_agent_evals as fixtures  # noqa: E402


@unittest.skipUnless(os.name == 'posix', 'baseline writes require descriptor-relative kernel locking')
class BaselineLeafTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AgentEvalTests('test_repeat_is_canonical_and_never_publishes_payload')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.baseline = self.fixture.baseline
        self.report = self.fixture.run_eval()

    def accept(self):
        return ev.accept_baseline(self.baseline, self.report, reason='Public inert control', scope='Owned fixture')

    def test_old_replace_mutation_cut_cannot_overwrite_a_foreign_leaf(self):
        foreign = b'public foreign replacement canary\n'
        original = ev.fsx.replace_at
        inserted = []
        def replace(parent, name, destination, target):
            if target == self.baseline.name:
                self.baseline.write_bytes(foreign)
                inserted.append(True)
            return original(parent, name, destination, target)
        with patch.object(ev.fsx, 'replace_at', side_effect=replace):
            try:
                self.accept()
            except ev.EvalError:
                pass
        if inserted:
            self.assertEqual(self.baseline.read_bytes(), foreign)
        else:
            self.assertEqual(ev.compare(self.report, self.baseline)['status'], 'pass')

    def test_old_unlink_mutation_cut_cannot_delete_a_foreign_leaf(self):
        foreign = b'public foreign cleanup canary\n'
        lock = self.baseline.with_name(self.baseline.name + '.lock')
        original = ev.fsx.unlink_at
        inserted = []
        def unlink(parent, name):
            if name == lock.name:
                replacement = self.fixture.root / 'replacement'
                replacement.write_bytes(foreign)
                replacement.replace(lock)
                inserted.append(True)
            return original(parent, name)
        with patch.object(ev.fsx, 'unlink_at', side_effect=unlink):
            self.accept()
        if inserted:
            self.assertTrue(lock.exists(), 'foreign replacement was unlinked')
            self.assertEqual(lock.read_bytes(), foreign)
        else:
            self.assertFalse(lock.exists(), 'new protocol must not create a pathname lock')

    def test_actual_descriptor_write_preserves_replacement_on_create_and_update(self):
        for existing, phase in ((False, 'prepare'), (True, 'prepare'), (False, 'commit'), (True, 'commit')):
            with self.subTest(existing=existing, phase=phase):
                self.baseline = self.fixture.root / (('update-' if existing else 'create-') + phase + '.json')
                if existing:
                    self.accept()
                foreign = b'public replacement at actual write cut\n'
                original = ev.os.write
                inserted = []
                def write(descriptor, data):
                    at_cut = phase == 'prepare' or bytes(data).startswith(b'{"commit":')
                    if not inserted and at_cut:
                        self.baseline.unlink()
                        self.baseline.write_bytes(foreign)
                        inserted.append(True)
                    return original(descriptor, data)
                with patch.object(ev.os, 'write', side_effect=write):
                    with self.assertRaises(ev.EvalError):
                        self.accept()
                self.assertTrue(inserted, 'the retained descriptor write cut must be exercised')
                self.assertEqual(self.baseline.read_bytes(), foreign)

    def test_cleanup_unlock_preserves_a_new_foreign_lock_name(self):
        original = ev.fsx.unlock_file
        lock = self.baseline.with_name(self.baseline.name + '.lock')
        inserted = []
        def unlock(descriptor):
            lock.write_bytes(b'foreign legacy lock canary\n')
            inserted.append(True)
            return original(descriptor)
        with patch.object(ev.fsx, 'unlock_file', side_effect=unlock), \
                patch.object(ev.fsx, 'unlink_at', wraps=ev.fsx.unlink_at) as unlink:
            self.accept()
        self.assertTrue(inserted)
        self.assertEqual(lock.read_bytes(), b'foreign legacy lock canary\n')
        unlink.assert_not_called()

    def test_v1_history_remains_readable_and_byte_preserved_before_append(self):
        first = self.accept()
        # Construct the V1 document from independently decoded physical entry bytes.
        entry = json.loads(self.baseline.read_bytes().split(b'\n')[1])
        self.assertEqual(entry['acceptance_digest'], first['baseline_id'])
        history = {'schema_version': 1, 'history': [entry]}
        legacy = (json.dumps(history, indent=2) + '\n').encode()
        self.baseline.write_bytes(legacy)
        self.assertEqual(ev.compare(self.report, self.baseline)['status'], 'pass')
        second = self.accept()
        self.assertTrue(self.baseline.read_bytes().startswith(legacy))
        stored = ev._baseline(self.baseline)
        self.assertEqual(len(stored['history']), 2)
        self.assertEqual(second['previous_digest'], first['baseline_id'])
        appended = self.baseline.read_bytes()[len(legacy):].splitlines()
        self.assertEqual(len(appended), 2)
        next_entry, marker = map(json.loads, appended)
        self.assertEqual(next_entry['previous_digest'], first['baseline_id'])
        self.assertEqual(marker, {'schema_version': 2, 'commit': second['baseline_id']})

    def test_partial_append_preserves_history_and_remains_explicitly_unavailable(self):
        self.accept()
        prefix = self.baseline.read_bytes()
        original = ev.os.write
        writes = []
        def interrupted(descriptor, data):
            if not writes:
                writes.append(True)
                return original(descriptor, data[:9])
            raise OSError(errno.ENOSPC, 'public fixture interruption')
        with patch.object(ev.os, 'write', side_effect=interrupted):
            with self.assertRaises(ev.EvalError):
                self.accept()
        partial = self.baseline.read_bytes()
        self.assertTrue(partial.startswith(prefix))
        self.assertGreater(len(partial), len(prefix))
        comparison = ev.compare(self.report, self.baseline)
        self.assertEqual(comparison['status'], 'incomparable')
        self.assertEqual(comparison['reason'], 'baseline_incomplete_append')
        with self.assertRaisesRegex(ev.EvalError, 'baseline_incomplete_append'):
            self.accept()
        self.assertEqual(self.baseline.read_bytes(), partial)

    def test_directory_kernel_lock_blocks_current_reader_and_writer(self):
        self.accept()
        directory = ev.fsx.open_dir(self.fixture.root)
        try:
            ev.fsx.lock_file(directory, blocking=False)
            with self.assertRaisesRegex(ev.EvalError, 'baseline_acceptance_busy'):
                self.accept()
            comparison = ev.compare(self.report, self.baseline)
            self.assertEqual(comparison['status'], 'incomparable')
            self.assertEqual(comparison['reason'], 'baseline_acceptance_busy')
        finally:
            ev.fsx.unlock_file(directory)
            ev.fsx.close_dir(directory)
        self.assertEqual(ev.compare(self.report, self.baseline)['status'], 'pass')

    def test_wire_has_independent_complete_frames_checksums_and_history(self):
        first = self.accept()
        second = self.accept()
        raw = self.baseline.read_bytes()
        self.assertTrue(raw.endswith(b'\n'))
        lines = [line for line in raw.split(b'\n') if line]
        self.assertEqual(len(lines), 5, 'one header and two prepared-entry/commit pairs')
        self.assertEqual(json.loads(lines[0]), {'schema_version': 2, 'history': []})
        previous = None
        for offset, accepted in ((1, first), (3, second)):
            entry, commit = json.loads(lines[offset]), json.loads(lines[offset + 1])
            payload = {key: value for key, value in entry.items() if key != 'acceptance_digest'}
            checksum = hashlib.sha256(json.dumps(payload, ensure_ascii=True, sort_keys=True,
                separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()
            self.assertEqual(entry['acceptance_digest'], checksum)
            self.assertEqual(entry['previous_digest'], previous)
            self.assertEqual(commit, {'schema_version': 2, 'commit': checksum})
            self.assertEqual(accepted['baseline_id'], checksum)
            previous = checksum
        self.assertEqual(ev.compare(self.report, self.baseline)['baseline_id'], second['baseline_id'])
        changed = list(lines)
        changed[-1] = json.dumps({'schema_version': 2, 'commit': '0' * 64}).encode()
        self.baseline.write_bytes(b'\n'.join(changed) + b'\n')
        self.assertEqual(ev.compare(self.report, self.baseline)['reason'], 'baseline_commit_mismatch')

    def test_prepare_fsync_failure_does_not_publish_a_committed_frame(self):
        self.accept()
        prefix = self.baseline.read_bytes()
        with patch.object(ev.os, 'fsync', side_effect=OSError(errno.EIO, 'public fsync refusal')):
            with self.assertRaisesRegex(ev.EvalError, 'baseline_write_unavailable'):
                self.accept()
        self.assertTrue(self.baseline.read_bytes().startswith(prefix))
        result = ev.compare(self.report, self.baseline)
        self.assertEqual(result['status'], 'incomparable')
        self.assertEqual(result['reason'], 'baseline_incomplete_append')

    def test_cancelled_partial_append_releases_kernel_lock_without_deleting_state(self):
        self.accept()
        prefix = self.baseline.read_bytes()
        original = ev.os.write
        def interrupt(descriptor, data):
            original(descriptor, data[:9])
            raise KeyboardInterrupt('public cancellation cut')
        with patch.object(ev.os, 'write', side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.accept()
        self.assertTrue(self.baseline.read_bytes().startswith(prefix))
        # A busy result would mean the kernel lock escaped cancellation cleanup.
        result = ev.compare(self.report, self.baseline)
        self.assertEqual(result['reason'], 'baseline_incomplete_append')

    def test_unsupported_directory_lock_refuses_before_a_new_leaf_is_created(self):
        with patch.object(ev.fsx, 'lock_file', side_effect=OSError(errno.ENOTSUP, 'public unsupported host')):
            with self.assertRaisesRegex(ev.EvalError, 'baseline_lock_unsupported'):
                self.accept()
        self.assertFalse(self.baseline.exists())

    def test_initial_create_is_no_replace_and_leaves_no_pathname_lock_or_temporary(self):
        original = ev.fsx.open_at
        inserted = []
        foreign = b'public initial create collision\n'
        def open_at(directory, name, flags, *args, **kwargs):
            if name == self.baseline.name and flags & os.O_CREAT:
                self.baseline.write_bytes(foreign)
                inserted.append(bool(flags & os.O_EXCL))
            return original(directory, name, flags, *args, **kwargs)
        with patch.object(ev.fsx, 'open_at', side_effect=open_at):
            with self.assertRaisesRegex(ev.EvalError, 'baseline_file_replaced'):
                self.accept()
        self.assertTrue(inserted)
        self.assertEqual(self.baseline.read_bytes(), foreign)
        self.assertTrue(all(inserted), 'initial creation must use native no-replace flags')
        self.assertEqual(list(self.fixture.root.glob('.eval-baseline-*')), [])
        self.assertFalse(self.baseline.with_name(self.baseline.name + '.lock').exists())

    def test_process_crash_preserves_prefix_and_releases_real_kernel_lock(self):
        self.accept()
        prefix = self.baseline.read_bytes()
        child = (
            "import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from getzilla import agent_evals as e\n"
            "root=Path(sys.argv[2]);report=e.replay(root,'manifest.json','outputs.json');original=e.os.write\n"
            "def interrupted(fd,data):\n"
            " original(fd,data[:9]);print('public-partial-ready',flush=True);sys.stdin.buffer.read(1)\n"
            " raise RuntimeError('owned fixture interrupted')\n"
            "e.os.write=interrupted\n"
            "e.accept_baseline(root/'baseline.json',report,reason='Public crash fixture',scope='Owned fixture')\n"
        )
        process = subprocess.Popen([sys.executable, '-c', child, str(ROOT / '.getzilla'), str(self.fixture.root)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})
        try:
            ready, _, _ = select.select([process.stdout], [], [], 10)
            self.assertTrue(ready, 'owned child did not reach its bounded partial-write cut')
            self.assertEqual(process.stdout.readline(), b'public-partial-ready\n')
            self.assertEqual(ev.compare(self.report, self.baseline)['reason'], 'baseline_acceptance_busy')
            with self.assertRaisesRegex(ev.EvalError, 'baseline_acceptance_busy'):
                self.accept()
        finally:
            process.kill()
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        self.assertTrue(self.baseline.read_bytes().startswith(prefix))
        self.assertEqual(ev.compare(self.report, self.baseline)['reason'], 'baseline_incomplete_append')

    def test_actual_file_and_archive_cli_accept_and_compare_complete_frames(self):
        from scripts.install_into import PayloadSelection, materialize_new
        expected_source = hashlib.sha256((ROOT / '.getzilla/getzilla/agent_evals.py').read_bytes()).hexdigest()
        for archive in (False, True):
            with self.subTest(archive=archive):
                installed = self.fixture.root / ('installed-archive' if archive else 'installed-files')
                materialize_new(ROOT, installed, selection=PayloadSelection((), engine_archive=archive))
                script = installed / 'scripts/getzilla_evals.py'
                baseline = 'archive-baseline.json' if archive else 'files-baseline.json'
                common = [sys.executable, str(script), '--root', str(self.fixture.root)]
                options = ['--manifest', 'manifest.json', '--outputs', 'outputs.json', '--baseline', baseline, '--json']
                accepted = subprocess.run([*common, 'accept', *options, '--reason', 'Public installed control',
                                            '--scope', 'Owned fixture only'], capture_output=True, text=True, timeout=30)
                self.assertEqual(accepted.returncode, 0, accepted.stderr + accepted.stdout)
                observed = subprocess.run([*common, 'run', *options], capture_output=True, text=True, timeout=30)
                self.assertEqual(observed.returncode, 0, observed.stderr + observed.stdout)
                report = json.loads(observed.stdout)
                self.assertEqual(report['comparison']['status'], 'pass')
                self.assertEqual(report['canonical']['identity']['runner_sha256'], expected_source)
                self.assertEqual(report['comparison']['baseline_id'], json.loads(accepted.stdout)['baseline_id'])
                lines = (self.fixture.root / baseline).read_bytes().splitlines()
                self.assertEqual(len(lines), 3)
                self.assertEqual(json.loads(lines[0]), {'schema_version': 2, 'history': []})
                self.assertEqual(json.loads(lines[2])['commit'], json.loads(accepted.stdout)['baseline_id'])

    def test_known_byte_limit_refuses_before_creating_a_baseline_leaf(self):
        with patch.object(ev, 'MAX_BASELINE_BYTES', 16):
            with self.assertRaisesRegex(ev.EvalError, 'baseline_history_limit'):
                self.accept()
        self.assertFalse(self.baseline.exists())


if __name__ == '__main__':
    unittest.main()
