"""Read before edit: a patch may not change an existing file this session never read (#218)."""
from __future__ import annotations

import subprocess
import sys
import threading
import os
import errno
import tempfile
import time
import unittest
from contextlib import contextmanager
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

import getzilla.read_ledger as ledger  # noqa: E402
import getzilla.state as state  # noqa: E402
from getzilla.read_ledger import command_files, output_files, patch_targets, record, seen  # noqa: E402
from getzilla.router import build_route  # noqa: E402
from getzilla.state import add_approval
from tests._support import activate_owned_route
from tests._support import project_copy, run_hook  # noqa: E402


def _patch(kind: str, path: str) -> str:
    body = '@@\n-a\n+b\n' if kind == 'Update' else '+b\n'
    return f'*** Begin Patch\n*** {kind} File: {path}\n{body}*** End Patch\n'


def _lock_refusal(error: OSError, stage: str) -> dict:
    # Keep only code locations, never the exception message, filename or locals.
    frames = []
    trace = error.__traceback__
    while trace is not None:
        code = trace.tb_frame.f_code
        frames.append((Path(code.co_filename).name, code.co_name, trace.tb_lineno))
        trace = trace.tb_next
    return {'writer': threading.current_thread().name, 'stage': stage,
            'error': type(error).__name__, 'errno': error.errno, 'frames': frames[-16:]}


class _WriterPhaseObserver:
    """Test-only phases; advisory refusals are not escaped worker failures."""
    def __init__(self, real_lock, refusals):
        self.real_lock = real_lock
        self.refusals = refusals
        self.current = threading.local()
        self.failures = {phase: False for phase in
                         ('barrier', 'before_record', 'acquire', 'update', 'release', 'unknown')}

    def capture(self, _error):
        phase = getattr(self.current, 'phase', 'unknown')
        phase = phase if phase in self.failures else 'unknown'
        self.failures[phase] = True

    @contextmanager
    def lock(self, *args, **kwargs):
        stage = self.current.phase = 'acquire'
        try:
            with self.real_lock(*args, **kwargs):
                stage = self.current.phase = 'update'
                yield
                stage = self.current.phase = 'release'
        except OSError as error:
            self.refusals.append(_lock_refusal(error, stage))
            raise

    def writer(self, root, start, index, errors):
        try:
            self.current.phase = 'barrier'
            start.wait(timeout=5)
            self.current.phase = 'before_record'
            record(root, 's', {f'f{index}.py'})
            self.current.phase = 'done'
        except BaseException as error:
            self.capture(error)
            errors.append(error)


class ReadLedgerHookTests(unittest.TestCase):
    def _shell(self, root: Path, command: str, session: str = 'ledger-session') -> None:
        payload = {'cwd': str(root), 'session_id': session, 'hook_event_name': 'PostToolUse',
                   'tool_name': 'exec_command', 'tool_input': {'cmd': command, 'workdir': str(root)},
                   'tool_response': {'output': ''}}
        code, _, stderr = run_hook(root, 'post_tool_use.py', payload)
        self.assertEqual(code, 0, stderr)

    def _patch(self, root: Path, patch: str, session: str = 'ledger-session') -> dict:
        payload = {'cwd': str(root), 'session_id': session, 'hook_event_name': 'PreToolUse',
                   'tool_name': 'apply_patch', 'tool_input': {'input': patch}}
        code, data, stderr = run_hook(root, 'pre_tool_use.py', payload)
        self.assertEqual(code, 0, stderr)
        return data

    def _project(self, root: Path) -> None:
        (root / 'app').mkdir()
        for name in ('read.py', 'unread.py'):
            (root / 'app' / name).write_text('a\n', encoding='utf-8')
        subprocess.run(['git', 'add', 'app'], cwd=root, check=True)

    def test_linked_worktree_read_is_known_to_canonical_session_ledger(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                            'commit', '-qm', 'fixture'], cwd=root, check=True)
            target = root / '.getzilla/runtime/worktrees/ledger-child'
            subprocess.run(['git', 'worktree', 'add', '-qb', 'ledger-child', str(target)], cwd=root, check=True)
            self._shell(root, 'cat app/read.py')
            self._shell(target, 'cat app/unread.py')
            read_patch = _patch('Update', str(target / 'app/unread.py'))
            unseen_patch = _patch('Update', str(target / 'app/read.py'))
            self.assertEqual(ledger.unread(root, 'ledger-session', read_patch, root), [])
            self.assertEqual(ledger.unread(root, 'ledger-session', unseen_patch, root),
                             ['.getzilla/runtime/worktrees/ledger-child/app/read.py'])
            self.assertEqual(ledger.unread(target, 'ledger-session', _patch('Update', 'app/unread.py'), target), [])
            self._shell(root, 'cat app/read.py', 'other-session')
            self.assertTrue(ledger.unread(root, 'other-session', read_patch, root))
            subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Example/project.git'],
                           cwd=root, check=True)
            activate_owned_route(root, build_route(root, 'fix read ledger regression', 'ledger-session').to_dict())
            add_approval(root, 'protected-path', 'fixture', 5, actions=['protected-path-write'],
                         resources=['.getzilla/runtime/worktrees/ledger-child/app/unread.py'])
            self.assertEqual(self._patch(root, read_patch)['decision'], 'allow')

    def test_unregistered_nested_git_pointer_does_not_share_a_ledger(self) -> None:
        with project_copy(git=True) as root:
            target = root / '.getzilla/runtime/worktrees/unregistered'
            target.mkdir(parents=True)
            (target / '.git').write_text('gitdir: not-a-worktree\n', encoding='utf-8')
            self.assertEqual(ledger._ledger_root(target), target.resolve())

    def test_a_patch_to_an_unread_file_is_refused_and_a_read_one_passes(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            self._shell(root, "nl -ba app/read.py | sed -n '1,40p'")
            data = self._patch(root, _patch('Update', 'app/unread.py'))
            self.assertEqual(data['decision'], 'deny', data)
            self.assertIn('`app/unread.py`', data['reason'])
            self.assertIn('read before you change it', data['reason'])
            self.assertEqual(self._patch(root, _patch('Update', 'app/read.py'))['decision'], 'allow')
            self.assertEqual(self._patch(root, _patch('Add', 'app/new.py'))['decision'], 'allow')
            self._shell(root, 'cat app/unread.py')
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'))['decision'], 'allow')

    def test_a_session_without_a_ledger_is_never_blocked(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'), 'fresh-session')['decision'], 'allow')
            self._shell(root, 'cat app/read.py', 'manual')
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'), 'manual')['decision'], 'allow')

    def test_a_file_the_session_patched_counts_as_seen(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            self._shell(root, 'cat app/read.py')
            payload = {'cwd': str(root), 'session_id': 'ledger-session', 'hook_event_name': 'PostToolUse',
                       'tool_name': 'apply_patch', 'tool_input': {'input': _patch('Add', 'app/new.py')},
                       'tool_response': {'output': ''}}
            (root / 'app/new.py').write_text('b\n', encoding='utf-8')
            run_hook(root, 'post_tool_use.py', payload)
            self.assertEqual(self._patch(root, _patch('Update', 'app/new.py'))['decision'], 'allow')


    def test_files_a_search_printed_and_a_claude_read_count_as_seen(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            payload = {'cwd': str(root), 'session_id': 'ledger-session', 'hook_event_name': 'PostToolUse',
                       'tool_name': 'exec_command', 'tool_input': {'cmd': 'rg -n a app', 'workdir': str(root)},
                       'tool_response': {'output': 'app/unread.py:1:a\n'}}
            run_hook(root, 'post_tool_use.py', payload)
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'))['decision'], 'allow')
        with project_copy(git=True) as root:
            self._project(root)
            self._shell(root, 'cat app/read.py', 'claude-session')
            payload = {'cwd': str(root), 'session_id': 'claude-session', 'hook_event_name': 'PostToolUse',
                       'tool_name': 'Read', 'tool_input': {'file_path': str(root / 'app/unread.py')}, 'tool_response': {}}
            run_hook(root, 'post_tool_use.py', payload)
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'), 'claude-session')['decision'], 'allow')

    def test_a_corrupt_ledger_lets_the_patch_run(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            self._shell(root, 'cat app/read.py')
            for item in (root / '.getzilla/runtime/reads').glob('*.json'):
                item.write_text('{not json', encoding='utf-8')
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'))['decision'], 'allow')


class ReadLedgerUnitTests(unittest.TestCase):
    def test_public_two_writer_phase_observer_preserves_updates(self) -> None:
        factory = globals().get('_WriterPhaseObserver')
        self.assertTrue(callable(factory), 'fixed worker phases are required')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            observer = factory(state.runtime_lock, [])
            errors = []
            start = threading.Barrier(2)
            threads = [threading.Thread(target=observer.writer, args=(root, start, index, errors))
                       for index in range(2)]
            with mock.patch.object(state, 'runtime_lock', observer.lock):
                for thread in threads:
                    thread.start()
                deadline = time.monotonic() + 10
                for thread in threads:
                    thread.join(max(0, deadline - time.monotonic()))
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertTrue(all(not values for values in observer.failures.values()))
            self.assertEqual(len(errors), 0)
            self.assertEqual(seen(root, 's'), {'f0.py', 'f1.py'})

    def test_advisory_update_and_release_refusals_are_not_escaped_failures(self) -> None:
        factory = globals().get('_WriterPhaseObserver')
        self.assertTrue(callable(factory), 'fixed worker phases are required')
        real_lock = state.runtime_lock

        @contextmanager
        def release_refusal(*args, **kwargs):
            with real_lock(*args, **kwargs):
                yield
            raise OSError(errno.EIO, 'public fixture release refusal')

        for stage in ('update', 'release'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                refusals, errors = [], []
                observer = factory(real_lock if stage == 'update' else release_refusal, refusals)
                with mock.patch.object(state, 'runtime_lock', observer.lock):
                    if stage == 'update':
                        with mock.patch.object(ledger, '_entries', side_effect=OSError(errno.EIO, 'public fixture update refusal')):
                            observer.writer(root, threading.Barrier(1), 0, errors)
                    else:
                        observer.writer(root, threading.Barrier(1), 0, errors)
                self.assertTrue(all(not values for values in observer.failures.values()))
                self.assertEqual(len(errors), 0)
                self.assertEqual([row['stage'] for row in refusals], [stage])
                self.assertEqual(seen(root, 's') or set(), set() if stage == 'update' else {'f0.py'})

    def test_escaped_barrier_snapshot_and_unknown_category_are_closed(self) -> None:
        factory = globals().get('_WriterPhaseObserver')
        self.assertTrue(callable(factory), 'fixed worker phases are required')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            observer = factory(state.runtime_lock, [])
            errors = []
            barrier = threading.Barrier(1)
            with mock.patch.object(barrier, 'wait', side_effect=threading.BrokenBarrierError('public fixture barrier')):
                observer.writer(root, barrier, 0, errors)
            self.assertIs(observer.failures['barrier'], True)
            self.assertEqual(sum(observer.failures.values()), 1)
            self.assertEqual(len(errors), 1)
            self.assertIsNone(seen(root, 's'))
            del observer.current.phase
            observer.capture(RuntimeError('public fixture unknown error'))
            self.assertIs(observer.failures['unknown'], True)

    def test_acquisition_failure_diagnostic_omits_private_paths_and_message(self) -> None:
        formatter = globals().get('_lock_refusal')
        self.assertTrue(callable(formatter), 'lock acquisition needs bounded safe internal frames')
        namespace = {}
        exec(compile('def operation():\n    raise FileNotFoundError(2, "PRIVATE-MESSAGE", "/PRIVATE-PATH/ledger")\n',
                     '/PRIVATE-DIRECTORY/operation.py', 'exec'), namespace)
        try:
            namespace['operation']()
        except OSError as error:
            diagnostic = formatter(error, 'acquire')
        self.assertEqual(diagnostic['stage'], 'acquire')
        self.assertEqual(diagnostic['errno'], 2)
        self.assertIn(('operation.py', 'operation', 2), diagnostic['frames'])
        self.assertEqual(set(diagnostic), {'writer', 'stage', 'error', 'errno', 'frames'})
        for basename, function, line in diagnostic['frames']:
            self.assertEqual(Path(basename).name, basename)
            self.assertIsInstance(function, str)
            self.assertIsInstance(line, int)
        self.assertNotIn('PRIVATE-', str(diagnostic))

        def nested(depth):
            if depth:
                nested(depth - 1)
            else:
                namespace['operation']()

        try:
            nested(30)
        except OSError as error:
            diagnostic = formatter(error, 'acquire')
        self.assertEqual(len(diagnostic['frames']), 16)
        self.assertIn(('operation.py', 'operation', 2), diagnostic['frames'])
        self.assertNotIn('PRIVATE-', str(diagnostic))

    def test_parallel_writers_keep_every_entry(self) -> None:
        with project_copy(git=True) as root:
            start = threading.Barrier(40)
            errors = []
            refusals = []
            real_lock = state.runtime_lock
            observer = _WriterPhaseObserver(real_lock, refusals)

            @contextmanager
            def observed_lock(*args, **kwargs):
                with observer.lock(*args, **kwargs):
                    yield

            def writer(index):
                observer.writer(root, start, index, errors)

            threads = [threading.Thread(target=writer, args=(index,), name=f'f{index}.py') for index in range(40)]
            with mock.patch.object(state, 'runtime_lock', observed_lock):
                for thread in threads:
                    thread.start()
                deadline = time.monotonic() + 10
                for thread in threads:
                    thread.join(max(0, deadline - time.monotonic()))
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertFalse(observer.failures['barrier'])
            self.assertFalse(observer.failures['before_record'])
            self.assertFalse(observer.failures['acquire'])
            self.assertFalse(observer.failures['update'])
            self.assertFalse(observer.failures['release'])
            self.assertFalse(observer.failures['unknown'])
            self.assertEqual(errors, [])
            self.assertEqual(seen(root, 's'), {f'f{index}.py' for index in range(40)},
                             f'advisory refusals (writer, stage, error, errno): {refusals}')

    def test_a_full_ledger_drops_the_oldest(self) -> None:
        with project_copy(git=True) as root:
            with mock.patch.object(ledger, 'MAX_ENTRIES', 3):
                for name in ('z.py', 'y.py', 'a.py', 'b.py'):
                    record(root, 'cap', {name})
            self.assertEqual(seen(root, 'cap'), {'y.py', 'a.py', 'b.py'})

    def _contended_schedule(self, *, empty_holder: bool) -> None:
        # Only scheduling is instrumented: PID writes, identity reads, locks and
        # ledger publication all use the real implementation and filesystem.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = state.runtime_dir(root) / '.reads.lock'
            if not empty_holder:
                lock.write_text('0\n', encoding='utf-8')
            paused = threading.Event()
            resume = threading.Event()
            contender_scheduled = threading.Event()
            owner_done = threading.Event()
            errors, transitions, lock_errors = [], [], []
            active = set()
            overlaps = []
            counts = {}
            real_write, real_file_lock = os.write, state.fsx.lock_file
            real_identity, real_lock = state._lock_identity, state.runtime_lock
            real_entries = ledger._entries

            def wait(event):
                if not event.wait(4):
                    raise AssertionError('schedule did not reach its next boundary')

            def file_lock(fd, **kwargs):
                try:
                    return real_file_lock(fd, **kwargs)
                except OSError:
                    if threading.current_thread().name == 'ledger-B':
                        contender_scheduled.set()
                    raise

            def written(fd, data):
                if empty_holder and threading.current_thread().name == 'ledger-A':
                    paused.set()
                    wait(resume)
                return real_write(fd, data)

            def identity(path):
                result = real_identity(path)
                name = threading.current_thread().name
                counts[name] = counts.get(name, 0) + 1
                if not empty_holder and name == 'ledger-A' and counts[name] == 2:
                    paused.set()
                    wait(resume)
                return result

            @contextmanager
            def observed_lock(*args, **kwargs):
                name = threading.current_thread().name
                try:
                    with real_lock(*args, **kwargs):
                        if active:
                            overlaps.append((name, sorted(active)))
                        active.add(name)
                        transitions.append(('enter', name))
                        try:
                            yield
                        finally:
                            transitions.append(('exit', name))
                            active.remove(name)
                except (OSError, TimeoutError) as error:
                    lock_errors.append(error)
                    raise

            def entries(path):
                result = real_entries(path)
                if threading.current_thread().name == 'ledger-B':
                    contender_scheduled.set()
                    wait(owner_done)
                return result

            def writer(name):
                try:
                    record(root, 's', {f'{name.lower()}.py'})
                except BaseException as error:
                    errors.append(error)
                finally:
                    if name == 'A':
                        owner_done.set()

            threads = [threading.Thread(target=writer, args=(name,), name=f'ledger-{name}')
                       for name in ('A', 'B')]
            with mock.patch.object(state.fsx, 'lock_file', file_lock), mock.patch.object(os, 'write', written), \
                    mock.patch.object(state, '_lock_identity', identity), \
                    mock.patch.object(state, 'runtime_lock', observed_lock), \
                    mock.patch.object(ledger, '_entries', entries):
                try:
                    threads[0].start()
                    wait(paused)
                    if empty_holder:
                        time.sleep(state.LOCK_WRITE_GRACE_SECONDS + 0.1)
                    threads[1].start()
                    # B must reach real admission (old code) or OS contention
                    # (repaired code). No scheduler-dependent admission window.
                    wait(contender_scheduled)
                    resume.set()
                    deadline = time.monotonic() + 6
                    for thread in threads:
                        thread.join(max(0, deadline - time.monotonic()))
                finally:
                    resume.set()
                    owner_done.set()
                    for thread in threads:
                        if thread.ident is not None:
                            thread.join(5)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(lock_errors, [])
            actual = seen(root, 's')
            self.assertEqual((overlaps, actual), ([], {'a.py', 'b.py'}), transitions)

    def test_live_holder_before_pid_publication_keeps_both_entries(self) -> None:
        self._contended_schedule(empty_holder=True)

    def test_successor_after_second_identity_read_keeps_both_entries(self) -> None:
        self._contended_schedule(empty_holder=False)

    def test_real_lock_timeout_is_advisory_and_later_record_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record(root, 's', {'before.py'})
            real_lock = state.runtime_lock

            def short_lock(root, name):
                return real_lock(root, name, timeout=0.1)

            with real_lock(root, 'reads'), mock.patch.object(state, 'runtime_lock', short_lock):
                start = time.monotonic()
                record(root, 's', {'dropped.py'})
                self.assertLess(time.monotonic() - start, 1)
            self.assertEqual(seen(root, 's'), {'before.py'})
            record(root, 's', {'after.py'})
            self.assertEqual(seen(root, 's'), {'before.py', 'after.py'})

    def test_os_lock_failure_is_advisory_and_preserves_existing_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record(root, 's', {'before.py'})
            with mock.patch.object(state.fsx, 'lock_file', side_effect=OSError(errno.EIO, 'device failed')):
                record(root, 's', {'dropped.py'})
            self.assertEqual(seen(root, 's'), {'before.py'})
            record(root, 's', {'after.py'})
            self.assertEqual(seen(root, 's'), {'before.py', 'after.py'})

    def test_unreadable_existing_ledger_preserves_saved_entries_and_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record(root, 's', {'prior.py'})
            path, = (root / ledger.LEDGER_DIR).glob('*.json')
            before = path.read_bytes()
            real_read = Path.read_text

            def read(target, *args, **kwargs):
                if target == path:
                    raise OSError(errno.EMFILE, 'descriptor limit')
                return real_read(target, *args, **kwargs)

            with mock.patch.object(Path, 'read_text', read):
                self.assertIsNone(seen(root, 's'))
                record(root, 's', {'unconfirmed.py'})
            self.assertEqual(path.read_bytes(), before)
            record(root, 's', {'after.py'})
            self.assertEqual(seen(root, 's'), {'prior.py', 'after.py'})

    def test_cd_globs_and_printed_paths(self) -> None:
        with project_copy(git=True) as root:
            (root / 'app').mkdir()
            for name in ('b.py', 'c.py'):
                (root / 'app' / name).write_text('x\n', encoding='utf-8')
            self.assertEqual(command_files(root, 'cd app && cat b.py', root), {'app/b.py'})
            self.assertEqual(command_files(root, 'cat app/*.py', root), {'app/b.py', 'app/c.py'})
            printed = 'diff --git a/app/b.py b/app/b.py\n+++ b/app/c.py\napp/b.py:3:x\n'
            self.assertEqual(output_files(root, printed, root), {'app/b.py', 'app/c.py'})

    def test_a_long_word_in_output_is_scanned_in_linear_time(self) -> None:
        # Codex review of #222 consumers: a long base64 value made the old pattern quadratic.
        import time
        with project_copy(git=True) as root:
            (root / 'app').mkdir()
            (root / 'app/b.py').write_text('x\n', encoding='utf-8')
            start = time.monotonic()
            found = output_files(root, 'A' * 150_000 + ' app/b.py:1:x\n', root)
            self.assertLess(time.monotonic() - start, 2.0)
            self.assertEqual(found, {'app/b.py'})

    def test_command_files_and_patch_targets(self) -> None:
        with project_copy(git=True) as root:
            (root / 'a.py').write_text('x\n', encoding='utf-8')
            self.assertEqual(command_files(root, "sed -n '1,20p' a.py missing.py --file=a.py", root), {'a.py'})
            self.assertEqual(command_files(root, 'cat /etc/hostname', root), set())
            changed, written = patch_targets(_patch('Update', 'a.py') + _patch('Delete', 'b.py') + _patch('Add', 'c.py'))
            self.assertEqual((changed, written), ({'a.py', 'b.py'}, {'c.py'}))


if __name__ == '__main__':
    unittest.main()
