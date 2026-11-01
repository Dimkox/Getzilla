from __future__ import annotations

import sys
import os
import errno
import multiprocessing
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.state import runtime_lock
from getzilla import fsx
from getzilla.util import runtime_dir
from tests._support import project_copy


def _hold_runtime_lock(root, ready):
    # A spawn child opens its own descriptors on every supported platform.
    with runtime_lock(Path(root), timeout=1):
        ready.send('acquired')
        ready.close()
        # The parent kills this holder. Do not wait on a shared semaphore:
        # notifying a killed waiter can itself hang the parent's cleanup.
        time.sleep(10)


class RuntimeStateTests(unittest.TestCase):
    def test_guard_refuses_links_without_touching_the_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'project'
            guard = runtime_dir(root) / '.state.guard.lock'
            target = Path(directory) / 'outside'
            for exists in (False, True):
                with self.subTest(target_exists=exists):
                    if exists:
                        target.write_bytes(b'untouched')
                    try:
                        guard.symlink_to(target)
                    except OSError as error:
                        self.skipTest(f'symlinks unavailable: {error}')
                    try:
                        with self.assertRaises(OSError):
                            with runtime_lock(root, timeout=0.1):
                                self.fail('a linked guard admitted a writer')
                        self.assertEqual(target.exists(), exists)
                        if exists:
                            self.assertEqual(target.read_bytes(), b'untouched')
                    finally:
                        guard.unlink()

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO control requires POSIX')
    def test_guard_refuses_a_fifo_without_waiting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(runtime_dir(root) / '.state.guard.lock')
            start = time.monotonic()
            with self.assertRaises(OSError):
                with runtime_lock(root, timeout=0.1):
                    self.fail('a nonregular guard admitted a writer')
            self.assertLess(time.monotonic() - start, 1)

    def test_zero_timeout_attempts_a_free_lock_without_waiting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with runtime_lock(Path(directory), timeout=0):
                with self.assertRaises(TimeoutError):
                    with runtime_lock(Path(directory), timeout=0):
                        self.fail('an occupied lock was acquired')

    def test_process_contender_is_excluded_then_recovers_after_owner_death(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = multiprocessing.get_context('spawn')
            ready, child_ready = context.Pipe(duplex=False)
            owner = context.Process(target=_hold_runtime_lock, args=(directory, child_ready))
            owner.start()
            child_ready.close()
            try:
                self.assertTrue(ready.poll(5), 'child did not acquire the lock')
                self.assertEqual(ready.recv(), 'acquired')
                start = time.monotonic()
                with self.assertRaises(TimeoutError):
                    with runtime_lock(root, timeout=0.15):
                        self.fail('two processes entered the protected block')
                self.assertLess(time.monotonic() - start, 1)
                owner.terminate()
                owner.join(5)
                self.assertFalse(owner.is_alive())
                with runtime_lock(root, timeout=1):
                    self.assertTrue((runtime_dir(root) / '.state.lock').exists())
                self.assertFalse((runtime_dir(root) / '.state.lock').exists())
            finally:
                ready.close()
                if owner.is_alive():
                    owner.terminate()
                owner.join(5)
                if owner.is_alive():
                    owner.kill()
                    owner.join(5)
                self.assertFalse(owner.is_alive())
                owner.close()

    def test_exception_releases_descriptors_and_retains_guard_identity(self) -> None:
        from getzilla.resource_inventory import classify
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guard = runtime_dir(root) / '.state.guard.lock'
            descriptors = []
            real_open = os.open

            def opened(path, *args, **kwargs):
                fd = real_open(path, *args, **kwargs)
                descriptors.append(fd)
                self.assertFalse(os.get_inheritable(fd))
                return fd

            with mock.patch.object(os, 'open', opened):
                with self.assertRaisesRegex(ValueError, 'operation failed'):
                    with runtime_lock(root):
                        identity = (guard.stat().st_dev, guard.stat().st_ino)
                        raise ValueError('operation failed')
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            self.assertFalse((runtime_dir(root) / '.state.lock').exists())
            self.assertEqual(classify(root, guard), 'protected')
            for _ in range(2):
                with runtime_lock(root):
                    self.assertEqual((guard.stat().st_dev, guard.stat().st_ino), identity)
                self.assertEqual((guard.stat().st_dev, guard.stat().st_ino), identity)

    def test_agent_lifecycle_guard_can_nest_runtime_lock(self) -> None:
        from getzilla.agent_lifecycle import _locked
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with _locked(root):
                runtime = runtime_dir(root)
                self.assertTrue((runtime / '.agents.lock').exists())
                self.assertFalse(os.path.samefile(runtime / '.agents.guard', runtime / '.agents.guard.lock'))
            self.assertFalse((runtime / '.agents.lock').exists())

    def test_non_contention_lock_error_propagates_and_closes_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            descriptors = []

            def failed(fd, **kwargs):
                descriptors.append(fd)
                raise OSError(errno.EIO, 'lock device failed')

            with mock.patch.object(fsx, 'lock_file', failed):
                with self.assertRaises(OSError) as raised:
                    with runtime_lock(Path(directory), timeout=0.1):
                        self.fail('an OS lock error admitted a writer')
            self.assertEqual(raised.exception.errno, errno.EIO)
            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError):
                os.fstat(descriptors[0])

    def test_pid_write_failure_closes_both_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptors = []
            real_open = os.open

            def opened(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                descriptors.append(fd)
                return fd

            with mock.patch.object(os, 'open', opened), \
                    mock.patch.object(os, 'write', side_effect=OSError(errno.EIO, 'write failed')):
                with self.assertRaises(OSError):
                    with runtime_lock(root):
                        self.fail('PID publication failed')
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            self.assertFalse((runtime_dir(root) / '.state.lock').exists())
            with runtime_lock(root, timeout=0.1):
                pass

    def test_expired_guard_wait_never_admits_a_free_pid_marker(self) -> None:
        for delayed_at in ('wake', 'acquired'):
            with self.subTest(delayed_at=delayed_at), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                guard = runtime_dir(root) / '.state.guard.lock'
                holder = os.open(guard, os.O_CREAT | os.O_RDWR | fsx.O_BINARY | fsx.O_NOINHERIT, 0o600)
                holder_locked = False
                clock, attempts, sleeps = [0.0], [], []
                real_lock = fsx.lock_file

                def attempted(fd, **kwargs):
                    attempts.append((fd, clock[0]))
                    real_lock(fd, **kwargs)
                    if delayed_at == 'acquired':
                        clock[0] = 0.6

                def delayed_sleep(seconds):
                    nonlocal holder_locked
                    sleeps.append(seconds)
                    fsx.unlock_file(holder)
                    holder_locked = False
                    clock[0] = 0.6 if delayed_at == 'wake' else 0.1

                try:
                    real_lock(holder, exclusive=True, blocking=False)
                    holder_locked = True
                    with mock.patch.object(time, 'monotonic', lambda: clock[0]), \
                            mock.patch.object(time, 'sleep', delayed_sleep), \
                            mock.patch.object(fsx, 'lock_file', attempted):
                        with self.assertRaises(TimeoutError):
                            with runtime_lock(root, timeout=0.5):
                                self.fail(f'writer admitted after expiry at {clock[0]}')
                    self.assertEqual(sleeps, [0.05])
                    self.assertFalse((runtime_dir(root) / '.state.lock').exists())
                    self.assertTrue(all(at < 0.5 for _, at in attempts), attempts)
                    with self.assertRaises(OSError):
                        os.fstat(attempts[-1][0])
                    with runtime_lock(root, timeout=0):
                        pass
                finally:
                    if holder_locked:
                        fsx.unlock_file(holder)
                    os.close(holder)

    def test_guard_and_pid_wait_share_one_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (runtime_dir(root) / '.state.lock').write_text(f'{os.getpid()}\n', encoding='utf-8')
            clock = [0.0]
            descriptors = []
            real_lock = fsx.lock_file

            def contended(fd, **kwargs):
                descriptors.append(fd)
                if clock[0] < 0.3:
                    raise BlockingIOError(errno.EAGAIN, 'held')
                return real_lock(fd, **kwargs)

            def advance(seconds):
                clock[0] += seconds

            with mock.patch.object(time, 'monotonic', lambda: clock[0]), \
                    mock.patch.object(time, 'sleep', advance), mock.patch.object(fsx, 'lock_file', contended):
                with self.assertRaises(TimeoutError):
                    with runtime_lock(root, timeout=0.5):
                        self.fail('live PID marker must exclude the writer')
            self.assertGreaterEqual(clock[0], 0.5)
            self.assertLessEqual(clock[0], 0.51)
            self.assertTrue(descriptors)
            with self.assertRaises(OSError):
                os.fstat(descriptors[-1])

    def test_windows_contention_retries_and_unlocks_before_close(self) -> None:
        # Branch control only. Native Windows locking is exercised by CI.
        with tempfile.TemporaryDirectory() as directory:
            attempts, unlocked = [], []

            def windows_lock(fd, **kwargs):
                self.assertEqual(kwargs, {'exclusive': True, 'blocking': False})
                attempts.append(fd)
                if len(attempts) <= 2:
                    raise OSError((errno.EACCES, errno.EDEADLK)[len(attempts) - 1], 'held')

            def windows_unlock(fd):
                os.fstat(fd)  # The descriptor must still be open here.
                unlocked.append(fd)

            with mock.patch.object(fsx, 'WINDOWS', True), \
                    mock.patch.object(fsx, 'lock_file', windows_lock), \
                    mock.patch.object(fsx, 'unlock_file', windows_unlock):
                with runtime_lock(Path(directory), timeout=0.5):
                    pass
            self.assertEqual(len(attempts), 3)
            self.assertEqual(unlocked, [attempts[-1]])
            with self.assertRaises(OSError):
                os.fstat(attempts[-1])

    def test_stale_process_lock_is_recovered(self) -> None:
        with project_copy() as root:
            lock = runtime_dir(root) / '.route.lock'
            lock.write_text('999999999\n', encoding='utf-8')
            with runtime_lock(root, 'route', timeout=0.5):
                self.assertTrue(lock.is_file())
            self.assertFalse(lock.exists())

    def test_malformed_lock_is_recovered(self) -> None:
        with project_copy() as root:
            lock = runtime_dir(root) / '.state.lock'
            lock.write_text('not-a-pid\n', encoding='utf-8')
            with runtime_lock(root, 'state', timeout=0.5):
                self.assertTrue(lock.is_file())
            self.assertFalse(lock.exists())

    def test_an_empty_lock_being_written_is_not_stolen(self) -> None:
        # The holder creates the lock and writes its pid a moment later; a reader must not delete it then.
        with project_copy() as root:
            lock = runtime_dir(root) / '.state.lock'
            lock.write_text('', encoding='utf-8')
            with self.assertRaises(TimeoutError):
                with runtime_lock(root, 'state', timeout=0.3):
                    pass
            old = lock.stat().st_mtime - 60
            os.utime(lock, (old, old))
            with runtime_lock(root, 'state', timeout=0.5):
                self.assertTrue(lock.is_file())

    def test_a_waiter_never_deletes_a_fresh_lock_that_replaced_the_stale_one(self) -> None:
        # #215: between the stale check and the unlink, a faster waiter can remove the dead lock and take a new one.
        import getzilla.state as state
        from unittest import mock
        with project_copy() as root:
            lock = runtime_dir(root) / '.state.lock'
            lock.write_text('999999999\n', encoding='utf-8')
            real = state._stale_lock
            calls = []

            def faster_waiter(path: Path) -> bool:
                if not calls:
                    calls.append(1)
                    path.unlink()
                    path.write_text(f'{os.getpid()}\n', encoding='utf-8')
                    return True
                return real(path)

            with mock.patch.object(state, '_stale_lock', faster_waiter):
                with self.assertRaises(TimeoutError):
                    with runtime_lock(root, 'state', timeout=0.3):
                        pass
            self.assertEqual(lock.read_text(encoding='utf-8'), f'{os.getpid()}\n')


if __name__ == '__main__':
    unittest.main()
