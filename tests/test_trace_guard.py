"""Nested trace guard reuse requires a live native manager resource."""
import contextvars
import asyncio
import errno
import os
import select
import subprocess
import json
import tempfile
import threading
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import state


class GuardLeaseTests(unittest.TestCase):
    def setUp(self):
        saved = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, saved)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(os.fchdir, saved)
        self.root = Path(self.temp.name)
        (self.root / '.getzilla/runtime').mkdir(parents=True)
        (self.root / '.getzilla').chmod(0o755)
        (self.root / '.getzilla/runtime').chmod(0o700)
        os.chdir(self.root)

    def test_native_nested_lease_is_live_only_in_its_manager_scope(self):
        from getzilla.trace_storage import native_root, held_guard
        with native_root(self.root) as anchor:
            with state.runtime_lock(self.root, 'task-transition'):
                lease = held_guard(anchor, 'task-transition')
                self.assertIsNotNone(lease)
                copied = contextvars.copy_context()
            with self.assertRaises(ValueError):
                copied.run(held_guard, anchor, 'task-transition')

    def test_copied_thread_context_cannot_reuse_parent_guard(self):
        from getzilla.trace_storage import native_root, held_guard
        with native_root(self.root) as anchor:
            with state.runtime_lock(self.root, 'task-transition'):
                copied = contextvars.copy_context()
                results = []
                def child():
                    try:
                        copied.run(held_guard, anchor, 'task-transition')
                    except ValueError:
                        results.append('refused')
                thread = threading.Thread(target=child)
                thread.start()
                thread.join(1)
                self.assertFalse(thread.is_alive())
                self.assertEqual(results, ['refused'])

    def test_same_number_same_inode_reopened_fd_is_refused_and_not_closed(self):
        from getzilla.trace_storage import native_root, held_guard
        with native_root(self.root) as anchor:
            with state.runtime_lock(self.root, 'task-transition'):
                lease = held_guard(anchor, 'task-transition')
                number = lease._primary
                os.close(number)
                reopened = os.open('.getzilla/runtime/.task-transition.guard.lock', os.O_RDWR | os.O_CLOEXEC)
                self.assertEqual(reopened, number)
                with self.assertRaises(ValueError):
                    held_guard(anchor, 'task-transition')
            try:
                self.assertGreater(os.fstat(reopened).st_ino, 0)
            finally:
                os.close(reopened)

    def test_copied_async_task_cannot_reuse_parent_scope(self):
        from getzilla.trace_storage import native_root, held_guard
        async def scenario():
            with native_root(self.root) as anchor:
                with state.runtime_lock(self.root, 'task-transition'):
                    async def child():
                        with self.assertRaises(ValueError):
                            held_guard(anchor, 'task-transition')
                    await asyncio.create_task(child())
                    self.assertIsNotNone(held_guard(anchor, 'task-transition'))
        asyncio.run(scenario())

    def test_both_reused_numbers_are_not_probed_locked_or_closed(self):
        from getzilla.trace_storage import native_root, held_guard
        from getzilla import fsx
        path = '.getzilla/runtime/.task-transition.guard.lock'
        with native_root(self.root) as anchor:
            with state.runtime_lock(self.root, 'task-transition'):
                lease = held_guard(anchor, 'task-transition')
                primary, keeper = lease._primary, lease._keeper
                os.close(primary)
                os.close(keeper)
                one, two = os.open(path, os.O_RDWR), os.open(path, os.O_RDWR)
                if one != primary:
                    os.dup2(one, primary)
                    os.close(one)
                if two != keeper:
                    os.dup2(two, keeper)
                    os.close(two)
                with self.assertRaises(ValueError):
                    held_guard(anchor, 'task-transition')
            try:
                self.assertGreater(os.fstat(primary).st_ino, 0)
                self.assertGreater(os.fstat(keeper).st_ino, 0)
                third = os.open(path, os.O_RDWR)
                try:
                    fsx.lock_file(third, blocking=False)
                    fsx.unlock_file(third)
                finally:
                    os.close(third)
            finally:
                os.close(primary)
                os.close(keeper)

    def test_closed_keeper_refuses_reuse_but_does_not_leak_owned_primary(self):
        from getzilla.trace_storage import native_root, held_guard
        with native_root(self.root) as anchor:
            with state.runtime_lock(self.root, 'task-transition'):
                lease = held_guard(anchor, 'task-transition')
                os.close(lease._keeper)
                with self.assertRaises(ValueError):
                    held_guard(anchor, 'task-transition')
            with state.runtime_lock(self.root, 'task-transition', timeout=0.1):
                pass

    @unittest.skipUnless(hasattr(os, 'fork'), 'native fork unavailable')
    def test_live_nonexec_fork_child_closes_copies_without_unlocking_parent(self):
        from getzilla.trace_storage import native_root, held_guard
        from getzilla import fsx
        read_ready, write_ready = os.pipe()
        read_release, write_release = os.pipe()
        pid = None
        try:
            with native_root(self.root) as anchor:
                with state.runtime_lock(self.root, 'task-transition'):
                    lease = held_guard(anchor, 'task-transition')
                    owned = (lease._primary, lease._keeper, lease._marker)
                    pid = os.fork()
                    if pid == 0:
                        try:
                            os.close(read_ready)
                            os.close(write_release)
                            closed = True
                            for descriptor in owned:
                                try:
                                    os.fstat(descriptor)
                                except OSError as error:
                                    closed = closed and error.errno == errno.EBADF
                                else:
                                    closed = False
                            descriptor = os.open('.getzilla/runtime/.task-transition.guard.lock', os.O_RDWR)
                            try:
                                fsx.lock_file(descriptor, blocking=False)
                            except BlockingIOError:
                                parent_held = True
                            else:
                                parent_held = False
                            os.close(descriptor)
                            os.write(write_ready, b'1' if closed and parent_held else b'0')
                            os.read(read_release, 1)
                            os._exit(0)
                        except BaseException:
                            os._exit(1)
                    os.close(write_ready)
                    write_ready = None
                    os.close(read_release)
                    read_release = None
                    self.assertTrue(select.select([read_ready], [], [], 2)[0], 'fork child failed to report')
                    self.assertEqual(os.read(read_ready, 1), b'1')
                # The non-exec child is still alive, but holds no inherited
                # resource that can retain the released parent's guard.
                with state.runtime_lock(self.root, 'task-transition', timeout=0.2):
                    pass
        finally:
            if pid not in {None, 0}:
                os.write(write_release, b'x')
                _, status = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            for descriptor in (read_ready, write_ready, read_release, write_release):
                if descriptor is not None:
                    os.close(descriptor)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux subreaper profile control')
    def test_parent_death_does_not_leave_guard_in_a_live_nonexec_child(self):
        script = Path(__file__).with_name('_guard_parent_death.py')
        result = subprocess.run([sys.executable, str(script), str(self.root)], cwd=self.root,
                                capture_output=True, text=True, timeout=6)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertTrue(evidence['parent_exit_without_cleanup'])
        self.assertTrue(evidence['lock_available_with_nonexec_child_alive'])
        self.assertTrue(evidence['owned_descendants_reaped'])


if __name__ == '__main__':
    unittest.main()
