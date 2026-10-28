from __future__ import annotations

import sys
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.state import runtime_lock
from getzilla.util import runtime_dir
from tests._support import project_copy


class RuntimeStateTests(unittest.TestCase):
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
