"""Disposable Linux probe: reap our own orphan after its lock-holder dies."""
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import state


def reap(pid):
    deadline = time.monotonic()+2
    while time.monotonic() < deadline:
        found, status = os.waitpid(pid, os.WNOHANG)
        if found:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.01)
    # This is our still-unreaped child, so its PID cannot have been reused.
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    raise AssertionError('owned probe child exceeded cleanup deadline')


def main():
    root = Path(sys.argv[1])
    os.chdir(root)
    library = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if library.prctl(37, ctypes.byref(previous), 0, 0, 0) or library.prctl(36, 1, 0, 0, 0):
        raise RuntimeError('disposable subreaper unavailable')
    read_ready, write_ready = os.pipe()
    read_release, write_release = os.pipe()
    holder = grandchild = None
    try:
        holder = os.fork()
        if holder == 0:
            try:
                os.close(read_ready)
                os.close(write_release)
                with state.runtime_lock(root, 'task-transition'):
                    child = os.fork()
                    if child == 0:
                        os.write(write_ready, f'{os.getpid()}\n'.encode())
                        os.read(read_release, 1)
                        os._exit(0)
                    # Deliberately skip every context/finally cleanup. The live
                    # nonexec child must not retain the parent's locked OFD.
                    os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(write_ready)
        write_ready = None
        os.close(read_release)
        read_release = None
        if not select.select([read_ready], [], [], 2)[0]:
            raise AssertionError('fork child did not report')
        grandchild = int(os.read(read_ready, 64))
        if reap(holder) != 0:
            raise AssertionError('holder failed before death cut')
        holder = None
        with state.runtime_lock(root, 'task-transition', timeout=0.2):
            pass
        os.write(write_release, b'x')
        if reap(grandchild) != 0:
            raise AssertionError('adopted child failed')
        grandchild = None
        print(json.dumps({'parent_exit_without_cleanup': True, 'lock_available_with_nonexec_child_alive': True,
                          'owned_descendants_reaped': True}))
    finally:
        for pid in (holder, grandchild):
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
        for descriptor in (read_ready, write_ready, read_release, write_release):
            if descriptor is not None:
                os.close(descriptor)
        library.prctl(36, previous.value, 0, 0, 0)


if __name__ == '__main__':
    main()
