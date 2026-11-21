"""Closed read-only control handoff. Root-only case uses ordinary owned files."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import select
import signal
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_image_backend as backend

NAMES = ("memory.max", "memory.swap.max", "pids.max", "cgroup.procs", "cpu.max")
VALUES = ("12884901888", "0", "256", str(os.getpid()), "200000 100000")


@unittest.skipUnless(sys.platform == "linux", "Linux read-only descriptor handoff")
class ControlHandoffTests(unittest.TestCase):
    def fixture(self, group):
        for name, value in zip(NAMES, VALUES):
            (group / name).write_text(value + "\n")

    def test_controls_are_closed_readonly_live_and_close_on_exec(self):
        self.assertTrue(callable(getattr(backend, "_open_ci_controls", None)), "need closed preopened controls")
        import fcntl

        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory:
            group = Path(directory)
            self.fixture(group)
            fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
            try:
                controls = backend._open_ci_controls(fd)
                try:
                    self.assertEqual(set(controls), set(NAMES))
                    for opened, _identity in controls.values():
                        self.assertEqual(fcntl.fcntl(opened, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
                        self.assertFalse(os.get_inheritable(opened))
                    (group / "memory.max").write_text("2147483648\n")
                    self.assertEqual(backend._read_ci_control(controls, "memory.max"), "2147483648")
                    opened = controls["memory.max"][0]
                    os.close(opened)
                    with self.assertRaises(OSError) as error:
                        backend._read_ci_control(controls, "memory.max")
                    self.assertEqual(error.exception.errno, 9)
                    controls.pop("memory.max")
                finally:
                    backend._close_ci_controls(controls)
            finally:
                os.close(fd)

    def test_partial_open_failure_closes_every_prior_control(self):
        self.assertTrue(callable(getattr(backend, "_open_ci_controls", None)), "need partial descriptor cleanup")
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory:
            group = Path(directory)
            self.fixture(group)
            real_open = os.open
            opened = []

            def port(name, *args, **kwargs):
                if name == "pids.max":
                    raise PermissionError(13, "owned fixture refusal")
                fd = real_open(name, *args, **kwargs)
                opened.append(fd)
                return fd

            fd = real_open(group, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with (
                    mock.patch.object(os, "open", side_effect=port),
                    self.assertRaises(backend.BackendUnavailable) as error,
                ):
                    backend._open_ci_controls(fd)
                self.assertEqual(error.exception.detail["errno"], 13)
                self.assertEqual(error.exception.detail["command_id"], "ci-control-pids.max")
                self.assertEqual(len(opened), 2)
                for previous in opened:
                    with self.assertRaises(OSError):
                        os.fstat(previous)
            finally:
                os.close(fd)

    def test_reused_foreign_descriptor_is_neither_read_nor_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory:
            group = Path(directory)
            self.fixture(group)
            (group / "foreign").write_text("owned unread foreign fixture")
            parent = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
            controls = backend._open_ci_controls(parent)
            original = controls["memory.max"][0]
            os.close(original)
            foreign = os.open(group / "foreign", os.O_RDONLY | os.O_CLOEXEC)
            if foreign != original:
                os.dup2(foreign, original, inheritable=False)
                os.close(foreign)
                foreign = original
            try:
                with mock.patch.object(os, 'pread', return_value=b'owned unread foreign fixture') as reader:
                    with self.assertRaises(ValueError):
                        backend._read_ci_control(controls, "memory.max")
                    reader.assert_not_called()
                with self.assertRaises(backend.BackendUnavailable):
                    backend._close_ci_controls(controls)
                self.assertTrue(stat.S_ISREG(os.fstat(foreign).st_mode))
            finally:
                os.close(foreign)
                backend._close_ci_controls(controls)
                os.close(parent)


@unittest.skipUnless(
    sys.platform == "linux"
    and getattr(os, "geteuid", lambda: -1)() == 0
    and os.environ.get("SUDO_UID", "").isdecimal()
    and int(os.environ.get("SUDO_UID", "0")) > 0,
    "requires explicit owned root ordinaryFS probe and real caller UID; not a kernel test",
)
class RootControlHandoffTests(unittest.TestCase):
    def test_real_root700_dropuid_keeps_fresh_readonly_proof(self):
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory:
            base = Path(directory)
            os.chown(base, uid, gid)
            volume, group = base / "volume", base / "root-controls"
            volume.mkdir(mode=0o700)
            group.mkdir(mode=0o700)
            os.chown(volume, uid, gid)
            for name, value in zip(NAMES, VALUES):
                (group / name).write_text(value + "\n")
                (group / name).chmod(0o444)
            self.assertEqual((group.stat().st_uid, stat.S_IMODE(group.stat().st_mode)), (0, 0o700))
            vfd = os.open(volume, os.O_RDONLY | os.O_DIRECTORY)
            cfd = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
            opener = getattr(backend, "_open_ci_controls", None)
            controls = opener(cfd) if opener else {}
            vi, gi = os.fstat(vfd), os.fstat(cfd)
            guard = (
                volume,
                object(),
                [],
                dict(
                    ci_corpus=True,
                    volume_fd=vfd,
                    cgroup_fd=cfd,
                    volume_identity=(vi.st_dev, vi.st_ino),
                    cgroup_root_device=gi.st_dev,
                    cgroup_root_inode=gi.st_ino,
                    controls=controls,
                ),
            )
            read, write = os.pipe()
            ack, send = os.pipe()
            child = None
            reaped = False
            try:
                child = os.fork()
                if child == 0:
                    try:
                        os.close(read)
                        os.close(send)
                        os.setgroups([])
                        os.setgid(gid)
                        os.setuid(uid)
                        real_stat = os.stat
                        with ExitStack() as stack:
                            stack.enter_context(mock.patch.object(backend, "_GUARD", guard))
                            stack.enter_context(
                                mock.patch.object(
                                    backend,
                                    "_filesystem",
                                    side_effect=lambda p: 0x63677270 if str(p) == "/sys/fs/cgroup" else 0x01021994,
                                )
                            )
                            stack.enter_context(
                                mock.patch.object(
                                    os,
                                    "stat",
                                    side_effect=lambda p, **kw: (
                                        gi if str(p) == "/sys/fs/cgroup" else real_stat(p, **kw)
                                    ),
                                )
                            )
                            stack.enter_context(
                                mock.patch.object(
                                    os,
                                    "fstatvfs",
                                    return_value=SimpleNamespace(
                                        f_blocks=8 * 1024**3 // 4096, f_frsize=4096, f_flag=os.ST_NOSUID | os.ST_NODEV
                                    ),
                                )
                            )
                            if not select.select([ack], [], [], 3)[0] or os.read(ack, 1) != b"1":
                                os._exit(3)
                            initial = False
                            error = None
                            try:
                                initial = backend.measured_ci_profile()
                            except backend.BackendUnavailable as fault:
                                error = dict(detail=fault.detail, cause_errno=getattr(fault.__cause__, "errno", None))
                            os.write(write, (json.dumps(dict(initial=initial, error=error)) + "\n").encode())
                            if initial:
                                if not select.select([ack], [], [], 3)[0] or os.read(ack, 1) != b"2":
                                    os._exit(4)
                                changed = None
                                try:
                                    backend.measured_ci_profile()
                                except backend.BackendUnavailable as fault:
                                    changed = fault.detail
                                os.close(controls["memory.max"][0])
                                stale = None
                                try:
                                    backend.measured_ci_profile()
                                except backend.BackendUnavailable as fault:
                                    stale = fault.detail
                                os.write(write, (json.dumps(dict(changed=changed, stale=stale)) + "\n").encode())
                        os._exit(0)
                    except BaseException:
                        os._exit(5)
                os.close(write)
                write = None
                os.close(ack)
                ack = None
                (group / "cgroup.procs").write_text(str(child) + "\n")
                os.write(send, b"1")
                self.assertTrue(select.select([read], [], [], 4)[0], "bounded child initial result")
                initial = json.loads(os.read(read, 4096))
                if initial["initial"]:
                    (group / "memory.max").write_text("2147483648\n")
                    os.write(send, b"2")
                    self.assertTrue(select.select([read], [], [], 4)[0], "bounded live reread result")
                    changed = json.loads(os.read(read, 4096))
                    self.assertEqual(changed["changed"]["command_id"], "ci-control-memory.max")
                    self.assertEqual(changed["stale"]["command_id"], "ci-control-memory.max")
                    self.assertEqual(changed["stale"]["errno"], 9)
                deadline = time.monotonic() + 3
                while True:
                    observed, status = os.waitpid(child, os.WNOHANG)
                    if observed:
                        reaped = True
                        self.assertEqual(status, 0)
                        break
                    if time.monotonic() >= deadline:
                        self.fail("bounded child reap")
                    time.sleep(0.01)
                self.assertTrue(
                    initial["initial"], "root0700/dropUID refusal: " + json.dumps(initial["error"], sort_keys=True)
                )
            finally:
                if child and not reaped:
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(child, 0)
                for fd in (read, write, ack, send, vfd, cfd):
                    if fd is not None:
                        os.close(fd)
                if controls:
                    backend._close_ci_controls(controls)
