"""Owned Linux BuildKit port: one hard tmpfs, namespace, cgroup and deadline.

This port needs root on an ephemeral runner. It never uses a Docker socket.
The caller must select this reviewed producer and the independently pinned
BuildKit distribution. Missing kernel capabilities are prerequisites, not PASS.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from fractions import Fraction
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import select
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from .security_oci import LIMITS, _Root

_ACTIVE = object()
_GUARD = None
_ROOT = Path(__file__).resolve().parents[1]
_BOOT = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
         'import sysconfig;sys.path.extend(sorted(set(sysconfig.get_paths()[k] for k in ("purelib","platlib"))));'
         'from getzilla.security_image_producer import _entry;raise SystemExit(_entry())')


class BackendUnavailable(ValueError):
    def __init__(self, message, *, detail=None):
        super().__init__(message)
        self.detail = dict(detail or {})


def _diagnostic(raw):
    raw = bytes(raw[:4097])
    def redact(value):
        value = value.decode('utf-8', errors='replace')
        value = re.sub(r'https?://\S+|/[A-Za-z0-9_./:-]+', '<path-or-url>', value)
        return re.sub(r'[A-Za-z0-9_+/=-]{48,}', '<opaque>', value)
    return {'captured_bytes': len(raw), 'captured_sha256': hashlib.sha256(raw).hexdigest(),
            'first': redact(raw[:512]), 'last': redact(raw[-512:])}


def _filesystem(path):
    # Linux statfs has ample trailing space on all supported 64-bit Linux ABIs.
    result = (ctypes.c_long * 32)()
    if ctypes.CDLL(None, use_errno=True).statfs(os.fsencode(path), ctypes.byref(result)):
        raise BackendUnavailable('cannot establish backend filesystem identity')
    return result[0]


def _fixed(command, *, timeout=10):
    from .architecture_diff import _run_capped, ArchitectureError
    if command[1:2] == ['--make-rprivate']:
        command_id = 'mount-propagation'
    elif command[1:3] == ['-t', 'cgroup2']:
        command_id = 'mount-cgroup'
    elif command[1:3] == ['-t', 'tmpfs']:
        command_id = 'mount-image-volume'
    elif command[0] == '/usr/bin/umount':
        command_id = 'unmount-' + {'/sys/fs/cgroup': 'cgroup-view', '/run': 'run',
            '/tmp': 'tmp', '/var/tmp': 'var-tmp'}.get(command[-1], 'owned-volume')
    elif command[-1] == '/sys/fs/cgroup':
        command_id = 'bind-owned-cgroup-root'
    elif command[-1] in {'/run', '/tmp', '/var/tmp'}:
        command_id = 'mask-' + command[-1].lstrip('/').replace('/', '-')
    else:
        command_id = 'bind-owned-volume'
    detail = dict(phase='kernel-command', command_id=command_id, errno=None, exit_code=None)
    try:
        code, _, stderr = _run_capped(command, cwd=_ROOT,
            env={'PATH': os.defpath, 'LANG': 'C'}, stdin_data=None,
            stdout_limit=1024, stderr_limit=4096, timeout=timeout)
    except (OSError, ArchitectureError) as error:
        detail['errno'] = getattr(error, 'errno', None)
        raise BackendUnavailable('bounded kernel command incomplete', detail=detail) from None
    if code:
        detail.update(exit_code=code, stderr=_diagnostic(stderr))
        raise BackendUnavailable('kernel command refused', detail=detail)


def _kill(cgroup):
    """Kill and observe empty owned cgroup before its directory can be removed."""
    (cgroup / 'cgroup.kill').write_text('1')
    deadline = time.monotonic() + 10
    while 'populated 1' in (cgroup / 'cgroup.events').read_text():
        if time.monotonic() >= deadline:
            raise BackendUnavailable('owned image cgroup did not become empty')
        time.sleep(.02)
    # runc can create children only below the dedicated cgroup namespace root.
    # Remove empty descendant directories from this unique owned subtree only.
    directories, pending = [], [(cgroup, 0)]
    while pending:
        current, depth = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                if time.monotonic() >= deadline:
                    raise BackendUnavailable('owned cgroup cleanup deadline exceeded')
                if entry.is_dir(follow_symlinks=False):
                    if len(directories) >= 10000 or depth >= 64:
                        raise BackendUnavailable('owned cgroup cleanup exceeds finite member bound')
                    path = Path(entry.path)
                    directories.append(path)
                    pending.append((path, depth + 1))
    for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        path.rmdir()


def _reap_children():
    deadline = time.monotonic() + 10
    while True:
        try:
            child, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if not child:
            if time.monotonic() >= deadline:
                raise BackendUnavailable('owned descendant reap did not complete')
            time.sleep(.02)


def _configure_cgroup(cgroup, bounds):
    from .startup_cpu import parse_cpu_list, format_cpu_list
    available = set(os.sched_getaffinity(0))
    if bounds.get('effective_cpuset'):
        available &= parse_cpu_list(bounds['effective_cpuset'])
    cpus = set(sorted(available)[:6])
    if not cpus:
        raise BackendUnavailable('image worker has no observed allowed CPUs')
    quotas = [Fraction(len(cpus))]
    for level in bounds['levels']:
        value = level.get('cpu.max')
        if value:
            quota, period = value.split()
            if quota != 'max':
                quotas.append(Fraction(int(quota), int(period)))
    quota = int(min(quotas) * 100000)
    if quota <= 0:
        raise BackendUnavailable('observed inherited CPU quota cannot be safely represented')
    controls = {'memory.max': str(2 * 1024 * 1024 * 1024), 'memory.swap.max': '0',
                'pids.max': '256', 'cpu.max': f'{quota} 100000'}
    for name, value in controls.items():
        path = cgroup / name
        if not path.is_file():
            raise BackendUnavailable('delegated finite image cgroup controls unavailable',
                detail={'phase': 'admission', 'command_id': 'cgroup-' + name})
        path.write_text(value)
        if path.read_text().strip() != value:
            raise BackendUnavailable('image cgroup control readback differs',
                detail={'phase': 'admission', 'command_id': 'cgroup-' + name})
    if (cgroup / 'cpuset.cpus').is_file():
        memory_nodes = (cgroup.parent / 'cpuset.mems.effective').read_text().strip()
        if not memory_nodes:
            raise BackendUnavailable('delegated image cpuset memory nodes are unknown')
        (cgroup / 'cpuset.mems').write_text(memory_nodes)
        (cgroup / 'cpuset.cpus').write_text(format_cpu_list(cpus))
        effective = parse_cpu_list((cgroup / 'cpuset.cpus.effective').read_text().strip())
        if effective != cpus:
            raise BackendUnavailable('delegated image cpuset readback differs')
    return sorted(cpus)


def _collect_pipeline(process, *, started=None, kernel_control=False):
    diagnostic, state = bytearray(), {'phase': 'producer'}
    try:
        return _collect_pipeline_inner(process, diagnostic, state, started=started, kernel_control=kernel_control)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        detail = dict(getattr(error, 'detail', {}))
        detail.update(phase=state['phase'], errno=getattr(error, 'errno', None),
                      exit_code=process.poll(), stderr=_diagnostic(diagnostic))
        for line in bytes(diagnostic).splitlines():
            try:
                value = json.loads(line)
                if isinstance(value, dict) and set(value) == {'fault'}:
                    detail.setdefault('worker_fault', value['fault'])
            except (ValueError, UnicodeError):
                pass
        raise BackendUnavailable('owned image pipeline incomplete', detail=detail) from None


def _collect_pipeline_inner(process, diagnostic, state, *, started=None, kernel_control=False):
    """Finite four-stage protocol; preparation keeps its original hard 600s."""
    from .security_oci import document
    phases = iter([('declare', 600), ('prepare', 600), ('evaluate', 1800), ('result', 0)])
    expected, budget = next(phases)
    started = time.monotonic() if started is None else started
    overall = started + (10 if kernel_control else 1800)
    deadline = min(overall, started + LIMITS['deadline_seconds'])
    output, pending = bytearray(), bytearray()
    with selectors.DefaultSelector() as selector:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = min(deadline, overall) - time.monotonic()
            if remaining <= 0:
                raise BackendUnavailable('owned image pipeline stage deadline exceeded')
            for key, _ in selector.select(remaining):
                stream = key.fileobj
                target = output if stream is process.stdout else diagnostic
                maximum = 8 * 1024 * 1024 if stream is process.stdout else 4096
                part = os.read(stream.fileno(), min(65536, maximum + 1 - len(target)))
                if not part:
                    selector.unregister(stream)
                    continue
                target.extend(part)
                if len(target) > maximum:
                    raise BackendUnavailable('image pipeline IPC exceeds finite bound')
                if stream is process.stdout:
                    pending.extend(part)
                    while b'\n' in pending:
                        line, _, rest = pending.partition(b'\n')
                        pending = bytearray(rest)
                        value = document(line)
                        if expected == 'result':
                            if set(value) != {'result'}:
                                raise BackendUnavailable('image pipeline result protocol differs')
                            expected = 'end'
                        else:
                            if value != {'stage': expected}:
                                raise BackendUnavailable('image pipeline stage order differs')
                            deadline = min(overall, time.monotonic() + budget)
                            state['phase'] = expected
                            expected, budget = next(phases)
        if pending or expected != 'end':
            raise BackendUnavailable('image pipeline protocol incomplete')
    remaining = min(deadline, overall) - time.monotonic()
    if remaining <= 0 or process.wait(timeout=remaining):
        raise BackendUnavailable('image pipeline child did not complete')
    return document(bytes(output).splitlines()[-1])['result']


def _retain_fault(workspace, detail):
    from .security_oci import _Root, canonical
    root = _Root(workspace)
    directory = None
    try:
        try:
            os.mkdir('image-faults', 0o700, dir_fd=root.fd)
        except FileExistsError:
            pass
        directory = os.open('image-faults', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root.fd)
        uid = int(os.environ.get('SUDO_UID', os.getuid()))
        gid = int(os.environ.get('SUDO_GID', os.getgid()))
        if os.fstat(directory).st_mode & 0o077:
            raise BackendUnavailable('private fault directory permissions refused')
        os.fchown(directory, uid, gid)
        name = uuid.uuid4().hex + '.json'
        raw = canonical(detail)
        if len(raw) > 16384:
            raise BackendUnavailable('private fault record exceeds finite bound')
        for leaf, body in ((name, raw), ('last-fault-' + name, canonical(
                {'artifact': name, 'sha256': hashlib.sha256(raw).hexdigest()}))):
            fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchown(stream.fileno(), uid, gid)
        os.replace('last-fault-' + name, 'last-fault.json', src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if directory is not None:
            os.close(directory)
        root.close()


def run_guarded(payload, workspace, *, owned_root=None, started=None):
    try:
        return _run_guarded(payload, workspace, owned_root=owned_root, started=started)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = dict(getattr(error, 'detail', {}))
        detail.setdefault('phase', 'admission-or-cleanup')
        detail.setdefault('command_id', 'owned-supervisor')
        detail.setdefault('errno', getattr(error, 'errno', None))
        detail.setdefault('exit_code', None)
        try:
            _retain_fault(workspace, detail)
        except (OSError, ValueError) as retention:
            detail['fault_retention_errno'] = getattr(retention, 'errno', None)
        raise BackendUnavailable('bounded image backend refused', detail=detail) from None


def _run_guarded(payload, workspace, *, owned_root=None, started=None):
    """Outer root supervisor. Deadline includes namespace opening and all work."""
    born = time.monotonic() if started is None else started
    if not 0 <= time.monotonic() - born <= LIMITS['deadline_seconds']:
        raise BackendUnavailable('image producer opening deadline expired')
    if sys.platform != 'linux' or os.geteuid() != 0 or _filesystem('/sys/fs/cgroup') != 0x63677270:
        raise BackendUnavailable('ephemeral root with writable cgroup v2 is required')
    if len(payload) > 65536:
        raise BackendUnavailable('image worker request exceeds finite byte bound')
    from .security_oci import document
    selected = document(payload)
    offline_control = isinstance(selected, dict) and selected.get('kind') == 'offline-tool-control'
    kernel_control = selected == {'kind': 'kernel-self-test'} or offline_control
    from .startup_cpu import cgroup_bounds
    bounds = cgroup_bounds()
    if bounds.get('cgroup_version') != 2 or not bounds.get('levels'):
        raise BackendUnavailable('current inherited image cgroup membership is unknown')
    parent = Path(bounds['levels'][0]['path'])
    if owned_root is not None:
        owned_root = Path(owned_root)
        if (not re.fullmatch(r'getzilla-image-job-[0-9a-f]{32}\.scope', owned_root.name)
                or parent != owned_root / 'supervisor' or len(bounds['levels']) < 2
                or Path(bounds['levels'][1]['path']) != owned_root):
            raise BackendUnavailable('image supervisor differs from its explicit owned job')
        for name in ('memory.max', 'memory.swap.max', 'pids.max'):
            if (parent / name).read_text().strip() != 'max':
                raise BackendUnavailable('finite supervisor subgroup bound cannot be bypassed')
        if (parent / 'cpu.max').read_text().split()[0] != 'max':
            raise BackendUnavailable('finite supervisor CPU bound cannot be bypassed')
        parent = owned_root
    if _filesystem(parent) != 0x63677270:
        raise BackendUnavailable('current image cgroup parent is not a measured cgroup v2 mount')
    library = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if library.prctl(37, ctypes.byref(previous), 0, 0, 0) or library.prctl(36, 1, 0, 0, 0):
        raise BackendUnavailable('owned child subreaper is unavailable')
    cgroup = parent / ('getzilla-images-' + uuid.uuid4().hex)
    cgroup.mkdir(mode=0o700)
    try:
        cpus = _configure_cgroup(cgroup, bounds)
        if not (cgroup / 'cgroup.kill').is_file():
            raise BackendUnavailable('kernel cgroup.kill is required')
        with tempfile.TemporaryDirectory(prefix='image-volume-', dir=workspace) as directory:
            # First fixed child joins the cgroup before exec/unshare. No candidate
            # command or environment controls this bootstrap.
            join = ('import os,sys,json;os.sched_setaffinity(0,json.loads(sys.argv[2]));'
                    'open(sys.argv[1]+"/cgroup.procs","w").write(str(os.getpid()));'
                    'os.execv("/usr/bin/unshare",sys.argv[3:])')
            worker = [sys.executable, '-I', '-S', '-B', '-c', _BOOT, str(_ROOT),
                      directory, str(cgroup)]
            command = [sys.executable, '-I', '-S', '-B', '-c', join, str(cgroup), json.dumps(cpus),
                       '/usr/bin/unshare', '--mount', '--cgroup', '--pid', '--fork', '--kill-child=KILL',
                       '--mount-proc', *(['--net'] if offline_control else []), *worker]
            process = None
            with tempfile.TemporaryFile() as request:
                request.write(payload)
                request.seek(0)
                try:
                    environment = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
                    for key in ('SUDO_UID', 'SUDO_GID'):
                        if os.environ.get(key, '').isdecimal():
                            environment[key] = os.environ[key]
                    process = subprocess.Popen(command, cwd=_ROOT, env=environment,
                        stdin=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                    return _collect_pipeline(process, started=born, kernel_control=kernel_control)
                finally:
                    fault = sys.exception()
                    _kill(cgroup)
                    if process is not None:
                        if process.poll() is None:
                            os.killpg(process.pid, 9)
                        process.wait(timeout=10)
                        if isinstance(fault, BackendUnavailable):
                            fault.detail['exit_code'] = process.returncode
                        process.stdout.close()
                        process.stderr.close()
                        _reap_children()
    finally:
        # The immediate child is reaped; cgroup.kill also reaches daemon
        # workers which changed process groups or sessions.
        fault = sys.exception()
        if isinstance(fault, BackendUnavailable):
            fault.detail['owned_cgroup'] = str(cgroup)
        _kill(cgroup)
        cgroup.rmdir()
        library.prctl(36, previous.value, 0, 0, 0)


@contextmanager
def namespace_volume(path, cgroup):
    """Called only by the fixed worker after unshare; mount proof is measured."""
    global _GUARD
    path, cgroup = Path(path), Path(cgroup)
    if _GUARD is not None:
        raise BackendUnavailable('nested image namespace is forbidden')
    if any(path.is_relative_to(base) for base in map(Path, ('/run', '/tmp', '/var/tmp'))):
        raise BackendUnavailable('image volume must use canonical runtime outside masked system temporaries')
    if (os.geteuid() != 0 or os.getpid() != 1
            or not re.fullmatch(r'getzilla-images-[0-9a-f]{32}', cgroup.name)
            or not cgroup.is_absolute() or '..' in cgroup.parts):
        raise BackendUnavailable('invalid image namespace owner')
    if str(os.getpid()) not in (cgroup / 'cgroup.procs').read_text().split():
        raise BackendUnavailable('image worker is outside its owned cgroup')
    if Path('/proc/self/cgroup').read_text().strip() != '0::/':
        raise BackendUnavailable('image worker lacks its dedicated cgroup namespace')
    _fixed(['/usr/bin/mount', '--make-rprivate', '/'])
    held = _Root(cgroup)
    try:
        expected = os.fstat(held.fd)
        _fixed(['/usr/bin/mount', '--bind', str(cgroup), '/sys/fs/cgroup'])
        actual = _Root('/sys/fs/cgroup')
        try:
            observed = os.fstat(actual.fd)
            flags = os.fstatvfs(actual.fd).f_flag
            required = os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC
            if ((observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino)
                    or _filesystem('/sys/fs/cgroup') != 0x63677270 or flags & required != required):
                raise BackendUnavailable('mounted cgroup root differs from held owned subtree')
        finally:
            actual.close()
    finally:
        held.close()
    controls = {name: (Path('/sys/fs/cgroup') / name).read_text().strip()
                for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    quota, period = controls['cpu.max'].split()
    if (controls['memory.max'] != str(2 * 1024 * 1024 * 1024) or controls['memory.swap.max'] != '0'
            or controls['pids.max'] != '256' or quota == 'max'
            or not 0 < int(quota) <= 6 * int(period) or not 0 < len(os.sched_getaffinity(0)) <= 6):
        raise BackendUnavailable('live image namespace resource controls differ from admitted bounds')
    _fixed(['/usr/bin/mount', '-t', 'tmpfs', '-o',
            f'size={LIMITS["max_storage_bytes"]},mode=0700,nosuid,nodev', 'getzilla-images', str(path)])
    try:
        info = os.statvfs(path)
        if _filesystem(path) != 0x01021994 or info.f_blocks * info.f_frsize != LIMITS['max_storage_bytes']:
            raise BackendUnavailable('image volume is not the exact hard-bounded tmpfs')
        # runc's ordinary /run state and helpers which ignore TMPDIR must share
        # this same volume. No second tmpfs or host daemon storage is available.
        with open('/etc/resolv.conf', 'rb') as source:
            resolver = source.read(65537)
        if len(resolver) > 65536:
            raise BackendUnavailable('runner resolver configuration exceeds bound')
        for name in ('run', 'tmp', 'var-tmp'):
            (path / name).mkdir(mode=0o700)
        for name in ('resolv.conf', 'stub-resolv.conf'):
            target = path / 'run/systemd/resolve' / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(resolver)
        mounted = []
        for name, target in (('run', '/run'), ('tmp', '/tmp'), ('var-tmp', '/var/tmp')):
            _fixed(['/usr/bin/mount', '--bind', str(path / name), target])
            mounted.append(target)
        _GUARD = (path, object(), mounted, {'cgroup_root_device': expected.st_dev,
                    'cgroup_root_inode': expected.st_ino, 'cgroup_mount_flags': flags})
        try:
            yield path
        finally:
            _GUARD = None
            # The fixed unshare child is PID 1 in its new PID namespace. This
            # signal cannot address host processes; reap all adopted workers.
            try:
                os.kill(-1, 9)
            except ProcessLookupError:
                pass
            _reap_children()
            for target in reversed(mounted):
                _fixed(['/usr/bin/umount', target])
    finally:
        # No lazy/forced unmount: remaining users are a real cleanup failure.
        try:
            _fixed(['/usr/bin/umount', str(path)])
        finally:
            _fixed(['/usr/bin/umount', '/sys/fs/cgroup'])


class BuildKit:
    def __init__(self, volume, *, archive, deadline):
        self.volume, self.deadline, self.process, self.log = Path(volume), deadline, None, None
        self.owner_pid, self.pidfd = os.getpid(), None
        if _GUARD is None or _GUARD[0] != self.volume:
            raise BackendUnavailable('BuildKit requires a measured live namespace volume')
        self.guard = _GUARD
        from .security_image_provision import archive_bytes, extract_tools
        # Open/identity-check a finite archive, verify the SOURCE distribution
        # pin, and copy its held bytes. Caller JSON hashes grant no authority.
        raw = archive_bytes(archive)
        directory = self.volume / 'pinned-bin'
        tools = extract_tools(io.BytesIO(raw), directory)
        for tool in tools.values():
            os.chmod(tool['path'], 0o555)
        os.chmod(directory, 0o555)
        # A held read-only bind mount prevents leaf replacement or changing the
        # executable through its name between verification and exec.
        _fixed(['/usr/bin/mount', '--bind', str(directory), str(directory)])
        self.guard[2].append(str(directory))
        _fixed(['/usr/bin/mount', '-o', 'remount,bind,ro', str(directory)])
        self.daemon, self.client, self.runc = (tools[key]['path'] for key in ('buildkitd', 'buildctl', 'buildkit-runc'))
        self.tool_identities = tools
        self.socket = _socket_alias(self.volume)
        self.address = 'unix://' + str(self.socket)
        self.env = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'HOME': str(self.volume / 'home'),
                    'TMPDIR': str(self.volume / 'tmp')}

    def __enter__(self):
        if os.getpid() != self.owner_pid:
            raise BackendUnavailable('only the daemon owner may start BuildKit')
        for name in ('home', 'cache'):
            (self.volume / name).mkdir(mode=0o700)
        config = self.volume / 'buildkit.toml'
        config.write_text('[worker.oci]\ndefaultCgroupParent = "/"\n')
        log_fd = os.open(self.volume / 'buildkit-startup.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.log = os.fdopen(log_fd, 'wb')
        try:
            self.process = subprocess.Popen([self.daemon, '--config', str(config), '--root', str(self.volume / 'cache'),
                '--addr', self.address, '--oci-worker-snapshotter', 'native', '--oci-worker-binary', self.runc,
                '--containerd-worker=false'],
                env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.log)
            self.pidfd = os.pidfd_open(self.process.pid)
            os.set_inheritable(self.pidfd, False)
            while not self.socket.exists():
                if self.process.poll() is not None or time.monotonic() >= self.deadline:
                    self.log.flush()
                    with open(self.volume / 'buildkit-startup.log', 'rb') as stream:
                        diagnostic = stream.read(4097)
                    raise BackendUnavailable('owned BuildKit daemon did not become ready', detail=dict(
                        phase='buildkit-startup', command_id='buildkitd-owned', exit_code=self.process.poll(),
                        errno=None, stderr=_diagnostic(diagnostic)))
                time.sleep(.02)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _daemon_alive(self):
        if self.pidfd is None:
            return False
        poller = select.poll()
        poller.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        return not poller.poll(0)

    def handoff_client(self, uid, gid):
        if os.getpid() != self.owner_pid or uid <= 0 or gid <= 0 or not stat.S_ISSOCK(self.socket.lstat().st_mode):
            raise BackendUnavailable('invalid owned BuildKit client handoff')
        for path in (self.volume, self.volume / 'home', self.volume / 'tmp', self.socket):
            os.chown(path, uid, gid, follow_symlinks=False)

    def build(self, recipe, context, output, *, offline_control=False):
        from .architecture_diff import _run_capped, ArchitectureError
        if self.guard is not _GUARD or not self._daemon_alive():
            raise BackendUnavailable('owned BuildKit lifetime ended')
        arguments = [self.client, '--addr', self.address, 'build', '--frontend', 'dockerfile.v0',
                     '--local', 'context=' + str(context), '--local', 'dockerfile=' + str(context),
                     '--opt', 'filename=' + str(Path(recipe['dockerfile']).relative_to(recipe['context'])),
                     '--opt', 'platform=' + recipe['platform'], '--opt', 'force-network-mode=' + ('none' if offline_control else 'sandbox'),
                     '--output', 'type=oci,oci-mediatypes=true,compression=gzip,dest=' + str(output)]
        for key, value in sorted(recipe['arguments'].items()):
            arguments.extend(['--opt', 'build-arg:' + key + '=' + value])
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BackendUnavailable('image producer aggregate deadline exceeded')
        try:
            code, _, stderr = _run_capped(arguments, cwd=context, env=self.env, stdin_data=None,
                stdout_limit=1024 * 1024, stderr_limit=1024 * 1024, timeout=remaining)
        except (OSError, ArchitectureError):
            raise BackendUnavailable('owned image build incomplete') from None
        if code:
            detail = dict(phase='build', command_id='buildctl-build', exit_code=code, errno=None,
                          stderr_captured_sha256=hashlib.sha256(stderr).hexdigest())
            if offline_control:
                detail['stderr'] = _diagnostic(stderr)  # Only the fixed owned scratch fixture.
            raise BackendUnavailable('owned image build failed; no build proof was issued', detail=detail)
        if not self._daemon_alive():
            raise BackendUnavailable('owned daemon ended before build completion was observed')
        # Only this actual process completion path can return the private marker.
        return _ACTIVE

    def __exit__(self, *_):
        try:
            if self.process is not None and os.getpid() == self.owner_pid:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            if self.log is not None:
                self.log.close()
            if self.pidfd is not None:
                os.close(self.pidfd)
                self.pidfd = None


def _socket_alias(volume):
    expected = _Root(Path(volume) / 'tmp')
    try:
        alias = _Root('/tmp')
        try:
            a, b = os.fstat(expected.fd), os.fstat(alias.fd)
            if ((a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) or b.st_mode & 0o077
                    or _filesystem('/tmp') != 0x01021994):
                raise BackendUnavailable('short socket alias differs from owned private volume')
            return Path('/tmp/getzilla-buildkit.sock')
        finally:
            alias.close()
    finally:
        expected.close()
