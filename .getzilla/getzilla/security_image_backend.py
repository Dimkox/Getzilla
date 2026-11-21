"""Owned Linux BuildKit port: one hard tmpfs, namespace, cgroup and deadline.

This port needs root on an ephemeral runner. It never uses a Docker socket.
The caller must select this reviewed producer and the independently pinned
BuildKit distribution. Missing kernel capabilities are prerequisites, not PASS.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
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

from .security_oci import LIMITS, CI_BYTES, CI_MEMORY, _Root
from . import security_image_authority as authority
from .security_image_authority import (  # noqa: F401 compatibility aliases for immutable helpers/seal
    BackendUnavailable,
    _ACTIVE,
    _CI_CONTROLS,
    _ci_control_identity,
    _filesystem,
    _read_ci_control,
    _readonly_control,
    measured_ci_profile,
)

_ROOT = Path(__file__).resolve().parents[1]
_BOOT = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
         'import sysconfig;sys.path.extend(sorted(set(sysconfig.get_paths()[k] for k in ("purelib","platlib"))));'
         'from getzilla.security_image_producer import _entry;raise SystemExit(_entry())')


def _diagnostic(raw):
    raw = bytes(raw)  # Callers already cap complete captures at no more than 1 MiB.
    def redact(value):
        value = value.decode('utf-8', errors='replace')
        value = re.sub(r'https?://\S+|/[A-Za-z0-9_./:-]+', '<path-or-url>', value)
        return re.sub(r'[A-Za-z0-9_+/=-]{48,}', '<opaque>', value)
    # Redact before slicing so a boundary cannot expose a URL/token fragment.
    safe = redact(raw)
    def retain(value, *, tail=False):
        # Bound serialized text too: Unicode/control escaping must fit the
        # existing nested 4096-byte worker IPC, without changing that cap.
        while len(json.dumps(value, ensure_ascii=True).encode('utf-8')) > 512:
            value = value[1:] if tail else value[:-1]
        return value
    return {'captured_bytes': len(raw), 'captured_sha256': hashlib.sha256(raw).hexdigest(),
            'first': retain(safe[:512]), 'last': retain(safe[-512:], tail=True)}


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
            # Fixed unmount arguments map to diagnostic labels; no temporary file is created.
            '/tmp': 'tmp', '/var/tmp': 'var-tmp'}.get(command[-1], 'owned-volume')  # nosec B108
    elif command[-1] == '/sys/fs/cgroup':
        command_id = 'bind-owned-cgroup-root'
    # Fixed path comparison selects a diagnostic label, not a temporary file.
    elif command[-1] in {'/run', '/tmp', '/var/tmp'}:  # nosec B108
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
    (cgroup / 'cgroup.kill').write_text('1', encoding='utf-8', newline='\n')
    deadline = time.monotonic() + 10
    while 'populated 1' in (cgroup / 'cgroup.events').read_text(encoding='utf-8'):
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


def _configure_cgroup(cgroup, bounds, *, ci_corpus=False):
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
    controls = {'memory.max': str(CI_MEMORY if ci_corpus else 2 * 1024 ** 3), 'memory.swap.max': '0',
                'pids.max': '256', 'cpu.max': f'{quota} 100000'}
    for name, value in controls.items():
        path = cgroup / name
        if not path.is_file():
            raise BackendUnavailable('delegated finite image cgroup controls unavailable',
                detail={'phase': 'admission', 'command_id': 'cgroup-' + name})
        path.write_text(value, encoding='utf-8', newline='\n')
        if path.read_text(encoding='utf-8').strip() != value:
            raise BackendUnavailable('image cgroup control readback differs',
                detail={'phase': 'admission', 'command_id': 'cgroup-' + name})
    if (cgroup / 'cpuset.cpus').is_file():
        memory_nodes = (cgroup.parent / 'cpuset.mems.effective').read_text(encoding='utf-8').strip()
        if not memory_nodes:
            raise BackendUnavailable('delegated image cpuset memory nodes are unknown')
        (cgroup / 'cpuset.mems').write_text(memory_nodes, encoding='utf-8', newline='\n')
        (cgroup / 'cpuset.cpus').write_text(format_cpu_list(cpus), encoding='utf-8', newline='\n')
        effective = parse_cpu_list((cgroup / 'cpuset.cpus.effective').read_text(encoding='utf-8').strip())
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


def run_guarded(payload, workspace, *, owned_root=None, started=None, ci_corpus=False):
    try:
        return _run_guarded(payload, workspace, owned_root=owned_root, started=started, ci_corpus=ci_corpus)
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


def _run_guarded(payload, workspace, *, owned_root=None, started=None, ci_corpus=False):
    """Outer root supervisor. Deadline includes namespace opening and all work."""
    born = time.monotonic() if started is None else started
    if not 0 <= time.monotonic() - born <= LIMITS['deadline_seconds']:
        raise BackendUnavailable('image producer opening deadline expired')
    if sys.platform != 'linux' or os.geteuid() != 0 or authority._filesystem('/sys/fs/cgroup') != 0x63677270:
        raise BackendUnavailable('ephemeral root with writable cgroup v2 is required')
    if len(payload) > 65536:
        raise BackendUnavailable('image worker request exceeds finite byte bound')
    from .security_oci import document
    selected = document(payload)
    offline_control = isinstance(selected, dict) and selected.get('kind') == 'offline-tool-control'
    kernel_control = selected == {'kind': 'kernel-self-test'} or offline_control
    if ci_corpus and (kernel_control or not isinstance(selected, dict) or selected.get('kind') != 'pipeline'):
        raise BackendUnavailable('CI corpus mode is only for the owned producer pipeline')
    from .startup_cpu import cgroup_bounds
    bounds = cgroup_bounds()
    if bounds.get('cgroup_version') != 2 or not bounds.get('levels'):
        raise BackendUnavailable('current inherited image cgroup membership is unknown')
    parent = Path(bounds['levels'][0]['path'])
    if ci_corpus and owned_root is None:
        raise BackendUnavailable('CI corpus requires its explicit owned job scope')
    if owned_root is not None:
        owned_root = Path(owned_root)
        if (not re.fullmatch(r'getzilla-image-job-[0-9a-f]{32}\.scope', owned_root.name)
                or parent != owned_root / 'supervisor' or len(bounds['levels']) < 2
                or Path(bounds['levels'][1]['path']) != owned_root):
            raise BackendUnavailable('image supervisor differs from its explicit owned job')
        for name in ('memory.max', 'memory.swap.max', 'pids.max'):
            if (parent / name).read_text(encoding='utf-8').strip() != 'max':
                raise BackendUnavailable('finite supervisor subgroup bound cannot be bypassed')
        if (parent / 'cpu.max').read_text(encoding='utf-8').split()[0] != 'max':
            raise BackendUnavailable('finite supervisor CPU bound cannot be bypassed')
        parent = owned_root
    if authority._filesystem(parent) != 0x63677270:
        raise BackendUnavailable('current image cgroup parent is not a measured cgroup v2 mount')
    if ci_corpus:
        from .security_image_job import _memory_admission
        # The owned leaf has its 12GiB cap. Admission checks the actual outer
        # allocation ancestors, without subtracting reserve inside that leaf.
        _memory_admission(parent.parent)
    library = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if library.prctl(37, ctypes.byref(previous), 0, 0, 0) or library.prctl(36, 1, 0, 0, 0):
        raise BackendUnavailable('owned child subreaper is unavailable')
    cgroup = parent / ('getzilla-images-' + uuid.uuid4().hex)
    cgroup.mkdir(mode=0o700)
    try:
        cpus = _configure_cgroup(cgroup, bounds, ci_corpus=ci_corpus)
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
            if ci_corpus:
                worker.append('ci-corpus')
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


def _close_ci_controls(controls):
    failure = None
    for name in _CI_CONTROLS:
        if name not in controls:
            continue
        fd, identity = controls[name]
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != identity[:2]:
                raise ValueError('control cleanup identity differs')
            os.close(fd)
        except (OSError, ValueError) as error:
            if not isinstance(error, OSError) or error.errno != 9:
                failure = {'phase': 'ci-control-cleanup', 'command_id': 'ci-control-' + name,
                           'errno': getattr(error, 'errno', None)}
    controls.clear()
    if failure is not None:
        raise BackendUnavailable('CI control cleanup refused', detail=failure)


def _open_ci_controls(cgroup):
    """Open the closed control set while root can search the owned0700 cgroup."""
    controls = {}
    name = _CI_CONTROLS[0]
    try:
        device = os.fstat(cgroup).st_dev
        for name in _CI_CONTROLS:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cgroup)
            try:
                info = os.fstat(fd)
                authority._readonly_control(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_dev != device:
                    raise ValueError('control is not on the held cgroup filesystem')
                controls[name] = (fd, authority._ci_control_identity(info))
            except BaseException:
                os.close(fd)
                raise
        return controls
    except BaseException as error:
        try:
            _close_ci_controls(controls)
        finally:
            if isinstance(error, (OSError, ValueError)):
                raise BackendUnavailable('CI control opening refused', detail={
                    'phase': 'ci-control-open', 'command_id': 'ci-control-' + name,
                    'errno': getattr(error, 'errno', None)}) from error
        raise


def _install_resolver(path, resolver):
    """Only resolver ancestors become searchable; daemon state stays private."""
    if not isinstance(resolver, bytes) or len(resolver) > 65536:
        raise BackendUnavailable('resolver copy exceeds existing bound')
    held = _Root(path)
    fd = None
    try:
        fd = os.dup(held.fd)
        for name in ('run', 'systemd', 'resolve'):
            try:
                os.mkdir(name, mode=0o711, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            os.fchmod(fd, 0o711)  # nosec B103: traversal only, root ownership remains unchanged
        for name in ('resolv.conf', 'stub-resolv.conf'):
            output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o644, dir_fd=fd)
            with os.fdopen(output, 'wb') as stream:
                stream.write(resolver)
                os.fchmod(stream.fileno(), 0o644)  # nosec B103: public resolver copy inside private job
    finally:
        if fd is not None:
            os.close(fd)
        held.close()


@contextmanager
def namespace_volume(path, cgroup, *, ci_corpus=False):
    """Called only by the fixed worker after unshare; mount proof is measured."""
    path, cgroup = Path(path), Path(cgroup)
    if authority._GUARD is not None:
        raise BackendUnavailable('nested image namespace is forbidden')
    # Refuse system temporary roots; the owned volume must be elsewhere.
    if any(path.is_relative_to(base) for base in map(Path, ('/run', '/tmp', '/var/tmp'))):  # nosec B108
        raise BackendUnavailable('image volume must use canonical runtime outside masked system temporaries')
    if (os.geteuid() != 0 or os.getpid() != 1
            or not re.fullmatch(r'getzilla-images-[0-9a-f]{32}', cgroup.name)
            or not cgroup.is_absolute() or '..' in cgroup.parts):
        raise BackendUnavailable('invalid image namespace owner')
    if str(os.getpid()) not in (cgroup / 'cgroup.procs').read_text(encoding='utf-8').split():
        raise BackendUnavailable('image worker is outside its owned cgroup')
    if Path('/proc/self/cgroup').read_text(encoding='utf-8').strip() != '0::/':
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
                    or authority._filesystem('/sys/fs/cgroup') != 0x63677270 or flags & required != required):
                raise BackendUnavailable('mounted cgroup root differs from held owned subtree')
        finally:
            actual.close()
    finally:
        held.close()
    controls = {name: (Path('/sys/fs/cgroup') / name).read_text(encoding='utf-8').strip()
                for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    quota, period = controls['cpu.max'].split()
    memory = CI_MEMORY if ci_corpus else 2 * 1024 ** 3
    storage = CI_BYTES if ci_corpus else LIMITS['max_storage_bytes']
    if (controls['memory.max'] != str(memory) or controls['memory.swap.max'] != '0'
            or controls['pids.max'] != '256' or quota == 'max'
            or not 0 < int(quota) <= 6 * int(period) or not 0 < len(os.sched_getaffinity(0)) <= 6):
        raise BackendUnavailable('live image namespace resource controls differ from admitted bounds')
    _fixed(['/usr/bin/mount', '-t', 'tmpfs', '-o',
            f'size={storage},mode=0700,nosuid,nodev', 'getzilla-images', str(path)])
    try:
        info = os.statvfs(path)
        if authority._filesystem(path) != 0x01021994 or info.f_blocks * info.f_frsize != storage:
            raise BackendUnavailable('image volume is not the exact hard-bounded tmpfs')
        # runc's ordinary /run state and helpers which ignore TMPDIR must share
        # this same volume. No second tmpfs or host daemon storage is available.
        with open('/etc/resolv.conf', 'rb') as source:
            resolver = source.read(65537)
        if len(resolver) > 65536:
            raise BackendUnavailable('runner resolver configuration exceeds bound')
        for name in ('run', 'tmp', 'var-tmp'):
            (path / name).mkdir(mode=0o700)
        _install_resolver(path, resolver)
        mounted = []
        # Private mount destinations mask host temporaries with measured 0700 tmpfs directories.
        for name, target in (('run', '/run'), ('tmp', '/tmp'), ('var-tmp', '/var/tmp')):  # nosec B108
            _fixed(['/usr/bin/mount', '--bind', str(path / name), target])
            mounted.append(target)
        proof_volume = proof_cgroup = None
        controls = {}
        proof_cleanup = ExitStack()
        try:
            if ci_corpus:
                proof_volume = _Root(path)
                proof_cleanup.callback(proof_volume.close)
                proof_cgroup = _Root('/sys/fs/cgroup')
                proof_cleanup.callback(proof_cgroup.close)
                controls = _open_ci_controls(proof_cgroup.fd)
                proof_cleanup.callback(_close_ci_controls, controls)
            authority._GUARD = (path, object(), mounted, {'cgroup_root_device': expected.st_dev,
                        'cgroup_root_inode': expected.st_ino, 'cgroup_mount_flags': flags})
            if ci_corpus:
                authority._GUARD[3].update(ci_corpus=True, volume_fd=proof_volume.fd, cgroup_fd=proof_cgroup.fd,
                    volume_identity=(os.fstat(proof_volume.fd).st_dev, os.fstat(proof_volume.fd).st_ino),
                    controls=controls)
            yield path
        finally:
            authority._GUARD = None
            try:
                proof_cleanup.close()
            finally:
                # PID1's fork copies disappear when owned workers are reaped;
                # closing a parent FD alone does not revoke a child's copy.
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
        self._in_build, self.last_prune_usage = False, {}
        if authority._GUARD is None or authority._GUARD[0] != self.volume:
            raise BackendUnavailable('BuildKit requires a measured live namespace volume')
        self.guard = authority._GUARD
        from .security_image_provision import archive_bytes, extract_tools
        # Open/identity-check a finite archive, verify the SOURCE distribution
        # pin, and copy its held bytes. Caller JSON hashes grant no authority.
        raw = archive_bytes(archive)
        directory = self.volume / 'pinned-bin'
        tools = extract_tools(io.BytesIO(raw), directory)
        for tool in tools.values():
            # Digest-verified sealed tools permit dropped-UID execution without granting write access.
            os.chmod(tool['path'], 0o555)  # nosec B103
        # Client traversal only beneath the private volume; immediate read-only bind prevents replacement.
        os.chmod(directory, 0o555)  # nosec B103
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
        config.write_text('[worker.oci]\ndefaultCgroupParent = "/"\n', encoding='utf-8', newline='\n')
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

    def _volume_usage(self):
        """Diagnostic integers only; CI capacity still requires the live native proof."""
        if self.guard is not authority._GUARD:
            raise BackendUnavailable('owned volume diagnostic lifetime ended')
        if not (isinstance(self.guard, tuple) and len(self.guard) > 3
                and self.guard[3].get('ci_corpus')):
            return {}  # Default/local controls have no held CI proof descriptor.
        proof = self.guard[3]
        if not authority.measured_ci_profile():
            raise BackendUnavailable('owned volume diagnostic proof unavailable')
        fd = proof['volume_fd']
        identity = os.fstat(fd)
        if (identity.st_dev, identity.st_ino) != proof['volume_identity']:
            raise BackendUnavailable('owned volume diagnostic descriptor changed')
        info = os.fstatvfs(fd)
        capacity, free, available = (info.f_blocks * info.f_frsize,
                                    info.f_bfree * info.f_frsize, info.f_bavail * info.f_frsize)
        if capacity != CI_BYTES or not 0 <= available <= free <= capacity:
            raise BackendUnavailable('owned volume diagnostic counters refused')
        return dict(capacity_bytes=capacity, used_bytes=capacity - free, free_bytes=available)

    def prune(self):
        """Retire this private daemon's unused cache after its export is retained."""
        from .architecture_diff import _run_capped, ArchitectureError
        if self.guard is not authority._GUARD or not self._daemon_alive() or self._in_build:
            raise BackendUnavailable('owned idle BuildKit required for cache retirement')
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BackendUnavailable('image producer aggregate deadline exceeded')
        try:
            code, _, stderr = _run_capped([self.client, '--addr', self.address, 'prune', '--all'],
                cwd=_ROOT, env=self.env, stdin_data=None, stdout_limit=65536,
                stderr_limit=4096, timeout=remaining)
        except (OSError, ArchitectureError):
            raise BackendUnavailable('owned BuildKit cache retirement incomplete') from None
        self.last_prune_usage = self._volume_usage()
        if code or not self._daemon_alive():
            raise BackendUnavailable('owned BuildKit cache retirement refused', detail=dict(
                phase='build-cache', command_id='buildctl-prune-owned', exit_code=code, errno=None,
                volume_after_prune=self.last_prune_usage, stderr=_diagnostic(stderr)))
        return self.last_prune_usage

    def build(self, recipe, context, output, *, offline_control=False):
        from .architecture_diff import _run_capped, ArchitectureError
        if self.guard is not authority._GUARD or not self._daemon_alive() or getattr(self, '_in_build', False):
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
        usage_before = self._volume_usage()
        self._in_build = True
        try:
            code, _, stderr = _run_capped(arguments, cwd=context, env=self.env, stdin_data=None,
                stdout_limit=1024 * 1024, stderr_limit=1024 * 1024, timeout=remaining)
        except (OSError, ArchitectureError):
            raise BackendUnavailable('owned image build incomplete') from None
        finally:
            self._in_build = False
        if code:
            detail = dict(phase='build', command_id='buildctl-build', exit_code=code, errno=None,
                          stderr_captured_sha256=hashlib.sha256(stderr).hexdigest(), stderr=_diagnostic(stderr))
            if usage_before:
                detail.update(volume_before_build=usage_before, volume_at_failure=self._volume_usage(),
                              volume_after_previous_prune=getattr(self, 'last_prune_usage', {}))
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
        # Open the already-private mount alias through held no-follow directory handles.
        alias = _Root('/tmp')  # nosec B108
        try:
            a, b = os.fstat(expected.fd), os.fstat(alias.fd)
            if ((a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) or b.st_mode & 0o077
                    # Filesystem identity rejects non-tmpfs aliases; this creates nothing.
                    or authority._filesystem('/tmp') != 0x01021994):  # nosec B108
                raise BackendUnavailable('short socket alias differs from owned private volume')
            # Fixed socket alias is returned only after held inode/device, 0700 and tmpfs proof.
            return Path('/tmp/getzilla-buildkit.sock')  # nosec B108
        finally:
            alias.close()
    finally:
        expected.close()
