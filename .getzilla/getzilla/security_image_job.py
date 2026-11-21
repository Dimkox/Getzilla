"""An explicitly allocated disposable image job, never an inherited app scope.

The fixed independent job budget does not inherit a caller service's shared
PID allowance. It remains below the selected existing slice's kernel bounds.
Only this new unit's own process is moved to its supervisor leaf.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import uuid

from .security_image_backend import BackendUnavailable, _diagnostic, _reap_children, _retain_fault
from .security_oci import document, CI_MEMORY

_ROOT = Path(__file__).resolve().parents[1]
_BOOT = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
         'import sysconfig;sys.path.extend(sorted(set(sysconfig.get_paths()[k] for k in ("purelib","platlib"))));'
         'from getzilla.security_image_job import _entry;raise SystemExit(_entry())')


def _memory_read(path, limit):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise BackendUnavailable('memory observation exceeds finite bound')
    return raw.decode('ascii')


def _memory_admission(parent):
    try:
        return _observe_memory(parent)
    except BackendUnavailable:
        raise
    except (OSError, ValueError) as error:
        raise BackendUnavailable('actual memory admission is unobservable') from error


def _observe_memory(parent):
    """Observe the selected allocation ancestors before creating any job resource."""
    from . import _cpu_capacity
    from .security_image_backend import _Root, _filesystem
    parent = Path(parent)
    membership = _memory_read(Path('/proc/self/cgroup'), 1024 * 1024)
    mountinfo = _memory_read(Path('/proc/self/mountinfo'), 1024 * 1024)
    kind, member = _cpu_capacity._membership(membership)
    mounts = _cpu_capacity._mounts(mountinfo, kind, member)
    matches = [mount for mount, _relative in mounts if parent.is_relative_to(mount)]
    if kind != 'cgroup2' or len(matches) != 1 or _filesystem(parent) != 0x63677270:
        raise BackendUnavailable('selected memory allocation ancestry is unknown')
    mount = matches[0]
    if not any(line.split()[3:5] == ['/', str(mount)] and ' - cgroup2 ' in line
               for line in mountinfo.splitlines()):
        raise BackendUnavailable('hidden memory allocation ancestors are unsupported')
    available = re.findall(r'^MemAvailable:\s+([0-9]{1,20}) kB$', _memory_read(Path('/proc/meminfo'), 65536), re.M)
    if len(available) != 1 or int(available[0]) <= 0:
        raise BackendUnavailable('actual MemAvailable is unresolved')
    remaining = int(available[0]) * 1024
    rows = []
    current = parent
    while True:
        if len(rows) >= 64:
            raise BackendUnavailable('memory ancestry exceeds finite depth')
        held = _Root(current)
        try:
            identity = os.fstat(held.fd)
            def read(name):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held.fd)
                try:
                    raw = os.read(fd, 129)
                    if not raw or len(raw) > 128:
                        raise BackendUnavailable('memory control exceeds finite bound')
                    return raw.decode('ascii').strip()
                finally:
                    os.close(fd)
            try:
                maximum = read('memory.max')
            except FileNotFoundError:
                if current != mount:
                    raise
                # The full cgroup2 kernel root has no memory.max. A visible
                # root control, including a finite namespaced root, is read.
                maximum = None
            if maximum is None:
                used, maximum = None, 'kernel-root-unlimited'
            else:
                used = read('memory.current')
                used_after = read('memory.current')
                if maximum != read('memory.max') or any(not re.fullmatch(r'[0-9]{1,20}', v) for v in (used, used_after)):
                    raise BackendUnavailable('memory controls changed or are malformed')
                used = max(int(used), int(used_after))
                if maximum != 'max':
                    if not re.fullmatch(r'[0-9]{1,20}', maximum) or used > int(maximum):
                        raise BackendUnavailable('finite memory remaining is unobservable')
                    remaining = min(remaining, int(maximum) - used)
            after = os.stat(current, follow_symlinks=False)
            if (identity.st_dev, identity.st_ino) != (after.st_dev, after.st_ino):
                raise BackendUnavailable('memory allocation ancestor changed identity')
            rows.append(dict(path=str(current), maximum=maximum, current=used,
                             device=identity.st_dev, inode=identity.st_ino))
        finally:
            held.close()
        if current == mount:
            break
        current = current.parent
    if (_memory_read(Path('/proc/self/cgroup'), 1024 * 1024) != membership
            or _memory_read(Path('/proc/self/mountinfo'), 1024 * 1024) != mountinfo):
        raise BackendUnavailable('memory observation hierarchy changed')
    reserve = 2 * 1024 ** 3
    if remaining < CI_MEMORY + reserve:
        raise BackendUnavailable('insufficient actual memory for CI corpus and host reserve', detail={
            'phase': 'memory-admission', 'remaining_bytes': remaining, 'required_bytes': CI_MEMORY + reserve})
    return dict(mem_available_bytes=int(available[0]) * 1024, remaining_bytes=remaining,
                reserve_bytes=reserve, allocation_bytes=CI_MEMORY, ancestors=rows, kernel_root=str(mount))


def run_job(payload, workspace, *, slice_name, ci_corpus=False):
    try:
        return _run_job(payload, workspace, slice_name=slice_name, ci_corpus=ci_corpus)
    except (OSError, ValueError) as error:
        detail = dict(getattr(error, 'detail', {}))
        detail.setdefault('phase', 'job-admission-or-cleanup')
        detail.setdefault('command_id', 'owned-job-scope')
        detail.setdefault('errno', getattr(error, 'errno', None))
        _retain_fault(workspace, detail)
        raise BackendUnavailable('explicit owned image job refused', detail=detail) from None


def _run_job(payload, workspace, *, slice_name, ci_corpus=False):
    from .architecture_diff import _run_capped, ArchitectureError
    from .startup_cpu import cgroup_bounds, parse_cpu_list, measure
    uid = os.environ.get('SUDO_UID', '')
    if (os.geteuid() != 0 or not uid.isdecimal()
            or slice_name not in {'user-' + uid + '.slice', 'system.slice'}):
        raise BackendUnavailable('explicit ephemeral image job allocation required')
    parent = Path('/sys/fs/cgroup')
    parent = parent / 'user.slice' / slice_name if slice_name.startswith('user-') else parent / slice_name
    required = {'cpu', 'memory', 'pids'}
    if not required <= set((parent / 'cgroup.subtree_control').read_text(encoding='utf-8').split()):
        raise BackendUnavailable('selected existing job slice does not delegate required controllers')
    bounds = cgroup_bounds()
    selected = document(payload)
    kernel = selected == {'kind': 'kernel-self-test'}
    tool_control = isinstance(selected, dict) and selected.get('kind') == 'offline-tool-control'
    control = kernel or tool_control
    if type(ci_corpus) is not bool or ci_corpus and (control or not isinstance(selected, dict) or selected.get('kind') != 'pipeline'):
        raise BackendUnavailable('CI allocation is only available to the owned producer pipeline')
    admission = _memory_admission(parent) if ci_corpus else None
    cpus = set(os.sched_getaffinity(0))
    if bounds.get('effective_cpuset'):
        cpus &= parse_cpu_list(bounds['effective_cpuset'])
    maximum = 6
    if not control:
        # Fresh independent GHA capacity. The assigned local controls above
        # already have the global reserve and must not reserve another two.
        snapshot = measure(reserve=2, probe=False)
        if type(snapshot.get('chosen_capacity')) is not int or snapshot['chosen_capacity'] <= 0:
            raise BackendUnavailable('fresh image job startup allocation unavailable')
        cpus &= parse_cpu_list(snapshot['verified_cpus'])
        maximum = min(maximum, snapshot['chosen_capacity'])
        from .security_oci import _Root
        held = _Root(workspace)
        try:
            fd = os.open('image-startup-' + uuid.uuid4().hex + '.json',
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=held.fd)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(json.dumps(snapshot, sort_keys=True).encode())
                os.fchown(stream.fileno(), int(uid), int(os.environ.get('SUDO_GID', uid)))
        finally:
            held.close()
    cpus = sorted(cpus)[:maximum]
    if not cpus or len(payload) > 65536:
        raise BackendUnavailable('explicit image job CPU/request bound unavailable')
    unit = 'getzilla-image-job-' + uuid.uuid4().hex + '.scope'
    owned = parent / unit
    seconds = 10 if control else 1800
    started = time.monotonic()
    command = ['/usr/bin/systemd-run', '--scope', '--quiet', '--collect', '--expand-environment=no',
        '--unit=' + unit, '--slice=' + slice_name,
        '--property=Delegate=cpu memory pids', '--property=MemoryMax=' + str(CI_MEMORY if ci_corpus else 2 * 1024 ** 3),
        '--property=MemorySwapMax=0', '--property=TasksMax=256',
        '--property=CPUQuota=' + str(len(cpus) * 100) + '%', '--property=RuntimeMaxSec=' + str(seconds),
        '--property=TimeoutStopSec=5s', '--property=KillMode=control-group',
        sys.executable, '-I', '-S', '-B', '-c', _BOOT, str(_ROOT),
        str(workspace), str(owned), json.dumps(cpus), str(started)]
    if ci_corpus:
        command.append('ci-corpus')
    environment = {'PATH': os.defpath, 'LANG': 'C', 'SUDO_UID': uid,
                   'SUDO_GID': os.environ.get('SUDO_GID', uid)}
    library = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if library.prctl(37, ctypes.byref(previous), 0, 0, 0) or library.prctl(36, 1, 0, 0, 0):
        raise BackendUnavailable('owned job subreaper unavailable')
    signals = (signal.SIGTERM, signal.SIGINT)
    handlers = {number: signal.getsignal(number) for number in signals}
    def interrupted(number, _frame):
        raise BackendUnavailable('owned image job interrupted', detail={'phase': 'interrupted', 'signal': number})
    for number in signals:
        signal.signal(number, interrupted)
    try:
        if admission is not None:
            from .security_oci import _Root
            held = _Root(workspace)
            try:
                fd = os.open('image-memory-' + uuid.uuid4().hex + '.json',
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=held.fd)
                with os.fdopen(fd, 'w') as stream:
                    json.dump(_memory_admission(parent), stream, sort_keys=True)
                    os.fchown(stream.fileno(), int(uid), int(os.environ.get('SUDO_GID', uid)))
            finally:
                held.close()
        try:
            code, output, stderr = _run_capped(command, cwd=_ROOT, env=environment, stdin_data=payload,
                stdout_limit=8 * 1024 * 1024, stderr_limit=4096, timeout=seconds)
            if code:
                detail = dict(phase='job-scope', command_id='systemd-owned-scope', exit_code=code,
                              errno=None, stderr=_diagnostic(stderr), owned_scope=str(owned))
                try:
                    result = document(output)
                    if set(result) == {'fault'}:
                        detail['inner_fault'] = result['fault']
                except ValueError:
                    pass
                raise BackendUnavailable('owned image job did not complete', detail=detail)
            result = document(output)
            if set(result) != {'result'}:
                raise BackendUnavailable('owned job result protocol differs')
            if control:
                result['result']['job_allocation'] = dict(scope=unit, slice=slice_name,
                    previous_membership=bounds.get('membership'), caller_service_pid_limit_inherited=False)
            return result['result']
        except (OSError, ValueError, ArchitectureError) as error:
            detail = dict(getattr(error, 'detail', {}))
            detail.setdefault('phase', 'job-scope')
            detail.setdefault('command_id', 'systemd-owned-scope')
            detail.setdefault('errno', getattr(error, 'errno', None))
            detail['owned_scope'] = str(owned)
            raise BackendUnavailable('explicit image job refused', detail=detail) from None
    finally:
        # Stop only this random owned unit; never a service or a caller slice.
        for number in signals:
            signal.signal(number, signal.SIG_IGN)
        try:
            if owned.exists():
                _run_capped(['/usr/bin/systemctl', 'stop', unit], cwd=_ROOT, env=environment,
                    stdin_data=None, stdout_limit=1024, stderr_limit=2048, timeout=10)
            deadline = time.monotonic() + 5
            while owned.exists():
                if time.monotonic() >= deadline:
                    raise BackendUnavailable('owned image scope cleanup incomplete', detail={
                        'phase': 'cleanup', 'command_id': 'systemd-stop-owned-scope', 'owned_scope': str(owned)})
                time.sleep(.02)
            _reap_children()
        finally:
            library.prctl(36, previous.value, 0, 0, 0)
            for number, handler in handlers.items():
                signal.signal(number, handler)


def _entry():
    from .security_image_backend import run_guarded
    try:
        if len(sys.argv) not in (5, 6) or len(sys.argv) == 6 and sys.argv[5] != 'ci-corpus':
            raise BackendUnavailable('invalid fixed image job dispatch')
        workspace, owned, cpus, started = Path(sys.argv[1]), Path(sys.argv[2]), json.loads(sys.argv[3]), float(sys.argv[4])
        from .startup_cpu import cgroup_bounds
        bounds = cgroup_bounds()
        if (not re.fullmatch(r'getzilla-image-job-[0-9a-f]{32}\.scope', owned.name)
                or Path(bounds['levels'][0]['path']) != owned):
            raise BackendUnavailable('owned job differs from actual systemd membership')
        if (owned / 'cgroup.procs').read_text(encoding='utf-8').split() != [str(os.getpid())]:
            raise BackendUnavailable('new image scope has unexpected supervisor processes')
        os.sched_setaffinity(0, cpus)
        supervisor = owned / 'supervisor'
        supervisor.mkdir(mode=0o700)
        (supervisor / 'cgroup.procs').write_text(str(os.getpid()), encoding='utf-8', newline='\n')
        (owned / 'cgroup.subtree_control').write_text('+cpu +memory +pids', encoding='utf-8', newline='\n')
        payload = sys.stdin.buffer.read(65537)
        result = run_guarded(payload, workspace, owned_root=owned, started=started, ci_corpus=len(sys.argv) == 6)
        sys.stdout.write(json.dumps({'result': result}, sort_keys=True) + '\n')
        return 0
    except BaseException as error:
        detail = dict(getattr(error, 'detail', {}))
        detail.setdefault('phase', 'job-admission')
        detail.setdefault('command_id', 'owned-job-supervisor')
        detail.setdefault('errno', getattr(error, 'errno', None))
        sys.stdout.write(json.dumps({'fault': detail}, sort_keys=True) + '\n')
        return 1
