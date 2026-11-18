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
from .security_oci import document

_ROOT = Path(__file__).resolve().parents[1]
_BOOT = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
         'import sysconfig;sys.path.extend(sorted(set(sysconfig.get_paths()[k] for k in ("purelib","platlib"))));'
         'from getzilla.security_image_job import _entry;raise SystemExit(_entry())')


def run_job(payload, workspace, *, slice_name):
    try:
        return _run_job(payload, workspace, slice_name=slice_name)
    except (OSError, ValueError) as error:
        detail = dict(getattr(error, 'detail', {}))
        detail.setdefault('phase', 'job-admission-or-cleanup')
        detail.setdefault('command_id', 'owned-job-scope')
        detail.setdefault('errno', getattr(error, 'errno', None))
        _retain_fault(workspace, detail)
        raise BackendUnavailable('explicit owned image job refused', detail=detail) from None


def _run_job(payload, workspace, *, slice_name):
    from .architecture_diff import _run_capped, ArchitectureError
    from .startup_cpu import cgroup_bounds, parse_cpu_list, measure
    uid = os.environ.get('SUDO_UID', '')
    if (os.geteuid() != 0 or not uid.isdecimal()
            or slice_name not in {'user-' + uid + '.slice', 'system.slice'}):
        raise BackendUnavailable('explicit ephemeral image job allocation required')
    parent = Path('/sys/fs/cgroup')
    parent = parent / 'user.slice' / slice_name if slice_name.startswith('user-') else parent / slice_name
    required = {'cpu', 'memory', 'pids'}
    if not required <= set((parent / 'cgroup.subtree_control').read_text().split()):
        raise BackendUnavailable('selected existing job slice does not delegate required controllers')
    bounds = cgroup_bounds()
    selected = document(payload)
    kernel = selected == {'kind': 'kernel-self-test'}
    tool_control = isinstance(selected, dict) and selected.get('kind') == 'offline-tool-control'
    control = kernel or tool_control
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
        '--property=Delegate=cpu memory pids', '--property=MemoryMax=2147483648',
        '--property=MemorySwapMax=0', '--property=TasksMax=256',
        '--property=CPUQuota=' + str(len(cpus) * 100) + '%', '--property=RuntimeMaxSec=' + str(seconds),
        '--property=TimeoutStopSec=5s', '--property=KillMode=control-group',
        sys.executable, '-I', '-S', '-B', '-c', _BOOT, str(_ROOT),
        str(workspace), str(owned), json.dumps(cpus), str(started)]
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
        if len(sys.argv) != 5:
            raise BackendUnavailable('invalid fixed image job dispatch')
        workspace, owned, cpus, started = Path(sys.argv[1]), Path(sys.argv[2]), json.loads(sys.argv[3]), float(sys.argv[4])
        from .startup_cpu import cgroup_bounds
        bounds = cgroup_bounds()
        if (not re.fullmatch(r'getzilla-image-job-[0-9a-f]{32}\.scope', owned.name)
                or Path(bounds['levels'][0]['path']) != owned):
            raise BackendUnavailable('owned job differs from actual systemd membership')
        if (owned / 'cgroup.procs').read_text().split() != [str(os.getpid())]:
            raise BackendUnavailable('new image scope has unexpected supervisor processes')
        os.sched_setaffinity(0, cpus)
        supervisor = owned / 'supervisor'
        supervisor.mkdir(mode=0o700)
        (supervisor / 'cgroup.procs').write_text(str(os.getpid()))
        (owned / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        payload = sys.stdin.buffer.read(65537)
        result = run_guarded(payload, workspace, owned_root=owned, started=started)
        sys.stdout.write(json.dumps({'result': result}, sort_keys=True) + '\n')
        return 0
    except BaseException as error:
        detail = dict(getattr(error, 'detail', {}))
        detail.setdefault('phase', 'job-admission')
        detail.setdefault('command_id', 'owned-job-supervisor')
        detail.setdefault('errno', getattr(error, 'errno', None))
        sys.stdout.write(json.dumps({'fault': detail}, sort_keys=True) + '\n')
        return 1
