"""Single owned offline study process, gated by the existing operation/run owners.

No import/status action starts a process. The public entry accepts only the
native operation reference; dictionaries, container IDs and argv are not inputs.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
import json
import hashlib
import math
import os
from pathlib import Path
import re
import secrets
import select
import time
import threading
import contextvars

from .budget import RetrievalError
from .contracts import digest

_ISSUER = object()
_LIVE = {}
_RESULTS = {}
ENTRY = '/worker/getzilla/retrieval/study_worker_entry.py'
MAX_SECONDS = 14400


def status():
    return {'status': 'unavailable', 'execution_enabled': False,
            'reason': 'current_operation_and_owned_runtime_required'}


class LiveStudyResourceRef:
    __slots__ = ('_issuer', '_owner')

    def __new__(cls, token=None, owner=None):
        if token is not _ISSUER:
            raise TypeError('native live resources only')
        value = super().__new__(cls)
        value._issuer, value._owner = token, owner
        return value

    def __reduce_ex__(self, protocol):
        raise TypeError('live resources cannot be serialized')


@dataclass(frozen=True)
class LiveStudyResourceObservation:
    execution_id: str
    container_id: str
    pid: int
    start_ticks: str
    image_id: str
    readback_digest: str
    pid_scope: str


class StudyInspectionResultRef:
    __slots__ = ('_issuer', '_owner')

    def __new__(cls, token=None, owner=None):
        if token is not _ISSUER:
            raise TypeError('native inspection results only')
        value = super().__new__(cls)
        value._issuer, value._owner = token, owner
        return value

    def __reduce_ex__(self, protocol):
        raise TypeError('inspection references cannot be serialized')


@dataclass(frozen=True)
class StudyInspectionResultObservation:
    execution_id: str
    report_relative_path: str
    report_sha256: str
    report_bytes: bytes = field(repr=False)
    report_size: int
    resource_readback_digest: str | None
    image_id: str
    registration_sha256: str
    execution_status: str
    cleanup_status: str
    native_execution_observation: str
    original_deadline: float


def _operation(reference):
    try:
        from .public_study_operation import (check_public_study_operation,
                                             PublicStudyOperationProjection)
        projection = check_public_study_operation(reference)
        if type(projection) is not PublicStudyOperationProjection:
            raise RetrievalError('study_operation_unavailable')
        return projection
    except (ImportError, AttributeError):
        raise RetrievalError('study_operation_unavailable') from None


def _container_environment(image_env):
    cleared = {key: '' for key in _observed_environment(image_env)}
    fixed = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
             'LD_PRELOAD': '', 'LD_AUDIT': '', 'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1',
             'MKL_NUM_THREADS': '1', 'NUMEXPR_NUM_THREADS': '1', 'VECLIB_MAXIMUM_THREADS': '1',
             'RAYON_NUM_THREADS': '1', 'CUDA_VISIBLE_DEVICES': '-1', 'NVIDIA_VISIBLE_DEVICES': 'void'}
    return {**cleared, **fixed}


def _observed_environment(image_env):
    if type(image_env) not in {tuple, list} or len(image_env) > 256:
        raise RetrievalError('study_image_environment_unavailable')
    cleared = {}
    for item in image_env:
        if type(item) is not str or '=' not in item or len(item) > 65536:
            raise RetrievalError('study_image_environment_unavailable')
        key = item.split('=', 1)[0]
        if not re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}', key) or key in cleared:
            raise RetrievalError('study_image_environment_unavailable')
        cleared[key] = item.split('=', 1)[1]
    return cleared


def _create_arguments(projection, execution_id, nonce, deadline, image_env=()):
    from .study_resources import _cpus
    _cpus(projection.cpu_ids)
    if not re.fullmatch('sha256:[0-9a-f]{64}', projection.image_id):
        raise RetrievalError('study_image_unavailable')
    for root in (projection.model_root, projection.software_root, projection.worker_root):
        if any(character in str(root) for character in ',\"\n\r\x00'):
            raise RetrievalError('study_export_path_unavailable')
    command = ('/usr/local/bin/python', '-I', '-S', '-B', ENTRY,
               '--nonce', nonce, '--deadline', str(deadline))
    args = ['create', '--interactive', '--pull=never', '--name', f'getzilla-study-{execution_id}-{nonce[:16]}',
            '--label', f'getzilla.study.execution={execution_id}',
            '--label', f'getzilla.study.nonce={nonce}', '--network=none', '--read-only',
            '--user=65532:65532', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
            '--memory=6442450944', '--memory-swap=6442450944', '--pids-limit=128',
            '--cpuset-cpus=' + ','.join(map(str, projection.cpu_ids)), '--cpus=2',
            '--ipc=none', '--cgroupns=private', '--runtime=runc',
            '--log-driver=none', '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=700',
            '--mount', f'type=bind,src={projection.model_root},dst=/model,readonly,bind-propagation=rprivate',
            '--mount', f'type=bind,src={projection.software_root},dst=/software,readonly,bind-propagation=rprivate',
            '--mount', f'type=bind,src={projection.worker_root},dst=/worker,readonly,bind-propagation=rprivate',
            *('--env=' + key + '=' + value for key, value in
              sorted(_container_environment(image_env).items())),
            '--entrypoint', command[0], projection.image_id, *command[1:]]
    return args, command


def _json(raw):
    from ..spec import _pairs_object, _reject_constant, _bounded_walk
    try:
        result = json.loads(raw, object_pairs_hook=_pairs_object, parse_constant=_reject_constant)
        _bounded_walk(result)
        return result
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RetrievalError('study_readback_unavailable') from None


def _start_ticks(pid):
    raw = Path(f'/proc/{pid}/stat').read_bytes()
    if len(raw) > 8192:
        raise RetrievalError('study_process_identity_unavailable')
    return raw.rsplit(b')', 1)[1].split()[19].decode('ascii')


def _bound_execution_deadline(projection, execution_deadline):
    original = getattr(projection, 'original_deadline', None)
    if projection.operation == 'rank_public_study':
        if type(original) is not float or not math.isfinite(original):
            raise RetrievalError('study_original_deadline_unavailable')
        deadline = min(execution_deadline, original)
    elif projection.operation == 'inspect_public_artifacts' and original is None:
        deadline = execution_deadline
    else:
        raise RetrievalError('study_original_deadline_unavailable')
    if time.monotonic() >= deadline:
        raise RetrievalError('study_original_deadline_expired')
    return deadline


class _Owner:
    def __init__(self, operation_ref, projection, admission, request):
        self.operation_ref, self.projection = operation_ref, projection
        self.admission, self.request = admission, request
        self.execution_id = admission.execution_id
        self.nonce = secrets.token_hex(32)
        self.container_id, self.attach, self.pidfd = None, None, None
        self.pid, self.start_ticks, self.readback_digest = None, None, None
        self.pid_scope = 'docker-daemon'
        self.closed, self.sequence = False, 0
        self.create_attempted = False
        from .. import execution
        live = execution._LIVE.get((str(projection.root.resolve()), admission.execution_id))
        if live is None or live[2] != admission.execution_generation:
            raise RetrievalError('study_execution_not_current')
        self.deadline = _bound_execution_deadline(projection, live[1])
        self.stack = ExitStack()
        self.reference = None
        self._channel_lock = threading.Lock()
        self._request_lock = threading.RLock()
        self._close_lock = threading.Lock()
        self._stop = threading.Event()
        self._heartbeat_thread = None
        self._readback_counter = 0
        self._native_child_binding = None
        self._native_start_dispatched = False
        self._native_completed = False
        self.records = []
        self.report_artifact = None
        self.inspection_facts = {'tokenizers': {}, 'conformance': {}, 'windows': [], 'lengths': {}}

    def current(self):
        from .. import execution
        if self.closed or time.monotonic() >= self.deadline:
            raise RetrievalError('study_runtime_deadline')
        if _operation(self.operation_ref) != self.projection:
            raise RetrievalError('study_operation_changed')
        caller = execution.trusted_caller(self.projection.root, execution_id=self.execution_id)
        record = execution.get(self.projection.root, caller, self.execution_id)
        control = execution.control_status(self.projection.root, caller)
        if (record['execution_status'] != 'running' or record['deadline_elapsed']
                or not record['live_continuity'] or control['stopped']):
            raise RetrievalError('study_execution_not_current')
        return record

    def call(self, args, *, cleanup=False):
        from .study_docker_process import OwnedCommand
        if not cleanup:
            self.current()
        child = OwnedCommand(self.projection.root, self.binary, args)
        try:
            deadline = (min(self.deadline, time.monotonic() + 30)
                        if not cleanup else time.monotonic() + 10)
            while not child.done() or child._selector.get_map():
                if time.monotonic() >= deadline:
                    raise RetrievalError('study_docker_deadline')
                if not cleanup:
                    self.current()
                child.drain(min(.05, deadline - time.monotonic()))
            return child.finish(deadline)
        finally:
            child.close()

    def inspect(self, *, cleanup=False):
        rows = _json(self.call(['inspect', '--type=container', self.container_id], cleanup=cleanup))
        if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
                or rows[0].get('Id') != self.container_id
                or rows[0].get('Config', {}).get('Labels', {}).get('getzilla.study.nonce') != self.nonce
                or rows[0]['Config']['Labels'].get('getzilla.study.execution') != self.execution_id):
            raise RetrievalError('study_container_identity_unavailable')
        return rows[0]

    def readback(self):
        self.current()
        self.artifacts.check()
        self.software.check()
        self.worker.check()
        observed = self.inspect()
        self.validate_container(observed)
        if (observed['State']['Running'] is not True or observed['State'].get('Paused') is not False
                or observed['State'].get('Restarting') is not False
                or observed['State']['Pid'] != self.pid or self.attach.done()):
            raise RetrievalError('study_process_identity_unavailable')
        if self.pidfd is not None and (_start_ticks(self.pid) != self.start_ticks
                                      or select.select([self.pidfd], [], [], 0)[0]):
            raise RetrievalError('study_process_identity_unavailable')
        from .study_kernel import read_kernel_profile
        kernel = ({'availability': 'observed', 'facts':
                   read_kernel_profile(self.pid, self.projection.cpu_ids, self.command)}
                  if self.pidfd is not None else {'availability': 'unavailable',
                      'reason': 'daemon_pid_not_proven_in_current_host_namespace'})
        inside = self._inside_live_readback()
        stable_inside = {key: value for key, value in inside.items() if key != 'native_child'}
        value = digest({'container': observed, 'host_kernel': kernel, 'inside': stable_inside})
        # State fields such as StartedAt and readback values are fixed for this
        # one process. Never adopt a restarted PID, changed cgroup or new image.
        if self.readback_digest is not None and value != self.readback_digest:
            raise RetrievalError('study_resource_changed')
        self.current()
        return value

    def validate_container(self, observed):
        from .study_resources import validate_container_readback
        validate_container_readback(observed, image_id=self.projection.image_id,
            cpu_ids=self.projection.cpu_ids, command=self.command,
            mounts={'/model': str(self.projection.model_root),
                    '/software': str(self.projection.software_root),
                    '/worker': str(self.projection.worker_root)})
        if (observed['Config'].get('OpenStdin') is not True
                or observed['Config'].get('Tty') is not False
                or _observed_environment(observed['Config']['Env']) != self.expected_env
                or observed['HostConfig'].get('RestartPolicy', {}).get('Name') != 'no'):
            raise RetrievalError('study_container_environment_changed')

    def start(self):
        from .study_artifacts import HeldArtifacts
        from .study_docker_process import DockerBinary, OwnedCommand
        self.current()
        self.artifacts = self.stack.enter_context(HeldArtifacts(self.projection.model_root,
            self.projection.artifact_files, deadline=min(self.deadline, time.monotonic() + 180)))
        self.software = self.stack.enter_context(HeldArtifacts(self.projection.software_root,
            self.projection.software_files, deadline=min(self.deadline, time.monotonic() + 180)))
        self.worker = self.stack.enter_context(HeldArtifacts(self.projection.worker_root,
            self.projection.worker_files, deadline=min(self.deadline, time.monotonic() + 180)))
        worker = next((row for row in self.projection.worker_files
                       if row[0] == 'getzilla/retrieval/study_worker_entry.py'), None)
        if worker is None or worker[2] != self.projection.worker_sha256:
            raise RetrievalError('study_worker_source_unavailable')
        self.binary = DockerBinary(self.projection)
        self.stack.callback(self.binary.close)
        info = _json(self.call(['info', '--format', '{{json .}}']))
        if info.get('ID') != self.projection.daemon_id:
            raise RetrievalError('study_daemon_changed')
        images = _json(self.call(['image', 'inspect', self.projection.image_id]))
        if len(images) != 1 or images[0].get('Id') != self.projection.image_id:
            raise RetrievalError('study_image_unavailable')
        image_env = images[0].get('Config', {}).get('Env') or []
        self.expected_env = _container_environment(image_env)
        args, self.command = _create_arguments(self.projection, self.execution_id, self.nonce,
                                               self.deadline, image_env)
        self.create_attempted = True
        self.container_id = self.call(args).decode('ascii').strip()
        if not re.fullmatch('[0-9a-f]{64}', self.container_id):
            self.container_id = None
            raise RetrievalError('study_create_outcome_unknown')
        self.validate_container(self.inspect())
        self.current()
        self.attach = OwnedCommand(self.projection.root, self.binary,
                                   ['start', '--attach', '--interactive', self.container_id])
        startup_deadline = min(self.deadline, time.monotonic() + 10)
        observed = self.inspect()
        while observed['State']['Running'] is not True:
            if time.monotonic() >= startup_deadline or self.attach.done():
                raise RetrievalError('study_worker_deadline')
            self.attach.drain(.01)
            observed = self.inspect()
        self.pid = observed['State']['Pid']
        if type(self.pid) is not int or self.pid <= 0:
            raise RetrievalError('study_process_identity_unavailable')
        hello = _json(self.attach.read_line(min(self.deadline, time.monotonic() + 10), limit=4096))
        if (type(hello) is not dict or set(hello) != {'phase', 'nonce', 'pid', 'inside'}
                or hello['phase'] != 'waiting' or hello['nonce'] != self.nonce or hello['pid'] != 1):
            raise RetrievalError('study_worker_handshake_unavailable')
        self.validate_inside(hello['inside'])
        self.start_ticks = hello['inside']['kernel']['start_ticks']
        self._bind_direct_host_pid(hello['inside']['kernel'])
        self._start_heartbeat()
        self.readback_digest = self.readback()
        self.reference = LiveStudyResourceRef(_ISSUER, self)
        _LIVE[id(self.reference)] = self
        return self.reference

    def _bind_direct_host_pid(self, inside_kernel):
        """Docker PID numbers can name unrelated processes in this caller's namespace."""
        descriptor = None
        try:
            for name, identity in inside_kernel['namespace_ids'].items():
                if os.readlink(f'/proc/{self.pid}/ns/{name}') != identity:
                    return
            if _start_ticks(self.pid) != self.start_ticks:
                return
            with open(f'/proc/{self.pid}/cmdline', 'rb') as stream:
                raw = stream.read(8193)
            if raw != b'\0'.join(part.encode() for part in self.command) + b'\0':
                return
            descriptor = os.pidfd_open(self.pid)
            if _start_ticks(self.pid) != self.start_ticks or select.select([descriptor], [], [], 0)[0]:
                return
            self.pidfd, descriptor = descriptor, None
            self.pid_scope = 'current-host-namespace'
        except (OSError, ValueError, KeyError):
            pass  # Explicit daemon-only scope, never a claim of host observation.
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _start_heartbeat(self):
        context = contextvars.copy_context()
        def keep_alive():
            try:
                while not self._stop.is_set():
                    self.current()
                    with self._channel_lock:
                        raw = json.dumps({'nonce': self.nonce, 'heartbeat': self.sequence},
                                         separators=(',', ':')).encode() + b'\n'
                        if os.write(self.attach.process.stdin.fileno(), raw) != len(raw):
                            raise RetrievalError('study_owner_channel_unavailable')
                    self._stop.wait(.5)
            except BaseException:
                if not self.closed:
                    self.close()
        self._heartbeat_thread = threading.Thread(target=lambda: context.run(keep_alive),
                                                  name='getzilla-owned-study', daemon=True)
        self._heartbeat_thread.start()

    def validate_inside(self, inside):
        if (type(inside) is not dict or set(inside) != {'pid', 'uid', 'gid', 'python',
                'cache_tag', 'machine', 'byteorder', 'bits', 'roots', 'gpu_devices',
                'kernel', 'native_child'}
                or inside['pid'] != 1 or inside['uid'] != 65532 or inside['gid'] != 65532
                or type(inside['python']) is not list or len(inside['python']) != 3
                or inside['python'][:2] != [3, 12] or type(inside['python'][2]) is not int
                or inside['cache_tag'] != 'cpython-312' or inside['machine'] != 'x86_64'
                or inside['byteorder'] != 'little' or inside['bits'] != 64
                or inside['gpu_devices'] != []
                or type(inside['roots']) is not dict
                or set(inside['roots']) != {'/model', '/software', '/worker'}):
            raise RetrievalError('study_inside_profile_unavailable')
        for target, source in (('/model', self.projection.model_root),
                               ('/software', self.projection.software_root),
                               ('/worker', self.projection.worker_root)):
            info = os.stat(source, follow_symlinks=False)
            if inside['roots'][target] != [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]:
                raise RetrievalError('study_inside_mount_changed')
        from .study_resources import validate_kernel_readback
        validate_kernel_readback(inside['kernel'], cpu_ids=self.projection.cpu_ids)
        with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
            boot_id = stream.read(128).strip()
        if (not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot_id)
                or inside['kernel'].get('boot_id') != boot_id
                or inside['kernel'].get('namespace_ids', {}).get('time') != os.readlink('/proc/self/ns/time')
                or type(inside['kernel'].get('start_ticks')) is not str
                or not inside['kernel']['start_ticks'].isdigit()
                or self.start_ticks is not None and inside['kernel']['start_ticks'] != self.start_ticks):
            raise RetrievalError('study_inside_clock_or_identity_unavailable')
        child = inside['native_child']
        if child is not None:
            if not self._native_start_dispatched or type(child) is not dict:
                raise RetrievalError('study_native_child_unavailable')
            if self._native_child_binding is None:
                self._native_child_binding = child
            elif child != self._native_child_binding:
                raise RetrievalError('study_native_child_changed')
        elif self._native_child_binding is not None:
            raise RetrievalError('study_native_child_changed')
        self.inside = inside

    def _inside_live_readback(self):
        if not self._request_lock.acquire(blocking=False):
            raise RetrievalError('study_request_already_running')
        try:
            self._readback_counter += 1
            raw = json.dumps({'nonce': self.nonce, 'resource_readback': self._readback_counter},
                             separators=(',', ':')).encode() + b'\n'
            deadline = min(self.deadline, time.monotonic() + 2)
            with self._channel_lock:
                self.attach.write(raw, deadline)
            result = _json(self.attach.read_line(deadline))
            if (type(result) is not dict or set(result) != {'phase', 'nonce', 'counter', 'facts'}
                    or result['phase'] != 'resource-readback' or result['nonce'] != self.nonce
                    or result['counter'] != self._readback_counter):
                raise RetrievalError('study_inside_readback_unavailable')
            self.validate_inside(result['facts'])
            return result['facts']
        finally:
            self._request_lock.release()

    def _request(self, stage, payload, *, source_cuts=(), query_deadline=None):
        """Trusted fixed driver only; never expose a generic caller encode API."""
        from .public_study_operation import admit_public_study_stage
        allowed = {'inspect_native_import': (('native-import',), 180),
                   'inspect_tokenizer': (('load-tokenizer',), 180),
                   'inspect_windows': (('windows', 'inspect-length'), 2),
                   'inspect_runtime': (('load-model', 'probe', 'packing-probe'), 180),
                   'inspect_release': (('release',), 2),
                   'rank_encode': (('encode', 'prepare-index'), 2), 'rank_score': (('score',), 2),
                   'rank_release': (('release',), 2)}
        if (stage not in allowed or type(payload) is not dict
                or payload.get('op') not in allowed[stage][0]
                or {'nonce', 'sequence'} & set(payload)):
            raise RetrievalError('study_stage_unavailable')
        if not self._request_lock.acquire(blocking=False):
            raise RetrievalError('study_request_already_running')
        try:
            admit_public_study_stage(self.operation_ref, self.reference, stage,
                                     source_cuts=source_cuts)
            check_live_study_resource(self.reference, self.projection)
            deadline = min(self.deadline, time.monotonic() + allowed[stage][1])
            if query_deadline is not None:
                if type(query_deadline) not in {int, float} or not math.isfinite(query_deadline):
                    raise RetrievalError('study_query_deadline_unavailable')
                deadline = min(deadline, query_deadline)
            from .public_study_operation import check_public_study_source_cuts
            if source_cuts:
                checkpoint = check_public_study_source_cuts(self.operation_ref, source_cuts)
                deadline = min(deadline, checkpoint.deadline)
            with self._channel_lock:
                self.sequence += 1
                self._native_start_dispatched = True
                raw = json.dumps({**payload, 'nonce': self.nonce, 'sequence': self.sequence,
                                  'absolute_deadline': deadline},
                                 ensure_ascii=False, allow_nan=False).encode() + b'\n'
                self.attach.write(raw, deadline)
            # Recheck ownership while native work is running, not just after it.
            while b'\n' not in self.attach.stdout:
                if time.monotonic() >= deadline or self.attach.done():
                    raise RetrievalError('study_worker_deadline')
                self.current()
                if source_cuts:
                    check_public_study_source_cuts(self.operation_ref, source_cuts)
                self.attach.drain(min(.05, deadline - time.monotonic()))
            result = _json(self.attach.read_line(deadline))
            if (type(result) is not dict or set(result) != {'sequence', 'status', 'result'}
                    or result['sequence'] != self.sequence or result['status'] != 'ok'):
                raise RetrievalError('study_worker_unavailable')
            # Same source cuts, no renewal; inputs and derivative output can
            # become unavailable even when the owned native operation completed.
            admit_public_study_stage(self.operation_ref, self.reference, stage,
                                     source_cuts=source_cuts)
            check_live_study_resource(self.reference, self.projection)
            if stage == 'inspect_native_import':
                self._native_completed = True
            actual = result['result']
            if payload['op'] == 'load-tokenizer':
                self.inspection_facts['tokenizers'][payload['model']] = actual
            elif payload['op'] == 'probe':
                self.inspection_facts['conformance'][payload['model']] = actual
            elif payload['op'] == 'windows':
                self.inspection_facts['windows'].extend(actual['windows'])
            elif payload['op'] == 'inspect-length':
                self.inspection_facts['lengths'][payload['model'], payload['corpus'], payload['window_id']] = actual
            elif payload['op'] == 'packing-probe':
                self.inspection_facts['packing'] = actual
            self.records.append({'stage': stage, 'sequence': self.sequence,
                                 'result_digest': digest(result['result'])})
            return result['result']
        except BaseException:
            self.close()
            raise
        finally:
            self._request_lock.release()

    def close(self):
        with self._close_lock:
            return self._close_owned()

    def _close_owned(self):
        if self.closed:
            return getattr(self, 'cleanup_confirmed', False)
        self.closed = True
        self._stop.set()
        if (self._heartbeat_thread is not None
                and threading.current_thread() is not self._heartbeat_thread):
            self._heartbeat_thread.join(timeout=2)
        if self.reference is not None:
            _LIVE.pop(id(self.reference), None)
        confirmed = not self.create_attempted or self.container_id is not None
        try:
            if self.container_id is not None:
                observed = self.inspect(cleanup=True)
                if observed['State']['Running']:
                    self.call(['kill', '--signal=KILL', self.container_id], cleanup=True)
                self.call(['wait', self.container_id], cleanup=True)
                if self.pidfd is not None and not select.select([self.pidfd], [], [], 0)[0]:
                    raise RetrievalError('study_cleanup_unconfirmed')
                self.call(['rm', self.container_id], cleanup=True)
        except (OSError, ValueError):
            confirmed = False
        finally:
            if self.attach is not None:
                confirmed = self.attach.close() and confirmed
            if self.pidfd is not None:
                os.close(self.pidfd)
                self.pidfd = None
            self.stack.close()
        self.cleanup_confirmed = confirmed
        return confirmed


def check_live_study_resource(reference, projection):
    if (type(reference) is not LiveStudyResourceRef
            or getattr(reference, '_issuer', None) is not _ISSUER
            or _LIVE.get(id(reference)) is not getattr(reference, '_owner', None)):
        raise RetrievalError('study_live_resource_unavailable')
    owner = reference._owner
    if projection != owner.projection or _operation(owner.operation_ref) != projection:
        raise RetrievalError('study_operation_changed')
    owner.readback()
    return LiveStudyResourceObservation(owner.execution_id, owner.container_id, owner.pid,
        owner.start_ticks, owner.projection.image_id, owner.readback_digest, owner.pid_scope)


def _capture_inspection_observation(owner, source_cuts, *, _scientific=False):
    """Capture only actual owner observations, never a caller-authored B manifest.

This intentionally incomplete observation definition cannot qualify Phase B.
The fixed scientific driver must separately complete its registered manifest.
"""
    from .public_study_operation import admit_public_study_stage
    from ..parallel import _log_folder, _create_log
    from ..execution_output import capture_artifact, MAX_ARTIFACT_BYTES
    if owner.projection.operation != 'inspect_public_artifacts' or owner.report_artifact is not None:
        raise RetrievalError('study_inspection_result_unavailable')
    admit_public_study_stage(owner.operation_ref, owner.reference, 'inspect_release', source_cuts=source_cuts)
    payload = {'schema_version': 1, 'definition': 'issue162-owned-inspection-observations-v1',
        'scientific_manifest_complete': False, 'execution_id': owner.execution_id,
        'operation_digest': owner.projection.operation_digest,
        'resource_readback_digest': owner.readback_digest, 'pid_scope': owner.pid_scope,
        'observations': owner.records,
        'native_execution_observation': ('native-completed' if owner._native_completed else
            'attempted-outcome-unknown' if owner._native_start_dispatched else 'not-released')}
    if _scientific:
        from .study_driver import _ports
        from .study_inspection_manifest import assemble
        ports = _ports()
        inputs = ports.reviewed_public_study_inputs(owner.operation_ref)
        facts = owner.inspection_facts
        payload = assemble(inputs, owner.projection,
            catalog=ports.reviewed_public_study_catalog(owner.operation_ref),
            graphs=ports.reviewed_public_study_graphs(owner.operation_ref),
            tokenizers=facts['tokenizers'], conformance=facts['conformance'],
            windows=facts['windows'], lengths=facts['lengths'], packing=facts['packing'],
            execution_id=owner.execution_id, readback_digest=owner.readback_digest)
    raw = json.dumps(payload, sort_keys=True, allow_nan=False, separators=(',', ':')).encode() + b'\n'
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise RetrievalError('study_inspection_output_exceeded')
    from .study_driver import _storage, _ports
    _storage(_ports(), owner, additional=len(raw))
    from contextlib import nullcontext
    existing = getattr(owner.backend, 'run_artifact_context', None)
    context = (nullcontext((existing._folder, existing._directory)) if existing is not None
               else _log_folder(owner.projection.root))
    with context as (folder, directory):
        with _create_log(directory, '001.log') as output:
            offset = 0
            while offset < len(raw):
                count = output.write(raw[offset:])
                if not count:
                    raise RetrievalError('study_inspection_output_unavailable')
                offset += count
        relative = (folder / '001.log').relative_to(owner.projection.root).as_posix()
        artifact = capture_artifact(owner.projection.root, relative)
    admit_public_study_stage(owner.operation_ref, owner.reference, 'inspect_release', source_cuts=source_cuts)
    if artifact['sha256'] != hashlib.sha256(raw).hexdigest():
        raise RetrievalError('study_inspection_output_unavailable')
    _storage(_ports(), owner)
    owner.report_artifact = artifact


def _capture_scientific_inspection(owner, source_cuts):
    """No caller manifest/flags: reconstruct from this actual owner's responses."""
    return _capture_inspection_observation(owner, source_cuts, _scientific=True)


def _inspection_result_after_terminal(owner):
    """Only the fixed producer can expose its captured actual terminal observation."""
    if not owner.closed or owner.report_artifact is None or len(_RESULTS) >= 8:
        raise RetrievalError('study_inspection_result_unavailable')
    reference = StudyInspectionResultRef(_ISSUER, owner)
    _RESULTS[id(reference)] = owner
    try:
        check_study_inspection_result(reference, owner.operation_ref)
    except BaseException:
        _RESULTS.pop(id(reference), None)
        raise
    return reference


def check_study_inspection_result(reference, operation_ref):
    if (type(reference) is not StudyInspectionResultRef
            or getattr(reference, '_issuer', None) is not _ISSUER
            or _RESULTS.get(id(reference)) is not getattr(reference, '_owner', None)):
        raise RetrievalError('study_inspection_result_unavailable')
    from .. import execution, execution_store
    from ..execution_output import capture_artifact, MAX_ARTIFACT_BYTES
    from ..package_status import read_package_file
    owner = reference._owner
    projection = _operation(operation_ref)
    if owner.operation_ref is not operation_ref or owner.projection != projection or not owner.closed:
        raise RetrievalError('study_inspection_result_unavailable')
    caller = execution.trusted_caller(projection.root, execution_id=owner.execution_id)
    record = execution.get(projection.root, caller, owner.execution_id)
    if (record['execution_status'] not in execution_store.TERMINAL
            or record['operation_id'] != projection.operation_digest
            or record['execution_generation'] != owner.admission.execution_generation):
        raise RetrievalError('study_inspection_result_unavailable')
    artifact = owner.report_artifact
    if (artifact is None or record['output'].get('artifact') != artifact
            or capture_artifact(projection.root, artifact['path']) != artifact):
        raise RetrievalError('study_inspection_output_unavailable')
    raw = read_package_file(projection.root, artifact['path'], limit=MAX_ARTIFACT_BYTES, single_link=True)
    if capture_artifact(projection.root, artifact['path']) != artifact:
        raise RetrievalError('study_inspection_output_unavailable')
    return StudyInspectionResultObservation(owner.execution_id, artifact['path'], artifact['sha256'],
        raw, len(raw), owner.readback_digest, projection.image_id, projection.registration_sha256,
        record['execution_status'], record['cleanup_status'],
        'native-completed' if owner._native_completed else
        'attempted-outcome-unknown' if owner._native_start_dispatched else 'not-released', owner.deadline)


class _Backend:
    kind, external_mutations, cooperative_admission = 'public-study-offline', False, True

    def __init__(self, operation_ref, projection):
        self.operation_ref, self.projection, self.owner = operation_ref, projection, None
        self.steps = (('inspection', 0),) if projection.operation == 'inspect_public_artifacts' else tuple(
            (model, index) for model in ('minilm', 'bge_m3') for index in range(3))
        self.step = 0
        self.artifact_anchor = None

    def admit_resources(self, registry, request):
        from ..execution_store import TERMINAL
        if any(record['backend']['kind'] == self.kind
               and (record['execution_status'] not in TERMINAL
                    or record['cleanup_status'] not in {'confirmed', 'not_required'})
               for record in registry['records'].values()):
            raise RetrievalError('study_worker_already_owned')

    def dispatch(self, root, admission, request):
        admission.consume(root, request)
        self.owner = _Owner(self.operation_ref, self.projection, admission, request)
        self.owner.backend = self
        try:
            self.owner.start()
        except Exception:
            confirmed = self.owner.close()
            return {'execution_status': 'failed', 'terminal_reason': 'study_start_unavailable',
                    'cleanup_status': 'confirmed' if confirmed else 'unconfirmed',
                    'operation_outcome': 'not_applicable'}
        except BaseException:
            self.owner.close()
            raise
        return None

    def advance(self, reference):
        if (self.owner is None or reference is not self.owner.reference
                or self.step + 1 >= len(self.steps)):
            raise RetrievalError('study_process_step_unavailable')
        previous = self.owner
        previous.current()
        if not previous.close():
            raise RetrievalError('study_cleanup_unconfirmed')
        self.step += 1
        self.owner = _Owner(self.operation_ref, self.projection, previous.admission, previous.request)
        self.owner.backend, self.owner.records = self, previous.records
        try:
            return self.owner.start()
        except BaseException:
            self.owner.close()
            raise

    def cancel(self, root, admission):
        admission.consume(root)
        return self.owner is not None and self.owner.close()


@contextmanager
def owned_study_runtime(operation_ref):
    from .. import execution
    projection = _operation(operation_ref)
    if os.name != 'posix' or not hasattr(os, 'pidfd_open') or not hasattr(os, 'P_PIDFD'):
        raise RetrievalError('owned_runtime_platform_unsupported')
    from .study_resources import RESOURCE_PROFILE_SHA256
    if (type(projection.hard_timeout_seconds) is not int
            or not 1 <= projection.hard_timeout_seconds <= MAX_SECONDS
            or projection.resource_profile_sha256 != RESOURCE_PROFILE_SHA256):
        raise RetrievalError('study_profile_unavailable')
    caller = execution.trusted_caller(projection.root)
    backend = _Backend(operation_ref, projection)
    record = execution.submit(projection.root, caller,
        execution.SubmitRequest(projection.execution_intent,
            {'operation_digest': projection.operation_digest}, projection.hard_timeout_seconds,
            label=projection.execution_label, operation_id=projection.operation_digest), backend=backend)
    if (backend.owner is None or backend.owner.reference is None or backend.owner.closed
            or record['execution_status'] != 'running'):
        raise RetrievalError('study_dispatch_not_repeated')
    owner = backend.owner
    check_live_study_resource(owner.reference, projection)
    failed = False
    try:
        yield owner.reference
    except BaseException:
        failed = True
        raise
    finally:
        owner = backend.owner
        confirmed = owner.close()
        caller = execution.trusted_caller(projection.root, execution_id=owner.execution_id)
        record = execution.get(projection.root, caller, owner.execution_id)
        output = None
        if owner.report_artifact is not None:
            size = owner.report_artifact['size']
            output = {'artifact': owner.report_artifact,
                      'preview': 'Actual bounded inspection observation stored.',
                      'observed_bytes': size, 'retained_bytes': size, 'dropped_bytes': 0,
                      'complete_output': False}
        elif backend.artifact_anchor is not None:
            output = {'artifact': backend.artifact_anchor, 'preview': 'Immutable study run artifacts.',
                      'complete_output': False}
        execution.record_event(projection.root, owner.admission.token,
            owner.execution_id, record['revision'], owner.admission.execution_generation,
            'owned-study-cleanup', {'execution_status': 'failed' if failed else 'succeeded',
                'terminal_reason': 'study_owner_closed',
                'cleanup_status': 'confirmed' if confirmed else 'unconfirmed',
                'operation_outcome': 'not_applicable', 'output': output})
