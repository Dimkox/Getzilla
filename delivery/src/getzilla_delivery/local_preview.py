"""Optional real Linux static preview. No default registration, daemon or TCP listener.

The local OS owner and native canonical task form the tenancy boundary. This is
not confinement from hostile same-UID Python code or an enterprise customer ACL.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import select
import socket
import stat
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

from .landing_filesystem import owned_lock
from .landing_publication_contracts import PublicationError
from .preview_contracts import (
    CAPABILITIES,
    LIMITS,
    PROFILE,
    PreviewError,
    PreviewManifest,
    artifact,
    canonical,
    digest,
)


def repository_root(root):
    from getzilla.util import git_output
    common = git_output(root, 'rev-parse', '--git-common-dir')
    if not common:
        raise PreviewError('repository_unavailable')
    directory = (root / common).resolve() if not Path(common).is_absolute() else Path(common).resolve()
    if directory.name != '.git' or not directory.is_dir():
        raise PreviewError('unsupported_repository_layout')
    return directory.parent


def native_binding(root):
    from getzilla import state
    from getzilla.util import git_output
    route = state.require_route_owner(root)
    if route.get('status') in ('completed', 'cancelled') or type(route.get('authority_epoch')) is not int:
        raise PreviewError('authority_unavailable')
    project = repository_root(root)
    return {'tenant': f'uid:{os.geteuid()}',
            'project': digest([str(project), project.stat().st_dev, project.stat().st_ino]),
            'repository': digest(str(project)), 'task': route['logical_task_id'],
            'run': route['route_id'], 'owner': route['session_id'],
            'authority_epoch': route['authority_epoch'],
            'context_revision': route['context']['revision'],
            'source_sha': git_output(root, 'rev-parse', 'HEAD'),
            'source_tree': git_output(root, 'rev-parse', 'HEAD^{tree}'),
            'budget_ref': route['logical_task_id']}


def check_binding(root, manifest, *, source=True):
    try:
        if source:
            binding = native_binding(root)
        else:
            from getzilla import state
            route = state.require_route_owner(root)
            if route.get('status') in ('completed', 'cancelled'):
                raise PreviewError('authority_unavailable')
            binding = {'task': route['logical_task_id'], 'run': route['route_id'],
                       'owner': route['session_id'], 'authority_epoch': route['authority_epoch'],
                       'context_revision': route['context']['revision']}
        if any(getattr(manifest, name) != value for name, value in binding.items()):
            raise PreviewError('binding_mismatch')
    except (OSError, ValueError, KeyError) as error:
        raise PreviewError('authority_unavailable') from error


def runtime_digest():
    # Bind the exact trusted server and contracts, never artifact executable code.
    return digest({name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                   for name in ('preview_child.py', 'preview_contracts.py', 'preview_kernel.py', 'local_preview.py')})


def read_state(fd):
    try:
        item = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(item)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise PreviewError('state_custody')
        return json.loads(os.read(item, 16385))
    finally:
        os.close(item)


def write_state(fd, value):
    data = canonical(value)
    if len(data) > 16384:
        raise PreviewError('state_limits')
    name = f'.state-{os.getpid()}'
    item = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.write(item, data)
        os.fsync(item)
    finally:
        os.close(item)
    os.replace(name, 'state.json', src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)


class PreviewHandle:
    def __init__(self, adapter, manifest):
        self.adapter, self.manifest = adapter, manifest
        self.directory = adapter.directory
        self.socket_path = self.directory / 'access.sock'
        self.socket_address = f'/proc/self/fd/{adapter.fd}/access.sock'
        self.pid = (read_state(adapter.fd) or {}).get('pid')

    def request(self, path='/'):
        check_binding(self.adapter.root, self.manifest)
        if (type(path) is not str or len(path) > 256 or '\r' in path or '\n' in path
                or not path.startswith('/') or not path.isascii()):
            raise PreviewError('request_path')
        current = read_state(self.adapter.fd)
        if not current or current['manifest_digest'] != self.manifest.identity or current['state'] != 'ready':
            raise PreviewError('preview_unavailable')
        request = f'GET {path} HTTP/1.0\r\nX-Preview-Binding: {self.manifest.identity}\r\n\r\n'.encode()
        response = self._exchange(request)
        head, body = response.split(b'\r\n\r\n', 1)
        return int(head.split(b' ')[1]), body

    def _exchange(self, request):
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(1)
                client.connect(self.socket_address)
                client.sendall(request)
                result = bytearray()
                while True:
                    part = client.recv(65536)
                    if not part:
                        break
                    result.extend(part)
                    if len(result) > LIMITS['file_bytes'] + 4096:
                        raise PreviewError('response_limits')
                return bytes(result)
        except (OSError, ValueError, PublicationError) as error:
            raise PreviewError('preview_unavailable') from error

    def _observation(self):
        current = read_state(self.adapter.fd)
        if not current or current['manifest_digest'] != self.manifest.identity:
            raise PreviewError('stale_generation')
        process = self.adapter.processes.get(self.pid)
        if process is not None and process.poll() is not None:
            process.wait()
            current['process_reaped'] = True
            if current.get('cleanup') == 'confirmed' and current['state'] == 'destroying':
                current.update(state='destroyed', termination_confirmed=True)
        return current

    def observe(self):
        current = self._observation()
        if current['state'] == 'destroying':
            return self.reconcile()
        return current

    def reconcile(self):
        """Observe termination first; never signal a PID loaded from a file."""
        current = self._observation()
        if current['state'] == 'destroyed':
            return current
        from getzilla.disposable_resources import _process_identity
        try:
            alive = _process_identity(current['pid']) == current.get('process_identity')
        except FileNotFoundError:
            alive = False
        except (OSError, ValueError, TypeError):
            raise PreviewError('recovery_unknown') from None
        if alive:
            return current
        try:
            lease = owned_lock(self.adapter.fd, 'lease.lock', create=False, exclusive=True)
        except (OSError, PublicationError):
            raise PreviewError('cleanup_unconfirmed') from None
        try:
            latest = read_state(self.adapter.fd)
            if not latest or latest['manifest_digest'] != self.manifest.identity:
                raise PreviewError('stale_generation')
            try:
                item = os.stat('access.sock', dir_fd=self.adapter.fd, follow_symlinks=False)
            except FileNotFoundError:
                item = None
            if item is not None:
                if (not stat.S_ISSOCK(item.st_mode)
                        or [item.st_dev, item.st_ino] != current.get('socket_identity')):
                    raise PreviewError('cleanup_unconfirmed')
                os.unlink('access.sock', dir_fd=self.adapter.fd)
            current.update(state='destroyed', cleanup='confirmed',
                           reason=current['reason'] if current['state'] == 'destroying' else 'child_failed',
                           termination_confirmed=True)
            write_state(self.adapter.fd, current)
            return current
        finally:
            os.close(lease)

    def revoke(self):
        check_binding(self.adapter.root, self.manifest)
        current = self.observe()
        if current['state'] == 'destroyed':
            return current
        self._exchange(f'POST /revoke HTTP/1.0\r\nX-Preview-Binding: {self.manifest.identity}\r\n\r\n'.encode())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            current = self.observe()
            if current['state'] in ('destroyed', 'destroying') and current.get('cleanup') == 'confirmed':
                process = self.adapter.processes.get(self.pid)
                if process is not None:
                    process.wait(timeout=1)
                    current['process_reaped'] = True
                    current.update(state='destroyed', termination_confirmed=True)
                elif current['state'] == 'destroying':
                    current = self.reconcile()
                if current['state'] == 'destroyed':
                    return current
            time.sleep(.01)
        raise PreviewError('cleanup_unconfirmed')


class NativeLocalPreview:
    def __init__(self, root: Path, *, enabled=False):
        self.root, self.enabled = root, enabled
        self.fd = None
        self.directory = root / '.getzilla/runtime/previews'
        self.processes = {}

    def _enabled(self):
        if not self.enabled:
            raise PreviewError('preview_disabled')
        if sys.platform != 'linux':
            raise PreviewError('unsupported_platform')

    def manifest(self, files, *, generation, key, ttl=60):
        self._enabled()
        _, artifact_digest = artifact(files)
        manifest = PreviewManifest(1, PROFILE, **native_binding(self.root),
                                   artifact_digest=artifact_digest,
                                   config_digest=digest({'limits': LIMITS, 'capabilities': CAPABILITIES}),
                                   runtime_digest=runtime_digest(),
                                   build_digest=digest({'mode': 'prebuilt-static', 'artifact': artifact_digest}),
                                   dependency_digest=digest([]), dataset_digest=digest(None),
                                   generation=generation, key=key, ttl=ttl)
        manifest.validate()
        return manifest

    def _open(self):
        if self.fd is not None:
            return
        # Linked task worktrees share the repository-wide project quota.
        self.directory = repository_root(self.root) / '.getzilla/runtime/previews'
        self.directory.parent.mkdir(parents=True, exist_ok=True)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in self.directory.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                info = os.fstat(descriptor)
                sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o002 and not sticky:
                    raise PreviewError('runtime_custody')
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise PreviewError('runtime_custody')
            self.fd = descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def create(self, manifest, files):
        self._enabled()
        if type(manifest) is not PreviewManifest:
            raise PreviewError('manifest_type')
        manifest.validate()
        check_binding(self.root, manifest)
        owned, identity = artifact(files)
        if identity != manifest.artifact_digest:
            raise PreviewError('artifact_mismatch')
        if manifest.runtime_digest != runtime_digest():
            raise PreviewError('runtime_mismatch')
        self._open()
        # Admission is serialized independently of the child's lifetime lease.
        admission = owned_lock(self.fd, 'admission.lock', create=True, exclusive=True)
        try:
            previous = read_state(self.fd)
            if previous and previous['key'] == manifest.key:
                if previous['manifest_digest'] != manifest.identity:
                    raise PreviewError('intent_conflict')
                return PreviewHandle(self, manifest)  # Never relaunch an interrupted intent.
            try:
                lease = owned_lock(self.fd, 'lease.lock', create=True, exclusive=True)
            except (OSError, ValueError, PublicationError) as error:
                raise PreviewError('project_busy') from error
            try:
                if previous and manifest.generation <= previous['generation']:
                    raise PreviewError('stale_generation')
                if previous and previous['state'] == 'destroying' and previous.get('cleanup') == 'confirmed':
                    from getzilla.disposable_resources import _process_identity
                    try:
                        still_alive = _process_identity(previous['pid']) == previous.get('process_identity')
                    except FileNotFoundError:
                        still_alive = False
                    if not still_alive:
                        previous['state'] = 'destroyed'
                if previous and previous['state'] not in ('destroyed',):
                    raise PreviewError('recovery_unknown')
                deadline = time.monotonic() + manifest.ttl
                value = {'state': 'provisioning', 'reason': None, 'manifest_digest': manifest.identity,
                         'manifest': asdict(manifest), 'generation': manifest.generation, 'key': manifest.key,
                         'pid': None, 'process_reaped': False, 'cleanup': 'pending',
                         'transport': 'private-af-unix', 'functional': 'not_run', 'human_acceptance': 'not_run',
                         'capabilities': CAPABILITIES, 'limits': LIMITS}
                write_state(self.fd, value)
                from getzilla.fsx import owned_popen
                env = {'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1',
                       'GETZILLA_SESSION_ID': manifest.owner}
                payload = canonical({'root': str(self.root), 'manifest': asdict(manifest),
                                     'files': {k: base64.b64encode(v).decode() for k, v in owned.items()},
                                     'deadline': deadline, 'directory_fd': self.fd, 'lease_fd': lease})
                command = [sys.executable, '-I', '-B', str(Path(__file__).with_name('preview_child.py'))]
                process = owned_popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, env=env, pass_fds=(self.fd, lease),
                                      cwd=self.root)
                self.processes[process.pid] = process
                try:
                    os.set_blocking(process.stdin.fileno(), False)
                    offset, send_deadline = 0, min(deadline, time.monotonic() + 3)
                    while offset < len(payload):
                        if time.monotonic() >= send_deadline or process.poll() is not None:
                            raise PreviewError('provision_timeout')
                        writable = select.select([], [process.stdin], [], .05)[1]
                        if writable:
                            try:
                                offset += os.write(process.stdin.fileno(), payload[offset:offset + 65536])
                            except BlockingIOError:
                                continue
                    process.stdin.close()
                except BaseException:
                    process.terminate()
                    process.wait(timeout=2)
                    raise
            finally:
                os.close(lease)
            ready_deadline = min(deadline, deadline - manifest.ttl + 3)
            while time.monotonic() < ready_deadline:
                current = read_state(self.fd)
                if current['state'] == 'ready':
                    return PreviewHandle(self, manifest)
                if process.poll() is not None:
                    raise PreviewError('provision_failed')
                time.sleep(.01)
            raise PreviewError('provision_unknown')
        finally:
            os.close(admission)

    def close(self):
        # Only Popen objects created by this instance are process capabilities.
        for process in self.processes.values():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
