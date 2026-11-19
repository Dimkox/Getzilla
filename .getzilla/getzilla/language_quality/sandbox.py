"""Offline container execution of consumer-controlled language tools."""
from __future__ import annotations

from dataclasses import dataclass
import os
import json
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import uuid

from ..cpu_budget import cpu_budget
from .models import ToolOutput


@dataclass(frozen=True)
class Execution:
    status: str
    output: ToolOutput
    summary: str = ''
    identity: str | None = None


def validate_spec(value: dict) -> dict:
    defaults = {'engine': 'docker', 'cpus': 2, 'memory_mb': 512, 'pids': 128,
                'timeout_seconds': 120, 'output_bytes': 1024 * 1024}
    if not isinstance(value, dict) or set(value) - (set(defaults) | {'image'}):
        raise ValueError('invalid sandbox configuration')
    result = {**defaults, **value}
    if not isinstance(result['engine'], str) or result['engine'] not in {'docker', 'podman'}:
        raise ValueError('unsupported sandbox backend')
    if not isinstance(result.get('image'), str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[a-f0-9]{64}', result['image']):
        raise ValueError('sandbox image must have an immutable sha256 digest')
    for name, lower, upper in (('cpus', 1, 64), ('memory_mb', 128, 8192), ('pids', 16, 512),
                               ('timeout_seconds', 1, 300), ('output_bytes', 1024, 1024 * 1024)):
        if type(result[name]) is not int or not lower <= result[name] <= upper:
            raise ValueError('invalid sandbox resource limit: ' + name)
    return result


def _stop(process: subprocess.Popen) -> None:
    # This is only the new session started below, never the controller group.
    try:
        if os.name == 'posix':
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def bounded_process(command: list[str], environment: dict[str, str], *, timeout: float,
                    output_limit: int, cancellation=None) -> Execution:
    """Bound memory while reading, instead of truncating an unbounded temp file."""
    if cancellation and cancellation():
        return Execution('CANCELLED', ToolOutput(-1, '', ''), 'cancelled before process start')
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, close_fds=True,
                               start_new_session=os.name == 'posix')
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    used = 0
    status, summary = 'COMPLETED', ''
    started = time.monotonic()
    try:
        with selectors.DefaultSelector() as selector:
            for name, handle in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(handle.fileno(), False)
                selector.register(handle, selectors.EVENT_READ, name)
            while selector.get_map():
                if cancellation and cancellation():
                    status, summary = 'CANCELLED', 'language execution cancelled'
                    break
                if time.monotonic() - started >= timeout:
                    status, summary = 'TIMEOUT', 'language execution exceeded time limit'
                    break
                for key, _ in selector.select(min(.05, timeout)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = output_limit - used
                    output[key.data].extend(chunk[:remaining])
                    used += min(remaining, len(chunk))
                    if len(chunk) > remaining:
                        status, summary = 'ERROR', 'language execution exceeded output limit'
                        break
                if status != 'COMPLETED':
                    break
        if status == 'COMPLETED':
            while process.poll() is None:
                if cancellation and cancellation():
                    status, summary = 'CANCELLED', 'language execution cancelled'
                    break
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    status, summary = 'TIMEOUT', 'language execution exceeded time limit'
                    break
                try:
                    process.wait(timeout=min(.05, remaining))
                except subprocess.TimeoutExpired:
                    continue
    finally:
        _stop(process)
        process.stdout.close()
        process.stderr.close()
    return Execution(status, ToolOutput(process.returncode,
                     bytes(output['stdout']).decode('utf-8', errors='replace'),
                     bytes(output['stderr']).decode('utf-8', errors='replace')), summary)


def private_parent(root: Path) -> Path:
    parent = root / '.getzilla/runtime/lqg'
    for path in (root / '.getzilla', root / '.getzilla/runtime', parent):
        if path.is_symlink():
            raise ValueError('unsafe sandbox scratch parent')
        path.mkdir(mode=0o700, exist_ok=True)
    attributes = parent.stat()
    if attributes.st_uid != os.getuid() or attributes.st_mode & 0o077:
        raise ValueError('sandbox scratch parent is not private to this user')
    return parent


def operator_images() -> frozenset[str]:
    """Read fixed host-owned admission, never repository policy or environment."""
    path = Path('/etc/getzilla/language-quality.json')
    try:
        for item in (Path('/etc'), path.parent, path):
            attributes = item.lstat()
            if stat.S_ISLNK(attributes.st_mode) or attributes.st_uid != 0 or attributes.st_mode & 0o022:
                return frozenset()
        if not stat.S_ISREG(attributes.st_mode) or attributes.st_size > 65536:
            return frozenset()
        from .core import _closed
        value = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_closed)
        if not isinstance(value, dict) or set(value) != {'schema_version', 'images'} or type(value['schema_version']) is not int or value['schema_version'] != 1:
            return frozenset()
        images = value['images']
        if not isinstance(images, list) or len(images) > 64 or len(set(images)) != len(images):
            return frozenset()
        for image in images:
            validate_spec({'image': image})
        return frozenset(images)
    except (OSError, UnicodeError, ValueError, TypeError):
        return frozenset()


class ContainerExecutor:
    def __init__(self, spec: dict, *, approved_images: frozenset[str] | None = None):
        self.spec = validate_spec(spec)
        self.client = Path('/usr/bin') / self.spec['engine']
        # Explicit admission is a trusted host API seam used by isolated tests or
        # an operator-owned runner. Repository policy never supplies this value.
        self.approved_images = operator_images() if approved_images is None else approved_images
        if not isinstance(self.approved_images, frozenset) or any(not isinstance(image, str) for image in self.approved_images):
            raise ValueError('operator image admission must be an immutable image set')

    def build_argv(self, snapshot: Path, package: str, argv: tuple[str, ...] | list[str], name: str) -> list[str]:
        from .core import safe_path
        if package != '.':
            safe_path(package)
        if not argv or not isinstance(argv[0], str) or not argv[0].startswith('/'):
            raise ValueError('sandbox entrypoint must be absolute')
        if any(not isinstance(arg, str) or '\0' in arg for arg in argv):
            raise ValueError('invalid sandbox argument')
        if not snapshot.is_absolute() or ',' in str(snapshot) or not re.fullmatch(r'lqg-[a-z0-9-]+', name):
            raise ValueError('invalid sandbox mount or name')
        cpus = cpu_budget(self.spec['cpus']).effective
        working = '/workspace' + ('/' + package if package != '.' else '')
        return [str(self.client), 'run', '--name', name, '--rm', '--pull', 'never',
                '--network', 'none', '--ipc', 'none', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--user', '65534:65534',
                '--cpus', str(cpus), '--memory', str(self.spec['memory_mb']) + 'm',
                '--memory-swap', str(self.spec['memory_mb']) + 'm', '--pids-limit', str(self.spec['pids']),
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m,mode=1777',
                '--mount', f'type=bind,src={snapshot},dst=/workspace,readonly',
                '--workdir', working, '--env', 'HOME=/tmp/home', '--env', 'TMPDIR=/tmp',
                '--env', 'CI=true', '--env', f'JAVA_TOOL_OPTIONS=-XX:ActiveProcessorCount={cpus}',
                '--env', f'GRADLE_OPTS=-Dorg.gradle.workers.max={cpus}',
                '--entrypoint', argv[0], self.spec['image'], *argv[1:]]

    def _available(self) -> bool:
        try:
            attributes = self.client.stat()
            return (os.name == 'posix' and not self.client.is_symlink() and stat.S_ISREG(attributes.st_mode)
                    and attributes.st_uid == 0 and not attributes.st_mode & 0o022)
        except OSError:
            return False

    def cache_identity(self, root: Path, *, cancellation=None) -> str | None:
        """Recheck host admission and locally resolved image before any cache read."""
        if self.spec['image'] not in self.approved_images or not self._available():
            return None
        with tempfile.TemporaryDirectory(prefix='identify-', dir=private_parent(root)) as temporary:
            environment = {'PATH': '/usr/bin:/bin', 'HOME': temporary,
                           'DOCKER_CONFIG': str(Path(temporary) / 'docker'), 'LANG': 'C.UTF-8'}
            result = bounded_process([str(self.client), 'image', 'inspect', '--format', '{{.Id}}', self.spec['image']],
                                     environment, timeout=10, output_limit=4096, cancellation=cancellation)
        image_id = result.output.stdout.strip()
        if result.status != 'COMPLETED' or result.output.returncode or not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
            return None
        return self.spec['engine'] + ':' + self.spec['image'] + ':' + image_id

    def execute(self, root: Path, package: str, files: tuple[str, ...], argv: tuple[str, ...] | list[str], *, cancellation=None, expected_digest=None) -> Execution:
        from .core import MAX_INPUT_BYTES, excluded, safe_path, read_input, _read_inputs
        if self.spec['image'] not in self.approved_images:
            return Execution('UNSUPPORTED_RUNNER', ToolOutput(-1, '', ''), 'sandbox image has no host-operator admission')
        if not self._available():
            return Execution('UNSUPPORTED_RUNNER', ToolOutput(-1, '', ''), 'trusted local container client unavailable')
        parent = private_parent(root)
        with tempfile.TemporaryDirectory(prefix='run-', dir=parent) as temporary:
            scratch = Path(temporary)
            snapshot = scratch / 'source'
            snapshot.mkdir()
            environment = {'PATH': '/usr/bin:/bin', 'HOME': str(scratch),
                           'DOCKER_CONFIG': str(scratch / 'docker'), 'LANG': 'C.UTF-8'}
            inspect = bounded_process([str(self.client), 'image', 'inspect', '--format', '{{.Id}}', self.spec['image']],
                                      environment, timeout=10, output_limit=4096, cancellation=cancellation)
            if inspect.status != 'COMPLETED':
                return inspect
            image_id = inspect.output.stdout.strip()
            if inspect.output.returncode or not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
                return Execution('UNSUPPORTED_RUNNER', ToolOutput(-1, '', ''), 'pinned sandbox image is not already available')
            identity = self.spec['engine'] + ':' + self.spec['image'] + ':' + image_id
            total = 0
            for name in files:
                safe_path(name)
                if excluded(name):
                    continue
                payload = read_input(root, name)
                total += len(payload)
                if total > MAX_INPUT_BYTES:
                    raise ValueError('sandbox snapshot byte limit exceeded')
                destination = snapshot / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('xb') as writer:
                    writer.write(payload)
                destination.chmod(0o444)
            if expected_digest is not None and _read_inputs(snapshot, files)[0] != expected_digest:
                return Execution('ERROR', ToolOutput(-1, '', ''), 'snapshot differs from planned input digest', identity)
            snapshot.chmod(0o755)
            name = 'lqg-' + uuid.uuid4().hex
            command = self.build_argv(snapshot, package, argv, name)
            result = None
            try:
                result = bounded_process(command, environment, timeout=self.spec['timeout_seconds'],
                                         output_limit=self.spec['output_bytes'], cancellation=cancellation)
            finally:
                # Killing a client alone cannot stop a detached daemon-owned container.
                cleanup = bounded_process([str(self.client), 'rm', '-f', name], environment, timeout=10, output_limit=4096)
            if cleanup.status != 'COMPLETED' or (cleanup.output.returncode and 'No such container' not in cleanup.output.stderr and 'no container with name or ID' not in cleanup.output.stderr):
                return Execution('ERROR', result.output, 'sandbox cleanup was not confirmed', identity)
            return Execution(result.status, result.output, result.summary, identity)
