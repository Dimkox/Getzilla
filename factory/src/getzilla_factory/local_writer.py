"""Execute an explicitly configured, trusted local writer in its own Git worktree.

This process engine does not grant Factory admission, OS confinement, model
qualification or publication rights. Factory admission remains the caller's job.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

from .execution_contracts import TaskPacketV1
from .workspace import WorkspaceSnapshotV1


@dataclass(frozen=True)
class LocalWriterResult:
    status: str
    packet_digest: str
    input_head_sha: str
    result_head_sha: str
    patch: Path
    report: Path
    workspace: Path


class LocalWriter:
    def __init__(self, repository: Path, runtime: Path, command: tuple[str, ...],
                 checks: tuple[tuple[str, ...], ...]):
        if not command or not checks or any(not check for check in checks):
            raise ValueError('writer and verification commands are required')
        self.repository = Path(repository).resolve(strict=True)
        self.runtime = Path(runtime).absolute()
        self.command = tuple(command)
        self.checks = tuple(tuple(check) for check in checks)

    @staticmethod
    def _git(root: Path, *args: str) -> bytes:
        env = {name: value for name, value in os.environ.items() if not name.startswith('GIT_')}
        env.update(GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1')
        return subprocess.check_output(
            ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', *args],
            cwd=root, env=env, stderr=subprocess.PIPE, timeout=30,
        )

    @staticmethod
    def _save(path: Path, value: dict) -> None:
        raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        temporary = path.with_suffix('.pending')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

    def _process(self, command, workspace, run, phase, packet, deadline, input_file=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {'phase': phase, 'returncode': None, 'status': 'timeout'}
        environment = {name: os.environ[name] for name in packet.capability_policy.environment_names
                       if name in {'PATH', 'LANG', 'LC_ALL', 'TZ'} and name in os.environ}
        environment.update(PATH=environment.get('PATH', os.defpath), HOME=str(run / 'home'),
                           PYTHONDONTWRITEBYTECODE='1', GIT_TERMINAL_PROMPT='0')
        def child_limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            limit = packet.limits.max_output_bytes
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        log = run / (phase + '.log')
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as output:
            child = subprocess.Popen(command, cwd=workspace, env=environment,
                                     stdin=input_file or subprocess.DEVNULL,
                                     stdout=output, stderr=subprocess.STDOUT,
                                     start_new_session=True, preexec_fn=child_limits)
            status = 'completed'
            try:
                code = child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                status = 'timeout'
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    code = child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    code = child.wait()
        return {'phase': phase, 'returncode': code, 'status': status,
                'log': log.name, 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}

    def run(self, packet: TaskPacketV1, prompt: str) -> LocalWriterResult:
        if os.name != 'posix' or packet.role != 'writer':
            raise ValueError('a Linux/POSIX writer packet is required')
        if not prompt or len(prompt.encode()) > 262144:
            raise ValueError('task prompt must contain at most 256 KiB')
        expected = packet.authority.exact_head_sha
        if self._git(self.repository, 'rev-parse', expected + '^{commit}').decode().strip() != expected:
            raise ValueError('packet source commit unavailable')
        identity = hashlib.sha256((packet.task_id + '\0' + packet.run_id).encode()).hexdigest()
        command_digest = hashlib.sha256(json.dumps([self.command, self.checks]).encode()).hexdigest()
        self.runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        run = self.runtime / identity
        run.mkdir(mode=0o700, exist_ok=True)
        lock = os.open(run / 'lock', os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            report, patch, workspace = run / 'result.json', run / 'change.patch', run / 'workspace'
            if report.exists():
                saved = json.loads(report.read_bytes())
                if (saved['packet_digest'] != packet.packet_digest
                        or saved['prompt_sha256'] != hashlib.sha256(prompt.encode()).hexdigest()
                        or saved['command_digest'] != command_digest):
                    raise ValueError('run identity already belongs to another task input')
                return LocalWriterResult(saved['status'], packet.packet_digest, expected,
                                         saved['result_head_sha'], patch, report, workspace)
            if workspace.exists():
                raise ValueError('interrupted run requires recovery; not executing twice')
            deadline = time.monotonic() + packet.limits.wall_seconds
            self._git(self.repository, 'worktree', 'add', '--detach', str(workspace), expected)
            (run / 'home').mkdir(mode=0o700)
            task = run / 'task.json'
            self._save(task, {'packet': packet.to_dict(), 'prompt': prompt})
            with task.open('rb') as source:
                invocation = self._process(self.command, workspace, run, 'writer', packet, deadline, source)
            checks = []
            status = 'writer_failed'
            if invocation['returncode'] == 0 and invocation['status'] == 'completed':
                status = 'checks_passed'
                for index, command in enumerate(self.checks):
                    result = self._process(command, workspace, run, 'check-' + str(index), packet, deadline)
                    checks.append(result)
                    if result['returncode'] != 0 or result['status'] != 'completed':
                        status = 'checks_failed'
                        break
            self._git(workspace, 'add', '-A')
            names = self._git(workspace, 'diff', '--cached', '--name-only', '-z').decode().split('\0')
            allowed = packet.capability_policy.allowed_paths
            if any(name and not any(name == path or name.startswith(path.rstrip('/') + '/') for path in allowed)
                   for name in names):
                status = 'scope_violation'
            diff = self._git(workspace, 'diff', '--cached', '--binary', expected)
            if len(diff) > packet.limits.max_output_bytes:
                raise ValueError('result patch exceeds output budget')
            fd = os.open(patch, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as target:
                target.write(diff)
            result_head = expected
            if diff and status != 'scope_violation':
                if self._git(workspace, 'diff', '--cached'):
                    self._git(workspace, '-c', 'user.name=Getzilla local writer',
                              '-c', 'user.email=local-writer@example.invalid', '-c', 'commit.gpgsign=false',
                              'commit', '-m', 'Local task ' + packet.task_id)
                result_head = self._git(workspace, 'rev-parse', 'HEAD').decode().strip()
            snapshot = WorkspaceSnapshotV1.from_facts({
                'contract_version': 1, 'repository_id': packet.repository_id,
                'workspace_handle': packet.workspace_handle, 'input_head_sha': expected,
                'result_head_sha': result_head, 'diff_digest': hashlib.sha256(diff).hexdigest(),
                'diff_lines': len(diff.splitlines()), 'source': 'trusted_git_broker',
            })
            self._save(report, {'status': status, 'qualification': 'review_required',
                                'packet_digest': packet.packet_digest,
                                'command_digest': command_digest,
                                'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(),
                                'input_head_sha': expected, 'result_head_sha': result_head,
                                'writer': invocation, 'checks': checks,
                                'workspace_snapshot': snapshot.to_dict()})
            return LocalWriterResult(status, packet.packet_digest, expected, result_head, patch, report, workspace)
        finally:
            os.close(lock)
