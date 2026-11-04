"""Independent heavy work runs on every verified CPU, never one command at a time.

Agents tend to run tests, checks and probes one after another even on a 26-CPU host, so a
session spends minutes and millions of context tokens with one core busy. Getzilla owns the
schedule instead of hoping the agent remembers a rule:

- :func:`capacity` is the number of worker processes for this host (the startup measurement
  in ``.getzilla/runtime/startup-capacity.json`` when fresh, else allowed CPUs minus the owner's
  reserve);
- :func:`run_batch` (``getzilla par``) runs independent shell commands concurrently, each one
  checked by the repository policy first, and returns a bounded summary while head/tail logs
  stay within a 32 MiB batch budget in ``.getzilla/runtime/par/``;
- :func:`serial_refusal` (PreToolUse) refuses a serial batch of heavy commands (``a && b && c``,
  ``for ... do ...; done``, ``find -exec``) and a test runner forced into one process, and
  answers with the parallel command. ``GETZILLA_SERIAL=1`` in front of a command keeps it
  serial on purpose;
- :func:`session_note` (SessionStart) measures the host and tells the agent its capacity.
"""
from __future__ import annotations

import glob as _glob
import importlib.util
import json
import os
import re
import selectors
import signal
import uuid
from collections import deque
from contextlib import contextmanager
import shlex
import subprocess
import time
from threading import Event
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from . import STACK_DIR

CONFIG = '.getzilla/config/parallel.json'
SNAPSHOT = '.getzilla/runtime/startup-capacity.json'
LOGS = '.getzilla/runtime/par'
STATS = '.getzilla/runtime/parallel-guard.json'
SERIAL = 'GETZILLA_SERIAL=1'
FRESH_SECONDS = 12 * 3600
PREVIEW_BYTES = 4096
RESPONSE_BYTES = 32768
LOG_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 65536
MAX_LISTED_PASSES = 15

_LOOP = re.compile(r'^\s*for\s+([A-Za-z_]\w*)\s+in\s+(.+?)\s*;\s*do\s+(.+?)\s*;?\s*done\s*$', re.S)
_FIND_EXEC = re.compile(r'\bfind\s+(.+?)\s+-exec\s+(\S+)(.*?)\{\}\s*\\?;')


def config(root: Path) -> dict[str, Any]:
    for path in (root / CONFIG, STACK_DIR / 'config' / 'parallel.json'):
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
    return {'min_batch': 3, 'reserve': 2, 'heavy_programs': [], 'install_words': [], 'runners': [],
            'batch_target_pattern': '(?i)test'}


def _allowed_cpus() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count() or 1


def capacity(root: Path) -> int:
    """Worker processes for this host: a fresh startup measurement, else allowed CPUs minus the reserve."""
    try:
        snapshot = json.loads((root / SNAPSHOT).read_text(encoding='utf-8'))
        observed = datetime.fromisoformat(str(snapshot['observed_at']).replace('Z', '+00:00')).timestamp()
        if time.time() - observed < FRESH_SECONDS and int(snapshot['chosen_capacity']) >= 1:
            return int(snapshot['chosen_capacity'])
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return max(1, _allowed_cpus() - int(config(root).get('reserve', 2)))


# -- running a batch ------------------------------------------------------------------------------

@dataclass
class Job:
    index: int
    command: str
    returncode: int | None = None
    seconds: float = 0.0
    log: Path | None = None
    refused: str | None = None
    observed_bytes: int = 0
    retained_bytes: int = 0
    dropped_bytes: int = 0
    truncated: bool = False
    preview: str = ''
    preview_truncated: bool = False
    log_error: str | None = None


def policy_refusal(root: Path, command: str, *, cwd: Path | None = None) -> str | None:
    """The same verdict the PreToolUse hook would give this command on its own."""
    from .policy import evaluate_pre_tool, sensitive_action

    directory = (root if cwd is None else cwd).resolve()
    event = {'tool_name': 'Bash', 'tool_input': {'command': command}}
    action = sensitive_action(root, event, execution_cwd=directory)
    if action:
        return f'sensitive action {action}: run it on its own so the policy and its approvals apply'
    allowed, reason = evaluate_pre_tool(root, event, execution_cwd=directory)
    return None if allowed else (reason or 'refused by repository policy')


def expand_each(patterns: list[str], template: str, cwd: Path) -> list[str]:
    paths: list[str] = []
    for pattern in patterns:
        matches = sorted(_glob.glob(pattern, root_dir=cwd)) if any(ch in pattern for ch in '*?[') else [pattern]
        paths.extend(match for match in matches if match not in paths)
    if '{}' not in template:
        template = f'{template} {{}}'
    return [template.replace('{}', shlex.quote(path)) for path in paths]


def _text(data: bytes, limit: int) -> str:
    """Decode only a bounded slice; discard incomplete UTF-8 at either boundary."""
    return data[-limit:].decode('utf-8', 'ignore')


def _preview(data: bytes) -> str:
    # Suppress likely credentials as a whole preview. Command text is never persisted or shown.
    text = _text(data, PREVIEW_BYTES)
    if re.search(r'(?i)(?:password|secret|token|api[_-]?key)\s*[:=]|PRIVATE KEY|AKIA[0-9A-Z]{16}', text):
        return '[preview withheld: possible credential]'
    return text


@contextmanager
def _log_folder(root: Path):
    """Hold no-follow directory descriptors through creation and every write (#168)."""
    from .resource_inventory import classify

    root = root.resolve()
    descriptors = [os.open(root, os.O_RDONLY | os.O_DIRECTORY)]
    try:
        for name in ('.getzilla', 'runtime', 'par'):
            try:
                os.mkdir(name, mode=0o700, dir_fd=descriptors[-1])
            except FileExistsError:
                pass
            descriptors.append(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                       dir_fd=descriptors[-1]))
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + f'-{os.getpid()}-{uuid.uuid4().hex}'
        folder = root / LOGS / stamp
        if classify(root, folder) != 'ephemeral':
            raise OSError('unsafe parallel log ownership')
        os.mkdir(stamp, mode=0o700, dir_fd=descriptors[-1])
        descriptors.append(os.open(stamp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=descriptors[-1]))
        yield folder, descriptors[-1]
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _create_log(directory: int, name: str):
    return os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory), 'wb', buffering=0)


def _capture(job: Job, directory: int, cwd: Path, quota: int, timeout: float | None,
             runner: Callable[..., Any], preview_limit: int = PREVIEW_BYTES,
             cancelled: Event | None = None) -> None:
    cancelled = cancelled or Event()
    if cancelled.is_set():
        job.returncode = 130
        return
    head_limit, tail_limit = quota // 2, quota - quota // 2
    tail: deque[bytes] = deque()
    tail_bytes = head_bytes = 0
    preview = bytearray()
    handle = None

    def write(data: bytes) -> None:
        nonlocal handle
        if handle is None:
            return
        try:
            # Raw FileIO can perform short writes.
            view = memoryview(data)
            while view:
                count = handle.write(view)
                if not count:
                    raise OSError('short log write')
                job.retained_bytes += count
                view = view[count:]
        except OSError as error:
            job.log_error = f'log write failed (errno={error.errno})'
            handle.close()
            handle = None

    try:
        handle = _create_log(directory, f'{job.index:03d}.log')
    except OSError as error:
        job.log_error = f'log create failed (errno={error.errno})'
    started = time.monotonic()
    try:
        # One merged pipe drains both streams. Every shell command passed policy preflight.
        process = runner(job.command, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,  # nosec B604
                         start_new_session=True)
        timed_out = False
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                stopped_at = None
                # EOF does not imply process exit: the deadline and cancellation
                # must cover children which close both descriptors before waiting.
                while selector.get_map() or process.poll() is None:
                    now = time.monotonic()
                    timed_out = timed_out or (timeout is not None and now - started >= timeout)
                    if stopped_at is None and (timed_out or cancelled.is_set()):
                        stopped_at = now
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if stopped_at is not None and now - stopped_at >= 1:
                        job.log_error = 'process-group cleanup or output drain unconfirmed'
                        break
                    if not selector.get_map():
                        time.sleep(0.01)
                        continue
                    for key, _ in selector.select(0.05):
                        data = os.read(key.fd, CHUNK_BYTES)
                        if not data:
                            selector.unregister(key.fileobj)
                            break
                        job.observed_bytes += len(data)
                        if preview_limit:
                            preview.extend(data)
                            del preview[:-preview_limit]
                        head = data[:max(0, head_limit - head_bytes)]
                        write(head)
                        head_bytes += len(head)
                        rest = data[len(head):]
                        if rest and tail_limit:
                            tail.append(rest)
                            tail_bytes += len(rest)
                            while tail_bytes > tail_limit:
                                excess = tail_bytes - tail_limit
                                first = tail.popleft()
                                if len(first) > excess:
                                    tail.appendleft(first[excess:])
                                    tail_bytes -= excess
                                else:
                                    tail_bytes -= len(first)
                job.returncode = 130 if cancelled.is_set() else (124 if timed_out else process.returncode)
        finally:
            # An interrupted parent must not leave its owned process group running.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.stdout is not None:
                process.stdout.close()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                job.log_error = 'process-group cleanup unconfirmed'
                job.returncode = 124 if timed_out else 130
        for chunk in tail:
            write(chunk)
    except OSError as error:
        job.returncode = 127
        job.log_error = f'capture failed (errno={error.errno})'
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError as error:
                job.log_error = f'log close failed (errno={error.errno})'
        job.seconds = time.monotonic() - started
        job.dropped_bytes = job.observed_bytes - job.retained_bytes
        job.truncated = job.dropped_bytes > 0
        job.preview = _preview(bytes(preview))
        job.preview_truncated = job.observed_bytes > preview_limit


def _entry(job: Job) -> dict[str, Any]:
    return {'index': job.index, 'exit': job.returncode, 'seconds': round(job.seconds, 2),
            'log': job.log.name if job.log else None, 'observed_bytes': job.observed_bytes,
            'retained_bytes': job.retained_bytes, 'dropped_bytes': job.dropped_bytes,
            'truncated': job.truncated, 'complete_output': not (job.truncated or job.log_error),
            'preview': job.preview, 'preview_truncated': job.preview_truncated, 'log_error': job.log_error}


def run_batch(root: Path, commands: list[str], *, workers: int, cwd: Path, timeout: float | None = None,
              runner: Callable[..., Any] = subprocess.Popen,
              log_quota: int = LOG_BYTES) -> tuple[list[Job], Path]:
    """Synchronous batch; the combined retained output budget applies to the whole batch.

    Lossy stdout is diagnostic output, never a mandatory full-report evidence artifact.
    """
    if not commands or not 0 <= log_quota <= LOG_BYTES:
        raise ValueError('commands required and log quota must be between zero and 32 MiB')
    cwd = cwd.resolve()
    jobs = [Job(index, command) for index, command in enumerate(commands, 1)]
    for job in jobs:
        job.refused = policy_refusal(root, job.command, cwd=cwd)
    with _log_folder(root) as (folder, directory):
        if any(job.refused for job in jobs):
            return jobs, folder

        cancellation = Event()

        def one(job: Job) -> None:
            job.log = folder / f'{job.index:03d}.log'
            quota = log_quota // len(jobs) + int(job.index <= log_quota % len(jobs))
            _capture(job, directory, cwd, quota, timeout, runner,
                     preview_limit=min(PREVIEW_BYTES, RESPONSE_BYTES // len(jobs)),
                     cancelled=cancellation)

        pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs))))
        try:
            for _ in pool.map(one, jobs):
                pass
        except BaseException:
            # Signal running workers before executor shutdown waits for them.
            cancellation.set()
            pool.shutdown(wait=True, cancel_futures=True)
            raise
        else:
            pool.shutdown(wait=True)
        from .resource_inventory import classify
        owned = os.fstat(directory)
        try:
            current = folder.lstat()
            intact = (classify(root, folder) == 'ephemeral'
                      and (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino))
        except OSError:
            intact = False
        if not intact:
            for job in jobs:
                job.log_error = 'log namespace changed; artifact unavailable'
        # Bound the serialized envelope too, including escaped control characters in previews.
        entries: list[dict[str, Any]] = []
        size = 2
        for job in jobs:
            entry = _entry(job)
            encoded = json.dumps(entry, ensure_ascii=False).encode('utf-8')
            if size + len(encoded) + 128 > RESPONSE_BYTES:
                entries.append({'metadata_truncated': True, 'omitted_jobs': len(jobs) - len(entries)})
                break
            entries.append(entry)
            size += len(encoded) + 2
        try:
            with _create_log(directory, 'summary.json') as handle:
                pending = memoryview((json.dumps(entries, ensure_ascii=False) + '\n').encode('utf-8'))
                while pending:
                    count = handle.write(pending)
                    if not count:
                        raise OSError('short summary write')
                    pending = pending[count:]
        except OSError as error:
            for job in jobs:
                job.log_error = f'summary write failed (errno={error.errno})'
    return jobs, folder


def report(root: Path, jobs: list[Job], folder: Path, *, workers: int, wall: float, show_all: bool = False) -> str:
    """Render a bounded response from captured values, without reopening host paths."""
    refused = sum(bool(job.refused) for job in jobs)
    failed = sum(job.returncode != 0 for job in jobs)

    def lines():
        if refused:
            yield f'getzilla par: nothing ran; {refused} of {len(jobs)} commands were refused:'
            for job in jobs:
                if job.refused:
                    # Policy errors can contain command operands; keep them out of the response.
                    yield f'  job {job.index}: refused by repository policy'
            return
        yield (f'getzilla par: {len(jobs)} commands on {min(workers, len(jobs))} workers, {wall:.1f} s wall '
               f'({sum(job.seconds for job in jobs):.1f} s of work); {len(jobs) - failed} passed, {failed} failed; '
               f'logs: {LOGS}/{folder.name}')
        for job in jobs:
            if job.returncode != 0 or show_all or len(jobs) - failed <= MAX_LISTED_PASSES:
                status = f'FAIL exit={job.returncode}' if job.returncode != 0 else 'pass'
                yield f'{status} {job.seconds:.1f}s  job {job.index}'
                if job.returncode != 0 or show_all:
                    yield job.preview
                    if job.preview_truncated:
                        yield '[preview truncated]'
            if job.truncated or job.log_error:
                yield (f'job {job.index}: observed={job.observed_bytes} retained={job.retained_bytes} '
                       f'dropped={job.dropped_bytes}; complete_output=false; '
                       f'{job.log_error or "output truncated"}; full-report evidence required separately')
        if not show_all and len(jobs) - failed > MAX_LISTED_PASSES:
            yield f'pass: {len(jobs) - failed} commands (bounded metadata in summary.json)'

    result = bytearray()
    marker = b'\n[response truncated; metadata/preview omitted]'
    # Reserve a byte for the CLI print newline as part of the response budget.
    budget = RESPONSE_BYTES - len(marker) - 1
    for line in lines():
        encoded = (line + '\n').encode('utf-8')
        if len(result) + len(encoded) > budget:
            result.extend(encoded[:max(0, budget - len(result))])
            return result.decode('utf-8', 'ignore') + marker.decode()
        result.extend(encoded)
    return result.decode('utf-8').rstrip()


# -- refusing serial batches ----------------------------------------------------------------------

@dataclass
class Serial:
    kind: str
    advice: str
    commands: list[str] = field(default_factory=list)


def _words(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return []


def _program(words: list[str]) -> str:
    words = [word for word in words if not re.match(r'^[A-Za-z_]\w*=', word)]
    return os.path.basename(words[0]) if words else ''


def _heavy(words: list[str], settings: dict[str, Any]) -> bool:
    program = _program(words)
    if program not in set(settings.get('heavy_programs', [])) and not program.endswith(('.sh', '.py', '.php')):
        return False
    return not any(word in set(settings.get('install_words', [])) for word in words[1:3])


def _chain(command: str) -> list[str] | None:
    """Top-level ``&&``/``;`` segments of a plain command; None when it has pipes, fallbacks or expansion."""
    if any(mark in command for mark in ('||', '|', '$', '`', '<<', '(', ')', '&&&')) or '\n' in command.strip():
        return None
    parts = re.split(r'\s*(?:&&|;)\s*', command.strip())
    return [part for part in parts if part]


def _par_command(workers: int, commands: list[str]) -> str:
    return f'getzilla par -j {workers} -- ' + ' '.join(shlex.quote(command) for command in commands)


def _runner_advice(words: list[str], settings: dict[str, Any], root: Path, workers: int) -> str | None:
    program = _program(words)
    args = words[1:]
    if program.startswith('python') and len(args) >= 2 and args[0] == '-m':
        program, args = args[1], args[2:]
    elif program in {'npx', 'bunx'} and args:
        program, args = os.path.basename(args[0]), args[1:]
    elif program in {'pnpm', 'yarn'} and len(args) >= 2 and args[0] in {'exec', 'dlx'}:
        program, args = os.path.basename(args[1]), args[2:]
    joined = ' '.join(args)
    for runner in settings.get('runners', []):
        if program not in runner.get('programs', []) and program != runner.get('module'):
            continue
        if runner.get('subcommand') and (not args or args[0] != runner['subcommand']):
            continue
        for flag in runner.get('serial_flags', []):
            if re.search(rf'(?:^|\s){re.escape(flag)}(?:\s|$)', joined):
                return runner['advice'].format(flag=flag, workers=workers)
        if runner.get('parallel_flags'):
            if any(arg == flag or arg.startswith(flag) for arg in args for flag in runner['parallel_flags']):
                return None
            targets = [arg for arg in args if not arg.startswith('-')]
            pattern = runner.get('targeted')
            if targets and pattern and all(re.search(pattern, target) for target in targets) and len(targets) <= 2:
                return None  # one or two named tests: a focused run, not a suite
            if runner.get('requires_module') and importlib.util.find_spec(runner['requires_module']) is None:
                return None
            return runner['advice'].format(workers=workers)
        if runner.get('paratest') and (root / runner['paratest']).is_file():
            return runner['advice'].format(workers=workers)
    return None


def serial_batch(root: Path, command: str, cwd: Path) -> Serial | None:
    settings = config(root)
    if command.lstrip().startswith(SERIAL) or re.search(r'\bgetzilla(?:_par\.py|\s+par)\b', command):
        return None
    workers = capacity(root)
    if workers < 3:
        return None
    loop = _LOOP.match(command)
    if loop:
        variable, items, body = loop.groups()
        if _heavy(_words(body.split(';')[0].split('&&')[0]), settings):
            template = re.sub(rf'"?\$\{{?{variable}\}}?"?', '{}', body)
            if '$' in items or '`' in items or '$' in template:
                return Serial('loop', f'this loop runs its body one item at a time on a {workers}-worker host; '
                              f'run the items with `getzilla par -j {workers} --each <glob> -- <command with {{}}>`')
            each = ' '.join(f'--each {shlex.quote(item)}' for item in _words(items))
            return Serial('loop', f'getzilla par -j {workers} {each} -- {shlex.quote(template)}')
    found = _FIND_EXEC.search(command)
    if found and _heavy([found.group(2), *_words(found.group(3))], settings):
        return Serial('find-exec', f'find {found.group(1)} -print0 | xargs -0 -P {workers} -n 1 {found.group(2)}{found.group(3).rstrip()}')
    segments = _chain(command)
    if segments:
        heavy = [segment for segment in segments if _heavy(_words(segment), settings)]
        pattern = re.compile(settings.get('batch_target_pattern', '(?i)test'))
        alike = len({_program(_words(segment)) for segment in heavy}) == 1
        if (len(heavy) >= int(settings.get('min_batch', 3)) and len(heavy) == len(segments) and alike
                and all(pattern.search(' '.join(_words(segment)[1:])) for segment in heavy)):
            return Serial('chain', _par_command(workers, segments), segments)
        for segment in segments:
            advice = _runner_advice(_words(segment), settings, root, workers)
            if advice:
                return Serial('runner', f'`{segment}` runs in one process on a {workers}-worker host: {advice}')
    return None


def _record(root: Path, kind: str) -> None:
    path = root / STATS
    try:
        data = json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}
        data = data if isinstance(data, dict) else {}
        data.setdefault('since', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
        data[kind] = int(data.get(kind, 0)) + 1
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    except (OSError, ValueError):
        return


def serial_refusal(root: Path, command: str, cwd: Path) -> str | None:
    """PreToolUse: the parallel command to run instead of a serial batch, or None."""
    found = serial_batch(root, command, cwd)
    if found is None:
        return None
    _record(root, found.kind)
    return ('Getzilla: not run, independent heavy work must use the verified CPUs instead of one process. '
            f'Run instead: {found.advice}\n'
            f'If the order matters (shared state, build then test), start the command with {SERIAL} and say why.')


def session_note(root: Path) -> str:
    """SessionStart: measure the host once and tell the agent how to use it."""
    workers = capacity(root)
    snapshot = root / SNAPSHOT
    try:
        fresh = time.time() - snapshot.stat().st_mtime < FRESH_SECONDS
    except OSError:
        fresh = False
    if not fresh:
        try:
            from .startup_cpu import measure

            measured = measure(reserve=int(config(root).get('reserve', 2)), probe=False)
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.write_text(json.dumps(measured, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
            workers = capacity(root)
        except Exception:
            # Measuring is best effort; the note keeps the fallback capacity.
            workers = capacity(root)
    return (f'Capacity: {workers} worker processes on this host (measured; {SNAPSHOT}). Run independent tests, checks and '
            f'reviews concurrently: `getzilla par -j {workers} -- "cmd1" "cmd2"` or `--each "<glob>" -- cmd {{}}`; '
            f'test suites with their parallel flag (pytest -n {workers}). Serial heavy batches are refused.')
