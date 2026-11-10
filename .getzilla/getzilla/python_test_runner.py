"""Isolated Core and Trust CI test sharding; local verification evidence only."""
from __future__ import annotations

from . import verification_journal as diagnostics

import argparse
import configparser
from contextlib import contextmanager
from dataclasses import dataclass, replace
from importlib import metadata
import importlib.util
import json
import os
import re
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from . import STACK_DIR, fsx
from ._cpu_capacity import linux_quota_capacity
from .verification_scope import FORCE_FULL_VARIABLE


PINS = {'pytest': '9.1.1', 'pytest-xdist': '3.8.0', 'pytest-cov': '7.1.0', 'coverage': '7.15.4'}
CONFIG = '.getzilla-test-runner.json'
TIMEOUT = 900
OUTPUT_LIMIT = 2 * 1024 * 1024
DEFAULT_CORE_WORKER_CAP = 6
DEFAULT_CORE_CPU_RESERVE = 2


class RunnerError(ValueError):
    pass


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RunnerError('duplicate test runner configuration key')
        result[key] = value
    return result


def selected_workers(root: Path) -> int | None:
    """No opt-in means the existing consumer runner remains authoritative."""
    return core_worker_selection(root, 'fast').workers


@dataclass(frozen=True)
class WorkerSelection:
    workers: int | None
    source: str
    capacity: int | None = None


def _automatic_capacity() -> int:
    """A live bounded ceiling, not a reservation of CPU, PID or memory capacity."""
    try:
        available = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        available = 0
    if available <= 0:
        available = os.cpu_count() or 1
    selected = min(28, max(1, available))
    if sys.platform == 'linux':
        quota = linux_quota_capacity()
        if quota is not None:
            selected = min(selected, quota)
    return selected


def core_worker_selection(root: Path, mode: str) -> WorkerSelection:
    """Keep explicit requests compatible; reserve bounded PR/release defaults."""
    path = root / CONFIG
    value: object = None
    source = 'consumer'
    if path.exists() or path.is_symlink():
        try:
            attributes = path.stat()
            if path.is_symlink() or not stat.S_ISREG(attributes.st_mode) or attributes.st_size > 4096:
                raise RunnerError('invalid test runner configuration file')
            config = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_closed_object)
            if not isinstance(config, dict) or set(config) != {'schema_version', 'workers'}:
                raise RunnerError('test runner configuration requires schema_version and workers')
            if type(config['schema_version']) is not int or config['schema_version'] != 1:
                raise RunnerError('unsupported test runner schema_version')
            value = config['workers']
            if value != 'auto' and (type(value) is not int or not 0 <= value <= 64):
                raise RunnerError('workers must be auto or an integer from 0 to 64')
            source = 'configuration'
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RunnerError('unreadable test runner configuration') from exc
    override = os.environ.get('GETZILLA_TEST_WORKERS')
    if override is not None:
        if override != 'auto' and (not override.isascii() or not override.isdecimal() or len(override) > 2):
            raise RunnerError('GETZILLA_TEST_WORKERS must be auto or an integer from 0 to 64')
        value = override if override == 'auto' else int(override)
        if value != 'auto' and value > 64:
            raise RunnerError('GETZILLA_TEST_WORKERS exceeds 64')
        source = 'environment'
    if value is None and mode not in {'pr', 'release'}:
        return WorkerSelection(None, source)
    if os.environ.get('_GETZILLA_TEST_CHILD') == '1':
        return WorkerSelection(0, 'child')
    if value is None:
        capacity = _automatic_capacity()
        return WorkerSelection(min(DEFAULT_CORE_WORKER_CAP, max(1, capacity - DEFAULT_CORE_CPU_RESERVE)),
                               'default', capacity)
    if value == 'auto':
        if not _parallel_process_cleanup_supported():
            return WorkerSelection(0, source)
        capacity = _automatic_capacity()
        return WorkerSelection(capacity, source, capacity)
    return WorkerSelection(int(value), source)


_CLEANUP_STAGES = frozenset({'owned_stop_reap', 'stdout_capture_file', 'stdout_capture_directory',
                             'stderr_capture_file', 'stderr_capture_directory', 'run_scratch_directory'})
_CLEANUP_CATEGORIES = frozenset({'permission', 'not_found', 'timeout', 'recursion', 'os_error', 'other'})
_CLEANUP_ORIGINS = frozenset({'process', 'tests', 'parallel_shard', 'coverage_combine',
                              'coverage_report', 'coverage_export'})
_CLEANUP_LIMIT = 16


@dataclass(frozen=True)
class CleanupFact:
    stage: str
    category: str
    errno: int | None = None
    origin: str = 'process'


@dataclass(frozen=True)
class CleanupMetadata:
    facts: tuple[CleanupFact, ...] = ()
    overflow: bool = False
    unavailable: bool = False


@dataclass
class ProcessResult:
    command: list[str]
    returncode: int
    stdout: str = ''
    stderr: str = ''
    seconds: float = 0.0
    terminal_state: str = 'completed'
    cleanup_error: str = ''
    cleanup_metadata: CleanupMetadata = CleanupMetadata()


def _validated_cleanup(value) -> CleanupMetadata:
    if (type(value) is not CleanupMetadata or type(value.facts) is not tuple
            or type(value.overflow) is not bool or type(value.unavailable) is not bool):
        return CleanupMetadata(unavailable=True)
    facts = []
    unavailable = value.unavailable
    for fact in value.facts[:_CLEANUP_LIMIT]:
        if (type(fact) is not CleanupFact or type(fact.stage) is not str or fact.stage not in _CLEANUP_STAGES
                or type(fact.category) is not str or fact.category not in _CLEANUP_CATEGORIES
                or type(fact.origin) is not str or fact.origin not in _CLEANUP_ORIGINS
                or not (fact.errno is None or type(fact.errno) is int and 0 <= fact.errno <= 65535)):
            unavailable = True
        else:
            facts.append(fact)
    return CleanupMetadata(tuple(facts), value.overflow or len(value.facts) > _CLEANUP_LIMIT, unavailable)


def _merge_cleanup(*values: CleanupMetadata) -> CleanupMetadata:
    facts = []
    overflow = unavailable = False
    for value in values:
        valid = _validated_cleanup(value)
        available = _CLEANUP_LIMIT - len(facts)
        facts.extend(valid.facts[:available])
        overflow = overflow or valid.overflow or len(valid.facts) > available
        unavailable = unavailable or valid.unavailable
    return CleanupMetadata(tuple(facts), overflow, unavailable)


def _with_cleanup_origin(value: CleanupMetadata, origin: str) -> CleanupMetadata:
    valid = _validated_cleanup(value)
    if type(origin) is not str or origin not in _CLEANUP_ORIGINS:
        return CleanupMetadata(unavailable=True)
    return CleanupMetadata(tuple(replace(fact, origin=origin) if fact.origin == 'process' else fact
                                 for fact in valid.facts), valid.overflow, valid.unavailable)


def _stored_cleanup(target) -> CleanupMetadata:
    try:
        value = target.cleanup_metadata if isinstance(target, ProcessResult) else getattr(
            target, '_getzilla_cleanup_metadata', CleanupMetadata())
    except BaseException:
        return CleanupMetadata(unavailable=True)
    return _validated_cleanup(value)


def _retain_cleanup(target, metadata: CleanupMetadata) -> None:
    if target is None:
        return
    valid = _validated_cleanup(metadata)
    if not (valid.facts or valid.overflow or valid.unavailable):
        return
    combined = _merge_cleanup(_stored_cleanup(target), valid)
    try:
        if isinstance(target, ProcessResult):
            target.cleanup_metadata = combined
        else:
            target._getzilla_cleanup_metadata = combined
    except BaseException:
        return  # A diagnostic sidecar must never replace the primary exception.


def _cleanup_failure(stage: str | None, error: BaseException) -> CleanupMetadata:
    if type(stage) is not str or stage not in _CLEANUP_STAGES:
        return CleanupMetadata(unavailable=True)
    if isinstance(error, PermissionError):
        category = 'permission'
    elif isinstance(error, FileNotFoundError):
        category = 'not_found'
    elif isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        category = 'timeout'
    elif isinstance(error, RecursionError):
        category = 'recursion'
    elif isinstance(error, OSError):
        category = 'os_error'
    else:
        category = 'other'
    try:
        number = getattr(error, 'errno', None)
    except BaseException:
        number = None
    if not (type(number) is int and 0 <= number <= 65535):
        number = None
    return CleanupMetadata((CleanupFact(stage, category, number),))


def _result_cleanup(value, origin: str) -> CleanupMetadata:
    metadata = _stored_cleanup(value)
    if isinstance(value, ProcessResult):
        if value.cleanup_error and not metadata.facts:
            metadata = replace(metadata, unavailable=True)
    else:
        try:
            present = isinstance(value, BaseException) and type(
                getattr(value, '_getzilla_cleanup_metadata', None)) is CleanupMetadata
        except BaseException:
            present = False
        if not present:
            metadata = replace(metadata, unavailable=True)
    return _with_cleanup_origin(metadata, origin)


def cleanup_details(value, *, origin: str = 'process', extra=None,
                    extra_origin: str = 'coverage_export') -> dict[str, object]:
    """Project closed facts only; private cleanup strings never become public data."""
    metadata = _result_cleanup(value, origin)
    if extra is not None and extra is not value:
        metadata = _merge_cleanup(metadata, _result_cleanup(extra, extra_origin))
    return {'status': 'recorded' if metadata.facts else ('unavailable' if metadata.unavailable else 'none_reported'),
            'facts': [{'stage': fact.stage, 'category': fact.category, 'origin': fact.origin,
                       **({'errno': fact.errno} if fact.errno is not None else {})} for fact in metadata.facts],
            'overflow': metadata.overflow, 'unavailable': metadata.unavailable}


class RunCancelled(SystemExit):
    """Signal exit with the last owned child's result still available."""

    def __init__(self, number: int, result: ProcessResult | None = None):
        super().__init__(128 + number)
        self.signal_number = number
        self.result = result
        self.checks: list[object] = []


@dataclass
class Cancellation:
    signal_number: int | None = None

    def __call__(self) -> int | None:
        return self.signal_number

    def check(self, result: ProcessResult | None = None) -> None:
        if self.signal_number is not None:
            if result is not None:
                result.terminal_state = 'cancelled'
            raise RunCancelled(self.signal_number, result)


_active_cancellation: Cancellation | None = None
_TERM_GRACE = 0.25
_KILL_REAP_TIMEOUT = 2.0


@dataclass
class CoreTestRun:
    tests: ProcessResult
    coverage: ProcessResult | None
    workers: int
    versions: dict[str, str]
    coverage_metadata: dict[str, object]
    progress: dict[str, object] | None = None
    coverage_export: ProcessResult | None = None


def _stop(process: subprocess.Popen) -> None:
    """Stop only the session or Job Object created by execute; repeated calls are safe."""
    job = fsx.owned_job(process)
    if os.name == 'posix':
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        else:
            # Also terminate descendants when their group leader already exited.
            deadline = time.monotonic() + _TERM_GRACE
            while time.monotonic() < deadline:
                process.poll()
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    elif job is not None:
        # The job holds every descendant, also those whose parent already exited;
        # Windows has no catchable SIGTERM, so termination is immediate.
        try:
            emptied = job.terminate(_KILL_REAP_TIMEOUT)
        finally:
            job.close()  # kill-on-close remains the last resort if termination failed
        if not emptied:
            raise RunnerError('owned process tree refused to exit after Job Object termination')
    elif process.poll() is None:
        if fsx.WINDOWS:
            # taskkill /T ends the live tree; without a Job Object, descendants that
            # outlive an already-exited child are not reachable (no group kill).
            fsx.kill_process_tree(process.pid)
        if process.poll() is None:
            process.kill()
    try:
        process.wait(timeout=_KILL_REAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=_KILL_REAP_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise RunnerError('owned process refused to exit after SIGKILL') from None


@contextmanager
def _cancellation():
    global _active_cancellation
    if threading.current_thread() is not threading.main_thread():
        raise RunnerError('test process ownership requires the main thread')
    if _active_cancellation is not None:
        yield _active_cancellation
        return
    cancellation = Cancellation()
    previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}

    def cancel(signum, frame):
        if cancellation.signal_number is None:
            cancellation.signal_number = signum

    for number in previous:
        signal.signal(number, cancel)
    _active_cancellation = cancellation
    try:
        yield cancellation
    finally:
        _active_cancellation = None
        for number, handler in previous.items():
            signal.signal(number, handler)


@contextmanager
def _output_resource(manager, retained: dict[str, ProcessResult | CleanupMetadata], label: str, cancellation: Cancellation, *,
                     stage: str | None = None):
    """Close capture resources without replacing a result or primary exception."""
    handle = manager.__enter__()
    primary: BaseException | None = None
    try:
        yield handle
    except BaseException as exc:
        if retained.get('result') is None:
            pending = retained.pop('cleanup_metadata', None)
            if pending is not None:
                _retain_cleanup(exc, pending)
        primary = exc
        raise
    finally:
        try:
            manager.__exit__(type(primary) if primary else None, primary,
                             primary.__traceback__ if primary else None)
        except Exception as cleanup:
            result = retained.get('result')
            if result is None and isinstance(primary, RunCancelled):
                result = primary.result
            _retain_cleanup(result if result is not None else (primary if primary is not None else cleanup),
                            _merge_cleanup(retained.pop('cleanup_metadata', CleanupMetadata()),
                                           _cleanup_failure(stage, cleanup)))
            diagnostic = f'{label} output cleanup failed: {type(cleanup).__name__}: {cleanup}'[:512]
            if result is not None:
                result.cleanup_error = '; '.join(filter(None, (result.cleanup_error, diagnostic)))
            elif primary is None:
                raise
            if primary is not None:
                primary.add_note(diagnostic)
        if primary is None and retained.get('result') is not None:
            cancellation.check(retained['result'])


@contextmanager
def _output_file(retained: dict[str, ProcessResult | CleanupMetadata], label: str, cancellation: Cancellation, *,
                 file_stage: str | None = None, directory_stage: str | None = None):
    # Anonymous files still emit parent-directory events on Linux. Keep their
    # continuous writes below a stable sibling of child fixture trees, so a
    # fixture's bounded ancestor guard does not consume runner output noise.
    with _output_resource(tempfile.TemporaryDirectory(prefix='grok-capture-'), retained,
                          f'{label} directory', cancellation,
                          stage=directory_stage) as directory:
        with _output_resource(tempfile.TemporaryFile(dir=directory), retained, label, cancellation,
                              stage=file_stage) as handle:
            yield handle


@diagnostics.observed('owned-command', stage='command')
def execute(command: list[str], root: Path, environment: dict[str, str], *, timeout: int = TIMEOUT) -> ProcessResult:
    """Bound output and stop this invocation's process tree on interruption."""
    run = diagnostics.current()
    if run:
        environment = run.child_environment(environment)
    started = time.monotonic()
    retained: dict[str, ProcessResult | CleanupMetadata] = {}
    with _cancellation() as cancelled, _output_file(retained, 'stdout', cancelled,
            file_stage='stdout_capture_file', directory_stage='stdout_capture_directory') as stdout, \
            _output_file(retained, 'stderr', cancelled, file_stage='stderr_capture_file',
                         directory_stage='stderr_capture_directory') as stderr:
        cancelled.check(ProcessResult(command, 128 + (cancelled() or 0), terminal_state='cancelled'))
        try:
            process = fsx.owned_popen(command, cwd=root, env=environment, stdout=stdout, stderr=stderr)
        except OSError as exc:
            detail = str(exc)
            if command and command[0] not in detail:
                detail = f'{detail}: {command[0]}'  # Windows WinError 2 names no file
            result = ProcessResult(command, 127, stderr=detail)
            retained['result'] = result
            return result
        if run and run.writer:
            run.writer.emit('command', 'unknown', step='owned-process', process=process.pid)
        reason = ''
        cleanup_error = ''
        cleanup_metadata = CleanupMetadata()
        try:
            while process.poll() is None:
                if cancelled():
                    reason = f'test process cancelled by {signal.Signals(cancelled()).name}'
                    break
                elif time.monotonic() - started > timeout:
                    reason = 'test process timeout'
                elif os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > OUTPUT_LIMIT:
                    reason = 'test process output limit exceeded'
                if reason:
                    break
                time.sleep(0.05)
        except BaseException as exc:
            try:
                _stop(process)
            except Exception as cleanup:
                _retain_cleanup(exc, _cleanup_failure('owned_stop_reap', cleanup))
                exc.add_note(f'owned process cleanup failed: {cleanup}')
            raise
        original_returncode = process.returncode
        try:
            _stop(process)
        except Exception as exc:
            cleanup_metadata = _merge_cleanup(cleanup_metadata, _cleanup_failure('owned_stop_reap', exc))
            retained['cleanup_metadata'] = cleanup_metadata
            cleanup_error = f'{type(exc).__name__}: {exc}'[:512]
        if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > OUTPUT_LIMIT:
            reason = 'test process output limit exceeded'
        stdout.seek(0)
        stderr.seek(0)
        out = stdout.read(OUTPUT_LIMIT).decode('utf-8', errors='backslashreplace')
        err = stderr.read(OUTPUT_LIMIT).decode('utf-8', errors='backslashreplace')
        if os.name == 'nt':
            # Text output ends lines with CRLF on Windows; records keep the one convention.
            out, err = out.replace('\r\n', '\n'), err.replace('\r\n', '\n')
        code = original_returncode if original_returncode is not None else process.returncode
        if cancelled():
            code = code if original_returncode is not None else 128 + cancelled()
        elif reason:
            code = 124
        if code is None:
            code = 1
        result = ProcessResult(command, code, out, err + reason, time.monotonic() - started,
                               'timeout' if reason == 'test process timeout' else 'completed', cleanup_error,
                               cleanup_metadata)
        retained.pop('cleanup_metadata', None)
        retained['result'] = result
        cancelled.check(result)
        return result


def _environment(root: Path, data_file: Path, *, temporary_root: Path | None = None) -> dict[str, str]:
    # Test children write temporary files inside this run's folder, so the run's own cleanup also
    # removes what a killed or timed-out child left behind (#168).
    scratch = temporary_root if temporary_root is not None else data_file.parent / 'tmp'
    scratch.mkdir(mode=0o700, exist_ok=True)
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(('PYTEST_', 'COVERAGE_', 'COV_CORE_'))
        and key not in ('GETZILLA_TEST_WORKERS', FORCE_FULL_VARIABLE)
    }
    environment.update(
        PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', PYTHONDONTWRITEBYTECODE='1',
        _GETZILLA_TEST_CHILD='1', COVERAGE_FILE=str(data_file), TMPDIR=str(scratch), TEMP=str(scratch), TMP=str(scratch),
        PYTHONPATH=os.pathsep.join((str(root), str(root / 'tests'), str(root / '.getzilla'), environment.get('PYTHONPATH', ''))),
    )
    return environment


def _unittest_command(result_file: Path, *arguments: str) -> list[str]:
    # STACK_DIR remains a real directory when the engine lives in getzilla.zip.
    return [sys.executable, str(STACK_DIR.parent / 'scripts/getzilla_unittest.py'),
            '--result', str(result_file), '--nonce', uuid.uuid4().hex, *arguments]


def _application_coverage_config(config: Path, directory: Path, *, root: Path) -> Path:
    """Preserve application coverage; omit exact external instrumentation only."""
    from . import pytest_progress

    harness = str((STACK_DIR.parent / 'scripts/getzilla_unittest.py').resolve())
    # Coverage's omit values are comma/newline-separated glob patterns with
    # environment expansion. Never broaden an exact infrastructure exclusion.
    if any(character in harness for character in '[]*?,\n\r$'):
        raise RunnerError('managed unittest path cannot be represented as an exact coverage omission')
    omissions = [harness]  # Retain the existing bootstrap-only exception.
    consumer = root.resolve()
    for origin in (fsx.__file__, pytest_progress.__file__, diagnostics.__file__):
        path = Path(origin).resolve()
        if path.is_relative_to(consumer):
            continue
        exact = str(path)
        if any(character in exact for character in '[]*?,\n\r$'):
            raise RunnerError('managed instrumentation path cannot be represented as an exact coverage omission')
        omissions.append(exact)
    settings = configparser.RawConfigParser()
    try:
        settings.read_string(config.read_text(encoding='utf-8'))
        if not settings.has_section('run'):
            settings.add_section('run')
        original = settings.get('run', 'omit', fallback='')
        settings.set('run', 'omit', original + '\n' + '\n'.join(omissions))
        overlay = directory / 'application.coveragerc'
        with overlay.open('x', encoding='utf-8') as output:
            settings.write(output)
        return overlay
    except (OSError, UnicodeError, configparser.Error) as exc:
        raise RunnerError('cannot preserve consumer coverage configuration') from exc


def _unittest_result(result: ProcessResult, result_file: Path) -> ProcessResult:
    if result.returncode:
        return result
    try:
        nonce = result.command[result.command.index('--nonce') + 1]
        initial = result_file.lstat()
        if (not re.fullmatch('[0-9a-f]{32}', nonce) or fsx.is_link(initial)
                or not stat.S_ISREG(initial.st_mode)):
            raise ValueError('invalid collection result identity')
        descriptor = os.open(result_file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(descriptor, 'rb') as source:
            identity = os.fstat(source.fileno())
            if (not stat.S_ISREG(identity.st_mode)
                    or (identity.st_dev, identity.st_ino) != (initial.st_dev, initial.st_ino)
                    or (hasattr(os, 'getuid') and identity.st_uid != os.getuid())):
                raise ValueError('invalid collection result owner or type')
            content = source.read(513)
        if len(content) > 512:
            raise ValueError('oversized collection result')
        report = json.loads(content)
        if (not isinstance(report, dict) or set(report) != {'schema_version', 'nonce', 'tests_run', 'successful'}
                or type(report['schema_version']) is not int or report['schema_version'] != 1
                or report['nonce'] != nonce
                or type(report['tests_run']) is not int or report['tests_run'] < 1
                or report['successful'] is not True):
            raise ValueError('no successful nonempty collection')
    except (OSError, ValueError, TypeError, IndexError):
        return replace(result, returncode=5,
                       stderr=result.stderr + '\nunittest collection result missing or invalid\n')
    return result


@diagnostics.entrypoint('named-tests')
def run_named_tests(root: Path, targets: list[str], *, budget: int = 180) -> ProcessResult:
    """Run explicit Core unittest names as a bounded observation, without coverage."""
    if type(budget) is not int or not 1 <= budget <= 180:
        raise RunnerError('named test budget must be an integer from 1 to 180 seconds')
    if not targets or any(
        not isinstance(target, str)
        or not re.fullmatch(r'tests\.test_[A-Za-z0-9_]+(?:\.[A-Za-z_][A-Za-z0-9_]*){0,2}', target)
        or not (root / 'tests' / (target.split('.')[1] + '.py')).is_file()
        for target in targets
    ):
        raise RunnerError('named tests require nonempty existing tests.test_module[.Class[.test_method]] targets')
    retained: dict[str, ProcessResult] = {}
    with _run_directory('grok-named-smoke-', retained) as directory:
        result_file = Path(directory) / 'unittest-result.json'
        retained['tests'] = _unittest_result(
            execute(_unittest_command(result_file, *targets), root,
                    _environment(root, Path(directory) / '.coverage'), timeout=budget), result_file)
    return retained['tests']


def _tool_versions(required: list[str]) -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in required:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError as exc:
            raise RunnerError(f'{name} missing; install .getzilla/config/python-test-requirements.txt with this Python') from exc
        if versions[name] != PINS[name]:
            raise RunnerError(f'{name} requires tested version {PINS[name]}; found {versions[name]}')
    return versions


def parallel_engine_ready(measured: bool) -> bool:
    """Every module the xdist engine needs, importable by THIS interpreter."""
    modules = ("pytest", "xdist", *(("pytest_cov",) if measured else ()))
    return all(importlib.util.find_spec(name) is not None for name in modules)


def _parallel_process_cleanup_supported() -> bool:
    """Whether this host can own and clean up the whole parallel process tree.

    POSIX uses a new session per owned child; Windows uses a kill-on-close Job
    Object per owned child (``fsx.owned_popen``).
    """
    return os.name == 'posix' or fsx.process_jobs_supported()


def select_engine(workers: int, measured: bool) -> tuple[int, str]:
    """Capability-selected engine: xdist only when importable and safely cleanable.

    Retake of closed defect 33: the Trust CI runner image has no pytest, so a
    requested-parallel run must degrade to one disclosed sequential unittest
    pass before execution, never after a failure, and never claim the parallel
    backend it did not use.
    """
    if workers > 0 and measured and not parallel_engine_ready(measured) and _parallel_process_cleanup_supported():
        return workers, "coverage-unittest-parallel"
    if workers > 0 and (
        not parallel_engine_ready(measured) or not _parallel_process_cleanup_supported()
    ):
        return 0, "unittest-degraded"
    if workers > 0:
        return workers, "pytest-xdist"
    return 0, "unittest"


def _progress_arguments(directory: Path, nonce: str, workers: int) -> list[str]:
    return ['-p', 'getzilla.pytest_progress', '--getzilla-progress-dir', str(directory),
            '--getzilla-progress-nonce', nonce, '--getzilla-progress-workers', str(workers),
            '--getzilla-progress-phases']


def _pytest_command(workers: int, distribution: str) -> list[str]:
    if not _parallel_process_cleanup_supported():
        raise RunnerError('parallel process cleanup requires POSIX sessions or Windows Job Objects; '
                          'use GETZILLA_TEST_WORKERS=0')
    # Windows os.devnull is 'nul', which pytest resolves to the device path \\.\nul. Its parent bounds
    # nothing, so collection and conftest lookup would climb every directory up to the drive root and
    # race other processes' temporary directories there; the project root bounds both instead.
    confcutdir = ['--confcutdir=.'] if os.name == 'nt' else []
    return [sys.executable, '-m', 'pytest', '-c', os.devnull, '-p', 'xdist.plugin', '-p', 'no:cacheprovider',
            '--import-mode=prepend', '--rootdir=.', *confcutdir, '-o', 'python_files=test*.py', '-q', '-n', str(workers),
            f'--dist={distribution}', '--max-worker-restart=0', '--durations=20', '-ra', '--show-capture=no']


def _unittest_files(root: Path) -> list[str]:
    tests = root / 'tests'
    return [path.name for path in sorted(tests.glob('test*.py')) if path.is_file()]


def _read_limited(path: Path) -> str:
    try:
        with path.open('rb') as handle:
            return handle.read(OUTPUT_LIMIT).decode('utf-8', errors='backslashreplace')
    except OSError as exc:
        return f'{type(exc).__name__}: {exc}'


def _parallel_coverage_unittest(root: Path, config: Path, data_file: Path, workers: int, environment: dict[str, str], *,
                                test_files: list[str] | None = None) -> ProcessResult:
    if test_files is None:
        test_files = _unittest_files(root)
    command = [sys.executable, '-m', 'coverage', 'run', '--parallel-mode', f'--rcfile={config}',
               *_unittest_command(Path('<result>'), 'discover', '-s', 'tests', '-p', '<test-file>')[1:]]
    if not test_files:
        return ProcessResult(command, 5, stderr='no unittest modules discovered')
    started = time.monotonic()
    active: list[tuple[str, subprocess.Popen, Path, Path, Path]] = []
    completed: list[ProcessResult] = []
    cleanup_errors: list[str] = []
    next_file = 0
    run = diagnostics.current()
    actors = {}
    workers = max(1, min(workers, len(test_files)))
    with _cancellation() as cancelled, tempfile.TemporaryDirectory(prefix='grok-core-parallel-') as out_dir:
        output_root = Path(out_dir)
        try:
            while next_file < len(test_files) or active:
                cancelled.check()
                while next_file < len(test_files) and len(active) < workers:
                    test_file = test_files[next_file]
                    next_file += 1
                    stdout = output_root / f'{test_file}.stdout'
                    stderr = output_root / f'{test_file}.stderr'
                    result_file = output_root / f'{test_file}.result.json'
                    out_handle = stdout.open('wb')
                    err_handle = stderr.open('wb')
                    actor = next(i for i in range(workers) if i not in actors.values())
                    child_env = {**environment, '_GETZILLA_TEST_CHILD': '1'}
                    if run:
                        child_env = run.child_environment(child_env, actor)
                        if run.writer:
                            run.writer.emit('command', 'start', step='unittest-shard')
                    try:
                        process = fsx.owned_popen(
                            [
                                sys.executable, '-m', 'coverage', 'run', '--parallel-mode',
                                f'--rcfile={config}',
                                *_unittest_command(result_file, 'discover', '-s', 'tests', '-p', test_file)[1:],
                            ],
                            cwd=root,
                            env=child_env,
                            stdout=out_handle,
                            stderr=err_handle,
                        )
                    except OSError as exc:
                        out_handle.close()
                        err_handle.close()
                        completed.append(ProcessResult(command, 127, stderr=f'{test_file}: {exc}'))
                        continue
                    out_handle.close()
                    err_handle.close()
                    actors[process.pid] = actor
                    if run and run.writer:
                        run.writer.emit('command', 'unknown', step='unittest-shard', process=process.pid)
                    active.append((test_file, process, stdout, stderr, result_file))
                for item in list(active):
                    test_file, process, stdout, stderr, result_file = item
                    if process.poll() is None:
                        continue
                    active.remove(item)
                    actors.pop(process.pid, None)
                    if run and run.writer:
                        run.writer.emit('command', 'end', step='unittest-shard', code=process.returncode,
                                        outcome='pass' if process.returncode == 0 else 'fail', process=process.pid)
                    job = fsx.owned_job(process)
                    if job is not None:
                        job.close()  # a finished shard's leftover descendants end with its job
                    completed.append(_unittest_result(ProcessResult(
                        list(process.args),
                        process.returncode if process.returncode is not None else 1,
                        stdout=_read_limited(stdout),
                        stderr=_read_limited(stderr),
                    ), result_file))
                if time.monotonic() - started > TIMEOUT:
                    for _test_file, process, _stdout, _stderr, _result_file in active:
                        _stop(process)
                        if run and run.writer:
                            run.writer.emit('command', 'end', step='unittest-shard', outcome='timeout', process=process.pid)
                    return ProcessResult(command, 124, stderr='parallel coverage unittest timeout',
                                         seconds=time.monotonic() - started, terminal_state='timeout',
                                         cleanup_metadata=_merge_cleanup(*(
                                             _with_cleanup_origin(_stored_cleanup(item), 'parallel_shard')
                                             for item in completed)))
                if active:
                    time.sleep(0.05)
        except BaseException as primary:
            _retain_cleanup(primary, _merge_cleanup(*(
                _with_cleanup_origin(_stored_cleanup(item), 'parallel_shard') for item in completed)))
            for test_file, process, _stdout, _stderr, _result_file in active:
                try:
                    _stop(process)
                except Exception as exc:
                    _retain_cleanup(primary, _cleanup_failure('owned_stop_reap', exc))
                    cleanup_errors.append(f'{test_file}: {type(exc).__name__}: {exc}'[:256])
            raise
    failed = [result for result in completed if result.returncode != 0]
    stdout = ''.join(result.stdout[-4000:] for result in failed[-20:])
    stderr = ''.join(result.stderr[-4000:] for result in failed[-20:])
    if failed:
        return ProcessResult(command, failed[0].returncode, stdout=stdout, stderr=stderr,
                             seconds=time.monotonic() - started,
                             cleanup_metadata=_merge_cleanup(*(
                                 _with_cleanup_origin(_stored_cleanup(item), 'parallel_shard')
                                 for item in completed)))
    combine = execute(
        [sys.executable, '-m', 'coverage', 'combine', f'--rcfile={config}', str(data_file.parent)],
        root,
        environment,
        timeout=120,
    )
    return ProcessResult(command, combine.returncode, stdout=combine.stdout, stderr=combine.stderr,
                         seconds=time.monotonic() - started,
                         cleanup_error=combine.cleanup_error,
                         cleanup_metadata=_merge_cleanup(*(
                             _with_cleanup_origin(_stored_cleanup(item), 'parallel_shard')
                             for item in completed),
                             _with_cleanup_origin(_stored_cleanup(combine), 'coverage_combine')))


@contextmanager
def _run_directory(prefix: str, retained: dict[str, ProcessResult]):
    """Cleanup cannot replace a completed test verdict or a signal exception."""
    directory = tempfile.TemporaryDirectory(prefix=prefix)
    primary: BaseException | None = None
    try:
        yield directory.name
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            directory.cleanup()
        except Exception as cleanup:
            result = retained.get('tests')
            if result is None and isinstance(primary, RunCancelled):
                result = primary.result
            _retain_cleanup(result if result is not None else (primary if primary is not None else cleanup),
                            _cleanup_failure('run_scratch_directory', cleanup))
            if result is not None:
                diagnostic = f'{type(cleanup).__name__}: {cleanup}'[:512]
                result.cleanup_error = '; '.join(filter(None, (result.cleanup_error, diagnostic)))
            elif primary is None:
                raise
            if primary is not None:
                primary.add_note(f'coverage scratch cleanup failed: {cleanup}')


@diagnostics.entrypoint('core-tests')
def run_core_tests(root: Path, mode: str, workers: int) -> CoreTestRun:
    measured = mode in {'pr', 'release'}
    workers, engine = select_engine(workers, measured)
    if engine == 'pytest-xdist':
        version_requirements = list(PINS)
    elif measured:
        version_requirements = ['coverage']
    else:
        version_requirements = []
    versions = _tool_versions(version_requirements)
    versions['engine'] = engine
    config = root / '.coveragerc'
    if measured and not config.is_file():
        raise RunnerError('required .coveragerc is missing')
    retained: dict[str, ProcessResult] = {}
    with _run_directory('grok-core-coverage-', retained) as directory:
        # Worker coverage/SQLite writes must stay below a sibling of fixture
        # storage, outside the fixture guards' nonrecursive ancestor watches.
        coverage_root = Path(directory) / 'coverage'
        coverage_root.mkdir(mode=0o700)
        if measured:
            config = _application_coverage_config(config, coverage_root, root=root)
        data_file = coverage_root / '.coverage'
        report_file = coverage_root / 'coverage.json'
        result_file = coverage_root / 'unittest-result.json'
        environment = _environment(root, data_file, temporary_root=Path(directory) / 'tmp')
        progress_root = Path(directory) / 'progress'
        progress_nonce = uuid.uuid4().hex
        if workers and engine == 'pytest-xdist':
            command = _pytest_command(workers, 'worksteal')
            if 1 <= workers <= 64:
                # The source CLI also serves uninstalled consumer roots. Load
                # this running engine's plugin; STACK_DIR is real for ZIP installs.
                environment['PYTHONPATH'] = os.pathsep.join((str(STACK_DIR), environment['PYTHONPATH']))
                try:
                    progress_root.mkdir(mode=0o700)
                except OSError:
                    pass  # Diagnostic storage cannot prevent the real backend.
                command += _progress_arguments(progress_root, progress_nonce, workers)
            if measured:
                command += ['-p', 'pytest_cov.plugin', '--cov', f'--cov-config={config}', '--cov-report=term']
            command += ['tests']
        elif workers and engine == 'coverage-unittest-parallel':
            command = [
                sys.executable, '-m', 'coverage', 'run', '--parallel-mode', f'--rcfile={config}',
                '-m', 'unittest', '<module>',
            ]
        else:
            command = _unittest_command(result_file, 'discover', '-s', 'tests')
            if measured:
                command = [sys.executable, '-m', 'coverage', 'run', f'--rcfile={config}', *command[1:]]
        if workers and engine == 'coverage-unittest-parallel':
            test_files = _unittest_files(root)
            workers = min(workers, len(test_files))
            tests = _parallel_coverage_unittest(root, config, data_file, workers, environment, test_files=test_files)
        else:
            tests = execute(command, root, environment)
            if engine != 'pytest-xdist':
                tests = _unittest_result(tests, result_file)
        retained['tests'] = tests
        progress = None
        if engine == 'pytest-xdist':
            from .pytest_progress import read_progress
            progress = read_progress(progress_root, progress_nonce, workers)
        coverage = None
        exported = None
        facts: dict[str, object] = {}
        if measured:
            coverage_command = [sys.executable, '-m', 'coverage', 'report', f'--rcfile={config}']
            if not data_file.is_file():
                coverage = ProcessResult(coverage_command, 1, stderr='current run produced no coverage data')
            else:
                exporting = False
                try:
                    coverage = execute(coverage_command, root, environment, timeout=120)
                    exporting = True
                    exported = execute([sys.executable, '-m', 'coverage', 'json', f'--rcfile={config}', '-o', str(report_file)], root, environment, timeout=120)
                except RunCancelled as exc:
                    exc.core_run = CoreTestRun(tests, exc.result, workers, versions, facts, progress,
                                              exc.result if exporting else None)
                    raise
                try:
                    from coverage import Coverage
                    from coverage.exceptions import CoverageException
                    document = json.loads(report_file.read_text(encoding='utf-8'))
                    expected_branch = Coverage(config_file=str(config)).get_option('run:branch')
                    if (not isinstance(document, dict)
                            or not isinstance(document.get('files'), dict) or not document['files']
                            or not isinstance(document.get('meta'), dict)
                            or type(document['meta'].get('branch_coverage')) is not bool
                            or document['meta']['branch_coverage'] != expected_branch
                            or not isinstance(document.get('totals'), dict)):
                        raise ValueError('coverage source or branch data missing')
                    facts = {'totals': document['totals'], 'branch_coverage': expected_branch, 'files': sorted(document['files'])}
                except (OSError, ValueError, TypeError, KeyError, CoverageException) as exc:
                    coverage.returncode = 1
                    coverage.stderr += f'\ninvalid current-run coverage: {exc}'
                if exported.returncode or tests.returncode or 'failed to return coverage data' in tests.stdout + tests.stderr:
                    coverage.returncode = 1
                    coverage.stderr += '\ncoverage does not qualify an unsuccessful or incomplete test run'
        return CoreTestRun(tests, coverage, workers, versions, facts, progress, exported)


def run_trust_tests(root: Path, workers: int) -> ProcessResult:
    """Keep Trust imports and database test methods in their own suite/process."""
    suite = root / 'trust-ci'
    if not (suite / 'tests').is_dir():
        raise RunnerError('trust-ci/tests is missing')
    workers, _engine = select_engine(workers, measured=False)
    _tool_versions(['pytest', 'pytest-xdist'] if workers else [])
    retained: dict[str, ProcessResult] = {}
    # Child temp files now live in this folder, so its cleanup must not replace the verdict (#134).
    with _run_directory('grok-trust-tests-', retained) as directory:
        result_file = Path(directory) / 'unittest-result.json'
        command = (_pytest_command(workers, 'loadfile') + ['tests']) if workers else _unittest_command(
            result_file, 'discover', '-s', 'tests')
        environment = _environment(suite, Path(directory) / '.coverage')
        environment['PYTHONPATH'] = os.pathsep.join(str(path) for path in (suite / 'src', suite / 'tests', suite))
        retained['tests'] = execute(command, suite, environment)
        if not workers:
            retained['tests'] = _unittest_result(retained['tests'], result_file)
    return retained['tests']


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=['trust-ci'], required=True)
    parser.parse_args()
    try:
        root = Path.cwd().resolve()
        requested = selected_workers(root) or 0
        workers, engine = select_engine(requested, measured=False)
        result = run_trust_tests(root, requested)
    except RunnerError as exc:
        print(f'Trust CI tests failed: {exc}', file=sys.stderr)
        return 1
    print(f'Trust CI: requested_workers={requested}; workers={workers}; engine={engine}; '
          f'seconds={result.seconds:.3f}; exit={result.returncode}')
    print(result.stdout, end='')
    print(result.stderr, end='', file=sys.stderr)
    if result.cleanup_error:
        print(f'owned test cleanup failed: {result.cleanup_error}', file=sys.stderr)
        return 1
    return result.returncode if result.returncode >= 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
