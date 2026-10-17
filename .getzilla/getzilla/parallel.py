"""Independent heavy work runs on every verified CPU, never one command at a time.

Agents tend to run tests, checks and probes one after another even on a 26-CPU host, so a
session spends minutes and millions of context tokens with one core busy. Getzilla owns the
schedule instead of hoping the agent remembers a rule:

- :func:`capacity` is the number of worker processes for this host (the startup measurement
  in ``.getzilla/runtime/startup-capacity.json`` when fresh, else allowed CPUs minus the owner's
  reserve);
- :func:`run_batch` (``getzilla par``) runs independent shell commands concurrently, each one
  checked by the repository policy first, and returns a short summary while full logs stay in
  ``.getzilla/runtime/par/``;
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
import shlex
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

CONFIG = '.getzilla/config/parallel.json'
SNAPSHOT = '.getzilla/runtime/startup-capacity.json'
LOGS = '.getzilla/runtime/par'
STATS = '.getzilla/runtime/parallel-guard.json'
SERIAL = 'GETZILLA_SERIAL=1'
FRESH_SECONDS = 12 * 3600
TAIL_LINES = 30
MAX_LISTED_PASSES = 15

_LOOP = re.compile(r'^\s*for\s+([A-Za-z_]\w*)\s+in\s+(.+?)\s*;\s*do\s+(.+?)\s*;?\s*done\s*$', re.S)
_FIND_EXEC = re.compile(r'\bfind\s+(.+?)\s+-exec\s+(\S+)(.*?)\{\}\s*\\?;')


def config(root: Path) -> dict[str, Any]:
    for path in (root / CONFIG, Path(__file__).resolve().parents[1] / 'config' / 'parallel.json'):
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


def policy_refusal(root: Path, command: str) -> str | None:
    """The same verdict the PreToolUse hook would give this command on its own."""
    from .policy import evaluate_pre_tool, sensitive_action

    event = {'tool_name': 'Bash', 'tool_input': {'command': command}}
    action = sensitive_action(root, event)
    if action:
        return f'sensitive action {action}: run it on its own so the policy and its approvals apply'
    allowed, reason = evaluate_pre_tool(root, event)
    return None if allowed else (reason or 'refused by repository policy')


def expand_each(patterns: list[str], template: str, cwd: Path) -> list[str]:
    paths: list[str] = []
    for pattern in patterns:
        matches = sorted(_glob.glob(pattern, root_dir=cwd)) if any(ch in pattern for ch in '*?[') else [pattern]
        paths.extend(match for match in matches if match not in paths)
    if '{}' not in template:
        template = f'{template} {{}}'
    return [template.replace('{}', shlex.quote(path)) for path in paths]


def run_batch(root: Path, commands: list[str], *, workers: int, cwd: Path, timeout: float | None = None,
              runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> tuple[list[Job], Path]:
    """Run independent commands concurrently; nothing runs when the policy refuses any of them."""
    jobs = [Job(index, command) for index, command in enumerate(commands, 1)]
    for job in jobs:
        job.refused = policy_refusal(root, job.command)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + f'-{os.getpid()}'
    folder = root / LOGS / stamp
    folder.mkdir(parents=True, exist_ok=True)
    if any(job.refused for job in jobs):
        return jobs, folder

    def one(job: Job) -> Job:
        job.log = folder / f'{job.index:03d}.log'
        started = time.monotonic()
        with job.log.open('wb') as handle:
            handle.write(f'$ {job.command}\n'.encode('utf-8'))
            handle.flush()
            try:
                proc = runner(job.command, shell=True, cwd=cwd, stdout=handle, stderr=subprocess.STDOUT,  # nosec B604 - the agent's own shell command, checked by the repository policy above
                              timeout=timeout, check=False)
                job.returncode = proc.returncode
            except subprocess.TimeoutExpired:
                job.returncode = 124
                handle.write(f'\ngetzilla par: timed out after {timeout} s\n'.encode('utf-8'))
        job.seconds = time.monotonic() - started
        return job

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs)))) as pool:
        list(pool.map(one, jobs))
    summary = [{'index': job.index, 'command': job.command, 'exit': job.returncode, 'seconds': round(job.seconds, 2),
                'log': job.log.name if job.log else None} for job in jobs]
    (folder / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8', newline='\n')
    return jobs, folder


def _tail(path: Path | None) -> str:
    if path is None:
        return ''
    lines = path.read_bytes().decode('utf-8', 'replace').splitlines()[1:]
    return '\n'.join('    ' + line for line in lines[-TAIL_LINES:])


def report(root: Path, jobs: list[Job], folder: Path, *, workers: int, wall: float, show_all: bool = False) -> str:
    refused = [job for job in jobs if job.refused]
    relative = folder.relative_to(root).as_posix() if folder.is_relative_to(root) else str(folder)
    if refused:
        lines = [f'getzilla par: nothing ran; {len(refused)} of {len(jobs)} commands were refused:']
        lines += [f'  {job.command}\n    -> {job.refused}' for job in refused]
        return '\n'.join(lines)
    failed = [job for job in jobs if job.returncode != 0]
    work = sum(job.seconds for job in jobs)
    lines = [f'getzilla par: {len(jobs)} commands on {min(workers, len(jobs))} workers, {wall:.1f} s wall '
             f'({work:.1f} s of work); {len(jobs) - len(failed)} passed, {len(failed)} failed; logs: {relative}']
    for job in failed:
        lines.append(f'FAIL exit={job.returncode} {job.seconds:.1f}s  {job.command}  ({job.log.name if job.log else "-"})')
        lines.append(_tail(job.log))
    passed = [job for job in jobs if job.returncode == 0]
    if show_all or len(passed) <= MAX_LISTED_PASSES:
        lines += [f'pass {job.seconds:.1f}s  {job.command}' for job in passed]
        if show_all:
            for job in passed:
                lines.append(_tail(job.log))
    else:
        lines.append(f'pass: {len(passed)} commands (each one in summary.json)')
    return '\n'.join(line for line in lines if line)


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
