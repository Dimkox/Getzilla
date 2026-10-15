"""Startup CPU step zero: measure effective capacity and record it (AGENTS.md mandatory startup).

Observes topology, process affinity, cgroup cpuset and finite quota, runs one bounded child-only
affinity probe when affinity is narrower than the allowed CPUs, and chooses a conservative
capacity. The parent's own affinity is never changed. Unknown bounds are reported as
uncertainties and keep the narrower observed value.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from . import _cpu_capacity
from .util import now_utc

SCHEMA_VERSION = 1
RUNTIME_RECORD = 'startup-capacity.json'
EVIDENCE_RECORD = 'evidence/startup-capacity.json'
_OUTPUT_LIMIT = 64 * 1024
_TIMEOUT = 15

Runner = Callable[[list[str]], dict[str, Any]]


def run_command(argv: list[str]) -> dict[str, Any]:
    """Run one argv without a shell; a missing tool or timeout is a recorded result, not an error."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {'argv': argv, 'code': None, 'stdout': '', 'stderr': f'{type(exc).__name__}: {exc}'}
    return {'argv': argv, 'code': proc.returncode,
            'stdout': proc.stdout[:_OUTPUT_LIMIT], 'stderr': proc.stderr[:_OUTPUT_LIMIT]}


def parse_cpu_list(text: str) -> set[int]:
    """Parse a kernel CPU list such as ``0,1,8-27``; malformed input raises ValueError."""
    result: set[int] = set()
    for part in text.strip().split(','):
        if not part:
            continue
        match = re.fullmatch(r'(\d+)(?:-(\d+))?', part.strip())
        if not match:
            raise ValueError(f'malformed CPU list: {text!r}')
        low = int(match[1])
        high = int(match[2]) if match[2] else low
        if high < low or high > 65535:
            raise ValueError(f'malformed CPU range: {part!r}')
        result.update(range(low, high + 1))
    return result


def format_cpu_list(cpus: set[int]) -> str:
    """Inverse of :func:`parse_cpu_list`, written like ``taskset`` (ranges for three or more)."""
    ranges: list[tuple[int, int]] = []
    for cpu in sorted(cpus):
        if ranges and ranges[-1][1] == cpu - 1:
            ranges[-1] = (ranges[-1][0], cpu)
        else:
            ranges.append((cpu, cpu))
    parts: list[str] = []
    for low, high in ranges:
        parts.extend([str(low), str(high)] if high == low + 1 else [str(low) if low == high else f'{low}-{high}'])
    return ','.join(parts)


def topology_from_lscpu(parseable: str) -> dict[str, Any]:
    """Online logical CPUs and physical cores from ``lscpu -p=CPU,CORE,SOCKET,ONLINE``."""
    online: set[int] = set()
    cores: set[tuple[str, str]] = set()
    for line in parseable.splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split(',')
        if len(fields) != 4 or not fields[0].isdecimal():
            raise ValueError(f'unexpected lscpu line: {line!r}')
        cpu, core, socket, state = fields
        if state.strip().upper() in {'Y', 'YES'}:
            online.add(int(cpu))
            cores.add((socket, core))
    if not online:
        raise ValueError('lscpu reported no online CPUs')
    return {'online_cpus': online, 'physical_cores': len(cores)}


def cgroup_bounds() -> dict[str, Any]:
    """Effective cpuset and per-level cpu.max along the process's visible cgroup ancestry."""
    membership_text = _cpu_capacity._read_text(Path('/proc/self/cgroup'), _cpu_capacity._PROC_LIMIT)
    mount_text = _cpu_capacity._read_text(Path('/proc/self/mountinfo'), _cpu_capacity._PROC_LIMIT)
    kind, membership = _cpu_capacity._membership(membership_text)
    mounts = _cpu_capacity._mounts(mount_text, kind, membership)
    levels: list[dict[str, Any]] = []
    cpuset: str | None = None
    for mountpoint, relative in mounts:
        for depth in range(len(relative), -1, -1):
            group = mountpoint.joinpath(*relative[:depth])
            level: dict[str, Any] = {'path': str(group)}
            for name in ('cpu.max', 'cpuset.cpus.effective', 'cpu.cfs_quota_us', 'cpu.cfs_period_us'):
                try:
                    level[name] = _cpu_capacity._read_text(group / name, _cpu_capacity._CONTROL_LIMIT).strip()
                except FileNotFoundError:
                    continue
            if cpuset is None and level.get('cpuset.cpus.effective'):
                cpuset = level['cpuset.cpus.effective']
            levels.append(level)
    return {'cgroup_version': 2 if kind == 'cgroup2' else 1, 'membership': '/' + '/'.join(membership),
            'levels': levels, 'effective_cpuset': cpuset}


def child_probe(candidates: set[int], runner: Runner) -> dict[str, Any]:
    """One bounded child-only affinity probe; the child reports its own allowed CPUs."""
    cpu_list = format_cpu_list(candidates)
    result = runner(['taskset', '-c', cpu_list, 'cat', '/proc/self/status'])
    allowed: set[int] | None = None
    if result['code'] == 0:
        match = re.search(r'^Cpus_allowed_list:\s*(\S+)\s*$', result['stdout'], re.MULTILINE)
        if match:
            try:
                allowed = parse_cpu_list(match[1]) or None
            except ValueError:
                allowed = None
    return {'requested': cpu_list, 'argv': result['argv'], 'code': result['code'],
            'stderr': result['stderr'], 'allowed': format_cpu_list(allowed) if allowed else None,
            'allowed_set': allowed}


def choose_capacity(*, online: set[int], affinity: set[int], cpuset: set[int] | None,
                    quota: int | None, probe_allowed: set[int] | None, reserve: int) -> dict[str, Any]:
    """Conservative capacity: allowed online CPUs (probed child or own affinity), finite quota, reserve."""
    allowed = online & cpuset if cpuset is not None else set(online)
    verified = (probe_allowed or affinity) & allowed
    if not verified:
        verified = affinity & online
    limit = len(verified)
    reasons = [f'verified allowed online CPUs={limit}']
    if quota is not None:
        limit = min(limit, quota)
        reasons.append(f'finite quota={quota}')
    if reserve:
        ceiling = max(1, len(online) - reserve)
        limit = min(limit, ceiling)
        reasons.append(f'owner reserve {reserve} -> ceiling {ceiling}')
    return {'verified_cpus': format_cpu_list(verified), 'chosen_capacity': max(1, limit), 'reasons': reasons}


_WINDOWS_CORES = ['powershell', '-NoProfile', '-NonInteractive', '-Command',
                  '(Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum']


def has_linux_affinity() -> bool:
    return hasattr(os, 'sched_getaffinity')


def measure_windows(*, reserve: int, runner: Runner) -> dict[str, Any]:
    """Windows step zero: logical and process-usable CPUs, physical cores; no cgroup or probe exists."""
    logical = os.cpu_count() or 1
    usable = getattr(os, 'process_cpu_count', os.cpu_count)() or logical
    uncertainties = ['Windows: job-object CPU rate limits are not inspected; usable CPUs come from the '
                     'process affinity (os.process_cpu_count)']
    commands = [runner(list(_WINDOWS_CORES))]
    text = commands[0]['stdout'].strip()
    physical = int(text) if commands[0]['code'] == 0 and text.isdecimal() else None
    if physical is None:
        uncertainties.append('physical core count unavailable')
    online = set(range(logical))
    affinity = set(range(min(usable, logical)))
    decision = choose_capacity(online=online, affinity=affinity, cpuset=None, quota=None,
                               probe_allowed=None, reserve=reserve)
    return {
        'schema_version': SCHEMA_VERSION,
        'kind': 'startup-cpu-step-zero',
        'platform': 'windows',
        'observed_at': now_utc(),
        'pid': os.getpid(),
        'commands': commands,
        'topology': {'physical_cores': physical, 'online_logical_cpus': logical,
                     'online_cpus': format_cpu_list(online)},
        'process': {'nproc': len(affinity), 'affinity': format_cpu_list(affinity)},
        'cgroup': None,
        'effective_cpuset': None,
        'finite_quota': None,
        'reserve': reserve,
        'probe': None,
        **decision,
        'uncertainties': uncertainties,
        'evidence_kind': 'local observation; not a verification receipt',
    }


def measure(*, reserve: int = 0, probe: bool = True, runner: Runner = run_command) -> dict[str, Any]:
    """Perform step zero and return the snapshot (no files are written here)."""
    if not has_linux_affinity():
        return measure_windows(reserve=reserve, runner=runner)
    uncertainties: list[str] = []
    commands = [runner(argv) for argv in (
        ['lscpu'], ['lscpu', '-p=CPU,CORE,SOCKET,ONLINE'], ['nproc', '--all'], ['nproc'],
        ['taskset', '-pc', str(os.getpid())],
    )]
    try:
        topology = topology_from_lscpu(commands[1]['stdout'])
    except ValueError as exc:
        uncertainties.append(f'topology: {exc}; using /sys/devices/system/cpu/online')
        online_text = Path('/sys/devices/system/cpu/online').read_text(encoding='utf-8')
        topology = {'online_cpus': parse_cpu_list(online_text), 'physical_cores': None}
    online = topology['online_cpus']
    affinity = set(os.sched_getaffinity(0))
    try:
        bounds = cgroup_bounds()
        cpuset = parse_cpu_list(bounds['effective_cpuset']) if bounds['effective_cpuset'] else None
        if cpuset is None:
            uncertainties.append('no cpuset.cpus.effective visible; online CPUs bound the probe')
    except (OSError, UnicodeError, ValueError) as exc:
        bounds, cpuset = {'error': f'{type(exc).__name__}: {exc}'}, None
        uncertainties.append(f'cgroup bounds unresolved: {exc}')
    quota = _cpu_capacity.linux_quota_capacity()
    if quota == 1 and 'error' in bounds:
        uncertainties.append('quota unknown; conservative capacity 1 applies')
    allowed = online & cpuset if cpuset is not None else set(online)
    candidates = set(sorted(allowed)[:max(1, len(online) - reserve)]) if reserve else allowed
    probe_record: dict[str, Any] | None = None
    probe_allowed: set[int] | None = None
    if probe and candidates - affinity:
        probe_record = child_probe(candidates, runner)
        probe_allowed = probe_record.pop('allowed_set')
        if probe_allowed is None:
            uncertainties.append('child affinity probe failed; existing affinity stays in force')
    if reserve and probe_allowed is None:
        probe_allowed = candidates & affinity
    decision = choose_capacity(online=online, affinity=affinity, cpuset=cpuset, quota=quota,
                               probe_allowed=probe_allowed, reserve=reserve)
    return {
        'schema_version': SCHEMA_VERSION,
        'kind': 'startup-cpu-step-zero',
        'observed_at': now_utc(),
        'pid': os.getpid(),
        'commands': commands,
        'topology': {'physical_cores': topology['physical_cores'], 'online_logical_cpus': len(online),
                     'online_cpus': format_cpu_list(online)},
        'process': {'nproc': len(affinity), 'affinity': format_cpu_list(affinity)},
        'cgroup': bounds,
        'effective_cpuset': format_cpu_list(cpuset) if cpuset is not None else None,
        'finite_quota': quota,
        'reserve': reserve,
        'probe': probe_record,
        **decision,
        'uncertainties': uncertainties,
        'evidence_kind': 'local observation; not a verification receipt',
    }
