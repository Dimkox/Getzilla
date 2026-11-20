"""Actual PID1 kernel readback using only reviewed source and Python stdlib."""
from __future__ import annotations

import os
from pathlib import Path

from .study_kernel import _cpu_list, _limit, _mounts, _read, _status
from .study_resources import validate_kernel_readback


def read_inside_kernel():
    if os.getpid() != 1:
        raise ValueError('PID1 readback only')
    base, cgroup = Path('/proc/self'), Path('/sys/fs/cgroup')
    result = _status(_read(base / 'status'))
    result['start_ticks'] = _read(base / 'stat').rsplit(')', 1)[1].split()[19]
    result['boot_id'] = _read('/proc/sys/kernel/random/boot_id').strip()
    result['interfaces'] = sorted(line.split(':', 1)[0].strip()
        for line in _read(base / 'net/dev').splitlines() if ':' in line)
    result['mounts'] = _mounts(_read(base / 'mountinfo'))
    result['cgroup_cpu_ids'] = _cpu_list(_read(cgroup / 'cpuset.cpus.effective').strip())
    for key, name in (('memory_max', 'memory.max'), ('swap_max', 'memory.swap.max'),
                      ('pids_max', 'pids.max')):
        result[key] = _limit(_read(cgroup / name).strip())
    quota = _read(cgroup / 'cpu.max').split()
    if (len(quota) != 2 or not all(item.isascii() and item.isdigit() for item in quota)
            or not 0 < int(quota[1]) <= 1000000 or int(quota[0]) != 2 * int(quota[1])):
        raise ValueError('CPU quota unavailable')
    result['cpu_max'] = quota
    info = cgroup.stat()
    result['cgroup_identity'] = [info.st_dev, info.st_ino]
    result['namespace_ids'] = {name: os.readlink(f'/proc/self/ns/{name}')
        for name in ('pid', 'mnt', 'net', 'user', 'cgroup', 'time')}
    result['ancestor_limits'] = 'not_visible_in_private_cgroup_namespace'
    # These are verified local ceilings; ancestors may impose tighter bounds.
    validate_kernel_readback(result, cpu_ids=tuple(result['cpu_ids']))
    return result
