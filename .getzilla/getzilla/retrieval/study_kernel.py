"""Read actual held-container process/cgroup facts, never caller declarations."""
from __future__ import annotations

import os
from pathlib import Path
import re

from .budget import RetrievalError
from .study_resources import validate_kernel_readback


def _read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = os.read(descriptor, 65537)
        if len(raw) > 65536:
            raise RetrievalError('study_kernel_readback_unavailable')
        return raw.decode('ascii')
    finally:
        os.close(descriptor)


def _cpu_list(text):
    if type(text) is not str or not re.fullmatch(r'[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*', text):
        raise RetrievalError('study_kernel_readback_unavailable')
    values = []
    for part in text.split(','):
        limits = part.split('-')
        low, high = int(limits[0]), int(limits[-1])
        if not 0 <= low <= high <= 1048575 or high - low > 4096:
            raise RetrievalError('study_kernel_readback_unavailable')
        values.extend(range(low, high + 1))
    if len(values) > 4096 or values != sorted(set(values)):
        raise RetrievalError('study_kernel_readback_unavailable')
    return values


def _status(text):
    values = {}
    required = {'Uid', 'CapEff', 'NoNewPrivs', 'Seccomp', 'Cpus_allowed_list', 'NSpid'}
    try:
        for line in text.splitlines():
            key, _, value = line.partition(':')
            if key in required:
                if key in values:
                    raise ValueError('duplicate')
                values[key] = value.strip()
        if set(values) != required:
            raise ValueError('missing')
        uids = values['Uid'].split()
        if uids != ['65532'] * 4 or values['NSpid'].split()[-1] != '1':
            raise ValueError('wrong process')
        return {'uid': int(uids[0]), 'cap_eff': int(values['CapEff'], 16),
                'no_new_privs': int(values['NoNewPrivs']), 'seccomp': int(values['Seccomp']),
                'cpu_ids': _cpu_list(values['Cpus_allowed_list'])}
    except (KeyError, ValueError, IndexError):
        raise RetrievalError('study_kernel_readback_unavailable') from None


def _limit(text):
    if text == 'max':
        return None
    if not re.fullmatch('[0-9]{1,20}', text):
        raise RetrievalError('study_kernel_readback_unavailable')
    return int(text)


def _mounts(text):
    mounts = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or '-' not in fields:
            raise RetrievalError('study_kernel_mount_unavailable')
        target = fields[4]
        if target in {'/', '/model', '/software', '/worker', '/tmp'}:
            if target in mounts:
                raise RetrievalError('study_kernel_mount_unavailable')
            mounts[target] = fields
    if set(mounts) != {'/', '/model', '/software', '/worker', '/tmp'}:
        raise RetrievalError('study_kernel_mount_unavailable')
    for target in ('/', '/model', '/software', '/worker'):
        if 'ro' not in mounts[target][5].split(','):
            raise RetrievalError('study_kernel_mount_unavailable')
    tmp = mounts['/tmp']
    if (not {'rw', 'nosuid', 'nodev', 'noexec'} <= set(tmp[5].split(','))
            or tmp[tmp.index('-') + 1] != 'tmpfs'):
        raise RetrievalError('study_kernel_mount_unavailable')
    return mounts


def read_kernel_profile(pid, cpu_ids, command):
    """The caller holds a pidfd/starttime and rechecks them around this read."""
    try:
        base = Path('/proc') / str(pid)
        result = _status(_read(base / 'status'))
        argv = _read(base / 'cmdline').split('\x00')
        if argv[-1] == '':
            argv.pop()
        if tuple(argv) != command:
            raise RetrievalError('study_kernel_argv_mismatch')
        network = _read(base / 'net/dev')
        result['interfaces'] = sorted(line.split(':', 1)[0].strip()
                                      for line in network.splitlines() if ':' in line)
        result['mounts'] = _mounts(_read(base / 'mountinfo'))
        cgroups = _read(base / 'cgroup').splitlines()
        if len(cgroups) != 1 or not cgroups[0].startswith('0::/'):
            raise RetrievalError('study_cgroup_unavailable')
        relative = cgroups[0][4:]
        if (not relative or not re.fullmatch('[A-Za-z0-9_./-]+', relative)
                or '..' in relative.split('/')):
            raise RetrievalError('study_cgroup_unavailable')
        cgroup_root = Path('/sys/fs/cgroup')
        directory = cgroup_root / relative
        info = directory.lstat()
        result['cgroup_identity'] = [str(directory), info.st_dev, info.st_ino]
        result['cgroup_cpu_ids'] = _cpu_list(_read(directory / 'cpuset.cpus.effective').strip())
        cpu_max = _read(directory / 'cpu.max').split()
        if (len(cpu_max) != 2 or not all(re.fullmatch('[0-9]{1,10}', item) for item in cpu_max)
                or not 0 < int(cpu_max[1]) <= 1000000 or int(cpu_max[0]) != 2 * int(cpu_max[1])):
            raise RetrievalError('study_cgroup_cpu_quota_unavailable')
        result['cpu_max'] = cpu_max
        for key, name in (('memory_max', 'memory.max'), ('swap_max', 'memory.swap.max'),
                          ('pids_max', 'pids.max')):
            result[key] = _limit(_read(directory / name).strip())
        ancestors = []
        parent = directory.parent
        for _ in range(32):
            if parent == cgroup_root:
                break  # The cgroup2 root is implicitly unlimited, not a child controller.
            if cgroup_root not in parent.parents:
                raise RetrievalError('study_cgroup_unavailable')
            ancestor = {'path': str(parent), 'cpu_ids':
                        _cpu_list(_read(parent / 'cpuset.cpus.effective').strip())}
            if not set(cpu_ids) <= set(ancestor['cpu_ids']):
                raise RetrievalError('study_cgroup_unavailable')
            for name in ('memory.max', 'memory.swap.max', 'pids.max'):
                ancestor[name] = _limit(_read(parent / name).strip())
            ancestor['cpu.max'] = _read(parent / 'cpu.max').strip()
            ancestors.append(ancestor)
            parent = parent.parent
        else:
            raise RetrievalError('study_cgroup_unavailable')
        result['ancestors'] = ancestors
        after = directory.lstat()
        if (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino):
            raise RetrievalError('study_cgroup_unavailable')
        validate_kernel_readback(result, cpu_ids=cpu_ids)
        return result
    except (OSError, UnicodeError, TypeError):
        raise RetrievalError('study_kernel_readback_unavailable') from None
