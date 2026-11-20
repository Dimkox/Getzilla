"""Fixed offline profile data validators, deliberately NOT resource issuers.

An inspect dictionary or a passing validator cannot mint a live permit. The
future native supervisor must independently hold actual container/PID/starttime,
cgroup, executable/image and artifact custody; read these facts itself; verify
ancestor limits; bound IPC/logs/deadlines; and retire its own complete childtree.
Until that owner and genuine operation admission exist, execution is unavailable.
"""
from __future__ import annotations

from .budget import RetrievalError
from .contracts import digest, hex_digest

MEMORY_BYTES = 6442450944
TMPFS_OPTIONS = frozenset({'rw', 'noexec', 'nosuid', 'nodev', 'size=67108864', 'mode=700'})


def resource_profile():
    """Fresh data projection; never a process, execution or resource permit."""
    return {'schema_version': 1, 'profile': 'issue162-owned-offline-v1',
            'cpu_count': 2, 'cpu_quota_cores': 2, 'runtime': 'runc',
            'clock': 'same-kernel-boot-and-time-namespace',
            'cgroup_namespace': 'private', 'memory_bytes': MEMORY_BYTES, 'swap_bytes': 0,
            'pids': 128, 'uid': 65532, 'gid': 65532, 'network': 'none',
            'read_only_root': True, 'mounts': ['/model', '/software', '/worker'],
            'mounts_read_only': True, 'mount_propagation': 'rprivate',
            'capabilities': [], 'no_new_privileges': True, 'seccomp': 'filter',
            'gpu': False, 'tmpfs_bytes': 67108864, 'docker_logs': 'none',
            'ort_intra_threads': 1, 'ort_inter_threads': 1, 'blas_threads': 1,
            'batch_size': 1, 'hard_timeout_max_seconds': 14400}


RESOURCE_PROFILE_SHA256 = digest(resource_profile())


def _cpus(values):
    if (type(values) is not tuple or len(values) != 2
            or any(type(value) is not int or not 0 <= value <= 1048575 for value in values)
            or tuple(sorted(set(values))) != values):
        raise RetrievalError('offline_profile_mismatch')
    return values


def validate_container_readback(observed, *, image_id, cpu_ids, command, mounts):
    """Compare untrusted Docker metadata with a separately frozen projection."""
    cpu_ids = _cpus(cpu_ids)
    if (type(image_id) is not str or not image_id.startswith('sha256:')
            or not hex_digest(image_id[7:]) or type(command) is not tuple or not command
            or any(type(arg) is not str or not arg for arg in command)
            or type(mounts) is not dict or set(mounts) != {'/model', '/software', '/worker'}
            or any(type(path) is not str or not path.startswith('/')
                   or '/..' in path or '\x00' in path for path in mounts.values())):
        raise RetrievalError('offline_profile_mismatch')
    try:
        config, host = observed['Config'], observed['HostConfig']
        actual_command = tuple(config['Entrypoint'] or []) + tuple(config['Cmd'] or [])
        fixed = {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
                 'Memory': MEMORY_BYTES, 'MemorySwap': MEMORY_BYTES, 'PidsLimit': 128,
                 'CpusetCpus': ','.join(map(str, cpu_ids)), 'PidMode': '', 'IpcMode': 'none',
                 'NanoCpus': 2000000000, 'Runtime': 'runc', 'CgroupnsMode': 'private'}
        if (observed['Image'] != image_id or config['User'] != '65532:65532'
                or actual_command != command
                or any(type(host[key]) is not type(value) or host[key] != value
                       for key, value in fixed.items())
                or host['CapDrop'] != ['ALL'] or host['CapAdd'] not in (None, [])
                or host['SecurityOpt'] != ['no-new-privileges:true']
                or host['Devices'] != [] or host['DeviceRequests'] not in (None, [])
                or host['LogConfig']['Type'] != 'none'
                # Validate the sole container-private tmpfs and its exact options.
                or set(host['Tmpfs']) != {'/tmp'}  # nosec B108
                or frozenset(host['Tmpfs']['/tmp'].split(',')) != TMPFS_OPTIONS):  # nosec B108
            raise RetrievalError('offline_profile_mismatch')
        actual_mounts = observed['Mounts']
        if type(actual_mounts) is not list or len(actual_mounts) != 3:
            raise RetrievalError('offline_profile_mismatch')
        seen = set()
        for item in actual_mounts:
            target = item['Destination']
            if (target in seen or target not in mounts or item['Source'] != mounts[target]
                    or item['Type'] != 'bind' or item['RW'] is not False
                    or item['Propagation'] != 'rprivate'):
                raise RetrievalError('offline_profile_mismatch')
            seen.add(target)
    except RetrievalError:
        raise
    except (KeyError, TypeError, AttributeError, ValueError):
        raise RetrievalError('offline_profile_mismatch') from None


def validate_kernel_readback(observed, *, cpu_ids):
    """Validate current kernel values, not caller flags; no live permit is issued."""
    cpu_ids = _cpus(cpu_ids)
    try:
        fixed = {'uid': 65532, 'cap_eff': 0, 'no_new_privs': 1, 'seccomp': 2,
                 'memory_max': MEMORY_BYTES, 'swap_max': 0, 'pids_max': 128}
        if (any(type(observed[key]) is not int or observed[key] != value
                for key, value in fixed.items())
                or type(observed['cpu_ids']) is not list
                or type(observed['cgroup_cpu_ids']) is not list
                or any(type(value) is not int for value in
                       observed['cpu_ids'] + observed['cgroup_cpu_ids'])
                or tuple(observed['cpu_ids']) != cpu_ids
                or tuple(observed['cgroup_cpu_ids']) != cpu_ids
                or observed['interfaces'] != ['lo']):
            raise RetrievalError('offline_kernel_profile_mismatch')
    except RetrievalError:
        raise
    except (KeyError, TypeError, AttributeError, ValueError):
        raise RetrievalError('offline_kernel_profile_mismatch') from None
