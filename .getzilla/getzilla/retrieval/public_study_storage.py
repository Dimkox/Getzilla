"""Fixed whole-study logical storage observations, never execution permission."""
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import time

from .contracts import digest
from .public_review_inputs import _require

MAX_BYTES = 12 * 1024**3
MAX_ENTRIES = 100000
MAX_SECONDS = 30
CANONICAL_ROOTS = (
    'scratch/retrieval162-prereg-20261105',
    'scratch/all-issues-delivery-20261119/retrieval-experiment-plan',
    'scratch/all-issues-delivery-20261119/data162-independent',
    'scratch/research-artifact-conditions-review-20261119',
    'scratch/research-metadata-snapshot-20261120-v1',
)
CANDIDATE_ROOTS = ('par', 'owned-public-review-v4', 'scratch/research-owned-inputs-v1',
                   'scratch/research-owned-inputs-v2')


@dataclass(frozen=True)
class StudyStorageObservation:
    logical_bytes: int
    scope_digest: str
    identity_digest: str


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _directory(path):
    """Open every absolute component without following a link."""
    path = Path(path)
    _require(path.is_absolute(), 'public_study_storage_unavailable')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            _require(os.fstat(descriptor).st_uid in {0, os.getuid()}, 'public_study_storage_unavailable')
        _require(os.fstat(descriptor).st_uid == os.getuid(), 'public_study_storage_unavailable')
        yield descriptor
    finally:
        os.close(descriptor)


def _scan(roots, deadline):
    records, inodes = [], {}
    def walk(descriptor, scope, relative, depth):
        _require(time.monotonic() < deadline and depth <= 32 and len(records) < MAX_ENTRIES,
                 'public_study_storage_unavailable')
        before = _identity(os.fstat(descriptor))
        entries = []
        with os.scandir(descriptor) as listing:
            for item in listing:
                _require(time.monotonic() < deadline and len(entries) + len(records) < MAX_ENTRIES,
                         'public_study_storage_unavailable')
                entries.append(item.name)
        entries.sort()
        records.append((scope, relative, before))
        for name in entries:
            _require(time.monotonic() < deadline and len(records) < MAX_ENTRIES,
                     'public_study_storage_unavailable')
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            _require(info.st_uid == os.getuid(), 'public_study_storage_unavailable')
            child_path = relative + '/' + name
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
                try:
                    _require(_identity(os.fstat(child)) == _identity(info), 'public_study_storage_changed')
                    walk(child, scope, child_path, depth + 1)
                finally:
                    os.close(child)
            else:
                _require(stat.S_ISREG(info.st_mode), 'public_study_storage_unavailable')
                records.append((scope, child_path, _identity(info)))
                key = (info.st_dev, info.st_ino)
                previous = inodes.setdefault(key, _identity(info))
                _require(previous == _identity(info), 'public_study_storage_changed')
            _require(_identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) == _identity(info),
                     'public_study_storage_changed')
        _require(_identity(os.fstat(descriptor)) == before, 'public_study_storage_changed')
    for scope, path in roots:
        with _directory(path) as descriptor:
            walk(descriptor, scope, '', 0)
    size = sum(identity[5] for identity in inodes.values())
    _require(size <= MAX_BYTES, 'public_study_storage_exceeded')
    return size, records


def _observe(roots, *, deadline):
    """Data-only bounded scanner; public scope is selected by the owner below."""
    unique = []
    for scope, path in sorted(roots, key=lambda item: (len(item[1].parts), str(item[1]))):
        _require(path.is_absolute() and '..' not in path.parts, 'public_study_storage_unavailable')
        if any(path == parent or parent in path.parents for _, parent in unique):
            continue
        unique.append((scope, path))
    first = _scan(unique, deadline)
    second = _scan(unique, deadline)
    _require(first == second, 'public_study_storage_changed')
    return StudyStorageObservation(first[0], digest(tuple((scope, str(path)) for scope, path in unique)),
                                   digest(first[1]))


def _validate_bootstrap_directory(root, reserved, execution_status):
    relative = getattr(reserved, 'relative_path', None)
    _require(type(relative) is str and execution_status == 'running', 'public_study_storage_unavailable')
    parts = Path(relative).parts
    _require(len(parts) == 4 and parts[:3] == ('.getzilla', 'runtime', 'par')
             and parts[3] not in {'.', '..'} and not Path(relative).is_absolute(),
             'public_study_storage_unavailable')
    path = root / relative
    with _directory(path) as descriptor:
        info = os.fstat(descriptor)
        _require((info.st_dev, info.st_ino) == (reserved.device, reserved.inode)
                 and stat.S_IMODE(info.st_mode) == 0o700, 'public_study_storage_changed')
        with os.scandir(descriptor) as entries:
            _require(next(entries, None) is None, 'public_study_storage_bootstrap_not_empty')
    return path


def _output_directory(root, operation, execution_id, record):
    from ..execution_output import capture_artifact
    output = record['output']
    artifact = None if output is None else output['artifact']
    if artifact is None:
        _require(record['execution_status'] == 'running', 'public_study_storage_unavailable')
        from .study_supervisor import reserved_study_output_directory
        reserved = reserved_study_output_directory(operation, execution_id)
        path = _validate_bootstrap_directory(root, reserved, record['execution_status'])
        return path, ('reserved', reserved.relative_path, reserved.device, reserved.inode)
    _require(capture_artifact(root, artifact['path']) == artifact, 'public_study_storage_unavailable')
    return (root / artifact['path']).parent, ('artifact', artifact)


def study_storage_observation(operation, execution_id):
    from .public_study_operation import check_public_study_operation
    from ..architecture_diff import _git_binding
    from ..execution import trusted_caller, _authorize, _find
    from ..execution_store import load_registry
    projection = check_public_study_operation(operation)
    root = projection.root
    caller = trusted_caller(root)
    registry = load_registry(root)
    record = _find(registry, execution_id)
    _authorize(root, caller, record)
    _require(record['operation_id'] == projection.operation_digest and not record['expired'],
             'public_study_storage_unavailable')
    output_directory, output_binding = _output_directory(root, operation, execution_id, record)
    common = _git_binding(root).common_directory
    _require(common is not None and common.name == '.git', 'public_study_storage_unavailable')
    canonical_runtime = common.parent / '.getzilla/runtime'
    runtime = root / '.getzilla/runtime'
    roots = [('canonical:' + name, canonical_runtime / name) for name in CANONICAL_ROOTS]
    roots += [('candidate:' + name, runtime / name) for name in CANDIDATE_ROOTS]
    roots += [('export:' + name, path) for name, path in (
        ('worker', projection.worker_root), ('software', projection.software_root), ('model', projection.model_root))]
    roots.append(('execution:' + execution_id, output_directory))
    deadline = time.monotonic() + MAX_SECONDS
    observation = _observe(roots, deadline=deadline)
    check_public_study_operation(operation)
    _require(load_registry(root) == registry
             and _output_directory(root, operation, execution_id, record) == (output_directory, output_binding),
             'public_study_storage_changed')
    return observation
