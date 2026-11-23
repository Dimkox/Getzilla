"""Finite retained-source composition adapter, not artifact or installation evidence.

The reviewed surface digest deliberately refuses unrelated source changes too.
Updating it requires independent review of the exact new source composition.
No target Python, build backend or retained source is imported or executed.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
import stat
import sys
import tarfile
import tomllib
from time import monotonic

ADAPTER = '.getzilla/getzilla/security_corresponding_source.py'
LEGAL = '.getzilla/config/license-exception-inputs/factory-source-delivery-v1/'
# Reviewed engine constants, never loaded from candidate policy or environment.
SURFACE_SHA256 = 'c79cd7e3de46198960df4ec9c4568d07b7ea022906cea82d05212df359c54ca1'
CATALOG = {
    'certifi': ('2026.10.19', '55233d49508cbaedddaab023a20f446ec60616cf2b2923a17c75eb9fef44752d',
                '64baf557a90ab3f2061ecf1f002dd65df65d86ea93e4eaa6d7c603ec650f14e2',
                '42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b'),
    'psycopg': ('3.3.4', 'e32cc7ce2af142492b171ae53e8b2606675dc49de8355fb9f5c37d44c4ff47a4',
                '01ca95a944172ecabfb916a4a9180d9a27d16328256914952a3f8f994d6e10b8',
                'b6bbc25ccf05c8fad3b061d9db2ef0909a555171b84b07f29458a447253d679a'),
}
ROOTS = tuple(LEGAL + 'vendor/' + name + '-' + row[0] + '/' for name, row in CATALOG.items())
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_FILES = 12000
MAX_SECONDS = 30


def _budget(deadline):
    if deadline is not None and monotonic() >= deadline:
        raise ValueError('corresponding-source original time budget exceeded')


def _sha(payload):
    return hashlib.sha256(payload).hexdigest()


def _read(root, relative, *, deadline=None):
    """Hold no-follow directory/file descriptors; check bytes and stable identity."""
    _budget(deadline)
    pure = PurePosixPath(relative)
    if (not relative or str(pure) != relative or pure.is_absolute() or '\\' in relative
            or any(p in {'.', '..'} for p in pure.parts)):
        raise ValueError('unsafe corresponding-source input')
    descriptors = []
    try:
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        for part in pure.parts[:-1]:
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(parent)
        fd = os.open(pure.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE:
            raise ValueError('corresponding-source input is not bounded regular content')
        chunks = []
        count = 0
        while count <= MAX_FILE:
            _budget(deadline)
            part = os.read(fd, min(65536, MAX_FILE + 1 - count))
            if not part:
                break
            chunks.append(part)
            count += len(part)
        after = os.fstat(fd)
        bound = os.stat(pure.name, dir_fd=parent, follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        if count > MAX_FILE or any(getattr(before, f) != getattr(after, f) or getattr(after, f) != getattr(bound, f) for f in fields):
            raise ValueError('corresponding-source custody changed')
        return b''.join(chunks), stat.S_IMODE(after.st_mode)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _trusted_adapter_bytes():
    # Actual loaded source, including the lean SDKzip representation. The reader
    # admits only fixed standard loaders and checks source identity/size.
    from .closed_loader_source import module_source
    if __name__ != 'getzilla.security_corresponding_source' or __name__ not in sys.modules:
        raise ValueError('trusted corresponding-source adapter identity unavailable')
    return module_source(sys.modules[__name__])


TRUSTED_ADAPTER_SHA256 = _sha(_trusted_adapter_bytes())


def surface_digest(root, files, *, deadline=None):
    """A closed composition; only the engine and exact retained trees are separate."""
    if not 1 <= len(files) <= MAX_FILES or files != sorted(set(files)):
        raise ValueError('corresponding-source surface membership unavailable')
    rows = []
    total = 0
    for path in files:
        _budget(deadline)
        if path.startswith(ROOTS):
            continue
        payload, mode = _read(root, path, deadline=deadline)
        total += len(payload)
        if total > MAX_TOTAL:
            raise ValueError('corresponding-source surface exceeds bound')
        if path == ADAPTER:
            if _sha(payload) != TRUSTED_ADAPTER_SHA256 or mode != 0o644:
                raise ValueError('candidate adapter differs from trusted checker')
            continue
        rows.append([path, mode, len(payload), _sha(payload)])
    if ADAPTER not in files:
        raise ValueError('candidate adapter missing')
    return _sha(json.dumps(rows, separators=(',', ':'), ensure_ascii=True).encode())


def _members(root, prefix, expected, *, deadline=None):
    """Check actual complete source-tree directories, including untracked entries."""
    seen = set()
    expected_dirs = {str(p) for path in expected for p in PurePosixPath(path).parents if str(p) != '.'}
    seen_dirs = set()
    descriptors = []
    try:
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(descriptor)
        for part in PurePosixPath(prefix).parts:
            descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            descriptors.append(descriptor)
        def walk(parent, relative, depth):
            _budget(deadline)
            if depth > 16:
                raise ValueError('source tree depth exceeds bound')
            with os.scandir(parent) as entries:
                for entry in entries:
                    _budget(deadline)
                    path = relative + entry.name
                    if entry.is_dir(follow_symlinks=False) and path in expected_dirs:
                        seen_dirs.add(path)
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                        try:
                            walk(child, path + '/', depth + 1)
                        finally:
                            os.close(child)
                    elif entry.is_file(follow_symlinks=False) and path in expected:
                        seen.add(path)
                    else:
                        raise ValueError('undeclared corresponding-source member')
        walk(descriptor, '', 0)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

    if seen != expected or seen_dirs != expected_dirs:
        raise ValueError('missing corresponding-source member')


def _source_payload(root, name, *, deadline, files=None):
    """Verify one fixed source and repack it; this alone grants no data role."""
    if name not in CATALOG or not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise ValueError('fixed source custody unavailable')
    version, snapshot_hash, map_hash, wheel_hash = CATALOG[name]
    stem = name + '-' + version
    def read(relative):
        return _read(root, relative, deadline=deadline)
    snapshot_raw, _ = read(LEGAL + stem + '-snapshot.json')
    map_raw, _ = read(LEGAL + stem + '-source-map.json')
    if _sha(snapshot_raw) != snapshot_hash or _sha(map_raw) != map_hash:
        raise ValueError('source snapshot or map changed')
    snapshot, source_map = json.loads(snapshot_raw), json.loads(map_raw)
    if source_map['wheel'] != {'filename': stem + '-py3-none-any.whl', 'sha256': wheel_hash}:
        raise ValueError('source map wheel identity changed')
    original = snapshot['original_publisher_archive']
    index_raw, _ = read(LEGAL + stem + '-index.json')
    if (_sha(index_raw) != original['index_sha256']
            or source_map['source']['original_archive_sha256'] != original['sha256']
            or source_map['source']['original_index_sha256'] != original['index_sha256']
            or source_map['source']['original_archive_url'] != original['url']):
        raise ValueError('original source identity differs')
    prefix = LEGAL + 'vendor/' + stem + '/'
    members = snapshot['members']
    expected = {m['path'] for m in members}
    _members(root, prefix, expected, deadline=deadline)
    if files is not None and set(p for p in files if p.startswith(prefix)) != {prefix + p for p in expected}:
        raise ValueError('Git source membership differs')
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for member in members:
            payload, mode = read(prefix + member['path'])
            if (_sha(payload) != member['sha256'] or len(payload) != member['bytes'] or mode != member['mode']
                    or member['original_path'] != stem + '/' + member['path']):
                raise ValueError('corresponding-source content or mode differs')
            payload.decode('utf-8')
            info = tarfile.TarInfo(member['original_path'])
            info.size, info.mode, info.mtime = len(payload), mode, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            archive.addfile(info, io.BytesIO(payload))
    repack = io.BytesIO()
    with gzip.GzipFile(fileobj=repack, filename='', mode='wb', compresslevel=9, mtime=0) as handle:
        handle.write(output.getvalue())
    _members(root, prefix, expected, deadline=deadline)
    for member in members:
        payload, mode = read(prefix + member['path'])
        if _sha(payload) != member['sha256'] or mode != member['mode'] or len(payload) != member['bytes']:
            raise ValueError('source changed during repack validation')
    return snapshot, source_map, repack.getvalue(), prefix


def classify(root, files, *, deadline=None):
    """Return typed retained declarations only for this exact reviewed composition."""
    controls = {LEGAL + name + '-' + row[0] + suffix
                for name, row in CATALOG.items()
                for suffix in ('-snapshot.json', '-source-map.json', '-index.json')}
    if not any(path.startswith(ROOTS) or path in controls for path in files):
        return []
    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise ValueError('retained-source classification requires no-follow source custody')
    if deadline is None:
        deadline = monotonic() + MAX_SECONDS
    def read(relative):
        return _read(root, relative, deadline=deadline)
    before = surface_digest(root, files, deadline=deadline)
    if before != SURFACE_SHA256:
        raise ValueError('supported source composition changed; retained-source role requires review')
    lock_raw, _ = read('factory/uv.lock')
    wheel_raw, _ = read('factory/runtime/runtime-wheels-linux-x86_64-cpython312.json')
    lock = tomllib.loads(lock_raw.decode())
    wheels = json.loads(wheel_raw)
    if wheels['lock_sha256'] != _sha(lock_raw) or wheels['profile'] != 'ubuntu-24.04-x86_64-cpython312':
        raise ValueError('declared runtime target does not match lock')
    rows = []
    for name, (version, snapshot_hash, map_hash, wheel_hash) in CATALOG.items():
        wheel = [w for w in wheels['wheels'] if w['name'] == name]
        filename = name + '-' + version + '-py3-none-any.whl'
        if wheel != [{'filename': filename, 'name': name, 'sha256': wheel_hash, 'version': version}]:
            raise ValueError('declared corresponding-source wheel changed')
        package = [p for p in lock['package'] if p['name'] == name and p['version'] == version]
        if len(package) != 1 or not any(w['hash'] == 'sha256:' + wheel_hash and w['url'].endswith('/' + filename) for w in package[0]['wheels']):
            raise ValueError('declared wheel has no exact lock artifact')
        snapshot, _source_map, repack, prefix = _source_payload(root, name, deadline=deadline, files=files)
        manifest = prefix + 'pyproject.toml'
        project_raw, project_mode = read(manifest)
        expected_project = next(m for m in snapshot['members'] if m['path'] == 'pyproject.toml')
        if (_sha(project_raw) != expected_project['sha256'] or len(project_raw) != expected_project['bytes']
                or project_mode != expected_project['mode']):
            raise ValueError('source project changed after retained-member validation')
        data = tomllib.loads(project_raw.decode())
        constraints = []
        def record(values, role, group=''):
            for requirement in values:
                constraints.append({'requirement': requirement, 'role': role, 'group': group})
        record(data.get('project', {}).get('dependencies', []), 'runtime')
        record(data.get('build-system', {}).get('requires', []), 'build')
        for group, values in data.get('project', {}).get('optional-dependencies', {}).items():
            record(values, {'test': 'test', 'docs': 'docs', 'dev': 'development'}.get(group, 'optional'), group)
        rows.append({'package': name, 'version': version, 'manifest': manifest,
                     'members': sorted(prefix + m['path'] for m in snapshot['members']), 'constraints': constraints,
                     'role': 'retained-corresponding-source-data', 'surface_sha256': before,
                     'snapshot_sha256': snapshot_hash, 'source_map_sha256': map_hash,
                     'original_publisher_archive': snapshot['original_publisher_archive'],
                     'repack': {'sha256': _sha(repack), 'bytes': len(repack),
                                'members': [m['original_path'] for m in snapshot['members']]},
                     'declared_target': {'profile': wheels['profile'], 'lock_sha256': _sha(lock_raw), 'wheel': wheel[0]},
                     'artifact_observation': 'declared-target-only'})
    from .security_osv_snapshot import _tracked_files
    if _tracked_files(root) != files or surface_digest(root, files, deadline=deadline) != before:
        raise ValueError('source composition changed during classification')
    return rows
