"""Copy exact acquired research bytes into an inert private layout. Never install or execute."""
from __future__ import annotations

import argparse
import base64
import csv
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
import time
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla.security_research_catalog import load_catalog, MANIFEST_PATH, MANIFEST_SHA256

MAX_TOTAL = 12 * 1024**3
MAX_FILE = 3_000_000_000
MAX_SOFTWARE = 256 * 1024**2
MAX_FILES = 4000
MAX_ENTRIES = 8192
MAX_ARCHIVE = 128 * 1024**2


def safe_path(name):
    if (type(name) is not str or not name or len(name) > 512
            or any(c in name for c in '\\:\x00\r\n')
            or any(p in {'', '.', '..', '.git'} for p in name.split('/'))):
        raise ValueError('unsafe relative path')
    return name


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def tick(deadline):
    if time.monotonic() > deadline:
        raise ValueError('preparation deadline exceeded')


def checked_wheel(payload, deadline=None):
    """Verify every member and complete RECORD. Return inert bytes; no installation rules."""
    deadline = time.monotonic() + 180 if deadline is None else deadline
    if not payload or len(payload) > MAX_ARCHIVE:
        raise ValueError('archive bounds')
    end = payload.rfind(b'PK\x05\x06', max(0, len(payload) - 65557))
    if end < 0 or end + 22 > len(payload):
        raise ValueError('missing ZIP end')
    _, disk, directory_disk, on_disk, count, size, _, comment = struct.unpack_from('<4s4H2LH', payload, end)
    if disk or directory_disk or count != on_disk or count > MAX_ENTRIES or size > 4 * 1024**2 or end + 22 + comment != len(payload):
        raise ValueError('unsupported ZIP shape')
    result, seen, expanded = {}, set(), 0
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for row in archive.infolist():
            tick(deadline)
            name = safe_path(row.filename.rstrip('/'))
            mode = row.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if (name in seen or row.orig_filename != row.filename or row.flag_bits & 1
                    or kind not in {0, stat.S_IFREG, stat.S_IFDIR} or mode & 0o7000
                    or bool(row.is_dir()) != (kind == stat.S_IFDIR) and kind != 0):
                raise ValueError('unsafe or duplicate ZIP member')
            seen.add(name)
            expanded += row.file_size
            if row.file_size < 0 or expanded > MAX_SOFTWARE:
                raise ValueError('expanded archive bounds')
            if row.is_dir():
                if row.file_size:
                    raise ValueError('nonempty directory')
                continue
            if len(result) >= MAX_FILES:
                raise ValueError('software file bound')
            result[name] = archive.read(row)
            if len(result[name]) != row.file_size:
                raise ValueError('truncated ZIP member')
    records = [n for n in result if n.endswith('.dist-info/RECORD') and n.count('/') == 1]
    if len(records) != 1:
        raise ValueError('one full wheel RECORD required')
    record = records[0]
    observed = set()
    for row in csv.reader(io.StringIO(result[record].decode('utf-8'), newline='')):
        tick(deadline)
        if len(row) != 3 or row[0] in observed or row[0] not in result:
            raise ValueError('RECORD inventory differs')
        name, digest, size = row
        observed.add(name)
        if name == record:
            if digest or size:
                raise ValueError('RECORD self row must be unhashed')
        else:
            actual = base64.urlsafe_b64encode(hashlib.sha256(result[name]).digest()).decode().rstrip('=')
            if digest != 'sha256=' + actual or size != str(len(result[name])):
                raise ValueError('RECORD hash or size differs')
    if observed != set(result):
        raise ValueError('RECORD does not cover all files')
    # File/directory prefix collisions are forbidden, including implicit directories.
    for name in result:
        if any('/'.join(name.split('/')[:i]) in result for i in range(1, len(name.split('/')))):
            raise ValueError('file and directory collision')
    return result


def closed_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def held_source(path):
    """Open through no-follow descriptors and retain ancestry until streaming finishes."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('source must be an absolute retained path')
    handles = []
    try:
        parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.append(parent)
        ancestry = []
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            info = os.fstat(child)
            if info.st_mode & 0o022:
                raise ValueError('writable source ancestry')
            ancestry.append((parent, part, identity(info)))
            handles.append(child)
            parent = child
        handle = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        handles.append(handle)
        info = os.fstat(handle)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_uid != os.getuid():
            raise ValueError('source is not an owned regular retained file')
        yield_value = (handle, parent, path.name, identity(info), ancestry)
        yield yield_value
        if identity(os.fstat(handle)) != yield_value[3] or identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != yield_value[3]:
            raise ValueError('source changed during copy')
        for ancestor, name, expected in ancestry:
            if identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False)) != expected:
                raise ValueError('source ancestry changed')
    finally:
        for handle in reversed(handles):
            os.close(handle)


held_source = contextmanager(held_source)


class PrivateOutput:
    """All output mutations use an owned directory descriptor, never followed paths."""
    def __init__(self, root, relative):
        self.handles, self.bindings, self.directories = [], [], set()
        try:
            absolute = Path(root) / safe_path(relative)
            self.path = absolute
            parent = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.handles.append(parent)
            for part in absolute.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                info = os.fstat(child)
                if info.st_mode & 0o022:
                    raise ValueError('unsafe output ancestry')
                self.bindings.append((parent, part, info.st_dev, info.st_ino))
                self.handles.append(child)
                parent = child
            if os.fstat(parent).st_uid != os.getuid():
                raise ValueError('output parent not owned')
            os.mkdir(absolute.name, 0o700, dir_fd=parent)
            self.root = os.open(absolute.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            self.handles.append(self.root)
            info = os.fstat(self.root)
            self.bindings.append((parent, absolute.name, info.st_dev, info.st_ino))
        except BaseException:
            self.close()
            raise

    def current(self):
        for parent, name, device, inode in self.bindings:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or (info.st_dev, info.st_ino) != (device, inode):
                raise ValueError('output custody changed')

    def file(self, relative):
        self.current()
        parts = safe_path(relative).split('/')
        parent = os.dup(self.root)
        try:
            for index, part in enumerate(parts[:-1]):
                path = '/'.join(parts[:index + 1])
                if path not in self.directories:
                    os.mkdir(part, 0o700, dir_fd=parent)
                    self.directories.add(path)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                info = os.fstat(child)
                if info.st_uid != os.getuid() or info.st_mode & 0o077:
                    os.close(child)
                    raise ValueError('output directory changed')
                os.close(parent)
                parent = child
            return os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        finally:
            os.close(parent)

    def close(self):
        for handle in reversed(self.handles):
            os.close(handle)
        self.handles = []


def copy_pinned(source, output, relative, expected, deadline):
    size, digest = expected
    if type(size) is not int or not 0 <= size <= MAX_FILE:
        raise ValueError('source size bound')
    with held_source(source) as (handle, _, _, observed, _):
        if observed[6] != size:
            raise ValueError('source size differs')
        target = output.file(relative)
        count, hashed = 0, hashlib.sha256()
        try:
            while True:
                tick(deadline)
                body = os.read(handle, min(1024**2, size - count + 1))
                if not body:
                    break
                count += len(body)
                if count > size:
                    raise ValueError('source grew')
                hashed.update(body)
                view = memoryview(body)
                while view:
                    written = os.write(target, view)
                    if written <= 0:
                        raise ValueError('short output write')
                    view = view[written:]
            if count != size or hashed.hexdigest() != digest:
                raise ValueError('source checksum differs')
            os.fsync(target)
            os.fchmod(target, 0o400)
        finally:
            os.close(target)
    output.current()


def fixed_layout(root):
    catalog = load_catalog()
    with (root / MANIFEST_PATH).open('rb') as stream:
        manifest_raw = stream.read(262145)
    if len(manifest_raw) > 262144 or hashlib.sha256(manifest_raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError('fixed manifest changed')
    manifest = closed_json(manifest_raw)
    layout = {}
    for wheel in catalog['wheels']:
        layout['artifacts/' + wheel['filename']] = (wheel['bytes'], wheel['sha256'])
        layout['artifacts/indices/' + wheel['index_filename']] = (wheel['index_bytes'], wheel['index_sha256'])
    for name, model in catalog['models'].items():
        for asset in model['assets']:
            if asset['runtime_referenced']:
                layout['models/' + name + '/' + asset['path']] = (asset['bytes'], asset['sha256'])
    layout['models/codec/o200k_base.tiktoken'] = (manifest['codec']['bytes'], manifest['codec']['sha256'])
    for path, row in catalog['retained_source_terms'].items():
        layout['terms/' + path] = (row['bytes'], row['sha256'])
    for row in [manifest['image']['config'], *manifest['image']['layers']]:
        digest = row['digest'].split(':')[1]
        layout['artifacts/blobs/sha256/' + digest] = (row['size'], digest)
    return catalog, layout


def materialize(root, source_map, output):
    root = Path(root).absolute()
    relative = safe_path(output)
    if not relative.startswith('.getzilla/runtime/scratch/'):
        raise ValueError('fresh runtime scratch output required')
    destination = root / relative
    from getzilla import state
    route = state.require_route_owner(root)
    route_binding = json.dumps(route, sort_keys=True, separators=(',', ':'))
    catalog, layout = fixed_layout(root)
    if type(source_map) is not dict or set(source_map) != set(layout):
        raise ValueError('source map must cover exactly fixed required inputs')
    if any(type(value) is not str for value in source_map.values()):
        raise ValueError('source paths only; caller pins forbidden')
    total = sum(size for size, _ in layout.values())
    if total + MAX_SOFTWARE > MAX_TOTAL or len(layout) + MAX_FILES > MAX_ENTRIES:
        raise ValueError('whole preparation bound')
    deadline = time.monotonic() + 180
    # Parent directories must already exist, be owned/private, and contain no symlink.
    parent = destination.parent
    current = root
    for part in parent.relative_to(root).parts:
        current /= part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError('unsafe output ancestry')
    if shutil.disk_usage(parent).free < total + MAX_SOFTWARE + 64 * 1024**2:
        raise ValueError('insufficient free disk')
    with_output = PrivateOutput(root, relative)
    try:
        report = _populate(with_output, catalog, layout, source_map, relative, deadline)
        if json.dumps(state.require_route_owner(root), sort_keys=True, separators=(',', ':')) != route_binding:
            raise ValueError('current task changed during preparation')
        return report
    finally:
        with_output.close()


def check_software(output, expected, deadline):
    """Complete fd-rooted inventory and hash verification under the original deadline."""
    expected_dirs = {'/'.join(name.split('/')[:i]) for name in expected
                     for i in range(1, len(name.split('/')))}
    observed, directories = set(), set()
    root = os.open('software', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=output.root)
    def visit(parent, prefix):
        tick(deadline)
        for name in os.listdir(parent):
            tick(deadline)
            path = prefix + name
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if path not in expected_dirs or info.st_mode & 0o077 or info.st_uid != os.getuid():
                    raise ValueError('unexpected software directory')
                directories.add(path)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    visit(child, path + '/')
                finally:
                    os.close(child)
            else:
                if (path not in expected or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_mode & 0o777 != 0o400 or info.st_uid != os.getuid()):
                    raise ValueError('unexpected software file')
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    if identity(os.fstat(descriptor)) != identity(info):
                        raise ValueError('software changed')
                    hashed, size = hashlib.sha256(), 0
                    while body := os.read(descriptor, 1024**2):
                        tick(deadline)
                        size += len(body)
                        if size > expected[path][0]:
                            raise ValueError('software size differs')
                        hashed.update(body)
                    if (size, hashed.hexdigest()) != expected[path] or identity(os.fstat(descriptor)) != identity(info):
                        raise ValueError('software digest differs')
                finally:
                    os.close(descriptor)
                observed.add(path)
    try:
        visit(root, '')
    finally:
        os.close(root)
    if observed != set(expected) or directories != expected_dirs:
        raise ValueError('software inventory differs')
    output.current()


def _populate(output, catalog, layout, source_map, relative, deadline):
    software, expanded = {}, 0
    for path, expected in sorted(layout.items()):
        copy_pinned(source_map[path], output, path, expected, deadline)
    for wheel in catalog['wheels']:
        tick(deadline)
        path = 'artifacts/' + wheel['filename']
        # Read the copied archive through the held output root; no package import.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=output.root)
        with os.fdopen(descriptor, 'rb') as stream:
            payload = stream.read(MAX_ARCHIVE + 1)
        if (len(payload), hashlib.sha256(payload).hexdigest()) != layout[path]:
            raise ValueError('copied wheel changed')
        rows = checked_wheel(payload, deadline)
        for name, body in rows.items():
            if name in software:
                raise ValueError('cross-wheel file collision')
            expanded += len(body)
            if len(software) >= MAX_FILES or expanded > MAX_SOFTWARE:
                raise ValueError('whole software bound')
            software[name] = (len(body), hashlib.sha256(body).hexdigest())
            fd = output.file('software/' + name)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o400)
    check_software(output, software, deadline)
    entries = len(layout) + len(software) + len(output.directories) + 2
    if entries > MAX_ENTRIES:
        raise ValueError('whole layout entry bound')
    registration = {'schema_version': 1, 'kind': 'public-research162-use/v1',
                    'artifact_root': relative + '/artifacts', 'model_root': relative + '/models',
                    'terms_root': relative + '/terms', 'software_root': relative + '/software'}
    report = {'schema_version': 1, 'kind': 'inert-research-materialization/v1',
              'manifest_sha256': MANIFEST_SHA256, 'source_files': layout,
              'software_files': software, 'software_bytes': expanded,
              'entries': entries, 'registration': registration,
              'execution_performed': False, 'source_use_reference_created': False}
    for name, value in [('registration.json', registration), ('inventory.json', report)]:
        fd = output.file(name)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    output.current()
    tick(deadline)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    with args.sources.open('rb') as stream:
        raw = stream.read(1024**2 + 1)
    if len(raw) > 1024**2:
        raise ValueError('source map bound')
    report = materialize(args.root, closed_json(raw), args.output)
    print(json.dumps({'prepared': True, 'software_files': len(report['software_files']),
                      'software_bytes': report['software_bytes'], 'execution_performed': False}))


if __name__ == '__main__':
    main()
