"""Bounded OCI bytes and physical layout reads. No engine, network or policy imports."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import zipfile

ARTIFACT_BYTES = 128 * 1024 * 1024
ARCHIVE_BYTES = 256 * 1024 * 1024
INDEX_BYTES = 16 * 1024 * 1024
METADATA_BYTES = 2 * 1024 * 1024
MEMBERS = 10000
MANIFEST_MEDIA = {'application/vnd.oci.image.manifest.v1+json',
                  'application/vnd.docker.distribution.manifest.v2+json'}
CONFIG_MEDIA = {'application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'}
LAYER_MEDIA = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip',
               'application/vnd.docker.image.rootfs.diff.tar.gzip'}
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')


class OCIError(ValueError):
    """Unproved OCI identity, format, resource or physical binding."""


def digest(raw: bytes) -> str:
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class Budget:
    """One logical application-byte ledger, never a physical device quota."""
    def __init__(self, profile=None, *, clock=time.monotonic, deadline=None):
        caps = {'max_images': 512, 'max_compressed_bytes': 512 * 1024 * 1024,
                'max_unpacked_bytes': 512 * 1024 * 1024, 'max_storage_bytes': 512 * 1024 * 1024,
                'max_manifest_bytes': 64 * 1024 * 1024, 'max_layers': MEMBERS, 'deadline_seconds': 900}
        self.profile = dict(profile) if isinstance(profile, dict) else {**caps, 'images': [], 'platform': 'linux/amd64'}
        if (profile is not None and not isinstance(profile, dict)
                or set(self.profile) != {*caps, 'images', 'platform'}
                or not isinstance(self.profile['platform'], str) or self.profile['platform'] not in {'linux/amd64', 'linux/arm64'}
                or any(type(self.profile[key]) is not int or not 0 < self.profile[key] <= cap for key, cap in caps.items())):
            raise OCIError('invalid or excessive selected OCI profile')
        self.clock = clock
        start = clock()
        self.deadline = min(start + self.profile['deadline_seconds'], deadline if deadline is not None else float('inf'))
        self.wire = self.expanded = self.storage = self.layers = self.members = 0

    def check(self):
        if self.clock() >= self.deadline:
            raise OCIError('OCI absolute deadline exceeded')

    def charge(self, kind, count):
        self.check()
        caps = {'wire': self.profile['max_compressed_bytes'],
                'expanded': min(self.profile['max_unpacked_bytes'], ARCHIVE_BYTES),
                'storage': self.profile['max_storage_bytes'], 'layers': self.profile['max_layers'], 'members': MEMBERS}
        if type(count) is not int or count < 0 or kind not in caps or getattr(self, kind) + count > caps[kind]:
            raise OCIError('OCI selected ' + kind + ' bound exceeded')
        setattr(self, kind, getattr(self, kind) + count)

    def manifest(self, raw):
        self.check()
        if not raw or len(raw) > min(self.profile['max_manifest_bytes'], INDEX_BYTES):
            raise OCIError('OCI metadata exceeds selected bound')


def _pairs(rows):
    result = {}
    for name, value in rows:
        if name in result:
            raise OCIError('duplicate OCI JSON key')
        result[name] = value
    return result


def json_object(raw, budget):
    budget.manifest(raw)
    try:
        result = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(OCIError('nonfinite OCI JSON')))
        if not isinstance(result, dict):
            raise OCIError('OCI JSON object required')
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise OCIError('invalid OCI JSON') from exc


def safe_name(name):
    if (not isinstance(name, str) or not name or len(name) > 1024 or '\\' in name or ':' in name
            or any(ord(char) < 32 for char in name) or PurePosixPath(name).is_absolute()
            or any(part in {'', '.', '..'} for part in name.split('/')) or len(name.split('/')) > 32):
        raise OCIError('unsafe OCI member path')
    return name


def archive_members(payload, filename, *, budget=None):
    """Read a closed regular-file archive without extraction or filesystem effects."""
    budget = budget or Budget()
    if not isinstance(payload, bytes) or not payload or len(payload) > ARTIFACT_BYTES:
        raise OCIError('OCI artifact compressed bound exceeded')
    rows, seen = {}, set()
    if filename.endswith('.zip'):
        end = payload.rfind(b'PK\x05\x06', max(0, len(payload) - 65557))
        if end < 0 or end + 22 > len(payload):
            raise OCIError('incomplete OCI ZIP')
        count = int.from_bytes(payload[end + 10:end + 12], 'little')
        directory = int.from_bytes(payload[end + 12:end + 16], 'little')
        if (count > MEMBERS or directory > 4 * 1024 * 1024 or any(payload[end + 4:end + 8])
                or int.from_bytes(payload[end + 8:end + 10], 'little') != count
                or end + 22 + int.from_bytes(payload[end + 20:end + 22], 'little') != len(payload)):
            raise OCIError('OCI ZIP directory exceeds bound')
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                for member in archive.infolist():
                    budget.check()
                    name = safe_name(member.filename.rstrip('/'))
                    if (name in seen or member.orig_filename != member.filename or member.flag_bits & 1
                            or stat.S_IFMT(member.external_attr >> 16) not in {0, stat.S_IFREG, stat.S_IFDIR}):
                        raise OCIError('ambiguous or unsupported OCI ZIP member')
                    seen.add(name)
                    budget.charge('members', 1)
                    budget.charge('expanded', member.file_size)
                    if member.is_dir():
                        if member.file_size:
                            raise OCIError('nonempty OCI ZIP directory')
                    else:
                        raw = archive.read(member)
                        if len(raw) != member.file_size:
                            raise OCIError('truncated OCI ZIP member')
                        rows[name] = raw
        except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
            raise OCIError('invalid OCI ZIP') from exc
        return rows
    if not filename.endswith('.tar'):
        raise OCIError('unsupported OCI archive format')
    # Account the entire TAR, including headers, padding and terminal blocks.
    budget.charge('expanded', len(payload))
    offset = 0
    while offset + 512 <= len(payload):
        budget.check()
        header = payload[offset:offset + 512]
        if not any(header):
            if len(payload) - offset < 1024 or any(payload[offset:]):
                raise OCIError('ambiguous OCI TAR ending')
            return rows
        try:
            checksum = int(header[148:156].strip(b' \0') or b'0', 8)
            size = int(header[124:136].strip(b' \0') or b'0', 8)
            name = header[:100].split(b'\0', 1)[0].decode('utf-8')
            prefix = header[345:500].split(b'\0', 1)[0].decode('utf-8')
            name = safe_name(((prefix + '/') if prefix else '') + name.rstrip('/'))
        except (ValueError, UnicodeError) as exc:
            raise OCIError('invalid OCI TAR header') from exc
        if checksum != sum(header[:148]) + 8 * 32 + sum(header[156:]):
            raise OCIError('OCI TAR checksum differs')
        kind = header[156:157]
        if kind not in {b'0', b'\0', b'5'} or name in seen or any(part.startswith('.wh.') for part in name.split('/')):
            raise OCIError('unsupported or duplicate OCI layer semantics')
        seen.add(name)
        budget.charge('members', 1)
        offset += 512
        padded = ((size + 511) // 512) * 512
        if size < 0 or offset + padded > len(payload) or any(payload[offset + size:offset + padded]):
            raise OCIError('truncated or ambiguous OCI TAR member')
        if kind == b'5':
            if size:
                raise OCIError('nonempty OCI directory')
        else:
            rows[name] = payload[offset:offset + size]
        offset += padded
    raise OCIError('OCI TAR has no complete ending')


def validate_layout(objects, reference, platform, *, budget=None):
    budget = budget or Budget()
    if (not isinstance(objects, dict) or not objects or len(objects) > MEMBERS
            or not isinstance(reference, str) or '@' not in reference
            or not DIGEST.fullmatch(reference.rsplit('@', 1)[1]) or platform not in {'linux/amd64', 'linux/arm64'}):
        raise OCIError('exact OCI subject and platform required')
    if any(not isinstance(raw, bytes) for raw in objects.values()) or sum(map(len, objects.values())) > ARTIFACT_BYTES:
        raise OCIError('OCI object set exceeds artifact bound')
    for name in objects:
        safe_name(name)
    try:
        if json_object(objects['oci-layout'], budget) != {'imageLayoutVersion': '1.0.0'}:
            raise OCIError('unsupported OCI layout version')
        index = json_object(objects['index.json'], budget)
        expected_platform = dict(zip(('os', 'architecture'), platform.split('/')))
        manifests = index.get('manifests')
        if index.get('schemaVersion') != 2 or not isinstance(manifests, list) or len(manifests) != 1:
            raise OCIError('OCI layout must select one qualified platform manifest')
        selected = manifests[0]
        if not isinstance(selected, dict) or selected.get('platform') != expected_platform:
            raise OCIError('OCI selected platform differs')
        used = {'oci-layout', 'index.json'}
        def blob(descriptor, media):
            budget.check()
            if (not isinstance(descriptor, dict) or set(descriptor) - {'mediaType', 'digest', 'size', 'platform', 'annotations'}
                    or descriptor.get('mediaType') not in media or not DIGEST.fullmatch(str(descriptor.get('digest', '')))
                    or type(descriptor.get('size')) is not int or not 0 < descriptor['size'] <= ARTIFACT_BYTES):
                raise OCIError('unsupported OCI descriptor')
            name = 'blobs/sha256/' + descriptor['digest'][7:]
            raw = objects[name]
            if len(raw) != descriptor['size'] or digest(raw) != descriptor['digest']:
                raise OCIError('OCI descriptor bytes differ')
            used.add(name)
            return raw
        if selected.get('digest') != reference.rsplit('@', 1)[1]:
            raise OCIError('OCI selected child differs from declared manifest')
        manifest = json_object(blob(selected, MANIFEST_MEDIA), budget)
        layers = manifest.get('layers')
        if manifest.get('schemaVersion') != 2 or not isinstance(layers, list) or not layers:
            raise OCIError('OCI manifest lacks complete layers')
        config = json_object(blob(manifest.get('config'), CONFIG_MEDIA), budget)
        if any(config.get(key) != value for key, value in expected_platform.items()) or config.get('variant'):
            raise OCIError('OCI config platform differs or is unsupported')
        rootfs = config.get('rootfs')
        if (not isinstance(rootfs, dict) or rootfs.get('type') != 'layers'
                or not isinstance(rootfs.get('diff_ids'), list) or len(rootfs['diff_ids']) != len(layers)):
            raise OCIError('OCI diff_id coverage differs')
        members, files = {}, {}
        for layer, diff_id in zip(layers, rootfs['diff_ids']):
            budget.charge('layers', 1)
            raw = blob(layer, LAYER_MEDIA)
            if layer['mediaType'].endswith(('+gzip', '.gzip')):
                chunks = []
                remaining = min(budget.profile['max_unpacked_bytes'], ARCHIVE_BYTES) - budget.expanded
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                    while True:
                        budget.check()
                        chunk = stream.read(min(65536, remaining + 1))
                        if len(chunk) > remaining:
                            raise OCIError('OCI decompression exceeds selected aggregate')
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                expanded = b''.join(chunks)
            else:
                expanded = raw
            if diff_id != digest(expanded):
                raise OCIError('OCI uncompressed diff_id differs')
            entries = archive_members(expanded, 'layer.tar', budget=budget)
            prefix = 'layers/' + layer['digest'][7:] + '/'
            for name, body in entries.items():
                full = prefix + name
                if full in members:
                    raise OCIError('repeated OCI layer identity')
                members[full] = {'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body)}
                if re.search(r'(license|licence|notice|copying|copyright)', PurePosixPath(name).name, re.I):
                    if len(body) > METADATA_BYTES:
                        raise OCIError('OCI license metadata exceeds bound')
                    files[full] = body
        if used != set(objects):
            raise OCIError('unreferenced or missing OCI object')
        members.update({'oci/' + name: {'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)} for name, raw in objects.items()})
        return {'manifest_digest': selected['digest'], 'config_digest': manifest['config']['digest'],
                'diff_ids': rootfs['diff_ids'], 'platform': platform, 'config': config,
                'members': members, 'files': files, 'objects': objects}
    except (KeyError, TypeError, OSError, EOFError, ValueError, RecursionError) as exc:
        if isinstance(exc, OCIError):
            raise
        raise OCIError('invalid or incomplete OCI object graph') from exc


def read_archive(payload, filename, reference, platform, *, budget=None):
    budget = budget or Budget()
    return validate_layout(archive_members(payload, filename, budget=budget), reference, platform, budget=budget)


def pack_layout(objects):
    estimate = sum(512 + ((len(raw) + 511) // 512) * 512 for raw in objects.values()) + 1024
    estimate = ((estimate + 10239) // 10240) * 10240
    if estimate > ARTIFACT_BYTES:
        raise OCIError('OCI TAR exceeds artifact bound before allocation')
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(objects.items()):
            safe_name(name)
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(raw))
    raw = output.getvalue()
    if len(raw) > ARTIFACT_BYTES:
        raise OCIError('OCI TAR exceeds artifact bound')
    return raw


def identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def open_directory_chain(path):
    """Pin every ancestor without following a link, including the selected root."""
    if os.name != 'posix':
        raise OCIError('physical OCI directory reader requires qualified POSIX support')
    path = Path(path).absolute()
    if '..' in path.parts:
        raise OCIError('OCI root escapes selection')
    handles = [os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)]
    try:
        for part in path.parts[1:]:
            handles.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=handles[-1]))
        return handles
    except OSError as exc:
        for descriptor in reversed(handles):
            os.close(descriptor)
        raise OCIError('OCI directory is not physically bound') from exc


def verify_directory_chain(path, handles):
    current = open_directory_chain(path)
    try:
        if [identity(os.fstat(fd))[:2] for fd in current] != [identity(os.fstat(fd))[:2] for fd in handles]:
            raise OCIError('OCI original directory ancestor chain changed')
    finally:
        for fd in reversed(current):
            os.close(fd)


def open_directory(path):
    handles = open_directory_chain(path)
    for descriptor in handles[:-1]:
        os.close(descriptor)
    return handles[-1]


def read_owned_file(root, relative, maximum=ARTIFACT_BYTES, *, budget=None):
    """Return bytes plus physical identities, with no followed parent/leaf link."""
    safe_name(relative)
    budget = budget or Budget()
    descriptor = None
    root_handles, parent_handles = [], []
    try:
        root_handles = open_directory_chain(root)
        root_descriptor = root_handles[-1]
        root_identity = identity(os.fstat(root_descriptor))
        parts = relative.split('/')
        parent_path = Path(root).joinpath(*parts[:-1])
        parent_handles = open_directory_chain(parent_path)
        parent = parent_handles[-1]
        verify_directory_chain(root, root_handles)
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= maximum:
            raise OCIError('OCI retained file is not bounded/regular')
        chunks, count = [], 0
        while True:
            budget.check()
            raw = os.read(descriptor, min(65536, maximum - count + 1))
            if not raw:
                break
            count += len(raw)
            if count > maximum:
                raise OCIError('OCI retained file grew beyond bound')
            chunks.append(raw)
        if (count != before.st_size or identity(before) != identity(os.fstat(descriptor))
                or identity(before) != identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))
                or identity(os.fstat(root_descriptor)) != root_identity):
            raise OCIError('OCI retained file changed during read')
        verify_directory_chain(root, root_handles)
        verify_directory_chain(parent_path, parent_handles)
        return b''.join(chunks), identity(before)
    except OSError as exc:
        raise OCIError('OCI retained file identity unavailable') from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for fd in reversed(parent_handles + root_handles):
            os.close(fd)


def read_directory(path, reference, platform, *, budget=None, validate=True):
    budget = budget or Budget()
    handles, directories = [], {}
    try:
        handles = open_directory_chain(path)
        descriptor = handles[-1]
        root_identity = identity(os.fstat(descriptor))
        objects, identities = {}, {'.': root_identity}
        def walk(parent, prefix='', depth=0):
            if depth > 3:
                raise OCIError('unexpected OCI directory depth')
            for name in sorted(os.listdir(parent)):
                budget.check()
                relative = safe_name(prefix + name)
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                child = os.open(name, flags | (os.O_DIRECTORY if stat.S_ISDIR(named.st_mode) else 0), dir_fd=parent)
                try:
                    before = os.fstat(child)
                    if identity(before) != identity(named):
                        raise OCIError('OCI object replaced before read')
                    identities[relative] = identity(before)
                    if stat.S_ISDIR(before.st_mode):
                        if relative not in {'blobs', 'blobs/sha256'}:
                            raise OCIError('unreferenced OCI directory')
                        directories[relative] = os.dup(child)
                        walk(child, relative + '/', depth + 1)
                    else:
                        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > ARTIFACT_BYTES:
                            raise OCIError('OCI object is not a bounded owned regular file')
                        if sum(map(len, objects.values())) + before.st_size > ARTIFACT_BYTES or len(objects) >= MEMBERS:
                            raise OCIError('OCI directory object set exceeds bound')
                        chunks, remaining = [], before.st_size + 1
                        while remaining:
                            budget.check()
                            raw = os.read(child, min(65536, remaining))
                            if not raw:
                                break
                            chunks.append(raw)
                            remaining -= len(raw)
                        body = b''.join(chunks)
                        if len(body) != before.st_size:
                            raise OCIError('OCI object changed length')
                        objects[relative] = body
                    if identity(os.fstat(child)) != identity(before) or identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(before):
                        raise OCIError('OCI object identity changed during read')
                finally:
                    os.close(child)
        walk(descriptor)
        if identity(os.fstat(descriptor)) != root_identity:
            raise OCIError('OCI directory changed during read')
        # Exact-byte reacquisition need not decompress an already validated graph.
        # Raw snapshots deliberately contain no semantic/config validation result.
        result = validate_layout(objects, reference, platform, budget=budget) if validate else {'objects': objects}
        verify_directory_chain(path, handles)
        for name, held in directories.items():
            current = open_directory(Path(path) / name)
            try:
                if identity(os.fstat(current)) != identities[name] or identity(os.fstat(held)) != identities[name]:
                    raise OCIError('OCI original object ancestor changed')
            finally:
                os.close(current)
        result['identities'] = identities
        return result
    except OSError as exc:
        raise OCIError('OCI physical object read refused') from exc
    finally:
        for fd in reversed([*handles, *directories.values()]):
            os.close(fd)
