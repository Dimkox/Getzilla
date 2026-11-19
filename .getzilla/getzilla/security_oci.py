"""Bounded local OCI image inputs. No registry, daemon, extraction or execution.

OCI and standard Docker2 graph bytes retain their original media and digests.
Only OCI tar/gzip and Docker2 gzip layers are supported; foreign layers refuse.
Selected index graphs must be locally complete. A private singleton layout
prevents the pinned scanner's nested-index first-child selection behavior.
The private staging directory is a trusted workflow boundary, not isolation
from a hostile process with the same operating-system identity.
"""
from contextlib import contextmanager, nullcontext
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import sys
import tarfile
import tempfile
import time

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
TAR = 'application/vnd.oci.image.layer.v1.tar'
GZIP = TAR + '+gzip'
DOCKER_INDEX = 'application/vnd.docker.distribution.manifest.list.v2+json'
DOCKER_MANIFEST = 'application/vnd.docker.distribution.manifest.v2+json'
DOCKER_CONFIG = 'application/vnd.docker.container.image.v1+json'
DOCKER_GZIP = 'application/vnd.docker.image.rootfs.diff.tar.gzip'
INDEX_MEDIA = frozenset({INDEX, DOCKER_INDEX})
MANIFEST_MEDIA = frozenset({MANIFEST, DOCKER_MANIFEST})
LAYER_MEDIA = frozenset({TAR, GZIP, DOCKER_GZIP})
OPAQUE_ATTESTATION = 'application/vnd.in-toto+json'
LIMITS = {'max_images': 512, 'max_compressed_bytes': 512 * 1024 * 1024,
          'max_unpacked_bytes': 512 * 1024 * 1024, 'max_storage_bytes': 512 * 1024 * 1024,
          'max_manifest_bytes': 16 * 1024 * 1024, 'max_layers': 10000, 'deadline_seconds': 900}
CI_BYTES = 8 * 1024 ** 3
CI_MEMORY = 12 * 1024 ** 3
_MAX_TAR_ENTRIES = 100000


def active_limits():
    """JSON is a declaration; only the existing measured native job raises bounds."""
    limits = dict(LIMITS)
    native = sys.modules.get(__package__ + '.security_image_backend')
    if native is not None and native.measured_ci_profile():
        for key in ('max_compressed_bytes', 'max_unpacked_bytes', 'max_storage_bytes'):
            limits[key] = CI_BYTES
    return limits

HEX = re.compile(r'sha256:[0-9a-f]{64}\Z')
REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}\Z')
_PROOF = object()
_LAYER_FACT_SEAL = object()
_LAYER_CACHE_MAX = 1024


class OCIError(ValueError):
    """Fixed local diagnostics contain no raw image/config/private path values."""
    def __init__(self, *args, detail=None):
        super().__init__(*args)
        self.detail = _bound_detail(detail) if detail is not None else {}


_BOUND_LIMITS = {'compressed': 'max_compressed_bytes', 'unpacked': 'max_unpacked_bytes',
                 'storage': 'max_storage_bytes', 'layers': 'max_layers',
                 'expanded': 'max_unpacked_bytes', 'entries': 'max_tar_entries'}
_BOUND_PHASES = {'compressed': {'budget-charge', 'layout-json', 'blob-compressed', 'member-read', 'component-read'},
                 'unpacked': {'budget-charge', 'layer-decoded', 'attestation-bytes', 'layer-cached-unpacked'},
                 'storage': {'budget-charge', 'blob-storage', 'scanner-entrypoint'},
                 'layers': {'budget-charge', 'layer-count', 'attestation-count'},
                 'entries': {'budget-charge', 'tar-entries'},
                 'expanded': {'budget-charge', 'tar-expanded', 'layer-cached-expanded'}}
_BOUND_KEYS = {'dimension', 'oci_phase', 'limit_name', 'before', 'charge', 'attempted', 'limit',
               'profile_compressed', 'profile_unpacked', 'profile_storage', 'image_ordinal'}


def _bound_detail(value):
    """Validate refusal-only observations; these fields grant no profile authority."""
    if type(value) is not dict or set(value) != _BOUND_KEYS:
        raise OCIError('Invalid OCI bound diagnostic')
    dimension = value['dimension']
    if (type(dimension) is not str or dimension not in _BOUND_LIMITS
            or type(value['oci_phase']) is not str or value['oci_phase'] not in _BOUND_PHASES[dimension]
            or type(value['limit_name']) is not str or value['limit_name'] != _BOUND_LIMITS[dimension]):
        raise OCIError('Invalid OCI bound diagnostic')
    numbers = ('before', 'charge', 'attempted', 'limit', 'profile_compressed', 'profile_unpacked', 'profile_storage')
    if (any(type(value[key]) is not int or not 0 <= value[key] < 2 ** 63 for key in numbers)
            or any(not 0 < value[key] <= CI_BYTES for key in numbers[4:])
            or type(value['image_ordinal']) is not int or not -1 <= value['image_ordinal'] < 512
            or not 0 <= value['before'] <= value['limit'] < value['attempted']
            or value['before'] + value['charge'] != value['attempted']):
        raise OCIError('Invalid OCI bound diagnostic')
    expected = (value['profile_' + ('unpacked' if dimension == 'expanded' else dimension)]
                if dimension in {'compressed', 'unpacked', 'storage', 'expanded'} else
                _MAX_TAR_ENTRIES if dimension == 'entries' else value['limit'])
    if value['limit'] != expected or not 0 < value['limit'] <= (10000 if dimension == 'layers' else 2 ** 63 - 1):
        raise OCIError('Invalid OCI bound diagnostic')
    return dict(value)


def bound_fault(error):
    if type(error) is not OCIError:
        return {}
    try:
        return _bound_detail(error.detail)
    except (OCIError, AttributeError, TypeError):
        return {}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise OCIError('Duplicate OCI JSON key')
        result[key] = value
    return result


def document(raw):
    try:
        result = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(OCIError('Nonfinite OCI JSON')))
        if not isinstance(result, dict):
            raise OCIError('OCI object required')
        return result
    except (UnicodeError, ValueError, RecursionError):
        raise OCIError('Invalid OCI JSON') from None


def _profile(profile):
    ceiling = active_limits()
    if (not isinstance(profile, dict) or set(profile) != set(LIMITS) | {'images', 'platform'}
            or profile['platform'] not in {'linux/amd64', 'linux/arm64'}
            or any(type(profile[k]) is not int or not 0 < profile[k] <= n for k, n in ceiling.items())):
        raise OCIError('Unsupported or oversized OCI profile')


class _Budget:
    def __init__(self, profile):
        _profile(profile)
        self.profile = profile
        self._native = None
        self._guard = None
        if any(profile[key] > LIMITS[key] for key in LIMITS):
            self._native = sys.modules[__package__ + '.security_image_backend']
            self._guard = self._native._GUARD
        self.image_ordinal = -1
        self._layer_facts = {}
        self._component_proof_bytes = 0
        self.deadline = time.monotonic() + profile['deadline_seconds']
        self.totals = dict(compressed=0, unpacked=0, storage=0, layers=0, entries=0, expanded=0)

    def tick(self):
        if self._native is not None and self._native._GUARD is not self._guard:
            raise OCIError('CI image profile lifetime ended')
        if time.monotonic() >= self.deadline:
            raise OCIError('OCI deadline exceeded')

    def charge(self, key, size, *, phase='budget-charge'):
        self.tick()
        limit = {'compressed': 'max_compressed_bytes', 'unpacked': 'max_unpacked_bytes',
                 'storage': 'max_storage_bytes', 'layers': 'max_layers', 'expanded': 'max_unpacked_bytes'}.get(key)
        ceiling = self.profile[limit] if limit else _MAX_TAR_ENTRIES
        if type(size) is not int or size < 0:
            raise OCIError('Aggregate OCI resource bound exceeded')
        if self.totals[key] + size > ceiling:
            detail = dict(dimension=key, oci_phase=phase, limit_name=_BOUND_LIMITS[key],
                          before=self.totals[key], charge=size, attempted=self.totals[key] + size, limit=ceiling,
                          profile_compressed=self.profile['max_compressed_bytes'],
                          profile_unpacked=self.profile['max_unpacked_bytes'],
                          profile_storage=self.profile['max_storage_bytes'], image_ordinal=self.image_ordinal)
            try:
                detail = _bound_detail(detail)
            except OCIError:
                raise OCIError('Aggregate OCI resource bound exceeded') from None
            raise OCIError(f'Aggregate OCI resource bound exceeded: {key} {detail["attempted"]}>{ceiling} ({phase})',
                           detail=detail)
        self.totals[key] += size


class _Root:
    def __init__(self, path):
        path = Path(path)
        if path.anchor != '/' or '..' in path.parts:
            raise OCIError('OCI layout path must be absolute and normalized')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open('/', flags)
        try:
            for name in path.parts[1:]:
                child = os.open(name, flags, dir_fd=fd)
                os.close(fd)
                fd = child
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd

    def close(self):
        os.close(self.fd)

    @contextmanager
    def file(self, relative, maximum):
        parts = PurePosixPath(relative).parts
        if not parts or relative.startswith('/') or any(p in {'.', '..'} for p in parts):
            raise OCIError('Unsafe OCI member path')
        fd = os.dup(self.fd)
        try:
            for name in parts[:-1]:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(leaf, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                    raise OCIError('OCI input is not a bounded regular file')
                yield stream, before.st_size
                after = os.fstat(stream.fileno())
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise OCIError('OCI input changed during read')
        finally:
            os.close(fd)

    def json(self, name, budget):
        with self.file(name, budget.profile['max_manifest_bytes']) as (stream, _):
            raw = stream.read(budget.profile['max_manifest_bytes'] + 1)
        budget.charge('compressed', len(raw), phase='layout-json')
        if len(raw) > budget.profile['max_manifest_bytes']:
            raise OCIError('OCI metadata exceeds bound')
        return document(raw)


class _Decoded:
    def __init__(self, stream, budget):
        self.stream, self.budget = stream, budget
        self.digest = hashlib.sha256()
        self.bytes = 0

    def read(self, size=-1):
        # tarfile streaming requests are bounded; never accept an unbounded read.
        size = 65536 if size < 0 else min(size, 65536)
        value = self.stream.read(size)
        self.budget.charge('unpacked', len(value), phase='layer-decoded')
        self.bytes += len(value)
        self.digest.update(value)
        return value


def _layer(path, media, expected, budget):
    budget.charge('layers', 1, phase='layer-count')
    if media not in LAYER_MEDIA or not isinstance(expected, str) or not HEX.fullmatch(expected):
        raise OCIError('Unsupported OCI layer or diff ID')
    path = Path(path)
    source = _Root(path.parent)
    complete = None
    try:
        # This descriptor stays open for BOTH fresh content hashing and miss
        # parsing. _Root.file checks the same regular FD's identity afterward.
        with source.file(path.name, budget.profile['max_storage_bytes']) as (raw, size):
            digest, total = hashlib.sha256(), 0
            while True:
                budget.tick()
                chunk = raw.read(min(65536, size - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > size:
                    raise OCIError('OCI layer changed during content hashing')
                digest.update(chunk)
            if total != size:
                raise OCIError('OCI layer changed during content hashing')
            key = (digest.hexdigest(), size, media, expected)
            fact = budget._layer_facts.get(key)
            valid = (type(fact) is tuple and len(fact) == 5 and fact[0] is _LAYER_FACT_SEAL
                     and fact[1] == key and all(type(n) is int and n >= 0 for n in fact[2:])
                     and fact[2] <= budget.profile['max_unpacked_bytes']
                     and fact[3] <= budget.profile['max_unpacked_bytes'] and fact[4] <= _MAX_TAR_ENTRIES)
            if valid:
                # No gzip/TAR parser runs here. Preserve conservative byte
                # weights and every layer occurrence; only NEW headers count.
                budget.charge('unpacked', fact[2], phase='layer-cached-unpacked')
                budget.charge('expanded', fact[3], phase='layer-cached-expanded')
            else:
                budget._layer_facts.pop(key, None)
                raw.seek(0)
                unpacked, expanded, entries = _parse_layer(raw, media, expected, budget)
                complete = (_LAYER_FACT_SEAL, key, unpacked, expanded, entries)
    finally:
        source.close()
    # Insert only AFTER the held FD's final identity/stability check succeeds.
    # A full cache is just an uncached parse, never truncated validation.
    if complete is not None and len(budget._layer_facts) < _LAYER_CACHE_MAX:
        budget._layer_facts[key] = complete


def _parse_layer(raw, media, expected, budget, *, visit=None):
    declared, entries = 0, 0
    with (gzip.GzipFile(fileobj=raw) if media in {GZIP, DOCKER_GZIP} else nullcontext(raw)) as decoded:
        stream = _Decoded(decoded, budget)
        with tarfile.open(fileobj=stream, mode='r|') as archive:
            for member in archive:
                entries += 1
                budget.charge('entries', 1, phase='tar-entries')
                name = member.name
                if (not name or len(name) > 4096 or '\\' in name or name.startswith('/')
                        or '..' in PurePosixPath(name).parts
                        or member.sparse is not None
                        or not (member.isfile() or member.isdir() or member.issym() or member.islnk())):
                    raise OCIError('Unsupported or unsafe OCI layer member')
                if member.issym() or member.islnk():
                    target = member.linkname
                    joined = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                    if (not target or '\\' in target or len(target) > 4096 or joined == '..'
                            or joined.startswith('../') or member.islnk() and target.startswith('/')):
                        raise OCIError('OCI link escapes image root')
                if member.size < 0 or declared + member.size > budget.profile['max_unpacked_bytes']:
                    raise OCIError('OCI logical layer size exceeds bound')
                budget.charge('expanded', member.size, phase='tar-expanded')
                declared += member.size
                if visit is not None:
                    visit(member, archive)
        while stream.read(65536):
            pass
        if 'sha256:' + stream.digest.hexdigest() != expected:
            raise OCIError('OCI uncompressed layer digest differs')
    return stream.bytes, declared, entries


class VerifiedOCIImage:
    __slots__ = ('reference', 'platform', 'layout', 'manifest_digest', 'config_digest', '_proof', '_files', '_budget')

    def __init__(self, reference, platform, layout, manifest_digest, config_digest, proof, budget, files):
        if proof is not _PROOF:
            raise OCIError('Verified OCI identity requires import')
        self.reference, self.platform, self.layout = reference, platform, layout
        self.manifest_digest, self.config_digest = manifest_digest, config_digest
        self._proof = proof
        self._budget = budget
        self._files = files

    def remaining_seconds(self):
        if self._proof is not _PROOF:
            raise OCIError('OCI import lifetime ended')
        self._budget.tick()
        return self._budget.deadline - time.monotonic()


def read_members(image, paths, *, member_limit=2 * 1024 * 1024, total_limit=16 * 1024 * 1024):
    """Read only requested regular installation evidence from a live verified image.

    No root filesystem is extracted. Selected links refuse instead of resolving
    arbitrary image paths. Every additional layer read retains the same ledger.
    """
    if (type(image) is not VerifiedOCIImage or image._proof is not _PROOF
            or type(paths) is not list or not 1 <= len(paths) <= 1024
            or any(type(p) is not str or not p or p.startswith('/') or '\\' in p
                   or any(v in {'', '.', '..'} for v in p.split('/')) for p in paths)
            or len(set(paths)) != len(paths)
            or type(member_limit) is not int or not 0 < member_limit <= 2 * 1024 * 1024
            or type(total_limit) is not int or not 0 < total_limit <= 16 * 1024 * 1024):
        raise OCIError('Invalid requested OCI installation evidence')
    image._budget.tick()
    selected, retained = {}, 0
    root = _Root(image.layout)
    @contextmanager
    def verified(digest):
        name = 'blobs/sha256/' + digest[7:]
        expected, size = image._files[name]
        with root.file(name, size) as (stream, actual):
            measured, count = hashlib.sha256(), 0
            while chunk := stream.read(65536):
                image._budget.tick()
                count += len(chunk)
                measured.update(chunk)
            if count != actual or actual != size or measured.hexdigest() != expected:
                raise OCIError('Verified OCI evidence blob changed')
            stream.seek(0)
            yield stream, size
    def blob(digest):
        with verified(digest) as (stream, size):
            if size > image._budget.profile['max_manifest_bytes']:
                raise OCIError('Requested OCI metadata exceeds bound')
            return stream.read(size + 1)
    try:
        manifest = document(blob(image.manifest_digest))
        config = document(blob(image.config_digest))
        for layer, diff in zip(manifest['layers'], config['rootfs']['diff_ids']):
            changes, removed, seen = {}, set(), set()
            def visit(member, archive):
                nonlocal retained
                name = member.name.removeprefix('./').rstrip('/')
                parent, _, leaf = name.rpartition('/')
                if leaf.startswith('.wh.'):
                    if not member.isfile() or member.size:
                        raise OCIError('Invalid OCI evidence whiteout')
                    target = parent if leaf == '.wh..wh..opq' else (parent + '/' if parent else '') + leaf[4:]
                    removed.update(p for p in paths if p == target or p.startswith(target + '/') or not target)
                    return
                relevant = [p for p in paths if p == name or p.startswith(name + '/')]
                if not relevant:
                    return
                if member.issym() or member.islnk():
                    raise OCIError('Selected OCI installation evidence has a link')
                if member.isdir():
                    return
                if name not in paths:
                    raise OCIError('Requested OCI evidence ancestor is not a directory')
                removed.update(p for p in relevant if p != name)
                if name in seen or not member.isfile() or member.size > member_limit:
                    raise OCIError('Duplicate or oversized requested OCI member')
                seen.add(name)
                retained += member.size
                if retained > total_limit:
                    raise OCIError('Requested OCI evidence exceeds aggregate bound')
                stream = archive.extractfile(member)
                body = stream.read(member_limit + 1) if stream is not None else None
                if body is None or len(body) != member.size:
                    raise OCIError('Requested OCI evidence is truncated')
                changes[name] = body
            with verified(layer['digest']) as (stream, size):
                image._budget.charge('compressed', size, phase='member-read')
                _parse_layer(stream, layer['mediaType'], diff, image._budget, visit=visit)
            for path in removed:
                selected.pop(path, None)
            selected.update(changes)
        if set(selected) != set(paths):
            raise OCIError('Requested OCI installation evidence is missing')
        image._budget.tick()
        return selected
    except (OSError, KeyError, TypeError, EOFError, tarfile.TarError, gzip.BadGzipFile):
        raise OCIError('Requested OCI installation evidence unavailable') from None
    finally:
        root.close()


def observe_final_files(image, retain):
    """Visit final installed files in a LIVE graph; retain only bounded data.

    This is component inventory, not extraction or runtime integrity. File bodies
    are hashed while streaming, links remain image data, and historical paths
    removed by whiteouts do not become installed software. All layer reads use
    the importer's existing shared ledger and verify the retained blob anew.
    """
    if type(image) is not VerifiedOCIImage or image._proof is not _PROOF or not callable(retain):
        raise OCIError('Component observation requires a live verified OCI image')
    image._budget.tick()
    root, final, retained = _Root(image.layout), {}, 0
    @contextmanager
    def verified(digest):
        name = 'blobs/sha256/' + digest[7:]
        expected, size = image._files[name]
        with root.file(name, size) as (stream, actual):
            measured, count = hashlib.sha256(), 0
            while chunk := stream.read(65536):
                image._budget.tick()
                count += len(chunk)
                measured.update(chunk)
            if count != actual or actual != size or measured.hexdigest() != expected:
                raise OCIError('Component observation blob changed')
            stream.seek(0)
            yield stream, size
    def blob(digest):
        with verified(digest) as (stream, size):
            if size > image._budget.profile['max_manifest_bytes']:
                raise OCIError('Component observation metadata exceeds bound')
            return document(stream.read(size + 1))
    try:
        manifest, config = blob(image.manifest_digest), blob(image.config_digest)
        if len(manifest['layers']) != len(config['rootfs']['diff_ids']):
            raise OCIError('Component observation layer identity differs')
        for layer, diff in zip(manifest['layers'], config['rootfs']['diff_ids']):
            changes, removals = {}, []
            def visit(member, archive):
                nonlocal retained
                name = member.name.removeprefix('./').rstrip('/')
                parent, _, leaf = name.rpartition('/')
                if leaf.startswith('.wh.'):
                    if not member.isfile() or member.size:
                        raise OCIError('Invalid component observation whiteout')
                    target = parent if leaf == '.wh..wh..opq' else (parent + '/' if parent else '') + leaf[4:]
                    removals.append((target, leaf == '.wh..wh..opq'))
                    return
                if name in changes:
                    raise OCIError('Duplicate component observation member')
                row = dict(path=name, layer=layer['digest'], mode=member.mode, bytes=member.size)
                if member.isdir():
                    row['kind'] = 'directory'
                elif member.islnk():
                    # TAR hardlinks name an already materialized inode, not a
                    # future dynamic path alias. A later overwrite of that path
                    # must not replace this link's component/license bytes.
                    target = posixpath.normpath(member.linkname)
                    source = changes.get(target, final.get(target))
                    if target.startswith(('/', '../')) or source is None or source['kind'] != 'file':
                        raise OCIError('Unproved component hardlink target')
                    row = dict(source, path=name, layer=layer['digest'], hardlink_source=dict(
                        path=target, layer=source['layer'], sha256=source['sha256'], from_lower=target not in changes))
                elif member.issym():
                    row.update(kind='symlink', target=member.linkname)
                else:
                    row['kind'] = 'file'
                    selected, chunks, measured, count, head = bool(retain(name)), [], hashlib.sha256(), 0, b''
                    window, go_binary = b'', False
                    if selected and (member.size > 8 * 1024 * 1024 or image._budget._component_proof_bytes + member.size > 512 * 1024 * 1024):
                        raise OCIError('Component package proof exceeds bound')
                    if selected:
                        image._budget._component_proof_bytes += member.size
                    with archive.extractfile(member) as source:
                        while chunk := source.read(65536):
                            image._budget.tick()
                            measured.update(chunk)
                            count += len(chunk)
                            if len(head) < 4:
                                head = (head + chunk)[:4]
                            window = window[-16:] + chunk
                            go_binary = go_binary or b'\xff Go buildinf:' in window
                            if selected:
                                chunks.append(chunk)
                    if count != member.size:
                        raise OCIError('Component observation member truncated')
                    row.update(sha256=measured.hexdigest(), elf=head == b'\x7fELF', executable=bool(member.mode & 0o111), go_binary=go_binary)
                    if selected:
                        row['body'] = b''.join(chunks)
                        retained += count
                changes[name] = row
            with verified(layer['digest']) as (stream, size):
                image._budget.charge('compressed', size, phase='component-read')
                _parse_layer(stream, layer['mediaType'], diff, image._budget, visit=visit)
            removed_paths = {path for path, opaque in removals if not opaque}
            opaque_paths = {path for path, opaque in removals if opaque}
            for row in changes.values():
                source = row.get('hardlink_source', {})
                if source.get('from_lower'):
                    parts = source['path'].split('/')
                    ancestors = ['/'.join(parts[:i]) for i in range(1, len(parts))]
                    if ('' in opaque_paths or source['path'] in removed_paths or
                            any(p in removed_paths or p in opaque_paths for p in ancestors)):
                        raise OCIError('Whiteout removed component hardlink source before layer application')
            for path in list(final):
                image._budget.tick()
                parts = path.split('/')
                ancestors = ['/'.join(parts[:i]) for i in range(1, len(parts))]
                if ('' in opaque_paths or path in removed_paths or
                        any(p in removed_paths or p in opaque_paths for p in ancestors)):
                    final.pop(path)
            blocked = {path for path, row in changes.items() if row['kind'] != 'directory'}
            for old in list(final):
                parts = old.split('/')
                if any('/'.join(parts[:i]) in blocked for i in range(1, len(parts))):
                    final.pop(old)
            final.update(changes)
        for path in final:
            image._budget.tick()
            parts = path.split('/')
            for i in range(1, len(parts)):
                ancestor = final.get('/'.join(parts[:i]))
                if ancestor and ancestor['kind'] != 'directory':
                    raise OCIError('Component overlay has an unsupported non-directory ancestor')
        image._budget.tick()
        return final
    except (OSError, KeyError, TypeError, EOFError, tarfile.TarError, gzip.BadGzipFile):
        raise OCIError('Component observation bytes unavailable') from None
    finally:
        root.close()


def scanner_identity(report, image):
    """OCI archive scanning reports ConfigName as ID and no RepoDigests."""
    if (type(image) is not VerifiedOCIImage or image._proof is not _PROOF
            or not isinstance(report, dict) or not isinstance(report.get('Metadata'), dict)
            or report['Metadata'].get('ImageID') != image.config_digest):
        raise OCIError('Scanner OCI config identity differs from verified graph')
    # The context remains live across scanner execution. Refuse mutation of
    # every retained graph member, not just the config named in scanner JSON.
    root = _Root(image.layout)
    try:
        for name, (expected, size) in image._files.items():
            digest = hashlib.sha256()
            with root.file(name, size) as (stream, actual):
                if actual != size:
                    raise OCIError('Private OCI graph changed during scanning')
                while True:
                    image._budget.tick()
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                raise OCIError('Private OCI graph changed during scanning')
    except OSError:
        raise OCIError('Private OCI graph unavailable after scanning') from None
    finally:
        root.close()


def _platform_variant(value):
    variant = value.get('variant')
    if variant in (None, ''):
        return None
    architecture = value.get('architecture')
    allowed = {'arm': ('v6', 'v7'), 'arm64': ('v8',)}
    if (not isinstance(architecture, str) or not isinstance(variant, str)
            or variant not in allowed.get(architecture, ())):
        raise OCIError('Unsupported OCI architecture/variant combination')
    return variant


def _descriptor(value, *, opaque_attestation=False):
    if (not isinstance(value, dict) or not {'mediaType', 'digest', 'size'} <= value.keys()
            or (value['mediaType'] not in INDEX_MEDIA | MANIFEST_MEDIA | LAYER_MEDIA | {CONFIG, DOCKER_CONFIG}
                and not (opaque_attestation is True and value['mediaType'] == OPAQUE_ATTESTATION))
            or not isinstance(value['digest'], str) or not HEX.fullmatch(value['digest'])
            or type(value['size']) is not int or value['size'] < 0 or value.get('urls')
            or value.get('data') is not None):
        raise OCIError('Unsupported OCI descriptor')
    return value['mediaType'], value['digest'], value['size']


def _index_children(children):
    """Only a linked same-index legacy BuildKit role admits opaque provenance."""
    if not isinstance(children, list) or not 1 <= len(children) <= 512:
        raise OCIError('OCI nested index is incomplete or excessive')
    ordinary, attestations, digests = {}, [], set()
    for child in children:
        media, digest, _ = _descriptor(child)
        if digest in digests:
            raise OCIError('Duplicate or conflicting OCI index role')
        digests.add(digest)
        annotations = child.get('annotations', {})
        if type(annotations) is not dict or any(type(k) is not str or type(v) is not str
                                              for k, v in annotations.items()):
            raise OCIError('Unsupported OCI annotations')
        platform = child.get('platform', {})
        role = annotations.get('vnd.docker.reference.type')
        link = annotations.get('vnd.docker.reference.digest')
        if role is not None or link is not None or platform == {'os': 'unknown', 'architecture': 'unknown'}:
            if (media != MANIFEST or platform != {'os': 'unknown', 'architecture': 'unknown'}
                    or role != 'attestation-manifest' or type(link) is not str or not HEX.fullmatch(link)):
                raise OCIError('Unsupported OCI attestation role')
            attestations.append((digest, link))
        else:
            ordinary[digest] = child
    for digest, link in attestations:
        target = ordinary.get(link)
        platform = target.get('platform') if target else None
        if (link == digest or target is None or _descriptor(target)[0] not in MANIFEST_MEDIA
                or type(platform) is not dict or not all(type(platform.get(k)) is str
                    and platform[k] not in {'', 'unknown'} for k in ('os', 'architecture'))):
            raise OCIError('OCI attestation target is not one runnable sibling')
    roles = {digest for digest, _ in attestations}
    return [(child, child['digest'] in roles) for child in children]


def _import_one(record, profile, stage, budget):
    source = _Root(record['layout'])
    try:
        if source.json('oci-layout', budget) != {'imageLayoutVersion': '1.0.0'}:
            raise OCIError('Unsupported OCI layout version')
        index = source.json('index.json', budget)
        if index.get('schemaVersion') != 2 or not isinstance(index.get('manifests'), list):
            raise OCIError('OCI index entrypoint missing')
        root_digest = record['reference'].rsplit('@', 1)[1]
        roots = [d for d in index['manifests'] if isinstance(d, dict) and d.get('digest') == root_digest]
        if len(roots) != 1:
            raise OCIError('Selected OCI root is missing or ambiguous')
        (stage / 'blobs').mkdir(mode=0o700)
        (stage / 'blobs/sha256').mkdir(mode=0o700)
        seen, active, candidates, roles = {}, set(), [], {}

        def blob(desc, *, opaque=False):
            media, digest, size = _descriptor(desc, opaque_attestation=opaque)
            old = seen.get(digest)
            if old is not None:
                if old != (media, size):
                    raise OCIError('Conflicting OCI descriptor identity')
                return stage / 'blobs/sha256' / digest[7:]
            if size > profile['max_storage_bytes'] or media not in LAYER_MEDIA and size > profile['max_manifest_bytes']:
                raise OCIError('OCI descriptor exceeds selected bound')
            budget.charge('storage', size, phase='blob-storage')
            budget.charge('compressed', size, phase='blob-compressed')
            destination = stage / 'blobs/sha256' / digest[7:]
            measured = hashlib.sha256()
            with source.file('blobs/sha256/' + digest[7:], size) as (stream, actual):
                if actual != size:
                    raise OCIError('OCI descriptor size differs')
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    total = 0
                    while True:
                        budget.tick()
                        chunk = stream.read(min(65536, size - total + 1))
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > size:
                            raise OCIError('OCI blob exceeds descriptor size')
                        measured.update(chunk)
                        output.write(chunk)
            if total != size or 'sha256:' + measured.hexdigest() != digest:
                raise OCIError('OCI descriptor digest differs')
            seen[digest] = (media, size)
            return destination

        def walk(desc, depth=0, *, attestation=False):
            budget.tick()
            media, digest, _ = _descriptor(desc)
            role = ('attestation', attestation) if attestation else ('ordinary', None)
            if digest in roles and roles[digest] != role:
                raise OCIError('Conflicting OCI graph roles')
            roles[digest] = role
            if depth > 32 or len(seen) > 10000 or digest in active:
                raise OCIError('OCI graph depth, nodes or cycle unsupported')
            path = blob(desc)
            if media not in INDEX_MEDIA | MANIFEST_MEDIA:
                raise OCIError('OCI entry is not an image/index')
            active.add(digest)
            value = document(path.read_bytes())
            if value.get('schemaVersion') != 2 or value.get('mediaType', media) != media or value.get('subject') or value.get('artifactType'):
                raise OCIError('Unsupported OCI image document')
            if media in INDEX_MEDIA:
                children = value.get('manifests')
                for child, child_attestation in _index_children(children):
                    walk(child, depth + 1, attestation=child['annotations']['vnd.docker.reference.digest'] if child_attestation else False)
            else:
                config_desc = value.get('config')
                if _descriptor(config_desc)[0] != (CONFIG if media == MANIFEST else DOCKER_CONFIG):
                    raise OCIError('OCI image config is unsupported')
                config_path = blob(config_desc)
                config = document(config_path.read_bytes())
                config_variant = _platform_variant(config)
                platform = config.get('os', '') + '/' + config.get('architecture', '')
                claim = desc.get('platform')
                if claim is not None and (not isinstance(claim, dict)
                        or claim.get('os', '') + '/' + claim.get('architecture', '') != platform
                        or claim.get('os.features') or claim.get('features')):
                    raise OCIError('OCI descriptor/config platform differs')
                if claim is not None:
                    claim_variant = _platform_variant(claim)
                    if config_variant is not None and config_variant != claim_variant:
                        raise OCIError('OCI descriptor/config variant differs')
                layers = value.get('layers')
                rootfs = config.get('rootfs')
                if (not isinstance(layers, list) or not layers or not isinstance(rootfs, dict)
                        or rootfs.get('type') != 'layers' or not isinstance(rootfs.get('diff_ids'), list)
                        or len(rootfs['diff_ids']) != len(layers)):
                    raise OCIError('OCI rootfs/layer accounting missing')
                if attestation and (platform != 'unknown/unknown' or config.get('config') != {}
                        or set(config) != {'architecture', 'os', 'config', 'rootfs'}
                        or any(key in value for key in ('subject', 'artifactType'))):
                    raise OCIError('Unsupported OCI attestation configuration')
                for layer, diff_id in zip(layers, rootfs['diff_ids']):
                    if attestation:
                        layer_media, layer_digest, layer_size = _descriptor(layer, opaque_attestation=True)
                        if layer_media != OPAQUE_ATTESTATION or diff_id != layer_digest:
                            raise OCIError('Opaque OCI attestation digest accounting differs')
                        blob(layer, opaque=True)
                        budget.charge('layers', 1, phase='attestation-count')
                        budget.charge('unpacked', layer_size, phase='attestation-bytes')
                        continue
                    layer_media = _descriptor(layer)[0]
                    allowed_layers = {TAR, GZIP} if media == MANIFEST else {DOCKER_GZIP}
                    if layer_media not in allowed_layers or not isinstance(diff_id, str) or not HEX.fullmatch(diff_id):
                        raise OCIError('Unsupported OCI layer or diff ID')
                    _layer(blob(layer), layer_media, diff_id, budget)
                if not attestation and platform == profile['platform']:
                    candidates.append((desc, config_desc['digest']))
            active.remove(digest)

        walk(roots[0])
        if len(candidates) != 1:
            raise OCIError('Selected OCI platform is missing or ambiguous')
        manifest, config_digest = candidates[0]
        # Drop annotations, subjects, extra indexes and alternate manifests from
        # the scanner entrypoint. Only this verified selected graph is reachable.
        descriptor = {k: manifest[k] for k in ('mediaType', 'digest', 'size')}
        descriptor['platform'] = dict(zip(('os', 'architecture'), profile['platform'].split('/')))
        files = {'blobs/sha256/' + digest[7:]: (digest[7:], size) for digest, (_media, size) in seen.items()}
        for name, value in (('oci-layout', {'imageLayoutVersion': '1.0.0'}),
                            ('index.json', {'schemaVersion': 2, 'mediaType': INDEX, 'manifests': [descriptor]})):
            raw = canonical(value)
            budget.charge('storage', len(raw), phase='scanner-entrypoint')
            fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
            files[name] = (hashlib.sha256(raw).hexdigest(), len(raw))
        return VerifiedOCIImage(record['reference'], profile['platform'], stage,
                                descriptor['digest'], config_digest, _PROOF, budget, files)
    finally:
        source.close()


def source_bindings(catalog):
    """Explicit source-use selections; no assertion about registry/deployment state."""
    if catalog is None or 'source_bindings' not in catalog:
        return None
    rows = catalog['source_bindings']
    if not isinstance(rows, list) or not 1 <= len(rows) <= 512:
        raise OCIError('Image source-use selection count is unavailable or excessive')
    records = catalog.get('records')
    if not isinstance(records, list):
        raise OCIError('Selected OCI artifacts are unavailable')
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {'manifest', 'line', 'source_sha256',
                'source_reference', 'reference', 'platform'}
                or not any(isinstance(record, dict) and record.get('reference') == row['reference']
                           and record.get('platform') == row['platform'] for record in records)):
            raise OCIError('Source use has no corresponding selected OCI artifact')
    return rows


def _selection(catalog, inventory, profile):
    """Bind an explicit catalog to every current immutable source image use."""
    _profile(profile)
    references = profile['images']
    if (not isinstance(inventory, dict) or not isinstance(catalog, dict)
            or set(catalog) - {'source_catalog_sha256'} not in ({'schema_version', 'inventory_sha256', 'records'},
                                   {'schema_version', 'inventory_sha256', 'records', 'source_bindings'})
            or ('source_catalog_sha256' in catalog and (not isinstance(catalog['source_catalog_sha256'], str)
                or re.fullmatch('[0-9a-f]{64}', catalog['source_catalog_sha256']) is None))
            or type(catalog['schema_version']) is not int or catalog['schema_version'] != 1
            or inventory.get('complete') is not True or inventory.get('gaps') != []
            or not isinstance(inventory.get('digest'), str)
            or not re.fullmatch('[0-9a-f]{64}', inventory['digest'])
            or catalog['inventory_sha256'] != inventory['digest']
            or not isinstance(references, list) or not references or len(references) > profile['max_images']
            or len(set(references)) != len(references)
            or any(not isinstance(v, str) or not REFERENCE.fullmatch(v) for v in references)
            or not isinstance(inventory.get('images'), list) or len(inventory['images']) > 512
            or set(references) != {v['reference'] for v in inventory['images']}
            or any(v.get('platform') != profile['platform'] for v in inventory['images'])
            or not isinstance(catalog['records'], list) or len(catalog['records']) != len(references)):
        raise OCIError('OCI catalog differs from complete immutable inventory/profile')
    records = catalog['records']
    if (any(not isinstance(r, dict) or set(r) != {'reference', 'platform', 'layout'}
            or r['platform'] != profile['platform'] or not isinstance(r['layout'], str)
            or Path(r['layout']).anchor != '/' or '..' in Path(r['layout']).parts for r in records)
            or {r['reference'] for r in records} != set(references)):
        raise OCIError('OCI selected artifact records differ')
    for binding in source_bindings(catalog) or []:
        if not any(all(item.get(key) == binding[key] for key in ('manifest', 'line', 'source_sha256',
                'source_reference', 'reference', 'platform'))
                and item.get('source_selection_sha256') == hashlib.sha256(canonical(binding)).hexdigest()
                for item in inventory['images']):
            raise OCIError('Selected source use differs from current inventory')
    return records


def validate_selection(catalog, inventory, profile):
    try:
        return _selection(catalog, inventory, profile)
    except (KeyError, TypeError, AttributeError):
        raise OCIError('Malformed OCI inventory/profile/catalog') from None


@contextmanager
def import_layouts(catalog, inventory, profile, workspace, *, _budget=None):
    """Import every selected image under ONE shared aggregate ledger.

    All returned paths exist only during this context. Inputs are revalidated
    per consumption; a retained JSON declaration never grants scan credit.
    """
    if _budget is not None and (type(_budget) is not _Budget or any(
            _budget.profile[key] != profile[key] for key in (*LIMITS, 'platform'))):
        raise OCIError('Shared OCI ledger differs from selected profile')
    budget = _Budget(profile) if _budget is None else _budget
    if budget._guard is not None:
        # The caller's tools/scratch directory can be outside the namespace
        # volume. CI image copies must share the measured physical store.
        workspace = budget._guard[0]
    try:
        records = validate_selection(catalog, inventory, profile)
        with tempfile.TemporaryDirectory(prefix='verified-oci-', dir=workspace) as owned:
            images = []
            for index, record in enumerate(sorted(records, key=lambda r: r['reference'])):
                budget.image_ordinal = index
                stage = Path(owned) / str(index)
                stage.mkdir(mode=0o700)
                image = _import_one(record, profile, stage, budget)
                wanted = {v.get('image_id') for v in inventory['images'] if v['reference'] == image.reference}
                if any(value is not None and value != image.config_digest for value in wanted):
                    raise OCIError('Selected source config pin differs from OCI graph')
                images.append(image)
            try:
                yield images
                budget.tick()
            finally:
                for image in images:
                    image._proof = None
    except (OSError, KeyError, TypeError, AttributeError, EOFError, tarfile.TarError):
        raise OCIError('Local OCI input unavailable, malformed or unsafe') from None
    finally:
        budget._layer_facts.clear()
