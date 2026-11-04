"""Read bounded package artifacts and saved registry evidence without extraction.

These checks establish internal consistency of caller-selected artifact bytes.
Publisher identity and execution provenance remain external-runner obligations.
"""
from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import stat
import struct
import tarfile
import zipfile
import zlib
from email import policy as email_policy
from email.parser import Parser
from pathlib import Path, PurePosixPath
from urllib.parse import quote, unquote, urlsplit

from . import manifest as file_manifest
from .security_osv_snapshot import VulnerabilityError, _pypi_key, _semver_key, normalize_name
from .security_data import _json

MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 10000


class ArtifactError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def safe_parts(relative: str) -> tuple[str, ...]:
    if (not isinstance(relative, str) or not relative or len(relative) > 1024 or '\\' in relative or ':' in relative
            or any(ord(character) < 32 for character in relative)):
        raise ArtifactError('artifact-path', 'artifact path must be a bounded relative POSIX path')
    path = PurePosixPath(relative)
    if path.is_absolute() or len(path.parts) > 32 or any(part in {'', '.', '..'} for part in relative.split('/')):
        raise ArtifactError('artifact-path', 'artifact path escapes its selected directory')
    return path.parts


def read_file(root: Path, relative: str, maximum: int) -> bytes:
    """Bind each directory without following links; read one bounded regular file."""
    parts = safe_parts(relative)
    root_descriptor = None
    descriptor = None
    try:
        _, root_descriptor = file_manifest._open_root(root)
        if isinstance(root_descriptor, str):
            descriptor = file_manifest._open_regular_at(root_descriptor, parts, relative)
        else:
            parent = os.dup(root_descriptor)
            try:
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    os.close(parent)
                    parent = child
                descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
            finally:
                os.close(parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ArtifactError('artifact-size', 'artifact evidence is not a bounded regular file')
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if file_manifest._identity(before) != file_manifest._identity(after) or remaining == 0:
            raise ArtifactError('artifact-changed', 'artifact evidence changed during its bounded read')
        return b''.join(chunks)
    except (OSError, file_manifest.ManifestError) as exc:
        raise ArtifactError('artifact-path', f'cannot read artifact evidence safely: {relative}') from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if isinstance(root_descriptor, int):
            os.close(root_descriptor)


def package_key(ecosystem: str, name: str, version: str) -> tuple:
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9@][A-Za-z0-9._/@-]{0,199}', name):
        raise ArtifactError('artifact-identity', 'package name is missing or unsupported')
    try:
        if ecosystem == 'PyPI':
            if '/' in name or '@' in name:
                raise ArtifactError('artifact-identity', 'invalid PyPI package name')
            return ecosystem, normalize_name(ecosystem, name), _pypi_key(version)
        if ecosystem == 'npm':
            return ecosystem, name.lower(), _semver_key(version)
    except VulnerabilityError as exc:
        raise ArtifactError('artifact-identity', str(exc)) from exc
    raise ArtifactError('license-ecosystem-coverage', f'artifact license metadata is unsupported for {ecosystem}')


def artifact_context(dependency: dict) -> dict:
    """Keep installed uses and named outputs separate even for identical wheel bytes."""
    result = {}
    for field in ('manifest', 'usage', 'distribution', 'delivery_context', 'delivery_kind'):
        if field in dependency:
            value = dependency[field]
            if not isinstance(value, str) or not value or len(value) > 1024 or any(ord(c) < 32 for c in value):
                raise ArtifactError('artifact-context', 'artifact use context is malformed')
            result[field] = value
    if 'delivery_kind' in result and result['delivery_kind'] not in {
            'installed-package', 'unchanged-artifact', 'factory-offline-archive'}:
        raise ArtifactError('license-delivery-target', 'delivery kind has no qualified adapter')
    if 'delivery_kind' in result and 'delivery_context' not in result:
        raise ArtifactError('artifact-context', 'delivery kind requires a named use/output context')
    return result


def artifact_identity(record: dict) -> str:
    """Exact artifact/source/context identity, independent of cache location."""
    package_key(record.get('ecosystem'), record.get('name'), record.get('version'))
    if len(safe_parts(record.get('filename'))) != 1:
        raise ArtifactError('artifact-identity', 'artifact filename must be a basename')
    _digest(record.get('sha256'), 'artifact')
    context = record.get('context', {})
    if not isinstance(context, dict) or artifact_context(context) != context:
        raise ArtifactError('artifact-context', 'artifact record context is malformed')
    origin = record.get('origin')
    if not isinstance(origin, dict):
        raise ArtifactError('artifact-origin', 'artifact has no exact source')
    _digest(origin.get('index_sha256'), 'index')
    if not all(isinstance(origin.get(field), str) and origin[field] for field in ('index_url', 'artifact_url')):
        raise ArtifactError('artifact-origin', 'artifact has no exact source URLs')
    value = {field: record[field] for field in ('ecosystem', 'name', 'version', 'filename', 'sha256')}
    value['context'] = context
    value['origin'] = {field: origin[field] for field in ('index_url', 'index_sha256', 'artifact_url')}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def select_artifact(dependency: dict, records: list[dict]) -> dict:
    key = package_key(dependency.get('ecosystem'), dependency.get('name'), dependency.get('version'))
    context = artifact_context(dependency)
    candidates = []
    for record in records:
        if package_key(record.get('ecosystem'), record.get('name'), record.get('version')) != key:
            continue
        if 'context' in record:
            if record['context'] != context:
                continue
        elif dependency.get('delivery_context'):
            continue  # Legacy wheel evidence cannot establish a named output/use.
        if any(dependency.get(observed) is not None and dependency[observed] != record.get(field)
               for observed, field in (('artifact_filename', 'filename'), ('artifact_sha256', 'sha256'))):
            continue
        if dependency.get('artifact_source') is not None and dependency['artifact_source'] != record.get('origin', {}).get('artifact_url'):
            continue
        candidates.append(record)
    if len(candidates) != 1:
        raise ArtifactError('license-artifact-missing', 'select exactly one artifact for this target, source and use context')
    return candidates[0]


def archive_inventory(payload: bytes, filename: str) -> dict[str, dict]:
    """Hash all ZIP members after the shared bounded, link-free archive validation."""
    if not filename.endswith(('.whl', '.zip')):
        raise ArtifactError('artifact-archive', 'extracted delivery requires ZIP member evidence')
    archive_files(payload, filename)
    result = {}
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            digest = hashlib.sha256()
            with archive.open(member) as stream:
                while chunk := stream.read(65536):
                    digest.update(chunk)
            result[member.filename] = {'sha256': digest.hexdigest(), 'size': member.file_size}
    return result


def pypi_index_url(name: str, version: str) -> str:
    package_key('PyPI', name, version)
    return f'https://pypi.org/pypi/{quote(normalize_name("PyPI", name), safe="")}/{quote(version, safe="")}/json'


def allowed_download_url(url: str) -> bool:
    if not isinstance(url, str) or len(url) > 4096:
        return False
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != 'https' or parsed.username or parsed.password or port is not None or parsed.query or parsed.fragment:
        return False
    if any(part in {'.', '..'} for part in unquote(parsed.path).split('/')) or '\\' in unquote(parsed.path):
        return False
    return (parsed.netloc == 'pypi.org' and re.fullmatch(r'/pypi/[^/]+/[^/]+/json', parsed.path) is not None
            or parsed.netloc == 'files.pythonhosted.org' and parsed.path.startswith('/packages/'))


def _digest(value, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{64}', value) is None:
        raise ArtifactError('artifact-hash', f'{label} requires a SHA-256 digest')
    return value


def verify_origin(root: Path, record: dict, payload: bytes, *, index_bytes: bytes | None = None) -> dict:
    origin = record.get('origin')
    if not isinstance(origin, dict):
        raise ArtifactError('artifact-origin', 'saved registry index evidence is missing')
    digest = _digest(record.get('sha256'), 'artifact')
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ArtifactError('artifact-hash', 'artifact bytes do not match the selected SHA-256')
    index_digest = _digest(origin.get('index_sha256'), 'registry index')
    if index_bytes is None:
        index_bytes = read_file(root, origin.get('index_path'), MAX_INDEX_BYTES)
    if not isinstance(index_bytes, bytes) or len(index_bytes) > MAX_INDEX_BYTES:
        raise ArtifactError('artifact-origin', 'saved registry index exceeds its byte budget')
    if hashlib.sha256(index_bytes).hexdigest() != index_digest:
        raise ArtifactError('artifact-origin', 'saved registry index SHA-256 mismatch')
    index = _json(index_bytes)
    ecosystem, name, version = record.get('ecosystem'), record.get('name'), record.get('version')
    key = package_key(ecosystem, name, version)
    filename = record.get('filename')
    if not isinstance(filename, str) or len(safe_parts(filename)) != 1:
        raise ArtifactError('artifact-path', 'artifact filename is invalid')
    if ecosystem == 'PyPI':
        if origin.get('index_url') != pypi_index_url(name, version):
            raise ArtifactError('artifact-origin', 'PyPI index URL does not match the exact requested release')
        info = index.get('info', {})
        if not isinstance(info, dict) or package_key('PyPI', info.get('name'), info.get('version')) != key:
            raise ArtifactError('artifact-origin', 'PyPI index package identity differs')
        urls = index.get('urls')
        if not isinstance(urls, list) or not all(isinstance(item, dict) for item in urls):
            raise ArtifactError('artifact-origin', 'PyPI release has no complete file list')
        matches = [item for item in urls if item.get('filename') == filename]
        if len(matches) != 1:
            raise ArtifactError('artifact-origin', 'selected artifact is missing or ambiguous in registry index')
        item = matches[0]
        if (not isinstance(item.get('digests'), dict) or item['digests'].get('sha256') != digest or item.get('url') != origin.get('artifact_url')
                or not allowed_download_url(item.get('url')) or urlsplit(item['url']).hostname != 'files.pythonhosted.org'):
            raise ArtifactError('artifact-origin', 'artifact hash and URL do not match the fixed PyPI file origin')
        if item.get('yanked') is not False:
            raise ArtifactError('artifact-origin', 'registry artifact is yanked or its status is unknown')
        expected_type = 'bdist_wheel' if filename.endswith('.whl') else 'sdist'
        if item.get('packagetype') != expected_type:
            raise ArtifactError('artifact-origin', 'registry artifact type disagrees with filename')
    else:
        expected_url = f'https://registry.npmjs.org/{quote(name, safe="")}/{quote(version, safe="")}'
        if origin.get('index_url') != expected_url or package_key('npm', index.get('name'), index.get('version')) != key:
            raise ArtifactError('artifact-origin', 'npm index package identity differs')
        distribution = index.get('dist', {})
        url = origin.get('artifact_url', '')
        parsed = urlsplit(url)
        if (not isinstance(distribution, dict) or distribution.get('tarball') != url or
                parsed.scheme != 'https' or parsed.netloc != 'registry.npmjs.org' or parsed.query or parsed.fragment):
            raise ArtifactError('artifact-origin', 'npm tarball URL is not the fixed registry origin')
        expected = 'sha512-' + base64.b64encode(hashlib.sha512(payload).digest()).decode('ascii')
        if distribution.get('integrity') != expected:
            raise ArtifactError('artifact-origin', 'npm tarball requires matching registry SHA-512 integrity')
    return {'index_url': origin['index_url'], 'index_sha256': index_digest,
            'artifact_url': origin['artifact_url'], 'artifact_sha256': digest}


def _interesting(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return (name in {'metadata', 'pkg-info', 'package.json'} or name.startswith(('license', 'copying', 'notice'))
            or any(part.lower() in {'licenses', 'licences'} for part in PurePosixPath(path).parts))


def archive_files(payload: bytes, filename: str, *, requested: set[str] | None = None) -> dict[str, bytes]:
    """Return only bounded metadata/license files; never write or execute archive members."""
    if not payload or len(payload) > MAX_ARTIFACT_BYTES:
        raise ArtifactError('artifact-size', 'artifact is empty or exceeds the compressed size budget')
    selected = {}
    seen = set()
    total = 0

    def admit(name: str, size: int) -> bool:
        nonlocal total
        safe_parts(name.rstrip('/'))
        if name in seen or len(seen) >= MAX_MEMBERS or size < 0:
            raise ArtifactError('artifact-archive', 'duplicate or excessive archive members')
        seen.add(name)
        total += size
        if total > MAX_ARCHIVE_BYTES:
            raise ArtifactError('artifact-size', 'archive exceeds the uncompressed size budget')
        wanted = _interesting(name) or name in (requested or set())
        if wanted and size > MAX_METADATA_BYTES:
            raise ArtifactError('artifact-size', 'archive metadata or license exceeds the size budget')
        return wanted

    try:
        if filename.endswith(('.whl', '.zip')):
            # Bound the central directory before zipfile allocates member objects.
            end = payload.rfind(b'PK\x05\x06', max(0, len(payload) - 65557))
            if end < 0 or len(payload) < end + 22:
                raise ArtifactError('artifact-archive', 'ZIP has no complete end record')
            _, disk, directory_disk, on_disk, count, directory_size, _, comment = struct.unpack_from('<4s4H2LH', payload, end)
            if disk or directory_disk or on_disk != count or count > MAX_MEMBERS or directory_size > 4 * 1024 * 1024 or end + 22 + comment != len(payload):
                raise ArtifactError('artifact-archive', 'unsupported ZIP64, multi-volume or oversized central directory')
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                for member in archive.infolist():
                    wanted = admit(member.filename, member.file_size)
                    kind = stat.S_IFMT(member.external_attr >> 16)
                    if kind not in {0, stat.S_IFREG, stat.S_IFDIR} or member.flag_bits & 1:
                        raise ArtifactError('artifact-archive', 'links, special files and encrypted members are forbidden')
                    if member.is_dir():
                        if member.file_size:
                            raise ArtifactError('artifact-archive', 'archive directory has unexpected contents')
                        continue
                    if wanted:
                        selected[member.filename] = archive.read(member)
                if archive.testzip() is not None:
                    raise ArtifactError('artifact-archive', 'archive member checksum failed')
        elif filename.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar')):
            opener = (gzip.open if filename.endswith(('.gz', '.tgz')) else
                      bz2.BZ2File if filename.endswith('.bz2') else lzma.LZMAFile if filename.endswith('.xz') else None)
            if opener is not None:
                with opener(io.BytesIO(payload), mode='rb') as stream:
                    expanded = stream.read(MAX_ARCHIVE_BYTES + 1)
            else:
                expanded = payload
            if len(expanded) > MAX_ARCHIVE_BYTES:
                raise ArtifactError('artifact-size', 'tar stream exceeds the uncompressed size budget')
            with tarfile.open(fileobj=io.BytesIO(expanded), mode='r|') as archive:
                for member in archive:
                    wanted = admit(member.name, member.size)
                    if not member.isfile() and not member.isdir():
                        raise ArtifactError('artifact-archive', 'archive links and special files are forbidden')
                    if wanted and member.isfile():
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise ArtifactError('artifact-archive', 'archive metadata cannot be read')
                        with stream:
                            selected[member.name] = stream.read(MAX_METADATA_BYTES + 1)
                        if len(selected[member.name]) != member.size:
                            raise ArtifactError('artifact-archive', 'truncated archive metadata')
        else:
            raise ArtifactError('artifact-archive', 'unsupported artifact archive format')
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, RuntimeError, OverflowError, lzma.LZMAError, zlib.error) as exc:
        raise ArtifactError('artifact-archive', f'archive validation failed: {exc}') from exc
    return selected


def package_metadata(files: dict[str, bytes], ecosystem: str, filename: str) -> dict:
    if ecosystem == 'npm':
        if 'package/package.json' not in files:
            raise ArtifactError('artifact-metadata', 'npm archive lacks package/package.json')
        value = _json(files['package/package.json'])
        if value.get('licenses') is not None:
            raise ArtifactError('license-conflict', 'deprecated npm licenses metadata needs explicit review')
        requirements = value.get('dependencies', {})
        if not isinstance(requirements, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in requirements.items()):
            raise ArtifactError('artifact-metadata', 'npm dependency metadata is malformed')
        return {'name': value.get('name'), 'version': value.get('version'), 'expression': value.get('license'),
                'license_paths': [], 'requires': list(requirements.items()), 'metadata_path': 'package/package.json',
                'root': 'package', 'peer_optional': bool(value.get('peerDependencies') or value.get('optionalDependencies'))}
    candidates = [path for path in files if (len(PurePosixPath(path).parts) == 2 and path.endswith('.dist-info/METADATA'))]
    if not filename.endswith('.whl'):
        candidates = [path for path in files if PurePosixPath(path).name == 'PKG-INFO' and len(PurePosixPath(path).parts) <= 2]
    if len(candidates) != 1:
        raise ArtifactError('artifact-metadata', 'artifact needs exactly one primary distribution metadata file')
    path = candidates[0]
    message = Parser(policy=email_policy.compat32).parsestr(files[path].decode('utf-8'))
    if message.defects:
        raise ArtifactError('artifact-metadata', 'distribution metadata is malformed')
    for field in ('Metadata-Version', 'Name', 'Version', 'License-Expression', 'License'):
        if len(message.get_all(field, [])) > 1:
            raise ArtifactError('license-conflict', f'duplicate metadata field: {field}')
    if message.get('Metadata-Version') not in {'1.0', '1.1', '1.2', '2.1', '2.2', '2.3', '2.4', '2.5', '2.6'}:
        raise ArtifactError('artifact-metadata', 'unsupported distribution metadata version')
    expression, legacy = message.get('License-Expression'), message.get('License')
    if expression and legacy:
        raise ArtifactError('license-conflict', 'License and License-Expression are mutually exclusive')
    expression = expression or legacy
    root = str(PurePosixPath(path).parent)
    license_root = root + '/licenses' if filename.endswith('.whl') else root
    paths = []
    for value in message.get_all('License-File', []):
        safe_parts(value)
        paths.append(f'{license_root}/{value}' if license_root != '.' else value)
    return {'name': message.get('Name'), 'version': message.get('Version'), 'expression': expression,
            'license_paths': paths, 'requires': message.get_all('Requires-Dist', []),
            'classifiers': message.get_all('Classifier', []), 'metadata_path': path, 'root': root,
            'dynamic': message.get_all('Dynamic', []), 'requires_external': message.get_all('Requires-External', [])}
