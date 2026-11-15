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
    if 'kind' in record:
        return family_identity(record)
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
        if 'kind' in record:
            continue
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


def family_identity(record: dict) -> str:
    """Tagged non-package identities never enter the package matching namespace."""
    required = {'schema_version', 'kind', 'subject', 'filename', 'path', 'sha256', 'bytes',
                'context', 'acquired_at', 'origin', 'components'}
    if (not isinstance(record, dict) or set(record) != required or type(record['schema_version']) is not int
            or record['schema_version'] != 1 or record['kind'] not in {'action', 'tool', 'image'}):
        raise ArtifactError('artifact-identity', 'unsupported tagged artifact schema')
    subject = record['subject']
    if (not isinstance(subject, dict) or not isinstance(subject.get('reference'), str)
            or not subject['reference'] or len(subject['reference']) > 1024):
        raise ArtifactError('artifact-identity', 'artifact needs an exact source-owned subject')
    _digest(subject.get('source_sha256'), 'source declaration')
    safe_parts(subject.get('manifest'))
    if type(subject.get('line')) is not int or not 1 <= subject['line'] <= 1000000:
        raise ArtifactError('artifact-context', 'artifact source line is unavailable')
    if not isinstance(record['context'], dict):
        raise ArtifactError('artifact-context', 'artifact use context must be an object')
    context = artifact_context(record['context'])
    if context != record['context'] or context != artifact_context(subject):
        raise ArtifactError('artifact-context', 'artifact context differs from source-owned use')
    if type(record['bytes']) is not int or not 0 < record['bytes'] <= MAX_ARTIFACT_BYTES:
        raise ArtifactError('artifact-size', 'artifact needs a bounded exact byte count')
    safe_parts(record['path'])
    if len(safe_parts(record['filename'])) != 1:
        raise ArtifactError('artifact-path', 'artifact filename must be a basename')
    _digest(record['sha256'], 'artifact')
    for key in ('origin', 'components'):
        if not isinstance(record[key], dict):
            raise ArtifactError('artifact-origin', 'artifact proof descriptor is missing')
    _digest(record['components'].get('sha256'), 'component proof')
    safe_parts(record['components'].get('path'))
    value = {key: record[key] for key in ('schema_version', 'kind', 'subject', 'filename', 'sha256', 'bytes', 'context', 'origin', 'components')}
    # Cache locations are not artifact identities; their actual bytes are bound below.
    value['origin'] = {key: item for key, item in value['origin'].items() if not key.endswith('_path')}
    value['components'] = {'sha256': record['components']['sha256']}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def select_family(subject: dict, kind: str, records: list[dict]) -> dict:
    matches = [record for record in records if record.get('kind') == kind and record.get('subject') == subject]
    if len(matches) != 1:
        raise ArtifactError('license-artifact-missing', 'select one exact source-owned artifact family record')
    family_identity(matches[0])
    return matches[0]


def _saved_proof(root: Path, path: str, digest: str) -> tuple[bytes, dict]:
    raw = read_file(root, path, MAX_INDEX_BYTES)
    if hashlib.sha256(raw).hexdigest() != _digest(digest, 'saved proof'):
        raise ArtifactError('artifact-origin', 'saved proof bytes changed')
    value = _json(raw)
    if not isinstance(value, dict):
        raise ArtifactError('artifact-origin', 'saved proof must be an object')
    return raw, value


def _check_git_namespace(rows: dict[str, dict]) -> None:
    """No regular Git blob can also be a directory containing another blob."""
    files = set(rows)
    for path in rows:
        parts = safe_parts(path)
        if any('/'.join(parts[:depth]) in files for depth in range(1, len(parts))):
            raise ArtifactError('artifact-origin', 'Git source has contradictory file/directory paths')


def _git_tree(rows: dict[str, dict]) -> str:
    """Recompute Git SHA-1 tree identity, not a substitute for publisher authority."""
    _check_git_namespace(rows)
    directories = {}
    for path, row in rows.items():
        parent, _, name = path.rpartition('/')
        directories.setdefault(parent, {})[name] = (row['mode'], row['sha'])
        while parent:
            parent, _, name = parent.rpartition('/')
            directories.setdefault(parent, {}).setdefault(name, None)
    hashes = {}
    for parent in sorted(directories, key=lambda name: name.count('/') + bool(name), reverse=True):
        entries = []
        for name, value in directories[parent].items():
            mode, digest = value if value is not None else ('40000', hashes[(parent + '/' if parent else '') + name])
            entries.append((name.encode() + (b'/' if mode == '40000' else b''), mode, name, digest))
        body = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)
                        for _, mode, name, digest in sorted(entries))
        hashes[parent] = hashlib.sha1(b'tree ' + str(len(body)).encode() + b'\0' + body, usedforsecurity=False).hexdigest()
    return hashes.get('', '')


def _validate_action_metadata(raw: bytes) -> None:
    """Admit only the implemented self-contained composite subset, not shell execution."""
    from .security_inventory import _parse_inventory_yaml, _YamlError
    from ._policy_legacy import _shell_tokens

    def unsupported():
        raise ArtifactError('artifact-action-unsupported', 'Action execution/dependency metadata needs qualified coverage')

    try:
        document = _parse_inventory_yaml(raw.decode('utf-8'))
    except (UnicodeDecodeError, _YamlError) as exc:
        code = exc.code if isinstance(exc, _YamlError) else 'artifact-action-unsupported'
        raise ArtifactError(code, 'Action metadata cannot be structurally qualified') from exc
    if (document.kind != 'mapping' or not set(document.value) <= {'name', 'description', 'author', 'runs'}
            or 'runs' not in document.value):
        unsupported()
    runs = document.value['runs']
    if runs.kind != 'mapping' or set(runs.value) != {'using', 'steps'}:
        unsupported()
    using, steps = runs.value['using'], runs.value['steps']
    if using.kind != 'scalar' or using.value != 'composite' or steps.kind != 'sequence':
        unsupported()
    for step in steps.value:
        if step.kind != 'mapping' or set(step.value) != {'run', 'shell'}:
            unsupported()
        command, shell = step.value['run'], step.value['shell']
        if command.kind != 'scalar' or shell.kind != 'scalar' or shell.value not in {'bash', 'sh'}:
            unsupported()
        # GitHub expression interpolation precedes shell quoting. A quoted
        # expression is therefore not a literal even if the shell lexer says so.
        if '${{' in command.value:
            unsupported()
        try:
            tokens = _shell_tokens(command.value.strip(' \t\r\n'))
        except ValueError:
            unsupported()
        if (len(tokens) != 2 or tokens[0].value != 'printf'
                or any(t.operator or t.expansion or t.substitution or t.opaque for t in tokens)
                or tokens[1].value.startswith('-') or '%' in tokens[1].value or '\\' in tokens[1].value):
            unsupported()


def _action_source(root: Path, record: dict, payload: bytes) -> tuple[dict, dict, list[dict]]:
    subject, origin = record['subject'], record['origin']
    match = re.fullmatch(r'([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:/([A-Za-z0-9_./-]+))?@([0-9a-f]{40})', subject['reference'])
    if not match or subject.get('kind') != 'github-action':
        raise ArtifactError('artifact-origin', 'Action needs a full exact Git commit and repository')
    owner, repository, subpath, revision = match.groups()
    if subpath:
        safe_parts(subpath)
    api = f'https://api.github.com/repos/{owner}/{repository}'
    if (set(origin) != {'kind', 'index_url', 'index_path', 'index_sha256', 'artifact_url', 'tree_path', 'tree_sha256', 'archive_root'}
            or origin['kind'] != 'github-source' or origin['index_url'] != api + '/git/commits/' + revision
            or origin['artifact_url'] != api + '/zipball/' + revision or not record['filename'].endswith('.zip')):
        raise ArtifactError('artifact-origin', 'Action proof does not name its fixed official Git source')
    commit_raw, commit = _saved_proof(root, origin['index_path'], origin['index_sha256'])
    tree_raw, tree = _saved_proof(root, origin['tree_path'], origin['tree_sha256'])
    if (commit.get('sha') != revision or not isinstance(commit.get('tree'), dict) or commit['tree'].get('sha') != tree.get('sha')
            or tree.get('truncated') is not False or not isinstance(tree.get('tree'), list)
            or not 0 < len(tree['tree']) <= MAX_MEMBERS):
        raise ArtifactError('artifact-origin', 'Action needs complete commit and tree evidence')
    rows = {}
    for row in tree['tree']:
        if not isinstance(row, dict):
            raise ArtifactError('artifact-origin', 'Git tree entry is malformed')
        name = row.get('path')
        safe_parts(name)
        if row.get('type') == 'tree' and row.get('mode') == '040000':
            continue
        if (name in rows or row.get('type') != 'blob' or row.get('mode') not in {'100644', '100755'}
                or not isinstance(row.get('sha'), str) or not re.fullmatch('[0-9a-f]{40}', row['sha'])
                or type(row.get('size')) is not int or not 0 <= row['size'] <= MAX_ARCHIVE_BYTES):
            raise ArtifactError('artifact-origin', 'Git links/submodules/ambiguous tree entries are unsupported')
        rows[name] = row
    if _git_tree(rows) != tree.get('sha'):
        raise ArtifactError('artifact-origin', 'complete Git tree identity differs')
    prefix = origin['archive_root']
    safe_parts(prefix)
    if '/' in prefix:
        raise ArtifactError('artifact-origin', 'archive needs one exact top-level root')
    inventory = archive_inventory(payload, record['filename'])
    observed = {}
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for member in archive.infolist():
            if member.orig_filename != member.filename:
                raise ArtifactError('artifact-archive', 'archive original and logical names differ')
            if member.is_dir():
                continue
            if not member.filename.startswith(prefix + '/'):
                raise ArtifactError('artifact-origin', 'archive member lies outside the Git source root')
            name = member.filename[len(prefix) + 1:]
            row = rows.get(name)
            if row is None or row['size'] != member.file_size or stat.S_IMODE(member.external_attr >> 16) != int(row['mode'], 8) & 0o777:
                raise ArtifactError('artifact-origin', 'archive member differs from its Git mode/size')
            digest = hashlib.sha1(b'blob ' + str(member.file_size).encode() + b'\0', usedforsecurity=False)
            with archive.open(member) as stream:
                while block := stream.read(65536):
                    digest.update(block)
            if digest.hexdigest() != row['sha']:
                raise ArtifactError('artifact-origin', 'archive blob differs from exact Git tree')
            observed[name] = row
    metadata = [(subpath + '/' if subpath else '') + name for name in ('action.yml', 'action.yaml')
                if (subpath + '/' if subpath else '') + name in rows]
    if observed != rows or len(metadata) != 1:
        raise ArtifactError('artifact-origin', 'archive is not the complete selected Action source')
    metadata_path = prefix + '/' + metadata[0]
    files = archive_files(payload, record['filename'], requested={metadata_path})
    _validate_action_metadata(files[metadata_path])
    evidence = [{'path': origin['index_path'], 'sha256': origin['index_sha256'], 'bytes': len(commit_raw)},
                {'path': origin['tree_path'], 'sha256': origin['tree_sha256'], 'bytes': len(tree_raw)}]
    return inventory, files, evidence


def _release_source(root: Path, record: dict, payload: bytes) -> tuple[dict, dict, list[dict]]:
    subject, origin = record['subject'], record['origin']
    match = re.fullmatch(r'https://github.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/download/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)', subject['reference'])
    if (not match or subject.get('kind') != 'release-tool' or subject.get('artifact_sha256') != record['sha256']
            or subject.get('platform') not in {'linux/amd64', 'linux/arm64'}):
        raise ArtifactError('artifact-origin', 'release tool needs source-owned bytes and a qualified platform')
    owner, repository, tag, filename = match.groups()
    if (set(origin) != {'kind', 'index_url', 'index_path', 'index_sha256', 'artifact_url', 'source_commit'}
            or origin['kind'] != 'github-release' or origin['artifact_url'] != subject['reference']
            or origin['index_url'] != f'https://api.github.com/repos/{owner}/{repository}/releases/tags/{tag}'
            or record['filename'] != filename or not filename.endswith('.zip')
            or not isinstance(origin['source_commit'], str) or not re.fullmatch('[0-9a-f]{40}', origin['source_commit'])):
        raise ArtifactError('artifact-origin', 'release tool source/asset identity is unsupported')
    raw, release = _saved_proof(root, origin['index_path'], origin['index_sha256'])
    if (release.get('tag_name') != tag or release.get('target_commitish') != origin['source_commit']
            or not isinstance(release.get('assets'), list) or len(release['assets']) > MAX_MEMBERS):
        raise ArtifactError('artifact-origin', 'release needs an exact retained source commit, not an unresolved branch/tag')
    candidates = [asset for asset in release['assets'] if isinstance(asset, dict) and asset.get('name') == filename]
    if (len(candidates) != 1 or candidates[0].get('browser_download_url') != subject['reference']
            or type(candidates[0].get('size')) is not int or candidates[0]['size'] != len(payload)
            or candidates[0].get('digest') != 'sha256:' + record['sha256']):
        raise ArtifactError('artifact-origin', 'release asset URL/size/digest differs from retained official metadata')
    inventory = archive_inventory(payload, filename)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        if any(member.orig_filename != member.filename for member in archive.infolist()):
            raise ArtifactError('artifact-archive', 'release archive names are ambiguous')
    return inventory, archive_files(payload, filename), [
        {'path': origin['index_path'], 'sha256': origin['index_sha256'], 'bytes': len(raw)}]


def _image_source(record: dict, payload: bytes) -> tuple[dict, dict, list[dict]]:
    """Read one OCI image and every layer; a vulnerability report is not a SBOM."""
    subject, origin = record['subject'], record['origin']
    reference = subject['reference']
    if (subject.get('kind') != 'oci-image' or not re.fullmatch(r'[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}', reference)
            or subject.get('platform') not in {'linux/amd64', 'linux/arm64'} or not record['filename'].endswith('.zip')
            or set(origin) != {'kind', 'manifest_digest'} or origin['kind'] != 'oci-layout'
            or origin['manifest_digest'] != reference.rsplit('@', 1)[1]):
        raise ArtifactError('artifact-origin', 'image needs an exact OCI identity and supported platform')
    outer = archive_inventory(payload, record['filename'])
    if 'oci-layout' not in outer or 'index.json' not in outer:
        raise ArtifactError('artifact-origin', 'OCI layout/index is missing')
    bound, licenses = {}, {}
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        if any(member.orig_filename != member.filename for member in archive.infolist()):
            raise ArtifactError('artifact-archive', 'OCI archive names are ambiguous')
        def read(name):
            if name not in outer or outer[name]['size'] > MAX_ARTIFACT_BYTES:
                raise ArtifactError('artifact-size', 'OCI object is missing or exceeds its bound')
            return archive.read(name)
        if _json(read('oci-layout')) != {'imageLayoutVersion': '1.0.0'}:
            raise ArtifactError('artifact-origin', 'unsupported OCI layout')
        index = _json(read('index.json'))
        platform = dict(zip(('os', 'architecture'), subject['platform'].split('/')))
        if (index.get('schemaVersion') != 2 or not isinstance(index.get('manifests'), list)
                or len(index['manifests']) != 1 or not isinstance(index['manifests'][0], dict)
                or index['manifests'][0].get('platform') != platform):
            raise ArtifactError('artifact-origin', 'OCI index must select exactly one matching platform')
        names = {'oci-layout', 'index.json'}
        def blob(descriptor, media):
            if (not isinstance(descriptor, dict) or descriptor.get('mediaType') not in media
                    or not isinstance(descriptor.get('digest'), str) or not re.fullmatch('sha256:[0-9a-f]{64}', descriptor['digest'])
                    or type(descriptor.get('size')) is not int or not 0 < descriptor['size'] <= MAX_ARTIFACT_BYTES):
                raise ArtifactError('artifact-origin', 'OCI descriptor is unsupported or unbounded')
            name = 'blobs/sha256/' + descriptor['digest'][7:]
            raw = read(name)
            if len(raw) != descriptor['size'] or hashlib.sha256(raw).hexdigest() != descriptor['digest'][7:]:
                raise ArtifactError('artifact-hash', 'OCI descriptor bytes differ')
            names.add(name)
            return raw
        selected = index['manifests'][0]
        if selected.get('digest') != origin['manifest_digest']:
            raise ArtifactError('artifact-origin', 'OCI selected manifest differs from image reference')
        manifest = _json(blob(selected, {'application/vnd.oci.image.manifest.v1+json'}))
        if (manifest.get('schemaVersion') != 2 or not isinstance(manifest.get('layers'), list)
                or not 0 < len(manifest['layers']) <= MAX_MEMBERS):
            raise ArtifactError('artifact-origin', 'OCI image has no complete bounded layers')
        config = _json(blob(manifest.get('config'), {'application/vnd.oci.image.config.v1+json'}))
        if any(config.get(key) != value for key, value in platform.items()):
            raise ArtifactError('artifact-origin', 'OCI config platform differs')
        rootfs = config.get('rootfs')
        if (not isinstance(rootfs, dict) or rootfs.get('type') != 'layers' or not isinstance(rootfs.get('diff_ids'), list)
                or len(rootfs['diff_ids']) != len(manifest['layers'])):
            raise ArtifactError('artifact-origin', 'OCI config lacks exact uncompressed layer identities')
        total = sum(row['size'] for row in outer.values())
        for layer, diff_id in zip(manifest['layers'], rootfs['diff_ids']):
            raw = blob(layer, {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip'})
            if layer['mediaType'].endswith('+gzip'):
                with gzip.open(io.BytesIO(raw), 'rb') as stream:
                    expanded = stream.read(MAX_ARCHIVE_BYTES + 1)
            else:
                expanded = raw
            if len(expanded) > MAX_ARCHIVE_BYTES or diff_id != 'sha256:' + hashlib.sha256(expanded).hexdigest():
                raise ArtifactError('artifact-hash', 'OCI uncompressed layer identity differs or exceeds its budget')
            prefix = 'layers/' + layer['digest'][7:] + '/'
            members = archive_inventory(expanded, 'layer.tar')
            total += sum(row['size'] for row in members.values())
            if total > MAX_ARCHIVE_BYTES or len(bound) + len(members) + len(outer) > MAX_MEMBERS:
                raise ArtifactError('artifact-size', 'OCI complete layer inventory exceeds aggregate limits')
            for name, row in members.items():
                if prefix + name in bound:
                    raise ArtifactError('artifact-origin', 'OCI repeats layer identity')
                bound[prefix + name] = row
            licenses.update({prefix + name: body for name, body in archive_files(expanded, 'layer.tar').items()})
        if names != set(outer):
            raise ArtifactError('artifact-origin', 'OCI layout contains unreferenced or missing objects')
    bound.update({'oci/' + name: row for name, row in outer.items()})
    return bound, licenses, []


def family_evidence(root: Path, record: dict) -> dict:
    """One byte-bound reader shared by license evaluation and receipt projection."""
    identity = family_identity(record)
    payload = read_file(root, record['path'], MAX_ARTIFACT_BYTES)
    if len(payload) != record['bytes'] or hashlib.sha256(payload).hexdigest() != record['sha256']:
        raise ArtifactError('artifact-hash', 'family payload differs from its exact bytes')
    if record['kind'] == 'action':
        members, files, evidence = _action_source(root, record, payload)
    elif record['kind'] == 'tool':
        members, files, evidence = _release_source(root, record, payload)
    elif record['kind'] == 'image':
        members, files, evidence = _image_source(record, payload)
    else:
        raise ArtifactError('artifact-family-coverage', 'this family requires a qualified source/SBOM adapter')
    raw, proof = _saved_proof(root, record['components']['path'], record['components']['sha256'])
    if (set(proof) != {'schema_version', 'kind', 'artifact_sha256', 'complete', 'unresolved', 'components'}
            or type(proof['schema_version']) is not int or proof['schema_version'] != 1
            or proof['kind'] != 'artifact-component-inventory' or proof['artifact_sha256'] != record['sha256']
            or proof['complete'] is not True or proof['unresolved'] != [] or not isinstance(proof['components'], list)
            or not 0 < len(proof['components']) <= MAX_MEMBERS):
        raise ArtifactError('license-transitive-coverage', 'component proof is incomplete or bound to other bytes')
    covered, ids = set(), set()
    for component in proof['components']:
        if (not isinstance(component, dict) or set(component) != {'id', 'expression', 'requires', 'files', 'license_paths', 'notice_paths'}
                or not isinstance(component['id'], str) or not component['id'] or component['id'] in ids
                or not isinstance(component['files'], list) or not component['files']
                or not all(isinstance(component[key], list) for key in ('requires', 'license_paths', 'notice_paths'))):
            raise ArtifactError('license-transitive-coverage', 'component ownership or dependency graph is malformed')
        ids.add(component['id'])
        for item in component['files']:
            if not isinstance(item, dict) or set(item) != {'path', 'sha256', 'bytes'}:
                raise ArtifactError('license-transitive-coverage', 'component file evidence is malformed')
            path = item['path']
            safe_parts(path)
            if path in covered or members.get(path) != {'sha256': item['sha256'], 'size': item['bytes']}:
                raise ArtifactError('license-transitive-coverage', 'component files do not partition actual archive bytes')
            covered.add(path)
        owned = {item['path'] for item in component['files']}
        for path in component['license_paths'] + component['notice_paths']:
            safe_parts(path)
            if path not in owned:
                raise ArtifactError('license-obligation-missing', 'component license/notice is not retained in its actual bytes')
    if covered != set(members) or any(not isinstance(dep, str) or dep not in ids for c in proof['components'] for dep in c['requires']):
        raise ArtifactError('license-transitive-coverage', 'component graph or complete source coverage differs')
    requested = {path for c in proof['components'] for path in c['license_paths'] + c['notice_paths']}
    if record['kind'] != 'image':
        files.update(archive_files(payload, record['filename'], requested=requested))
    elif any(path not in files for path in requested):
        raise ArtifactError('license-obligation-missing', 'OCI license/notice is not a retained recognized layer file')
    evidence.append({'path': record['components']['path'], 'sha256': record['components']['sha256'], 'bytes': len(raw)})
    return {'artifact_id': identity, 'members': members, 'files': files, 'components': proof['components'],
            'binding': {'artifact_id': identity, 'artifact_sha256': record['sha256'], 'artifact_size': len(payload),
                        'subject': record['subject'], 'context': record['context'], 'proofs': evidence},
            'bound_bytes': len(payload) + sum(item['bytes'] for item in evidence)}


def archive_inventory(payload: bytes, filename: str) -> dict[str, dict]:
    """Hash all ZIP members after the shared bounded, link-free archive validation."""
    archive_files(payload, filename)
    result = {}
    if not filename.endswith(('.whl', '.zip')):
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:*') as archive:
            for member in archive:
                if member.isdir():
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    raise ArtifactError('artifact-archive', 'archive member cannot be read')
                digest = hashlib.sha256()
                size = 0
                with stream:
                    while block := stream.read(65536):
                        digest.update(block)
                        size += len(block)
                if size != member.size:
                    raise ArtifactError('artifact-archive', 'archive member is truncated')
                result[member.name] = {'sha256': digest.hexdigest(), 'size': size}
        return result
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
                    if member.orig_filename != member.filename:
                        raise ArtifactError('artifact-archive', 'original and logical ZIP member names differ')
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
    provides_extra = message.get_all('Provides-Extra', [])
    if (len(provides_extra) > 256 or
            any(not isinstance(value, str) or len(value) > 512 for value in provides_extra)):
        raise ArtifactError('artifact-metadata', 'Provides-Extra exceeds its bounded metadata contract')
    return {'name': message.get('Name'), 'version': message.get('Version'), 'expression': expression,
            'license_paths': paths, 'requires': message.get_all('Requires-Dist', []),
            'metadata_version': message.get('Metadata-Version'), 'provides_extra': provides_extra,
            'classifiers': message.get_all('Classifier', []), 'metadata_path': path, 'root': root,
            'dynamic': message.get_all('Dynamic', []), 'requires_external': message.get_all('Requires-External', [])}
