"""Bounded custody evidence for Factory's extracted offline archive.

This verifies local bytes and composition. It supplies no publisher identity,
legal decision, build provenance or independent release approval.
"""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re

from .security_artifacts import (ArtifactError, MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES,
                                 archive_inventory, artifact_identity, read_file,
                                 safe_parts, select_artifact, verify_origin)
from .security_data import _json

PROFILE = 'ubuntu-24.04-x86_64-cpython312'


def verify_deliveries(root: Path, deliveries: list[dict], records: list[dict], dependencies: list[dict]) -> dict:
    """Bind actual output bytes to exact source wheels and complete extracted members."""
    if not isinstance(deliveries, list) or len(deliveries) > 128:
        raise ArtifactError('license-delivery-invalid', 'delivery evidence must be a bounded list')
    if not isinstance(dependencies, list) or not all(isinstance(dep, dict) for dep in dependencies):
        raise ArtifactError('license-delivery-invalid', 'delivery needs an explicit component inventory')
    verified = {}
    identities = {artifact_identity(record): record for record in records}
    total = 0
    for delivery in deliveries:
        required = {'context', 'kind', 'profile', 'path', 'sha256', 'manifest_path',
                    'manifest_sha256', 'sidecar_path', 'components'}
        if not isinstance(delivery, dict) or set(delivery) != required:
            raise ArtifactError('license-delivery-invalid', 'delivery must bind archive, detached identity and composition')
        context = delivery['context']
        if not isinstance(context, str) or not context or context in verified:
            raise ArtifactError('license-delivery-invalid', 'delivery context is missing or repeated')
        if delivery['kind'] != 'factory-offline-archive' or delivery['profile'] != PROFILE:
            raise ArtifactError('license-delivery-target', 'output kind or platform/ABI has no qualified delivery adapter')
        payload = read_file(root, delivery['path'], MAX_ARTIFACT_BYTES)
        detached = read_file(root, delivery['manifest_path'], MAX_INDEX_BYTES)
        sidecar = read_file(root, delivery['sidecar_path'], 65536)
        total += len(payload) + len(detached) + len(sidecar)
        if total > 512 * 1024 * 1024:
            raise ArtifactError('artifact-size', 'delivery evidence exceeds its aggregate byte budget')
        archive_digest = hashlib.sha256(payload).hexdigest()
        manifest_digest = hashlib.sha256(detached).hexdigest()
        if delivery['sha256'] != archive_digest or delivery['manifest_sha256'] != manifest_digest:
            raise ArtifactError('license-delivery-hash', 'final archive or detached manifest digest differs')
        expected_sidecar = (f"{archive_digest}  {PurePosixPath(delivery['path']).name}\n"
                            f"{manifest_digest}  {PurePosixPath(delivery['manifest_path']).name}\n").encode()
        if sidecar != expected_sidecar:
            raise ArtifactError('license-delivery-hash', 'detached checksum file does not identify this final archive and manifest')
        members = archive_inventory(payload, delivery['path'])
        manifest = _json(detached)
        if (manifest.get('schema_version') != 'factory-release/v1' or manifest.get('profile') != 'factory-python'
                or not isinstance(manifest.get('files'), list) or not 1 <= len(manifest['files']) <= 10000):
            raise ArtifactError('license-delivery-invalid', 'detached Factory member manifest is missing')
        declared = {}
        for member in manifest['files']:
            if not isinstance(member, dict) or set(member) != {'path', 'size', 'sha256', 'mode'}:
                raise ArtifactError('license-delivery-invalid', 'detached member identity is malformed')
            safe_parts(member['path'])
            if member['path'] in declared or type(member['size']) is not int or member['size'] < 0:
                raise ArtifactError('license-delivery-invalid', 'detached member identity is duplicated or invalid')
            declared[member['path']] = {'size': member['size'], 'sha256': member['sha256']}
        if members != declared:
            raise ArtifactError('license-delivery-hash', 'actual archive members differ from detached manifest')
        components = delivery['components']
        if not isinstance(components, list) or not 1 <= len(components) <= 512:
            raise ArtifactError('license-delivery-composition', 'output requires its complete exact source wheel composition')
        expected = {artifact_identity(select_artifact(dep, records)) for dep in dependencies
                    if dep.get('delivery_context') == context}
        source_members, component_ids = {}, set()
        for component in components:
            if not isinstance(component, dict) or set(component) != {'artifact_id', 'prefix'}:
                raise ArtifactError('license-delivery-composition', 'output component lacks exact source identity')
            identity = component['artifact_id']
            if not isinstance(identity, str) or identity not in identities or identity in component_ids:
                raise ArtifactError('license-delivery-composition', 'output component is missing, unknown or repeated')
            component_ids.add(identity)
            record = identities[identity]
            if (record.get('context', {}).get('delivery_context') != context
                    or record.get('context', {}).get('delivery_kind') != 'factory-offline-archive'
                    or record.get('context', {}).get('distribution') == 'internal'
                    or record['ecosystem'] != 'PyPI' or component['prefix'] != 'site-packages/'):
                raise ArtifactError('license-delivery-composition', 'component belongs to another delivery or use')
            filename = record['filename']
            universal = re.search(r'-(?:py3|py2\.py3)-none-any\.whl$', filename)
            native_tags = re.search(r'-cp312-cp312-([A-Za-z0-9_.]+)\.whl$', filename)
            native = native_tags and all(re.fullmatch(r'manylinux(?:2014|_2_17)_x86_64', tag)
                                         for tag in native_tags[1].split('.'))
            if not (universal or native):
                raise ArtifactError('license-delivery-target', 'source wheel platform/ABI does not match the offline profile')
            wheel = read_file(root, record['path'], MAX_ARTIFACT_BYTES)
            verify_origin(root, record, wheel)
            total += len(wheel)
            if total > 512 * 1024 * 1024:
                raise ArtifactError('artifact-size', 'delivery composition exceeds its aggregate byte budget')
            for path, observed in archive_inventory(wheel, filename).items():
                target = component['prefix'] + path
                if target in source_members:
                    raise ArtifactError('license-delivery-composition', 'source wheels collide in the extracted output')
                source_members[target] = observed
        if component_ids != expected:
            raise ArtifactError('license-delivery-composition', 'composition and inventory output components differ')
        actual = {path: member for path, member in members.items() if path.startswith('site-packages/')}
        if actual != source_members:
            raise ArtifactError('license-obligation-missing', 'extracted output differs from source wheels, including LICENSE/NOTICE custody')
        if (not any(path.startswith('app/getzilla_factory/') for path in members)
                or any(not path.startswith(('app/getzilla_factory/', 'site-packages/')) for path in members)):
            raise ArtifactError('license-delivery-composition', 'archive has unknown contents outside the qualified Factory output')
        verified[context] = {'context': context, 'kind': delivery['kind'], 'profile': delivery['profile'],
                             'archive_sha256': archive_digest, 'manifest_sha256': manifest_digest,
                             'sidecar_sha256': hashlib.sha256(sidecar).hexdigest(),
                             'output_bytes': len(payload) + len(detached) + len(sidecar),
                             'components': sorted(component_ids), 'members': source_members}
    return verified
