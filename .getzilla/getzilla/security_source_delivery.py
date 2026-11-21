"""Exact finite legal payload expectations; never publisher or license approval.

Only the source-bound Factory declaration can carry these expectations. Artifact
bundles cannot choose an allowlist. Actual wheel origins remain separately checked.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from time import monotonic

from . import security_corresponding_source as source
from .security_artifacts import normalize_name

CHECKER_ROOT = Path(__file__).resolve().parents[2]
TERMS = {
    'certifi': (
        ('certifi-2026.10.19-notice.txt', 'legal/notices/certifi-2026.10.19.txt',
         'c51aabdbd8f75029406cb74b07644deafe9822019bf85e4f5a4e201690e09f15'),
        ('MPL-2.0.txt', 'legal/licenses/MPL-2.0.txt',
         '3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04')),
    'psycopg': (
        ('psycopg-3.3.4-notice.txt', 'legal/notices/psycopg-3.3.4.txt',
         'f595e1af82fd7f397b753a9ffa35a0d65f078d8ee2a9d7ea5ed1cdc67d4f755d'),
        ('GPL-3.0.txt', 'legal/licenses/GPL-3.0.txt',
         '3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986')),
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def subject_name(name):
    return normalize_name('PyPI',name) if type(name) is str else None


def wheel_rows(dependencies):
    return [{'name': subject_name(dep['name']), 'version': dep['version'], 'filename': dep['artifact_filename'],
             'sha256': dep['artifact_sha256']} for dep in dependencies]


def fixed_delivery(root, wheels, *, deadline=None):
    """Independently reconstruct the fixed builder's exact legal payload identities.

    This verifies fixed source bytes, not source execution role or installed wheels.
    """
    if not isinstance(wheels, list) or len(wheels) > 512:
        raise ValueError('source delivery needs bounded wheel identities')
    selected = [{**w,'name':subject_name(w.get('name'))} for w in wheels
                if subject_name(w.get('name')) in source.CATALOG]
    if not selected:
        return None
    if len({w['name'] for w in selected}) != len(selected):
        raise ValueError('source delivery has duplicate wheel subjects')
    if deadline is None:
        deadline = monotonic() + source.MAX_SECONDS
    bodies, packages, mapping = {}, [], []
    for wheel in sorted(selected, key=lambda w: w['name']):
        name = wheel['name']
        version, snapshot_hash, map_hash, wheel_hash = source.CATALOG[name]
        stem = name + '-' + version
        if wheel != {'name': name, 'version': version, 'filename': stem + '-py3-none-any.whl', 'sha256': wheel_hash}:
            raise ValueError('source delivery wheel identity differs from fixed subject')
        snapshot, provenance, repack, _prefix = source._source_payload(root, name, deadline=deadline)
        target = 'legal/sources/' + stem + '.tar.gz'
        bodies[target] = repack
        delivery = {'path': target, 'sha256': _sha(repack), 'bytes': len(repack),
                    'representation': 'canonical-repack-of-unchanged-source',
                    'snapshot_manifest_sha256': snapshot_hash,
                    'original_publisher_archive_sha256': snapshot['original_publisher_archive']['sha256']}
        retained = [{key: delivery[key] for key in ('path', 'sha256', 'bytes')}]
        for filename, target, digest in TERMS[name]:
            raw, mode = source._read(root, source.LEGAL + filename, deadline=deadline)
            if _sha(raw) != digest or mode != 0o644 or target in bodies:
                raise ValueError('original legal text identity or mode differs')
            bodies[target] = raw
            retained.append({'path': target, 'sha256': digest, 'bytes': len(raw)})
        mapping.append({**provenance, 'source_delivery': delivery, 'retained_files': retained})
        packages.append({**wheel, 'snapshot_sha256': snapshot_hash, 'source_map_sha256': map_hash,
                         'original_publisher_archive': snapshot['original_publisher_archive']})
    bodies['legal/source-map.json'] = json.dumps({'schema_version': 1, 'packages': mapping},
                                                 sort_keys=True, separators=(',', ':')).encode()
    project_license, project_mode = source._read(root,'LICENSE',deadline=deadline)
    if project_mode != 0o644:
        raise ValueError('project license source mode differs')
    bodies['legal/project/LICENSE'] = project_license
    result = {'schema_version': 1, 'kind': 'factory-corresponding-source-delivery',
            'source_surface_sha256': source.SURFACE_SHA256, 'packages': packages,
            'members': [{'path': path, 'size': len(raw), 'sha256': _sha(raw), 'mode': 0o644}
                        for path, raw in sorted(bodies.items())]}
    source._budget(deadline)
    return result


def admitted_delivery(root, inventory, wheels):
    """Rederive exact source-role admission; caller declarations cannot substitute it."""
    if not any(subject_name(w.get('name')) in source.CATALOG for w in wheels):
        return None
    from .security_osv_snapshot import _tracked_files
    deadline = monotonic() + source.MAX_SECONDS
    rows = source.classify(root, _tracked_files(root), deadline=deadline)
    if not rows or inventory.get('corresponding_sources') != rows:
        raise ValueError('source delivery has no current source-role admission')
    return fixed_delivery(root, wheels, deadline=deadline)


def _same(actual, expected):
    # Traverse only the fixed expected shape, never arbitrary caller nesting.
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(_same(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(_same(a, b) for a, b in zip(actual, expected))
    return actual == expected


def validate_proof(proof, wheels, *, checker=CHECKER_ROOT, deadline=None):
    """Compare the complete closed proof with fixed trusted checker source bytes."""
    if deadline is None:
        deadline = monotonic() + source.MAX_SECONDS
    expected = fixed_delivery(checker, wheels, deadline=deadline)
    if not _same(proof, expected):
        raise ValueError('source delivery proof differs from trusted exact expectations')
    source._budget(deadline)
    return expected


def verify_members(proof, wheels, members, modes, declared_modes, *, checker=CHECKER_ROOT):
    """Join actual final legal bytes and modes to already verified wheel identities."""
    deadline = monotonic() + source.MAX_SECONDS
    expected = validate_proof(proof, wheels, checker=checker, deadline=deadline)
    if expected is None:
        return {}
    identities = {m['path']: {'size': m['size'], 'sha256': m['sha256']} for m in expected['members']}
    actual_legal = {path for path in members if path.startswith('legal/')}
    if actual_legal != set(identities):
        raise ValueError('actual legal member set differs from fixed source delivery')
    for row in expected['members']:
        source._budget(deadline)
        path = row['path']
        if (members.get(path) != identities[path] or type(modes.get(path)) is not int
                or type(declared_modes.get(path)) is not int or modes.get(path) != row['mode']
                or declared_modes.get(path) != row['mode']):
            raise ValueError('required corresponding-source legal body missing or changed')
    source._budget(deadline)
    return identities
