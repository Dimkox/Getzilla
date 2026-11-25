"""Owner decision 2026-11-25. Classify scanner evidence at each evaluation."""
from __future__ import annotations


def blocks_vulnerability(row: dict) -> bool:
    # Unknown schemas, EOL notices and missing assessments require review.
    severity = row.get('severity')
    fixed = row.get('fixed')
    if not isinstance(severity, str) or not row.get('id') or not row.get('package') or not row.get('version'):
        return True
    if isinstance(fixed, str):
        versions = [fixed] if fixed else []
    elif isinstance(fixed, list):
        versions = fixed
    else:
        return True
    if any(not isinstance(v, str) or not v.strip() for v in versions):
        return True
    level = severity.upper()
    if level in {'LOW', 'MEDIUM', 'MODERATE'}:
        return False
    if level == 'UNKNOWN' and not versions:
        return False
    if level in {'CRITICAL', 'HIGH'}:
        return bool(versions)
    return True


def record_filesystem(image, rows, state):
    """Record installed path and byte identities from a verified OCI graph."""
    if state is None or state.get('images', {}).get(image.reference) is not image:
        return
    cache = state.setdefault('threshold_filesystems', {})
    if image.reference not in cache:
        files = {p: row['sha256'] for p, row in rows.items() if row['kind'] == 'file'}
        links = {p for p, row in rows.items() if row['kind'] in {'symlink', 'hardlink'}}
        cache[image.reference] = files, set(files.values()), links


def removed_from_finals(finding, inventory):
    from . import security_image_authority as authority
    state = authority._LIVE
    if (not state or authority._GUARD is None or state.get('native_guard') is not authority._GUARD
            or not inventory.get('complete') or state['declared_inventory'] != inventory):
        return False
    reference, path = finding.get('image'), finding.get('target')
    if not isinstance(path, str) or not path or any(p in {'', '.', '..'} for p in path.split('/')):
        return False
    uses = [u for u in inventory['images'] if u['reference'] == reference]
    recipes = {b['dockerfile'] for b in inventory['builds']}
    built = set(state['builds'].values())
    if not uses or not built or reference in built or any(u['manifest'] not in recipes for u in uses):
        return False
    # Check all other images conservatively, even other build inputs.
    cache = state.get('threshold_filesystems', {})
    if set(cache) != {u['reference'] for u in inventory['images']} or len(cache) < 2:
        return False
    original = cache[reference][0].get(path)
    if not original:
        return False
    ancestors = {'/'.join(path.split('/')[:n]) for n in range(1, len(path.split('/')) + 1)}
    return all(path not in files and original not in digests and not ancestors.intersection(links)
               for ref, (files, digests, links) in cache.items() if ref != reference)
