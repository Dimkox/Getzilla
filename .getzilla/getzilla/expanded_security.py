"""Applicable mandatory security obligations in the existing verifier contract.

Local results establish input integrity, coverage and scan outcomes. Independent
execution/acquisition authority is supplied by the protected CI/provider, never
by a candidate-written ``trusted`` field. No network is performed here.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .security_osv_snapshot import Dependency, VulnerabilityError, load_config, query_offline
from .security_data import CVE_ID, SOURCE_URLS, SecurityDataError, osv_decision_ids, read_snapshot
from .security_intelligence import IntelligenceError, enrich_findings, validate_epss, validate_kev
from .security_inventory import canonical_digest, collect_inventory, read_image_selection, declared_inventory

CHECK_FAMILIES = {
    'security-inventory': 'inventory', 'known-vulnerabilities': 'vulnerabilities',
    'security-kev': 'known-exploitation', 'security-epss': 'exploit-prediction',
    'security-malicious-packages': 'malicious-packages',
    'security-container-images': 'container-images',
}
_SOURCE_FIELDS = ('source_id', 'source_url', 'content_sha256', 'payload_size', 'acquisition', 'coverage')


def _clock(now: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if now is None else now
    if current.tzinfo is None or current.utcoffset() is None:
        raise SecurityDataError('security clock must be timezone-aware')
    return current.astimezone(timezone.utc)


def _database(root: Path, environ: dict[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    selected = env.get('GETZILLA_SECURITY_DB') or env.get('GETZILLA_OSV_DB')
    # The descriptor reader must see every named ancestor. Resolving a link
    # here would erase the boundary it is required to validate.
    return (Path(selected) if selected else root / '.getzilla/runtime/security-data').absolute()


def _database_name(root: Path, database: Path) -> str:
    try:
        return database.relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(database)


def _policy_digest(root: Path) -> str:
    return canonical_digest({'expanded_security_version': 2, 'checks': CHECK_FAMILIES})


def _read_source(database: Path, source_id: str, now: datetime) -> tuple[dict[str, Any], dict[str, Any]]:
    scopes = {source_id.removeprefix('osv:')} if source_id.startswith('osv:') else {'CVE'}
    payload, evidence = read_snapshot(database, source_id, now=now, required_scope=scopes)
    try:
        if source_id == 'kev':
            parsed = validate_kev(payload, now=now)
        elif source_id == 'epss':
            parsed = validate_epss(payload, now=now)
        elif source_id.startswith('osv:'):
            parsed = {'coverage': evidence['coverage']}
        else:
            raise SecurityDataError('source has no qualified body evaluator')
    except IntelligenceError as exc:
        raise SecurityDataError(str(exc)) from exc
    if parsed['coverage'] != evidence['coverage']:
        raise SecurityDataError('source body coverage differs from snapshot metadata')
    published = evidence['acquisition'].get('source_published_at')
    if published is not None and source_id in {'kev', 'epss'} and published != parsed['source_published_at']:
        raise SecurityDataError('source publication metadata differs from the actual payload')
    return parsed, {field: evidence[field] for field in _SOURCE_FIELDS}


def _source_descriptor(root: Path, database: Path, source_id: str, now: datetime) -> dict[str, Any]:
    named = _database_name(root, database)
    try:
        _, evidence = _read_source(database, source_id, now)
        return {'database': named, **evidence}
    except (OSError, SecurityDataError, ValueError):
        # Missing/invalid inputs stay declared in the plan. Age/error messages
        # are not part of its digest, so merely reading a plan cannot change it.
        return {'database': named, 'source_id': source_id, 'unavailable': True}


def _selection_authority(root, env):
    from .public_security_context import source_binding, ci_run_context
    from .security_tools import TRUSTED_ROOT
    from .public_security_context import current_context, validate_context
    with tempfile.TemporaryDirectory(prefix='selection-binding-', dir=Path(root).parent) as directory:
        source = source_binding(root, TRUSTED_ROOT, Path(directory))
    context = current_context()
    run = validate_context(context, source) if context is not None else ci_run_context(env)
    return source, run


def selected_inventory(root: Path, *, environ: dict[str, str] | None = None, now=None) -> dict[str, Any]:
    """Validate source/run/freshness at every native consumption, not declaration."""
    from .security_artifacts import MAX_INDEX_BYTES, read_file
    from .security_data import _json
    from .security_oci import source_bindings, validate_selection
    from .public_security_context import validate_selection_authority, validate_input_profile
    env = os.environ if environ is None else environ
    selected = env.get('GETZILLA_SECURITY_IMAGE_ARTIFACTS')
    declaration = env.get('GETZILLA_SECURITY_IMAGE_SELECTION')
    if not selected and not declaration:
        return collect_inventory(root)
    if declaration and not selected and 'GETZILLA_SECURITY_INPUT_PROFILE' not in env:
        # Preserve393's declaration-only API; it never grants scanner credit.
        return current_inventory(root, environ=env, now=now)
    selection = read_image_selection(Path(declaration)) if declaration else None
    catalog = None
    if selected:
        path = Path(selected).absolute()
        catalog = _json(read_file(path.parent, path.name, MAX_INDEX_BYTES))
    before, run = _selection_authority(root, env)
    validate_selection_authority(before, run, selection, now=now)
    inventory = (declared_inventory(root, selection) if selection is not None else
                 collect_inventory(root, image_bindings=source_bindings(catalog)))
    raw = env.get('GETZILLA_SECURITY_INPUT_PROFILE', '')
    if not isinstance(raw, str) or not raw or len(raw.encode()) > MAX_INDEX_BYTES:
        raise SecurityDataError('selected image current input profile absent or excessive')
    profile = _json(raw.encode())
    roots = {'database': str(_database(root, env)),
             'artifacts': str(Path(env.get('GETZILLA_SECURITY_ARTIFACTS') or root / '.getzilla/runtime/security-artifacts').absolute()),
             'tools': str(Path(env.get('GETZILLA_SECURITY_TOOLS') or root / '.getzilla/runtime/security-tools').absolute())}
    from .security_tools import TRUSTED_ROOT
    package_pins=None
    package_graphs=None
    if 'python_source_pins' in profile:
        from .security_python_target import source_pins,validate_target,closure_graphs
        package_pins=source_pins(root,inventory,validate_target(profile['python_target']))
        package_graphs=closure_graphs(root,inventory)
    package_ci_uses=None
    if 'python_ci_uses' in profile:
        from .security_image_authority import ci_use_observations
        package_ci_uses=ci_use_observations(root,inventory,before,run,package_graphs)
    validate_input_profile(profile, before, inventory, roots, run, _policy_digest(TRUSTED_ROOT),
                           now=now, image_artifacts=catalog, image_selection=selection,package_pins=package_pins,package_graphs=package_graphs,package_ci_uses=package_ci_uses)
    if catalog is not None:
        validate_selection(catalog, inventory, profile['image_profile'])
    after, after_run = _selection_authority(root, env)
    if after != before or after_run != run or (declaration and read_image_selection(Path(declaration)) != selection):
        raise SecurityDataError('image selection authority changed during native consumption')
    if selected and _json(read_file(path.parent, path.name, MAX_INDEX_BYTES)) != catalog:
        raise SecurityDataError('selected image catalog changed during native consumption')
    return inventory


def current_inventory(root: Path, *, environ=None, now=None) -> dict[str, Any]:
    """Revalidate native selection against current source/checker/run and age."""
    env = os.environ if environ is None else environ
    path = env.get('GETZILLA_SECURITY_IMAGE_SELECTION')
    selection = read_image_selection(Path(path)) if path else None
    if selection is None:
        return collect_inventory(root)
    from .public_security_context import validate_selection_authority
    before, run = _selection_authority(root, env)
    validate_selection_authority(before, run, selection, now=_clock(now))
    result = declared_inventory(root, selection)
    after, after_run = _selection_authority(root, env)
    validate_selection_authority(after, after_run, selection, now=_clock(now))
    if after != before or after_run != run or read_image_selection(Path(path)) != selection:
        raise SecurityDataError('image selection authority changed during native consumption')
    return result


def validate_data_source(binding: dict[str, Any], *, root: Path, now: datetime | None = None,
                          environ: dict[str, str] | None = None, policy_root: Path | None = None) -> bool:
    """Revalidate the exact frozen source and its current age at consumption."""
    if not isinstance(binding, dict) or set(binding) != {'database', *_SOURCE_FIELDS}:
        raise SecurityDataError('required source was unavailable or its binding is incomplete')
    root = Path(root).resolve()
    if binding['source_id'] == 'trivy-db':
        from .security_tools import tools_directory, trivy_database_source
        if trivy_database_source(tools_directory(root, environ), now=now) != binding:
            raise SecurityDataError('image database differs from the frozen required source')
        return True
    if not isinstance(binding['source_id'], str) or binding['source_id'] not in SOURCE_URLS:
        raise SecurityDataError('unsupported security data source')
    if not isinstance(binding['database'], str):
        raise SecurityDataError('invalid database binding')
    named = Path(binding['database'])
    selected = named if named.is_absolute() else root / named
    if selected.absolute() != _database(root, environ):
        raise SecurityDataError('snapshot database is not the caller-selected source')
    _, actual = _read_source(selected, binding['source_id'], _clock(now))
    if actual != {field: binding[field] for field in _SOURCE_FIELDS}:
        raise SecurityDataError('security source changed since the required plan was recorded')
    return True


def security_obligations(root: Path, inventory: dict[str, Any] | None = None, *,
                         environ: dict[str, str] | None = None, now: datetime | None = None,
                         policy_root: Path | None = None) -> list[dict[str, Any]]:
    root = Path(root).resolve()
    current = _clock(now)
    inventory = selected_inventory(root, environ=environ, now=now) if inventory is None else inventory
    database = _database(root, environ)
    dependencies, images, tools = inventory['dependencies'], inventory['images'], inventory['tools']
    unknown = not inventory['complete']
    source_ids = sorted({f'osv:{item["ecosystem"]}' for item in dependencies})
    descriptors = {name: _source_descriptor(root, database, name, current) for name in [*source_ids, 'kev', 'epss']}
    if images:
        from .security_tools import tools_directory, trivy_database_source
        tools_path = tools_directory(root, environ)
        try:
            descriptors['trivy-db'] = trivy_database_source(tools_path, now=current)
        except (OSError, ValueError, RuntimeError):
            descriptors['trivy-db'] = {'database': str(tools_path / 'cache/db/trivy.db'),
                                       'source_id': 'trivy-db', 'unavailable': True}
    applicability = {
        'security-inventory': True, 'known-vulnerabilities': bool(dependencies) or unknown,
        'security-kev': bool(dependencies or images) or unknown,
        'security-epss': bool(dependencies or images) or unknown,
        'security-malicious-packages': bool(dependencies) or unknown,
        'security-container-images': bool(images) or unknown,
    }
    image_sources = ['trivy-db'] if images else []
    feeds = {'known-vulnerabilities': source_ids, 'security-kev': ['kev', *source_ids, *image_sources],
             'security-epss': ['epss', *source_ids, *image_sources],
             'security-malicious-packages': source_ids, 'security-container-images': image_sources}
    evidence = {'schema_version': 1, 'inventory_sha256': inventory['digest'], 'complete': inventory['complete'],
                'policy_sha256': _policy_digest(policy_root or root), 'manifest_count': len(inventory['manifests']),
                'dependency_count': len(dependencies), 'image_count': len(images), 'tool_count': len(tools),
                'fixture_exclusions': inventory['excluded_fixture_paths']}
    return [
        {'id': name, 'check_id': name, 'requirement_ids': [],
         'applicability': 'required' if applicability[name] else 'not_applicable',
         'reason': 'applicable-or-unresolved-objects' if applicability[name] else 'complete-inventory-no-objects',
         'evidence': evidence, 'expected_tests': [],
         'data_sources': [descriptors[source] for source in feeds.get(name, [])] if applicability[name] else []}
        for name in CHECK_FAMILIES
    ]


def _dependencies(inventory: dict[str, Any]) -> list[Dependency]:
    return sorted({Dependency(item['ecosystem'], item['name'], item['version'], item['manifest'])
                   for item in inventory['dependencies']})


def known_vulnerability_report(root: Path, *, environ: dict[str, str] | None = None,
                               now: datetime | None = None, inventory: dict[str, Any] | None = None,
                               policy_root: Path | None = None) -> dict[str, Any]:
    """Qualifying offline scan of the complete derived inventory, including build inputs."""
    root = Path(root).resolve()
    current = _clock(now)
    inventory = selected_inventory(root, environ=environ, now=now) if inventory is None else inventory
    report: dict[str, Any] = {'status': 'fail', 'findings': [], 'accepted': [], 'source_evidence': [],
                              'dependencies': len(inventory['dependencies']), 'inventory_sha256': inventory['digest'],
                              'policy_sha256': _policy_digest(policy_root or root), 'assurance': 'local-input-integrity-only'}
    if not inventory['complete']:
        return {**report, 'summary': 'dependency/tool/image inventory is incomplete',
                'reason_code': 'inventory-incomplete', 'gaps': inventory['gaps']}
    if not inventory['dependencies']:
        return {**report, 'status': 'skip', 'summary': 'complete inventory contains no dependency objects',
                'reason_code': 'not-applicable'}
    try:
        database = _database(root, environ)
        evidence: list[dict[str, Any]] = []
        findings = query_offline(_dependencies(inventory), database, now=current, source_evidence=evidence)
        report['source_evidence'] = [{'database': _database_name(root, database),
                                     **{field: item[field] for field in _SOURCE_FIELDS}} for item in evidence]
        accepted = {str(item['id']): item['expires'] for item in load_config(policy_root or root)['accept']
                    if date.fromisoformat(item['expires']) >= current.date()}
        for finding in findings:
            expiry = next((accepted[item] for item in osv_decision_ids(finding.to_dict()) if item in accepted), None)
            if expiry is not None:
                finding.accepted_until = expiry
                report['accepted'].append(finding.to_dict())
            else:
                report['findings'].append(finding.to_dict())
        report.update(status='fail' if report['findings'] else 'pass',
                      reason_code='affected-finding' if report['findings'] else 'complete',
                      summary=f'{len(report["findings"])} unresolved known vulnerabilities; {len(report["accepted"])} time-limited exceptions')
    except (VulnerabilityError, SecurityDataError, OSError, ValueError) as exc:
        report.update(summary=str(exc), reason_code='data-unavailable')
    return report


def _result(name: str, outcome: str, summary: str, inventory: dict[str, Any], policy: str,
            *, sources=(), findings=(), gaps=()) -> dict[str, Any]:
    status = 'skip' if outcome == 'not_applicable' else 'pass' if outcome == 'pass' else 'fail'
    detail = {'schema_version': 1, 'kind': 'security-result', 'family': CHECK_FAMILIES[name],
              'outcome': outcome, 'reason_code': outcome.replace('_', '-'),
              'inventory_sha256': inventory['digest'], 'policy_sha256': policy,
              'data_sources': list(sources), 'findings': list(findings), 'gaps': list(gaps),
              'assurance': 'local-input-integrity-only'}
    if outcome == 'not_applicable':
        detail['applicability_evidence'] = {'complete': inventory['complete'], 'inventory_sha256': inventory['digest'],
                                          'reason': 'complete-inventory-no-objects'}
    return {'name': name, 'status': status, 'summary': summary, 'details': [detail]}


def known_vulnerability_check(root: Path, *, environ: dict[str, str] | None = None,
                              now: datetime | None = None, inventory: dict[str, Any] | None = None,
                              policy_root: Path | None = None) -> dict[str, Any]:
    """Keep the native verifier and isolated scanner on one complete evidence contract."""
    inventory = selected_inventory(root, environ=environ, now=now) if inventory is None else inventory
    report = known_vulnerability_report(root, environ=environ, now=now, inventory=inventory,
                                        policy_root=policy_root)
    outcome = ('not_applicable' if report['status'] == 'skip' else 'pass' if report['status'] == 'pass'
               else 'finding' if report['findings'] else 'blocked')
    result = _result('known-vulnerabilities', outcome, report['summary'], inventory, report['policy_sha256'],
                     sources=report['source_evidence'], findings=report['findings'], gaps=report.get('gaps', []))
    result['details'][0]['accepted'] = report['accepted']
    return result


def run_checks(root: Path, *, environ: dict[str, str] | None = None, now: datetime | None = None,
               inventory: dict[str, Any] | None = None, policy_root: Path | None = None) -> list[dict[str, Any]]:
    """Execute the six additional families; the verifier owns its existing OSV check."""
    root = Path(root).resolve()
    current = _clock(now)
    env = os.environ if environ is None else environ
    inventory = selected_inventory(root, environ=env, now=now) if inventory is None else inventory
    policy = _policy_digest(policy_root or root)
    obligations = {item['check_id']: item for item in security_obligations(root, inventory, environ=env, now=current,
                                                                        policy_root=policy_root)}
    results = [_result('security-inventory', 'pass' if inventory['complete'] else 'blocked',
                       f'{len(inventory["dependencies"])} dependency identities; {len(inventory["gaps"])} inventory gaps',
                       inventory, policy, gaps=inventory['gaps'])]
    database = _database(root, env)
    findings, source_evidence, query_error = [], [], None
    if inventory['dependencies'] and inventory['complete']:
        try:
            raw_evidence: list[dict[str, Any]] = []
            findings = [item.to_dict() for item in query_offline(_dependencies(inventory), database, now=current,
                                                               source_evidence=raw_evidence)]
            source_evidence = [{'database': _database_name(root, database),
                                **{field: item[field] for field in _SOURCE_FIELDS}} for item in raw_evidence]
        except (VulnerabilityError, SecurityDataError, OSError, ValueError) as exc:
            query_error = str(exc)
    image_scan = None
    if inventory['images'] and inventory['complete']:
        from .security_tools import scan_images, tools_directory
        image_scan = scan_images(inventory, environ={**env, 'GETZILLA_SECURITY_TOOLS': str(tools_directory(root, env))}, now=current)
    for name in ('security-kev', 'security-epss', 'security-malicious-packages', 'security-container-images'):
        obligation = obligations[name]
        if obligation['applicability'] == 'not_applicable':
            results.append(_result(name, 'not_applicable', 'complete source inventory proves no applicable objects', inventory, policy))
            continue
        if not inventory['complete']:
            results.append(_result(name, 'blocked', 'inventory incomplete; applicability cannot be waived', inventory, policy, gaps=inventory['gaps']))
            continue
        try:
            if name in {'security-kev', 'security-epss'}:
                source_id = 'kev' if name == 'security-kev' else 'epss'
                parsed, proof = _read_source(database, source_id, current)
                proof = {'database': _database_name(root, database), **proof}
                if query_error:
                    raise SecurityDataError('vulnerability identities unavailable: ' + query_error)
                if image_scan is not None and image_scan['outcome'] == 'blocked':
                    raise SecurityDataError('image vulnerability inventory is incomplete')
                all_findings = findings + (image_scan.get('findings', []) if image_scan else [])
                if image_scan:
                    all_findings += [f for image in image_scan.get('images', []) for f in image.get('accepted_evidence', [])]
                all_sources = [proof, *source_evidence, *(image_scan.get('data_sources', []) if image_scan else [])]
                if all_sources != obligation['data_sources']:
                    raise SecurityDataError('enrichment source changed since its required plan was derived')
                cves = sorted({value for finding in all_findings for value in osv_decision_ids(finding)
                               if CVE_ID.fullmatch(value)})
                if source_id == 'kev':
                    hits = [{'cve': identifier, **parsed['records'][identifier]} for identifier in cves if identifier in parsed['records']]
                    results.append(_result(name, 'finding' if hits else 'pass',
                                           f'{len(hits)} active KEV matches; generic OSV waivers do not clear KEV',
                                           inventory, policy, sources=all_sources, findings=hits))
                else:
                    empty_kev = {'records': {}}
                    enriched = enrich_findings(all_findings, empty_kev, parsed)
                    results.append(_result(name, 'pass', 'EPSS forecast is current; unscored CVEs remain unknown',
                                           inventory, policy, sources=all_sources, findings=enriched))
            elif name == 'security-malicious-packages':
                if query_error:
                    raise SecurityDataError(query_error)
                hits = [item for item in findings if any(value.startswith('MAL-') for value in osv_decision_ids(item))]
                results.append(_result(name, 'finding' if hits else 'pass',
                                       f'{len(hits)} active malicious-package catalog matches in complete OSV ecosystem snapshots',
                                       inventory, policy, sources=source_evidence, findings=hits))
            else:
                if image_scan is None:
                    raise SecurityDataError('no image scan covered the required image inventory')
                report = image_scan
                if report.get('data_sources', []) != obligation['data_sources']:
                    raise SecurityDataError('image database changed since the required plan was derived')
                check = _result(name, report['outcome'], report['summary'], inventory, policy,
                                sources=report.get('data_sources', []), findings=report.get('findings', []), gaps=report.get('gaps', []))
                if any(image.get('accepted_evidence') for image in report.get('images', [])):
                    from .security_dind_exception import DECISION
                    check['details'][0]['dind_exception'] = [dict(DECISION)]
                results.append(check)
        except (ImportError, OSError, ValueError, RuntimeError) as exc:
            results.append(_result(name, 'blocked', str(exc), inventory, policy,
                                   sources=obligation['data_sources'], gaps=[{'code': 'required-input-unavailable', 'message': str(exc)}]))
    return results


def artifact_catalog_source(inventory: dict, artifacts: Path, policy: dict, *, now: datetime | None = None,
                            target_binding: dict | None = None) -> dict:
    """Freeze actual catalog bytes for final-receipt revalidation, without policy PASS.

    Recompute at receipt consumption and compare the whole source projection.
    Coverage.complete describes only the structural completeness of this
    manifest's referenced records. It never claims complete dependency, tool,
    image, license or distribution coverage. evaluate_artifacts supplies those
    decisions independently. Hashes and unsigned timestamps supply integrity
    bindings only; external runner qualification supplies independent authority.

    The returned projection stays stable while bytes, inventory, policy and the
    original acquisition time stay unchanged. Clock validation runs on every
    call; copying a catalog cannot renew its 72-hour lifetime. Missing or
    inconsistent references raise ArtifactError; an invalid clock may raise
    SecurityDataError. Callers must map either exception to unavailable.
    """
    from . import security_license_contracts as _catalog_policy
    import json
    import re
    from .security_artifacts import (ArtifactError, MAX_INDEX_BYTES, MAX_ARTIFACT_BYTES,
                                     artifact_identity, read_file, verify_origin, family_evidence, _json)
    from .security_data import MAX_AGE_SECONDS, SecurityDataError, _clock, _timestamp
    from .security_deliveries import verify_deliveries
    try:
        digest = inventory.get('digest') if isinstance(inventory, dict) else None
        if not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None:
            raise ArtifactError('artifact-inventory-binding', 'catalog needs the exact source inventory digest')
        selected_policy = _catalog_policy._policy(policy)
        if target_binding is not None:
            from .security_python_target import _binding
            _binding(target_binding)
            if target_binding['inventory_sha256'] != digest:
                raise ArtifactError('artifact-inventory-binding', 'Python target belongs to another source inventory')
        current = _clock(now)
        raw = read_file(artifacts, 'manifest.json', MAX_INDEX_BYTES)
        bundle = _json(raw)
        if type(bundle.get('schema_version')) is not int or bundle['schema_version'] != 1 or bundle.get('inventory_digest') != digest:
            raise ArtifactError('artifact-inventory-binding', 'catalog schema or source inventory binding differs')
        acquired = bundle.get('last_verified_sync_utc')
        age = (current - _timestamp(acquired)).total_seconds()
        if age < 0 or age > MAX_AGE_SECONDS:
            raise ArtifactError('artifact-stale', 'catalog acquisition is future-dated or older than 72 hours')
        records = bundle.get('records')
        if not isinstance(records, list) or not records or len(records) > 10000 or not all(isinstance(record, dict) for record in records):
            raise ArtifactError('artifact-manifest', 'catalog has no bounded complete records')
        bindings, seen, total = [], set(), len(raw)
        for record in records:
            key = artifact_identity(record)
            if key in seen:
                raise ArtifactError('artifact-manifest', 'catalog repeats a package artifact identity')
            seen.add(key)
            if 'kind' in record:
                subjects = inventory.get('images' if record['kind'] == 'image' else 'tools', [])
                if record['subject'] not in subjects:
                    raise ArtifactError('artifact-inventory-binding', 'family does not belong to the current source inventory')
                _catalog_policy._family_age(record, current, acquired)
                evidence = family_evidence(artifacts, record)
                total += evidence['bound_bytes']
                if total > 512 * 1024 * 1024:
                    raise ArtifactError('artifact-size', 'catalog exceeds the aggregate bound-byte budget')
                bindings.append(evidence['binding'])
                continue
            origin = record.get('origin')
            if not isinstance(origin, dict):
                raise ArtifactError('artifact-origin', 'catalog record lacks its saved registry index')
            if 'acquired_at' in record:
                _catalog_policy._family_age(record, current, acquired)
            payload = read_file(artifacts, record.get('path'), MAX_ARTIFACT_BYTES)
            index = read_file(artifacts, origin.get('index_path'), MAX_INDEX_BYTES)
            verified = verify_origin(artifacts, record, payload, index_bytes=index)
            observed = None
            if record['ecosystem'] == 'PyPI' and (target_binding is not None or 'python_target' in record):
                from .security_python_target import verify_record
                observed = verify_record(record,payload,target_binding)
            bound = {'ecosystem': record['ecosystem'], 'name': record['name'], 'version': record['version'],
                     'path': record['path'], 'filename': record['filename'], 'artifact_size': len(payload),
                     'artifact_id': key, 'context': record.get('context', {}),
                     'index_path': origin['index_path'], 'index_size': len(index), **verified}
            if observed is not None:
                bound['python_target'] = observed
            total += len(payload) + len(index)
            if record.get('redistributed_path') is not None:
                delivered = read_file(artifacts, record['redistributed_path'], MAX_ARTIFACT_BYTES)
                delivery_digest = hashlib.sha256(delivered).hexdigest()
                if delivery_digest != verified['artifact_sha256']:
                    raise ArtifactError('artifact-hash', 'catalog delivered artifact bytes no longer match')
                bound['delivery'] = {'path': record['redistributed_path'], 'sha256': delivery_digest, 'size': len(delivered)}
                total += len(delivered)
            if total > 512 * 1024 * 1024:
                raise ArtifactError('artifact-size', 'catalog exceeds the aggregate bound-byte budget')
            bindings.append(bound)
        deliveries = verify_deliveries(artifacts, bundle.get('deliveries', []), records, inventory.get('dependencies', []),
            corresponding_source_delivery=inventory.get('corresponding_source_delivery'))
        total += sum(delivery['output_bytes'] for delivery in deliveries.values())
        if total > 512 * 1024 * 1024:
            raise ArtifactError('artifact-size', 'catalog and delivered outputs exceed the aggregate bound-byte budget')
        # Also bind the supplied input contents: a caller changing an input
        # while retaining its old digest must not obtain the same projection.
        inventory_body = json.dumps(inventory, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(inventory_body) > MAX_INDEX_BYTES:
            raise ArtifactError('artifact-size', 'source inventory exceeds its byte budget')
        binding = {'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'inventory_digest': digest,
                   'inventory_content_sha256': hashlib.sha256(inventory_body).hexdigest(),
                   'policy_digest': selected_policy['digest'],
                   'records': sorted(bindings, key=lambda item: item['artifact_id']),
                   'deliveries': deliveries}
        if target_binding is not None and 'factory_inputs' in target_binding:
            from .security_factory_inputs import verify
            auxiliary=verify(artifacts,target_binding,selected_policy,now=now)
            binding['factory_output']=auxiliary['projection']
            total+=auxiliary['projection']['payload_size']
            if total>512*1024*1024:
                raise ArtifactError('artifact-size','catalog and Factory output exceed the shared aggregate byte budget')
        if target_binding is not None and 'ci_uses' in target_binding and 'ci_consumer' not in target_binding:
            from .security_ci_inputs import verify as verify_ci
            binding['ci_installations']=[]
            for index,consumer in enumerate(target_binding['ci_uses']['consumers']):
                if consumer.get('image_target_observed') is not True:
                    continue
                auxiliary=verify_ci(artifacts,target_binding,index,selected_policy,now=now)
                binding['ci_installations'].append(auxiliary['projection'])
                total+=auxiliary['projection']['payload_size']
                if total>512*1024*1024:
                    raise ArtifactError('artifact-size','CI installations exceed the shared package byte budget')
        if target_binding is not None and 'ci_uses' in target_binding:
            from .security_python_target import digest as python_digest
            binding['ci_use_observation_sha256']=python_digest(target_binding['ci_uses'])
        content = json.dumps(binding, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        return {'database': str(Path(artifacts).absolute()), 'source_id': 'artifact-license-catalog',
                'source_url': 'urn:getzilla:artifact-license-catalog:1',
                'content_sha256': hashlib.sha256(content).hexdigest(), 'payload_size': total,
                'acquisition': {'last_verified_sync_utc': acquired, 'retrieval_kind': 'catalog-binding',
                                'producer': 'getzilla-artifact-catalog-v1'},
                'coverage': {'schema': 'artifact-license-catalog-1', 'scopes': ['catalog'],
                             'record_count': len(bindings), 'complete': True}}
    except (ArtifactError, SecurityDataError):
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise ArtifactError('artifact-catalog-unavailable', str(exc)) from exc
