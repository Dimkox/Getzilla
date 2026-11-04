"""Applicable mandatory security obligations in the existing verifier contract.

Local results establish input integrity, coverage and scan outcomes. Independent
execution/acquisition authority is supplied by the protected CI/provider, never
by a candidate-written ``trusted`` field. No network is performed here.
"""
from __future__ import annotations

import hashlib
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .known_vulns import Dependency, VulnerabilityError, load_config, query_offline
from .security_data import SecurityDataError, read_snapshot
from .security_intelligence import IntelligenceError, enrich_findings, validate_epss, validate_kev
from .security_inventory import canonical_digest, collect_inventory

CHECK_FAMILIES = {
    'security-inventory': 'inventory', 'known-vulnerabilities': 'vulnerabilities',
    'security-kev': 'known-exploitation', 'security-epss': 'exploit-prediction',
    'security-malicious-packages': 'malicious-packages', 'security-licenses': 'licenses',
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
    path = root / '.getzilla/config/license-policy.json'
    if not path.exists():
        return canonical_digest({'license_policy': 'absent', 'expanded_security_version': 1})
    if path.is_symlink() or path.stat().st_size > 65536:
        return canonical_digest({'license_policy': 'invalid', 'expanded_security_version': 1})
    return canonical_digest({'license_policy_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                             'expanded_security_version': 1})


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
    if binding['source_id'] == 'artifact-license-catalog':
        from .security_licenses import artifact_catalog_source, load_policy
        env = os.environ if environ is None else environ
        artifacts = Path(env.get('GETZILLA_SECURITY_ARTIFACTS') or root / '.getzilla/runtime/security-artifacts')
        proof = artifact_catalog_source(collect_inventory(root), artifacts, load_policy(policy_root or root), now=now)
        if proof != binding:
            raise SecurityDataError('license catalog differs from the frozen required source')
        return True
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
    inventory = collect_inventory(root) if inventory is None else inventory
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
    if dependencies or images or tools or unknown:
        from .security_licenses import artifact_catalog_source, load_policy
        env = os.environ if environ is None else environ
        artifacts = Path(env.get('GETZILLA_SECURITY_ARTIFACTS') or root / '.getzilla/runtime/security-artifacts')
        try:
            descriptors['artifact-license-catalog'] = artifact_catalog_source(
                inventory, artifacts, load_policy(policy_root or root), now=current)
        except (OSError, ValueError, RuntimeError):
            descriptors['artifact-license-catalog'] = {'database': str(artifacts.absolute()),
                                                       'source_id': 'artifact-license-catalog', 'unavailable': True}
    applicability = {
        'security-inventory': True, 'known-vulnerabilities': bool(dependencies) or unknown,
        'security-kev': bool(dependencies or images) or unknown,
        'security-epss': bool(dependencies or images) or unknown,
        'security-malicious-packages': bool(dependencies) or unknown,
        'security-licenses': bool(dependencies or images or tools) or unknown,
        'security-container-images': bool(images) or unknown,
    }
    image_sources = ['trivy-db'] if images else []
    feeds = {'known-vulnerabilities': source_ids, 'security-kev': ['kev', *source_ids, *image_sources],
             'security-epss': ['epss', *source_ids, *image_sources],
             'security-malicious-packages': source_ids, 'security-container-images': image_sources,
             'security-licenses': ['artifact-license-catalog']}
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
    inventory = collect_inventory(root) if inventory is None else inventory
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
            expiry = next((accepted[item] for item in (finding.vuln_id, *finding.aliases) if item in accepted), None)
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
    inventory = collect_inventory(root) if inventory is None else inventory
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
    inventory = collect_inventory(root) if inventory is None else inventory
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
    for name in ('security-kev', 'security-epss', 'security-malicious-packages', 'security-licenses', 'security-container-images'):
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
                all_sources = [proof, *source_evidence, *(image_scan.get('data_sources', []) if image_scan else [])]
                if all_sources != obligation['data_sources']:
                    raise SecurityDataError('enrichment source changed since its required plan was derived')
                cves = sorted({value for finding in all_findings for value in [finding['id'], *finding.get('aliases', [])]
                               if isinstance(value, str) and value.startswith('CVE-')})
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
                hits = [item for item in findings if any(value.startswith('MAL-') for value in [item['id'], *item.get('aliases', [])])]
                results.append(_result(name, 'finding' if hits else 'pass',
                                       f'{len(hits)} active malicious-package catalog matches in complete OSV ecosystem snapshots',
                                       inventory, policy, sources=source_evidence, findings=hits))
            elif name == 'security-licenses':
                from .security_licenses import artifact_catalog_source, evaluate_artifacts, load_policy
                artifacts = Path(env.get('GETZILLA_SECURITY_ARTIFACTS') or root / '.getzilla/runtime/security-artifacts')
                license_policy = load_policy(policy_root or root)
                report = evaluate_artifacts(inventory, artifacts, license_policy, now=current)
                outcome = 'pass' if report['status'] == 'pass' else 'blocked'
                proof = artifact_catalog_source(inventory, artifacts, license_policy, now=current)
                if [proof] != obligation['data_sources']:
                    raise SecurityDataError('license artifact inputs changed during evaluation')
                results.append(_result(name, outcome, report['summary'], inventory, policy,
                                       sources=[proof], findings=report.get('details', []), gaps=report.get('gaps', [])))
            else:
                if image_scan is None:
                    raise SecurityDataError('no image scan covered the required image inventory')
                report = image_scan
                if report.get('data_sources', []) != obligation['data_sources']:
                    raise SecurityDataError('image database changed since the required plan was derived')
                results.append(_result(name, report['outcome'], report['summary'], inventory, policy,
                                       sources=report.get('data_sources', []), findings=report.get('findings', []), gaps=report.get('gaps', [])))
        except (ImportError, OSError, ValueError, RuntimeError) as exc:
            results.append(_result(name, 'blocked', str(exc), inventory, policy,
                                   sources=obligation['data_sources'], gaps=[{'code': 'required-input-unavailable', 'message': str(exc)}]))
    from .security_licenses import attach_factory_offline_intent, factory_offline_intent, load_policy
    for check in results:
        if check.get('name') == 'security-licenses':
            attach_factory_offline_intent(check, factory_offline_intent(root, load_policy(policy_root or root)))
    return results
