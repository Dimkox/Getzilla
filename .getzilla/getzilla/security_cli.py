"""Expanded security entry point for a separately selected checker checkout.

The caller chooses that checkout by an externally reviewed commit. This module
cannot promote its own report into provider or human authority. It accepts a
candidate only as source data, never imports it, and keeps all eleven outcomes.
"""
from __future__ import annotations

import argparse
import json
import re
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .expanded_security import CHECK_FAMILIES, _policy_digest, known_vulnerability_check, run_checks, security_obligations
from .python_test_runner import execute
from .security_acquisition import _atomic, provision_tools, refresh_feeds
from .security_data import MAX_AGE_SECONDS, SOURCE_URLS, SecurityDataError, _coverage, _acquisition
from .security_inventory import collect_inventory
from .security_license_acquisition import acquire_pypi
from .security_licenses import ALLOWED, _select_expression, _repository_identity
from .security_tools import TRUSTED_ROOT, TRIVY_DB_URL, _environment, refresh_images, scan_source

REQUIRED_CHECKS = ('security-inventory', 'known-vulnerabilities', 'security-kev', 'security-epss',
                   'security-malicious-packages', 'security-licenses', 'security-container-images',
                   'opengrep', 'secret-scan', 'bandit', 'trivy-config')


def _clock(now=None):
    current = datetime.now(timezone.utc) if now is None else now
    if current.tzinfo is None or current.utcoffset() is None:
        raise SecurityDataError('timezone-aware security clock required')
    return current.astimezone(timezone.utc)


def _git(root: Path, arguments: list[str], scratch: Path) -> str:
    result = execute(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', str(root), *arguments],
                     scratch, _environment(scratch), timeout=30)
    if result.returncode or result.terminal_state != 'completed' or result.cleanup_error:
        raise SecurityDataError('cannot establish source identity using a completed Git observation')
    return result.stdout.strip()


def source_binding(root: Path, checker: Path, scratch: Path) -> dict:
    values = []
    for project in (root, checker):
        identity = _git(project, ['rev-parse', 'HEAD', 'HEAD^{tree}'], scratch).splitlines()
        if len(identity) != 2 or not all(re.fullmatch(r'[a-f0-9]{40}', value) for value in identity):
            raise SecurityDataError('exact commit and tree identity required')
        clean = not _git(project, ['status', '--porcelain=v1', '--untracked-files=all'], scratch)
        repository = _repository_identity(_git(project, ['remote', 'get-url', 'origin'], scratch))
        values.append((identity, clean, repository))
    return {'head_sha': values[0][0][0], 'tree_sha': values[0][0][1],
            'checker_sha': values[1][0][0], 'checker_tree_sha': values[1][0][1],
            'candidate_clean': values[0][1], 'checker_clean': values[1][1],
            'same_project': bool(values[0][2] and values[1][2] and values[0][2].lower() == values[1][2].lower())}


def _check(name: str, outcome: str, summary: str, inventory: dict, policy: str,
           *, sources=(), findings=(), gaps=(), extra=None) -> dict:
    detail = {'kind': 'security-result', 'schema_version': 1, 'outcome': outcome,
              'inventory_sha256': inventory['digest'], 'policy_sha256': policy,
              'data_sources': list(sources), 'findings': list(findings), 'gaps': list(gaps),
              'assurance': 'local-input-integrity-only'}
    if extra:
        detail.update(extra)
    if outcome == 'not_applicable':
        detail['applicability_evidence'] = {'complete': inventory['complete'], 'inventory_sha256': inventory['digest'],
                                          'reason': 'complete-inventory-no-objects'}
    return {'name': name, 'status': 'pass' if outcome == 'pass' else 'skip' if outcome == 'not_applicable' else 'fail',
            'summary': summary, 'details': [detail]}



def _digest(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _source_valid(source: dict) -> bool:
    if not isinstance(source, dict) or set(source) != {'database', 'source_id', 'source_url',
            'content_sha256', 'payload_size', 'acquisition', 'coverage'}:
        return False
    identifier = source['source_id']
    urls = {**SOURCE_URLS, 'trivy-db': TRIVY_DB_URL,
            'artifact-license-catalog': 'urn:getzilla:artifact-license-catalog:1'}
    if (not isinstance(identifier, str) or identifier not in urls or source['source_url'] != urls[identifier]
            or not isinstance(source['database'], str) or not source['database']
            or not _digest(source['content_sha256']) or type(source['payload_size']) is not int
            or source['payload_size'] <= 0 or not isinstance(source['acquisition'], dict)):
        return False
    try:
        acquisition = source['acquisition']
        if identifier == 'artifact-license-catalog':
            required = {'last_verified_sync_utc', 'retrieval_kind'}
            if (not required <= set(acquisition) <= required | {'producer', 'source_revision', 'source_published_at'}
                    or acquisition['retrieval_kind'] != 'catalog-binding'):
                return False
        else:
            _acquisition(acquisition)
        coverage = _coverage(source['coverage'])
        scope = identifier.removeprefix('osv:') if identifier.startswith('osv:') else {
            'kev':'CVE', 'epss':'CVE', 'trivy-db':'container-images', 'artifact-license-catalog':'catalog'}[identifier]
        return scope in coverage['scopes'] and coverage['record_count'] > 0
    except (SecurityDataError, KeyError, TypeError):
        return False


def _findings_consistent(name: str, detail: dict, current: datetime) -> bool:
    findings, accepted = detail['findings'], detail.get('accepted', [])
    if name == 'known-vulnerabilities':
        fields = {'ecosystem', 'package', 'version', 'manifest', 'id', 'aliases', 'summary',
                  'severity', 'fixed', 'accepted_until'}
        if findings or not isinstance(accepted, list):
            return False
        for finding in accepted:
            if (not isinstance(finding, dict) or set(finding) != fields
                    or not all(isinstance(finding.get(k), str) and finding[k] for k in
                               ('ecosystem', 'package', 'version', 'manifest', 'id', 'accepted_until'))
                    or not all(isinstance(finding.get(k), list) and all(isinstance(v, str) for v in finding[k])
                               for k in ('aliases', 'fixed'))):
                return False
            try:
                if date.fromisoformat(finding['accepted_until']) < current.date():
                    return False
            except ValueError:
                return False
        return True
    if name == 'secret-scan':
        fields = {'rule', 'path', 'line', 'column', 'file_sha256', 'disposition'}
        return all(isinstance(f, dict) and fields <= set(f) <= fields | {'byte_offset'}
                   and f['rule'] == 'generic-secret' and _digest(f['file_sha256'])
                   and isinstance(f['disposition'], str)
                   and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', f['disposition']) is not None
                   and isinstance(f['path'], str) and type(f['line']) is int and f['line'] > 0
                   and type(f['column']) is int and f['column'] > 0 for f in findings)
    if name == 'security-epss':
        fields = {'ecosystem', 'package', 'version', 'manifest', 'id', 'aliases', 'summary', 'severity',
                  'fixed', 'accepted_until', 'image', 'target', 'intelligence', 'enrichment_reason'}
        return all(isinstance(f, dict) and not set(f) - fields and isinstance(f.get('id'), str)
                   and isinstance(f.get('intelligence'), dict) and isinstance(f.get('aliases'), list)
                   and f.get('enrichment_reason') in {'cve-aliases', 'no-cve-alias'} for f in findings)
    if name == 'security-licenses':
        fields = {'ecosystem', 'package', 'version', 'manifest', 'status', 'expression', 'selected_expression',
                  'distribution', 'artifact_sha256', 'origin', 'license_files', 'notice_files', 'obligations'}
        for finding in findings:
            if (not isinstance(finding, dict) or not fields <= set(finding) <= fields | {'artifact_id', 'context', 'delivery'}
                    or finding['status'] != 'pass' or finding['distribution'] not in {'internal', 'redistributed'}
                    or not _digest(finding['artifact_sha256']) or not isinstance(finding['license_files'], list)
                    or not finding['license_files'] or not isinstance(finding['notice_files'], list)):
                return False
            try:
                selected, _ = _select_expression(finding['selected_expression'], list(ALLOWED))
                chosen, _ = _select_expression(finding['expression'], selected)
                if (finding['selected_expression'] != ' AND '.join(selected)
                        or set(chosen) != set(selected)):
                    return False
            except ValueError:
                return False
            if any(not isinstance(f, dict) or not _digest(f.get('sha256'))
                   for f in finding['license_files'] + finding['notice_files']):
                return False
        return True
    return not findings


def _detail_consistent(name: str, detail: dict, inventory: str, policy: str, current: datetime) -> bool:
    required = {'kind', 'schema_version', 'outcome', 'inventory_sha256', 'policy_sha256',
                'data_sources', 'findings', 'gaps', 'assurance'}
    extra = {'family', 'reason_code', 'applicability_evidence'}
    extra |= ({'accepted'} if name == 'known-vulnerabilities' else
              {'factory_offline_use'} if name == 'security-licenses' else
              {'binary_inputs'} if name == 'secret-scan' else
              {'coverage'} if name in {'opengrep', 'bandit', 'trivy-config'} else set())
    if (not required <= set(detail) <= required | extra or type(detail.get('schema_version')) is not int
            or detail['schema_version'] != 1 or detail['kind'] != 'security-result'
            or detail['inventory_sha256'] != inventory
            or detail['policy_sha256'] != policy or detail['assurance'] != 'local-input-integrity-only'
            or detail.get('family', CHECK_FAMILIES.get(name, name)) != CHECK_FAMILIES.get(name, name)
            or any(not isinstance(detail[k], list) for k in ('data_sources', 'findings', 'gaps'))
            or detail['gaps']):
        return False
    if detail['outcome'] == 'not_applicable':
        return not detail['findings'] and not detail['data_sources'] and not detail.get('accepted')
    if ('applicability_evidence' in detail or detail['outcome'] != 'pass'
            or not _findings_consistent(name, detail, current)):
        return False
    identifiers = [s.get('source_id') for s in detail['data_sources'] if isinstance(s, dict)]
    if (len(identifiers) != len(detail['data_sources']) or any(not isinstance(i, str) for i in identifiers)
            or len(identifiers) != len(set(identifiers)) or not all(_source_valid(s) for s in detail['data_sources'])):
        return False
    allowed = ({'kev', 'trivy-db'} if name == 'security-kev' else
               {'epss', 'trivy-db'} if name == 'security-epss' else
               {'artifact-license-catalog'} if name == 'security-licenses' else
               {'trivy-db'} if name == 'security-container-images' else set())
    osv_family = name in {'known-vulnerabilities', 'security-malicious-packages', 'security-kev', 'security-epss'}
    if any(i not in allowed and not (osv_family and i.startswith('osv:')) for i in identifiers):
        return False
    required_source = {'known-vulnerabilities':'osv:', 'security-malicious-packages':'osv:',
                       'security-kev':'kev', 'security-epss':'epss',
                       'security-licenses':'artifact-license-catalog', 'security-container-images':'trivy-db'}.get(name)
    if required_source and not any(i.startswith('osv:') if required_source == 'osv:' else i == required_source
                                   for i in identifiers):
        return False
    if name in {'opengrep', 'bandit', 'trivy-config'}:
        coverage = detail.get('coverage')
        if (not isinstance(coverage, dict) or set(coverage) != {'expected', 'observed'}
                or any(not isinstance(coverage[k], list) or not all(isinstance(p, str) and p for p in coverage[k])
                       for k in ('expected', 'observed')) or not coverage['expected']
                or not set(coverage['expected']) <= set(coverage['observed'])):
            return False
    return True


def finalize_report(before: dict, after: dict, checks: list[dict], inventory_digest: str,
                     policy_digest: str, *, now=None) -> dict:
    current = _clock(now)
    gaps = []
    if not isinstance(checks, list) or not all(isinstance(c, dict) for c in checks):
        gaps.append('expanded check records are malformed')
        checks = []
    if not _digest(inventory_digest) or not _digest(policy_digest):
        gaps.append('inventory or policy binding is malformed')
    names = [item.get('name') for item in checks]
    if (len(names) != len(REQUIRED_CHECKS) or any(not isinstance(name, str) for name in names)
            or set(names) != set(REQUIRED_CHECKS)):
        gaps.append('expanded check set is missing, duplicated or unknown')
    if not isinstance(before, dict) or not isinstance(after, dict):
        gaps.append('source identity envelope is malformed')
        before, after = {}, {}
    identity_fields = ('head_sha', 'tree_sha', 'checker_sha', 'checker_tree_sha')
    if not all(isinstance(after.get(k), str) and re.fullmatch(r'[0-9a-f]{40}', after[k]) for k in identity_fields):
        gaps.append('source identity digest is malformed')
    if before != after or not all(after.get(key) is True for key in ('candidate_clean', 'checker_clean', 'same_project')):
        gaps.append('source changed, is not clean, or checker policy belongs to another project')
    expiry = current + timedelta(seconds=MAX_AGE_SECONDS)
    for check in checks:
        if not isinstance(check.get('name'), str) or check['name'] not in REQUIRED_CHECKS:
            continue
        if not isinstance(check.get('details'), list):
            gaps.append(f'{check.get("name")}: malformed structured details')
            continue
        details = [value for value in check['details'] if isinstance(value, dict)
                   and value.get('kind') == 'security-result' and value.get('schema_version') == 1]
        if len(details) != 1:
            gaps.append(f'{check.get("name")}: missing unique structured result')
            continue
        detail = details[0]
        consistent = _detail_consistent(check.get('name'), detail, inventory_digest, policy_digest, current)
        if not consistent:
            gaps.append(f'{check.get("name")}: contradictory or incomplete per-check evidence')
        if consistent and check['name'] == 'known-vulnerabilities':
            for finding in detail.get('accepted', []):
                accepted_date = date.fromisoformat(finding['accepted_until'])
                # Avoid adding a day to a far-future maximum date: it cannot shorten this report.
                if accepted_date < expiry.date():
                    boundary = datetime.combine(accepted_date + timedelta(days=1),
                                                datetime.min.time(), tzinfo=timezone.utc)
                    expiry = min(expiry, boundary)
        if check.get('status') == 'skip':
            expected = {'complete': True, 'inventory_sha256': inventory_digest, 'reason': 'complete-inventory-no-objects'}
            if detail.get('outcome') != 'not_applicable' or detail.get('applicability_evidence') != expected:
                gaps.append(f'{check.get("name")}: no applicable-object proof')
        elif check.get('status') != 'pass' or detail.get('outcome') != 'pass':
            gaps.append(f'{check.get("name")}: did not pass')
        sources = detail.get('data_sources')
        if not isinstance(sources, list):
            continue
        for source in sources:
            try:
                acquisition = source['acquisition']
                times = [acquisition['last_verified_sync_utc']]
                if source['source_id'] in {'epss', 'trivy-db'}:
                    times.append(acquisition['source_published_at'])
                for value in times:
                    instant = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    if instant.tzinfo is None or not 0 <= (current - instant).total_seconds() <= MAX_AGE_SECONDS:
                        raise ValueError('source outside its age bound')
                    expiry = min(expiry, instant + timedelta(seconds=MAX_AGE_SECONDS))
            except (KeyError, TypeError, ValueError, AttributeError):
                gaps.append(f'{check.get("name")}: missing, future or stale source timestamp')
    return {'schema_version': 1, 'kind': 'security-expanded', 'status': 'fail' if gaps else 'pass',
            'source': after, 'created_at_utc': current.isoformat(),
            'valid_until_utc': None if gaps else expiry.isoformat(), 'checks': checks,
            'inventory_sha256': inventory_digest, 'policy_sha256': policy_digest,
            'assurance': 'local-input-integrity-only', 'qualification_gaps': gaps}


def evaluate(root: Path, database: Path, artifacts: Path, tools: Path, *, refresh=False,
             provision=False, now=None) -> dict:
    root, artifacts, tools = (path.resolve() for path in (root, artifacts, tools))
    database = database.absolute()  # Keep named links visible to descriptor snapshot I/O.
    env = {'GETZILLA_SECURITY_DB': str(database), 'GETZILLA_SECURITY_ARTIFACTS': str(artifacts),
           'GETZILLA_SECURITY_TOOLS': str(tools)}
    inventory = collect_inventory(root)
    policy = _policy_digest(TRUSTED_ROOT)
    acquisitions = []
    checks = []
    before = after = {}
    tools.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='expanded-', dir=tools) as directory:
        scratch = Path(directory)
        try:
            before = source_binding(root, TRUSTED_ROOT, scratch)
            def acquire(label, operation):
                try:
                    acquisitions.extend(operation())
                except (ImportError, OSError, ValueError, RuntimeError) as exc:
                    acquisitions.append({'kind': label, 'status': 'fail', 'reason': str(exc)})
            if provision:
                acquire('tool-acquisition', lambda: provision_tools(tools))
            if refresh:
                ecosystems = sorted({item['ecosystem'] for item in inventory['dependencies']})
                if inventory['dependencies'] or inventory['images']:
                    acquire('feed-acquisition', lambda: refresh_feeds(database, ecosystems, now=now))
                if inventory['dependencies']:
                    def package_artifacts():
                        bundle = acquire_pypi(inventory['dependencies'], artifacts, inventory_digest=inventory['digest'], now=now)
                        return [{'kind': 'artifact-acquisition', 'status': 'fail' if bundle.get('gaps') else 'pass',
                                 'records': len(bundle.get('records', [])), 'gaps': bundle.get('gaps', [])}]
                    acquire('artifact-acquisition', package_artifacts)
                if inventory['images']:
                    acquire('image-acquisition', lambda: refresh_images(inventory, tools, now=now))
            initial_plan = security_obligations(root, inventory, environ=env, now=now, policy_root=TRUSTED_ROOT)
            checks.extend(run_checks(root, environ=env, now=now, inventory=inventory, policy_root=TRUSTED_ROOT))
            checks.append(known_vulnerability_check(root, environ=env, now=now, inventory=inventory,
                                                    policy_root=TRUSTED_ROOT))
            for value in scan_source(root, inventory, environ=env, trusted_root=TRUSTED_ROOT):
                outcome = value['outcome']
                if outcome == 'not_applicable' and not inventory['complete']:
                    outcome = 'blocked'
                checks.append(_check(value['name'], outcome, value['summary'], inventory, policy,
                                     findings=value.get('findings', []), gaps=value.get('gaps', []),
                                     extra={key: value[key] for key in ('coverage', 'binary_inputs', 'factory_offline_use') if key in value}))
            final_inventory = collect_inventory(root)
            final_plan = security_obligations(root, final_inventory, environ=env, now=now, policy_root=TRUSTED_ROOT)
            if final_plan != initial_plan or final_inventory['digest'] != inventory['digest']:
                raise SecurityDataError('required inputs, source age or inventory changed during security execution')
            expected_sources = {item['check_id']: item['data_sources'] for item in final_plan}
            for check in checks:
                if check['name'] in expected_sources and check['status'] == 'pass':
                    if check['details'][0]['data_sources'] != expected_sources[check['name']]:
                        raise SecurityDataError('observed security sources differ from the required plan')
            after = source_binding(root, TRUSTED_ROOT, scratch)
        except (ImportError, OSError, ValueError, RuntimeError) as exc:
            observed = {item['name'] for item in checks}
            for name in REQUIRED_CHECKS:
                if name not in observed:
                    checks.append(_check(name, 'blocked', str(exc), inventory, policy,
                                         gaps=[{'code': 'execution-incomplete', 'message': str(exc)}]))
            # Preserve completed observations, but make acceptance explicitly fail.
            after = {**before, 'execution_error': str(exc)}
    checks.sort(key=lambda item: REQUIRED_CHECKS.index(item['name']))
    report = finalize_report(before, after, checks, inventory['digest'], policy, now=now)
    report['acquisitions'] = acquisitions
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Run expanded security with a separately selected trusted checker checkout.')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--refresh', action='store_true', help='explicitly acquire current feeds, artifacts and immutable images')
    parser.add_argument('--provision-tools', action='store_true', help='download only reviewed digest-pinned scanner assets')
    parser.add_argument('--json-out', type=Path, required=True)
    args = parser.parse_args(argv)
    report = evaluate(args.root, args.database, args.artifacts, args.tools,
                      refresh=args.refresh, provision=args.provision_tools)
    _atomic(args.json_out, (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + '\n').encode())
    for check in report['checks']:
        print(f'{check["status"].upper()} {check["name"]}: {check["summary"]}')
    for gap in report['qualification_gaps']:
        print(f'BLOCKED: {gap}')
    return 0 if report['status'] == 'pass' else 1
