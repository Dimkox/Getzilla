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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .expanded_security import _policy_digest, known_vulnerability_check, run_checks, security_obligations
from .python_test_runner import execute
from .security_acquisition import _atomic, provision_tools, refresh_feeds
from .security_data import MAX_AGE_SECONDS, SecurityDataError
from .security_inventory import collect_inventory
from .security_license_acquisition import acquire_pypi
from .security_licenses import _repository_identity
from .security_tools import TRUSTED_ROOT, _environment, refresh_images, scan_source

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


def finalize_report(before: dict, after: dict, checks: list[dict], inventory_digest: str,
                     policy_digest: str, *, now=None) -> dict:
    current = _clock(now)
    gaps = []
    names = [item.get('name') for item in checks]
    if len(names) != len(REQUIRED_CHECKS) or set(names) != set(REQUIRED_CHECKS):
        gaps.append('expanded check set is missing, duplicated or unknown')
    if before != after or not all(after.get(key) is True for key in ('candidate_clean', 'checker_clean', 'same_project')):
        gaps.append('source changed, is not clean, or checker policy belongs to another project')
    expiry = current + timedelta(seconds=MAX_AGE_SECONDS)
    for check in checks:
        details = [value for value in check.get('details', []) if isinstance(value, dict)
                   and value.get('kind') == 'security-result' and value.get('schema_version') == 1]
        if len(details) != 1:
            gaps.append(f'{check.get("name")}: missing unique structured result')
            continue
        detail = details[0]
        if check.get('status') == 'skip':
            expected = {'complete': True, 'inventory_sha256': inventory_digest, 'reason': 'complete-inventory-no-objects'}
            if detail.get('outcome') != 'not_applicable' or detail.get('applicability_evidence') != expected:
                gaps.append(f'{check.get("name")}: no applicable-object proof')
        elif check.get('status') != 'pass' or detail.get('outcome') != 'pass':
            gaps.append(f'{check.get("name")}: did not pass')
        for source in detail.get('data_sources', []):
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
                                     extra={key: value[key] for key in ('coverage', 'binary_inputs') if key in value}))
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
