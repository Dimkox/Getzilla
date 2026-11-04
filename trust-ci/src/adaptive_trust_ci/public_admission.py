"""Read-only public admission spike with an offline signed producer contract.

Selectors identify candidate observations. Only host-owned Authority pins and an
independent producer signature confer authority. No production producer, key,
publisher, private scheduler, or branch-protection integration is configured.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
import base64
import hashlib
from urllib.parse import quote
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .github import GitHubClient, GitHubError
from .models import canonical_json, parse_datetime, require_digest, require_repository, require_sha


@dataclass(frozen=True)
class Selector:
    repository: str
    repository_id: int
    pr_number: int
    base_sha: str
    head_sha: str
    tree_sha: str
    run_id: int
    run_attempt: int


@dataclass(frozen=True, kw_only=True)
class OperatorSecurityCore:
    """Modules supplied by the operator's pinned Getzilla installation."""
    git: ModuleType
    security: ModuleType
    known_vulns: ModuleType
    inventory: ModuleType
    paths: ModuleType
    admission: ModuleType
    report: ModuleType
    tools: ModuleType

    def source_families(self, files: list[str]) -> dict[str, bool]:
        # Match the pinned scan_source file selection without executing candidate tools.
        selected = [Path(name) for name in files if not name.startswith('.getzilla/sast/')
                    and not self.tools._SAST_EXCLUDED.intersection(Path(name).parts)]
        return {
            'opengrep': any(path.suffix in self.tools._SAST_SUFFIXES for path in selected),
            'bandit': any(path.suffix == '.py' for path in selected),
            'trivy-config': any(path.name.lower().startswith('dockerfile') or
                                path.name.endswith('.Dockerfile') or path.suffix == '.tf' for path in selected),
        }


@dataclass(frozen=True)
class Authority:
    repository: str
    repository_id: int
    runner_repository: str
    runner_repository_id: int
    runner_sha: str
    runner_tree_sha: str
    workflow_id: int
    workflow_path: str
    checker_sha: str
    checker_tree_sha: str
    workflow_blob_sha: str
    producer_app_id: int
    event: str
    branch: str
    public_key_pem: bytes
    policy_digest: str
    target_branch: str = 'main'
    required_jobs: tuple[str, ...] = ()
    security_core: OperatorSecurityCore | None = None


@dataclass(frozen=True)
class Evidence:
    binding: dict[str, Any]
    report: dict[str, Any]
    integration: dict[str, Any] | None = None


@dataclass(frozen=True)
class Decision:
    eligible: bool
    blockers: tuple[str, ...]


def evaluate(client: GitHubClient, authority: Authority | None, selector: Selector,
             evidence: Evidence | None, *, now: datetime, snapshot_root: Path | None = None,
             candidate_root: Path | None = None) -> Decision:
    """Verify protected producer evidence without executing candidate code.

    The host must obtain Authority outside the candidate checkout and invoke this
    module and the Getzilla verifier from its own pinned deployment. Evidence may
    be transported through untrusted storage because its complete report digest
    and execution identity are independently signed. Eligibility is an offline
    decision only. The operator supplies a local object store for the requested
    commit. Only immutable Git objects are inspected, never candidate worktree bytes.
    """
    if authority is None:
        return Decision(False, ('authority-unconfigured',))
    if evidence is None:
        return Decision(False, ('independent-evidence-unavailable',))
    core = authority.security_core
    if core is None:
        return Decision(False, ('trusted-getzilla-security-verifier-unavailable',))
    if client.api_url != 'https://api.github.com':
        return Decision(False, ('provider-origin-untrusted',))
    try:
        _validate_inputs(authority, selector, now)
        blockers = _provider_blockers(client, authority, selector)
        blockers.extend(_binding_blockers(authority, selector, evidence, now))
        blockers.extend(_candidate_obligations(core, candidate_root, selector, evidence.report, now))
        blockers.extend(_security_blockers(core, authority, selector, evidence.report, now, snapshot_root))
        integration = getattr(evidence, 'integration', None)
        if integration is not None:
            blockers.extend(_integration_blockers(core, candidate_root, selector, integration))
            integrated = replace(selector, head_sha=integration['merge_sha'], tree_sha=integration['tree_sha'])
            blockers.extend(_candidate_obligations(core, candidate_root, integrated, integration['report'], now))
            blockers.extend(_security_blockers(core, authority, integrated, integration['report'], now, snapshot_root))
        return Decision(not blockers, tuple(blockers))
    except (ImportError, KeyError, TypeError, ValueError, AttributeError, GitHubError) as exc:
        return Decision(False, (f'provider-metadata-or-evidence-invalid:{type(exc).__name__}',))


def _validate_inputs(authority: Authority, selector: Selector, now: datetime) -> None:
    if now.tzinfo is None:
        raise ValueError('admission time requires a timezone')
    for value in (authority.repository, authority.runner_repository, selector.repository):
        if require_repository(value) != value:
            raise ValueError('repository identity must be exact')
    for value in (selector.base_sha, selector.head_sha, selector.tree_sha,
                  authority.runner_sha, authority.runner_tree_sha, authority.checker_sha,
                  authority.checker_tree_sha, authority.workflow_blob_sha):
        if require_sha(value, 'pin') != value:
            raise ValueError('source pins must be exact')
    if require_digest(authority.policy_digest, 'policy') != authority.policy_digest:
        raise ValueError('policy digest must be exact')
    for value in (authority.repository_id, authority.runner_repository_id,
                  authority.workflow_id, authority.producer_app_id, selector.repository_id,
                  selector.pr_number, selector.run_id, selector.run_attempt):
        if type(value) is not int or value <= 0:
            raise ValueError('provider IDs must be positive integers')
    if (authority.event not in {'workflow_dispatch', 'repository_dispatch'}
            or not authority.branch or not authority.workflow_path.startswith('.github/workflows/')
            or '..' in authority.workflow_path.split('/') or authority.target_branch != 'main'):
        raise ValueError('protected independent producer configuration required')
    if (not authority.required_jobs or len(authority.required_jobs) > 100
            or len(set(authority.required_jobs)) != len(authority.required_jobs)
            or any(not isinstance(name, str) or not name.strip() for name in authority.required_jobs)):
        raise ValueError('complete operator-owned producer job graph required')


def _provider_blockers(client: GitHubClient, authority: Authority, selector: Selector) -> list[str]:
    # Reuse the authenticated canonical client, with only fixed GET operations.
    def get(path):
        value = client._request('GET', path)
        if not isinstance(value, dict):
            raise ValueError('provider response must be an object')
        return value

    problems = []
    source_root = f'/repos/{authority.repository}'
    repo = get(source_root)
    if (selector.repository != authority.repository or selector.repository_id != authority.repository_id
            or repo['id'] != authority.repository_id or repo['full_name'] != authority.repository):
        problems.append('source-repository-identity-mismatch')
    pr = get(f'{source_root}/pulls/{selector.pr_number}')
    if (pr['number'] != selector.pr_number or pr['state'] != 'open'
            or pr['head']['sha'] != selector.head_sha or pr['base']['sha'] != selector.base_sha
            or pr['base']['ref'] != authority.target_branch
            or not isinstance(pr['head']['ref'], str) or not pr['head']['ref']
            or pr['head']['ref'] == authority.target_branch
            or pr['base']['repo']['id'] != authority.repository_id
            or pr['head']['repo']['id'] != authority.repository_id):
        problems.append('source-pr-identity-mismatch')
    for repository, sha, tree, label in (
            (authority.repository, selector.head_sha, selector.tree_sha, 'source-tree'),
            (authority.repository, authority.checker_sha, authority.checker_tree_sha, 'checker-tree'),
            (authority.runner_repository, authority.runner_sha, authority.runner_tree_sha, 'runner-tree')):
        commit = get(f'/repos/{repository}/git/commits/{sha}')
        if commit['sha'] != sha or commit['tree']['sha'] != tree:
            problems.append(f'{label}-mismatch')
    root = f'/repos/{authority.runner_repository}'
    # This initial contract serializes the protected producer across PRs. An
    # older dispatch is never reusable, even if a newer run targets another PR.
    current = get(f'{root}/actions/workflows/{authority.workflow_id}/runs?branch={quote(authority.branch, safe="")}&per_page=1')
    runs = current.get('workflow_runs')
    if (type(current.get('total_count')) is not int or current['total_count'] < 1
            or not isinstance(runs, list) or len(runs) != 1
            or runs[0].get('id') != selector.run_id
            or runs[0].get('run_attempt') != selector.run_attempt):
        problems.append('current-producer-run-mismatch')
    latest = get(f'{root}/actions/runs/{selector.run_id}')
    attempt = get(f'{root}/actions/runs/{selector.run_id}/attempts/{selector.run_attempt}')
    expected = {'id': selector.run_id, 'run_attempt': selector.run_attempt,
                'workflow_id': authority.workflow_id, 'event': authority.event,
                'head_sha': authority.runner_sha, 'head_branch': authority.branch,
                'path': authority.workflow_path, 'status': 'completed', 'conclusion': 'success'}
    for run in (latest, attempt):
        if (any(run[key] != value for key, value in expected.items())
                or any(run[key]['id'] != authority.runner_repository_id
                       or run[key]['full_name'] != authority.runner_repository
                       for key in ('repository', 'head_repository'))):
            problems.append('producer-run-identity-mismatch')
    if latest['check_suite_id'] != attempt['check_suite_id']:
        problems.append('producer-run-suite-mismatch')
    jobs = get(f'{root}/actions/runs/{selector.run_id}/attempts/{selector.run_attempt}/jobs?per_page=100')
    values = jobs.get('jobs')
    if (type(jobs.get('total_count')) is not int or not isinstance(values, list)
            or jobs['total_count'] != len(authority.required_jobs) or len(values) != jobs['total_count']
            or sorted(value.get('name', '') for value in values) != sorted(authority.required_jobs)
            or any(type(job.get('id')) is not int or job['id'] <= 0 or job.get('run_id') != selector.run_id
                   or job.get('head_sha') != authority.runner_sha or job.get('status') != 'completed'
                   or job.get('conclusion') != 'success' for job in values)):
        problems.append('producer-required-jobs-incomplete-or-failed')
    workflow = get(f'{root}/actions/workflows/{authority.workflow_id}')
    if (workflow['id'] != authority.workflow_id or workflow['path'] != authority.workflow_path
            or workflow['state'] != 'active'):
        problems.append('producer-workflow-identity-mismatch')
    suite = get(f"{root}/check-suites/{attempt['check_suite_id']}")
    if suite['app']['id'] != authority.producer_app_id:
        problems.append('producer-app-identity-mismatch')
    if (suite['id'] != attempt['check_suite_id'] or suite['head_sha'] != authority.runner_sha
            or suite['repository']['id'] != authority.runner_repository_id
            or suite['status'] != 'completed' or suite['conclusion'] != 'success'):
        problems.append('producer-suite-identity-mismatch')
    blob = get(f'{root}/contents/{authority.workflow_path}?ref={authority.runner_sha}')
    if (blob['type'] != 'file' or blob['path'] != authority.workflow_path
            or blob['sha'] != authority.workflow_blob_sha):
        problems.append('producer-workflow-blob-mismatch')
    return problems


def _binding_blockers(authority: Authority, selector: Selector,
                      evidence: Evidence, now: datetime) -> list[str]:
    """Draft public producer contract, separate from private Trust CI job envelopes."""
    try:
        binding = evidence.binding['payload']
        key = serialization.load_pem_public_key(authority.public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError('independent producer key must be Ed25519')
        key.verify(base64.b64decode(evidence.binding['signature'], validate=True), canonical_json(binding))
        issued, expires = parse_datetime(binding['issued_at']), parse_datetime(binding['expires_at'])
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return ['independent-binding-signature-invalid-or-unavailable']
    problems = []
    if not (timedelta(0) <= now - issued <= timedelta(hours=72)
            and now <= expires <= issued + timedelta(hours=72)):
        problems.append('independent-binding-freshness-invalid')
    expected = {
        'schema_version': 1, 'kind': 'getzilla-public-ci-binding',
        'repository': authority.repository, 'repository_id': authority.repository_id,
        'pr_number': selector.pr_number, 'base_sha': selector.base_sha,
        'head_sha': selector.head_sha, 'tree_sha': selector.tree_sha,
        'runner_repository': authority.runner_repository, 'runner_repository_id': authority.runner_repository_id,
        'runner_sha': authority.runner_sha, 'runner_tree_sha': authority.runner_tree_sha,
        'workflow_id': authority.workflow_id, 'workflow_path': authority.workflow_path,
        'checker_sha': authority.checker_sha, 'checker_tree_sha': authority.checker_tree_sha,
        'workflow_blob_sha': authority.workflow_blob_sha, 'producer_app_id': authority.producer_app_id,
        'run_id': selector.run_id, 'run_attempt': selector.run_attempt, 'event': authority.event,
        'policy_digest': authority.policy_digest,
        'security_report_sha256': hashlib.sha256(canonical_json(evidence.report)).hexdigest(),
        'issued_at': binding['issued_at'], 'expires_at': binding['expires_at'],
    }
    integration = getattr(evidence, 'integration', None)
    if integration is not None:
        expected.update(schema_version=2, integration={
            'merge_sha': integration['merge_sha'], 'tree_sha': integration['tree_sha'],
            'report_sha256': hashlib.sha256(canonical_json(integration['report'])).hexdigest()})
    if binding != expected:
        problems.append('independent-binding-identity-or-report-digest-mismatch')
    return problems


def _integration_blockers(core: OperatorSecurityCore, root: Path | None,
                          selector: Selector, integration: dict) -> list[str]:
    """Recompute the permitted two-parent Git integration in an operator object store."""
    try:
        if root is None or set(integration) != {'merge_sha', 'tree_sha', 'report'}:
            return ['integration-source-unavailable']
        for name in ('merge_sha', 'tree_sha'):
            if require_sha(integration[name], name) != integration[name]:
                return ['integration-identity-invalid']
        commit = core.git.run_git_bounded(root, ['cat-file', 'commit', integration['merge_sha']], limit=128 * 1024)
        headers = commit.split(b'\n\n', 1)[0].splitlines() if commit else []
        parents = [line.removeprefix(b'parent ').decode('ascii') for line in headers if line.startswith(b'parent ')]
        if (parents != [selector.base_sha, selector.head_sha]
                or not headers or headers[0] != f"tree {integration['tree_sha']}".encode('ascii')):
            return ['integration-parents-or-tree-mismatch']
        # A conflict is a refusal. No candidate conflict resolver or script runs.
        merged = core.git.run_git_bounded(root, ['merge-tree', '--write-tree', selector.base_sha,
                                                selector.head_sha], allow_failure=True, limit=128 * 1024)
        if not merged or merged.strip() != integration['tree_sha'].encode('ascii'):
            return ['integration-strategy-tree-mismatch-or-conflict']
        return []
    except (OSError, RuntimeError, ValueError, UnicodeError):
        return ['integration-source-unavailable']


def _candidate_obligations(core: OperatorSecurityCore, root: Path | None, selector: Selector,
                           report: dict, now: datetime) -> list[str]:
    """Derive mandatory families from a bounded private copy of the exact commit."""
    if root is None:
        return ['security-candidate-source-unavailable']
    try:
        commit = core.git.run_git_bounded(root, ['cat-file', 'commit', selector.head_sha], limit=128 * 1024)
        if not commit or commit.split(b'\n', 1)[0] != f'tree {selector.tree_sha}'.encode('ascii'):
            return ['security-candidate-source-tree-mismatch']
        paths = core.git.git_tree_paths(root, selector.head_sha, ('',))
        if not core.paths.validate_paths(paths).ok or any('.git' in (part.casefold() for part in Path(p).parts) for p in paths):
            return ['security-candidate-source-path-unsupported']
        with TemporaryDirectory(prefix='public-security-inventory-') as directory:
            # Keep data and policy inputs separate. No filters, hooks or assets
            # from the candidate are executed by the immutable blob reader.
            source = Path(directory) / 'source'
            evaluator = Path(directory) / 'evaluator'
            source.mkdir()
            evaluator.mkdir()
            size = 0
            for start in range(0, len(paths), 32):
                group = paths[start:start + 32]
                blobs = core.git._git_blobs(root, selector.head_sha, group)
                for name in group:
                    payload = blobs[name]
                    if payload is None:
                        return ['security-candidate-source-incomplete']
                    size += len(payload)
                    if size > 32 * 1024 * 1024:
                        return ['security-candidate-source-limit']
                    target = source / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(payload)
            if set(core.known_vulns._tracked_files(source)) != set(paths):
                return ['security-candidate-source-incomplete']
            inventory = core.inventory.collect_inventory(source)
            obligations = core.security.security_obligations(evaluator, inventory, environ={}, now=now)
    except (OSError, RuntimeError, ValueError):
        return ['security-candidate-source-unavailable']

    problems = []
    if inventory['complete'] is not True or inventory['digest'] != report.get('inventory_sha256'):
        problems.append('security-inventory-digest-mismatch-or-incomplete')
    results = {value['name']: value['status'] for value in report['checks']}
    required = {item['check_id']: item['applicability'] == 'required' for item in obligations}
    for name, applies in required.items():
        if applies and name not in {'security-inventory', 'known-vulnerabilities'}:
            problems.append(f'security-required-family-unqualified:{name}')
    required['secret-scan'] = True
    required.update(core.source_families(inventory['files']))
    for name, applies in required.items():
        if results.get(name) != ('pass' if applies else 'skip'):
            problems.append(f'security-family-applicability-mismatch:{name}')
    return problems


def _security_blockers(core: OperatorSecurityCore, authority: Authority, selector: Selector,
                       report: dict[str, Any], now: datetime, snapshot_root: Path | None) -> list[str]:
    # Keep the existing eleven-check inventory, freshness and NA proof semantics.
    record = {'report': report, 'checker': {
        'head': authority.checker_sha, 'tree': authority.checker_tree_sha,
        'selected_ref': authority.checker_sha, 'selection': 'operator-variable',
        'boundary': 'separate-checkout',
    }}
    problems = [f'security:{problem}' for problem in core.admission._security(record, selector.head_sha, selector.tree_sha, now)]
    if report.get('policy_sha256') != authority.policy_digest:
        problems.append('security-policy-digest-mismatch')
    if report.get('qualification_gaps'):
        problems.append('security-qualification-gaps-present')
    recalculated = core.report.finalize_report(report['source'], report['source'], report['checks'],
                                  report['inventory_sha256'], report['policy_sha256'], now=now)
    if recalculated['status'] != 'pass':
        problems.append('security-report-or-feed-freshness-invalid')
    for check in report['checks']:
        markers = [item for item in check.get('details', []) if isinstance(item, dict)
                   and item.get('kind') == 'security-result']
        for marker in markers:
            # This bounded spike admits no finding dispositions, including waivers.
            if marker.get('gaps') or marker.get('findings'):
                problems.append('security-findings-or-coverage-gaps-present')
            if (marker.get('inventory_sha256') != report['inventory_sha256']
                    or marker.get('policy_sha256') != authority.policy_digest):
                problems.append('security-marker-input-digest-mismatch')
            sources = marker.get('data_sources', [])
            if core.security.CHECK_FAMILIES.get(check['name']) == 'inventory':
                if check.get('status') != 'pass' or marker.get('outcome') != 'pass':
                    problems.append('security-inventory-required')
            elif check['name'] in core.security.CHECK_FAMILIES and marker.get('outcome') == 'pass':
                # The MVP qualifies applicable OSV consumption only. Other feed
                # families need their full producer/input contracts integrated.
                if check['name'] != 'known-vulnerabilities':
                    problems.append('security-applicable-family-unqualified')
                elif not sources or any(not source.get('source_id', '').startswith('osv:') for source in sources):
                    problems.append('security-applicable-osv-inputs-unavailable')
            for source in sources:
                if snapshot_root is None:
                    problems.append('security-trusted-snapshot-mirror-unavailable')
                    continue
                try:
                    core.security.validate_data_source(source, root=snapshot_root, now=now, environ={})
                except (OSError, ValueError, RuntimeError):
                    problems.append('security-frozen-source-bytes-coverage-or-age-invalid')
    return problems
