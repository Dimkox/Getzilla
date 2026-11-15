from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import subprocess
import secrets
import sys
import tempfile
import unittest
import zipfile
from types import SimpleNamespace

# The independent host must supply the existing pinned Getzilla verifier.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / '.getzilla'))

from adaptive_trust_ci.github import GitHubClient
from adaptive_trust_ci.models import canonical_json
from adaptive_trust_ci.public_admission import Authority, Evidence, OperatorSecurityCore, Selector, evaluate
from adaptive_trust_ci.signing import Signer
from getzilla import (architecture_diff, ci_admission, expanded_security, known_vulns, security_cli,
                      security_inventory, security_tools, source_paths)
from getzilla.expanded_security import known_vulnerability_check
from getzilla.security_inventory import collect_inventory
from getzilla.security_data import osv_coverage, publish_snapshot


NOW = datetime(2026, 11, 4, 1, tzinfo=timezone.utc)
HEAD, BASE, CHECKER, CHECKER_TREE, WORKFLOW = (c * 40 for c in 'acdef')
POLICY = '1' * 64
RUNNER, RUNNER_TREE = '9' * 40, '8' * 40
FAMILIES = ('security-inventory', 'known-vulnerabilities', 'security-kev', 'security-epss',
            'security-malicious-packages', 'security-licenses', 'security-container-images',
            'opengrep', 'secret-scan', 'bandit', 'trivy-config')


class ProviderTransport:
    """Recorded provider boundary. No candidate-provided metadata enters this reader."""

    def __init__(self, records):
        self.records = records
        self.calls = []

    def request(self, method, url, headers, body):
        self.calls.append((method, url, body))
        if method != 'GET' or body is not None:
            raise AssertionError('admission attempted a provider mutation')
        return 200, copy.deepcopy(self.records[url.removeprefix('https://api.github.com')])


class PublicAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.signer = Signer.generate()
        self.snapshot_root = None
        directory = tempfile.TemporaryDirectory(prefix='getzilla-policy-source-')
        self.addCleanup(directory.cleanup)
        self.candidate_root = Path(directory.name)
        self.git('init', '-q')
        self.git('commit', '--allow-empty', '-qm', 'empty dependency-free source')
        self.base_sha = self.git('rev-parse', 'HEAD')
        self.git('commit', '--allow-empty', '-qm', 'candidate')
        head, tree = self.git('rev-parse', 'HEAD', 'HEAD^{tree}').splitlines()
        inventory = collect_inventory(self.candidate_root)['digest']
        self.selector = Selector('Dimkox/Getzilla', 1404516308, 318, self.base_sha, head, tree, 100, 2)
        self.authority = Authority(
            repository='Dimkox/Getzilla', repository_id=1404516308,
            runner_repository='independent/runner', runner_repository_id=202,
            runner_sha=RUNNER, runner_tree_sha=RUNNER_TREE,
            workflow_id=303, workflow_path='.github/workflows/getzilla.yml',
            checker_sha=CHECKER, checker_tree_sha=CHECKER_TREE, workflow_blob_sha=WORKFLOW,
            producer_app_id=404, event='workflow_dispatch', branch='main',
            required_jobs=('security-expanded', 'live-acceptance'),
            public_key_pem=self.signer.public_key_pem(), policy_digest=POLICY,
            security_core=OperatorSecurityCore(
                git=architecture_diff, security=expanded_security, known_vulns=known_vulns,
                inventory=security_inventory, paths=source_paths, admission=ci_admission,
                report=security_cli, tools=security_tools,
            ),
        )
        source = {'head_sha': head, 'tree_sha': tree, 'checker_sha': CHECKER,
                  'checker_tree_sha': CHECKER_TREE, 'candidate_clean': True,
                  'checker_clean': True, 'same_project': True}
        self.report = {
            'schema_version': 1, 'kind': 'security-expanded', 'status': 'pass',
            'source': source, 'assurance': 'local-input-integrity-only',
            'created_at_utc': NOW.isoformat(),
            'valid_until_utc': (NOW + timedelta(hours=72)).isoformat(),
            'policy_sha256': POLICY, 'inventory_sha256': inventory,
            'qualification_gaps': [],
            'checks': [{'name': name, 'status': 'pass', 'details': [{
                'kind': 'security-result', 'schema_version': 1, 'outcome': 'pass',
                'policy_sha256': POLICY, 'inventory_sha256': inventory,
                'findings': [], 'gaps': [], 'data_sources': [],
            }]} for name in FAMILIES],
        }
        for check in self.report['checks']:
            if check['name'] in {'security-inventory', 'secret-scan'}:
                continue
            check['status'] = 'skip'
            check['details'][0].update(outcome='not_applicable', applicability_evidence={
                'complete': True, 'inventory_sha256': inventory, 'reason': 'complete-inventory-no-objects'})
        self.binding_payload = {
            'schema_version': 1, 'kind': 'getzilla-public-ci-binding',
            'repository': 'Dimkox/Getzilla', 'repository_id': 1404516308,
            'pr_number': 318, 'base_sha': self.base_sha, 'head_sha': head, 'tree_sha': tree,
            'runner_repository': 'independent/runner', 'runner_repository_id': 202,
            'runner_sha': RUNNER, 'runner_tree_sha': RUNNER_TREE,
            'workflow_id': 303, 'workflow_path': '.github/workflows/getzilla.yml',
            'checker_sha': CHECKER, 'checker_tree_sha': CHECKER_TREE,
            'workflow_blob_sha': WORKFLOW, 'producer_app_id': 404,
            'run_id': 100, 'run_attempt': 2, 'event': 'workflow_dispatch',
            'policy_digest': POLICY, 'security_report_sha256': self.report_digest(),
            'issued_at': NOW.isoformat(), 'expires_at': (NOW + timedelta(hours=72)).isoformat(),
        }
        repo = {'id': 202, 'full_name': 'independent/runner'}
        run = {'id': 100, 'run_attempt': 2, 'workflow_id': 303, 'event': 'workflow_dispatch',
               'head_sha': RUNNER, 'head_branch': 'main', 'head_repository': repo,
               'repository': repo, 'path': '.github/workflows/getzilla.yml',
               'status': 'completed', 'conclusion': 'success', 'check_suite_id': 505}
        self.records = {
            '/repos/Dimkox/Getzilla': {'id': 1404516308, 'full_name': 'Dimkox/Getzilla'},
            '/repos/Dimkox/Getzilla/pulls/318': {
                'number': 318, 'state': 'open',
                'head': {'sha': head, 'ref': 'feature', 'repo': {'id': 1404516308}},
                'base': {'sha': self.base_sha, 'ref': 'main', 'repo': {'id': 1404516308}},
            },
            f'/repos/Dimkox/Getzilla/git/commits/{head}': {'sha': head, 'tree': {'sha': tree}},
            '/repos/independent/runner/actions/runs/100': run,
            '/repos/independent/runner/actions/workflows/303/runs?branch=main&per_page=1': {
                'total_count': 1, 'workflow_runs': [copy.deepcopy(run)]},
            '/repos/independent/runner/actions/runs/100/attempts/2': copy.deepcopy(run),
            '/repos/independent/runner/actions/runs/100/attempts/2/jobs?per_page=100': {
                'total_count': 2, 'jobs': [{'id': number, 'name': name, 'run_id': 100,
                    'head_sha': RUNNER, 'status': 'completed', 'conclusion': 'success'}
                    for number, name in enumerate(('security-expanded', 'live-acceptance'), 1)]},
            '/repos/independent/runner/actions/workflows/303': {
                'id': 303, 'path': '.github/workflows/getzilla.yml', 'state': 'active'},
            '/repos/independent/runner/check-suites/505': {
                'id': 505, 'head_sha': RUNNER, 'app': {'id': 404},
                'repository': repo, 'status': 'completed', 'conclusion': 'success'},
            f'/repos/independent/runner/git/commits/{RUNNER}': {
                'sha': RUNNER, 'tree': {'sha': RUNNER_TREE}},
            f'/repos/Dimkox/Getzilla/git/commits/{CHECKER}': {
                'sha': CHECKER, 'tree': {'sha': CHECKER_TREE}},
            f'/repos/independent/runner/contents/.github/workflows/getzilla.yml?ref={RUNNER}': {
                'type': 'file', 'path': '.github/workflows/getzilla.yml', 'sha': WORKFLOW},
        }

    def git(self, *args):
        return subprocess.check_output(
            ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', *args],
            cwd=self.candidate_root, text=True).strip()

    def bind_current_candidate(self):
        head, tree = self.git('rev-parse', 'HEAD', 'HEAD^{tree}').splitlines()
        self.selector = replace(self.selector, head_sha=head, tree_sha=tree)
        self.records['/repos/Dimkox/Getzilla/pulls/318']['head']['sha'] = head
        self.records[f'/repos/Dimkox/Getzilla/git/commits/{head}'] = {'sha': head, 'tree': {'sha': tree}}
        self.report['source'].update(head_sha=head, tree_sha=tree)
        self.binding_payload.update(head_sha=head, tree_sha=tree)

    def report_digest(self):
        return hashlib.sha256(canonical_json(self.report)).hexdigest()

    def evidence(self):
        return Evidence({
            'payload': self.binding_payload, 'signature': self.signer.sign(self.binding_payload),
        }, self.report)

    def evaluate(self, *, authority=True, evidence=True, now=NOW):
        self.transport = ProviderTransport(self.records)
        client = GitHubClient(token=secrets.token_urlsafe(24), transport=self.transport)
        return evaluate(client, self.authority if authority else None, self.selector,
                        self.evidence() if evidence else None, now=now,
                        snapshot_root=self.snapshot_root, candidate_root=self.candidate_root)

    def assertBlocked(self, result, reason):
        self.assertFalse(result.eligible)
        self.assertTrue(any(reason in problem for problem in result.blockers), result.blockers)

    def resign_report_binding(self):
        self.binding_payload['security_report_sha256'] = self.report_digest()

    def test_independently_signed_bound_offline_case_is_eligible(self):
        result = self.evaluate()
        self.assertTrue(result.eligible, result.blockers)
        self.assertEqual(result.blockers, ())
        self.assertTrue(self.transport.calls)
        self.assertTrue(all(method == 'GET' and body is None for method, _, body in self.transport.calls))

    def test_candidate_only_pass_without_authority_is_blocked(self):
        self.assertBlocked(self.evaluate(authority=False), 'authority-unconfigured')
        self.assertEqual(self.transport.calls, [])

    def test_missing_operator_core_fails_before_provider_reads(self):
        self.authority = replace(self.authority, security_core=None)
        self.assertBlocked(self.evaluate(), 'trusted-getzilla-security-verifier-unavailable')
        self.assertFalse(self.transport.calls)

    def test_missing_independent_evidence_is_blocked(self):
        self.assertBlocked(self.evaluate(evidence=False), 'independent-evidence-unavailable')

    def test_missing_signed_run_binding_is_blocked(self):
        self.binding_payload = {}
        self.assertBlocked(self.evaluate(), 'binding')

    def test_wrong_producer_app_is_blocked(self):
        self.records['/repos/independent/runner/check-suites/505']['app']['id'] = 405
        self.assertBlocked(self.evaluate(), 'producer-app')

    def test_wrong_run_identity_is_blocked(self):
        self.records['/repos/independent/runner/actions/runs/100']['id'] = 101
        self.assertBlocked(self.evaluate(), 'run')

    def test_attempt_replay_is_blocked(self):
        self.records['/repos/independent/runner/actions/runs/100']['run_attempt'] = 3
        self.assertBlocked(self.evaluate(), 'run')

    def test_old_success_cannot_override_a_newer_protected_workflow_run(self):
        latest = self.records['/repos/independent/runner/actions/workflows/303/runs?branch=main&per_page=1']
        latest['workflow_runs'][0].update(id=101, conclusion='failure')
        self.assertBlocked(self.evaluate(), 'current-producer-run')

    def test_failed_or_missing_expected_live_job_blocks_signed_security_success(self):
        jobs = self.records['/repos/independent/runner/actions/runs/100/attempts/2/jobs?per_page=100']
        jobs['jobs'][1]['conclusion'] = 'failure'
        self.assertBlocked(self.evaluate(), 'producer-required-jobs')
        jobs['jobs'].pop()
        jobs['total_count'] = 1
        self.assertBlocked(self.evaluate(), 'producer-required-jobs')

    def test_wrong_runner_commit_is_blocked(self):
        self.records['/repos/independent/runner/actions/runs/100']['head_sha'] = HEAD
        self.assertBlocked(self.evaluate(), 'run')

    def test_wrong_workflow_blob_is_blocked(self):
        self.records[f'/repos/independent/runner/contents/.github/workflows/getzilla.yml?ref={RUNNER}']['sha'] = HEAD
        self.assertBlocked(self.evaluate(), 'workflow-blob')

    def test_candidate_workflow_event_is_blocked(self):
        self.records['/repos/independent/runner/actions/runs/100']['event'] = 'pull_request'
        self.assertBlocked(self.evaluate(), 'run')

    def test_wrong_runner_origin_is_blocked(self):
        self.records['/repos/independent/runner/actions/runs/100']['head_repository']['id'] = 999
        self.assertBlocked(self.evaluate(), 'run')

    def test_source_changed_since_selector_is_blocked(self):
        self.records['/repos/Dimkox/Getzilla/pulls/318']['head']['sha'] = BASE
        self.assertBlocked(self.evaluate(), 'source')

    def test_wrong_source_tree_is_blocked(self):
        self.records[f'/repos/Dimkox/Getzilla/git/commits/{self.selector.head_sha}']['tree']['sha'] = BASE
        self.assertBlocked(self.evaluate(), 'source-tree')

    def test_stale_over_72_hours_is_blocked(self):
        self.assertBlocked(self.evaluate(now=NOW + timedelta(hours=72, seconds=1)), 'freshness')

    def test_binding_with_excessive_lifetime_is_blocked(self):
        self.binding_payload['expires_at'] = (NOW + timedelta(hours=73)).isoformat()
        self.assertBlocked(self.evaluate(), 'binding-freshness')

    def test_binding_signed_by_candidate_key_is_blocked(self):
        evidence = self.evidence()
        evidence.binding['signature'] = Signer.generate().sign(self.binding_payload)
        client = GitHubClient(token='test', transport=ProviderTransport(self.records))
        self.assertBlocked(evaluate(client, self.authority, self.selector, evidence, now=NOW), 'binding-signature')

    def test_post_signature_security_tampering_is_blocked(self):
        self.binding_payload['security_report_sha256'] = '0' * 64
        self.assertBlocked(self.evaluate(), 'binding-identity')

    def test_signed_failed_security_verdict_is_blocked(self):
        self.report['checks'][0]['details'][0]['outcome'] = 'fail'
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security')

    def test_signed_missing_mandatory_scanner_is_blocked(self):
        self.report['checks'].pop()
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security')

    def test_signed_skip_without_applicability_proof_is_blocked(self):
        self.report['checks'][0]['status'] = 'skip'
        self.report['checks'][0]['details'][0]['outcome'] = 'not_applicable'
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security')

    def test_signed_valid_inventory_bound_not_applicable_is_eligible(self):
        check = self.report['checks'][1]
        check['status'] = 'skip'
        check['details'][0].update(outcome='not_applicable', applicability_evidence={
            'complete': True, 'inventory_sha256': self.report['inventory_sha256'], 'reason': 'complete-inventory-no-objects'})
        self.resign_report_binding()
        self.assertTrue(self.evaluate().eligible)

    def test_signed_secret_scan_skip_cannot_admit_empty_source(self):
        check = next(item for item in self.report['checks'] if item['name'] == 'secret-scan')
        check['status'] = 'skip'
        check['details'][0].update(outcome='not_applicable', applicability_evidence={
            'complete': True, 'inventory_sha256': self.report['inventory_sha256'],
            'reason': 'complete-inventory-no-objects'})
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security-family-applicability-mismatch:secret-scan')

    def test_signed_wrong_candidate_binding_is_blocked(self):
        self.binding_payload['head_sha'] = BASE
        self.assertBlocked(self.evaluate(), 'binding-identity')

    def test_incomplete_provider_metadata_is_blocked(self):
        del self.records['/repos/independent/runner/actions/runs/100']['repository']
        self.assertBlocked(self.evaluate(), 'provider-metadata')

    def test_untrusted_provider_api_origin_is_blocked(self):
        client = GitHubClient(token='test', transport=ProviderTransport(self.records), api_url='https://candidate.invalid')
        self.assertBlocked(evaluate(client, self.authority, self.selector, self.evidence(), now=NOW), 'provider-origin')

    def test_wrong_scanner_checker_commit_is_blocked(self):
        self.report['source']['checker_sha'] = HEAD
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security')

    def test_signed_expired_report_with_fresh_binding_is_blocked(self):
        self.report['created_at_utc'] = (NOW - timedelta(hours=73)).isoformat()
        self.report['valid_until_utc'] = NOW.isoformat()
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security')

    def test_signed_wrong_security_policy_is_blocked(self):
        self.report['policy_sha256'] = '4' * 64
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security-policy')

    def test_signed_duplicate_mandatory_scanner_is_blocked(self):
        self.report['checks'].append(copy.deepcopy(self.report['checks'][0]))
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security')

    def test_failed_independent_producer_run_is_blocked(self):
        self.records['/repos/independent/runner/actions/runs/100']['conclusion'] = 'failure'
        self.assertBlocked(self.evaluate(), 'run')

    def test_naive_verifier_time_is_blocked(self):
        self.assertBlocked(self.evaluate(now=NOW.replace(tzinfo=None)), 'invalid')

    def test_signed_future_binding_is_blocked(self):
        self.binding_payload['issued_at'] = (NOW + timedelta(seconds=1)).isoformat()
        self.assertBlocked(self.evaluate(), 'binding-freshness')

    def test_unavailable_canonical_verifier_is_blocked(self):
        broken = replace(self.authority.security_core, admission=None)
        self.authority = replace(self.authority, security_core=broken)
        self.assertBlocked(self.evaluate(), 'provider-metadata-or-evidence-invalid')

    def test_source_target_branch_must_be_main(self):
        self.records['/repos/Dimkox/Getzilla/pulls/318']['base']['ref'] = 'release'
        self.assertBlocked(self.evaluate(), 'source')

    def test_same_repository_feature_branch_policy_refuses_forks(self):
        self.records['/repos/Dimkox/Getzilla/pulls/318']['head']['repo']['id'] = 999
        self.assertBlocked(self.evaluate(), 'source')

    def test_signed_critical_finding_cannot_claim_pass(self):
        self.report['checks'][7]['details'][0]['findings'] = [{'severity': 'critical', 'id': 'regression'}]
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security')

    def test_signed_marker_gap_cannot_claim_pass(self):
        self.report['checks'][7]['details'][0]['gaps'] = ['scanner did not cover complete source']
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security')

    def test_applicable_feed_pass_without_source_objects_is_blocked(self):
        check = self.report['checks'][1]
        check['status'] = 'pass'
        check['details'][0]['outcome'] = 'pass'
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security')

    def prepare_applicable_osv_evidence(self):
        directory = tempfile.TemporaryDirectory(prefix='getzilla-public-admission-')
        self.addCleanup(directory.cleanup)
        self.snapshot_root = Path(directory.name)
        (self.candidate_root / 'requirements.txt').write_text('sample==1.0.0\n')
        self.git('add', 'requirements.txt')
        self.git('commit', '-qm', 'add a real dependency')
        self.bind_current_candidate()
        out = io.BytesIO()
        record = {'id': 'GHSA-unrelated-fixture', 'modified': NOW.isoformat(),
                  'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'other'}, 'versions': ['1.0.0']}]}
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr('GHSA-unrelated-fixture.json', json.dumps(record))
        payload = out.getvalue()
        publish_snapshot(self.snapshot_root / '.getzilla/runtime/security-data', 'osv:PyPI', payload,
                         acquisition={'last_verified_sync_utc': NOW.isoformat(), 'retrieval_kind': 'download'},
                         coverage=osv_coverage(payload, 'PyPI'), now=NOW)
        check = known_vulnerability_check(self.candidate_root, now=NOW,
                                          environ={'GETZILLA_SECURITY_DB': str(self.snapshot_root / '.getzilla/runtime/security-data')})
        self.assertEqual(check['status'], 'pass', check)
        marker = check['details'][0]
        inventory, policy = marker['inventory_sha256'], marker['policy_sha256']
        self.authority = replace(self.authority, policy_digest=policy)
        self.report.update(inventory_sha256=inventory, policy_sha256=policy)
        self.binding_payload['policy_digest'] = policy
        for existing in self.report['checks']:
            detail = existing['details'][0]
            detail.update(inventory_sha256=inventory, policy_sha256=policy)
            if 'applicability_evidence' in detail:
                detail['applicability_evidence']['inventory_sha256'] = inventory
        self.report['checks'][1] = check
        self.resign_report_binding()

    def test_applicable_osv_pass_revalidates_real_snapshot_bytes_and_coverage(self):
        self.prepare_applicable_osv_evidence()
        from getzilla.expanded_security import validate_data_source
        source, = self.report['checks'][1]['details'][0]['data_sources']
        self.assertTrue(validate_data_source(source, root=self.snapshot_root, now=NOW, environ={}))
        self.assertBlocked(self.evaluate(), 'security-required-family-unqualified')

    def test_all_signed_feed_skips_do_not_override_candidate_dependencies(self):
        (self.candidate_root / 'requirements.txt').write_text('sample==1.0.0\n')
        self.git('add', 'requirements.txt')
        self.git('commit', '-qm', 'requires additional families')
        self.bind_current_candidate()
        self.resign_report_binding()
        result = self.evaluate()
        self.assertBlocked(result, 'security-inventory-digest-mismatch')
        self.assertBlocked(result, 'security-required-family-unqualified')

    def test_immutable_git_objects_ignore_worktree_injections_and_missing_mirror_blocks(self):
        (self.candidate_root / 'requirements.txt').write_text('hidden==1.0.0\n')
        self.assertTrue(self.evaluate().eligible)
        self.candidate_root = None
        self.assertBlocked(self.evaluate(), 'security-candidate-source')

    def test_applicable_osv_pass_without_host_mirror_is_blocked(self):
        self.prepare_applicable_osv_evidence()
        self.snapshot_root = None
        self.assertBlocked(self.evaluate(), 'security-trusted-snapshot-mirror-unavailable')

    def test_stale_per_feed_cannot_be_hidden_by_fresh_signed_report(self):
        self.prepare_applicable_osv_evidence()
        self.report['checks'][1]['details'][0]['data_sources'][0]['acquisition']['last_verified_sync_utc'] = (
            NOW - timedelta(hours=73)).isoformat()
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security-frozen-source')

    def test_snapshot_payload_substitution_is_blocked(self):
        self.prepare_applicable_osv_evidence()
        source = self.report['checks'][1]['details'][0]['data_sources'][0]
        payload = self.snapshot_root / '.getzilla/runtime/security-data/.snapshots/sha256' / source['content_sha256']
        payload.write_bytes(b'substituted')
        self.assertBlocked(self.evaluate(), 'security-frozen-source')

    def test_inventory_family_cannot_be_not_applicable(self):
        check = self.report['checks'][0]
        check['status'] = 'skip'
        check['details'][0].update(outcome='not_applicable', applicability_evidence={
            'complete': True, 'inventory_sha256': self.report['inventory_sha256'], 'reason': 'complete-inventory-no-objects'})
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security-inventory-required')

    def integration_evidence(self, *, drop_base=False, conflict=False):
        # Only text data enters this nonempty fixture; no candidate code runs.
        self.git('checkout', '-qb', 'base-side', self.base_sha)
        (self.candidate_root / 'base.txt').write_text('base contribution\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'base contribution')
        base = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-qb', 'head-side', self.base_sha)
        name = 'base.txt' if conflict else 'head.txt'
        (self.candidate_root / name).write_text('head contribution\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'head contribution')
        self.bind_current_candidate()
        self.selector = replace(self.selector, base_sha=base)
        self.records['/repos/Dimkox/Getzilla/pulls/318']['base']['sha'] = base
        self.binding_payload['base_sha'] = base
        self.report['inventory_sha256'] = collect_inventory(self.candidate_root)['digest']
        for check in self.report['checks']:
            marker = check['details'][0]
            marker['inventory_sha256'] = self.report['inventory_sha256']
            if 'applicability_evidence' in marker:
                marker['applicability_evidence']['inventory_sha256'] = self.report['inventory_sha256']
        if drop_base or conflict:
            tree = self.selector.tree_sha
        else:
            tree = self.git('merge-tree', '--write-tree', base, self.selector.head_sha).splitlines()[0]
        merged = self.git('commit-tree', tree, '-p', base, '-p', self.selector.head_sha, '-m', 'integration')
        integrated = copy.deepcopy(self.report)
        integrated['source'].update(head_sha=merged, tree_sha=tree)
        if not drop_base and not conflict:
            self.git('checkout', '-q', merged)
            digest = collect_inventory(self.candidate_root)['digest']
            integrated['inventory_sha256'] = digest
            for check in integrated['checks']:
                marker = check['details'][0]
                marker['inventory_sha256'] = digest
                if 'applicability_evidence' in marker:
                    marker['applicability_evidence']['inventory_sha256'] = digest
        integration = {'merge_sha': merged, 'tree_sha': tree, 'report': integrated}
        self.resign_report_binding()
        self.binding_payload.update(schema_version=2, integration={
            'merge_sha': merged, 'tree_sha': tree,
            'report_sha256': hashlib.sha256(canonical_json(integrated)).hexdigest()})
        return SimpleNamespace(binding={'payload': self.binding_payload,
            'signature': self.signer.sign(self.binding_payload)}, report=self.report, integration=integration)

    def check_integration(self, evidence):
        return evaluate(GitHubClient(token='test', transport=ProviderTransport(self.records)),
                        self.authority, self.selector, evidence, now=NOW, candidate_root=self.candidate_root)

    def test_diverged_nonempty_integration_preserves_both_contributions(self):
        evidence = self.integration_evidence()
        self.assertNotEqual(evidence.integration['tree_sha'], self.selector.tree_sha)
        result = self.check_integration(evidence)
        self.assertTrue(result.eligible, result.blockers)
        files = self.git('ls-tree', '-r', '--name-only', evidence.integration['merge_sha']).splitlines()
        self.assertEqual(files, ['base.txt', 'head.txt'])

    def test_signed_integration_cannot_drop_base_contribution(self):
        self.assertBlocked(self.check_integration(self.integration_evidence(drop_base=True)), 'integration')

    def test_conflicting_integration_needs_new_resolved_candidate(self):
        self.assertBlocked(self.check_integration(self.integration_evidence(conflict=True)), 'integration')

    def test_valid_osv_feed_cannot_substitute_for_kev_authority(self):
        self.prepare_applicable_osv_evidence()
        source = copy.deepcopy(self.report['checks'][1]['details'][0]['data_sources'])
        check = self.report['checks'][2]
        check['status'] = 'pass'
        check['details'][0].update(outcome='pass', data_sources=source)
        self.resign_report_binding()
        self.assertBlocked(self.evaluate(), 'security-applicable-family-unqualified')


if __name__ == '__main__':
    unittest.main()
