"""Closed fixtures for the canonical evaluator consumer; no provider effects."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import ast
import base64
import copy
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from adaptive_trust_ci.public_admission import Evidence
from adaptive_trust_ci.public_merge import BoundPublicVerifier

NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)
POLICY, BASE = 'a' * 64, 'b' * 40


class Signer:
    def __init__(self, key):
        self.key = key

    def sign(self, payload):
        from adaptive_trust_ci.security_bundle import canonical_json
        return base64.b64encode(self.key.sign(canonical_json(payload))).decode()


class ProviderTransport:
    """Finite encoded GET model. This never opens a network connection."""
    def __init__(self, records):
        self.records, self.calls = records, []
        self.before_read = lambda: None
        self.clock = lambda: 0

    def client(self, deadline=None, remaining=None):
        from adaptive_trust_ci.github import GitHubClient
        from adaptive_trust_ci.github_observer import BoundedGetTransport
        transport = BoundedGetTransport(clock=self.clock)
        def exchange(url, headers, request_deadline, maximum):
            self.before_read()
            path = url.removeprefix('https://api.github.com')
            self.calls.append(('GET', url, None))
            raw = json.dumps(self.records[path]).encode()
            if len(raw) > maximum:
                raise ValueError('owned finite model exceeds requested bound')
            return 200, raw, len(raw)
        transport._exchange = exchange
        return GitHubClient(token='fixture', transport=transport)


class CanonicalProducerFixture(unittest.TestCase):
    """Owned Git/byte/signature model; accepted pure marker/time functions only."""
    def setUp(self):
        from adaptive_trust_ci import public_admission as admission, security_bundle as bundle
        runtime = Path(__file__).resolve().parents[2] / '.getzilla/runtime'
        temp = TemporaryDirectory(prefix='327-canonical-', dir=runtime)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.candidate_root, self.snapshot_root = self.root / 'source', self.root / 'snapshots'
        self.checker_root, self.home = self.root / 'checker', self.root / 'home'
        for directory in (self.candidate_root, self.snapshot_root, self.checker_root, self.home):
            directory.mkdir(mode=0o700)
        self.environment = {'PATH': os.defpath, 'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.home),
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0',
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
        for directory in (self.candidate_root, self.checker_root):
            self.git('init', '-q', root=directory)
            (directory / 'README.md').write_text('owned synthetic content\n')
            self.git('add', 'README.md', root=directory)
            self.git('commit', '-qm', 'owned base', root=directory)
        base = self.git('rev-parse', 'HEAD')
        (self.candidate_root / 'README.md').write_text('owned synthetic candidate\n')
        self.git('commit', '-qam', 'owned candidate')
        self.selector = admission.Selector('Dimkox/Getzilla', 1404516308, 318, base,
            self.git('rev-parse', 'HEAD'), self.git('rev-parse', 'HEAD^{tree}'), 100, 2)
        checker = self.git('rev-parse', 'HEAD', root=self.checker_root)
        checker_tree = self.git('rev-parse', 'HEAD^{tree}', root=self.checker_root)
        tree = self.git('merge-tree', '--write-tree', base, self.selector.head_sha).splitlines()[0]
        merged = self.git('commit-tree', tree, '-p', base, '-p', self.selector.head_sha, '-m', 'owned integration')
        self.integration = {'merge_sha': merged, 'tree_sha': tree, 'parents': [base, self.selector.head_sha], 'strategy': 'merge'}
        key = Ed25519PrivateKey.generate()
        self.signer = Signer(key)
        pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        source = Path(__file__).resolve().parents[2] / '.getzilla/getzilla/security_cli.py'
        parsed = ast.parse(source.read_text())
        names = {'_clock', '_digest', '_findings_consistent', '_detail_consistent', 'finalize_report'}
        functions = [node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name in names]
        required = next(ast.literal_eval(node.value) for node in parsed.body if isinstance(node, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == 'REQUIRED_CHECKS' for t in node.targets))
        namespace = {'datetime': datetime, 'timezone': timezone, 'timedelta': timedelta, 're': re,
                     'CHECK_FAMILIES': {}, 'REQUIRED_CHECKS': required, 'MAX_AGE_SECONDS': 259200}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), 'exec'), namespace)
        self.pure_report = namespace
        manifest = admission.content_manifest(self.candidate_root)
        inventory = {'complete': True, 'digest': bundle.digest(manifest), 'files': [row['path'] for row in manifest]}
        families = [name for name in required if name not in {'secret-scan', 'opengrep', 'bandit', 'trivy-config'}]
        self.obligations = [{'check_id': name, 'applicability': 'required' if name == 'security-inventory' else 'not_applicable',
                             'data_sources': []} for name in families]
        identity = {'head_sha': self.selector.head_sha, 'tree_sha': self.selector.tree_sha,
                    'checker_sha': checker, 'checker_tree_sha': checker_tree,
                    'candidate_clean': True, 'checker_clean': True, 'same_project': True}
        def bounded_git(root, args, **kwargs):
            return self.git_bytes(*args, root=Path(root), allow_failure=kwargs.get('allow_failure', False))
        core = SimpleNamespace(policy_root=self.checker_root,
            inventory=SimpleNamespace(collect_inventory=lambda _: inventory),
            security=SimpleNamespace(_policy_digest=lambda _: POLICY, security_obligations=lambda *a, **kw: self.obligations),
            tools=SimpleNamespace(_SAST_EXCLUDED=set(), _SAST_SUFFIXES={'.py'}),
            git=SimpleNamespace(run_git_bounded=bounded_git),
            report=SimpleNamespace(_detail_consistent=namespace['_detail_consistent'],
                source_binding=lambda *args: dict(identity), finalize_report=namespace['finalize_report']))
        self.authority = admission.Authority('Dimkox/Getzilla', 1404516308, 'independent/runner', 2,
            '3' * 40, '4' * 40, 9, '.github/workflows/check.yml', checker, checker_tree, '7' * 40,
            13, 'workflow_dispatch', 'protected', pem, POLICY, required_jobs=('producer',), security_core=core)
        checks, normalized = [], []
        for name in required:
            applies = name in {'security-inventory', 'secret-scan'}
            marker = {'kind': 'security-result', 'schema_version': 1, 'outcome': 'pass' if applies else 'not_applicable',
                'inventory_sha256': inventory['digest'], 'policy_sha256': POLICY, 'data_sources': [], 'findings': [],
                'gaps': [], 'assurance': 'local-input-integrity-only'}
            if not applies:
                marker['applicability_evidence'] = {'complete': True, 'inventory_sha256': inventory['digest'],
                                                   'reason': 'complete-inventory-no-objects'}
            status = 'pass' if applies else 'skip'
            checks.append({'name': name, 'status': status, 'details': [marker]})
            normalized.append({'name': name, 'status': status, 'outcome': marker['outcome'], 'finding_count': 0,
                'gap_count': 0, 'source_ids': [], 'coverage_sha256': inventory['digest']})
        self.descriptors = {'checks': checks, 'source_descriptors': []}
        self.report = {'inventory_sha256': inventory['digest'], 'created_at': NOW.isoformat(),
            'valid_until': (NOW + timedelta(hours=72)).isoformat(), 'checks': normalized,
            'evidence_sha256': bundle.digest(self.descriptors)}
        self.binding_payload = {'version': 1, 'kind': 'getzilla-security-bundle-binding',
            'source_sha256': bundle.digest(self.selector.source().as_dict()), 'report_sha256': bundle.digest(self.report),
            'policy_sha256': POLICY, 'authority_sha256': self.authority.as_policy().authority_digest,
            'issued_at': NOW.isoformat(), 'expires_at': (NOW + timedelta(hours=72)).isoformat(),
            'integration_sha256': bundle.digest(self.integration)}
        self.records = self.provider_records()

    def git_bytes(self, *args, root=None, allow_failure=False):
        result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.hooksPath=' + os.devnull,
            '-c', 'core.fsmonitor=false', '-c', 'commit.gpgsign=false', '-c', 'user.name=fixture',
            '-c', 'user.email=fixture@example.invalid', *args], cwd=root or self.candidate_root,
            env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
        if result.returncode and not allow_failure:
            raise ValueError('owned Git fixture command failed')
        return result.stdout

    def git(self, *args, root=None):
        return self.git_bytes(*args, root=root).decode().strip()

    def evidence(self):
        from adaptive_trust_ci.security_bundle import digest
        payload = copy.deepcopy(self.binding_payload)
        payload.update(report_sha256=digest(self.report), authority_sha256=self.authority.as_policy().authority_digest,
                       integration_sha256=digest(self.integration))
        return Evidence({'payload': payload, 'signature': self.signer.sign(payload)}, copy.deepcopy(self.report),
                        copy.deepcopy(self.integration), copy.deepcopy(self.descriptors))

    def prepare_applicable_osv_evidence(self):
        # Applicable but unavailable license coverage remains unsupported by the sole evaluator.
        self.obligations[1]['applicability'] = 'required'
        self.obligations[1]['check_id'] = 'security-licenses'

    def provider_records(self):
        s, a = self.selector, self.authority
        run = {'id': s.run_id, 'run_attempt': s.run_attempt, 'workflow_id': a.workflow_id, 'event': a.event,
            'head_sha': a.runner_sha, 'head_branch': a.branch, 'path': a.workflow_path, 'status': 'completed',
            'conclusion': 'success', 'repository': {'id': 2, 'full_name': a.runner_repository},
            'head_repository': {'id': 2, 'full_name': a.runner_repository}, 'check_suite_id': 12}
        prefix = '/repos/' + a.runner_repository
        records = {'/repos/' + s.repository: {'id': s.repository_id, 'full_name': s.repository},
            f'/repos/{s.repository}/pulls/{s.pr_number}': {'number': s.pr_number, 'state': 'open',
                'head': {'sha': s.head_sha, 'ref': 'feature', 'repo': {'id': s.repository_id}},
                'base': {'sha': s.base_sha, 'ref': 'main', 'repo': {'id': s.repository_id}}},
            prefix + '/actions/workflows/9/runs?branch=protected&per_page=1': {'total_count': 1, 'workflow_runs': [run]},
            prefix + '/actions/runs/100': run, prefix + '/actions/runs/100/attempts/2': run,
            prefix + '/actions/runs/100/attempts/2/jobs?per_page=100': {'total_count': 1, 'jobs': [
                {'id': 10, 'name': 'producer', 'run_id': 100, 'head_sha': a.runner_sha, 'status': 'completed', 'conclusion': 'success'}]},
            prefix + '/actions/workflows/9': {'id': 9, 'path': a.workflow_path, 'state': 'active'},
            prefix + '/check-suites/12': {'id': 12, 'app': {'id': a.producer_app_id}, 'head_sha': a.runner_sha,
                'repository': {'id': 2}, 'status': 'completed', 'conclusion': 'success'},
            prefix + '/contents/' + a.workflow_path + '?ref=' + a.runner_sha:
                {'type': 'file', 'path': a.workflow_path, 'sha': a.workflow_blob_sha}}
        for repository, sha, tree in ((s.repository, s.head_sha, s.tree_sha),
                (s.repository, a.checker_sha, a.checker_tree_sha), (a.runner_repository, a.runner_sha, a.runner_tree_sha)):
            records[f'/repos/{repository}/git/commits/{sha}'] = {'sha': sha, 'tree': {'sha': tree}}
        return records


class CanonicalConsumerContractTests(unittest.TestCase):
    def fixture(self):
        evidence = Evidence({'payload': {'issued_at': NOW.isoformat(),
            'expires_at': (NOW + timedelta(hours=1)).isoformat()}},
            {'created_at': NOW.isoformat(), 'valid_until': (NOW + timedelta(hours=1)).isoformat()},
            {'merge_sha': 'a' * 40}, {'checks': [{'name': 'owned', 'details': ['fixed']}],
                                     'source_descriptors': []})
        return evidence, BoundPublicVerifier(None, SimpleNamespace(security_core=None), evidence)

    def test_descriptors_are_frozen_and_part_of_the_evidence_identity(self):
        evidence, verifier = self.fixture()
        identity = verifier.evidence_id
        with patch('adaptive_trust_ci.public_admission.evaluate',
                   return_value=SimpleNamespace(eligible=False, blockers=('owned',), valid_until=None)) as evaluate:
            evidence.descriptors['checks'][0]['details'].append('changed')
            verifier(None, NOW)
        supplied = evaluate.call_args.args[3]
        self.assertEqual(supplied.descriptors, {'checks': [{'name': 'owned', 'details': ['fixed']}],
                                                'source_descriptors': []})
        self.assertEqual(verifier.evidence_id, identity)
        other = BoundPublicVerifier(None, SimpleNamespace(security_core=None), evidence)
        self.assertNotEqual(other.evidence_id, identity)

    def test_validated_absolute_horizon_is_consumed_without_legacy_wire(self):
        _, verifier = self.fixture()
        horizon = NOW + timedelta(seconds=9)
        with patch('adaptive_trust_ci.public_admission.evaluate',
                   return_value=SimpleNamespace(eligible=True, blockers=(), valid_until=horizon)):
            self.assertTrue(verifier(None, NOW).eligible)
        try:
            actual = verifier.deadline(NOW)
        except ValueError:
            actual = None
        self.assertEqual(actual, horizon)

    def test_a_later_evaluation_cannot_renew_the_frozen_horizon(self):
        _, verifier = self.fixture()
        first = NOW + timedelta(seconds=4)
        with patch('adaptive_trust_ci.public_admission.evaluate', side_effect=[
                SimpleNamespace(eligible=True, blockers=(), valid_until=first),
                SimpleNamespace(eligible=True, blockers=(), valid_until=first + timedelta(hours=1))]):
            verifier(None, NOW)
            verifier(None, NOW + timedelta(seconds=1))
        try:
            actual = verifier.deadline(NOW + timedelta(seconds=1))
        except ValueError:
            actual = None
        self.assertEqual(actual, first)

    def test_unvalidated_or_absent_horizon_refuses(self):
        for eligible, horizon in ((False, NOW + timedelta(hours=1)), (True, None)):
            with self.subTest(eligible=eligible):
                _, verifier = self.fixture()
                with patch('adaptive_trust_ci.public_admission.evaluate', return_value=
                           SimpleNamespace(eligible=eligible, blockers=(), valid_until=horizon)):
                    verifier(None, NOW)
                with self.assertRaises(ValueError):
                    verifier.deadline(NOW)

    def bounded_verifier(self, calls=0, raw_bytes=0):
        from adaptive_trust_ci.github import GitHubClient
        from adaptive_trust_ci.github_observer import BoundedGetTransport
        evidence, _ = self.fixture()
        transport = BoundedGetTransport(clock=lambda: 0)
        transport.deadline, transport.calls, transport.raw_bytes = 7, calls, raw_bytes
        transport._exchange = lambda *args: (200, b'{}', 2)
        client = GitHubClient(token='fixture', transport=transport)
        verifier = BoundPublicVerifier(client, SimpleNamespace(security_core=None), evidence)
        return verifier, transport

    def one_owned_get(self, client, *args, **kwargs):
        from adaptive_trust_ci.github_observer import ObservationError
        try:
            client.transport.request('GET', 'https://api.github.com/repos/owner/project', {})
        except ObservationError:
            return SimpleNamespace(eligible=False, blockers=('exhausted',), valid_until=None)
        return SimpleNamespace(eligible=True, blockers=(), valid_until=NOW + timedelta(seconds=4))

    def test_exhausted_shared_request_or_raw_budget_is_not_renewed(self):
        for calls, raw_bytes in ((14, 0), (0, 4194304)):
            with self.subTest(calls=calls, raw_bytes=raw_bytes):
                verifier, transport = self.bounded_verifier(calls, raw_bytes)
                with patch('adaptive_trust_ci.public_admission.evaluate', side_effect=self.one_owned_get):
                    self.assertFalse(verifier(None, NOW).eligible)
                self.assertEqual(transport.raw_bytes, raw_bytes)
                self.assertEqual(transport.deadline, 7)

    def test_only_remaining_shared_budget_can_be_consumed(self):
        verifier, transport = self.bounded_verifier(calls=13, raw_bytes=100)
        with patch('adaptive_trust_ci.public_admission.evaluate', side_effect=self.one_owned_get):
            self.assertTrue(verifier(None, NOW).eligible)
            self.assertFalse(verifier(None, NOW).eligible)
        self.assertEqual((transport.calls, transport.raw_bytes, transport.deadline), (14, 102, 7))

    def test_unsupported_evidence_depth_refuses_before_delegation(self):
        evidence, _ = self.fixture()
        value = []
        for _ in range(26):
            value = [value]
        evidence.descriptors['checks'] = value
        refused = False
        try:
            BoundPublicVerifier(None, SimpleNamespace(security_core=None), evidence)
        except ValueError:
            refused = True
        self.assertTrue(refused)


class CanonicalFixtureTests(unittest.TestCase):
    def test_owned_signed_fixture_uses_the_real_canonical_boundary(self):
        from adaptive_trust_ci.public_admission import evaluate
        fixture = CanonicalProducerFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        router = ProviderTransport(fixture.records)
        with patch('adaptive_trust_ci.public_admission.time', SimpleNamespace(monotonic=lambda: 0)):
            decision = evaluate(router.client(), fixture.authority, fixture.selector, fixture.evidence(), now=NOW,
                                snapshot_root=fixture.snapshot_root, candidate_root=fixture.candidate_root)
        self.assertTrue(decision.eligible, decision)
        self.assertEqual(decision.valid_until, NOW + timedelta(hours=72))
        self.assertEqual(len(router.calls), 14)


class ValidatedHorizonBoundaryTests(unittest.TestCase):
    def test_horizon_requires_the_actual_boundary_ports_and_paired_source(self):
        import contextlib
        from unittest.mock import Mock
        from adaptive_trust_ci import public_admission as admission
        from adaptive_trust_ci import security_bundle as bundle
        selector = admission.Selector('owner/project', 1, 7, '1' * 40, '2' * 40, '3' * 40, 11, 2)
        source = selector.source()
        policy = bundle.BundlePolicy('a' * 64)
        identity = {'head_sha': source.head_sha, 'tree_sha': source.tree_sha,
            'checker_sha': '4' * 40, 'checker_tree_sha': '5' * 40,
            'candidate_clean': True, 'checker_clean': True, 'same_project': True}
        expiry = NOW + timedelta(seconds=7)
        source_binding = Mock(side_effect=[identity, dict(identity)])
        finalize = Mock(return_value={'status': 'pass', 'valid_until_utc': expiry.isoformat()})
        inventory = {'complete': True, 'digest': 'b' * 64, 'files': []}
        core = SimpleNamespace(policy_root='owned-policy',
            inventory=SimpleNamespace(collect_inventory=lambda _: inventory),
            security=SimpleNamespace(_policy_digest=lambda _: policy.policy_digest,
                security_obligations=lambda *a, **kw: [{'check_id': 'security-inventory',
                    'applicability': 'required', 'data_sources': []}]),
            tools=SimpleNamespace(_SAST_EXCLUDED=set(), _SAST_SUFFIXES=set()),
            report=SimpleNamespace(_detail_consistent=lambda *a: True,
                source_binding=source_binding, finalize_report=finalize))
        records, checks = [], []
        for name in ('security-inventory', 'secret-scan', 'opengrep', 'bandit', 'trivy-config'):
            required = name in ('security-inventory', 'secret-scan')
            marker = {'kind': 'security-result', 'outcome': 'pass' if required else 'not_applicable',
                      'findings': [], 'gaps': [], 'data_sources': []}
            status = 'pass' if required else 'skip'
            records.append({'name': name, 'status': status, 'details': [marker]})
            checks.append({'name': name, 'status': status, 'outcome': marker['outcome'],
                'finding_count': 0, 'gap_count': 0, 'source_ids': [], 'coverage_sha256': inventory['digest']})
        descriptors = {'checks': records, 'source_descriptors': []}
        document = {'version': 1, 'source': source.as_dict(), 'policy_sha256': policy.policy_digest,
            'binding': None, 'integration': None, 'report': {'inventory_sha256': inventory['digest'],
                'created_at': NOW.isoformat(), 'valid_until': (NOW + timedelta(hours=1)).isoformat(),
                'checks': checks, 'evidence_sha256': bundle.digest(descriptors)}}
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(admission, 'content_manifest', return_value=[]))
            stack.enter_context(patch.object(admission, '_snapshot_preflight', return_value=[]))
            stack.enter_context(patch.object(admission, '_source_binding'))
            stack.enter_context(patch.object(admission, '_integration', return_value=(None, False)))
            facts = admission.validate_local_inputs(policy, bundle.parse_bundle(bundle.canonical_json(document)),
                source_root='owned-source', snapshot_root='owned-snapshots', descriptors=descriptors,
                now=NOW, core=core)
        self.assertTrue(facts.source_validated)
        self.assertEqual(facts.valid_until, expiry.isoformat())
        self.assertEqual(facts.checker_source, ('4' * 40, '5' * 40))
        self.assertEqual(source_binding.call_count, 2)
        finalize.assert_called_once_with(identity, identity, records, inventory['digest'], policy.policy_digest, now=NOW)


class CompositeObservationBudgetTests(unittest.TestCase):
    def budget(self, purpose='merge', used_bytes=0):
        from adaptive_trust_ci import public_merge
        from adaptive_trust_ci.github import GitHubClient
        from adaptive_trust_ci.github_observer import BoundedGetTransport
        allocator = getattr(public_merge, 'ObservationSessions', None)
        self.assertIsNotNone(allocator, 'explicit composite allocation is required')
        self.elapsed, self.size, self.failure = 0, 2, False
        self.clock = lambda: self.elapsed
        self.allocations, self.maximums = [], []
        original = BoundedGetTransport(clock=self.clock)
        original.raw_bytes = used_bytes
        def allocate(deadline, remaining):
            self.allocations.append((deadline, remaining))
            transport = BoundedGetTransport(clock=self.clock)
            def exchange(url, headers, request_deadline, maximum):
                self.maximums.append((request_deadline, maximum))
                if self.failure:
                    raise TimeoutError('owned finite exchange unavailable')
                return 200, b'{}', self.size
            transport._exchange = exchange
            return GitHubClient(token='fixture', transport=transport)
        return allocator(GitHubClient(token='fixture', transport=original), allocate, purpose=purpose)

    def get(self, client):
        return client.transport.request('GET', 'https://api.github.com/repos/owner/project', {})

    def test_merge_two_and_publisher_four_sessions_each_keep_exact14_limit(self):
        from adaptive_trust_ci.github_observer import ObservationError
        for purpose, limit in (('merge', 2), ('publisher', 4)):
            with self.subTest(purpose=purpose):
                budget = self.budget(purpose)
                for _ in range(limit):
                    with budget.session('a' * 64) as client:
                        for _ in range(14):
                            self.get(client)
                        with self.assertRaises(ObservationError):
                            self.get(client)
                with self.assertRaises(ValueError):
                    with budget.session('a' * 64):
                        self.fail('extra session allocated')
                self.assertEqual(len(self.allocations), limit)
                self.assertEqual(budget.remaining_bytes, 4194304 - 28 * limit)

    def test_cross_session_remaining_raw_is_passed_before_exchange(self):
        budget = self.budget(used_bytes=3145728)
        self.size = 1048576
        with budget.session('a' * 64) as client:
            self.get(client)
        self.assertEqual(self.maximums, [(5, 1048576)])
        self.assertEqual(budget.remaining_bytes, 0)
        with self.assertRaises(ValueError):
            with budget.session('a' * 64):
                self.fail('exhausted bytes acquired new credit')
        self.assertEqual(len(self.allocations), 1)

    def test_plus_one_wire_claim_refuses_without_decode_or_refund(self):
        from adaptive_trust_ci.github_observer import ObservationError
        budget = self.budget(used_bytes=3145728)
        self.size = 1048577
        with budget.session('a' * 64) as client:
            with self.assertRaises(ObservationError):
                self.get(client)
        self.assertEqual(budget.remaining_bytes, 0)

    def test_original_absolute_deadline_never_renews(self):
        budget = self.budget()
        self.elapsed = 19
        with budget.session('a' * 64) as client:
            self.assertEqual(client.transport.deadline, 20)
            self.get(client)
        self.assertEqual(self.maximums[0][0], 20)
        self.elapsed = 20
        with self.assertRaises(ValueError):
            with budget.session('a' * 64):
                self.fail('expired operation acquired a session')

    def test_unknown_exchange_burns_reserved_bytes_and_no_extra_session(self):
        from adaptive_trust_ci.github_observer import ObservationError
        budget = self.budget()
        self.failure = True
        with budget.session('a' * 64) as client:
            with self.assertRaises(ObservationError):
                self.get(client)
        self.assertEqual(budget.remaining_bytes, 3145728)
        self.failure = False
        with budget.session('a' * 64) as client:
            self.get(client)
        with self.assertRaises(ValueError):
            with budget.session('a' * 64):
                self.fail('UNKNOWN reset session credit')
        self.assertEqual(len(self.allocations), 2)

    def test_different_evidence_cannot_rebind_a_consumed_operation(self):
        budget = self.budget()
        with budget.session('a' * 64) as client:
            self.get(client)
        with self.assertRaises(ValueError):
            with budget.session('b' * 64):
                self.fail('operation rebound to substituted evidence')

from dataclasses import replace
from test_public_merge import LocalBackend
from adaptive_trust_ci.public_merge import ObservationSessions, Snapshot, SignedReview, execute, review_bytes, review_payload


class SignedAdmissionMergeTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(dir=Path(__file__).resolve().parents[2] / '.getzilla/runtime')
        self.addCleanup(temp.cleanup)
        self.db_path = Path(temp.name) / 'fence.db'
        self.fixture = CanonicalProducerFixture()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.transport = ProviderTransport(self.fixture.records)
        self.client = self.transport.client()
        self.private = Ed25519PrivateKey.generate()
        self.pem = self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.clock = NOW
        self.selector = self.fixture.selector

    def arrange(self, evidence=None):
        evidence = evidence or self.fixture.evidence()
        merged = self.fixture.integration['merge_sha']
        observations = ObservationSessions(self.client, self.transport.client, purpose='merge')
        verifier = BoundPublicVerifier(self.client, self.fixture.authority, evidence,
            snapshot_root=self.fixture.snapshot_root, candidate_root=self.fixture.candidate_root,
            observations=observations)
        payload = review_payload(self.selector, 12, 1, 'approve', self.clock, evidence_id=verifier.evidence_id,
                                 merge_oid=merged, target_generation=1)
        review = SignedReview(payload, base64.b64encode(self.private.sign(review_bytes(payload))).decode())
        backend = LocalBackend(Snapshot('initial', self.selector, 'main', True, (review,), True,
                                        verifier.evidence_id, True, None, merged, 1), self.db_path)
        backend.now = self.clock
        return verifier, backend

    def dispatch(self, verifier, backend):
        with patch('adaptive_trust_ci.public_admission.time', SimpleNamespace(monotonic=lambda: 0)):
            return execute(backend, verifier, owner_id=12, owner_key=self.pem, selector=self.selector,
                           clock=lambda: self.clock)

    def test_signed_owner_and_producer_with_exact_empty_candidate(self):
        evidence = self.fixture.evidence()
        verifier, backend = self.arrange(evidence)
        evidence.report.clear()
        self.assertEqual(self.dispatch(verifier, backend).state, 'merged')
        self.assertEqual(backend.merges, [self.selector])
        self.assertTrue(self.transport.calls)
        self.assertTrue(all(method == 'GET' and body is None for method, _, body in self.transport.calls))

    def test_applicable_osv_cannot_grant_a_merge_with_unqualified_dependencies(self):
        self.fixture.prepare_applicable_osv_evidence()
        self.selector = self.fixture.selector
        verifier, backend = self.arrange()
        self.assertEqual(self.dispatch(verifier, backend).state, 'blocked')
        self.assertFalse(backend.calls)

    def test_old_report_blocks_after_72h(self):
        self.clock += timedelta(hours=72, microseconds=1)
        verifier, backend = self.arrange()
        self.assertEqual(self.dispatch(verifier, backend).state, 'blocked')
        self.assertFalse(backend.calls)
        self.assertFalse(backend.merges)

    def advance_clock_on_first_read(self, backend):
        observed = self.clock + timedelta(seconds=9)
        def delayed_read():
            if not self.transport.calls:
                self.clock = backend.now = observed
        self.transport.before_read = delayed_read
        return observed

    def test_slow_successful_verification_starts_a_fresh_dispatch_window(self):
        verifier, backend = self.arrange()
        observed = self.advance_clock_on_first_read(backend)
        self.assertEqual(self.dispatch(verifier, backend).state, 'merged')
        ticket, = backend.calls
        self.assertEqual(ticket.valid_from, observed)
        self.assertEqual(ticket.valid_until, observed + timedelta(seconds=5))

    def test_binding_expired_during_provider_reads_blocks_dispatch(self):
        self.fixture.binding_payload['expires_at'] = (self.clock + timedelta(seconds=8)).isoformat()
        verifier, backend = self.arrange()
        self.advance_clock_on_first_read(backend)
        self.assertEqual(self.dispatch(verifier, backend).state, 'blocked')
        self.assertFalse(backend.calls)

    def test_rechecking_does_not_extend_binding(self):
        self.fixture.binding_payload['expires_at'] = (self.clock + timedelta(seconds=2)).isoformat()
        verifier, backend = self.arrange()
        backend.now += timedelta(seconds=2, microseconds=1)
        result = self.dispatch(verifier, backend)
        self.assertEqual(result.state, 'blocked')
        self.assertEqual(result.reason, 'atomic-backend-expired')
        self.assertEqual(backend.calls[0].valid_until, self.clock + timedelta(seconds=2))
        self.assertFalse(backend.merges)

    def test_newer_attempt_at_source_overrides_approvable_snapshot(self):
        verifier, backend = self.arrange()
        self.fixture.records['/repos/independent/runner/actions/runs/100']['run_attempt'] = 3
        self.assertEqual(self.dispatch(verifier, backend).state, 'blocked')
        self.assertFalse(backend.calls)

    def test_published_time_can_be_earlier_than_database_download_time(self):
        # Exercise the accepted pure freshness calculator, while the canonical
        # consumer still refuses an unsupported applicable intelligence family.
        self.fixture.prepare_applicable_osv_evidence()
        self.selector = self.fixture.selector
        checks = copy.deepcopy(self.fixture.descriptors['checks'])
        feed = {'source_id': 'epss', 'acquisition': {'last_verified_sync_utc': self.clock.isoformat(),
            'source_published_at': (self.clock - timedelta(hours=72) + timedelta(seconds=2)).isoformat()}}
        checks[0]['details'][0]['data_sources'] = [feed]
        namespace = dict(self.fixture.pure_report)
        # This fixed pure timing model does not qualify the synthetic feed.
        namespace['_detail_consistent'] = lambda *args: True
        function = namespace['finalize_report']
        import types
        function = types.FunctionType(function.__code__, namespace)
        identity = {'head_sha': self.selector.head_sha, 'tree_sha': self.selector.tree_sha,
            'checker_sha': self.fixture.authority.checker_sha, 'checker_tree_sha': self.fixture.authority.checker_tree_sha,
            'candidate_clean': True, 'checker_clean': True, 'same_project': True}
        timed = function(identity, identity, checks, self.fixture.report['inventory_sha256'], POLICY, now=self.clock)
        self.assertEqual(datetime.fromisoformat(timed['valid_until_utc']), self.clock + timedelta(seconds=2))
        verifier, backend = self.arrange()
        self.assertEqual(self.dispatch(verifier, backend).state, 'blocked')
        self.assertFalse(backend.calls)

    def test_producer_and_owner_must_not_share_the_same_public_key(self):
        self.fixture.signer = Signer(self.private)
        self.fixture.authority = replace(self.fixture.authority, public_key_pem=self.pem)
        self.pem = self.pem.replace(b'\n', b'\r\n')
        verifier, backend = self.arrange()
        result = self.dispatch(verifier, backend)
        self.assertEqual(result.state, 'blocked')
        self.assertEqual(result.reason, 'producer-and-owner-share-key')
        self.assertFalse(backend.calls)


class DispatchBudgetBoundaryTests(SignedAdmissionMergeTests):
    def test_processing_elapsed_does_not_force_validation_at_the_distant_expiry(self):
        verifier, backend = self.arrange()
        with patch('adaptive_trust_ci.public_admission.time',
                   SimpleNamespace(monotonic=unittest.mock.Mock(side_effect=[0, 0.001, 0, 0.001]))):
            result = execute(backend, verifier, owner_id=12, owner_key=self.pem,
                             selector=self.selector, clock=lambda: self.clock)
        self.assertEqual(result.state, 'merged', result)
        self.assertEqual(backend.calls[0].valid_until, self.clock + timedelta(seconds=5))


class CanonicalDispatchRefusalTests(unittest.TestCase):
    def test_generic_positive_without_validated_horizon_never_dispatches(self):
        from test_public_merge import FinalMergeTests, OWNER
        fixture = FinalMergeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for claimed_horizon in (False, True):
            if claimed_horizon:
                fixture.verify.deadline = lambda now: now + timedelta(seconds=5)
            result = execute(fixture.backend, fixture.verify, owner_id=OWNER, owner_key=fixture.pem,
                             selector=fixture.selector, clock=lambda: fixture.now)
            self.assertEqual(result.state, 'blocked')
            self.assertEqual(fixture.backend.calls, [])
