"""Public controller qualification using real signatures, Git objects and a local HTTP boundary."""
import copy
import hashlib
import hmac
import io
import json
import secrets
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import test_public_merge_admission as producer
from adaptive_trust_ci.github import GitHubClient
from adaptive_trust_ci.public_merge import BoundPublicVerifier, ObservationSessions
from adaptive_trust_ci.public_publisher import (
    PublicationJournal, PublisherConfig, publish, verify_webhook, scoped_client_factory,
)
from adaptive_trust_ci.github_app import GitHubAppAuth


class PublicationPortFixture:
    """Finite local model frames, not a provider transport or authority proof."""
    def __init__(self, directory, raw_change=None):
        from datetime import datetime, timezone
        from adaptive_trust_ci.public_admission import Evidence, Selector
        self.now = datetime(2026, 11, 11, tzinfo=timezone.utc)
        self.selector = Selector('owner/project', 1, 7, '1' * 40, '2' * 40, '3' * 40, 11, 2)
        self.config = PublisherConfig('owner/project', 1, 9, 10, 'a' * 64)
        self.verifier = BoundPublicVerifier(None, SimpleNamespace(security_core=None), Evidence({}, {}, None, {}))
        self.journal = PublicationJournal.create(Path(directory) / 'model.sqlite')
        self.calls, self.checks, self.broker_calls, self.closed = [], [], [], []
        self.raw_change = raw_change
        self.client = SimpleNamespace(api_url='https://api.github.com',
                                      _request=lambda *a: self.unqualified_request())

    def unqualified_request(self):
        raise AssertionError('ordinary client transport must never run')

    def model(self, method, path, body):
        self.calls.append((method, path))
        if path == '/installation/repositories?per_page=100':
            return {'total_count': 1, 'repositories': [{'id': 1, 'full_name': 'owner/project'}]}
        if path == '/repos/owner/project':
            return {'id': 1, 'full_name': 'owner/project'}
        if '/check-runs?' in path:
            return {'total_count': len(self.checks), 'check_runs': list(self.checks)}
        if method == 'POST':
            self.checks.append({**body, 'id': 1, 'app': {'id': 9},
                'url': 'https://api.github.com/repos/owner/project/check-runs/1'})
        elif method == 'PATCH':
            self.checks[0].update(body)
        return dict(self.checks[0])

    def factory(self, *args):
        self.broker_calls.append(args)
        return self.client

    def open(self, client, method, path, body, *, deadline, maximum):
        raw = json.dumps(self.model(method, path, body)).encode()
        if self.raw_change:
            raw = self.raw_change(method, path, raw)
        closed = self.closed
        class Response(io.BytesIO):
            status, encoding = 200, None
            url = 'https://api.github.com' + path
            def close(inner):
                closed.append(path)
                super().close()
        return Response(raw)

    def run(self, **kwargs):
        from datetime import timedelta
        with patch.object(BoundPublicVerifier, 'matches_publisher', return_value=True), \
             patch.object(BoundPublicVerifier, '__call__', return_value=
                          SimpleNamespace(eligible=True, blockers=(), valid_until=self.now + timedelta(hours=1))):
            return publish(self.config, self.journal, self.verifier, self.selector,
                           client_factory=self.factory, clock=lambda: self.now,
                           enabled=True, request_port=self, **kwargs)


class BoundedPublicationPortTests(unittest.TestCase):
    def fixture(self, change=None):
        directory = TemporaryDirectory(dir=Path(__file__).resolve().parents[2] / '.getzilla/runtime')
        self.addCleanup(directory.cleanup)
        return PublicationPortFixture(directory.name, change)

    def test_explicit_model_port_publishes_once_and_closes_every_frame(self):
        fixture = self.fixture()
        self.assertEqual(fixture.run().state, 'published')
        self.assertEqual(sum(method == 'POST' for method, _ in fixture.calls), 1)
        self.assertEqual(len(fixture.closed), len(fixture.calls))

    def test_oversize_raw_frame_refuses_before_any_publication(self):
        fixture = self.fixture(lambda *a: b' ' * 1048577)
        self.assertEqual(fixture.run().state, 'unknown')
        self.assertEqual(fixture.checks, [])
        self.assertEqual(len(fixture.closed), 1)

    def test_malformed_post_reply_stays_unknown_and_recovery_never_reposts(self):
        fixture = self.fixture(lambda method, path, raw: b'{' if method == 'POST' else raw)
        self.assertEqual(fixture.run().state, 'unknown')
        self.assertEqual(len(fixture.checks), 1)
        self.assertEqual(fixture.run().state, 'published')
        self.assertEqual(sum(method == 'POST' for method, _ in fixture.calls), 1)


class UnboundedPublicationRefusalTests(unittest.TestCase):
    def test_ordinary_request_client_is_refused_before_broker_or_effect(self):
        from datetime import datetime, timedelta, timezone
        from adaptive_trust_ci.public_admission import Evidence, Selector
        now = datetime(2026, 11, 11, tzinfo=timezone.utc)
        selector = Selector('owner/project', 1, 7, '1' * 40, '2' * 40, '3' * 40, 11, 2)
        config = PublisherConfig('owner/project', 1, 9, 10, 'a' * 64)
        verifier = BoundPublicVerifier(None, SimpleNamespace(security_core=None), Evidence({}, {}, None, {}))
        calls, checks = [], []
        def request(method, path, body=None):
            calls.append((method, path))
            if path == '/installation/repositories?per_page=100':
                return {'total_count': 1, 'repositories': [{'id': 1, 'full_name': 'owner/project'}]}
            if path == '/repos/owner/project':
                return {'id': 1, 'full_name': 'owner/project'}
            if '/check-runs?' in path:
                return {'total_count': len(checks), 'check_runs': list(checks)}
            if method == 'POST':
                checks.append({**body, 'id': 1, 'app': {'id': 9},
                    'url': 'https://api.github.com/repos/owner/project/check-runs/1'})
            elif method == 'PATCH':
                checks[0].update(body)
            return dict(checks[0])
        client = SimpleNamespace(api_url='https://api.github.com', _request=request)
        broker_calls = []
        def factory(*args):
            broker_calls.append(args)
            return client
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[2] / '.getzilla/runtime') as directory:
            journal = PublicationJournal.create(Path(directory) / 'journal.sqlite')
            with patch.object(BoundPublicVerifier, 'matches_publisher', return_value=True), \
                 patch.object(BoundPublicVerifier, '__call__', return_value=
                              SimpleNamespace(eligible=True, blockers=(), valid_until=now + timedelta(hours=1))):
                result = publish(config, journal, verifier, selector, client_factory=factory,
                                 clock=lambda: now, enabled=True)
        self.assertEqual(result.state, 'blocked')
        self.assertEqual(broker_calls, [])
        self.assertEqual(calls, [])


class SharedPublicationBudgetTests(BoundedPublicationPortTests):
    def composed(self, change=None):
        fixture = self.fixture(change)
        model = producer.CompositeObservationBudgetTests()
        fixture.verifier.observations = model.budget('publisher')
        self.model = model
        return fixture

    def test_publication_raw_consumes_the_same_remaining_allocation(self):
        fixture = self.composed()
        budget = fixture.verifier.observations
        budget._left = 1
        result = fixture.run()
        self.assertEqual(result.state, 'unknown')
        self.assertEqual(fixture.calls, [('GET', '/installation/repositories?per_page=100')])
        self.assertEqual(budget.remaining_bytes, 0)

    def test_original_deadline_and_purpose_refuse_before_effects(self):
        for purpose, expired in (('merge', False), ('publisher', True)):
            fixture = self.composed()
            fixture.verifier.observations.purpose = purpose
            if expired:
                self.model.elapsed = 21
            self.assertEqual(fixture.run().state, 'blocked')
            self.assertEqual(fixture.calls, [])

    def test_unknown_retry_does_not_allocate_a_fifth_evaluation(self):
        for lost in ('POST', 'PATCH'):
            def change(method, path, raw):
                if method == lost:
                    raise TimeoutError('owned committed operation lost its reply')
                return raw
            fixture = self.composed(change)
            budget = fixture.verifier.observations
            def verify(selector, now):
                with budget.session(fixture.verifier.evidence_id):
                    pass
                return SimpleNamespace(eligible=True, blockers=())
            with patch.object(BoundPublicVerifier, 'matches_publisher', return_value=True), \
                 patch.object(BoundPublicVerifier, '__call__', side_effect=verify):
                def invoke():
                    return publish(fixture.config, fixture.journal, fixture.verifier, fixture.selector,
                        client_factory=fixture.factory, clock=lambda: fixture.now, enabled=True, request_port=fixture)
                self.assertEqual(invoke().state, 'unknown')
                fixture.raw_change = None
                self.assertEqual(invoke().state, 'published')
            self.assertEqual(budget._sessions, 4)
            self.assertEqual(sum(method == 'POST' for method, _ in fixture.calls), 1)


class PublicPublisherTests(unittest.TestCase):
    def setUp(self):
        self.fixture = producer.CanonicalProducerFixture()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        temp = TemporaryDirectory(dir=Path(__file__).resolve().parents[2] / '.getzilla/runtime')
        self.addCleanup(temp.cleanup)
        self.journal = PublicationJournal.create(Path(temp.name) / 'publication.sqlite')
        self.config = PublisherConfig('Dimkox/Getzilla', 1404516308, 9001, 9002, producer.POLICY)
        self.now = producer.NOW
        self.writes = []
        self.checks = []
        self.credentials = []
        self.lose_create = False
        self.lose_patch = False
        self.before_patch = lambda: None
        self.records = self.fixture.records
        self.transport = self
        self.client = GitHubClient(token=secrets.token_urlsafe(24), transport=self)
        self.router = producer.ProviderTransport(self.records)
        self.verifier = self.new_verifier(self.fixture.evidence())
        self.terminal = False

    def new_verifier(self, evidence):
        original = self.router.client()
        return BoundPublicVerifier(original, self.fixture.authority, evidence,
            snapshot_root=self.fixture.snapshot_root, candidate_root=self.fixture.candidate_root,
            observations=ObservationSessions(original, self.router.client, purpose='publisher'))

    def open(self, client, method, path, body, *, deadline, maximum):
        status, value = self.request(method, 'https://api.github.com' + path, {}, body)
        class Frame(io.BytesIO):
            url, encoding = 'https://api.github.com' + path, None
        frame = Frame(json.dumps(value).encode())
        frame.status = status
        return frame

    def request(self, method, url, headers, body):
        path = url.removeprefix('https://api.github.com')
        prefix = '/repos/Dimkox/Getzilla'
        if method == 'GET':
            if path == '/installation/repositories?per_page=100':
                return 200, {'total_count': 1, 'repositories': [
                    {'id': 1404516308, 'full_name': 'Dimkox/Getzilla'}]}
            if '/check-runs?' in path:
                return 200, {'total_count': len(self.checks), 'check_runs': copy.deepcopy(self.checks)}
            if path.startswith(prefix + '/check-runs/'):
                return 200, copy.deepcopy(self.checks[int(path.rsplit('/', 1)[1]) - 1])
            return 200, copy.deepcopy(self.records[path])
        self.writes.append((method, path, copy.deepcopy(body)))
        if method == 'POST' and path == prefix + '/check-runs':
            check = dict(body, id=len(self.checks) + 1, app={'id': 9001})
            check['url'] = 'https://api.github.com' + prefix + '/check-runs/' + str(check['id'])
            self.checks.append(check)
            if self.lose_create:
                raise TimeoutError('reply lost after creation')
            return 201, copy.deepcopy(check)
        if method == 'PATCH' and path.startswith(prefix + '/check-runs/'):
            self.before_patch()
            check = self.checks[int(path.rsplit('/', 1)[1]) - 1]
            check.update(body)
            if self.lose_patch:
                raise TimeoutError('reply lost after completion')
            return 200, copy.deepcopy(check)
        raise AssertionError((method, path))

    def client_factory(self, installation_id, request):
        self.credentials.append((installation_id, request))
        return self.client

    def run_publisher(self, *, enabled=True):
        # A completed prior operation is a new explicit fixture allocation.
        # UNKNOWN retries retain the same object, deadline, counters and raw budget.
        if self.terminal:
            self.verifier = self.new_verifier(producer.Evidence(**json.loads(self.verifier._bundle)))
        self.terminal = False
        with patch('adaptive_trust_ci.public_admission.time', SimpleNamespace(monotonic=lambda: 0)):
            result = publish(self.config, self.journal, self.verifier, self.fixture.selector,
                client_factory=self.client_factory, clock=lambda: self.now, enabled=enabled, request_port=self)
        self.terminal = result.state == 'published'
        return result

    def test_disabled_acquires_no_credentials_and_writes_nothing(self):
        self.assertEqual(self.run_publisher(enabled=False).state, 'disabled')
        self.assertEqual(self.credentials, [])
        self.assertEqual(self.writes, [])

    def test_exact_signed_candidate_publishes_one_success_with_scoped_permissions(self):
        result = self.run_publisher()
        self.assertEqual(result.state, 'published', result)
        self.assertEqual(self.checks[0]['head_sha'], self.fixture.selector.head_sha)
        self.assertEqual(self.checks[0]['app']['id'], 9001)
        self.assertEqual(self.checks[0]['conclusion'], 'success')
        self.assertEqual(self.credentials[0], (9002, {'repository_ids': [1404516308], 'permissions': {
            'checks': 'write', 'actions': 'read', 'contents': 'read', 'pull_requests': 'read'}}))
        self.assertEqual(self.run_publisher().state, 'published')
        self.assertEqual(len([item for item in self.writes if item[0] == 'POST']), 1)

    def test_candidate_success_and_wrong_head_never_publish(self):
        self.records['/repos/Dimkox/Getzilla/pulls/318']['head']['sha'] = producer.BASE
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.assertFalse(self.credentials)
        self.assertFalse(self.writes)

    def test_stale_report_and_old_attempt_never_publish(self):
        self.now += producer.timedelta(hours=73)
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.now = producer.NOW
        self.records['/repos/independent/runner/actions/runs/100']['run_attempt'] = 3
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.assertFalse(self.writes)

    def test_lost_create_reply_reconciles_without_a_second_post(self):
        self.lose_create = True
        self.assertEqual(self.run_publisher().state, 'unknown')
        self.journal = PublicationJournal(self.journal.path)
        self.assertEqual(self.run_publisher().state, 'published')
        self.assertEqual(len([item for item in self.writes if item[0] == 'POST']), 1)

    def test_lost_completion_reply_is_reconciled(self):
        self.lose_patch = True
        self.assertEqual(self.run_publisher().state, 'unknown')
        self.assertEqual(self.run_publisher().state, 'published')
        self.assertEqual(len(self.writes), 2)

    def test_uncertain_creation_without_a_receipt_never_reissues(self):
        self.lose_create = True
        self.assertEqual(self.run_publisher().state, 'unknown')
        self.checks.clear()
        self.assertEqual(self.run_publisher().state, 'unknown')
        self.assertEqual(len(self.writes), 1)

    def test_wrong_publisher_is_never_patched_or_accepted(self):
        self.lose_create = True
        self.run_publisher()
        self.checks[0]['app']['id'] = 123
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.assertEqual(len(self.writes), 1)

    def test_wrong_context_or_head_or_repository_is_never_reused(self):
        self.lose_create = True
        self.run_publisher()
        original = copy.deepcopy(self.checks[0])
        for change in ({'name': 'linux'}, {'head_sha': producer.BASE}, {'url': 'https://api.github.com/repos/other/repo/check-runs/1'}):
            with self.subTest(change=change):
                self.checks[0] = dict(original, **change)
                self.assertEqual(self.run_publisher().state, 'blocked')
                self.assertEqual(len(self.writes), 1)

    def test_head_change_after_creation_prevents_success(self):
        factory = self.client_factory
        def create_client(*args):
            client = factory(*args)
            self.records['/repos/Dimkox/Getzilla/pulls/318']['head']['sha'] = producer.BASE
            return client
        self.client_factory = create_client
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.assertFalse(any(item[2].get('conclusion') == 'success' for item in self.writes))

    def test_duplicate_matching_checks_are_ambiguous(self):
        self.lose_create = True
        self.run_publisher()
        self.checks.append(copy.deepcopy(self.checks[0]))
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.assertEqual(len(self.writes), 1)

    def test_conflicting_signed_evidence_for_one_attempt_cannot_publish_twice(self):
        self.original_binding = copy.deepcopy(self.fixture.evidence().binding)
        self.assertEqual(self.run_publisher().state, 'published')
        self.fixture.binding_payload['issued_at'] = (self.now - producer.timedelta(seconds=1)).isoformat()
        self.fixture.binding_payload['expires_at'] = (self.now + producer.timedelta(hours=71)).isoformat()
        self.router = producer.ProviderTransport(self.records)
        self.verifier = self.new_verifier(self.fixture.evidence())
        self.terminal = False
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.assertEqual(self.checks[0]['conclusion'], 'action_required')
        self.verifier = self.new_verifier(producer.Evidence(copy.deepcopy(self.original_binding),
            self.fixture.report, self.fixture.integration, self.fixture.descriptors))
        self.journal = PublicationJournal(self.journal.path)
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.assertEqual(len([item for item in self.writes if item[0] == 'POST']), 1)

    def test_change_during_success_write_is_demoted_after_readback(self):
        self.before_patch = lambda: self.records['/repos/Dimkox/Getzilla/pulls/318']['head'].update(sha=producer.BASE)
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.assertEqual(self.checks[0]['conclusion'], 'action_required')

    def test_webhook_authenticates_original_bytes_and_rejects_forgery(self):
        raw, secret = b'{"action":"completed"}', b'x' * 32
        signature = 'sha256=' + hmac.new(secret, raw, hashlib.sha256).hexdigest()
        self.assertTrue(verify_webhook(raw, signature, secret))
        self.assertFalse(verify_webhook(raw + b' ', signature, secret))
        self.assertFalse(verify_webhook(raw, 'sha256=' + '0' * 64, secret))
        self.assertFalse(verify_webhook(raw, signature, b''))

    def test_webhook_delivery_replay_is_durable(self):
        self.assertTrue(self.journal.accept_delivery('event-1'))
        self.journal = PublicationJournal(self.journal.path)
        self.assertFalse(self.journal.accept_delivery('event-1'))

    def test_real_broker_never_uses_installation_wide_token_request(self):
        requests = []
        class TokenTransport:
            def request(inner, method, url, headers, body):
                requests.append((method, url, body))
                if method == 'GET' and url == 'https://api.github.com/app/installations/9002':
                    return 200, {'id': 9002, 'app_id': 9001}
                return 201, {'token': 'test-scoped-token',
                    'expires_at': (producer.NOW + producer.timedelta(hours=1)).isoformat()}
        auth = GitHubAppAuth(9001, 9002, Path('/unused-test-key'), transport=TokenTransport(), now_fn=lambda: self.now)
        auth._jwt_headers = lambda now: {'Authorization': 'fixture JWT'}
        factory = scoped_client_factory(self.config, auth)
        client = factory(9002, self.config.token_request())
        self.assertEqual(client._access_token(), 'test-scoped-token')
        self.assertEqual(client._access_token(), 'test-scoped-token')
        self.assertEqual(requests, [('GET', 'https://api.github.com/app/installations/9002', None),
                                   ('POST', 'https://api.github.com/app/installations/9002/access_tokens',
                                    self.config.token_request())])
        with self.assertRaises(ValueError):
            factory(9002, {'permissions': {'contents': 'write'}})

    def test_token_readback_refuses_broader_repository_access(self):
        request = self.request
        def broader(method, url, headers, body):
            if url.endswith('/installation/repositories?per_page=100'):
                return 200, {'total_count': 2, 'repositories': [
                    {'id': 1404516308, 'full_name': 'Dimkox/Getzilla'}, {'id': 2, 'full_name': 'other/repo'}]}
            return request(method, url, headers, body)
        self.request = lambda method, url, headers, body: broader(method, url, headers, body)
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.assertEqual(self.writes, [])

    def test_broker_rejects_wrong_installation_before_minting_a_token(self):
        requests = []
        class TokenTransport:
            def request(inner, method, url, headers, body):
                requests.append((method, url))
                self.assertEqual(headers['Authorization'], 'fixture JWT')
                return 200, {'id': 9002, 'app_id': 123}
        auth = GitHubAppAuth(9001, 9002, Path('/unused-test-key'), transport=TokenTransport(), now_fn=lambda: self.now)
        auth._jwt_headers = lambda now: {'Authorization': 'fixture JWT'}
        client = scoped_client_factory(self.config, auth)(9002, self.config.token_request())
        with self.assertRaises(ValueError):
            client._access_token()
        self.assertEqual(requests, [('GET', 'https://api.github.com/app/installations/9002')])
