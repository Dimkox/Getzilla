"""Public controller qualification using real signatures, Git objects and a local HTTP boundary."""
import copy
from dataclasses import replace
import hashlib
import hmac
import secrets
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import test_public_admission as producer
from adaptive_trust_ci.github import GitHubClient
from adaptive_trust_ci.public_merge import BoundPublicVerifier
from adaptive_trust_ci.public_publisher import (
    PublicationJournal, PublisherConfig, publish, verify_webhook, scoped_client_factory,
)
from adaptive_trust_ci.github_app import GitHubAppAuth


class PublicPublisherTests(unittest.TestCase):
    def setUp(self):
        self.fixture = producer.PublicAdmissionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        temp = TemporaryDirectory()
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
        self.verifier = BoundPublicVerifier(self.client, self.fixture.authority, self.fixture.evidence(),
                                            candidate_root=self.fixture.candidate_root)

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
        return publish(self.config, self.journal, self.verifier, self.fixture.selector,
                       client_factory=self.client_factory, clock=lambda: self.now, enabled=enabled)

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
        self.verifier = BoundPublicVerifier(self.client, self.fixture.authority, self.fixture.evidence(),
                                            candidate_root=self.fixture.candidate_root)
        self.assertEqual(self.run_publisher().state, 'blocked')
        self.assertEqual(self.checks[0]['conclusion'], 'action_required')
        self.verifier = BoundPublicVerifier(self.client, self.fixture.authority,
            producer.Evidence(copy.deepcopy(self.original_binding), self.fixture.report),
            candidate_root=self.fixture.candidate_root)
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
        self.client.transport = type('Transport', (), {'request': staticmethod(broader)})()
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
