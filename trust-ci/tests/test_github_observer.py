from __future__ import annotations

import io
import json
from types import SimpleNamespace
from unittest import mock
import unittest

from adaptive_trust_ci.github_observer import BoundedGetTransport, ObservationError, observe
from adaptive_trust_ci.github import GitHubClient
from adaptive_trust_ci.security_bundle import BundlePolicy, GithubSource


class Response(io.BytesIO):
    status = 200

    def __init__(self, value, headers=None):
        super().__init__(value)
        self.headers = headers or {}


class Opener:
    def __init__(self, response):
        self.response, self.calls = response, []

    def open(self, request, *, timeout):
        self.calls.append((request.method, request.full_url, timeout))
        return self.response


class GitHubObserverTests(unittest.TestCase):
    def test_raw_overflow_is_refused_before_json_decode(self):
        opener = Opener(Response(b'{"padding":"' + b'x' * 1048576 + b'"}'))
        transport = BoundedGetTransport(opener=opener, clock=lambda: 0)
        with mock.patch('adaptive_trust_ci.github_observer.bounded_json', return_value={}) as decode:
            with self.assertRaises(ObservationError):
                transport.request('GET', 'https://api.github.com/repos/owner/project', {})
            decode.assert_not_called()
        self.assertTrue(opener.response.closed)

    def test_encoding_and_foreign_origin_never_decode_or_dispatch(self):
        encoded = Opener(Response(b'{}', {'Content-Encoding': 'gzip'}))
        with self.assertRaises(ObservationError):
            BoundedGetTransport(opener=encoded, clock=lambda: 0).request(
                'GET', 'https://api.github.com/repos/owner/project', {})
        foreign = Opener(Response(b'{}'))
        with self.assertRaises(ObservationError):
            BoundedGetTransport(opener=foreign, clock=lambda: 0).request('GET', 'https://example.com/repos/x/y', {})
        self.assertEqual(foreign.calls, [])

    def test_bounded_plain_response_uses_only_get(self):
        opener = Opener(Response(b'{"id":1}'))
        status, value = BoundedGetTransport(opener=opener, clock=lambda: 0).request(
            'GET', 'https://api.github.com/repos/owner/project', {})
        self.assertEqual((status, value), (200, {'id': 1}))
        self.assertEqual(opener.calls[0][0], 'GET')
        self.assertLessEqual(opener.calls[0][2], 5)

    def test_aggregate_request_and_deadline_limits(self):
        class Many:
            def open(self, request, *, timeout):
                return Response(json.dumps({str(i): 'x' * 4000 for i in range(250)}).encode())
        transport = BoundedGetTransport(opener=Many(), clock=lambda: 0)
        for _ in range(4):
            transport.request('GET', 'https://api.github.com/repos/owner/project', {})
        with self.assertRaises(ObservationError):
            transport.request('GET', 'https://api.github.com/repos/owner/project', {})
        opener = Opener(Response(b'{}'))
        expired = BoundedGetTransport(opener=opener, clock=mock.Mock(side_effect=[0, 21]))
        with self.assertRaises(ObservationError):
            expired.request('GET', 'https://api.github.com/repos/owner/project', {})
        self.assertEqual(opener.calls, [])


def provider_fixture(change=None):
    source = GithubSource('owner/project', 1, 7, 'refs/heads/main', '8' * 40, '1' * 40, '2' * 40, 11, 2)
    policy = BundlePolicy('a' * 64, authority_digest='b' * 64, required_jobs=('producer',))
    authority = SimpleNamespace(repository='owner/project', repository_id=1, runner_repository='owner/runner', runner_repository_id=2,
        runner_sha='3' * 40, runner_tree_sha='4' * 40, checker_sha='5' * 40, checker_tree_sha='6' * 40,
        workflow_blob_sha='7' * 40, workflow_id=9, workflow_path='.github/workflows/check.yml',
        branch='protected', target_branch='main', event='workflow_dispatch', producer_app_id=13, as_policy=lambda: policy)
    pr = {'number': 7, 'state': 'open', 'head': {'sha': source.head_sha, 'ref': 'feature', 'repo': {'id': 1}},
          'base': {'sha': source.base_sha, 'ref': 'main', 'repo': {'id': 1}}}
    run = {'id': 11, 'run_attempt': 2, 'workflow_id': 9, 'event': 'workflow_dispatch', 'head_sha': authority.runner_sha,
           'head_branch': 'protected', 'path': authority.workflow_path, 'status': 'completed', 'conclusion': 'success',
           'repository': {'id': 2, 'full_name': 'owner/runner'}, 'head_repository': {'id': 2, 'full_name': 'owner/runner'}, 'check_suite_id': 12}
    responses = {'/repos/owner/project': {'id': 1, 'full_name': 'owner/project'}, '/repos/owner/project/pulls/7': pr,
        '/repos/owner/runner/actions/workflows/9/runs?branch=protected&per_page=1': {'total_count': 1, 'workflow_runs': [{'id': 11, 'run_attempt': 2}]},
        '/repos/owner/runner/actions/runs/11': run, '/repos/owner/runner/actions/runs/11/attempts/2': run,
        '/repos/owner/runner/actions/runs/11/attempts/2/jobs?per_page=100': {'total_count': 1, 'jobs': [
            {'id': 10, 'name': 'producer', 'run_id': 11, 'head_sha': authority.runner_sha, 'status': 'completed', 'conclusion': 'success'}]},
        '/repos/owner/runner/actions/workflows/9': {'id': 9, 'path': authority.workflow_path, 'state': 'active'},
        '/repos/owner/runner/check-suites/12': {'id': 12, 'app': {'id': 13}, 'head_sha': authority.runner_sha,
            'repository': {'id': 2}, 'status': 'completed', 'conclusion': 'success'},
        '/repos/owner/runner/contents/.github/workflows/check.yml?ref=' + authority.runner_sha:
            {'type': 'file', 'path': authority.workflow_path, 'sha': authority.workflow_blob_sha}}
    for repository, sha, tree in ((source.repository, source.head_sha, source.tree_sha),
            (source.repository, authority.checker_sha, authority.checker_tree_sha),
            (authority.runner_repository, authority.runner_sha, authority.runner_tree_sha)):
        responses[f'/repos/{repository}/git/commits/{sha}'] = {'sha': sha, 'tree': {'sha': tree}}
    class Router:
        def __init__(self):
            self.calls = []
        def open(self, request, *, timeout):
            path = request.full_url.removeprefix('https://api.github.com')
            self.calls.append(path)
            value = json.loads(json.dumps(responses[path]))
            if change:
                change(path, self.calls.count(path), value)
            return Response(json.dumps(value).encode())
    router = Router()
    client = GitHubClient(token='synthetic-fixture-not-operator', transport=BoundedGetTransport(opener=router, clock=lambda: 0))
    return source, authority, client, router


class ProviderGraphTests(unittest.TestCase):
    def test_complete_graph_and_final_scope_require_exact14_gets(self):
        source, authority, client, router = provider_fixture()
        result = observe(client, authority, source)
        self.assertTrue(result.validated)
        self.assertEqual(result.jobs, ('producer',))
        self.assertEqual(len(router.calls), 14)
        self.assertEqual(router.calls[-2:], ['/repos/owner/project/pulls/7', '/repos/owner/runner/actions/runs/11'])

    def test_failed_or_partial_jobs_latest_attempt_and_retarget_refuse(self):
        def missing(path, count, value):
            if '/jobs?' in path:
                value['total_count'] = 2
        def rerun(path, count, value):
            if path == '/repos/owner/runner/actions/runs/11':
                value['run_attempt'] = 3
        def retarget(path, count, value):
            if path.endswith('/pulls/7') and count == 2:
                value['base']['ref'] = 'different'
        for change in (missing, rerun, retarget):
            with self.subTest(change=change.__name__):
                source, authority, client, router = provider_fixture(change)
                with self.assertRaises(ObservationError):
                    observe(client, authority, source)
                self.assertLessEqual(len(router.calls), 14)

