"""NEW guarded API/public-worker/HTTP controls; no App, DB or real transport."""
import asyncio
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import importlib.util
import inspect
import io
import json
import os
import tempfile
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

W = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(W / 'trust-ci/src'))
from adaptive_trust_ci.github import GitHubClient
from adaptive_trust_ci.public_publisher import PublisherConfig, Publication
from adaptive_trust_ci import api
from adaptive_trust_ci.worker import Worker
if importlib.util.find_spec('adaptive_trust_ci.public_http'):
    from adaptive_trust_ci import public_http as http
else:
    http = None
if importlib.util.find_spec('adaptive_trust_ci.public_runtime'):
    from adaptive_trust_ci import public_runtime as runtime
else:
    runtime = None
ACTIVE = False
OWNED = None


def guard(event, args):
    if not ACTIVE:
        return
    if event.startswith(('socket.', 'subprocess.', 'shutil.')) or event in ('os.system', 'os.posix_spawn'):
        raise AssertionError('new fixture denies process/network')
    if event == 'open' or event.startswith('os.'):
        if (OWNED is None or not args or not isinstance(args[0], (str, bytes, os.PathLike))
                or not Path(os.fsdecode(args[0])).absolute().is_relative_to(OWNED)):
            raise AssertionError('new fixture denies outside I/O')


sys.addaudithook(guard)


@contextlib.contextmanager
def guarded():
    global ACTIVE
    ACTIVE = True
    try:
        yield
    finally:
        ACTIVE = False


class PublicRuntimeWiring(unittest.TestCase):
    def config(self):
        return PublisherConfig('owned/fixture', 7, 81, 91, 'a' * 64)

    def test_disabled_configuration_reads_nothing(self):
        self.assertIsNotNone(runtime, 'missing real public service composition')
        with guarded():
            self.assertIsNone(runtime.load_config(Path('/UNREAD-OWNED'), enabled=False))
            with self.assertRaises(ValueError):
                runtime.load_config(None, enabled=True)

    def test_authenticated_wakeup_cannot_supply_authority_or_evidence(self):
        self.assertIsNotNone(runtime, 'missing canonical wakeup ingress')
        calls = []
        queue = SimpleNamespace(enqueue=lambda delivery, targets: calls.append((delivery, targets)) or ['owned-job'])
        ingress = runtime.PublicIngress(SimpleNamespace(publisher=self.config()), queue, b'owned-fixture-secret-' * 2)
        value = {'repository': {'full_name': 'owned/fixture', 'id': 7}, 'pull_request': {'number': 5},
                 'authority': {'eligible': True}, 'report': {'status': 'pass'}}
        raw = json.dumps(value).encode()
        signature = 'sha256=' + hmac.new(ingress.secret, raw, hashlib.sha256).hexdigest()
        with guarded():
            result = ingress.accept(raw, signature, 'pull_request', 'owned-delivery')
        self.assertEqual(result['job_ids'], ['owned-job'])
        self.assertEqual(calls, [('owned-delivery', (5,))])
        with guarded(), self.assertRaises(ValueError):
            ingress.accept(raw, 'sha256=' + '0' * 64, 'pull_request', 'owned-bad-auth')
        self.assertEqual(len(calls), 1)
        value['repository']['id'] = 8
        raw = json.dumps(value).encode()
        signature = 'sha256=' + hmac.new(ingress.secret, raw, hashlib.sha256).hexdigest()
        with guarded(), self.assertRaises(ValueError):
            ingress.accept(raw, signature, 'pull_request', 'owned-other')
        self.assertEqual(len(calls), 1)

    def test_streamed_webhook_refuses_before_own_buffer_growth(self):
        self.assertIsNotNone(runtime, 'missing bounded API adapter')
        closed = []
        class Request:
            async def stream(self):
                try:
                    yield b'x' * 9
                finally:
                    closed.append(True)
        ingress = SimpleNamespace(accept=lambda *args: self.fail('oversize must not parse/authenticate'))
        loop = asyncio.new_event_loop()
        try:
            with guarded(), self.assertRaises(ValueError):
                loop.run_until_complete(runtime.receive_webhook(ingress, Request(), 's', 'pull_request', 'd', maximum=8))
            self.assertEqual(closed, [True], 'owned request stream must close on refusal')
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    def test_public_worker_dispatch_has_no_legacy_green_fallback(self):
        self.assertIsNotNone(runtime, 'missing actual public worker entry')
        finished, calls = [], []
        queue = SimpleNamespace(claim=lambda: ('owned-job', 5),
                                finish=lambda *args: finished.append(args))
        worker = runtime.PublicWorker(SimpleNamespace(publisher=self.config()), queue,
            operation=lambda pr: calls.append(pr) or Publication('blocked', 'owned-unqualified'))
        with guarded():
            result = worker.run_once()
        self.assertEqual(calls, [5])
        self.assertEqual(result['state'], 'blocked')
        self.assertEqual(finished, [('owned-job', 'blocked', 'owned-unqualified')])

    def test_worker_reaches_existing_canonical_publisher_seam(self):
        self.assertIsNotNone(runtime, 'missing canonical publisher composition')
        queue = object()
        worker = runtime.PublicWorker(SimpleNamespace(publisher=self.config()), queue, journal=queue)
        parts = SimpleNamespace(selector=object(), verifier=object(), client_factory=object(),
                                request_port=object(), clock=object())
        with patch.object(worker, '_prepare_publication', return_value=parts), \
                patch.object(runtime, 'publish', return_value=Publication('blocked', 'owned-refusal')) as publish:
            with guarded():
                result = worker.publish_for_pr(5)
        self.assertEqual(result.state, 'blocked')
        self.assertEqual(publish.call_args.args, (worker.config.publisher, queue, parts.verifier, parts.selector))
        self.assertIs(publish.call_args.kwargs['request_port'], parts.request_port)
        self.assertIs(publish.call_args.kwargs['enabled'], True)

    def test_http_port_preserves_raw_body_and_uses_fixed_owned_child(self):
        self.assertIsNotNone(http, 'missing concrete bounded HTTP port')
        requests = []
        raw = b'  {"owned":1}  '
        def exchange(command, payload, deadline):
            requests.append((command, json.loads(payload), deadline))
            return struct.pack('!II', 200, len(raw)) + raw
        client = GitHubClient(token='-'.join(('owned', 'fixture', 'token')))
        port = http.BoundedHTTPPort('owned/fixture', clock=lambda: 1.0)
        with patch.object(http, '_run_owned', side_effect=exchange):
            with guarded():
                with port.open(client, 'GET', '/repos/owned/fixture', None, deadline=3.0, maximum=64) as response:
                    self.assertEqual(response.read(64), raw)
        self.assertEqual(requests[0][1]['action'], 'http')
        self.assertEqual(requests[0][1]['maximum'], 64)
        self.assertEqual(requests[0][2], 3.0)
        self.assertIn('--public-http-worker', requests[0][0])

    def test_http_port_rejects_framing_and_unbounded_token_callback(self):
        self.assertIsNotNone(http, 'missing concrete bounded HTTP port')
        port = http.BoundedHTTPPort('owned/fixture', clock=lambda: 1.0)
        client = GitHubClient(token='-'.join(('owned', 'fixture', 'token')))
        with patch.object(http, '_run_owned', return_value=struct.pack('!II', 200, 5) + b'12345'):
            with guarded(), self.assertRaises(ValueError):
                port.open(client, 'GET', '/repos/owned/fixture', None, deadline=3.0, maximum=4)
        lazy = GitHubClient(token_provider=lambda: self.fail('unbounded broker must not run'))
        with guarded(), self.assertRaises(ValueError):
            port.open(lazy, 'GET', '/repos/owned/fixture', None, deadline=3.0, maximum=4)
        forged = SimpleNamespace(api_url='https://api.github.com', token_provider=None, token='owned',
                                 _headers=lambda: self.fail('unsupported client callback ran'))
        def observed():
            try:
                port.open(forged, 'GET', '/repos/owned/fixture', None, deadline=3.0, maximum=4)
            except Exception as error:
                return type(error).__name__
            return 'accepted'
        with guarded():
            self.assertEqual(observed(), 'ValueError')

    def test_new_http_reader_rejects_compression_and_late_eof(self):
        self.assertIsNotNone(http, 'missing bounded HTTP response reader')
        class Response(io.BytesIO):
            status = 200
            url = 'https://api.github.com/repos/owned/fixture'
            headers = {'Content-Encoding': 'gzip'}
        opener = SimpleNamespace(open=lambda *args, **kwargs: Response(b'{}'))
        with guarded(), self.assertRaises(ValueError):
            http._read_http(opener, 'GET', Response.url, {}, None, 3.0, lambda: 1.0, 64)
        Response.headers = {}
        ticks = iter([1.0, 1.0, 1.0, 4.0])
        with guarded(), self.assertRaises(ValueError):
            http._read_http(opener, 'GET', Response.url, {}, None, 3.0, lambda: next(ticks, 4.0), 64)

    def test_api_consumer_calls_bounded_ingress_without_legacy_job(self):
        self.assertTrue(hasattr(api, 'public_webhook'), 'existing API has no public dispatch join')
        received = []
        ingress = SimpleNamespace(accept=lambda *args: received.append(args) or {'accepted': True})
        class Request:
            async def stream(self):
                yield b'owned'
        loop = asyncio.new_event_loop()
        try:
            with guarded():
                result = loop.run_until_complete(api.public_webhook(
                    SimpleNamespace(stopped=False), ingress, Request(), 'sig', 'pull_request', 'delivery'))
            self.assertEqual(result, {'accepted': True})
            self.assertEqual(received, [(b'owned', 'sig', 'pull_request', 'delivery')])
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    def test_existing_worker_exposes_explicit_public_factory(self):
        self.assertTrue(hasattr(Worker, 'build_public'), 'existing worker has no public factory join')
        with patch.object(runtime.PublicWorker, 'load', return_value='owned-public-worker') as load:
            with guarded():
                result = Worker.build_public(Path('/UNREAD-OWNED-CONFIG'))
        self.assertEqual(result, 'owned-public-worker')
        self.assertEqual(load.call_args.args, (Path('/UNREAD-OWNED-CONFIG'),))

    def test_unknown_publication_retains_same_allocation_for_recovery(self):
        worker = runtime.PublicWorker(SimpleNamespace(publisher=self.config()), object(), journal=object())
        parts = SimpleNamespace(selector=object(), verifier=object(), client_factory=object(), request_port=object(), clock=object())
        with patch.object(worker, '_prepare_publication', return_value=parts) as prepare, \
                patch.object(runtime, 'publish', return_value=Publication('unknown', 'owned-unconfirmed')) as publish:
            with guarded():
                self.assertEqual(worker.publish_for_pr(5).state, 'unknown')
                self.assertEqual(worker.publish_for_pr(5).state, 'unknown')
            self.assertEqual(prepare.call_count, 1, 'UNKNOWN must not create a fresh allocation/nonce')
            self.assertEqual(publish.call_count, 2)
            self.assertTrue(all(call.args[2] is parts.verifier for call in publish.call_args_list))
            with guarded():
                self.assertEqual(worker.publish_for_pr(6).state, 'blocked')
            self.assertEqual(prepare.call_count, 1, 'one unresolved operation bounds retained control state')

    def test_worker_request_preflight_precedes_json_allocation(self):
        with patch.object(http, 'canonical_json', side_effect=AssertionError('must preflight before encoding')):
            def observed():
                try:
                    http._exchange({'owned': 'x' * 65537}, 3.0)
                except Exception as error:
                    return type(error).__name__
                return 'accepted'
            with guarded():
                self.assertEqual(observed(), 'ValueError')

    def test_observation_broker_uses_read_only_profile(self):
        self.assertIn('purpose', inspect.signature(http.issue_scoped_token).parameters,
                      'read observation must not acquire checks-write publication credentials')
        reserved = []
        budget = SimpleNamespace(clock=lambda: 1.0, deadline=4.0,
            reserve=lambda maximum, **kwargs: reserved.append(maximum) or maximum,
            finish=lambda *args: None)
        now = datetime(2026, 11, 16, tzinfo=timezone.utc)
        body = json.dumps({'token': 'owned-read-token', 'expires_at': (now + timedelta(minutes=30)).isoformat()}).encode()
        with patch.object(http, '_run_owned', return_value=struct.pack('!III', 201, 37, len(body)) + body) as exchange:
            with guarded():
                token = http.issue_scoped_token(self.config(), Path('/UNREAD-OWNED-KEY'), budget, now=now, purpose='observer')
        self.assertEqual(token, 'owned-read-token')
        self.assertEqual(json.loads(exchange.call_args.args[1])['token_request']['permissions']['checks'], 'read')

    def test_malformed_host_pins_refuse_before_worker_or_credential_setup(self):
        value = dict(schema_version=1,
            publisher=dict(repository='owned/fixture', repository_id=7, app_id=81, installation_id=91, policy_digest='a'*64),
            authority=dict(repository='owned/fixture', repository_id=7, runner_repository='owned/runner', runner_repository_id=8,
                runner_sha='a'*40, runner_tree_sha='b'*40, workflow_id=11, workflow_path='.github/workflows/owned.yml',
                checker_sha='not-a-real-pin', checker_tree_sha='d'*40, workflow_blob_sha='e'*40, producer_app_id=15368,
                event='workflow_dispatch', branch='main', policy_digest='a'*64, required_jobs=['owned-job']),
            producer_key_path='/UNREAD-PUBLIC-KEY', app_key_path='/UNREAD-PRIVATE-KEY',
            journal_path='/UNREAD-JOURNAL', input_root='/UNREAD-INPUTS',
            producer={'snapshot_root':'/UNREAD-SNAPSHOTS', 'machine_key_path':'/UNREAD-MACHINE',
                      'image_artifacts':None, 'cgroup_root':'/UNREAD-CGROUP', 'dispatch':{'enabled':False}})
        with patch.object(runtime, 'read_file', return_value=json.dumps(value).encode()):
            with guarded(), self.assertRaises(ValueError):
                runtime.load_config(Path('/UNREAD-CONFIG'), enabled=True)

    def test_global_stop_prevents_public_claim_and_dispatch(self):
        queue = SimpleNamespace(claim=lambda: self.fail('global stop must prevent durable claim'))
        worker = runtime.PublicWorker(SimpleNamespace(publisher=self.config()), queue)
        worker.stop_event.set()
        with guarded():
            self.assertIsNone(worker.run_once())

    def test_http_scope_rejects_traversal_before_owned_worker(self):
        client = GitHubClient(token='-'.join(('owned', 'fixture', 'token')))
        port = http.BoundedHTTPPort('owned/fixture', clock=lambda: 1.0)
        with patch.object(http, '_run_owned', side_effect=AssertionError('out-of-scope request reached worker')):
            for path in ('/repos/owned/fixture/../../foreign', '/repos/owned/fixture/%2e%2e/foreign'):
                def observed():
                    try:
                        port.open(client, 'GET', path, None, deadline=3.0, maximum=64)
                    except Exception as error:
                        return type(error).__name__
                    return 'accepted'
                with self.subTest(path=path), guarded():
                    self.assertEqual(observed(), 'ValueError')

    def test_private_file_reader_checks_descriptor_mode_and_closes(self):
        self.assertTrue(hasattr(http, '_read_app_key'), 'missing private descriptor boundary')
        if os.name != 'posix':
            with guarded(), self.assertRaises(ValueError):
                http._read_app_key(Path('/UNREAD-UNSUPPORTED'))
            return
        parent = W / '.getzilla/runtime/scratch/public-runtime-fixtures'
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            path = Path(directory) / 'owned.bin'
            path.write_bytes(b'owned ordinary bytes, not a real key')
            path.chmod(0o600)
            global OWNED
            OWNED = Path(directory)
            try:
                with guarded():
                    self.assertEqual(http._read_app_key(path), b'owned ordinary bytes, not a real key')
                path.chmod(0o644)
                with guarded(), self.assertRaises(ValueError):
                    http._read_app_key(path)
            finally:
                OWNED = None

    def test_scoped_token_minting_uses_same_shared_allocation(self):
        self.assertIsNotNone(http, 'missing bounded scoped broker')
        reservations, finishes = [], []
        budget = SimpleNamespace(clock=lambda: 1.0, deadline=4.0,
            reserve=lambda maximum, **kwargs: reservations.append((maximum, kwargs)) or maximum,
            finish=lambda reserved, actual: finishes.append((reserved, actual)))
        now = datetime(2026, 11, 16, tzinfo=timezone.utc)
        body = json.dumps({'token': 'owned-fixture-token', 'expires_at': (now + timedelta(minutes=30)).isoformat()}).encode()
        frame = struct.pack('!III', 201, 37, len(body)) + body
        with patch.object(http, '_run_owned', return_value=frame) as exchange:
            with guarded():
                token = http.issue_scoped_token(self.config(), Path('/UNREAD-OWNED-KEY'), budget, now=now)
        self.assertEqual(token, 'owned-fixture-token')
        self.assertEqual(len(reservations), 2)
        self.assertTrue(all(value[1] == {'publication': True} for value in reservations))
        self.assertEqual([value[1] for value in finishes], [37, len(body)])
        payload = json.loads(exchange.call_args.args[1])
        self.assertEqual(payload['token_request']['repository_ids'], [7])
        self.assertEqual(payload['token_request']['permissions'], self.config().token_request()['permissions'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
