"""Owned local sources through actual authenticated handlers, PostgreSQL and UDS.

Provider registry facts only seed a task fixture. They do not qualify a native model.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
from pathlib import Path
import socketserver
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch

from fastapi.testclient import TestClient

from getzilla_factory.api import Authenticator, create_app
from getzilla_factory.contracts import canonical_digest
from getzilla_factory.result_dispatch import UdsResultHandoffClient
from getzilla_factory.server import load_actors
from factory.tests.test_access_authority import authority_fixture
from factory.tests import test_execution_persistence_postgres as execution_fixtures
from factory.tests.test_postgres_integration import DATABASE_URL


@unittest.skipUnless(DATABASE_URL, 'owned disposable PostgreSQL is required')
class AccessReleasePostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        execution_fixtures.ExecutionPersistencePostgresTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        execution_fixtures.ExecutionPersistencePostgresTests.tearDownClass()

    def setUp(self):
        self.fixture = execution_fixtures.ExecutionPersistencePostgresTests('runTest')
        self.fixture.setUp()
        if self._testMethodName == 'test_packet_without_read_file_cannot_use_the_local_source_adapter':
            selection = self.fixture.selection(capabilities=['text'])
            selection['capability_policy']['allowed_tools'] = []
            with patch.object(self.fixture, 'selection', lambda **_kwargs: selection):
                self.task, self.execution = self.fixture.claim_execution('access-owned', capabilities=['text'])
        else:
            self.task, self.execution = self.fixture.claim_execution('access-owned', capabilities=['text'])
        self.directory = tempfile.TemporaryDirectory(prefix='getzilla-access150-source-')
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        path, self.policy, self.key = authority_fixture(root)
        self.policy_path = path
        for record in self.policy['actors']:
            record['repositories'] = ['owner/repository', 'other/repository']
            record['projects'][0]['repository_id'] = 'owner/repository'
            record['projects'][1]['repository_id'] = 'other/repository'
            record['scopes'] += ['task:execute', 'task:claim']
        for index, source in enumerate(self.policy['sources']):
            source['repository_id'] = ['owner/repository', 'other/repository'][index]
        self.policy['destinations'][0]['repository_id'] = 'owner/repository'
        self.policy['actors'][2]['scopes'] += ['task:cancel', 'factory:kill']
        self.policy['actors'][2]['repositories'] = ['*']
        worker = copy.deepcopy(self.policy['actors'][0])
        worker.update(actor_id='worker', kind='worker', principal_id='user-a',
                      delegation_owner='user-a', delegation_expires_at=4102444800)
        credential = root / 'worker-credential'
        credential.write_text('synthetic-owned-credential-worker')
        credential.chmod(0o600)
        worker['token_file'] = str(credential)
        self.policy['actors'].append(worker)
        path.write_text(json.dumps(self.policy))
        self.auth = Authenticator(load_actors(path))
        self.received = []
        self.sink_entered = threading.Event()
        self.sink_release = threading.Event()
        self.sink_release.set()
        self.sink_pending = False
        owner = self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.rfile.readline()
                headers = {}
                while (line := self.rfile.readline()) != b'\r\n':
                    key, value = line.decode('ascii').split(':', 1)
                    headers[key.lower()] = value.strip()
                raw = self.rfile.read(int(headers['content-length']))
                body = json.loads(raw)
                owner.sink_entered.set()
                if not owner.sink_release.wait(0.8):
                    return
                owner.received.append((headers, body))
                response = {'status': 'delivered', 'operation_id': body['operation_id'],
                    'request_digest': body['request_digest'], 'envelope_digest': body['envelope_digest'],
                    'postcondition_digest': canonical_digest({'contract': 'next-model-result-postcondition/v1',
                        **{key: body[key] for key in ('operation_id', 'request_digest', 'envelope_digest')}})}
                if owner.sink_pending:
                    response.update(status='pending', postcondition_digest=None)
                wire = json.dumps(response).encode()
                self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' +
                                  str(len(wire)).encode() + b'\r\nConnection: close\r\n\r\n' + wire)
        socket_path = root / 'sink.sock'
        self.sink = socketserver.UnixStreamServer(str(socket_path), Handler)
        socket_path.chmod(0o600)
        self.thread = threading.Thread(target=self.sink.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.sink.server_close)
        self.addCleanup(self.sink.shutdown)
        self.source = root / 'owned-source'
        self.source.write_bytes(b'OWNED PRIVATE PROJECT A MARKER\n')
        self.source.chmod(0o600)
        self.client = UdsResultHandoffClient(socket_path, 'synthetic-owned-sink-credential', timeout_seconds=0.2)
        self.access = None
        try:
            module = importlib.import_module('getzilla_factory.access_release')
        except ModuleNotFoundError:
            module = None
        if module is not None:
            binding = {'key': self.key('a'), 'version': 'v1', 'repository_id': self.task.repository_id,
                'workspace_handle': self.execution.workspace_handle, 'relative_path': 'factory/src/owned.txt',
                'file': str(self.source), 'content_digest': hashlib.sha256(self.source.read_bytes()).hexdigest()}
            self.access = module.AccessReleaseService(self.fixture.store, self.auth.access_authority,
                module.LocalSourceAdapter([binding]), {'private-a': self.client})
        self.http = TestClient(create_app(self.fixture.service, self.auth, access_service=self.access))
        self.http.__enter__()
        self.addCleanup(self.http.__exit__, None, None, None)
        grant = self.execution.lease
        self.request = {'grant': {'task_id': grant.task_id, 'run_id': grant.run_id, 'owner': grant.owner,
            'role': grant.role.value, 'fence': grant.fence, 'packet_digest': grant.packet_digest,
            'expires_at': grant.expires_at.isoformat()},
            'packet_digest': self.execution.packet_digest, 'sources': [self.key('a')], 'destination_id': 'private-a'}
        self.worker_headers = {'Authorization': 'Bearer synthetic-owned-credential-worker'}

    def prepare(self, body=None):
        return self.http.post('/v1/access/source-read', json=body or self.request, headers=self.worker_headers)

    def release(self, prepared_id):
        return self.http.post('/v1/access/release', json={'prepared_id': prepared_id}, headers=self.worker_headers)

    def test_owned_source_reaches_exactly_one_registered_real_sink(self):
        response = self.prepare()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn('OWNED PRIVATE', response.text)
        identifier = response.json()['prepared_id']
        admitted = self.release(identifier)
        self.assertEqual(admitted.status_code, 200, admitted.text)
        self.assertEqual(self.received, [], 'only the actual dispatcher may send')
        self.assertEqual(self.access.run_once(), 1)
        self.assertEqual(len(self.received), 1)
        headers, body = self.received[0]
        self.assertEqual(headers['authorization'], 'Bearer synthetic-owned-sink-credential')
        self.assertEqual(body['result_envelope']['sanitized_payload'], self.source.read_text())
        self.assertEqual(self.access.run_once(), 0)
        self.assertEqual(self.release(identifier).status_code, 409)
        self.assertEqual(len(self.received), 1)

    def test_packet_without_read_file_cannot_use_the_local_source_adapter(self):
        response = self.prepare()
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.received, [])

    def test_external_provider_registration_cannot_relabel_a_cached_file_as_local_authority(self):
        from getzilla_factory.access_authority import AccessError
        from getzilla_factory.access_release import LocalSourceAdapter
        key = self.key('a') | {'provider': 'external-mcp'}
        with self.assertRaises(AccessError):
            LocalSourceAdapter([{'key': key, 'version': 'v1', 'repository_id': self.task.repository_id,
                'workspace_handle': self.execution.workspace_handle, 'relative_path': 'factory/src/owned.txt',
                'file': str(self.source), 'content_digest': hashlib.sha256(self.source.read_bytes()).hexdigest()}])
        self.assertEqual(self.received, [])

    def test_restart_and_foreign_credentials_cannot_restore_a_prepared_reference(self):
        from getzilla_factory.access_release import AccessReleaseService
        identifier = self.prepare().json()['prepared_id']
        response = self.http.post('/v1/access/release', json={'prepared_id': identifier},
            headers={'Authorization': 'Bearer synthetic-owned-credential-user-b'})
        self.assertEqual(response.status_code, 409)
        restarted = AccessReleaseService(self.fixture.store, self.auth.access_authority,
            self.access._sources, {'private-a': self.client})
        with TestClient(create_app(self.fixture.service, self.auth, access_service=restarted)) as http:
            self.assertEqual(http.post('/v1/access/release', json={'prepared_id': identifier},
                headers=self.worker_headers).status_code, 409)
        self.assertEqual(self.received, [])

    def revoke(self, *, deleted=False):
        update = copy.deepcopy(self.policy)
        update['revision'] += 1
        if deleted:
            update['sources'][0]['deleted'] = True
        else:
            update['groups'][0]['members'] = []
        response = self.http.post('/v1/access/authority',
            json={'expected_revision': self.policy['revision'], 'authority': update},
            headers={'Authorization': 'Bearer synthetic-owned-credential-operator'})
        self.assertEqual(response.status_code, 200, response.text)
        self.policy = update

    def test_revoked_prepared_and_queued_bytes_never_reach_the_sink(self):
        for queued in (False, True):
            with self.subTest(queued=queued):
                prepared = self.prepare()
                self.assertEqual(prepared.status_code, 200, prepared.text)
                if queued:
                    self.assertEqual(self.release(prepared.json()['prepared_id']).status_code, 200)
                self.revoke()
                if not queued:
                    self.assertEqual(self.release(prepared.json()['prepared_id']).status_code, 403)
                self.assertEqual(self.access.run_once(), 0)
                self.assertEqual(self.received, [])
                restore = copy.deepcopy(self.policy)
                restore['revision'] += 1
                restore['groups'][0]['members'] = ['user-a']
                admin = self.auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
                self.auth.access_authority.update(admin, self.policy['revision'], restore)
                self.policy = restore

    def test_queue_expiry_denies_before_any_transport(self):
        prepared = self.prepare().json()['prepared_id']
        self.assertEqual(self.release(prepared).status_code, 200)
        time.sleep(0.27)
        self.assertEqual(self.access.run_once(), 0)
        self.assertEqual(self.received, [])

    def test_real_rollback_and_commit_with_lost_ack_cannot_confirm_queue(self):
        from getzilla_factory.store import StoreUnavailable
        native = self.fixture.store._transaction
        for committed in (False, True):
            with self.subTest(committed=committed):
                prepared = self.prepare().json()['prepared_id']
                @contextmanager
                def fault(**kwargs):
                    with native(**kwargs) as cursor:
                        yield cursor
                        if not committed:
                            raise StoreUnavailable('synthetic precommit failure')
                    if committed:
                        raise StoreUnavailable('synthetic lost commit acknowledgment')
                with patch.object(self.fixture.store, '_transaction', fault):
                    response = self.release(prepared)
                self.assertEqual(response.status_code, 503, response.text)
                self.assertEqual(self.access.run_once(), 0)
                self.assertEqual(self.release(prepared).status_code, 409)
                self.assertEqual(self.received, [])
                with native() as cursor:
                    cursor.execute('SELECT count(*) FROM factory.next_model_request_outbox_v1')
                    self.assertEqual(cursor.fetchone()[0], int(committed))

    def test_source_replacement_and_caller_lineage_or_path_are_opaque_refusals(self):
        original = self.source.read_bytes()
        for field in ('lineage', 'audience', 'file', 'permission_revision', 'payload'):
            request = copy.deepcopy(self.request)
            request[field] = 'SYNTHETIC CALLER PRIVATE TEXT'
            response = self.prepare(request)
            self.assertEqual(response.status_code, 422)
            self.assertNotIn('SYNTHETIC CALLER', response.text)
        self.source.write_bytes(b'OWNED FOREIGN REPLACEMENT MARKER')
        response = self.prepare()
        self.assertEqual(response.status_code, 503, response.text)
        self.assertNotIn('FOREIGN REPLACEMENT', response.text)
        self.assertEqual(self.source.read_bytes(), b'OWNED FOREIGN REPLACEMENT MARKER')
        self.assertEqual(self.received, [])
        self.source.write_bytes(original)

    def test_task_fence_rejects_null_owner_at_the_actual_database_boundary(self):
        import psycopg
        grant = self.execution.lease
        with self.assertRaises(psycopg.errors.RaiseException):
            with self.fixture.store._transaction() as cursor:
                cursor.execute('SELECT factory.access_task_fence_v1(%s,%s,%s,%s,%s)',
                    (grant.task_id, grant.run_id, None, grant.fence, grant.packet_digest))

    def test_real_server_composition_wakes_the_registered_consumer(self):
        from getzilla_factory.server import build_app
        from getzilla_factory.settings import FactorySettings
        settings = FactorySettings(self.fixture.runtime_url, Path(self.directory.name) / 'control.sock', self.policy_path)
        try:
            app = build_app(settings, access_sources=self.access._sources,
                            access_destinations={'private-a': self.client})
        except TypeError:
            self.fail('Actual server composition has no shared-authority source/dispatcher wiring')
        with TestClient(app) as http:
            prepared = http.post('/v1/access/source-read', json=self.request, headers=self.worker_headers)
            self.assertEqual(prepared.status_code, 200, prepared.text)
            response = http.post('/v1/access/release', json=prepared.json(), headers=self.worker_headers)
            self.assertEqual(response.status_code, 200, response.text)
            until = time.monotonic() + 1
            while not self.received and time.monotonic() < until:
                time.sleep(0.005)
            self.assertEqual(len(self.received), 1)
            self.assertEqual(self.received[0][1]['result_envelope']['sanitized_payload'], self.source.read_text())

    def test_two_principals_two_projects_same_resource_id_use_actual_handlers(self):
        import psycopg
        import uuid
        from getzilla_factory.access_release import AccessReleaseService, LocalSourceAdapter
        from getzilla_factory.service import FactoryService
        from factory.tests.test_contracts import valid_intake
        from factory.tests.test_execution_service import trusted_registry
        from factory.tests.test_postgres_integration import NOW
        root = Path(self.directory.name)
        policy = copy.deepcopy(self.policy)
        policy['revision'] = 2
        policy['actors'][1]['scopes'].append('task:submit')
        worker = copy.deepcopy(policy['actors'][-1])
        credential = root / 'worker-b-credential'
        credential.write_text('synthetic-owned-credential-worker-b')
        credential.chmod(0o600)
        worker.update(actor_id='worker-b', principal_id='user-b', delegation_owner='user-b', token_file=str(credential))
        policy['actors'].append(worker)
        policy['groups'].append({'tenant_id': 'tenant-a', 'group_id': 'team-b', 'members': ['user-b']})
        policy['sources'][1]['groups'] = ['team-b']
        destination = copy.deepcopy(policy['destinations'][0])
        destination.update(destination_id='private-b', project_id='project-b',
                           repository_id='other/repository', readers=['user-b'])
        policy['destinations'].append(destination)
        admin = self.auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
        self.auth.access_authority.update(admin, 1, policy)
        self.policy = policy
        # Synthetic M0 fixture permits intake; it is not an external CI receipt.
        with psycopg.connect(DATABASE_URL) as connection:
            connection.execute('INSERT INTO factory.m0_authority_observations '
                '(observation_id,observed_at,check_name,exact_head_sha,issuer,evidence_digest,repository_id,policy_digest) '
                    'VALUES(%s,%s,%s,%s,%s,%s,%s,%s)', (uuid.uuid4(), NOW-timedelta(seconds=1),
                    'adaptive-trust-ci/verified@06ecf1c875bc', '3'*40, 'external-trust-ci-api',
                    '8'*64, 'other/repository', '06ecf1c875bc'+'9'*52))
        selection = self.fixture.selection(capabilities=['text'])
        selection['workspace_handle'] = 'workspace:' + 'e'*64
        selection['capability_policy']['allowed_tools'] = ['read_file']
        selection['capability_policy']['artifact_classes'] = ['report']
        service = FactoryService(self.fixture.store, execution_registry=trusted_registry(selection))
        with TestClient(create_app(service, self.auth, execution_enabled=True)) as http:
            body = valid_intake()
            body.update(request_id='access-project-b', source_id='access-project-b', repository_id='other/repository')
            body['m0_authority']['observed_at'] = (NOW-timedelta(seconds=1)).isoformat()
            response = http.post('/v1/tasks', json=body, headers={
                'Authorization': 'Bearer synthetic-owned-credential-user-b',
                'Idempotency-Key': body['request_id'], 'X-Correlation-ID': 'access-project-b'})
            self.assertEqual(response.status_code, 201, response.text)
            claimed = http.post('/v2/execution/claims', json={**selection,
                'role': 'reader', 'repositories': ['other/repository'], 'lease_seconds': 60},
                headers={'Authorization': 'Bearer synthetic-owned-credential-worker-b',
                    'Idempotency-Key': canonical_digest({'access': 'project-b'}), 'X-Correlation-ID': 'access-project-b'})
            self.assertEqual(claimed.status_code, 200, claimed.text)
            execution_b = claimed.json()['grant']
            self.assertIsNotNone(execution_b, 'real reader capacity must admit the second project fixture')
        source_b = root / 'owned-source-b'
        source_b.write_bytes(b'OWNED PRIVATE PROJECT B MARKER\n')
        source_b.chmod(0o600)
        bindings = []
        for project, source, repository, workspace in (
                ('a', self.source, 'owner/repository', self.execution.workspace_handle),
                ('b', source_b, 'other/repository', execution_b['workspace_handle'])):
            bindings.append({'key': self.key(project), 'version': 'v1', 'repository_id': repository,
                'workspace_handle': workspace, 'relative_path': 'factory/src/owned.txt', 'file': str(source),
                'content_digest': hashlib.sha256(source.read_bytes()).hexdigest()})
        access = AccessReleaseService(self.fixture.store, self.auth.access_authority,
            LocalSourceAdapter(bindings), {'private-a': self.client, 'private-b': self.client})
        with TestClient(create_app(service, self.auth, access_service=access)) as http:
            for principal, execution, allowed in (('worker', None, 'a'), ('worker-b', execution_b, 'b')):
                for project in ('a', 'b'):
                    request = copy.deepcopy(self.request)
                    if execution is not None:
                        request.update(grant=execution['lease'], packet_digest=execution['packet_digest'])
                    request.update(sources=[self.key(project)], destination_id='private-' + project)
                    headers = {'Authorization': 'Bearer synthetic-owned-credential-' + principal}
                    response = http.post('/v1/access/source-read', json=request, headers=headers)
                    with self.subTest(principal=principal, project=project):
                        self.assertEqual(response.status_code, 200 if project == allowed else 403, response.text)
                        if project == allowed:
                            self.assertEqual(http.post('/v1/access/release', json=response.json(), headers=headers).status_code, 200)
                            self.assertEqual(access.run_once(), 1)
            self.assertEqual([body['result_envelope']['sanitized_payload'] for _headers, body in self.received],
                             [self.source.read_text(), source_b.read_text()])

    def test_task_row_wait_is_bounded_and_cannot_publish_a_pending_entry(self):
        import psycopg
        identifier = self.prepare().json()['prepared_id']
        with psycopg.connect(DATABASE_URL) as connection:
            connection.execute('SELECT task_id FROM factory.tasks WHERE task_id=%s FOR UPDATE', (self.task.task_id,))
            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=1) as pool:
                response = pool.submit(self.release, identifier).result(timeout=2)
            elapsed = time.monotonic() - started
            self.assertEqual(response.status_code, 503, response.text)
            self.assertLess(elapsed, 2)
            self.assertEqual(self.access.run_once(), 0)
            self.assertEqual(self.received, [])

    def test_queued_source_deletion_stop_and_task_cancel_deny_dispatch(self):
        for operation in ('deletion', 'stop', 'cancel'):
            with self.subTest(operation=operation):
                identifier = self.prepare().json()['prepared_id']
                self.assertEqual(self.release(identifier).status_code, 200)
                if operation == 'deletion':
                    self.revoke(deleted=True)
                else:
                    path = '/v1/kill-switches' if operation == 'stop' else f'/v1/tasks/{self.task.task_id}/cancel'
                    body = ({'scope_key': 'global', 'enabled': True, 'reason': 'owned-control'}
                            if operation == 'stop' else {'reason': 'owned-control'})
                    response = self.http.post(path, json=body, headers={
                        'Authorization': 'Bearer synthetic-owned-credential-operator',
                        'Idempotency-Key': canonical_digest({'control': operation}), 'X-Correlation-ID': 'access-control'})
                    self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(self.access.run_once(), 0)
                self.assertEqual(self.received, [])
                # Restore only the owned test fixture for the next independent case.
                if operation == 'deletion':
                    restore = copy.deepcopy(self.policy)
                    restore['revision'] += 1
                    restore['sources'][0]['deleted'] = False
                    admin = self.auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
                    self.auth.access_authority.update(admin, self.policy['revision'], restore)
                    self.policy = restore
                elif operation == 'stop':
                    response = self.http.post('/v1/kill-switches', json={
                        'scope_key': 'global', 'enabled': False, 'reason': 'owned-restore'}, headers={
                        'Authorization': 'Bearer synthetic-owned-credential-operator',
                        'Idempotency-Key': canonical_digest({'control': 'restore'}), 'X-Correlation-ID': 'access-control'})
                    self.assertEqual(response.status_code, 200, response.text)

    def test_sql_file_and_transport_work_never_run_inside_source_mutex(self):
        from getzilla_factory import access_release
        authority = self.auth.access_authority
        native_transaction = self.fixture.store._transaction
        native_private, native_dispatch = access_release._private, self.client.dispatch
        owner = self
        class Cursor:
            def __init__(self, cursor):
                self.cursor = cursor
            def execute(self, *args, **kwargs):
                owner.assertFalse(authority._source._is_owned(), 'SQL inside SOURCE')
                return self.cursor.execute(*args, **kwargs)
            def __getattr__(self, name):
                return getattr(self.cursor, name)
        @contextmanager
        def observed_transaction(**kwargs):
            owner.assertFalse(authority._source._is_owned(), 'connect inside SOURCE')
            with native_transaction(**kwargs) as cursor:
                yield Cursor(cursor)
            owner.assertFalse(authority._source._is_owned(), 'commit inside SOURCE')
        def private(*args, **kwargs):
            self.assertFalse(authority._source._is_owned(), 'file read inside SOURCE')
            return native_private(*args, **kwargs)
        def dispatch(claim):
            self.assertFalse(authority._source._is_owned(), 'transport inside SOURCE')
            return native_dispatch(claim)
        with patch.object(self.fixture.store, '_transaction', observed_transaction), \
                patch.object(access_release, '_private', private), patch.object(self.client, 'dispatch', dispatch):
            prepared = self.prepare()
            self.assertEqual(prepared.status_code, 200, prepared.text)
            self.assertEqual(self.release(prepared.json()['prepared_id']).status_code, 200)
            self.assertEqual(self.access.run_once(), 1)
        self.assertEqual(len(self.received), 1)

    def test_pending_queue_cannot_send_before_real_commit_and_revocation_does_not_wait_for_it(self):
        native = self.fixture.store._transaction
        identifier = self.prepare().json()['prepared_id']
        before_commit, allow_commit = threading.Event(), threading.Event()
        @contextmanager
        def barrier(**kwargs):
            with native(**kwargs) as cursor:
                yield cursor
                before_commit.set()
                if not allow_commit.wait(1):
                    raise AssertionError('owned commit barrier timed out')
        with patch.object(self.fixture.store, '_transaction', barrier), ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.release, identifier)
            try:
                self.assertTrue(before_commit.wait(1))
                self.assertEqual(self.access.run_once(), 0)
                self.assertEqual(self.received, [])
                started = time.monotonic()
                self.revoke()
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                allow_commit.set()
            self.assertEqual(pending.result(timeout=2).status_code, 200)
        self.assertEqual(self.access.run_once(), 0)
        self.assertEqual(self.received, [])

    def test_unknown_actual_sink_outcome_stays_blocked_and_is_never_reposted(self):
        import psycopg
        self.sink_pending = True
        prepared = self.prepare().json()['prepared_id']
        self.assertEqual(self.release(prepared).status_code, 200)
        self.assertEqual(self.access.run_once(), 1)
        self.assertEqual(len(self.received), 1)
        self.assertEqual(self.access.run_once(), 0)
        self.assertEqual(self.release(prepared).status_code, 409)
        with psycopg.connect(DATABASE_URL) as connection:
            self.assertEqual(connection.execute('SELECT access_phase,dispatch_phase FROM '
                'factory.next_model_request_outbox_v1').fetchone(), ('unknown', 'blocked'))
            self.assertEqual(connection.execute('SELECT factory.claim_model_requests_v1(%s,%s,%s)',
                ('ordinary-dispatcher', 1, 5)).fetchone()[0], [])

    def test_revoke_during_actual_uds_transport_does_not_hold_source_or_task_locks(self):
        import psycopg
        prepared = self.prepare().json()['prepared_id']
        self.assertEqual(self.release(prepared).status_code, 200)
        self.sink_release.clear()
        with ThreadPoolExecutor(max_workers=1) as pool:
            dispatched = pool.submit(self.access.run_once)
            try:
                self.assertTrue(self.sink_entered.wait(1))
                started = time.monotonic()
                self.revoke()
                # A separate actual DB transaction can acquire the task row during UDS.
                with psycopg.connect(DATABASE_URL) as connection:
                    connection.execute("SET LOCAL lock_timeout='100ms'")
                    connection.execute('SELECT task_id FROM factory.tasks WHERE task_id=%s FOR UPDATE', (self.task.task_id,))
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                self.sink_release.set()
            self.assertEqual(dispatched.result(timeout=2), 1)
        # Dispatch admission preceded t0. The late effect is retained, not called revoked.
        self.assertEqual(len(self.received), 1)

    def test_private_source_cannot_target_a_public_or_unauthorized_audience(self):
        for public in (True, False):
            update = copy.deepcopy(self.policy)
            update['revision'] += 1
            update['destinations'][0].update(public=public, readers=[] if public else ['user-a', 'user-b'])
            admin = self.auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
            self.auth.access_authority.update(admin, self.policy['revision'], update)
            self.policy = update
            response = self.prepare()
            self.assertEqual(response.status_code, 403, response.text)
            self.assertNotIn('OWNED PRIVATE', response.text)
            self.assertEqual(self.received, [])

    def test_blocked_owned_source_read_does_not_block_operator_revision(self):
        from getzilla_factory import access_release
        entered, proceed = threading.Event(), threading.Event()
        native = access_release._private
        def bounded_read(*args, **kwargs):
            entered.set()
            proceed.wait(0.6)
            return native(*args, **kwargs)
        with patch.object(access_release, '_private', bounded_read), ThreadPoolExecutor(max_workers=1) as pool:
            request = pool.submit(self.prepare)
            try:
                self.assertTrue(entered.wait(1))
                started = time.monotonic()
                self.revoke()
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                proceed.set()
            self.assertEqual(request.result(timeout=2).status_code, 403)
        self.assertEqual(self.received, [])
