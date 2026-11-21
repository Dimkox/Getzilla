"""Closed Factory stop authority, with no deployed/provider/credential access."""
import hashlib
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
import secrets
import subprocess
from pathlib import Path
import tempfile
import threading
import time
import uuid
import unittest
from unittest.mock import patch

from getzilla_factory.landing_provider import LandingProviderError


class FactoryStopEntryTests(unittest.TestCase):
    def test_selector_encodes_the_actual_full_job_id_without_legacy_aliases(self):
        from getzilla_factory.factory_stop import landing_source_id
        for job in ('actual-job-1', 'A' * 128):
            expected = 'landing:v1:' + hashlib.sha256(job.encode('utf-8')).hexdigest()
            self.assertEqual(landing_source_id(job), expected)
            self.assertEqual(len(expected), 75)
        self.assertNotEqual(landing_source_id('actual-job-1'), landing_source_id('Actual-job-1'))

    def test_unbound_direct_probe_refuses_before_credential_lookup(self):
        from getzilla_factory import landing_live_executors as live
        with patch.object(live, 'qwen_api_key', side_effect=AssertionError('credential reader must not run')) as key:
            with self.assertRaises(LandingProviderError) as error:
                live.probe_qwen()
        self.assertEqual(str(error.exception), 'factory_stop_binding_required')
        self.assertEqual(key.call_count, 0)

    def test_opaque_capability_cannot_be_created_from_labels(self):
        from getzilla_factory.factory_stop import FactoryStopCapability
        with self.assertRaises(TypeError):
            FactoryStopCapability(repository_id='claimed', actor_id='claimed', task_id='claimed')

    def test_async_boundary_refuses_claimed_capability_before_observation(self):
        from unittest.mock import AsyncMock, Mock
        from getzilla_factory.factory_stop import FactoryStopError, require_stop_capability_async
        claimed = Mock(check_async=AsyncMock())
        async def exercise():
            for value in (None, {'repository_id': 'claimed'}, claimed):
                with self.assertRaises(FactoryStopError) as error:
                    await require_stop_capability_async(value, input_digest='1' * 64)
                self.assertEqual(error.exception.code, 'factory_stop_binding_required')
        asyncio.run(exercise())
        claimed.check_async.assert_not_awaited()

    def test_unbound_executor_refuses_before_lazy_credential_and_transport(self):
        import httpx
        from unittest.mock import Mock
        from getzilla_factory.landing_http import HttpLandingExecutionRequest, HttpLandingProfile
        from getzilla_factory.landing_live_executors import qwen_landing_executor
        profile = HttpLandingProfile.for_provider('qwen-intl', available=True)
        key = Mock(return_value='synthetic-key')
        posts = Mock(side_effect=AssertionError('transport must not run'))
        executor = qwen_landing_executor(profile=profile, credential_loader=key,
                                         transport=httpx.MockTransport(posts))
        with self.assertRaises(LandingProviderError) as error:
            executor.run(HttpLandingExecutionRequest(profile.profile_digest, '1' * 64, b'{}'))
        self.assertEqual(str(error.exception), 'factory_stop_binding_required')
        self.assertEqual(key.call_count, 0)
        self.assertEqual(posts.call_count, 0)

    def test_standalone_env_composition_refuses_before_credential_lookup(self):
        from getzilla_factory import landing_live_executors as live
        with patch.object(live, 'qwen_api_key', side_effect=AssertionError('key lookup must not run')) as key:
            with self.assertRaises(LandingProviderError) as error:
                live.compose_env_landing(object(), environ={live.LANDING_PROVIDER_ENV: 'qwen-intl'})
        self.assertEqual(str(error.exception), 'factory_stop_binding_required')
        self.assertEqual(key.call_count, 0)

    def test_standalone_server_composition_refuses_before_any_credential_lookup(self):
        from types import SimpleNamespace
        from getzilla_factory import landing_live_executors as live
        from getzilla_factory.landing_server import compose_server_landing
        from getzilla_factory.settings import SettingsError
        settings = SimpleNamespace(validate_landing=lambda: None, landing_live_enabled=True)
        with patch.object(live, 'qwen_api_key', side_effect=AssertionError('key lookup must not run')) as key:
            with self.assertRaises(SettingsError):
                compose_server_landing(settings, repository_root=Path('/unread-fixture-control'))
        self.assertEqual(key.call_count, 0)


from factory.tests.paid_fixture import PaidProtocolTestCase


@unittest.skipUnless(os.environ.get('FACTORY_TEST_DATABASE_URL'), 'requires bound disposable PostgreSQL')
class FactoryStopAuthorityTests(PaidProtocolTestCase):
    def setUp(self):
        super().setUp()
        import psycopg
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
        from factory.tests.run_disposable_exit import _binding_matches
        from factory.tests.postgres_fixture_reset import reset_fixture_tables
        from getzilla_factory.admin import provision_runtime_login
        from getzilla_factory.migrations import PostgresMigrator
        from getzilla_factory.models import Actor
        from getzilla_factory.service import FactoryService
        from getzilla_factory.store import PostgresFactoryStore
        from getzilla_factory.landing_intake import PrivateLandingBlobStore
        from getzilla_factory.landing_renderer import TARGET_BASE_SHA, TARGET_BASE_TREE, TARGET_REPOSITORY_ID
        from getzilla_factory.landing_service import LandingJobRecord
        from getzilla_factory.landing_sqlite_store import SQLiteLandingJobStore
        self.psycopg, self.url = psycopg, os.environ['FACTORY_TEST_DATABASE_URL']
        self.assertTrue(_binding_matches(os.environ['FACTORY_TEST_POSTGRES_CONTAINER_ID'],
                                        os.environ['FACTORY_TEST_POSTGRES_CONTAINER'],
                                        os.environ['FACTORY_TEST_POSTGRES_NONCE'], require_running=True))
        PostgresMigrator(self.url).apply()
        with psycopg.connect(self.url) as connection, connection.cursor() as cursor:
            reset_fixture_tables(cursor)
            cursor.execute('TRUNCATE factory.kill_switch_heads')
            cursor.execute('INSERT INTO factory.metric_counters(singleton) VALUES (true)')
        login = 'stop_bound_fixture'
        password = secrets.token_hex(24)
        provision_runtime_login(self.url, login, password)
        def remove_login():
            with psycopg.connect(self.url) as connection:
                connection.execute('DROP ROLE stop_bound_fixture')
        self.addCleanup(remove_login)
        runtime = make_conninfo(**{**conninfo_to_dict(self.url), 'user': login, 'password': password})
        self.service = FactoryService(PostgresFactoryStore(runtime))
        self.actor = Actor('fixture-client', 'client', frozenset({'task:submit', 'task:read', 'landing:submit'}),
                           frozenset({TARGET_REPOSITORY_ID}))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        control = root / 'control'
        control.mkdir(mode=0o700)
        self.now = datetime.now(timezone.utc)
        self.body = b'Synthetic gardening fixture brief.'
        self.blobs = PrivateLandingBlobStore(root / 'quarantine', repository_root=control)
        source = self.blobs.accept(
            job_id='actual-fixture-job', tenant_id=self.actor.actor_id, repository_id=TARGET_REPOSITORY_ID,
            exact_base_sha=TARGET_BASE_SHA, exact_base_tree=TARGET_BASE_TREE, site_id='therealaidarkfactory.online',
            media_kind='text', media_type='text/plain', chunks=(self.body,), received_at=self.now,
            expires_at=self.now + timedelta(days=1))
        self.landing_store = SQLiteLandingJobStore(root / 'state', repository_root=control)
        self.addCleanup(self.landing_store.close)
        self.landing_store.create_or_replay(LandingJobRecord(source, 'accepted', None, None),
                                            command_key=source.job_id, request_digest=source.input_digest)
        self.source = self.landing_store.get(source.tenant_id, source.repository_id, source.job_id).source

    def intake_payload(self):
        from factory.tests.test_contracts import valid_intake
        from getzilla_factory.factory_stop import landing_source_id
        payload = valid_intake()  # Synthetic contract facts, never an external approval/receipt.
        payload.update(repository_id=self.source.repository_id, source_type='api',
                       source_id=landing_source_id(self.source.job_id), source_digest=self.source.content_sha256,
                       exact_base_sha=self.source.exact_base_sha)
        payload['m0_authority']['observed_at'] = self.now.isoformat()
        # Synthetic authority fixture in this explicitly bound disposable DB.
        # This is not evidence of a real external CI check, approval or receipt.
        with self.psycopg.connect(self.url) as connection:
            connection.execute(
                'INSERT INTO factory.m0_authority_observations '
                '(observation_id,observed_at,check_name,exact_head_sha,issuer,evidence_digest,repository_id,policy_digest) '
                'VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
                (uuid.uuid4(), self.now, payload['m0_authority']['check_name'],
                 payload['m0_authority']['exact_head_sha'], 'external-trust-ci-api',
                 hashlib.sha256(b'synthetic-disposable-authority-fixture').hexdigest(),
                 self.source.repository_id, payload['policy_digest']))
        return payload

    def intake(self, *, actor=None):
        return self.service.intake(self.intake_payload(), actor=actor or self.actor, now=self.now).task

    def test_stored_source_observation_uses_a_bounded_read_without_a_write_reservation(self):
        import sqlite3
        with sqlite3.connect(self.landing_store.database_path, isolation_level=None) as connection:
            connection.execute('BEGIN IMMEDIATE')
            try:
                started = time.monotonic()
                observed = self.landing_store.observe_job(self.actor.actor_id, self.source.repository_id,
                                                          self.source.job_id)
                self.assertEqual(observed.source, self.source)
                self.assertLess(time.monotonic() - started, .5)
            finally:
                connection.execute('ROLLBACK')

    def test_stored_source_observation_refuses_busy_owner_without_waiting_for_external_work(self):
        from getzilla_factory.landing_service import LandingServiceError
        entered, release = threading.Event(), threading.Event()
        def holder():
            with self.landing_store._lock:
                entered.set()
                release.wait(3)
        with ThreadPoolExecutor(max_workers=1) as workers:
            held = workers.submit(holder)
            self.assertTrue(entered.wait(3))
            try:
                started = time.monotonic()
                with self.assertRaises(LandingServiceError):
                    self.landing_store.observe_job(self.actor.actor_id, self.source.repository_id, self.source.job_id)
                self.assertLess(time.monotonic() - started, .5)
            finally:
                release.set()
                held.result(timeout=3)

    def test_failed_source_observation_does_not_leave_a_transaction_open(self):
        from getzilla_factory.landing_service import LandingServiceError
        with patch.object(self.landing_store, '_select_record', side_effect=LandingServiceError(
                'fixture-corrupt-source', 500, 'synthetic fixture failure')):
            with self.assertRaises(LandingServiceError):
                self.landing_store.observe_job(self.actor.actor_id, self.source.repository_id, self.source.job_id)
        self.assertEqual(self.landing_store.get(self.actor.actor_id, self.source.repository_id,
                                                self.source.job_id).source, self.source)

    def test_real_task_and_stored_landing_owner_issue_one_opaque_capability(self):
        task = self.intake()
        capability = self.service.landing_stop_capability(self.source, actor=self.actor, landing_store=self.landing_store)
        capability.check(input_digest=self.source.input_digest)
        from getzilla_factory.factory_stop import FactoryStopError, require_stop_capability_async
        async def exercise():
            self.assertIs(await require_stop_capability_async(
                capability, input_digest=self.source.input_digest), capability)
            with self.assertRaises(FactoryStopError) as error:
                await require_stop_capability_async(capability, input_digest='0' * 64)
            self.assertEqual(error.exception.code, 'factory_stop_binding_required')
        asyncio.run(exercise())
        self.assertEqual(capability._initial.task_id, task.task_id)
        self.assertEqual(capability._initial.actor_id, self.source.tenant_id)
        self.assertEqual(capability._initial.job_id, self.source.job_id)
        self.assertNotIn(self.source.tenant_id, repr(capability))

    def test_missing_or_foreign_task_and_request_actor_cannot_replace_stored_creator(self):
        from getzilla_factory.factory_stop import FactoryStopError
        from getzilla_factory.models import Actor
        with self.assertRaises(FactoryStopError):
            self.service.landing_stop_capability(self.source, actor=self.actor, landing_store=self.landing_store)
        other = Actor('another-client', 'client', self.actor.scopes, self.actor.repositories)
        self.intake(actor=other)
        for actor in (self.actor, other):
            with self.assertRaises(FactoryStopError):
                self.service.landing_stop_capability(self.source, actor=actor, landing_store=self.landing_store)

    def test_off_on_off_revision_change_fences_existing_capability(self):
        from getzilla_factory.factory_stop import FactoryStopError
        from getzilla_factory.models import Actor
        self.intake()
        capability = self.service.landing_stop_capability(self.source, actor=self.actor, landing_store=self.landing_store)
        operator = Actor('fixture-operator', 'operator', frozenset({'factory:kill'}), frozenset({'*'}))
        for enabled, key in ((True, 'a' * 64), (False, 'b' * 64)):
            self.service.set_kill(scope_key='global', enabled=enabled, reason='fixture',
                                  idempotency_key=key, actor=operator, now=self.now)
            with self.assertRaises(FactoryStopError):
                capability.check()

    def test_unrelated_repository_stop_does_not_change_actual_repo_fence(self):
        from getzilla_factory.models import Actor
        self.intake()
        capability = self.service.landing_stop_capability(self.source, actor=self.actor, landing_store=self.landing_store)
        operator = Actor('fixture-operator', 'operator', frozenset({'factory:kill'}), frozenset({'*'}))
        self.service.set_kill(scope_key='repository:unrelated', enabled=True, reason='fixture',
                              idempotency_key='c' * 64, actor=operator, now=self.now)
        capability.check()

    def test_already_enabled_factory_stop_cannot_issue_a_new_capability(self):
        from getzilla_factory.factory_stop import FactoryStopError
        self.intake()
        self.stop_global()
        with self.assertRaises(FactoryStopError) as error:
            self.service.landing_stop_capability(self.source, actor=self.actor, landing_store=self.landing_store)
        self.assertEqual(str(error.exception), 'factory_stop_changed')

    def test_direct_probe_uses_a_real_bound_synthetic_source_and_stop_before_keys(self):
        import httpx
        from unittest.mock import Mock
        from factory.tests.test_landing_normalizer import draft
        from getzilla_factory.contracts import canonical_json
        from getzilla_factory import landing_live_executors as live
        from getzilla_factory.landing_service import LandingJobRecord
        brief = ('Create an English landing page for a fictional local gardening club. '
                 'One hero section. No links, prices, contacts or factual claims.')
        self.body = brief.encode()
        source = self.blobs.accept(
            job_id='actual-bound-probe-job', tenant_id=self.actor.actor_id,
            repository_id=self.source.repository_id, exact_base_sha=self.source.exact_base_sha,
            exact_base_tree=self.source.exact_base_tree, site_id=self.source.site_id,
            media_kind='text', media_type='text/plain', chunks=(self.body,), received_at=self.now,
            expires_at=self.now + timedelta(days=1))
        self.landing_store.create_or_replay(LandingJobRecord(source, 'accepted', None, None),
                                            command_key=source.job_id, request_digest=source.input_digest)
        self.source = self.landing_store.get(source.tenant_id, source.repository_id, source.job_id).source
        self.intake()
        capability = self.service.landing_stop_capability(self.source, actor=self.actor,
                                                         landing_store=self.landing_store)
        document = {'object': 'chat.completion', 'model': 'qwen3.5-plus',
                    'choices': [{'index': 0, 'finish_reason': 'stop', 'message': {
                        'role': 'assistant', 'content': draft().decode()}}],
                    'usage': {'prompt_tokens': 12, 'completion_tokens': 34, 'total_tokens': 46}}
        from getzilla_factory.landing_http import HttpLandingProfile
        profile = HttpLandingProfile.for_provider('qwen-intl', available=True)
        document['model'] = profile.model_id
        posts = Mock(side_effect=lambda request: httpx.Response(200, headers={'Content-Type': 'application/json'},
                                                               stream=httpx.ByteStream(canonical_json(document))))
        with patch.object(live, 'qwen_api_key', return_value='synthetic-key') as key:
            result = live.probe_qwen(stop_capability=capability, transport=httpx.MockTransport(posts),
                admission=self.admission(profile.provider_id, profile.model_id, self.source.input_digest))
        self.assertEqual(result['state'], 'normalized')
        self.assertEqual(result['input_digest'], self.source.input_digest)
        self.assertEqual(key.call_count, 1)
        self.assertEqual(posts.call_count, 1)
        self.stop_global()
        with patch.object(live, 'qwen_api_key', side_effect=AssertionError('stopped credential read')) as key:
            with self.assertRaises(LandingProviderError) as error:
                live.probe_qwen(stop_capability=capability, transport=httpx.MockTransport(posts))
        self.assertEqual(str(error.exception), 'factory_stop_changed')
        key.assert_not_called()
        self.assertEqual(posts.call_count, 1)

    def http_request(self, profile, capability):
        from getzilla_factory.contracts import canonical_json
        from getzilla_factory.landing_http import HTTP_NORMALIZER_PROMPT, HTTP_PROTOCOL_VERSION, HttpLandingExecutionRequest
        payload = canonical_json({'instruction': HTTP_NORMALIZER_PROMPT, 'request': {
            'protocol_version': HTTP_PROTOCOL_VERSION, 'profile_digest': profile.profile_digest,
            'input_digest': self.source.input_digest, 'media_kind': 'text', 'source_payload': self.body.decode(),
            'source_content_sha256': self.source.content_sha256}})
        return HttpLandingExecutionRequest(profile.profile_digest, self.source.input_digest, payload,
                                           stop_capability=capability)

    def stop_global(self):
        from getzilla_factory.models import Actor
        operator = Actor('fixture-operator', 'operator', frozenset({'factory:kill'}), frozenset({'*'}))
        self.service.set_kill(scope_key='global', enabled=True, reason='fixture', idempotency_key='d' * 64,
                              actor=operator, now=self.now)

    def test_revocation_during_credential_load_prevents_actual_post(self):
        import httpx
        from unittest.mock import Mock
        from getzilla_factory.landing_http import HttpLandingProfile
        from getzilla_factory.landing_live_executors import qwen_landing_executor
        self.intake()
        capability = self.service.landing_stop_capability(self.source, actor=self.actor, landing_store=self.landing_store)
        profile = HttpLandingProfile.for_provider('qwen-intl', available=True)
        def key():
            self.stop_global()
            return 'synthetic-key'
        class UnexpectedBody(httpx.AsyncByteStream):
            async def __aiter__(inner):
                yield b'{}'
        posts = Mock(return_value=httpx.Response(200, headers={'Content-Type': 'application/json'},
                                                 stream=UnexpectedBody()))
        executor = qwen_landing_executor(profile=profile, credential_loader=key,
                                         transport=httpx.MockTransport(posts))
        with self.assertRaises(LandingProviderError) as error:
            executor.run(self.http_request(profile, capability))
        self.assertEqual(str(error.exception), 'factory_stop_changed')
        self.assertEqual(posts.call_count, 0)
        self.assertFalse(error.exception.dispatched)

    def test_changed_request_content_binding_refuses_before_credential_and_post(self):
        import json
        from dataclasses import replace
        import httpx
        from unittest.mock import Mock
        from getzilla_factory.contracts import canonical_json
        from getzilla_factory.landing_http import HttpLandingProfile
        from getzilla_factory.landing_live_executors import qwen_landing_executor
        self.intake()
        capability = self.service.landing_stop_capability(self.source, actor=self.actor,
                                                         landing_store=self.landing_store)
        profile = HttpLandingProfile.for_provider('qwen-intl', available=True)
        request = self.http_request(profile, capability)
        document = json.loads(request.payload)
        document['request']['source_content_sha256'] = 'f' * 64
        key = Mock(return_value='synthetic-key')
        posts = Mock(return_value=httpx.Response(200, content=b'{}'))
        executor = qwen_landing_executor(profile=profile, credential_loader=key,
                                         transport=httpx.MockTransport(posts))
        with self.assertRaises(LandingProviderError) as error:
            executor.run(replace(request, payload=canonical_json(document)))
        self.assertEqual(str(error.exception), 'factory_stop_binding_required')
        self.assertFalse(error.exception.dispatched)
        key.assert_not_called()
        posts.assert_not_called()

    def assert_active_stop(self, phase):
        import httpx
        from getzilla_factory.landing_http import HttpLandingProfile
        from getzilla_factory.landing_live_executors import qwen_landing_executor
        self.intake()
        capability = self.service.landing_stop_capability(self.source, actor=self.actor, landing_store=self.landing_store)
        profile = HttpLandingProfile.for_provider('qwen-intl', available=True)
        entered, closed = threading.Event(), threading.Event()
        class Body(httpx.AsyncByteStream):
            async def __aiter__(inner):
                entered.set()
                await asyncio.sleep(3)
                yield b'{}'
            async def aclose(inner):
                closed.set()
        async def handler(request):
            if phase == 'headers':
                entered.set()
                await asyncio.sleep(3)
                raise httpx.ConnectError('synthetic delayed transport outcome')
            return httpx.Response(200, headers={'Content-Type': 'application/json'}, stream=Body())
        executor = qwen_landing_executor(profile=profile, credential_loader=lambda: 'synthetic-key',
                                         transport=httpx.MockTransport(handler))
        with ThreadPoolExecutor(max_workers=1) as workers:
            result = workers.submit(executor.run, self.http_request(profile, capability))
            self.assertTrue(entered.wait(5))
            self.stop_global()
            started = time.monotonic()
            with self.assertRaises(LandingProviderError) as error:
                result.result(timeout=5)
        self.assertEqual(str(error.exception), 'factory_stop_changed')
        self.assertEqual(error.exception.category, 'policy')
        self.assertTrue(error.exception.dispatched)
        self.assertLess(time.monotonic() - started, 2)
        if phase == 'body':
            self.assertTrue(closed.is_set())

    def test_stop_interrupts_wait_for_response_headers(self):
        self.assert_active_stop('headers')

    def test_stop_interrupts_wait_for_response_body(self):
        self.assert_active_stop('body')

    def assert_authority_outage(self, phase):
        """Pause only our bound fixture during actual connect, role or stop IO."""
        import httpx
        from factory.tests.run_disposable_exit import _binding_matches
        from getzilla_factory.landing_http import HttpLandingProfile
        from getzilla_factory.landing_live_executors import qwen_landing_executor
        self.intake()
        capability = self.service.landing_stop_capability(self.source, actor=self.actor,
                                                         landing_store=self.landing_store)
        profile = HttpLandingProfile.for_provider('qwen-intl', available=True)
        entered, paused, closed = threading.Event(), threading.Event(), threading.Event()
        pause_requested = threading.Event()
        container = os.environ['FACTORY_TEST_POSTGRES_CONTAINER_ID']
        def docker_state(action):
            self.assertTrue(_binding_matches(container, os.environ['FACTORY_TEST_POSTGRES_CONTAINER'],
                                             os.environ['FACTORY_TEST_POSTGRES_NONCE'], require_running=True))
            subprocess.run(['docker', action, container], check=True, capture_output=True, timeout=10)
        connections = []
        original_connect = self.psycopg.AsyncConnection.connect
        original_async_execute = self.psycopg.AsyncCursor.execute
        async def pause():
            # Docker's bounded process owner installs signal handlers. Keep
            # its exact identity check and pause on the main test thread.
            pause_requested.set()
            while not paused.is_set():
                await asyncio.sleep(.005)
        async def paused_connect(*arguments, **keywords):
            if phase == 'connect' and entered.is_set() and not paused.is_set():
                await pause()
            connection = await original_connect(*arguments, **keywords)
            connections.append(connection)
            return connection
        async def paused_async_query(cursor, query, *arguments, **keywords):
            selected = (phase == 'query' and str(query).startswith('WITH heads AS')) or (
                phase == 'session' and 'FROM pg_roles WHERE rolname=session_user' in str(query))
            if selected and entered.is_set() and not paused.is_set():
                await pause()
            return await original_async_execute(cursor, query, *arguments, **keywords)
        class Body(httpx.AsyncByteStream):
            async def __aiter__(inner):
                entered.set()
                await asyncio.sleep(10)
                yield b'{}'
            async def aclose(inner):
                closed.set()
        executor = qwen_landing_executor(profile=profile, credential_loader=lambda: 'synthetic-key',
            transport=httpx.MockTransport(lambda request: httpx.Response(
                200, headers={'Content-Type': 'application/json'}, stream=Body())))
        with (ThreadPoolExecutor(max_workers=1) as workers,
              patch.object(self.psycopg.AsyncConnection, 'connect', paused_connect),
              patch.object(self.psycopg.AsyncCursor, 'execute', paused_async_query)):
            result = workers.submit(executor.run, self.http_request(profile, capability))
            try:
                if not pause_requested.wait(5):
                    # Surface an early executor refusal instead of hiding it
                    # behind the downstream pause signal assertion.
                    result.result(timeout=1)
                    self.fail('authority outage did not reach the pause boundary')
                docker_state('pause')
                paused.set()
                try:
                    result.result(timeout=2)
                except LandingProviderError as error:
                    self.assertEqual(str(error), 'factory_stop_authority_unavailable')
                    self.assertTrue(error.dispatched)
                    self.assertTrue(closed.is_set())
                except TimeoutError:
                    self.fail('authority observation did not bound the active HTTP wait')
                else:
                    self.fail('authority outage accepted a provider result')
            finally:
                if paused.is_set():
                    docker_state('unpause')
                    self.stop_global()
                try:
                    result.result(timeout=5)
                except LandingProviderError:
                    pass
        self.assertTrue(connections)
        self.assertTrue(all(connection.closed for connection in connections))
        deadline = time.monotonic() + 1
        while True:
            with self.psycopg.connect(self.url) as connection:
                count = connection.execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE usename='stop_bound_fixture'"
                ).fetchone()[0]
            if count == 0 or time.monotonic() >= deadline:
                break
            time.sleep(.02)
        self.assertEqual(count, 0, 'owned observer left a live fixture connection')

    def test_authority_outage_during_query_cancels_active_http_with_a_real_bound(self):
        self.assert_authority_outage('query')

    def test_authority_outage_during_session_check_cancels_active_http_with_a_real_bound(self):
        self.assert_authority_outage('session')

    def test_authority_outage_during_connect_cancels_active_http_with_a_real_bound(self):
        self.assert_authority_outage('connect')

    def test_cancelled_observation_closes_owned_connection_and_joins_its_task(self):
        self.intake()
        connections = []
        async def exercise():
            entered = asyncio.Event()
            async def waiting_query(cursor, source, actor):
                connections.append(cursor.connection)
                entered.set()
                await asyncio.sleep(10)
            with patch.object(self.service.store, '_landing_stop_snapshot_query', waiting_query):
                task = asyncio.create_task(self.service.store.landing_stop_snapshot(self.source, self.actor))
                await asyncio.wait_for(entered.wait(), 2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            self.assertEqual(asyncio.all_tasks(), {asyncio.current_task()})
        started = time.monotonic()
        asyncio.run(exercise())
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(connections)
        self.assertTrue(all(connection.closed for connection in connections))

    def assert_observer_exception_cleanup(self, error_type):
        self.intake()
        connections = []
        async def failed_query(cursor, source, actor):
            connections.append(cursor.connection)
            raise error_type('synthetic observer interruption')
        with patch.object(self.service.store, '_landing_stop_snapshot_query', failed_query):
            with self.assertRaises(error_type):
                asyncio.run(self.service.store.landing_stop_snapshot(self.source, self.actor))
        self.assertTrue(connections)
        self.assertTrue(all(connection.closed for connection in connections))

    def test_observer_exception_closes_its_owned_connection(self):
        self.assert_observer_exception_cleanup(RuntimeError)

    def test_observer_keyboard_interrupt_closes_its_owned_connection(self):
        self.assert_observer_exception_cleanup(KeyboardInterrupt)

    def assert_httpcore_stop(self, phase):
        """Exercise actual httpx/httpcore connects and reads; mock only network IO."""
        import httpcore
        import httpx
        from getzilla_factory.landing_http import HttpLandingProfile
        from getzilla_factory.landing_live_executors import qwen_landing_executor
        self.intake()
        capability = self.service.landing_stop_capability(self.source, actor=self.actor,
                                                         landing_store=self.landing_store)
        entered, closed = threading.Event(), threading.Event()
        writes = []
        class Stream:
            async def start_tls(inner, **kwargs):
                return inner
            def get_extra_info(inner, name):
                return None
            async def write(inner, data, **kwargs):
                writes.append(len(data))  # Never retain or print synthetic credential headers.
            async def read(inner, maximum, **kwargs):
                entered.set()
                await asyncio.sleep(3)
                raise httpcore.ReadTimeout('synthetic blocked header read')
            async def aclose(inner):
                closed.set()
        class Backend:
            async def connect_tcp(inner, *arguments, **keywords):
                if phase == 'connect':
                    entered.set()
                    await asyncio.sleep(3)
                    raise httpcore.ConnectTimeout('synthetic blocked connect')
                return Stream()
            async def connect_unix_socket(inner, *arguments, **keywords):
                raise AssertionError('unexpected Unix socket')
            async def sleep(inner, seconds):
                await asyncio.sleep(seconds)
        transport = httpx.AsyncHTTPTransport(retries=0)
        transport._pool._network_backend = Backend()  # Pinned test dependency, no production seam.
        profile = HttpLandingProfile.for_provider('qwen-intl', available=True)
        executor = qwen_landing_executor(profile=profile, credential_loader=lambda: 'synthetic-key', transport=transport)
        with ThreadPoolExecutor(max_workers=1) as workers:
            result = workers.submit(executor.run, self.http_request(profile, capability))
            self.assertTrue(entered.wait(5))
            self.stop_global()
            started = time.monotonic()
            with self.assertRaises(LandingProviderError) as error:
                result.result(timeout=5)
        self.assertEqual(str(error.exception), 'factory_stop_changed')
        self.assertEqual(error.exception.category, 'policy')
        self.assertTrue(error.exception.dispatched)  # Admitted; remote outcome remains unconfirmed.
        self.assertLess(time.monotonic() - started, 2)
        if phase == 'connect':
            self.assertEqual(writes, [])
        else:
            self.assertTrue(writes)
            self.assertTrue(closed.is_set())

    def test_stop_interrupts_actual_http_stack_connect_await(self):
        self.assert_httpcore_stop('connect')

    def test_stop_interrupts_actual_http_stack_header_read(self):
        self.assert_httpcore_stop('headers')

    def test_actual_api_orders_factory_task_before_upload_and_replay_never_posts_twice(self):
        import httpx
        from unittest.mock import Mock
        from fastapi.testclient import TestClient
        from getzilla_factory.api import Authenticator, create_app
        from getzilla_factory.contracts import canonical_json
        from getzilla_factory.factory_stop import landing_source_id
        from getzilla_factory.landing_http import HttpLandingNormalizer, HttpLandingProfile
        from getzilla_factory.landing_live_executors import qwen_landing_executor
        from getzilla_factory.landing_service import LandingApplicationService
        from factory.tests.test_landing_normalizer import draft
        job = 'actual-api-positive-job'
        self.assertIsNone(self.landing_store.find(self.actor.actor_id, self.source.repository_id, job))
        profile = HttpLandingProfile.for_provider('qwen-intl', available=True)
        key = Mock(return_value='synthetic-key')
        document = {'object': 'chat.completion', 'model': profile.model_id,
                    'choices': [{'index': 0, 'finish_reason': 'stop', 'message': {
                        'role': 'assistant', 'content': draft().decode()}}],
                    'usage': {'prompt_tokens': 12, 'completion_tokens': 34, 'total_tokens': 46}}
        posts = Mock(side_effect=lambda request: httpx.Response(200, headers={'Content-Type': 'application/json'},
                                                               stream=httpx.ByteStream(canonical_json(document))))
        executor = qwen_landing_executor(profile=profile, credential_loader=key,
                                         transport=httpx.MockTransport(posts))
        landing = LandingApplicationService(self.landing_store, self.blobs, HttpLandingNormalizer(profile, executor),
                                            profile_digest=profile.profile_digest, factory_service=self.service)
        app = create_app(self.service, Authenticator({'synthetic-fixture-token': self.actor}),
                          execution_enabled=False, landing_service=landing)
        payload = self.intake_payload()
        payload['source_id'] = landing_source_id(job)
        auth = {'Authorization': 'Bearer synthetic-fixture-token', 'X-Correlation-ID': 'fixture-correlation'}
        with TestClient(app) as client:
            accepted = client.post('/v1/tasks', headers={**auth, 'Idempotency-Key': payload['request_id']}, json=payload)
            self.assertEqual(accepted.status_code, 201, accepted.json())
            self.assertIsNone(self.landing_store.find(self.actor.actor_id, self.source.repository_id, job))
            self.assertEqual(key.call_count, 0)
            headers = {**auth, 'Idempotency-Key': job, 'Content-Type': 'text/plain',
                       'X-Repository-ID': self.source.repository_id, 'X-Exact-Base-SHA': self.source.exact_base_sha,
                       'X-Exact-Base-Tree': self.source.exact_base_tree}
            uploaded = client.post('/v1/landing-inputs', headers=headers, content=self.body)
            self.assertEqual(uploaded.status_code, 202, uploaded.json())
            repeated = client.post('/v1/landing-inputs', headers=headers, content=self.body)
            self.assertEqual(repeated.status_code, 202, repeated.json())
        self.assertEqual(posts.call_count, 1)
        self.assertEqual(key.call_count, 1)
        stored = self.landing_store.get(self.actor.actor_id, self.source.repository_id, job)
        self.assertEqual(stored.observation.category, 'normalized')
        self.assertTrue(stored.observation.dispatched)
        self.assertEqual(uploaded.json()['input_digest'], stored.source.input_digest)

    def test_job_cancel_progresses_during_http_and_late_success_is_not_published(self):
        import httpx
        from getzilla_factory.factory_stop import landing_source_id
        from getzilla_factory.landing_http import HttpLandingNormalizer, HttpLandingProfile
        from getzilla_factory.landing_live_executors import qwen_landing_executor
        from getzilla_factory.landing_service import LandingApplicationService
        job = 'actual-cancellable-job'
        payload = self.intake_payload()
        payload['source_id'] = landing_source_id(job)
        self.service.intake(payload, actor=self.actor, now=self.now)
        entered = threading.Event()
        class Body(httpx.AsyncByteStream):
            async def __aiter__(inner):
                entered.set()
                await asyncio.sleep(3)
                yield b'{}'
        profile = HttpLandingProfile.for_provider('qwen-intl', available=True)
        executor = qwen_landing_executor(profile=profile, credential_loader=lambda: 'synthetic-key',
                                         transport=httpx.MockTransport(lambda request: httpx.Response(
                                             200, headers={'Content-Type': 'application/json'}, stream=Body())))
        landing = LandingApplicationService(self.landing_store, self.blobs, HttpLandingNormalizer(profile, executor),
                                            profile_digest=profile.profile_digest, factory_service=self.service)
        with ThreadPoolExecutor(max_workers=1) as workers:
            result = workers.submit(landing.submit, job_id=job, repository_id=self.source.repository_id,
                                     exact_base_sha=self.source.exact_base_sha, exact_base_tree=self.source.exact_base_tree,
                                     media_type='text/plain', chunks=(self.body,), actor=self.actor)
            self.assertTrue(entered.wait(5))
            started = time.monotonic()
            cancelled = landing.cancel(job, repository_id=self.source.repository_id,
                                        idempotency_key='fixture-cancel', actor=self.actor)
            self.assertLess(time.monotonic() - started, .5)
            self.assertEqual(cancelled.state, 'cancelled')
            finished = result.result(timeout=5).job
        self.assertEqual(finished.state, 'cancelled')
        self.assertIsNone(finished.artifact)
        self.assertEqual(finished.observation.category, 'policy')
        self.assertEqual(finished.observation.usage_status, 'unavailable')


if __name__ == '__main__':
    unittest.main()
