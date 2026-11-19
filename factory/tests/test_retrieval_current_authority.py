"""Real owned operator authority/files; SQL task fixture remains substituted.

These tests do not claim PostgreSQL, real model or UDS qualification.
"""
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from factory.tests.test_access_authority import authority_fixture
from factory.tests import test_native_access as base
from factory.tests.test_retrieval_access import PROFILE, QUERY
from getzilla.native_access import NativeAccessBroker, NativeAccessError, RegisteredQuery
from getzilla_factory.access_authority import AccessAuthority, AccessError, _private
from getzilla_factory.access_release import AccessReleaseService, LocalSourceAdapter


class CurrentAuthorityRetrievalTests(unittest.TestCase):
    transaction = base.FactoryNativeAccessTests.transaction
    read_empty = base.FactoryNativeAccessTests.read_empty
    deadline = base.FactoryNativeAccessTests.deadline

    def setUp(self):
        base.FactoryNativeAccessTests.setUp(self)
        self.owned = tempfile.TemporaryDirectory(prefix='getzilla-retrieval-current-')
        self.addCleanup(self.owned.cleanup)
        self.root = Path(self.owned.name)

    def enable(self, *, classification='internal'):
        path, self.policy, self.key = authority_fixture(self.root)
        self.policy_path = path
        for principal in ('user-a', 'user-b'):
            worker = copy.deepcopy(next(item for item in self.policy['actors'] if item['actor_id'] == principal))
            worker.update(actor_id='worker-' + principal[-1], kind='worker', principal_id=principal,
                delegation_owner=principal, delegation_expires_at=4102444800)
            worker['scopes'] += ['task:execute']
            credential = self.root / ('worker-' + principal[-1])
            credential.write_text('synthetic-retrieval-credential-' + principal)
            credential.chmod(0o600)
            worker['token_file'] = str(credential)
            self.policy['actors'].append(worker)
        own_key, foreign_key = self.key('a'), self.key('b')
        restricted_key = own_key | {'resource': 'restricted-same-project'}
        other_tenant_key = own_key | {'tenant': 'tenant-b'}
        self.policy['sources'] += [dict(key=restricted_key, repository_id='repo-a', version='v1',
            deleted=False, readers=['user-b'], groups=[], public=False),
            dict(key=other_tenant_key, repository_id='repo-a', version='v1',
                deleted=False, readers=['user-a'], groups=[], public=False)]
        self.policy['destinations'].append(dict(destination_id='private-b', tenant_id='tenant-a',
            project_id='project-a', repository_id='repo-a', readers=['user-b'], public=False, revision=1))
        path.write_text(json.dumps(self.policy))
        self.authority = AccessAuthority.load(path)
        self.admin = self.authority.open_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
        self.session = self.authority.open_session('Bearer synthetic-retrieval-credential-user-a', 'source:read')
        self.context = replace(self.context, owner='worker-a', repository_id='repo-a',
            allowed_paths=('owned.py', 'restricted.py', 'foreign.py', 'other-tenant.py'), max_output_bytes=32768)
        self.store._proposal_context.return_value = self.context
        self.grant = replace(self.grant, owner='worker-a')
        self.workflow = self.n.FactoryTaskBinding(self.grant, 'b' * 64)
        self.source_bytes = b'def choose_key(value):\n    return "AUTHORIZED_A"\n'
        registrations = []
        for key, relative, raw, repository in (
                (own_key, 'owned.py', self.source_bytes, 'repo-a'),
                (restricted_key, 'restricted.py', b'def choose_key():\n    return "DENIED_SAME_PROJECT"\n', 'repo-a'),
                (foreign_key, 'foreign.py', b'def choose_key():\n    return "DENIED_OTHER_PROJECT"\n', 'repo-b'),
                (other_tenant_key, 'other-tenant.py', b'def choose_key():\n    return "DENIED_OTHER_TENANT"\n', 'repo-a')):
            source = self.root / relative
            source.write_bytes(raw)
            source.chmod(0o600)
            registrations.append(dict(key=key, version='v1', repository_id=repository,
                workspace_handle='workspace', relative_path=relative, file=str(source),
                content_digest=hashlib.sha256(raw).hexdigest(), classification=classification))
        self.sources = LocalSourceAdapter(registrations)
        self.reads = []
        def actual_read(path, limit):
            self.reads.append(Path(path).name)
            return _private(path, limit)
        self.enterContext(patch('getzilla_factory.access_release._private', side_effect=actual_read))
        destination = self.service._destinations['registered-response']
        self.service = AccessReleaseService(self.store, self.authority, self.sources,
            {'private-a': destination, 'private-b': destination}, retrieval_profile=PROFILE)
        self.host = self.n.FactoryNativeAccessHost(self.service)
        self.broker = NativeAccessBroker._compose(self.host)
        self.handle = self.broker.bind_native_request(self.session, self.workflow)
        self.retrieval_query = RegisteredQuery(QUERY, ('current-destination',), {
            'query': 'choose_key', 'destination_id': 'private-a', 'token_budget': 2048})

    def prepare_retrieval(self):
        cut = self.broker.load_authorized_cut(self.handle, self.retrieval_query, absolute_deadline=self.deadline())
        reference = self.broker.prepare_owned_response(self.handle, QUERY, cut,
            'private-a', absolute_deadline=self.deadline())
        return cut, reference, next(iter(self.service._prepared.values()))

    # These tests retain real authority/files; their SQL fixture is explicit.
    def test_real_authority_excludes_other_principal_project_tenant_before_read(self):
        self.enable()
        cut, _, prepared = self.prepare_retrieval()
        wire = prepared.envelope.sanitized_payload
        self.assertIn('AUTHORIZED_A', wire)
        for marker in ('DENIED_SAME_PROJECT', 'DENIED_OTHER_PROJECT', 'DENIED_OTHER_TENANT',
                       'restricted.py', 'foreign.py', 'other-tenant.py'):
            self.assertNotIn(marker, wire)
        self.assertEqual({item.dependency.key for item in cut.documents}, {tuple(self.key('a').values())})
        self.assertEqual(set(self.reads), {'owned.py'})

    def test_second_principal_same_project_cannot_receive_first_principal_context(self):
        self.enable()
        session = self.authority.open_session('Bearer synthetic-retrieval-credential-user-b', 'source:read')
        self.store._proposal_context.return_value = replace(self.context, owner='worker-b')
        workflow = self.n.FactoryTaskBinding(replace(self.grant, owner='worker-b'), 'b' * 64)
        handle = self.broker.bind_native_request(session, workflow)
        query = RegisteredQuery(QUERY, ('current-destination',), {
            'query': 'choose_key', 'destination_id': 'private-b', 'token_budget': 2048})
        cut = self.broker.load_authorized_cut(handle, query, absolute_deadline=self.deadline())
        self.broker.prepare_owned_response(handle, QUERY, cut, 'private-b', absolute_deadline=self.deadline())
        prepared = next(iter(self.service._prepared.values()))
        self.assertIn('DENIED_SAME_PROJECT', prepared.envelope.sanitized_payload)
        self.assertNotIn('AUTHORIZED_A', prepared.envelope.sanitized_payload)
        self.assertEqual(set(self.reads), {'restricted.py'})

    def test_group_removal_rejects_old_session_and_stale_prepared_context(self):
        self.enable()
        _, reference, _ = self.prepare_retrieval()
        update = copy.deepcopy(self.policy)
        update['revision'] = 2
        update['groups'][0]['members'] = []
        self.authority.update(self.admin, 1, update)
        with self.assertRaises(NativeAccessError):
            self.broker.admit_response(self.handle, reference)
        fresh = self.broker.bind_native_request(self.session, self.workflow)
        with self.assertRaises(NativeAccessError):
            self.broker.load_authorized_cut(fresh, self.retrieval_query, absolute_deadline=self.deadline())
        self.assertEqual(self.service._queue._entries, {})

    def test_deleted_source_and_duplicate_or_out_of_order_updates_never_restore_context(self):
        self.enable()
        self.prepare_retrieval()
        update = copy.deepcopy(self.policy)
        update['revision'] = 2
        update['sources'][0]['deleted'] = True
        self.authority.update(self.admin, 1, update)
        with self.assertRaises(AccessError):
            self.authority.update(self.admin, 1, self.policy)
        fresh = self.broker.bind_native_request(self.session, self.workflow)
        with self.assertRaises(NativeAccessError):
            self.broker.load_authorized_cut(fresh, self.retrieval_query, absolute_deadline=self.deadline())
        self.assertEqual(self.service._queue._entries, {})

    def test_source_replacement_invalidates_captured_citations_without_permission_revision_change(self):
        self.enable()
        cut = self.broker.load_authorized_cut(self.handle, self.retrieval_query, absolute_deadline=self.deadline())
        (self.root / 'owned.py').write_bytes(b'def choose_key():\n    return "CHANGED"\n')
        with self.assertRaises(NativeAccessError):
            self.broker.prepare_owned_response(self.handle, QUERY, cut, 'private-a', absolute_deadline=self.deadline())
        self.assertEqual(self.service._prepared, {})

    def test_unavailable_authority_cannot_reuse_cached_context_and_disposal_needs_no_old_allow(self):
        self.enable()
        self.prepare_retrieval()
        self.policy_path.unlink()
        with self.assertRaises(NativeAccessError):
            self.broker.load_authorized_cut(self.handle, self.retrieval_query,
                absolute_deadline=self.deadline())
        self.broker.discard(self.handle)
        self.assertEqual(self.broker._requests, {})
        self.assertIsNone(getattr(next(iter(self.service._prepared.values())), 'envelope', None))
