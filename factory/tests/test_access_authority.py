"""Actual authenticated source admission, using owned synthetic authority only."""
from __future__ import annotations

import unittest
import copy
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from getzilla_factory.api import Authenticator, create_app
from getzilla_factory.models import Actor
from getzilla_factory.service import FactoryService
from getzilla_factory import server


def authority_fixture(root):
    actors = []
    for name, kind in [('user-a', 'client'), ('user-b', 'client'), ('operator', 'operator')]:
        credential = root / (name + '-credential')
        credential.write_text('synthetic-owned-credential-' + name)
        credential.chmod(0o600)
        actors.append({'actor_id': name, 'kind': kind,
            'scopes': ['source:read', 'source:release'] + (['factory:access-admin'] if kind == 'operator' else []),
            'repositories': ['repo-a', 'repo-b'], 'token_file': str(credential),
            'credential_generation': 1, 'principal_id': name, 'tenant_id': 'tenant-a',
            'projects': [{'project_id': 'project-a', 'repository_id': 'repo-a'},
                         {'project_id': 'project-b', 'repository_id': 'repo-b'}],
            'delegation_owner': None, 'delegation_expires_at': None})
    def key(project):
        return {'tenant': 'tenant-a', 'project': 'project-' + project,
                'provider': 'local', 'site': 'site-' + project, 'resource': 'same-id'}
    payload = {'schema_version': 2, 'revision': 1, 'actors': actors,
        'groups': [{'tenant_id': 'tenant-a', 'group_id': 'team-a', 'members': ['user-a']}],
        'sources': [{'key': key(project), 'repository_id': 'repo-' + project,
            'version': 'v1', 'deleted': False, 'readers': [], 'groups': ['team-a'], 'public': False}
            for project in ('a', 'b')],
        'destinations': [{'destination_id': 'private-a', 'tenant_id': 'tenant-a',
            'project_id': 'project-a', 'repository_id': 'repo-a',
            'readers': ['user-a'], 'public': False, 'revision': 1}]}
    path = root / 'actors.json'
    path.write_text(json.dumps(payload))
    path.chmod(0o600)
    return path, payload, key


class AccessAuthorityTests(unittest.TestCase):
    def load_v2(self, path):
        try:
            loaded = server.load_actors(path)
        except server.ServerError:
            self.fail('The operator authority loader has no supported V2 source boundary')
        authenticator = Authenticator(loaded)
        self.assertTrue(hasattr(authenticator, 'access_session'),
                        'No authenticated non-replayable source session exists')
        return authenticator

    def test_current_group_removal_invalidates_an_old_authenticated_session(self):
        # Break caught: reusing frozen Actor/group permission after an operator update.
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, payload, key = authority_fixture(root)
            auth = self.load_v2(path)
            session = auth.access_session('Bearer synthetic-owned-credential-user-a', 'source:read')
            authority = auth.access_authority
            self.assertTrue(authority.authorize(session, key('a'), 'v1', 'source:read'))
            next_state = copy.deepcopy(payload)
            next_state['revision'] = 2
            next_state['groups'][0]['members'] = []
            admin = auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
            authority.update(admin, 1, next_state)
            self.assertFalse(authority.authorize(session, key('a'), 'v1', 'source:read'))

    def test_rotated_credential_session_is_not_reissued_from_old_actor_identity(self):
        # Break caught: a stale credential generation reacquiring current user rights.
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, payload, key = authority_fixture(root)
            auth = self.load_v2(path)
            session = auth.access_session('Bearer synthetic-owned-credential-user-a', 'source:read')
            admin = auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
            replacement = root / 'rotated-credential'
            replacement.write_text('synthetic-owned-rotated-credential-user-a')
            replacement.chmod(0o600)
            next_state = copy.deepcopy(payload)
            next_state['revision'] = 2
            next_state['actors'][0]['token_file'] = str(replacement)
            next_state['actors'][0]['credential_generation'] = 2
            digest = auth.access_authority.permission_digest
            auth.access_authority.update(admin, 1, next_state)
            self.assertEqual(auth.access_authority.permission_digest, digest,
                             'Permission digest must exclude credentials and credential reference paths')
            self.assertFalse(auth.access_authority.authorize(session, key('a'), 'v1', 'source:read'))
            with self.assertRaises(Exception):
                auth.access_session('Bearer synthetic-owned-credential-user-a', 'source:read')
            fresh = auth.access_session('Bearer synthetic-owned-rotated-credential-user-a', 'source:read')
            self.assertTrue(auth.access_authority.authorize(fresh, key('a'), 'v1', 'source:read'))

    def test_generation_only_rotation_invalidates_the_old_native_session(self):
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            path, payload, key = authority_fixture(Path(directory))
            auth = self.load_v2(path)
            old = auth.access_session('Bearer synthetic-owned-credential-user-a', 'source:read')
            admin = auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
            payload['revision'] = 2
            payload['actors'][0]['credential_generation'] = 2
            auth.access_authority.update(admin, 1, payload)
            self.assertFalse(auth.access_authority.authorize(old, key('a'), 'v1', 'source:read'))
            fresh = auth.access_session('Bearer synthetic-owned-credential-user-a', 'source:read')
            self.assertTrue(auth.access_authority.authorize(fresh, key('a'), 'v1', 'source:read'))

    def test_hardlinked_operator_file_is_rejected_before_reading(self):
        # Break caught: parsing a private alias before admitting operator-file custody.
        import os
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, _payload, _key = authority_fixture(root)
            os.link(path, root / 'alias')
            with patch.object(server, '_read_private_file', side_effect=AssertionError('operator bytes read')):
                with self.assertRaises(server.ServerError):
                    server.load_actors(path)

    def test_valid_credential_without_scope_keeps_forbidden_semantics(self):
        # Break caught: V2 turns a missing scope into authentication or grants it.
        from fastapi import HTTPException
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, payload, _key = authority_fixture(root)
            payload['actors'][0]['scopes'] = []
            path.write_text(json.dumps(payload))
            auth = self.load_v2(path)
            with self.assertRaises(HTTPException) as raised:
                auth.authenticate('Bearer synthetic-owned-credential-user-a', 'source:read')
            self.assertEqual(raised.exception.status_code, 403)

    def test_boot_change_and_caller_source_claims_never_restore_a_session(self):
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, _payload, key = authority_fixture(root)
            auth = self.load_v2(path)
            session = auth.access_session('Bearer synthetic-owned-credential-user-a', 'source:read')
            restarted = self.load_v2(path)
            self.assertFalse(restarted.access_authority.authorize(session, key('a'), 'v1', 'source:read'))
            forged = key('a') | {'public': True}
            self.assertFalse(auth.access_authority.authorize(session, forged, 'v1', 'source:read'))
            self.assertFalse(auth.access_authority.authorize(session, key('a'), 'stale', 'source:read'))
            self.assertFalse(auth.access_authority.authorize({'actor_id': 'user-a'}, key('a'), 'v1', 'source:read'))

    def test_two_operator_updates_cannot_publish_the_same_expected_revision(self):
        from getzilla_factory.access_authority import AccessError
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, payload, _key = authority_fixture(root)
            auth = self.load_v2(path)
            admin = auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
            payload['revision'] = 2
            def update():
                try:
                    auth.access_authority.update(admin, 1, payload)
                    return 'published'
                except AccessError:
                    return 'denied'
            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertCountEqual(pool.map(lambda _: update(), range(2)), ['published', 'denied'])

    def test_failed_durable_update_does_not_keep_the_old_protected_authority(self):
        # Break caught: a replaced but unverified private file leaves old permissions usable.
        from getzilla_factory.access_authority import AccessError
        import os
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, payload, key = authority_fixture(root)
            auth = self.load_v2(path)
            session = auth.access_session('Bearer synthetic-owned-credential-user-a', 'source:read')
            admin = auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
            payload['revision'] = 2
            native = os.fsync
            def fail_directory(descriptor):
                import stat
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    raise OSError('synthetic durability fault')
                return native(descriptor)
            with patch.object(os, 'fsync', fail_directory):
                with self.assertRaises(AccessError):
                    auth.access_authority.update(admin, 1, payload)
            self.assertFalse(auth.access_authority.authorize(session, key('a'), 'v1', 'source:read'))

    def test_loader_does_not_bind_old_rights_to_a_replaced_config(self):
        # Break caught: credentials load between two config reads publishes the old policy.
        from getzilla_factory import access_authority
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, payload, _key = authority_fixture(root)
            native = access_authority._snapshot
            def replace_after_parse(incoming):
                result = native(incoming)
                payload['revision'] = 2
                payload['groups'][0]['members'] = []
                path.write_text(json.dumps(payload))
                return result
            with patch.object(access_authority, '_snapshot', replace_after_parse):
                with self.assertRaises(server.ServerError):
                    server.load_actors(path)

    def test_changed_credential_file_cannot_keep_old_credential_session_alive(self):
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, payload, key = authority_fixture(root)
            auth = self.load_v2(path)
            session = auth.access_session('Bearer synthetic-owned-credential-user-a', 'source:read')
            Path(payload['actors'][0]['token_file']).write_text('synthetic-owned-replacement-credential')
            self.assertFalse(auth.access_authority.authorize(session, key('a'), 'v1', 'source:read'))

    def test_descriptor_link_custody_is_checked_before_private_bytes_are_read(self):
        import os
        from getzilla_factory import access_authority, settings
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, _payload, _key = authority_fixture(root)
            native_open, native_read = os.open, os.read
            reads = []
            def alias_before_open(name, *args, **kwargs):
                if name == path.name:
                    os.link(path, root / 'unexpected-alias')
                return native_open(name, *args, **kwargs)
            def observe_read(descriptor, maximum):
                reads.append(descriptor)
                return native_read(descriptor, maximum)
            with patch.object(settings.os, 'open', alias_before_open), patch.object(settings.os, 'read', observe_read):
                with self.assertRaises(access_authority.AccessError):
                    access_authority._private(path, 1_048_576)
            self.assertEqual(reads, [], 'descriptor custody must precede the first byte read')

    def test_public_loader_checks_descriptor_links_before_its_initial_json_read(self):
        import os
        from getzilla_factory import settings
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, _payload, _key = authority_fixture(root)
            native_open, native_read = os.open, os.read
            reads = []
            def alias_before_open(name, *args, **kwargs):
                if name == path.name and not (root / 'unexpected-alias').exists():
                    os.link(path, root / 'unexpected-alias')
                return native_open(name, *args, **kwargs)
            def observe_read(descriptor, maximum):
                reads.append(descriptor)
                return native_read(descriptor, maximum)
            with patch.object(settings.os, 'open', alias_before_open), patch.object(settings.os, 'read', observe_read):
                with self.assertRaises(server.ServerError):
                    server.load_actors(path)
            self.assertEqual(reads, [], 'initial JSON detection must obey descriptor custody too')

    def test_closed_v2_malformed_scalar_is_a_fixed_loader_refusal(self):
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            root = Path(directory)
            path, payload, _key = authority_fixture(root)
            payload['actors'][0]['kind'] = {'SYNTHETIC_PRIVATE': 'not-a-kind'}
            path.write_text(json.dumps(payload))
            try:
                server.load_actors(path)
            except server.ServerError as error:
                self.assertNotIn('SYNTHETIC_PRIVATE', str(error))
            except Exception:
                self.fail('Malformed operator scalar did not receive a fixed loader refusal')
            else:
                self.fail('Malformed operator scalar was accepted')

    def test_operator_handler_commits_current_revision_and_rejects_client_updates(self):
        with tempfile.TemporaryDirectory(prefix='getzilla-access150-') as directory:
            path, payload, key = authority_fixture(Path(directory))
            auth = self.load_v2(path)
            session = auth.access_session('Bearer synthetic-owned-credential-user-a', 'source:read')
            payload['revision'] = 2
            payload['groups'][0]['members'] = []
            with TestClient(create_app(FactoryService(object()), auth)) as client:
                body = {'expected_revision': 1, 'authority': payload}
                refused = client.post('/v1/access/authority', json=body,
                    headers={'Authorization': 'Bearer synthetic-owned-credential-user-a'})
                self.assertEqual(refused.status_code, 403)
                self.assertEqual(json.loads(path.read_text())['revision'], 1)
                response = client.post('/v1/access/authority', json=body,
                    headers={'Authorization': 'Bearer synthetic-owned-credential-operator'})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json(), {'revision': 2})
                self.assertFalse(auth.access_authority.authorize(session, key('a'), 'v1', 'source:read'))
                replay = client.post('/v1/access/authority', json=body,
                    headers={'Authorization': 'Bearer synthetic-owned-credential-operator'})
                self.assertEqual(replay.status_code, 409)

    def test_static_v1_actor_cannot_open_the_protected_source_channel(self):
        # Break caught: treating an ordinary authenticated Actor as current source authority.
        actor = Actor('user-a', 'client', frozenset({'source:read'}), frozenset({'repo-a'}))
        app = create_app(FactoryService(object()), Authenticator({'synthetic-local-credential-a': actor}))
        with TestClient(app) as client:
            response = client.post('/v1/access/source-read',
                headers={'Authorization': 'Bearer synthetic-local-credential-a'},
                json={'source': {'tenant': 'tenant-a', 'project': 'project-a',
                    'provider': 'local', 'site': 'site-a', 'resource': 'same-id'}, 'version': 'v1'})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('synthetic-local-credential-a', response.text)
        self.assertIn('source_authority_unavailable', response.text)


if __name__ == '__main__':
    unittest.main()
