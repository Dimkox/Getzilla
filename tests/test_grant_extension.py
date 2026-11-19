"""Explicit extensions preserve the original authority and one publication intent."""
from __future__ import annotations

import inspect
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import state, util
from getzilla.component_state import BoundRoot, ComponentStateError
from tests.test_grant_lifecycle import github_project

A, B, C = 'tests/extension-a.py', 'tests/extension-b.py', 'tests/extension-c.py'


class GrantExtensionTests(unittest.TestCase):
    def parent(self, root, ttl=15):
        (root / 'tests').mkdir(exist_ok=True)
        return state.add_approval(root, 'protected-path', 'synthetic delegated A', ttl,
                                  actions=['protected-path-write'], resources=[A])

    def extend(self, root, parent, resources=(A, B), request='1' * 32, ttl=10):
        self.assertTrue(hasattr(state, 'extend_protected_path_approval'), 'explicit extension API is missing')
        with mock.patch.object(state, 'add_approval', side_effect=AssertionError('fallback mint')):
            return state.extend_protected_path_approval(root, parent['id'], request, 'synthetic delegated full set', ttl,
                                                       actions=['protected-path-write'], resources=list(resources))

    def valid(self, root, path):
        return state.has_valid_approval(root, 'protected-path', action='protected-path-write', resource=path)

    def store(self, root):
        return json.loads(state.approvals_path(root).read_bytes())

    def test_extension_keeps_original_anchor_and_replaces_parent_authority(self):
        with github_project() as root:
            parent = self.parent(root)
            (root / A).write_text('# permitted A\n')
            subprocess.run(['git', 'add', A], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'permitted A'], cwd=root, check=True)
            result = self.extend(root, parent)
            self.assertEqual(result['status'], 'created')
            child = result['grant']
            self.assertEqual(child['anchor_commit'], parent['anchor_commit'])
            self.assertEqual(child['git_head'], parent['git_head'])
            self.assertEqual(child['resources'], [A, B])
            self.assertLessEqual(datetime.fromisoformat(child['expires_at']), datetime.fromisoformat(parent['expires_at']))
            tombstone = next(row for row in self.store(root) if row['id'] == parent['id'])
            self.assertEqual(state.approval_record_kind(tombstone), 'supersession')
            self.assertNotIn('authorization', tombstone)
            (root / B).write_text('# newly permitted B\n')
            self.assertTrue(self.valid(root, A))
            self.assertTrue(self.valid(root, B))
            self.assertFalse(self.valid(root, C))

    def test_editing_new_path_before_extension_cannot_repair_parent(self):
        with github_project() as root:
            parent = self.parent(root)
            (root / B).write_text('# outside old set\n')
            before = state.approvals_path(root).read_bytes()
            with self.assertRaises(ValueError):
                self.extend(root, parent)
            self.assertEqual(state.approvals_path(root).read_bytes(), before)

    def test_chain_old_request_replay_and_pruning_never_mint_or_follow(self):
        with github_project() as root:
            parent = self.parent(root)
            child = self.extend(root, parent)['grant']
            before = state.approvals_path(root).read_bytes()
            replay = self.extend(root, parent)
            self.assertEqual(replay['status'], 'replayed')
            self.assertEqual(replay['grant']['id'], child['id'])
            self.assertEqual(state.approvals_path(root).read_bytes(), before)
            grandchild = self.extend(root, child, (A, B, C), '2' * 32)['grant']
            before = state.approvals_path(root).read_bytes()
            with self.assertRaises(ValueError):
                self.extend(root, parent)
            self.assertEqual(state.approvals_path(root).read_bytes(), before)
            rows = [row for row in self.store(root) if row['id'] == grandchild['id']]
            state.approvals_path(root).write_text(json.dumps(rows))
            with self.assertRaises(ValueError):
                self.extend(root, parent)
            self.assertEqual(len(self.store(root)), 1)

    def test_replay_conflict_and_successor_revocation_do_not_repair(self):
        with github_project() as root:
            parent = self.parent(root)
            child = self.extend(root, parent)['grant']
            with self.assertRaises(ValueError):
                self.extend(root, parent, (A, C))
            rows = [row for row in self.store(root) if row['id'] != child['id']]
            state.approvals_path(root).write_text(json.dumps(rows))
            before = state.approvals_path(root).read_bytes()
            with self.assertRaises(ValueError):
                self.extend(root, parent)
            self.assertEqual(state.approvals_path(root).read_bytes(), before)

    def test_status_only_v2_and_unknown_kind_never_authorize(self):
        with github_project() as root:
            parent = self.parent(root)
            for extra in ({'status': 'superseded'}, {'kind': 'unknown-active'}):
                state.approvals_path(root).write_text(json.dumps([{**parent, **extra}]))
                self.assertFalse(self.valid(root, A))

    def test_invalid_full_sets_and_foreign_session_leave_store_unchanged(self):
        with github_project() as root:
            parent = self.parent(root)
            before = state.approvals_path(root).read_bytes()
            for resources in ((B,), (A,), (A, '*'), (A, '../outside')):
                with self.subTest(resources=resources), self.assertRaises(ValueError):
                    self.extend(root, parent, resources)
                self.assertEqual(state.approvals_path(root).read_bytes(), before)
            state.bind_session('foreign')
            with self.assertRaises(ValueError):
                self.extend(root, parent)
            state.bind_session('s1')
            self.assertEqual(state.approvals_path(root).read_bytes(), before)

    def test_parent_removal_at_publication_preserves_foreign_store(self):
        with github_project() as root:
            parent = self.parent(root)
            original = BoundRoot.write
            foreign = b'[]\n'
            def revoke(binding, relative, content, mode, **kwargs):
                if relative.endswith('/approvals.json'):
                    state.approvals_path(root).write_bytes(foreign)
                return original(binding, relative, content, mode, **kwargs)
            with mock.patch.object(BoundRoot, 'write', revoke):
                result = self.extend(root, parent)
            self.assertEqual(result['status'], 'unknown')
            self.assertIsNone(result.get('grant'))
            self.assertEqual(state.approvals_path(root).read_bytes(), foreign)

    def test_exact_old_new_unknown_publication_failures_are_distinct(self):
        for phase in ('old', 'new', 'unknown'):
            with self.subTest(phase=phase), github_project() as root:
                parent = self.parent(root)
                before = state.approvals_path(root).read_bytes()
                original = BoundRoot.write
                def fail(binding, relative, content, mode, **kwargs):
                    if phase == 'old':
                        raise ComponentStateError('synthetic before publication')
                    original(binding, relative, content, mode, **kwargs)
                    if phase == 'unknown':
                        state.approvals_path(root).write_bytes(b'[]\n')
                    raise ComponentStateError('synthetic lost response')
                with mock.patch.object(BoundRoot, 'write', fail):
                    result = self.extend(root, parent)
                self.assertEqual(result['status'], {'old': 'refused', 'new': 'created', 'unknown': 'unknown'}[phase])
                if phase == 'old':
                    self.assertEqual(state.approvals_path(root).read_bytes(), before)
                if phase == 'unknown':
                    self.assertIsNone(result.get('grant'))

    def test_strict_fingerprint_refuses_unreadable_outside_source(self):
        self.assertIn('strict', inspect.signature(util.tree_fingerprint).parameters)
        with github_project() as root:
            (root / 'outside.py').write_text('outside\n')
            anchor = util.git_head(root)
            with mock.patch.object(util, 'file_sha256', side_effect=OSError('PRIVATE_IO')):
                with self.assertRaises(ValueError):
                    util.tree_fingerprint(root, [A], anchor=anchor, strict=True)

    def test_cli_explicit_full_set_and_replay_are_typed(self):
        with github_project() as root:
            parent = self.parent(root)
            command = [sys.executable, str(ROOT / 'scripts/getzilla_approve.py'), 'protected-path',
                       '--extend', parent['id'], '--request-id', '1' * 32,
                       '--reason', 'synthetic delegated full set', '--ttl', '10',
                       '--action', 'protected-path-write', '--resource', A, '--resource', B]
            env = {**os.environ, 'GETZILLA_SESSION_ID': 's1'}
            for status in ('created', 'replayed'):
                result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                parsed = json.loads(result.stdout)
                self.assertEqual(parsed['status'], status)
                self.assertFalse(parsed['external_trust_ci_authority'])
            before = state.approvals_path(root).read_bytes()
            for extras in (['--request-id', '3' * 32], ['--extend', parent['id']],
                           ['--extend', parent['id'], '--request-id', '4' * 32, '--profile', 'release']):
                invalid = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_approve.py'),
                                          'protected-path', '--reason', 'synthetic', '--action',
                                          'protected-path-write', '--resource', A, *extras],
                                         cwd=root, env=env, capture_output=True, text=True)
                self.assertNotEqual(invalid.returncode, 0)
                self.assertNotIn('Traceback', invalid.stderr)
                self.assertEqual(state.approvals_path(root).read_bytes(), before)

    def test_closed_history_readers_and_unsupported_rows(self):
        with github_project() as root:
            parent = self.parent(root)
            child = self.extend(root, parent)['grant']
            rows = self.store(root)
            state.approvals_path(root).write_text(json.dumps([rows[0]]))
            self.assertEqual(state.approval_mismatch(root, 'protected-path', action='protected-path-write', resource=C), '')
            state.approvals_path(root).write_text(json.dumps(rows))
            self.assertTrue(self.valid(root, B))
            tombstone = rows[0]
            for changed in ({**tombstone, 'status': 'active'}, {**tombstone, 'authorization': 'delegated-local-grant'},
                            {**tombstone, 'kind': 'future'}, {**tombstone, 'schema_version': True}):
                with self.subTest(row=changed):
                    state.approvals_path(root).write_text(json.dumps([changed, child]))
                    self.assertFalse(self.valid(root, B))
                    before = state.approvals_path(root).read_bytes()
                    with self.assertRaises(ValueError):
                        state.add_approval(root, 'protected-path', 'no reset', actions=['protected-path-write'], resources=[C])
                    self.assertEqual(state.approvals_path(root).read_bytes(), before)
            state.approvals_path(root).write_text(json.dumps([{**parent, 'status': 'superseded'}]))
            self.assertEqual(state.approval_mismatch(root, 'protected-path', action='protected-path-write', resource=A), '')

    def test_short_ttl_and_operation_time_are_exact_and_replay_does_not_refresh(self):
        with github_project() as root:
            parent = self.parent(root)
            now = datetime.now(timezone.utc) + timedelta(seconds=3)
            with mock.patch.object(state, 'datetime', wraps=datetime) as clock:
                clock.now.return_value = now
                child = self.extend(root, parent, ttl=1)['grant']
            tombstone = self.store(root)[0]
            self.assertEqual(datetime.fromisoformat(tombstone['superseded_at']), now)
            self.assertEqual(tombstone['expires_at'], parent['expires_at'])
            self.assertEqual(datetime.fromisoformat(child['expires_at']), now + timedelta(minutes=1))
            with mock.patch.object(state, 'datetime', wraps=datetime) as clock:
                clock.now.return_value = now + timedelta(minutes=2)
                with self.assertRaisesRegex(ValueError, 'EXTENSION_REPLAY_NOT_CURRENT'):
                    self.extend(root, parent, ttl=1)

    def test_expired_parent_and_branch_task_epoch_repository_changes_refuse(self):
        from getzilla.router import build_route
        from tests._support import activate_owned_route
        for change in ('expiry', 'branch', 'task', 'epoch', 'repository'):
            with self.subTest(change=change), github_project() as root:
                parent = self.parent(root)
                if change == 'expiry':
                    rows = self.store(root)
                    rows[0]['expires_at'] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
                    rows[0]['created_at'] = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
                    state.approvals_path(root).write_text(json.dumps(rows))
                elif change == 'branch':
                    subprocess.run(['git', 'checkout', '-qb', 'other'], cwd=root, check=True)
                elif change == 'task':
                    activate_owned_route(root, build_route(root, 'A separate task', 's1').to_dict())
                elif change == 'epoch':
                    rows = self.store(root)
                    rows[0]['authority_epoch'] += 1
                    state.approvals_path(root).write_text(json.dumps(rows))
                else:
                    subprocess.run(['git', 'remote', 'set-url', 'origin', 'https://github.com/other/repo'], cwd=root, check=True)
                before = state.approvals_path(root).read_bytes()
                with self.assertRaises(ValueError):
                    self.extend(root, parent)
                self.assertEqual(state.approvals_path(root).read_bytes(), before)

    def test_other_grants_do_not_union_resources_or_expiry(self):
        with github_project() as root:
            parent = self.parent(root, ttl=3)
            other = state.add_approval(root, 'protected-path', 'synthetic separate files', 30,
                                       actions=['protected-path-write'], resources=[B, C])
            child = self.extend(root, parent)['grant']
            self.assertEqual(self.store(root)[1], other)
            self.assertLessEqual(datetime.fromisoformat(child['expires_at']), datetime.fromisoformat(parent['expires_at']))
            self.assertEqual(child['resources'], [A, B])
            self.assertNotIn(C, child['resources'])

    def test_malformed_duplicate_oversized_and_linked_store_never_reset(self):
        for bad in ('duplicate', 'json', 'duplicate-key', 'oversize', 'rows', 'symlink', 'hardlink', 'directory', 'fifo'):
            with self.subTest(bad=bad), github_project() as root:
                parent = self.parent(root)
                path = state.approvals_path(root)
                if bad == 'duplicate':
                    path.write_text(json.dumps([parent, parent]))
                elif bad == 'json':
                    path.write_text('[malformed PRIVATE_PAYLOAD')
                elif bad == 'duplicate-key':
                    path.write_text('[{"id":"a","id":"b","schema_version":2}]')
                elif bad == 'oversize':
                    path.write_bytes(b' ' * 1_048_577)
                elif bad == 'rows':
                    path.write_text(json.dumps([{**parent, 'id': f'{number:016x}'} for number in range(201)]))
                elif bad == 'directory':
                    path.unlink()
                    path.mkdir()
                elif bad == 'fifo':
                    if not hasattr(os, 'mkfifo'):
                        continue
                    path.unlink()
                    os.mkfifo(path)
                else:
                    target = root / '.getzilla/runtime/synthetic-store'
                    path.rename(target)
                    if bad == 'symlink':
                        path.symlink_to(target)
                    else:
                        os.link(target, path)
                with self.assertRaisesRegex(ValueError, '^EXTENSION_STORE_UNQUALIFIED$'):
                    self.extend(root, parent)
                self.assertFalse(self.valid(root, A))

    def test_capacity_refuses_instead_of_dropping_unrelated_records(self):
        with github_project() as root:
            parent = self.parent(root)
            state.approvals_path(root).write_text(json.dumps([{**parent, 'id': f'{number:016x}'} for number in range(199)] + [parent]))
            before = state.approvals_path(root).read_bytes()
            with self.assertRaisesRegex(ValueError, 'EXTENSION_STORE_UNQUALIFIED'):
                self.extend(root, parent)
            self.assertEqual(state.approvals_path(root).read_bytes(), before)

    def test_pending_scope_and_native_handoff_cannot_extend_old_authority(self):
        from getzilla.continuity import submit
        for operation in ('pending', 'handoff'):
            with self.subTest(operation=operation), github_project() as root:
                parent = self.parent(root)
                route = state.get_active_route(root)
                if operation == 'pending':
                    submit(root, 'Also edit a newly requested feature.', 's1')
                else:
                    submit(root, '', 's2', continue_route=route['route_id'],
                           expected_epoch=route['authority_epoch'], expected_revision=route['state_revision'],
                           request_id='synthetic-handoff')
                before = state.approvals_path(root).read_bytes()
                with self.assertRaisesRegex(ValueError, 'EXTENSION_AUTHORITY_MISMATCH'):
                    self.extend(root, parent)
                self.assertEqual(state.approvals_path(root).read_bytes(), before)

    def test_input_types_limits_and_old_bindings_refuse_without_coercion(self):
        class TextLike:
            def __str__(self):
                raise AssertionError('coerced private object')
            def __eq__(self, other):
                raise AssertionError('called object hook')
        with github_project() as root:
            parent = self.parent(root)
            before = state.approvals_path(root).read_bytes()
            for kwargs in ({'ttl_minutes': True}, {'ttl_minutes': 0}, {'ttl_minutes': 1441},
                           {'reason': 'x' * 1025}, {'request_id': 'x' * 32}, {'parent_id': TextLike()},
                           {'resources': [A, TextLike()]}, {'resources': [A, 'x' * 4097]},
                           {'resources': [A] * 1025}, {'resources': [A, '%2e%2e/other']},
                           {'actions': TextLike()}, {'actions': [TextLike()]}, {'source': TextLike()}):
                request = dict(parent_id=parent['id'], request_id='1' * 32, reason='synthetic', ttl_minutes=10,
                               actions=['protected-path-write'], resources=[A, B])
                request.update(kwargs)
                with self.subTest(keys=list(kwargs)), self.assertRaises(ValueError):
                    state.extend_protected_path_approval(root, **request)
                self.assertEqual(state.approvals_path(root).read_bytes(), before)
            for fields in ({'binding': state.GRANTED_RESOURCES_BINDING}, {'schema_version': 1},
                           {'owner_session_id': None}, {'logical_task_id': None}, {'session_id': None}):
                state.approvals_path(root).write_text(json.dumps([{**parent, **fields}]))
                with self.subTest(fields=fields), self.assertRaises(ValueError):
                    self.extend(root, parent)

    def test_reason_limit_is_strict_utf8_bytes_and_refusals_do_not_write(self):
        for reason in ('a' * 1024, 'é' * 512, '€' * 341 + 'a', '🙂' * 256):
            with self.subTest(accepted_bytes=len(reason.encode('utf-8'))), github_project() as root:
                parent = self.parent(root)
                with mock.patch.object(state, 'add_approval', side_effect=AssertionError('fallback mint')):
                    result = state.extend_protected_path_approval(
                        root, parent['id'], '1' * 32, reason, 10,
                        actions=['protected-path-write'], resources=[A, B])
                self.assertEqual(result['status'], 'created')
                self.assertEqual(result['grant']['reason'], reason)
        class TextSubclass(str):
            def encode(self, *args, **kwargs):
                raise AssertionError('called text subtype hook')
        for reason in ('a' * 1025, 'é' * 513, '€' * 342, '🙂' * 257,
                       '\ud800', 'valid\udfff', TextSubclass('synthetic'), None, 42):
            with self.subTest(reason_type=type(reason).__name__), github_project() as root:
                parent = self.parent(root)
                before = state.approvals_path(root).read_bytes()
                original_write = BoundRoot.write
                with mock.patch.object(BoundRoot, 'write', autospec=True, side_effect=original_write) as writer, \
                     mock.patch.object(state, 'add_approval', side_effect=AssertionError('fallback mint')):
                    with self.assertRaises(state.GrantExtensionError) as caught:
                        state.extend_protected_path_approval(
                            root, parent['id'], '1' * 32, reason, 10,
                            actions=['protected-path-write'], resources=[A, B])
                    self.assertEqual(caught.exception.code, 'INVALID_EXTENSION_REQUEST')
                    self.assertEqual(str(caught.exception), 'INVALID_EXTENSION_REQUEST')
                    writer.assert_not_called()
                self.assertEqual(state.approvals_path(root).read_bytes(), before)

    def test_strict_fingerprint_preserves_complete_digest_and_detects_unstable_reads(self):
        with github_project() as root:
            outside = root / 'outside.py'
            outside.write_text('outside\n')
            anchor = util.git_head(root)
            self.assertEqual(util.tree_fingerprint(root, [A], anchor=anchor),
                             util.tree_fingerprint(root, [A], anchor=anchor, strict=True))
            original = util.file_sha256
            def unstable(path, **kwargs):
                result = original(path, **kwargs)
                path.write_text('changed during observation\n')
                return result
            with mock.patch.object(util, 'file_sha256', unstable), self.assertRaises(ValueError):
                util.tree_fingerprint(root, [A], anchor=anchor, strict=True)

    def test_landing_reader_accepts_history_but_rejects_status_only_authority(self):
        from contextlib import ExitStack
        from types import SimpleNamespace
        for component in ('factory/src', 'delivery/src'):
            sys.path.insert(0, str(ROOT / component))
        from scripts import getzilla_landing_publish as landing
        from getzilla_delivery.landing_publication_contracts import PublicationError
        with github_project() as root:
            parent = self.parent(root)
            self.extend(root, parent)
            history = self.store(root)
            now = datetime.now(timezone.utc)
            config = {'route_id': 'synthetic-route', 'change_id': 'synthetic-change'}
            grant = {'schema_version': 2, 'authorization': 'delegated-local-grant',
                     'repository': 'Dimkox/Getzilla', **config, 'git_head': 'a' * 40,
                     'grant_binding_digest': 'b' * 64, 'scope': 'external-write',
                     'actions': ['external-write'], 'resources': ['synthetic-tool'],
                     'source': 'explicit-user-consent', 'id': 'c' * 16,
                     'created_at': (now - timedelta(minutes=1)).isoformat(),
                     'expires_at': (now + timedelta(minutes=1)).isoformat()}
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(state, 'get_active_route', return_value=config))
                stack.enter_context(mock.patch.object(state, 'get_active_change', return_value={'change_id': config['change_id']}))
                stack.enter_context(mock.patch.object(util, 'git_head', return_value='a' * 40))
                stack.enter_context(mock.patch.object(util, 'git_output', return_value='https://github.com/Dimkox/Getzilla.git'))
                stack.enter_context(mock.patch.object(util, 'tree_fingerprint', return_value='b' * 64))
                with mock.patch.object(landing, 'read_private_file', return_value=json.dumps([*history, grant]).encode()):
                    self.assertEqual(len(landing._authority(config, root, SimpleNamespace(resource='synthetic-tool'))), 64)
                with mock.patch.object(landing, 'read_private_file', return_value=json.dumps([{**grant, 'status': 'superseded'}]).encode()):
                    with self.assertRaises(PublicationError):
                        landing._authority(config, root, SimpleNamespace(resource='synthetic-tool'))
                for unsupported in (42, None, [], {'schema_version': 99}, {**grant, 'kind': 'unknown'}):
                    for rows in ([history[0], unsupported, grant], [unsupported, history[0], grant]):
                        with self.subTest(unsupported_type=type(unsupported).__name__, history_first=rows[0] == history[0]), \
                             mock.patch.object(landing, 'read_private_file', return_value=json.dumps(rows).encode()):
                            with self.assertRaisesRegex(PublicationError, '^publication_grants$'):
                                landing._authority(config, root, SimpleNamespace(resource='synthetic-tool'))
                for rows in ([history[0], {'schema_version': 1}, grant], [{'schema_version': 1}, history[0], grant]):
                    with mock.patch.object(landing, 'read_private_file', return_value=json.dumps(rows).encode()):
                        self.assertEqual(len(landing._authority(config, root, SimpleNamespace(resource='synthetic-tool'))), 64)

    def test_conflicting_retained_links_refuse_but_pruned_history_is_not_authority(self):
        with github_project() as root:
            parent = self.parent(root)
            child = self.extend(root, parent)['grant']
            rows = self.store(root)
            rows[0]['successor_record_sha256'] = 'f' * 64
            state.approvals_path(root).write_text(json.dumps(rows))
            self.assertFalse(self.valid(root, B))
            with self.assertRaisesRegex(ValueError, 'EXTENSION_STORE_UNQUALIFIED'):
                self.extend(root, child, (A, B, C), '2' * 32)
            state.approvals_path(root).write_text(json.dumps([child]))
            self.assertTrue(self.valid(root, B))

    def test_concurrent_same_or_different_requests_have_one_publication(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        for same_request in (True, False):
            with self.subTest(same_request=same_request), github_project() as root:
                parent = self.parent(root)
                barrier = Barrier(2)
                def operation(number):
                    state.bind_session('s1')
                    barrier.wait(timeout=5)
                    try:
                        return state.extend_protected_path_approval(
                            root, parent['id'], ('1' if same_request else str(number + 1)) * 32,
                            'synthetic delegated full set', 10,
                            actions=['protected-path-write'], resources=[A, B])['status']
                    except state.GrantExtensionError as error:
                        return error.code
                    finally:
                        state.bind_session(None)
                with mock.patch.object(state, 'add_approval', side_effect=AssertionError('fallback mint')), ThreadPoolExecutor(max_workers=2) as pool:
                    outcomes = list(pool.map(operation, (0, 1)))
                self.assertEqual(outcomes.count('created'), 1)
                self.assertEqual(outcomes.count('replayed'), 1 if same_request else 0)
                self.assertEqual(len(self.store(root)), 2)

    def test_actual_publication_cuts_and_unavailable_readback(self):
        from getzilla.component_state import fsx
        for phase in ('temp-fsync', 'replace-before', 'replace-after', 'directory-fsync', 'unavailable-readback'):
            with self.subTest(phase=phase), github_project() as root:
                parent = self.parent(root)
                original_replace, original_write, original_read = fsx.replace_at, BoundRoot.write, BoundRoot.read
                before = state.approvals_path(root).read_bytes()
                written = False
                def replace(*args, **kwargs):
                    if phase == 'replace-before':
                        raise OSError('PRIVATE_FAILURE')
                    original_replace(*args, **kwargs)
                    if phase == 'replace-after':
                        raise OSError('PRIVATE_FAILURE')
                def write(*args, **kwargs):
                    nonlocal written
                    original_write(*args, **kwargs)
                    written = True
                def read(binding, relative, **kwargs):
                    if written and relative == '.getzilla/runtime/approvals.json':
                        raise ComponentStateError('PRIVATE_FAILURE')
                    return original_read(binding, relative, **kwargs)
                from contextlib import ExitStack
                with ExitStack() as stack:
                    if phase == 'temp-fsync':
                        stack.enter_context(mock.patch.object(os, 'fsync', side_effect=OSError('PRIVATE_FAILURE')))
                    elif phase.startswith('replace-'):
                        stack.enter_context(mock.patch.object(fsx, 'replace_at', replace))
                    elif phase == 'directory-fsync':
                        stack.enter_context(mock.patch.object(fsx, 'fsync_dir', side_effect=OSError('PRIVATE_FAILURE')))
                    else:
                        stack.enter_context(mock.patch.object(BoundRoot, 'write', write))
                        stack.enter_context(mock.patch.object(BoundRoot, 'read', read))
                    result = self.extend(root, parent)
                expected = {'temp-fsync': 'refused', 'replace-before': 'refused', 'replace-after': 'created',
                            'directory-fsync': 'created', 'unavailable-readback': 'unknown'}[phase]
                self.assertEqual(result['status'], expected)
                self.assertNotIn('PRIVATE_FAILURE', json.dumps(result))
                if expected == 'refused':
                    self.assertEqual(state.approvals_path(root).read_bytes(), before)
                if expected == 'unknown':
                    self.assertIsNone(result['grant'])
                    self.assertTrue(result['inspection_required'])
                    self.assertFalse(result['retryable'])
                self.assertEqual(list((root / '.getzilla/runtime').glob('.getzilla-component-*.tmp')), [])

    def test_lock_refusal_is_typed_and_private_details_do_not_escape(self):
        from contextlib import contextmanager
        @contextmanager
        def refused_lock(*args, **kwargs):
            raise ValueError('PRIVATE_LOCK_FAILURE')
            yield
        with github_project() as root:
            parent = self.parent(root)
            with mock.patch.object(state, 'runtime_lock', refused_lock):
                with self.assertRaisesRegex(ValueError, '^EXTENSION_STORE_UNQUALIFIED$'):
                    self.extend(root, parent)

    def test_source_or_context_change_at_callback_never_returns_authority(self):
        for change in ('source-before', 'source-after', 'successor-revoke', 'replay-revoke'):
            with self.subTest(change=change), github_project() as root:
                parent = self.parent(root)
                before = state.approvals_path(root).read_bytes()
                original = BoundRoot.write
                def change_write(binding, relative, content, mode, **kwargs):
                    if change == 'source-before':
                        (root / C).write_text('# outside old and combined\n')
                    original(binding, relative, content, mode, **kwargs)
                    if change == 'source-after':
                        (root / C).write_text('# outside after replace\n')
                    elif change == 'successor-revoke':
                        state.approvals_path(root).write_text('[]\n')
                with mock.patch.object(BoundRoot, 'write', change_write):
                    result = self.extend(root, parent)
                if change == 'source-before':
                    self.assertEqual(result['status'], 'refused')
                    self.assertEqual(state.approvals_path(root).read_bytes(), before)
                elif change == 'source-after':
                    self.assertEqual(result['status'], 'committed_not_current')
                elif change == 'successor-revoke':
                    self.assertEqual(result['status'], 'unknown')
                else:
                    original_read = BoundRoot.read
                    count = 0
                    def revoke_read(binding, relative, **kwargs):
                        nonlocal count
                        if relative == '.getzilla/runtime/approvals.json':
                            count += 1
                            if count == 2:
                                state.approvals_path(root).write_text('[]\n')
                        return original_read(binding, relative, **kwargs)
                    with mock.patch.object(BoundRoot, 'read', revoke_read), self.assertRaisesRegex(ValueError, 'EXTENSION_REPLAY_NOT_CURRENT'):
                        self.extend(root, parent)
                if change != 'replay-revoke':
                    self.assertIsNone(result.get('grant'))


if __name__ == '__main__':
    unittest.main()
