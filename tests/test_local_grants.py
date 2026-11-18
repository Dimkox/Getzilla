"""Real local Git grants retain physical repository, actor and source fences."""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))
from getzilla import state
from getzilla.router import build_route
from tests._support import activate_owned_route

TARGET = 'AGENTS.md'
TOOL = 'mcp__fixture__write_item'


class LocalGrantTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT/'.getzilla/runtime/scratch'
        parent.mkdir(parents=True, exist_ok=True)
        owned = tempfile.TemporaryDirectory(prefix='owned-local-grants-', dir=parent)
        self.addCleanup(owned.cleanup)
        self.root = Path(owned.name)
        env = patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'local-owner'})
        env.start()
        self.addCleanup(env.stop)
        state.bind_session('local-owner')
        self.addCleanup(state.bind_session, None)

    def git(self, root, *args):
        return subprocess.run(['git', *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()

    def repository(self, name='repo', *, routed=True):
        root = self.root/name
        root.mkdir()
        self.git(root, 'init', '-q', '-b', 'task')
        self.git(root, 'config', 'user.name', 'Fixture')
        self.git(root, 'config', 'user.email', 'fixture@example.invalid')
        (root/TARGET).write_text('# Owned inert fixture\n', encoding='utf-8')
        (root/'inert.py').write_text('VALUE = 1\n', encoding='utf-8')
        self.git(root, 'add', '.')
        self.git(root, 'commit', '-qm', 'fixture')
        if routed:
            activate_owned_route(root, build_route(root, 'Fix owned local fixture', 'local-owner').to_dict())
        return root

    def issue(self, root, scope='protected-path'):
        return state.add_approval(root, scope, 'explicit fixture consent', 5,
            actions=['protected-path-write' if scope == 'protected-path' else 'external-write'],
            resources=[TARGET if scope == 'protected-path' else TOOL], source='explicit-user-consent')

    def valid(self, root, scope='protected-path', **kwargs):
        return state.has_valid_approval(root, scope,
            action=kwargs.get('action', 'protected-path-write' if scope == 'protected-path' else 'external-write'),
            resource=kwargs.get('resource', TARGET if scope == 'protected-path' else TOOL))

    def test_originless_grants_preserve_exact_resources_and_source_rules(self):
        for scope in ('protected-path', 'external-write'):
            with self.subTest(scope=scope):
                root = self.repository(scope)
                grant = self.issue(root, scope)
                self.assertRegex(grant['repository'], r'^local-git-v1:[a-f0-9]{64}$')
                self.assertEqual(grant['session_id'], 'local-owner')
                self.assertTrue(self.valid(root, scope))
                self.assertFalse(self.valid(root, scope, resource='other-exact-resource'))
                (root/TARGET).write_text('# approved path edit\n', encoding='utf-8')
                self.assertEqual(self.valid(root, scope), scope == 'protected-path')
                if scope == 'protected-path':
                    self.git(root, 'add', TARGET)
                    self.git(root, 'commit', '-qm', 'approved file')
                    self.assertTrue(self.valid(root, scope))
                (root/'inert.py').write_text('VALUE = 2\n', encoding='utf-8')
                self.assertFalse(self.valid(root, scope))

    def test_missing_origin_never_grants_production_or_remote_target_authority(self):
        from getzilla._policy_legacy import _mcp_repository_problem
        root = self.repository()
        with self.assertRaises(RuntimeError):
            state.add_approval(root, 'production', 'fixture', 5,
                               actions=['git-push-branch'], resources=['task'])
        self.assertFalse(state.has_valid_approval(root, 'production', action='git-push-branch', resource='task'))
        self.assertIsNotNone(_mcp_repository_problem(root, {'owner': 'Fixture', 'repo': 'Repo'}))
        self.assertFalse(state.approvals_path(root).exists())

    def test_missing_manual_or_other_session_cannot_issue_or_replay_local_grants(self):
        root = self.repository(routed=False)
        for scope in ('protected-path', 'external-write'):
            grant = self.issue(root, scope)
            for session in (None, 'manual', 'other-owner'):
                with self.subTest(scope=scope, session=session):
                    state.bind_session(session)
                    self.assertFalse(self.valid(root, scope))
                    if session in (None, 'manual'):
                        before = state.approvals_path(root).read_bytes()
                        with self.assertRaises(ValueError):
                            self.issue(root, scope)
                        self.assertEqual(state.approvals_path(root).read_bytes(), before)
            state.bind_session('local-owner')
            grant.pop('session_id')
            state.approvals_path(root).write_text(json.dumps([grant]), encoding='utf-8')
            self.assertFalse(self.valid(root, scope))

    def test_copied_same_head_tree_and_ledger_cannot_replay_in_another_clone(self):
        root = self.repository(routed=False)
        grant = self.issue(root, 'external-write')
        other = self.root/'clone'
        self.git(self.root, 'clone', '-q', '--no-hardlinks', str(root), str(other))
        self.git(other, 'remote', 'remove', 'origin')
        self.assertEqual(self.git(root, 'rev-parse', 'HEAD'), self.git(other, 'rev-parse', 'HEAD'))
        state.approvals_path(other).write_text(json.dumps([grant]), encoding='utf-8')
        self.assertFalse(self.valid(other, 'external-write'))

    def test_linked_worktree_and_replaced_git_directory_cannot_replay(self):
        root = self.repository(routed=False)
        grant = self.issue(root, 'external-write')
        other = self.root/'linked'
        self.git(root, 'worktree', 'add', '-q', '-b', 'other', str(other))
        state.approvals_path(other).write_text(json.dumps([grant]), encoding='utf-8')
        self.assertFalse(self.valid(other, 'external-write'))
        linked = self.issue(other, 'external-write')
        self.assertNotEqual(linked['repository'], grant['repository'])
        self.assertTrue(self.valid(other, 'external-write'))
        registration = other/'.git'
        registration.chmod(registration.stat().st_mode | stat.S_IWRITE)
        registration.write_text('gitdir: ../missing\n', encoding='utf-8')
        self.assertFalse(self.valid(other, 'external-write'))
        original = root/'.git'
        moved = root/'.git-old'
        original.rename(moved)
        shutil.copytree(moved, original)
        self.assertFalse(self.valid(root, 'external-write'))

    def test_origin_changes_invalidate_and_bad_origins_never_local_fallback(self):
        root = self.repository()
        self.issue(root)
        for origin in ('', 'https://invalid.example/repo', 'https://token:secret@github.com/Fixture/Repo',
                       'https://github.com.evil.example/Fixture/Repo'):
            with self.subTest(origin=origin):
                self.git(root, 'config', '--replace-all', 'remote.origin.url', origin)
                self.assertFalse(self.valid(root))
                before = state.approvals_path(root).read_bytes()
                with self.assertRaises(RuntimeError):
                    self.issue(root)
                self.assertEqual(state.approvals_path(root).read_bytes(), before)
        self.git(root, 'config', '--add', 'remote.origin.url', '')
        with self.assertRaises(RuntimeError):
            self.issue(root)
        self.git(root, 'config', '--unset-all', 'remote.origin.url')
        self.assertTrue(self.valid(root))
        self.git(root, 'remote', 'add', 'origin', 'https://github.com/Fixture/Repo.git')
        self.assertFalse(self.valid(root))

    def test_ttl_branch_task_and_epoch_fences_remain(self):
        root = self.repository()
        grant = self.issue(root)
        grant['expires_at'] = '2000-01-01T00:00:00+00:00'
        state.approvals_path(root).write_text(json.dumps([grant]), encoding='utf-8')
        self.assertFalse(self.valid(root))
        self.issue(root)
        self.git(root, 'switch', '-qc', 'different')
        self.assertFalse(self.valid(root))
        self.git(root, 'switch', '-q', 'task')
        self.assertTrue(self.valid(root))
        for field, value in (('logical_task_id', 'task:wrong'), ('authority_epoch', 99), ('owner_session_id', 'wrong')):
            grant = self.issue(root)
            grant[field] = value
            state.approvals_path(root).write_text(json.dumps([grant]), encoding='utf-8')
            self.assertFalse(self.valid(root), field)

    def test_origin_query_error_or_ambiguous_values_cannot_establish_local_identity(self):
        from getzilla import architecture_diff
        root = self.repository()
        self.issue(root)
        run = architecture_diff._run_capped
        for code, output in ((2, b''), (0, b'\n'), (0, b'invalid\ninvalid\n')):
            def failed_query(command, **kwargs):
                if command[-3:] == ['config', '--get-all', 'remote.origin.url']:
                    return code, output, b'private diagnostic not identity'
                return run(command, **kwargs)
            with self.subTest(code=code, output=output), \
                 patch.object(architecture_diff, '_run_capped', side_effect=failed_query):
                self.assertFalse(self.valid(root))
                with self.assertRaises(RuntimeError):
                    self.issue(root)

    def test_git_registration_query_runs_with_isolated_existing_git_boundary(self):
        from getzilla import architecture_diff
        root = self.repository()
        with patch.object(architecture_diff, '_run_capped', wraps=architecture_diff._run_capped) as run:
            self.issue(root)
        query = next(call for call in run.call_args_list if call.args[0][-3:] == ['config', '--get-all', 'remote.origin.url'])
        self.assertEqual(query.kwargs['timeout'], 30)
        self.assertEqual(query.kwargs['env']['GIT_CONFIG_NOSYSTEM'], '1')
        self.assertEqual(query.kwargs['env']['GIT_CONFIG_GLOBAL'], os.devnull)
        self.assertNotIn('GIT_DIR', query.kwargs['env'])

    def test_approve_cli_materializes_both_originless_scopes_without_remote_changes(self):
        root = self.repository()
        for scope, action, resource in (('protected-path', 'protected-path-write', TARGET),
                                        ('external-write', 'external-write', TOOL)):
            result = subprocess.run([sys.executable, str(ROOT/'scripts/getzilla_approve.py'), scope,
                '--reason', 'explicit fixture owner consent', '--source', 'explicit-user-consent',
                '--action', action, '--resource', resource], cwd=root, env=os.environ.copy(),
                check=True, capture_output=True, text=True, timeout=15)
            grant = json.loads(result.stdout)
            self.assertTrue(grant['repository'].startswith('local-git-v1:'))
            self.assertFalse(grant['external_trust_ci_authority'])
            self.assertTrue(self.valid(root, scope))
        self.assertEqual(self.git(root, 'remote'), '')

    def test_broken_linked_common_directory_and_backlink_refuse(self):
        root = self.repository(routed=False)
        linked = self.root/'linked'
        self.git(root, 'worktree', 'add', '-q', '-b', 'other', str(linked))
        self.issue(linked, 'external-write')
        gitdir = Path(self.git(linked, 'rev-parse', '--absolute-git-dir'))
        for name in ('commondir', 'gitdir'):
            path = gitdir/name
            original = path.read_bytes()
            path.write_text('../missing\n', encoding='utf-8')
            try:
                self.assertFalse(self.valid(linked, 'external-write'), name)
            finally:
                path.write_bytes(original)
            self.assertTrue(self.valid(linked, 'external-write'))
