"""Writes need exact grants and durable request identity; display checks never authorize merge."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
sys.path.insert(0, str(ROOT / '.getzilla/integrations'))
from getzilla import state
from getzilla.git_platforms import parse_remote
from getzilla_entire.client import EntireError, Repository
from getzilla_entire.process import ProcessResult
from getzilla_entire.journal import RequestJournal
from getzilla_entire.operations import EntireAdapter, assess_checks
from tests.test_entire_adapter import API, HEAD, MIRROR, REPO_ID, TRAIL_ID, URL
from tests.test_approval_resources import github_project


class GrantIdentityTests(unittest.TestCase):
    def test_real_github_dot_repository_keeps_existing_grant_binding(self):
        with github_project() as root:
            subprocess.run(['git', 'remote', 'set-url', 'origin', 'https://github.com/example/.github.git'],
                           cwd=root, check=True)
            grant = state.add_approval(root, 'production', 'fixture user authorization', 5,
                                       actions=['git-push-branch'], resources=['getzilla/task'])
            self.assertEqual(grant['repository'], 'example/.github')
            self.assertTrue(state.has_valid_approval(root, 'production', action='git-push-branch', resource='getzilla/task'))

    def test_native_mirror_and_github_grants_are_distinct(self):
        for url, expected in [(URL, URL), (MIRROR, MIRROR),
                              ('git@github.com:Team/Repo.git', 'Team/Repo')]:
            with self.subTest(url=url), mock.patch.object(state, 'git_output', return_value=url):
                self.assertEqual(state._repository_identity(ROOT), expected)

    def test_lookalike_and_secret_bearing_identity_cannot_reuse_grants(self):
        for url in ['https://evilgithub.com/Team/Repo.git', 'https://github.com.evil.test/Team/Repo',
                    'https://token:secret@github.com/Team/Repo', 'entire://evil.test/et/Team/Repo']:
            with self.subTest(url=url), mock.patch.object(state, 'git_output', return_value=url):
                with self.assertRaises(RuntimeError):
                    state._repository_identity(ROOT)

    def test_real_grant_binds_entire_mode_host_and_exact_commit(self):
        for url in (URL, MIRROR):
            with self.subTest(url=url), github_project() as root:
                subprocess.run(['git', 'remote', 'set-url', 'origin', url], cwd=root, check=True)
                resource = url + '#refs/heads/getzilla/task'
                state.add_approval(root, 'production', 'fixture user authorization', 5,
                                   actions=['git-push-branch'], resources=[resource])
                self.assertTrue(state.has_valid_approval(root, 'production', action='git-push-branch', resource=resource))
                other = MIRROR if url == URL else URL
                subprocess.run(['git', 'remote', 'set-url', 'origin', other], cwd=root, check=True)
                self.assertFalse(state.has_valid_approval(root, 'production', action='git-push-branch', resource=resource))
                subprocess.run(['git', 'remote', 'set-url', 'origin', url], cwd=root, check=True)
                subprocess.run(['git', 'commit', '--quiet', '--allow-empty', '-m', 'new exact head'], cwd=root, check=True)
                self.assertFalse(state.has_valid_approval(root, 'production', action='git-push-branch', resource=resource))


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal = RequestJournal(self.root)
        self.intent = {'operation': 'trail-create', 'repository': URL, 'head': HEAD}

    def test_duplicate_success_returns_original_without_a_second_write(self):
        self.assertIsNone(self.journal.begin('request-123', self.intent))
        result = {'status': 'created', 'trail_id': TRAIL_ID}
        self.journal.finish('request-123', self.intent, 'succeeded', result)
        self.assertEqual(self.journal.begin('request-123', self.intent), result)

    def test_crash_unknown_and_reused_key_never_retry_automatically(self):
        self.journal.begin('request-123', self.intent)
        with self.assertRaisesRegex(EntireError, 'reconcil'):
            self.journal.begin('request-123', self.intent)
        with self.assertRaises(EntireError):
            self.journal.begin('request-123', {**self.intent, 'head': 'b' * 40})
        self.journal.finish('request-123', self.intent, 'unknown', {'reason': 'timeout'})
        with self.assertRaisesRegex(EntireError, 'reconcil'):
            self.journal.begin('request-123', self.intent)

    def test_request_paths_and_linked_runtime_are_rejected(self):
        for key in ['../../outside', 'a/b', '', '*']:
            with self.subTest(key=key), self.assertRaises(EntireError):
                self.journal.begin(key, self.intent)
        with tempfile.TemporaryDirectory() as outside:
            (self.root / '.getzilla').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(EntireError):
                self.journal.begin('request-123', self.intent)
            self.assertEqual(list(Path(outside).iterdir()), [])

    def test_concurrent_request_has_exactly_one_owner(self):
        def begin(_):
            try:
                return self.journal.begin('request-123', self.intent) is None
            except EntireError:
                return False
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(begin, range(8))), 1)


class WriteGuardTests(unittest.TestCase):
    def setUp(self):
        environment = mock.patch.dict(os.environ, {key: value for key, value in os.environ.items()
                                      if not key.startswith('GIT_')}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.client = mock.Mock()
        self.repo = Repository(parse_remote(URL), REPO_ID, API, 'private', True)
        self.client.discover.return_value = self.repo
        self.client.context = 'work'
        self.client.executable.side_effect = lambda name: name
        self.authorizer = mock.Mock(return_value=True)
        self.adapter = EntireAdapter(self.root, self.client, authorize=self.authorizer)
        self.adapter.identity = mock.Mock(return_value=self.repo.identity)
        self.adapter.local_head = mock.Mock(return_value=HEAD)
        self.adapter.transport_guard = mock.Mock()
        self.adapter.remote_head = mock.Mock(return_value=HEAD)
        self.adapter.branch = mock.Mock(side_effect=lambda value: value)

    def test_push_is_exact_and_has_no_force_or_extra_refspec(self):
        result = self.adapter.push('getzilla/task', HEAD, 'request-123')
        self.assertEqual(result['status'], 'pushed')
        command = self.client.run.call_args.args[0]
        self.assertIn(f'{HEAD}:refs/heads/getzilla/task', command)
        self.assertIn(URL, command)
        self.assertNotIn('--force', command)
        self.assertIn('--no-follow-tags', command)
        self.authorizer.assert_called_with(self.root, 'production', action='git-push-branch',
                                          resource=URL + '#refs/heads/getzilla/task')

    def test_missing_grant_stale_head_and_unknown_native_permissions_refuse_writes(self):
        self.authorizer.return_value = False
        with self.assertRaises(EntireError):
            self.adapter.push('getzilla/task', HEAD, 'request-123')
        self.client.run.assert_not_called()
        self.authorizer.return_value = True
        self.adapter.local_head.return_value = 'b' * 40
        with self.assertRaises(EntireError):
            self.adapter.push('getzilla/task', HEAD, 'request-123')
        self.adapter.local_head.return_value = HEAD
        self.client.discover.return_value = Repository(self.repo.identity, REPO_ID, API, 'private', None)
        with self.assertRaises(EntireError):
            self.adapter.push('getzilla/task', HEAD, 'request-123')
        self.client.run.assert_not_called()

    def test_ambiguous_write_does_not_retry(self):
        self.client.run.side_effect = EntireError('timeout', 'timeout')
        with self.assertRaises(EntireError):
            self.adapter.push('getzilla/task', HEAD, 'request-123')
        self.client.run.reset_mock()
        with self.assertRaisesRegex(EntireError, 'reconcil'):
            self.adapter.push('getzilla/task', HEAD, 'request-123')
        self.client.run.assert_not_called()

    def test_merge_is_unsupported_even_with_grants(self):
        with self.assertRaises(EntireError) as result:
            self.adapter.merge(TRAIL_ID, HEAD)
        self.assertEqual(result.exception.code, 'unsupported')
        self.client.run.assert_not_called()
        self.client.command_json.assert_not_called()

    def test_inherited_git_override_cannot_authorize_another_checkout(self):
        with mock.patch.dict(os.environ, {'GIT_DIR': '/different/approved/checkout/.git'}):
            with self.assertRaises(EntireError) as error:
                self.adapter.push('getzilla/task', HEAD, 'request-123')
        self.assertEqual(error.exception.code, 'git_environment')
        self.authorizer.assert_not_called()
        self.client.run.assert_not_called()

    def trail(self):
        return {'id': TRAIL_ID, 'number': 42, 'projectId': '01ARZ3NDEKTSV4RRFFQ69G5FAC',
                'repoIds': [REPO_ID], 'title': 'A private title', 'status': 'open',
                'changes': [{'id': '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'repositoryId': REPO_ID,
                             'number': 7, 'branch': 'getzilla/task', 'status': 'open'}]}

    def test_create_explicitly_links_and_deduplicates_without_implicit_push(self):
        self.client.command_json.return_value = self.trail()
        result = self.adapter.create_trail('getzilla/task', 'main', 'A private title', 'body', HEAD, 'request-123')
        self.assertEqual((result['trail_number'], result['change_number']), (42, 7))
        command = self.client.command_json.call_args.args[0]
        self.assertIn('--repo', command)
        self.assertIn('et/team/repo', command)
        self.assertIn('--branch-action', command)
        self.assertIn('link', command)
        self.client.run.assert_not_called()
        self.client.command_json.reset_mock()
        again = self.adapter.create_trail('getzilla/task', 'main', 'A private title', 'body', HEAD, 'request-123')
        self.assertTrue(again['replayed'])
        self.client.command_json.assert_not_called()
        self.assertNotIn('A private title', next((self.root / '.getzilla/runtime/entire-requests').glob('*.json')).read_text())

    def test_mirror_uses_gh_namespace_without_claiming_upstream_publication(self):
        self.repo = Repository(parse_remote(MIRROR), REPO_ID, API, 'private', None)
        self.client.discover.return_value = self.repo
        self.adapter.identity.return_value = self.repo.identity
        self.client.command_json.return_value = self.trail()
        self.adapter.create_trail('getzilla/task', 'main', 'Title', '', HEAD, 'request-123')
        command = self.client.command_json.call_args.args[0]
        self.assertIn('gh/team', command)
        self.assertIn('gh/team/repo', command)
        self.assertNotIn('et/team', command)

    def test_create_refuses_unpublished_commit_and_different_processing_placement(self):
        self.adapter.remote_head.return_value = 'b' * 40
        with self.assertRaises(EntireError):
            self.adapter.create_trail('getzilla/task', 'main', 'Title', '', HEAD, 'request-123')
        self.adapter.remote_head.return_value = HEAD
        self.client.discover.side_effect = [self.repo, Repository(self.repo.identity, REPO_ID, 'https://other.entire.io', 'private', True)]
        with self.assertRaises(EntireError):
            self.adapter.create_trail('getzilla/task', 'main', 'Title', '', HEAD, 'request-456')
        self.client.command_json.assert_not_called()

    def test_checks_reads_repo_change_number_not_project_trail_number(self):
        self.client.command_json.return_value = self.trail()
        self.client.change_detail.return_value = {
            'id': '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'number': 7, 'branch': 'getzilla/task',
            'parent': {'id': TRAIL_ID}, 'mergeability': ChecksTests().snapshot(),
            'actions': {'merge': {'state': 'enabled'}}}
        result = self.adapter.checks(TRAIL_ID, HEAD)
        self.client.change_detail.assert_called_once_with(self.repo, 7)
        self.assertEqual(result['provider_preflight'], 'passed')
        self.assertFalse(result['merge_supported'])

    def test_pagination_loops_do_not_claim_a_complete_listing(self):
        summary = self.trail()
        summary.pop('changes')  # v0.12.2 list explicitly omits repository changes.
        self.client.command_json.return_value = {'items': [summary], 'nextPageToken': 'repeat'}
        with self.assertRaises(EntireError) as error:
            self.adapter.trails()
        self.assertEqual(error.exception.code, 'pagination')
        self.assertEqual(self.client.command_json.call_count, 2)

    def test_list_accepts_official_summary_without_changes(self):
        summary = self.trail()
        summary.pop('changes')
        self.client.command_json.return_value = {'items': [summary], 'nextPageToken': None}
        result = self.adapter.trails()
        self.assertTrue(result['complete'])
        self.assertEqual(result['items'][0]['trail_number'], 42)
        self.assertNotIn('change_number', result['items'][0])


class TransportPolicyTests(unittest.TestCase):
    def test_hooks_and_url_rewrites_are_preserved_and_block_automatic_push(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            hook = root / 'custom-hooks/pre-push'
            hook.parent.mkdir()
            hook.write_text('#!/bin/sh\nentire hooks git pre-push "$1"\n', encoding='utf-8')
            before = hook.read_bytes()
            client = mock.Mock()
            client.executable.side_effect = lambda name: name
            client.run.side_effect = [ProcessResult(1), ProcessResult(0, str(hook).encode())]
            adapter = EntireAdapter(root, client)
            with self.assertRaises(EntireError) as error:
                adapter.transport_guard(pushing=True)
            self.assertEqual(error.exception.code, 'hook_side_effects')
            self.assertEqual(hook.read_bytes(), before)
            client.run.side_effect = [ProcessResult(0, b'url.https://evil.test/.insteadof entire://\n')]
            with self.assertRaises(EntireError) as error:
                adapter.transport_guard()
            self.assertEqual(error.exception.code, 'url_rewrite')

    def test_fetch_is_one_ref_without_tags_submodules_or_hooks_changes(self):
        client = mock.Mock()
        client.executable.side_effect = lambda name: name
        repo = Repository(parse_remote(URL), REPO_ID, API, 'private', True)
        client.discover.return_value = repo
        adapter = EntireAdapter(ROOT, client)
        adapter.identity = mock.Mock(return_value=repo.identity)
        adapter.branch = mock.Mock(side_effect=lambda value: value)
        adapter.transport_guard = mock.Mock()
        adapter.fetch('feature/task')
        command = client.run.call_args.args[0]
        self.assertIn('--no-tags', command)
        self.assertIn('--no-recurse-submodules', command)
        self.assertEqual(command[-1], 'refs/heads/feature/task:refs/remotes/origin/feature/task')


class ChecksTests(unittest.TestCase):
    def snapshot(self):
        return {'head_sha': HEAD, 'mergeable': True, 'conflict_status': 'clean',
                'comparison_status': 'available', 'behind_by': 0,
                'checks': {'availability': 'available', 'runs': [
                    {'name': 'verify', 'status': 'completed', 'conclusion': 'success', 'app_name': 'GitHub Actions'}]},
                'gates': [{'gate_type': 'checks', 'gate_key': 'checks', 'blocking': True,
                           'status': 'passed', 'state': 'evaluated', 'head_sha': HEAD,
                           'evaluated_at_sha': HEAD, 'stale_reason': None}]}

    def test_provider_success_is_not_trusted_ci_or_merge_permission(self):
        result = assess_checks(self.snapshot(), HEAD)
        self.assertEqual(result['provider_preflight'], 'passed')
        self.assertFalse(result['trusted_ci_verified'])
        self.assertFalse(result['merge_supported'])

    def test_unknown_empty_pending_or_stale_is_not_pass(self):
        for change in [{'head_sha': 'b' * 40}, {'checks': {'availability': 'unavailable'}},
                       {'checks': {'availability': 'available', 'runs': []}}, {'gates': []},
                       {'comparison_status': 'unknown'}, {'mergeable': None}]:
            result = assess_checks({**self.snapshot(), **change}, HEAD)
            self.assertNotEqual(result['provider_preflight'], 'passed')
        for status in ['pending', 'error', 'skipped', 'approved', 'satisfied', 'unknown']:
            value = self.snapshot()
            value['gates'][0]['status'] = status
            self.assertNotEqual(assess_checks(value, HEAD)['provider_preflight'], 'passed')


if __name__ == '__main__':
    unittest.main()
