from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.policy import WRITE_ROLES, evaluate_pre_tool, production_action, write_roles
from getzilla.router import build_route
from getzilla.state import (
    add_approval,
    approvals_path,
    has_valid_approval,
    record_agent_start,
    set_active_route,
)
from tests._support import project_copy


@contextlib.contextmanager
def github_project() -> Iterator[Path]:
    with project_copy(git=True) as root:
        subprocess.run(
            ['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'],
            cwd=root,
            check=True,
        )
        route = build_route(root, 'Исправить PHP баг', 's1').to_dict()
        set_active_route(root, route)
        yield root


class PolicyTests(unittest.TestCase):
    def test_new_grant_uses_neutral_binding_digest_key(self) -> None:
        with github_project() as root:
            approval = add_approval(
                root,
                'production',
                'ship',
                5,
                actions=['git-push-branch'],
            )

            self.assertIn('grant_binding_digest', approval)
            self.assertNotIn('tree_fingerprint', approval)
            self.assertNotIn('authorization_tree_fingerprint', json.dumps(approval))

    def test_legacy_tree_fingerprint_grant_remains_valid(self) -> None:
        with github_project() as root:
            approval = add_approval(
                root,
                'production',
                'ship',
                5,
                actions=['git-push-branch'],
            )
            approval['tree_fingerprint'] = approval.pop('grant_binding_digest')
            approvals_path(root).write_text(json.dumps([approval]), encoding='utf-8')

            self.assertTrue(
                has_valid_approval(
                    root,
                    'production',
                    action='git-push-branch',
                )
            )

    def test_conflicting_grant_binding_fields_fail_closed(self) -> None:
        with github_project() as root:
            approval = add_approval(
                root,
                'production',
                'ship',
                5,
                actions=['git-push-branch'],
            )
            approval['tree_fingerprint'] = '0' * 64
            approvals_path(root).write_text(json.dumps([approval]), encoding='utf-8')

            self.assertFalse(
                has_valid_approval(
                    root,
                    'production',
                    action='git-push-branch',
                )
            )

    def test_blocks_destructive_git(self) -> None:
        with project_copy() as root:
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': 'git reset --hard HEAD~1'}})
            self.assertFalse(allowed)
            self.assertIn('destructive', reason or '')

    def test_allows_normal_test_command(self) -> None:
        with project_copy() as root:
            allowed, _ = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': 'php -l local/test.php'}})
            self.assertTrue(allowed)

    def test_production_action_classifier_distinguishes_branch_tag_and_release(self) -> None:
        self.assertEqual(production_action('git push origin feature'), 'git-push-branch')
        self.assertEqual(production_action('git push origin v2.1.0'), 'git-push-tag')
        self.assertEqual(production_action("bash -lc 'gh release create v2.1.0'"), 'github-release')
        self.assertEqual(production_action('gh workflow run release.yml'), 'workflow-dispatch')
        self.assertEqual(production_action('git -C nested push origin feature'), 'git-push-branch')
        self.assertEqual(production_action('git -C nested push origin v2.1.0'), 'git-push-tag')
        self.assertEqual(production_action('git --git-dir=../repo/.git push origin feature'), 'git-push-branch')
        for command in (
            'sudo -E git push origin feature',
            'doas -u root git push origin feature',
            'env GIT_DIR=../repo/.git git push origin feature',
            '/usr/bin/git push origin feature',
            "bash --noprofile -lc 'git push origin feature'",
        ):
            self.assertEqual(production_action(command), 'git-push-branch', command)

    def test_blocks_production_side_effect_without_grant(self) -> None:
        with github_project() as root:
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': 'git push origin feature'}})
            self.assertFalse(allowed)
            self.assertIn('git-push-branch', reason or '')

    def test_exact_action_grant_allows_only_that_action(self) -> None:
        with github_project() as root:
            add_approval(root, 'production', 'standing release consent', 5, actions=['git-push-branch'], resources=['feature'])
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': 'git push origin feature'}})
            self.assertTrue(allowed, reason)
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': 'git push origin v2.1.0'}})
            self.assertFalse(allowed)
            self.assertIn('git-push-tag', reason or '')

    def test_grant_is_invalid_after_tree_change(self) -> None:
        with github_project() as root:
            add_approval(root, 'production', 'ship', 5, actions=['git-push-branch'], resources=['feature'])
            (root / 'AGENTS.md').write_text('changed\n', encoding='utf-8')
            allowed, _ = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': 'git push origin feature'}})
            self.assertFalse(allowed)

    def test_grant_is_invalid_after_new_commit(self) -> None:
        with github_project() as root:
            add_approval(root, 'production', 'ship', 5, actions=['git-push-branch'], resources=['feature'])
            (root / 'new.txt').write_text('new\n', encoding='utf-8')
            subprocess.run(['git', 'add', 'new.txt'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'new'], cwd=root, check=True)
            allowed, _ = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': 'git push origin feature'}})
            self.assertFalse(allowed)

    def test_workflow_dispatch_is_forbidden_even_with_production_grant(self) -> None:
        with github_project() as root:
            add_approval(root, 'production', 'ship', 5, actions=['git-push-branch'], resources=['feature'])
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': 'gh workflow run release.yml'}})
            self.assertFalse(allowed)
            self.assertIn('forbidden', (reason or '').lower())

    def test_path_text_and_echo_are_not_side_effects(self) -> None:
        with project_copy() as root:
            for command in (
                'ls engineering/changes/20260814-publish-v2-0-3/release.md',
                'echo production deploy release publish',
                'cat engineering/changes/demo/release.md',
            ):
                allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})
                self.assertTrue(allowed, (command, reason))

    def test_approve_cli_invocation_is_not_itself_blocked(self) -> None:
        with project_copy() as root:
            allowed, reason = evaluate_pre_tool(root, {
                'tool_name': 'Bash',
                'tool_input': {'command': 'python3 scripts/getzilla_approve.py production --profile release --reason "ship"'},
            })
            self.assertTrue(allowed, reason)

    def test_wrapped_shell_push_requires_matching_grant(self) -> None:
        with github_project() as root:
            command = "bash -lc 'cd dist && git push origin feature'"
            allowed, _ = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})
            self.assertFalse(allowed)
            add_approval(root, 'production', 'ship', 5, actions=['git-push-branch'], resources=['feature'])
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})
            self.assertTrue(allowed, reason)

    def test_direct_http_write_requires_resource_bound_external_grant(self) -> None:
        with github_project() as root:
            command = 'curl -X POST https://api.github.com/repos/Dimkox/Getzilla/issues -d "{}"'
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})
            self.assertFalse(allowed)
            self.assertIn('api.github.com', reason or '')
            add_approval(
                root,
                'external-write',
                'create issue',
                5,
                actions=['external-write'],
                resources=['https://api.github.com/repos/Dimkox/Getzilla/issues'],
            )
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})
            self.assertTrue(allowed, reason)

    def test_blocks_secret_read(self) -> None:
        with project_copy() as root:
            (root / 'config').mkdir()
            (root / 'config/.env').write_text('SECRET=x')
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Read', 'tool_input': {'path': 'config/.env'}})
            self.assertFalse(allowed)
            self.assertIn('secret', (reason or '').lower())

    def test_blocks_write_outside_repository(self) -> None:
        with project_copy() as root:
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Write', 'tool_input': {'path': '../outside.txt'}})
            self.assertFalse(allowed)
            self.assertIn('outside', reason or '')

    def test_protected_path_requires_exact_resource_grant(self) -> None:
        with github_project() as root:
            target = '.getzilla/getzilla/policy.py'
            allowed, _ = evaluate_pre_tool(root, {'tool_name': 'Write', 'tool_input': {'path': target}})
            self.assertFalse(allowed)
            add_approval(
                root,
                'protected-path',
                'reviewed policy edit',
                5,
                actions=['protected-path-write'],
                resources=['.getzilla/getzilla/policy.py'],
            )
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Write', 'tool_input': {'path': target}})
            self.assertTrue(allowed, reason)
            allowed, _ = evaluate_pre_tool(root, {'tool_name': 'Write', 'tool_input': {'path': 'AGENTS.md'}})
            self.assertFalse(allowed)

    def test_control_plane_shell_mutation_is_blocked_even_with_path_grant(self) -> None:
        with github_project() as root:
            add_approval(
                root,
                'protected-path',
                'reviewed edit',
                5,
                actions=['protected-path-write'],
                resources=['AGENTS.md'],
            )
            allowed, reason = evaluate_pre_tool(root, {
                'tool_name': 'Bash',
                'tool_input': {'command': "printf x >> AGENTS.md"},
            })
            self.assertFalse(allowed)
            self.assertIn('structured write', reason or '')

    def test_allows_local_bitrix_edit(self) -> None:
        with project_copy() as root:
            allowed, _ = evaluate_pre_tool(root, {'tool_name': 'Write', 'tool_input': {'path': 'local/modules/acme.demo/lib/Test.php'}})
            self.assertTrue(allowed)

    def test_blocks_agent_outside_route_and_allows_selected_writer(self) -> None:
        with project_copy() as root:
            route = build_route(root, 'Исправить PHP баг', 's1').to_dict()
            set_active_route(root, route)
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Agent', 'tool_input': {'agent_type': 'ai_implementer'}})
            self.assertFalse(allowed)
            self.assertIn('outside active route', reason or '')
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Agent', 'tool_input': {'agent_type': route['write_agent']}})
            self.assertTrue(allowed, reason)

    def test_routing_write_roles_match_constant_and_fallback(self) -> None:
        with project_copy() as root:
            self.assertEqual(write_roles(root), set(WRITE_ROLES))
            (root / '.getzilla/config/routing.json').unlink()
            self.assertEqual(write_roles(root), set(WRITE_ROLES))
            (root / '.getzilla/config/routing.json').write_text('{', encoding='utf-8')
            self.assertEqual(write_roles(root), set(WRITE_ROLES))

    def test_blocks_second_different_write_agent(self) -> None:
        with project_copy() as root:
            route = build_route(root, 'Исправить PHP баг', 's1').to_dict()
            route['allowed_agents'].append('general_implementer')
            set_active_route(root, route)
            record_agent_start(root, 'a1', route['write_agent'])
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Agent', 'tool_input': {'agent_type': 'general_implementer'}})
            self.assertFalse(allowed)
            self.assertTrue('write owner' in (reason or '') or 'already active' in (reason or ''))

    def test_blocks_second_same_role_writer(self) -> None:
        with project_copy() as root:
            route = build_route(root, 'Fix a PHP bug', 's1').to_dict()
            set_active_route(root, route)
            record_agent_start(root, 'first-writer', route['write_agent'])
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Agent',
                'tool_input': {'agent_type': route['write_agent']}})
            self.assertFalse(allowed)
            self.assertIn('already active', reason or '')

    def test_mcp_write_requires_tool_bound_external_grant(self) -> None:
        tool = 'mcp__github__create_issue'
        with github_project() as root:
            allowed, _ = evaluate_pre_tool(root, {'tool_name': tool, 'tool_input': {'title': 'x'}})
            self.assertFalse(allowed)
            add_approval(
                root,
                'external-write',
                'create issue',
                5,
                actions=['external-write'],
                resources=[tool],
            )
            allowed, reason = evaluate_pre_tool(root, {'tool_name': tool, 'tool_input': {'title': 'x'}})
            self.assertTrue(allowed, reason)
            allowed, _ = evaluate_pre_tool(root, {'tool_name': 'mcp__github__delete_issue', 'tool_input': {'id': 1}})
            self.assertFalse(allowed)

    def test_every_github_write_tool_needs_a_grant_and_reads_do_not(self) -> None:
        # These names carry the write verb inside the name and used to pass with no grant (#193).
        from getzilla.policy import mcp_side_effect, sensitive_action
        writes = ('issue_write', 'sub_issue_write', 'pull_request_review_write', 'add_issue_comment',
                  'add_reply_to_pull_request_comment', 'add_comment_to_pending_review', 'push_files',
                  'resolve_review_thread', 'unresolve_review_thread', 'enable_pr_auto_merge',
                  'disable_pr_auto_merge', 'fork_repository', 'request_copilot_review', 'actions_run_trigger',
                  'create_issue', 'update_issue_comment', 'merge_pull_request', 'create_or_update_file',
                  # Not on the verb list: a GitHub server fails closed for any tool that is not a known read.
                  'run_workflow', 'manage_notification_subscription', 'star_repository', 'unstar_repository',
                  'reprioritize_sub_issue', 'mark_all_notifications_read', 'some_future_tool')
        reads = ('get_me', 'issue_read', 'list_issues', 'search_issues', 'pull_request_read', 'get_check_run',
                 'get_job_logs', 'actions_get', 'actions_list', 'list_branches', 'get_file_contents',
                 'run_secret_scanning', 'search_code', 'projects_list', 'download_workflow_run_artifact',
                 'list_starred_repositories')
        with github_project() as root:
            for server in ('github', 'plugin_github_github', 'GitHub'):
                for name in writes:
                    tool = f'mcp__{server}__{name}'
                    with self.subTest(tool=tool):
                        self.assertTrue(mcp_side_effect(tool))
                        self.assertEqual(sensitive_action(root, {'tool_name': tool, 'tool_input': {}}),
                                         'external-write')
                        allowed, reason = evaluate_pre_tool(root, {'tool_name': tool, 'tool_input': {}})
                        self.assertFalse(allowed)
                        self.assertIn('external-write grant', reason or '')
                for name in reads:
                    with self.subTest(tool=f'mcp__{server}__{name}'):
                        self.assertFalse(mcp_side_effect(f'mcp__{server}__{name}'))

    def test_camel_case_and_hyphen_write_tools_need_a_grant(self) -> None:
        from getzilla.policy import mcp_side_effect
        writes = ('mcp__Atlassian_MCP__executeWrite', 'mcp__Atlassian_MCP__executeDestructive',
                  'mcp__Atlassian_MCP__createJiraIssue', 'mcp__Atlassian_MCP__editJiraIssue',
                  'mcp__Atlassian_MCP__addCommentToJiraIssue', 'mcp__Atlassian_MCP__transitionJiraIssue',
                  'mcp__Atlassian_MCP__updateConfluencePage', 'mcp__Google_Docs__batchUpdate',
                  'mcp__Ahrefs__management-projects-create', 'mcp__Ahrefs__management-project-keywords-delete',
                  'mcp__Ahrefs__social-media-post-update', 'mcp__claude-code-remote__set_session_tags',
                  'mcp__claude-code-remote__add_repo', 'mcp__Gmail__label_message', 'mcp__x__runJob',
                  'mcp__x__page_write', 'mcp__x__records-write', 'mcp__gh__actions_run_trigger',
                  'mcp__x__delete__file', 'mcp__a__github__create_issue',
                  # Every server fails closed (#195): a verb inside a word, after the first token, off
                  # any list, or no read verb at all is a write.
                  'mcp__x__bulkCreate', 'mcp__x__doWrite', 'mcp__x__createissue', 'mcp__x__issue_create',
                  'mcp__x__page_update', 'mcp__x__modify_record', 'mcp__x__pay_invoice', 'mcp__x__refund_order',
                  'mcp__x__get_or_create_user', 'mcp__x__list_and_delete', 'mcp__Ahrefs__site-explorer-metrics',
                  'mcp__Ahrefs__management-projects', 'mcp__x__updatedSince', 'mcp__x__createdAt',
                  'mcp__slack-post__message', 'mcp__x__')
        reads = ('mcp__Atlassian_MCP__getJiraIssue', 'mcp__Atlassian_MCP__searchConfluence',
                 'mcp__Atlassian_MCP__atlassianUserInfo', 'mcp__Atlassian_MCP__executeRead',
                 'mcp__claude-code-remote__get_session', 'mcp__claude-code-remote__read_documentation',
                 'mcp__claude-code-remote__list_sessions', 'mcp__Gmail__search_threads',
                 'mcp__cloud-run__get_service', 'mcp__x-post__list_items', 'mcp__Claude_Docs__query',
                 'mcp__x__fetchPage', 'mcp__x__describe-table', 'mcp__x__records_lookup', 'Bash', 'Edit')
        for tool in writes:
            with self.subTest(tool=tool):
                self.assertTrue(mcp_side_effect(tool))
        for tool in reads:
            with self.subTest(tool=tool):
                self.assertFalse(mcp_side_effect(tool))

    def test_a_project_can_name_its_own_read_tools_exactly(self) -> None:
        from getzilla.policy import mcp_side_effect
        with github_project() as root:
            tool = 'mcp__Ahrefs__site-explorer-metrics'
            self.assertTrue(mcp_side_effect(tool, root))
            config_path = root / '.getzilla/config/policy.json'
            config = json.loads(config_path.read_text(encoding='utf-8'))
            config['mcp_read_tools'] = {'Ahrefs': ['site-explorer-metrics']}
            config_path.write_text(json.dumps(config), encoding='utf-8')
            self.assertFalse(mcp_side_effect(tool, root))
            self.assertTrue(mcp_side_effect('mcp__Ahrefs__management-projects-create', root))
            self.assertTrue(mcp_side_effect('mcp__Other__site-explorer-metrics', root))
            allowed, reason = evaluate_pre_tool(root, {'tool_name': tool, 'tool_input': {}})
            self.assertTrue(allowed, reason)

    def test_github_write_grants_bind_to_the_local_repository(self) -> None:
        # A grant names only the tool; the call's owner/repo must be the repository it binds (#184).
        tool = 'mcp__github__issue_write'
        with github_project() as root:
            add_approval(root, 'external-write', 'own issue', 5, actions=['external-write'], resources=[tool])
            for target in ({'owner': 'Dimkox', 'repo': 'Getzilla'}, {'owner': 'dimkox', 'repo': 'getzilla'}, {}):
                with self.subTest(target=target):
                    allowed, reason = evaluate_pre_tool(root, {'tool_name': tool,
                                                               'tool_input': {'method': 'create', **target}})
                    self.assertTrue(allowed, reason)
            for target in ({'owner': 'Dimkox', 'repo': 'Other'}, {'owner': 'someone', 'repo': 'Getzilla'},
                           {'owner': 'Dimkox'}, {'repo': 'Getzilla'}, {'owner': 'Dimkox', 'repo': ''},
                           {'owner': ['Dimkox'], 'repo': 'Getzilla'}, {'owner': 'Dimkox/Getzilla', 'repo': ''},
                           {'owner': 'Dimkox ', 'repo': 'Getzilla'}, {'owner': 'Dimkox', 'repo': 'Getzilla/x'},
                           # U+212A KELVIN SIGN lowercases to an ASCII k: only the ASCII name check refuses it.
                           {'owner': 'DimKox', 'repo': 'Getzilla'}):
                with self.subTest(target=target):
                    allowed, reason = evaluate_pre_tool(root, {'tool_name': tool,
                                                               'tool_input': {'method': 'create', **target}})
                    self.assertFalse(allowed)
                    self.assertIn('refused', reason or '')
            # A renamed GitHub server is bound the same way; another server's owner/repo keys are not GitHub targets.
            renamed = 'mcp__plugin_github_github__issue_write'
            add_approval(root, 'external-write', 'renamed server', 5, actions=['external-write'], resources=[renamed])
            allowed, reason = evaluate_pre_tool(root, {'tool_name': renamed,
                                                       'tool_input': {'owner': 'other', 'repo': 'project'}})
            self.assertFalse(allowed)
            self.assertIn('refused', reason or '')
            other = 'mcp__claude-code-remote__add_repo'
            add_approval(root, 'external-write', 'add repo', 5, actions=['external-write'], resources=[other])
            allowed, reason = evaluate_pre_tool(root, {'tool_name': other,
                                                       'tool_input': {'owner': 'other', 'repo': 'project'}})
            self.assertTrue(allowed, reason)
        with project_copy(git=True) as root:
            set_active_route(root, build_route(root, 'Исправить PHP баг', 's1').to_dict())
            allowed, reason = evaluate_pre_tool(root, {'tool_name': tool,
                                                       'tool_input': {'owner': 'Dimkox', 'repo': 'Getzilla'}})
            self.assertFalse(allowed)
            self.assertIn('no GitHub origin', reason or '')


if __name__ == '__main__':
    unittest.main()
