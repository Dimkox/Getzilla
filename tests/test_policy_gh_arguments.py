"""Offline gh policy controls. These tests never execute a gh command."""
from __future__ import annotations

import contextlib
import os
import shlex
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla._policy_legacy import _http_write_resource, analyze_command_authority, production_targets  # noqa: E402
from getzilla.policy import evaluate_pre_tool, sensitive_action  # noqa: E402
from getzilla.router import build_route  # noqa: E402
from getzilla.state import add_approval, approvals_path
from tests._support import activate_owned_route
from tests._support import project_copy, run_hook  # noqa: E402


class GhArgumentPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.stack = contextlib.ExitStack()
        cls.root = cls.stack.enter_context(project_copy(git=True))
        subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'],
                       cwd=cls.root, check=True)
        activate_owned_route(cls.root, build_route(cls.root, 'Offline argument fixture', 'gh-arguments').to_dict())
        (cls.root / '.env').write_text('SYNTHETIC_TEST_VALUE=fixture\n', encoding='utf-8')
        (cls.root / '.env.example').write_text('PUBLIC_TEMPLATE=fixture\n', encoding='utf-8')
        (cls.root / 'body.md').write_text('Public fixture\n', encoding='utf-8')

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stack.close()

    def setUp(self) -> None:
        approvals_path(self.root).write_text('[]', encoding='utf-8')

    def grant(self, resource: str, *, production: bool = False) -> None:
        add_approval(self.root, 'production' if production else 'external-write', 'offline fixture', 5,
                     actions=['pull-request-merge' if production else 'external-write'], resources=[resource])

    def verdict(self, command: str) -> tuple[bool, str | None]:
        return evaluate_pre_tool(self.root, {'tool_name': 'Bash', 'tool_input': {'command': command}})

    def hook_verdict(self, command: str) -> dict:
        code, result, error = run_hook(self.root, 'pre_tool_use.py', {
            'cwd': str(self.root), 'session_id': 'gh-arguments',
            'tool_name': 'Bash',
            'tool_input': {'command': command},
        })
        self.assertEqual(code, 0, error)
        return result

    def test_repo_spellings_preserve_exact_resource_and_grant(self) -> None:
        self.grant('gh:dimkox/getzilla pr create')
        for selector in ('-R Dimkox/Getzilla', '-RDimkox/Getzilla', '-R=Dimkox/Getzilla',
                         '--repo Dimkox/Getzilla', '--repo=Dimkox/Getzilla'):
            for prefix in (f'gh {selector} pr create', f'gh pr create {selector}'):
                command = f'{prefix} --head feature --title Fixture --body body'
                with self.subTest(command=command):
                    self.assertEqual(_http_write_resource(command, self.root), 'gh:dimkox/getzilla pr create')
                    allowed, reason = self.verdict(command)
                    self.assertTrue(allowed, reason)

    def test_quoted_option_values_do_not_select_a_repository(self) -> None:
        self.grant('gh:dimkox/getzilla pr create')
        for option in ('--body', '-b', '--title', '-t'):
            for value in ('-Rother/project', '--repo=other/project', '--repo', '--hostname=other.example'):
                command = f'gh pr create {option} "{value}" --repo Dimkox/Getzilla --head feature'
                with self.subTest(command=command):
                    self.assertEqual(_http_write_resource(command, self.root), 'gh:dimkox/getzilla pr create')
                    allowed, reason = self.verdict(command)
                    self.assertTrue(allowed, reason)

    def test_quoted_selector_data_cannot_use_the_wrong_grant(self) -> None:
        self.grant('gh:other/project pr create')
        command = 'gh pr create --body "-Rother/project" --title Fixture --repo Dimkox/Getzilla --head feature'
        allowed, reason = self.verdict(command)
        self.assertFalse(allowed)
        self.assertIn('gh:dimkox/getzilla pr create', reason or '')

    def test_body_file_spellings_cannot_read_secret_material(self) -> None:
        self.grant('gh:dimkox/getzilla pr create')
        for option in ('-F .env', '-F.env', '-F=.env', '-F".env"', '--body-file .env', '--body-file=.env'):
            command = f'gh pr create --repo Dimkox/Getzilla --head feature --title Fixture {option}'
            with self.subTest(command=command):
                allowed, reason = self.verdict(command)
                self.assertFalse(allowed)
                self.assertIn('secret', reason or '')

    def test_public_body_files_stay_usable_with_exact_grants(self) -> None:
        self.grant('gh:dimkox/getzilla pr create')
        for operand in ('body.md', '.env.example'):
            for option in (f'-F {operand}', f'-F{operand}', f'-F={operand}', f'--body-file={operand}'):
                command = f'gh pr create -R Dimkox/Getzilla --head feature --title Fixture {option}'
                with self.subTest(command=command):
                    allowed, reason = self.verdict(command)
                    self.assertTrue(allowed, reason)

    def test_body_text_is_not_a_secret_file_operand(self) -> None:
        self.grant('gh:dimkox/getzilla pr create')
        for value in ('-F.env', '--body-file .env', '.env', '--repo other/project'):
            command = f"gh pr create --repo Dimkox/Getzilla --head feature --title Fixture --body '{value}'"
            with self.subTest(command=command):
                self.assertEqual(_http_write_resource(command, self.root), 'gh:dimkox/getzilla pr create')
                allowed, reason = self.verdict(command)
                self.assertTrue(allowed, reason)

    def test_literal_text_does_not_remove_the_grant_requirement(self) -> None:
        for value in ('$literal', '-Rother/project', '--repo'):
            command = f"gh pr create --repo Dimkox/Getzilla --head feature --title Fixture --body '{value}'"
            with self.subTest(command=command):
                self.assertFalse(self.verdict(command)[0])

    def test_unresolved_shell_words_are_not_authorized_by_a_static_grant(self) -> None:
        self.grant('gh:dimkox/getzilla pr create')
        for value in ('$BODY', '"$BODY"'):
            with self.subTest(value=value):
                self.assertFalse(self.verdict(f'gh pr create --repo Dimkox/Getzilla --body {value}')[0])

    def test_unknown_options_before_the_subcommand_do_not_hide_a_write(self) -> None:
        for group in ('pr', 'issue'):
            command = f'gh {group} --body view create --repo Dimkox/Getzilla --title Fixture'
            with self.subTest(command=command):
                self.assertFalse(self.verdict(command)[0])

    def test_create_aliases_keep_body_file_protection(self) -> None:
        for group in ('pr', 'issue'):
            self.setUp()
            self.grant(f'gh:dimkox/getzilla {group} new')
            command = f'gh {group} new -R Dimkox/Getzilla --title Fixture -b "-Rother/project"'
            with self.subTest(command=command):
                allowed, reason = self.verdict(command)
                self.assertTrue(allowed, reason)
                allowed, reason = self.verdict(f'gh {group} new --repo Dimkox/Getzilla --title Fixture -F.env')
                self.assertFalse(allowed)
                self.assertIn('secret', reason or '')

    def test_ambiguous_or_unknown_targeting_is_denied_with_a_grant(self) -> None:
        self.grant('gh:dimkox/getzilla pr create')
        for tail in ('--repo Other/Project', '-R Dimkox/Getzilla', '--repo', '--repo=',
                     '--unknown-option', '-dRother/project', '-- --repo=Other/Project',
                     '--body one --body-file body.md', '--body-file body.md -F body.md'):
            command = f'gh pr create --repo Dimkox/Getzilla --head feature --title Fixture {tail}'
            with self.subTest(command=command):
                self.assertFalse(self.verdict(command)[0])
        for selector in ('--repo "$TARGET"', '--repo "$OWNER/$REPO"', '--repo /', '--repo ""'):
            with self.subTest(selector=selector):
                self.assertFalse(self.verdict(f'gh pr create {selector} --head feature --fill')[0])

    def test_issue_body_and_repo_are_separate_operands(self) -> None:
        self.grant('gh:dimkox/getzilla issue create')
        command = 'gh issue create -R Dimkox/Getzilla --title Fixture -b "-Rother/project"'
        allowed, reason = self.verdict(command)
        self.assertTrue(allowed, reason)
        self.assertFalse(self.verdict('gh issue create --repo Dimkox/Getzilla --title Fixture -F.env')[0])

    def test_edit_and_comment_share_only_their_body_file_roles(self) -> None:
        for group in ('pr', 'issue'):
            for verb in ('edit', 'comment'):
                self.setUp()
                self.grant(f'gh:dimkox/getzilla {group} {verb} 5')
                command = f'gh {group} {verb} 5 -R Dimkox/Getzilla -b "-Rother/project"'
                with self.subTest(command=command):
                    allowed, reason = self.verdict(command)
                    self.assertTrue(allowed, reason)
                    allowed, reason = self.verdict(f'gh {group} {verb} 5 -R Dimkox/Getzilla -F.env')
                    self.assertFalse(allowed)
                    self.assertIn('secret', reason or '')

    def test_pr_review_boolean_shorthands_do_not_consume_the_selector(self) -> None:
        self.grant('github-pr-review:Dimkox/Getzilla#5')
        for flag in ('-a', '-c', '-r'):
            command = f'gh pr review {flag} 5 --body "-Rother/project" -R Dimkox/Getzilla'
            with self.subTest(command=command):
                self.assertEqual(_http_write_resource(command, self.root), 'github-pr-review:dimkox/getzilla#5')
                allowed, reason = self.verdict(command)
                self.assertTrue(allowed, reason)
        self.assertFalse(self.verdict('gh pr review -c 5 -R Dimkox/Getzilla -F.env')[0])

    def test_pr_review_text_does_not_authorize_a_different_repo(self) -> None:
        self.grant('github-pr-review:Other/Project#5')
        self.assertFalse(self.verdict('gh pr review 5 --body "-ROther/Project" --repo Dimkox/Getzilla')[0])

    def test_pr_merge_boolean_and_subject_arity_stay_distinct(self) -> None:
        self.grant('Dimkox/Getzilla#5', production=True)
        for flag in ('-d', '-m', '-r', '-s'):
            command = f'gh pr merge {flag} 5 --body "-Rother/project" --subject "--hostname=other.example" -R Dimkox/Getzilla'
            with self.subTest(command=command):
                allowed, reason = self.verdict(command)
                self.assertTrue(allowed, reason)
        self.assertFalse(self.verdict('gh pr merge 5 -R Dimkox/Getzilla -F.env')[0])

    def test_pr_merge_data_does_not_select_a_different_repo(self) -> None:
        self.grant('Other/Project#5', production=True)
        self.assertFalse(self.verdict('gh pr merge 5 --body "-ROther/Project" --repo Dimkox/Getzilla')[0])

    def test_merge_body_text_cannot_set_the_admin_option(self) -> None:
        self.grant('Dimkox/Getzilla#5', production=True)
        allowed, reason = self.verdict('gh pr merge 5 --repo Dimkox/Getzilla --body "--admin"')
        self.assertTrue(allowed, reason)

    def test_api_typed_fields_and_raw_fields_are_not_pr_body_files(self) -> None:
        resource = 'github-api:POST api.github.com/repos/Dimkox/Getzilla/issues'
        self.grant(resource)
        for field in ('-F name=-Rother/project', '-F name=.env', '-f name=@.env',
                      '-F "name=--hostname=other.example"'):
            command = f'gh api repos/Dimkox/Getzilla/issues {field}'
            with self.subTest(command=command):
                self.assertEqual(_http_write_resource(command, self.root), resource)
                allowed, reason = self.verdict(command)
                self.assertTrue(allowed, reason)
        for field in ('-F name=@.env', '-Fname=@.env', '--input=.env'):
            with self.subTest(field=field):
                allowed, reason = self.verdict(f'gh api repos/Dimkox/Getzilla/issues {field}')
                self.assertFalse(allowed)
                self.assertIn('secret', reason or '')

    @staticmethod
    def api_host_commands(endpoint: str, method: str) -> tuple[str, ...]:
        return (
            f'gh --hostname other.example api {endpoint} --method {method}',
            f'gh --hostname=other.example api {endpoint} --method {method}',
            f'gh api {endpoint} --hostname other.example --method {method}',
            f'gh api {endpoint} --hostname=other.example --method {method}',
        )

    def test_api_host_positions_cannot_borrow_the_default_host_grant(self) -> None:
        self.grant('github-api:POST api.github.com/repos/Dimkox/Getzilla/issues')
        for command in self.api_host_commands('repos/Dimkox/Getzilla/issues', 'POST'):
            with self.subTest(command=command):
                self.assertFalse(self.verdict(command)[0])
                self.assertEqual(self.hook_verdict(command).get('decision'), 'deny')
                self.assertEqual(_http_write_resource(command, self.root),
                                 'github-api:POST other.example/repos/Dimkox/Getzilla/issues')

    def test_api_host_positions_accept_the_exact_host_grant(self) -> None:
        resource = 'github-api:POST other.example/repos/Dimkox/Getzilla/issues'
        self.grant(resource)
        for selected in self.api_host_commands('repos/Dimkox/Getzilla/issues', 'POST'):
            for command in (selected, f'GH_HOST=unrelated.example {selected}'):
                with self.subTest(command=command):
                    self.assertEqual(_http_write_resource(command, self.root), resource)
                    allowed, reason = self.verdict(command)
                    self.assertTrue(allowed, reason)
                    self.assertEqual(self.hook_verdict(command).get('decision'), 'allow')

    def test_api_merge_host_positions_cannot_borrow_default_host_scopes(self) -> None:
        self.grant('github-api:PUT api.github.com/repos/Dimkox/Getzilla/pulls/5/merge')
        self.grant('Dimkox/Getzilla#5', production=True)
        for command in self.api_host_commands('repos/Dimkox/Getzilla/pulls/5/merge', 'PUT'):
            with self.subTest(command=command):
                self.assertFalse(self.verdict(command)[0])
                self.assertEqual(self.hook_verdict(command).get('decision'), 'deny')
                self.assertEqual(production_targets(self.root, command),
                                 [('pull-request-merge', 'other.example/dimkox/getzilla#5')])

    def test_api_merge_host_positions_require_both_exact_scopes(self) -> None:
        resource = 'github-api:PUT other.example/repos/Dimkox/Getzilla/pulls/5/merge'
        for api_grant, merge_grant in ((False, False), (True, False), (False, True), (True, True)):
            self.setUp()
            if api_grant:
                self.grant(resource)
            if merge_grant:
                self.grant('other.example/dimkox/getzilla#5', production=True)
            for command in self.api_host_commands('repos/Dimkox/Getzilla/pulls/5/merge', 'PUT'):
                with self.subTest(command=command, api_grant=api_grant, merge_grant=merge_grant):
                    self.assertEqual(_http_write_resource(command, self.root), resource)
                    self.assertEqual(production_targets(self.root, command),
                                     [('pull-request-merge', 'other.example/dimkox/getzilla#5')])
                    allowed, reason = self.verdict(command)
                    self.assertEqual(allowed, api_grant and merge_grant, reason)
                    self.assertEqual(self.hook_verdict(command).get('decision'),
                                     'allow' if api_grant and merge_grant else 'deny')

    def test_api_host_prefix_keeps_endpoint_url_authority(self) -> None:
        resource = 'github-api:POST endpoint.example/repos/Dimkox/Getzilla/issues'
        self.grant(resource)
        for command in self.api_host_commands('https://endpoint.example/repos/Dimkox/Getzilla/issues', 'POST'):
            with self.subTest(command=command):
                self.assertEqual(_http_write_resource(command, self.root), resource)
                allowed, reason = self.verdict(command)
                self.assertTrue(allowed, reason)
                self.assertEqual(self.hook_verdict(command).get('decision'), 'allow')

    def test_api_host_prefix_cannot_hide_duplicate_host_selectors(self) -> None:
        self.grant('github-api:POST other.example/repos/Dimkox/Getzilla/issues')
        for prefix in ('--hostname other.example', '--hostname=other.example'):
            for suffix in ('--hostname other.example', '--hostname=unrelated.example'):
                command = f'gh {prefix} api repos/Dimkox/Getzilla/issues --method POST {suffix}'
                with self.subTest(command=command):
                    self.assertFalse(self.verdict(command)[0])
                    self.assertEqual(self.hook_verdict(command).get('decision'), 'deny')
                    self.assertTrue(analyze_command_authority(command).ambiguous)

    def test_hook_keeps_secret_checks_before_exact_grant_admission(self) -> None:
        self.grant('gh:dimkox/getzilla pr create')
        for suffix, expected in (('-Fbody.md', 'allow'), ('-F.env', 'deny')):
            command = f'gh pr create --repo Dimkox/Getzilla --head feature --title Fixture {suffix}'
            code, result, error = run_hook(self.root, 'pre_tool_use.py', {
                'cwd': str(self.root), 'session_id': 'gh-arguments', 'tool_name': 'Bash',
                'tool_input': {'command': command},
            })
            with self.subTest(command=command):
                self.assertEqual(code, 0, error)
                self.assertEqual(result.get('decision'), expected, result)

    def test_linked_pr_admission_grammar_keeps_the_same_exact_resource(self) -> None:
        # The closed grammar from b007447 compares this exact resource after root admission.
        for options in (
            '--repo Dimkox/Getzilla --head feature --fill',
            '-R Dimkox/Getzilla -H feature -t Fixture -b "-Rother/project"',
            '-R=Dimkox/Getzilla -Hfeature -Bmain --title=Fixture --body-file=body.md',
            '--body "--repo" --title "--hostname=other.example" --repo=Dimkox/Getzilla --head=feature',
            '--repo Dimkox/Getzilla --head feature -F body.md --draft',
        ):
            command = f'gh pr create {options}'
            with self.subTest(command=command):
                self.assertEqual(_http_write_resource(command, self.root), 'gh:dimkox/getzilla pr create')

    def test_hook_rejects_title_expansions_with_an_otherwise_valid_grant(self) -> None:
        for group in ('pr', 'issue'):
            self.setUp()
            self.grant(f'gh:dimkox/getzilla {group} create')
            for value in ('{Fixture,--body-file=.env}', '--*/*', '"--"*/*',
                          '$TITLE', '"$TITLE"', '$(printf Fixture)', '`printf Fixture`',
                          '<(printf Fixture)', '>(printf Fixture)', '~', '[ab]', '{1..2}'):
                command = f'gh {group} create --repo Dimkox/Getzilla --title {value} --body public'
                if value == '{Fixture,--body-file=.env}':
                    command = command.removesuffix(' --body public')
                with self.subTest(command=command):
                    result = self.hook_verdict(command)
                    self.assertEqual(result.get('decision'), 'deny', result)
                    self.assertEqual(_http_write_resource(command, self.root), 'gh:')
                    self.assertTrue(analyze_command_authority(command).ambiguous)

    def test_hook_preserves_quoted_and_escaped_title_literals(self) -> None:
        for group in ('pr', 'issue'):
            self.setUp()
            resource = f'gh:dimkox/getzilla {group} create'
            self.grant(resource)
            for value in ("'{Fixture,--body-file=.env}'", '"{Fixture,--body-file=.env}"',
                          r'\{Fixture,--body-file=.env\}', '"--*/*"', r'--\*/\*',
                          "'$TITLE'", r'\$TITLE', r'"\$TITLE"', "'`literal`'", r'\`literal\`',
                          "'<(literal)'", r'\<\(literal\)', "'~'", "'[ab]'", r'\[ab\]',
                          '"--repo=Other/Project"', '.env', 'Fixture'):
                command = f'gh {group} create --repo Dimkox/Getzilla --title {value} --body public'
                with self.subTest(command=command):
                    result = self.hook_verdict(command)
                    self.assertEqual(result.get('decision'), 'allow', result)
                    self.assertEqual(_http_write_resource(command, self.root), resource)

    def test_hook_title_literals_cannot_use_a_wrong_resource_grant(self) -> None:
        self.grant('gh:other/project pr create')
        for value in ('"--repo=Other/Project"', "'$TITLE'", '"--*/*"',
                      '"{Fixture,--body-file=.env}"'):
            command = f'gh pr create --repo Dimkox/Getzilla --title {value} --body public'
            with self.subTest(command=command):
                self.assertEqual(_http_write_resource(command, self.root), 'gh:dimkox/getzilla pr create')
                self.assertEqual(self.hook_verdict(command).get('decision'), 'deny')

    def test_hook_rejects_api_field_expansions_without_losing_write_classification(self) -> None:
        self.grant('github-api:POST api.github.com/repos/Dimkox/Getzilla/issues')
        for value in ('$FIELDS', '"$FIELDS"', '--*/*', '{title=x,--hostname=other.example}',
                      '$(printf title=x)', '<(printf title=x)'):
            command = f'gh api repos/Dimkox/Getzilla/issues -f {value}'
            with self.subTest(command=command):
                result = self.hook_verdict(command)
                self.assertEqual(result.get('decision'), 'deny', result)
                self.assertEqual(_http_write_resource(command, self.root), 'gh:')
                self.assertTrue(analyze_command_authority(command).ambiguous)

    def test_hook_preserves_api_literal_fields_and_quoted_graphql(self) -> None:
        resource = 'github-api:POST api.github.com/repos/Dimkox/Getzilla/issues'
        self.grant(resource)
        for field in ("-f '$FIELDS'", r'-f \$FIELDS', r'-f "\$FIELDS"', '-f "--*/*"',
                      '-f "{title=x,--hostname=other.example}"',
                      '-F "name=--hostname=other.example"', '-f name=@.env'):
            command = f'gh api -HAccept:application/json repos/Dimkox/Getzilla/issues {field}'
            with self.subTest(command=command):
                result = self.hook_verdict(command)
                self.assertEqual(result.get('decision'), 'allow', result)
                self.assertEqual(_http_write_resource(command, self.root), resource)
        self.setUp()
        self.grant('github-api:POST api.github.com/graphql')
        command = "gh api graphql -f 'query=query($id:ID!){node(id:$id){id}}'"
        self.assertEqual(self.hook_verdict(command).get('decision'), 'allow')

    def test_hook_api_literal_field_cannot_use_a_foreign_host_grant(self) -> None:
        self.grant('github-api:POST other.example/repos/Dimkox/Getzilla/issues')
        for field in ('-f "title=fixture --hostname other.example"', "-f '$FIELDS'"):
            command = f'gh api repos/Dimkox/Getzilla/issues {field}'
            with self.subTest(command=command):
                self.assertEqual(_http_write_resource(command, self.root),
                                 'github-api:POST api.github.com/repos/Dimkox/Getzilla/issues')
                self.assertEqual(self.hook_verdict(command).get('decision'), 'deny')

    def test_hook_read_api_query_requires_literal_glob_punctuation(self) -> None:
        endpoint = 'repos/Dimkox/Getzilla/commits?per_page=3'
        for argument in (shlex.quote(endpoint), endpoint.replace('?', r'\?')):
            command = f"gh api {argument} --jq '.[] | {{sha, subject: .commit.message}}'"
            with self.subTest(command=command):
                self.assertEqual(self.hook_verdict(command).get('decision'), 'allow')
        command = f'gh api {endpoint}'
        self.assertEqual(self.hook_verdict(command).get('decision'), 'deny')
        self.assertEqual(_http_write_resource(command, self.root), 'gh:')

    def test_expansion_check_reaches_wrapped_and_nested_gh(self) -> None:
        self.grant('gh:dimkox/getzilla pr create')
        opaque = 'gh pr create --repo Dimkox/Getzilla --title --*/* --body public'
        literal = 'gh pr create --repo Dimkox/Getzilla --title "--*/*" --body public'
        for command in (f'env {opaque}', f'bash -c {shlex.quote(opaque)}'):
            with self.subTest(command=command):
                self.assertEqual(self.hook_verdict(command).get('decision'), 'deny')
                self.assertEqual(_http_write_resource(command, self.root), 'gh:')
        self.assertEqual(self.hook_verdict(f'bash -c {shlex.quote(literal)}').get('decision'), 'allow')
        # Root admission already refuses env wrappers; a lexer repair must not broaden that boundary.
        self.assertEqual(self.hook_verdict(f'env {literal}').get('decision'), 'deny')

    def test_production_and_review_body_literals_retain_their_exact_grants(self) -> None:
        for verb, resource, production in (
            ('review', 'github-pr-review:dimkox/getzilla#5', False),
            ('merge', 'Dimkox/Getzilla#5', True),
        ):
            self.setUp()
            self.grant(resource, production=production)
            for body in ("'$literal'", "'`literal`'", '"{literal,words}"'):
                command = f'gh pr {verb} 5 --repo Dimkox/Getzilla --body {body}'
                with self.subTest(command=command):
                    self.assertEqual(self.hook_verdict(command).get('decision'), 'allow')
            command = f'gh pr {verb} 5 --repo Dimkox/Getzilla --body --*/*'
            self.assertEqual(self.hook_verdict(command).get('decision'), 'deny')

    def pr_url_command(self, verb: str, selector: str, extra: str = '') -> str:
        flags = '--approve' if verb == 'review' else '--squash --match-head-commit ' + 'a' * 40
        return f'gh pr {verb} {shlex.quote(selector)} {flags} {extra}'.strip()

    def grant_pr_target(self, verb: str, target: str = 'Dimkox/Getzilla#5') -> None:
        self.grant(target if verb == 'merge' else 'github-pr-review:' + target,
                   production=verb == 'merge')

    def assert_ungrantable_pr_url(self, verb: str, selector: str) -> None:
        command = self.pr_url_command(verb, selector)
        result = self.hook_verdict(command)
        self.assertEqual(result.get('decision'), 'deny', result)
        if verb == 'review':
            resource = _http_write_resource(command, self.root)
            # The existing parser can also leave the repository unknown (for example IPv6 syntax).
            self.assertIn(resource, {'github-pr-review:dimkox/getzilla#', 'github-pr-review:#'})
            self.assertEqual(sensitive_action(self.root, {
                'tool_name': 'Bash', 'tool_input': {'command': command},
            }), 'external-write')
            with self.assertRaises(ValueError):
                self.grant(resource)
        else:
            self.assertEqual(production_targets(self.root, command), [('pull-request-merge', None)])
            self.assertIn(sensitive_action(self.root, {
                'tool_name': 'Bash', 'tool_input': {'command': command},
            }), {'pull-request-merge', 'external-write'})

    def test_canonical_pr_url_review_and_merge_keep_exact_grant_admission(self) -> None:
        for verb in ('review', 'merge'):
            self.setUp()
            self.grant_pr_target(verb)
            for url in (
                'https://github.com/Dimkox/Getzilla/pull/5',
                'http://github.com/Dimkox/Getzilla/pull/5',
                'https://GITHUB.COM/Dimkox/Getzilla/pull/5/',
                'https://github.com/Dimkox/Getzilla/pull/5/files',
                'https://github.com/Dimkox/Getzilla/pull/5#discussion',
            ):
                command = self.pr_url_command(verb, url)
                with self.subTest(verb=verb, url=url):
                    result = self.hook_verdict(command)
                    self.assertEqual(result.get('decision'), 'allow', result)
                    if verb == 'review':
                        self.assertEqual(_http_write_resource(command, self.root),
                                         'github-pr-review:dimkox/getzilla#5')
                    else:
                        self.assertEqual(production_targets(self.root, command),
                                         [('pull-request-merge', 'dimkox/getzilla#5')])

    def test_literal_canonical_review_queries_keep_exact_grants(self) -> None:
        self.grant_pr_target('review')
        plain = 'https://github.com/Dimkox/Getzilla/pull/5'
        self.assertEqual(self.hook_verdict(self.pr_url_command('review', plain)).get('decision'), 'allow')
        for selector in (shlex.quote(plain + '?tab=commits'), plain + r'\?tab=commits',
                         shlex.quote(plain) + "'?tab='commits"):
            command = f'gh pr review {selector} --approve'
            with self.subTest(selector=selector):
                self.assertEqual(self.hook_verdict(command).get('decision'), 'allow')
                self.assertEqual(_http_write_resource(command, self.root), 'github-pr-review:dimkox/getzilla#5')
        for selector in (plain + '?tab=commits', shlex.quote(plain) + '?tab=commits',
                         '"' + plain + '?tab=$TAB"'):
            with self.subTest(active=selector):
                self.assertEqual(self.hook_verdict(f'gh pr review {selector} --approve').get('decision'), 'deny')

    def test_review_queries_do_not_relax_host_grants_or_merge_queries(self) -> None:
        canonical = 'https://github.com/Dimkox/Getzilla/pull/5?tab=commits'
        for wrong in (None, 'Other/Project#5', 'Dimkox/Getzilla#6'):
            self.setUp()
            if wrong is not None:
                self.grant_pr_target('review', wrong)
            with self.subTest(wrong=wrong):
                self.assertEqual(self.hook_verdict(self.pr_url_command('review', canonical)).get('decision'), 'deny')
        self.setUp()
        self.grant_pr_target('review')
        for authority in ('other.example', 'github.com:443', 'user@github.com', 'gıthub.com'):
            with self.subTest(authority=authority):
                url = canonical.replace('github.com', authority)
                self.assertEqual(self.hook_verdict(self.pr_url_command('review', url)).get('decision'), 'deny')
        self.setUp()
        self.grant_pr_target('merge')
        self.assertEqual(self.hook_verdict(self.pr_url_command('merge', canonical)).get('decision'), 'deny')

    def test_foreign_pr_url_review_and_merge_cannot_use_default_host_grants(self) -> None:
        for verb in ('review', 'merge'):
            self.setUp()
            self.grant_pr_target(verb)
            for authority in (
                'other.example', 'github.com.other.example', 'othergithub.com', 'api.github.com',
                'github.com.', 'github.com:443', 'github.com:8443',
                'fixture@github.com', 'github.com@other.example', 'fixture:fixture@github.com',
                'gıthub.com', 'gİthub.com', 'github．com', '%67ithub.com',
                '127.0.0.1', '[::1]',
            ):
                url = f'https://{authority}/Dimkox/Getzilla/pull/5'
                with self.subTest(verb=verb, authority=authority):
                    self.assert_ungrantable_pr_url(verb, url)

    def test_malformed_pr_urls_do_not_become_grantable_branch_selectors(self) -> None:
        for verb in ('review', 'merge'):
            self.setUp()
            self.grant_pr_target(verb)
            for url in (
                'https:/github.com/Dimkox/Getzilla/pull/5',
                'https:github.com/Dimkox/Getzilla/pull/5',
                '//github.com/Dimkox/Getzilla/pull/5',
                'ssh://github.com/Dimkox/Getzilla/pull/5',
                'https://github.com/Dimkox/Getzilla/issues/5',
                'https://github.com/Dimkox/Getzilla/pull/5suffix',
                'https://github.com/Dimkox/Getzilla/pull/%35',
                'https://github.com/Dimkox/%47etzilla/pull/5',
                'https://github.com/Dimkox/../pull/5',
                'https://github.com/Dimkox/Getzilla/pull/5%2fother',
                'https://github.com\\@other.example/Dimkox/Getzilla/pull/5',
                'https://github.com/Dimkox/Getzilla/pull/5\n',
                'https://github.com/Dimkox/Getzilla/pull/5 trailing',
            ):
                with self.subTest(verb=verb, url=url):
                    self.assert_ungrantable_pr_url(verb, url)

    def test_canonical_pr_urls_still_require_the_matching_repo_and_number(self) -> None:
        for verb in ('review', 'merge'):
            for wrong_target in ('Other/Project#5', 'Dimkox/Getzilla#6'):
                self.setUp()
                self.grant_pr_target(verb, wrong_target)
                command = self.pr_url_command(verb, 'https://github.com/Dimkox/Getzilla/pull/5')
                with self.subTest(verb=verb, wrong_target=wrong_target):
                    self.assertEqual(self.hook_verdict(command).get('decision'), 'deny')

    def test_pr_url_text_in_a_body_does_not_change_the_selected_resource(self) -> None:
        for verb in ('review', 'merge'):
            self.setUp()
            self.grant_pr_target(verb)
            for body in (
                'https://other.example/Other/Project/pull/9',
                'https://fixture@github.com/Other/Project/pull/9',
                'https://github.com/Other/Project/pull/%39 .env --repo Other/Project',
            ):
                command = self.pr_url_command(
                    verb, 'https://github.com/Dimkox/Getzilla/pull/5', '--body ' + shlex.quote(body))
                with self.subTest(verb=verb, body=body):
                    result = self.hook_verdict(command)
                    self.assertEqual(result.get('decision'), 'allow', result)

    def test_pr_url_fix_preserves_numeric_branch_and_secret_file_controls(self) -> None:
        for verb in ('review', 'merge'):
            for selector in ('5', 'feature/url-host', 'contributor:feature/url-host'):
                self.setUp()
                self.grant_pr_target(verb, 'Dimkox/Getzilla#' + selector)
                command = self.pr_url_command(verb, selector, '--repo Dimkox/Getzilla')
                with self.subTest(verb=verb, selector=selector):
                    result = self.hook_verdict(command)
                    self.assertEqual(result.get('decision'), 'allow', result)
            self.setUp()
            self.grant_pr_target(verb)
            for body_file, expected in (('.env.example', 'allow'), ('.env', 'deny')):
                command = self.pr_url_command(
                    verb, 'https://github.com/Dimkox/Getzilla/pull/5', '--body-file ' + body_file)
                with self.subTest(verb=verb, body_file=body_file):
                    result = self.hook_verdict(command)
                    self.assertEqual(result.get('decision'), expected, result)


@unittest.skipUnless(shutil.which('bash'), 'Bash argv-only controls require Bash')
class GhShellArgvControls(unittest.TestCase):
    """Only printf runs: gh and secret paths are argument strings, never commands or reads."""

    def test_expansion_and_literal_controls_match_real_bash_argv(self) -> None:
        with project_copy() as root:
            fixture = root / 'argv-fixture'
            for filename in ('--aaa/title', '--repo=Other/Project'):
                path = fixture / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            cases = (
                ('--title {Fixture,--body-file=.env}', ['--title', 'Fixture', '--body-file=.env']),
                ('--title "{Fixture,--body-file=.env}"', ['--title', '{Fixture,--body-file=.env}']),
                (r'--title \{Fixture,--body-file=.env\}', ['--title', '{Fixture,--body-file=.env}']),
                ('--title --*/*', ['--title', '--aaa/title', '--repo=Other/Project']),
                ('--title "--*/*"', ['--title', '--*/*']),
                (r'--title --\*/\*', ['--title', '--*/*']),
                ('-f $FIELDS', ['-f', 'title=fixture', '--hostname', 'other.example']),
                ('-f "$FIELDS"', ['-f', 'title=fixture --hostname other.example']),
                ("-f '$FIELDS'", ['-f', '$FIELDS']),
                (r'-f \$FIELDS', ['-f', '$FIELDS']),
            )
            for shell_words, expected in cases:
                with self.subTest(shell_words=shell_words):
                    result = subprocess.run(
                        [shutil.which('bash') or 'bash', '--noprofile', '--norc', '-c',
                         'printf "%s\\0" gh ' + shell_words],
                        cwd=fixture, check=True, capture_output=True,
                        env={'PATH': os.defpath, 'LC_ALL': 'C', 'FIELDS': 'title=fixture --hostname other.example'},
                    )
                    self.assertEqual(result.stdout.decode().split('\0')[:-1], ['gh', *expected])


if __name__ == '__main__':
    unittest.main()
