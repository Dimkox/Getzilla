"""Offline gh policy controls. These tests never execute a gh command."""
from __future__ import annotations

import contextlib
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla._policy_legacy import _http_write_resource  # noqa: E402
from getzilla.policy import evaluate_pre_tool  # noqa: E402
from getzilla.router import build_route  # noqa: E402
from getzilla.state import add_approval, approvals_path, set_active_route  # noqa: E402
from tests._support import project_copy, run_hook  # noqa: E402


class GhArgumentPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.stack = contextlib.ExitStack()
        cls.root = cls.stack.enter_context(project_copy(git=True))
        subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'],
                       cwd=cls.root, check=True)
        set_active_route(cls.root, build_route(cls.root, 'Offline argument fixture', 'gh-arguments').to_dict())
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
        for value in ('$BODY', '"$BODY"', "'$literal'"):
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


if __name__ == '__main__':
    unittest.main()
