"""Offline mutation admission controls. No command under test is executed."""
from __future__ import annotations

import contextlib
import shlex
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.policy import evaluate_pre_tool, sensitive_action
from getzilla.router import build_route
from getzilla.state import add_approval, approvals_path
from tests._support import activate_owned_route
from tests._support import project_copy, run_hook


class CompoundWritePolicyTests(unittest.TestCase):
    PR = ('gh pr create -R Dimkox/Getzilla --head feature --title Fixture --body public',
          'external-write', 'external-write', 'gh:dimkox/getzilla pr create')
    ISSUE = ('gh issue create -R Other/Project --title Fixture --body public',
             'external-write', 'external-write', 'gh:other/project issue create')
    API = ('gh api repos/Dimkox/Getzilla/issues -f title=fixture',
           'external-write', 'external-write', 'github-api:POST api.github.com/repos/Dimkox/Getzilla/issues')
    REVIEW = ('gh pr review 5 -R Dimkox/Getzilla --approve',
              'external-write', 'external-write', 'github-pr-review:dimkox/getzilla#5')
    CURL = ('curl --request POST --data public https://api.example.test/items',
            'external-write', 'external-write', 'https://api.example.test/items')
    WGET = ('wget --post-data public https://api.example.test/other',
            'external-write', 'external-write', 'https://api.example.test/other')
    POWERSHELL = ('Invoke-WebRequest -Method POST -Body public https://api.example.test/ps',
                  'external-write', 'external-write', 'https://api.example.test/ps')
    MERGE = ('gh pr merge 5 -R Dimkox/Getzilla --squash',
             'production', 'pull-request-merge', 'dimkox/getzilla#5')

    @classmethod
    def setUpClass(cls) -> None:
        cls.stack = contextlib.ExitStack()
        cls.root = cls.stack.enter_context(project_copy(git=True))
        subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'],
                       cwd=cls.root, check=True)
        activate_owned_route(cls.root, build_route(cls.root, 'Offline compound mutation fixture', 'compound').to_dict())
        (cls.root / 'body.md').write_text('Public fixture\n', encoding='utf-8')
        (cls.root / 'request.cfg').write_text('url = https://api.example.test/items\n', encoding='utf-8')

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stack.close()

    def setUp(self) -> None:
        approvals_path(self.root).write_text('[]', encoding='utf-8')

    def grant(self, case: tuple[str, str, str, str]) -> None:
        _, scope, action, resource = case
        add_approval(self.root, scope, 'offline exact mutation fixture', 5,
                     actions=[action], resources=[resource])

    def check(self, command: str, expected: bool, *, hook: bool = True) -> None:
        event = {'tool_name': 'Bash', 'tool_input': {'command': command}}
        allowed, reason = evaluate_pre_tool(self.root, event)
        with self.subTest(layer='policy', command=command):
            self.assertEqual(allowed, expected, (command, reason))
        if hook:
            code, result, error = run_hook(self.root, 'pre_tool_use.py', {
                **event, 'cwd': str(self.root), 'session_id': 'compound',
            })
            with self.subTest(layer='hook', command=command):
                self.assertEqual(code, 0, error)
                self.assertEqual(result.get('decision'), 'allow' if expected else 'deny', (command, result))

    def test_single_mutation_families_keep_exact_grants(self) -> None:
        for case in (self.PR, self.ISSUE, self.API, self.REVIEW, self.CURL, self.WGET, self.POWERSHELL, self.MERGE):
            with self.subTest(case=case[0]):
                self.setUp()
                self.check(case[0], False)
                self.grant(case)
                self.check(case[0], True)

    def test_first_grant_cannot_cover_a_second_foreign_write(self) -> None:
        self.grant(self.PR)
        self.check(self.PR[0], True)
        self.check(self.ISSUE[0], False)
        for separator in ('; ', ' && ', '\n'):
            for first, second in ((self.PR, self.ISSUE), (self.ISSUE, self.PR)):
                with self.subTest(separator=separator, first=first[0]):
                    self.check(first[0] + separator + second[0], False)

    def test_repeated_granted_write_is_still_two_mutations(self) -> None:
        self.grant(self.PR)
        self.check(self.PR[0], True)
        for separator in ('; ', ' && ', '\n'):
            with self.subTest(separator=separator):
                self.check(self.PR[0] + separator + self.PR[0], False)

    def test_all_classifier_pairs_refuse_two_independently_granted_writes(self) -> None:
        for first, second in (
            (self.PR, self.ISSUE), (self.PR, self.API), (self.PR, self.REVIEW),
            (self.PR, self.CURL), (self.API, self.REVIEW), (self.CURL, self.WGET),
            (self.POWERSHELL, self.PR), (self.MERGE, self.PR), (self.MERGE, self.API),
        ):
            self.setUp()
            self.grant(first)
            self.grant(second)
            self.check(first[0], True)
            self.check(second[0], True)
            for left, right in ((first, second), (second, first)):
                for separator in ('; ', ' && '):
                    with self.subTest(left=left[0], right=right[0], separator=separator):
                        self.check(left[0] + separator + right[0], False)

    def test_literal_read_prefixes_and_separator_data_remain_usable(self) -> None:
        self.grant(self.PR)
        for prefix in ("printf '%s' 'public; && data' && ", 'gh pr view 5 -R Dimkox/Getzilla; ',
                       f'cd {shlex.quote(str(self.root))} && '):
            with self.subTest(prefix=prefix):
                self.check(prefix + self.PR[0], True)
        for body in ("'one; gh issue create -R Other/Project'", "'one && two'", "'one\ntwo'",
                     r'one\;two', r'one\&\&two', "'https://other.example/; curl -X POST'", '"semi"\';colon\''):
            with self.subTest(body=body):
                self.check(self.PR[0].removesuffix('public') + body, True)

    def test_supported_wrappers_keep_one_write_and_expose_two(self) -> None:
        self.grant(self.PR)
        self.grant(self.ISSUE)
        for prefix in ('command ', 'timeout 5 ', 'nice -n 1 '):
            with self.subTest(prefix=prefix):
                self.check(prefix + self.PR[0], True)
                self.check(prefix + self.PR[0] + '; ' + self.ISSUE[0], False)
        self.check('bash -c ' + shlex.quote(self.PR[0]), True)
        self.check('bash -c ' + shlex.quote(self.PR[0] + '; ' + self.ISSUE[0]), False)

    def test_unresolved_dispatchers_cannot_reuse_a_single_write_grant(self) -> None:
        self.grant(self.PR)
        for command in (
            'watch ' + shlex.quote(self.PR[0]),
            'xargs -a body.md -- ' + self.PR[0],
            'bash -c ' + shlex.quote('bash -c ' + shlex.quote(self.PR[0])),
            self.PR[0] + ' | cat', self.PR[0] + ' || printf fallback',
        ):
            with self.subTest(command=command):
                self.check(command, False)

    def test_later_environment_on_a_read_cannot_rename_an_earlier_write(self) -> None:
        command = 'gh issue create --title Fixture --body public'
        own = (command, 'external-write', 'external-write', 'gh:dimkox/getzilla issue create')
        foreign = (command, 'external-write', 'external-write', 'gh:other/project issue create')
        self.grant(own)
        self.check('GH_REPO=Dimkox/Getzilla ' + command, True)
        for chain in (
            'GH_REPO=Other/Project ' + command + '; GH_REPO=Dimkox/Getzilla printf done',
            'export GH_REPO=Other/Project; ' + command + '; export GH_REPO=Dimkox/Getzilla',
        ):
            with self.subTest(chain=chain):
                self.check(chain, False)
        self.setUp()
        self.grant(foreign)
        self.check('GH_REPO=Other/Project ' + command, True)
        self.check('GH_REPO=Other/Project printf data; ' + command, False)
        self.setUp()
        self.grant(self.API)
        self.check(self.API[0], True)
        self.check('GH_HOST=other.example ' + self.API[0] + '; GH_HOST=api.github.com printf done', False)

    def test_control_flow_and_other_shell_languages_are_unresolved(self) -> None:
        self.grant(self.PR)
        self.check(self.PR[0], True)
        for command in (
            'while true; do\n' + self.PR[0] + '\ndone',
            'for item in one two; do\n' + self.PR[0] + '\ndone',
            'if true; then\n' + self.PR[0] + '\nfi',
            'fish -c ' + shlex.quote(self.PR[0]),
            'script -c ' + shlex.quote(self.PR[0]),
        ):
            with self.subTest(command=command):
                self.check(command, False)

    def test_temporary_read_environment_does_not_change_write_authority(self) -> None:
        command = 'gh issue create --title Fixture --body public'
        own = (command, 'external-write', 'external-write', 'gh:dimkox/getzilla issue create')
        foreign = (command, 'external-write', 'external-write', 'gh:other/project issue create')
        own_command = 'GH_REPO=Dimkox/Getzilla ' + command
        read = 'GH_REPO=Other/Project printf done'
        self.grant(own)
        self.check(own_command, True)
        for literal_read in (read, 'GH_REPO=Other/Project gh pr view 5'):
            for chain in (literal_read + '; ' + own_command, own_command + '; ' + literal_read):
                with self.subTest(chain=chain):
                    self.check(chain, True)
        for prefix in ('export GH_REPO=Other/Project', 'GH_REPO=Other/Project :', 'GH_REPO=Other/Project'):
            with self.subTest(persistent=prefix):
                self.check(prefix + '; ' + own_command, False)
        self.setUp()
        self.grant(foreign)
        self.check('GH_REPO=Other/Project ' + command, True)
        self.check(read + '; ' + command, False)
        self.check('GH_REPO=Other/Project ' + command + '; GH_REPO=Dimkox/Getzilla printf done', True)

    def test_api_merge_counts_once_and_requires_both_scopes(self) -> None:
        command = 'gh api -X PUT repos/Dimkox/Getzilla/pulls/5/merge'
        api = (command, 'external-write', 'external-write',
               'github-api:PUT api.github.com/repos/Dimkox/Getzilla/pulls/5/merge')
        self.grant(self.MERGE)
        self.check(command, False)
        self.grant(api)
        self.check(command, True)
        self.setUp()
        self.grant(api)
        self.check(command, False)

    def test_one_git_push_still_checks_every_ref(self) -> None:
        first = ('git push origin fixture-one', 'production', 'git-push-branch', 'fixture-one')
        second = ('git push origin fixture-two', 'production', 'git-push-branch', 'fixture-two')
        self.grant(first)
        self.check(first[0], True)
        self.check('git push origin fixture-one fixture-two', False)
        self.grant(second)
        self.check('git push origin fixture-one fixture-two', True)
        self.check(first[0] + '; ' + second[0], False)

    def test_http_url_data_does_not_select_the_endpoint(self) -> None:
        endpoint = 'https://api.example.test/items'
        data = 'https://text.example.test/data'
        commands = (
            f'curl --data {shlex.quote(data)} {endpoint}',
            f'curl --header {shlex.quote(data)} --request POST --url {endpoint}',
            f'wget --post-data {shlex.quote(data)} {endpoint}',
            f'Invoke-WebRequest -Body {shlex.quote(data)} -Method POST -Uri {endpoint}',
        )
        for command in commands:
            with self.subTest(command=command):
                self.setUp()
                self.grant(('', 'external-write', 'external-write', endpoint))
                self.check(command, True)
                self.setUp()
                self.grant(('', 'external-write', 'external-write', data))
                self.check(command, False)

    def test_http_multitarget_and_configuration_are_ungrantable(self) -> None:
        self.grant(self.CURL)
        self.check(self.CURL[0], True)
        endpoint = self.CURL[3]
        for command in (
            f'curl -X POST {endpoint} https://other.example/items',
            f'curl -X POST --url {endpoint} --url https://other.example/items',
            f'curl -X POST {endpoint} --next https://other.example/items',
            f'curl -X POST -K request.cfg {endpoint}',
            'curl --config request.cfg', 'wget --config=request.cfg',
            f'wget --post-data public {endpoint} https://other.example/items',
            f'Invoke-WebRequest -Method POST -Uri {endpoint} https://other.example/items',
        ):
            with self.subTest(command=command):
                self.check(command, False)
                self.assertIsNotNone(sensitive_action(self.root, {
                    'tool_name': 'Bash', 'tool_input': {'command': command},
                }))


if __name__ == '__main__':
    unittest.main()
