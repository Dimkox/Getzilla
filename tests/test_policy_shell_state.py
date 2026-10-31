"""Offline original-source shell context controls. No command under test is run."""
from __future__ import annotations

import contextlib
import hashlib
import os
import shlex
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.policy import evaluate_pre_tool
from getzilla.router import build_route
from getzilla.state import add_approval, approvals_path, set_active_route
from tests._support import project_copy, run_hook


class ShellStatePolicyTests(unittest.TestCase):
    ISSUE = 'gh issue create --title Fixture --body public'
    ISSUE_RESOURCE = 'gh:dimkox/getzilla issue create'
    API = 'gh api repos/Dimkox/Getzilla/issues -f title=fixture'
    API_RESOURCE = 'github-api:POST api.github.com/repos/Dimkox/Getzilla/issues'

    @classmethod
    def setUpClass(cls) -> None:
        cls.stack = contextlib.ExitStack()
        cls.root = cls.stack.enter_context(project_copy(git=True))
        subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'],
                       cwd=cls.root, check=True)
        set_active_route(cls.root, build_route(cls.root, 'Offline shell context fixture', 'shell-state').to_dict())
        (cls.root / 'public.txt').write_text('Other/Project\n', encoding='utf-8')
        cls.sequence = 0

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stack.close()

    def setUp(self) -> None:
        approvals_path(self.root).write_text('[]', encoding='utf-8')
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop('GH_HOST', None)
        os.environ['GH_REPO'] = 'Dimkox/Getzilla'
        self.grant(self.ISSUE_RESOURCE)

    def grant(self, resource: str) -> None:
        add_approval(self.root, 'external-write', 'offline exact context fixture', 5,
                     actions=['external-write'], resources=[resource])

    def check(self, command: str, expected: bool, *, hook_expected: bool | None = None) -> None:
        event = {'tool_name': 'Bash', 'tool_input': {'command': command}}
        allowed, reason = evaluate_pre_tool(self.root, event)
        with self.subTest(layer='policy', command=command):
            self.assertEqual(allowed, expected, (command, reason))
        type(self).sequence += 1
        session = self.id() + str(self.sequence) + hashlib.sha256(command.encode()).hexdigest()
        code, result, error = run_hook(self.root, 'pre_tool_use.py', {
            **event, 'cwd': str(self.root), 'session_id': session,
        })
        with self.subTest(layer='hook', command=command):
            self.assertEqual(code, 0, error)
            expected_hook = expected if hook_expected is None else hook_expected
            self.assertEqual(result.get('decision'), 'allow' if expected_hook else 'deny', (command, result))

    def test_review_inherited_repository_cases(self) -> None:
        self.check(self.ISSUE, True)
        self.check(self.ISSUE + ' -R Other/Project', False)
        for prefix in ('printf -v GH_REPO Other/Project', 'read -r GH_REPO < public.txt',
                       'read -r GH_REPO <<< Other/Project'):
            self.check(prefix + '; ' + self.ISSUE, False)

    def test_review_inherited_host_case(self) -> None:
        os.environ['GH_HOST'] = 'api.github.com'
        self.grant(self.API_RESOURCE)
        self.check(self.API, True)
        self.check('GH_HOST=other.example ' + self.API, False)
        self.check('printf -v GH_HOST other.example; ' + self.API, False)

    def test_stateful_builtin_families_are_unproved(self) -> None:
        for prefix in (
            'read GH_REPO', 'read -r GH_REPO', 'read -a GH_REPO', 'read -A GH_REPO',
            'readarray GH_REPO', 'mapfile GH_REPO', 'mapfile -C public_callback -c 1 GH_REPO',
            'getopts x GH_REPO -- x', 'export GH_REPO', 'export -n GH_REPO', 'unset GH_REPO',
            'declare GH_REPO=Other/Project', 'declare -g GH_REPO=Other/Project',
            'declare -n ref=GH_REPO', 'typeset -i GH_REPO=1', 'typeset -n ref=GH_REPO',
            'local -n ref=GH_REPO', 'readonly GH_REPO', 'set -- GH_REPO', 'set +a',
            'shift', 'shopt -s expand_aliases', 'hash -p public.txt gh', 'hash -r',
            'enable -n printf', 'enable -f public.txt public', 'alias gh=public', 'unalias gh',
            'trap public_callback DEBUG', 'umask 077', 'ulimit -n 10', 'wait',
            'command read -r GH_REPO', 'builtin printf -v GH_REPO Other/Project',
            'exec printf public', '. public.txt', 'source public.txt', 'eval public',
        ):
            self.check(prefix + '; ' + self.ISSUE, False)

    def test_indirect_and_default_destinations_are_unproved(self) -> None:
        for prefix in (
            'read', 'read -r unrelated', 'mapfile', 'readarray unrelated', 'getopts x unrelated x',
            'printf -v unrelated public', 'printf %n unrelated', 'unrelated=public',
            'GH_REPO=Other/Project', 'unrelated=public :', 'GH_REPO=Other/Project :',
            'unrelated=public unknown_reader',
        ):
            self.check(prefix + '; ' + self.ISSUE, False)

    def test_printf_nonliteral_format_roles_are_unproved(self) -> None:
        for prefix in (
            'printf -v GH_REPO Other/Project', 'printf -vGH_REPO Other/Project',
            "printf '%n' GH_REPO", "printf '%s%n' public GH_REPO", "printf '%%%n' GH_REPO",
            "printf '%d' 'GH_REPO=1'", "printf '%i' 'GH_REPO=1'", "printf '%f' 'GH_REPO=1'",
            "printf '%x' 'GH_REPO=1'", "printf '%*s' 'GH_REPO=1' public",
            "printf '%1$s' public", "printf '%b' public", "printf '%q' public",
            "printf '%(date)T' 1", "printf '%5s' public", "printf '\\x25n' GH_REPO",
        ):
            self.check(prefix + '; ' + self.ISSUE, False)

    def test_printf_literal_formats_and_operands_keep_their_roles(self) -> None:
        for prefix in (
            'printf public', "printf 'literal text\\n'", "printf '%%'", "printf '%%n'",
            "printf '%%%%n' GH_REPO", "printf '%s' public", "printf '%s\\n' public",
            "printf '%s%s' '-v' GH_REPO", "printf '%s' '%n'", "printf '%s' '-v GH_REPO'",
            "printf '%s' 'Other/Project; read GH_REPO'", "printf '%s' '&& $(read GH_REPO)'",
            "printf -- '-v GH_REPO'", "printf '%s' 'GH_REPO=Other/Project'",
            "command printf '%s' public", "GH_REPO=Other/Project printf '%s' public",
        ):
            self.check(prefix + '; ' + self.ISSUE, True)

    def test_known_read_command_forms_remain_usable(self) -> None:
        for prefix in (
            'echo public', 'pwd', 'pwd -P', 'true', 'false', 'cat public.txt', 'cat -- public.txt',
            'git status --short', 'git --no-pager status --porcelain=v1', 'git log -n 1 --oneline',
            'git diff --stat', 'git show --no-patch --format=%H HEAD', 'git rev-parse --show-toplevel',
            'git config --get remote.origin.url', 'git remote get-url origin', 'git branch --show-current',
            'gh pr view 5 -R Dimkox/Getzilla', 'gh -R Dimkox/Getzilla pr view 5 --json number,title',
            'gh issue list --limit 5 -R Dimkox/Getzilla', 'gh issue view 5 --comments',
            'gh repo view Dimkox/Getzilla --json name', 'gh pr checks 5', 'gh pr diff 5 --stat',
            'gh api repos/Dimkox/Getzilla/issues --method GET',
        ):
            self.check(prefix + '; ' + self.ISSUE, True)

    def test_read_family_names_do_not_admit_stateful_subcommands_or_options(self) -> None:
        for prefix in (
            'git config remote.origin.url public', 'git config --unset remote.origin.url',
            'git remote set-url origin public', 'git remote rename origin other',
            'git branch feature', 'git branch -m feature', 'git checkout feature', 'git clone public',
            'git -c alias.public=status public', 'git status --unproved-option',
            'git log --output=public.txt', 'git diff --ext-diff', 'git diff --textconv',
            'gh pr checkout 5', 'gh repo clone Dimkox/Getzilla', 'gh release download fixture',
            'gh config set host other.example', 'gh alias set public status', 'gh extension exec public',
            'gh pr view 5 --unproved-option', 'gh api repos/Dimkox/Getzilla/issues --unproved-option',
            'awk public public.txt', 'sed public public.txt', 'jq public public.txt',
            'rg --pre public public.txt', 'stat -A GH_REPO public.txt', 'cat --unproved-option public.txt',
        ):
            self.check(prefix + '; ' + self.ISSUE, False)

    def test_only_bounded_literal_same_root_directory_forms_are_supported(self) -> None:
        for prefix in (f'cd {shlex.quote(str(self.root))}', 'cd .', 'cd dist', 'cd -- dist', 'pushd .', 'pushd dist'):
            self.check(prefix + ' && ' + self.ISSUE, True)
        for prefix in ('cd', 'cd -', 'cd ..', 'cd -P ..', 'pushd', 'pushd +1', 'pushd -0',
                       'pushd -n .', 'pushd ..', 'popd', 'cd . extra'):
            self.check(prefix + '; ' + self.ISSUE, False)

    def test_command_local_target_environment_remains_local(self) -> None:
        for read in ("GH_REPO=Other/Project printf '%s' public", 'GH_REPO=Other/Project gh pr view 5'):
            self.check(read + '; ' + self.ISSUE, True)
            self.check(self.ISSUE + '; ' + read, True)
        self.check('GH_REPO=Other/Project ' + self.ISSUE, False)

    def test_existing_wrapper_root_boundary_stays_closed(self) -> None:
        # Exact 02ab RED evidence shows the root guard already refuses these
        # outer compositions. Correct command-local data does not broaden it.
        for prefix in ("env GH_REPO=Other/Project printf '%s' public",
                       'env GH_REPO=Other/Project gh pr view 5',
                       'bash -c ' + shlex.quote("printf '%s' public")):
            self.check(prefix + '; ' + self.ISSUE, True, hook_expected=False)

    def test_unknown_context_is_unproved_before_and_after_a_mutation(self) -> None:
        for prefix in ('unknown_reader public', 'command unknown_reader public', 'builtin echo public',
                       'exec echo public', 'timeout --unproved-option 5 echo public'):
            self.check(prefix + '; ' + self.ISSUE, False)
            self.check(self.ISSUE + '; ' + prefix, False)

    def test_shell_payload_context_propagates_without_a_nested_mutation(self) -> None:
        for payload in ('read GH_REPO', 'unknown_reader public', 'unrelated=public',
                        'git config remote.origin.url public', "printf '%n' GH_REPO"):
            self.check('bash -c ' + shlex.quote(payload) + '; ' + self.ISSUE, False)
            self.check('bash -c ' + shlex.quote(payload + '; ' + self.ISSUE), False)
        # The existing root guard admits one complete payload, not a separate
        # shell prefix followed by an outer mutation.
        self.check('bash -c ' + shlex.quote("printf '%s' public; " + self.ISSUE), True)

    def test_neutral_names_cannot_hide_redirection_or_active_expansion(self) -> None:
        for prefix in ('echo public > public.txt', 'printf public 1> public.txt',
                       'cat < public.txt', 'true 3> public.txt', 'echo "$GH_REPO"',
                       'printf public$(unknown_reader)', 'echo *'):
            self.check(prefix + '; ' + self.ISSUE, False)
        self.check("printf '%s' '>' ';' '&&' '$GH_REPO' '*'; " + self.ISSUE, True)

    def test_curl_noproxy_value_is_data_for_reads_and_one_write(self) -> None:
        self.grant('https://api.example.test/items')
        for option in ("--noproxy '*'", "--noproxy='*'", '--noproxy https://data.example.test/'):
            self.check('curl ' + option + ' https://api.example.test/items', True)
            self.check('curl ' + option + ' -X POST -d public https://api.example.test/items', True)
        self.check('curl --noproxy', False)
        self.check('curl --noproxy=* -X POST -d public https://api.example.test/items', False)


if __name__ == '__main__':
    unittest.main()
