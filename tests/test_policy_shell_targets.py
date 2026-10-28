import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.policy import evaluate_pre_tool
from tests._support import project_copy


class ShellTargetPolicyTest(unittest.TestCase):
    def check(self, root, command):
        return evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})

    def test_names_outside_repo_do_not_trigger_control_plane(self):
        with project_copy() as root:
            command = (
                'docker cp probe.py adaptive-trust-ci-worker-1:/tmp/probe.py && '
                'curl -o /tmp/trust-ci-live.body http://127.0.0.1/health/live'
            )
            allowed, reason = self.check(root, command)
            self.assertTrue(allowed, reason)

    def test_real_control_plane_target_is_blocked_and_named(self):
        with project_copy() as root:
            allowed, reason = self.check(root, 'printf x >> AGENTS.md')
            self.assertFalse(allowed)
            self.assertIn('AGENTS.md', reason or '')

    def test_argv_mutation_commands_name_control_plane_targets(self):
        with project_copy() as root:
            cases = (
                "sed -i 's/a/b/' AGENTS.md",
                'rm AGENTS.md',
                'touch AGENTS.md',
                'tee AGENTS.md',
                'curl -o README.md http://example.invalid/x',
                'bash -c "printf x >> AGENTS.md"',
                'cp README.md AGENTS.md',
                'install README.md AGENTS.md',
                'rsync README.md AGENTS.md',
                'wget -O AGENTS.md http://example.invalid/x',
                'perl -i -pe s/a/b/ AGENTS.md',
            )
            for command in cases:
                allowed, reason = self.check(root, command)
                self.assertFalse(allowed, f'{command}: {reason}')

    def test_a_cd_moves_the_base_of_later_targets(self):
        # #214: a target after `cd` is read from the directory the shell is in, not the repository root.
        with project_copy() as root:
            (root / 'docs').mkdir(exist_ok=True)
            (root / 'docs/notes.md').write_text('x', encoding='utf-8')
            denied = (
                'cd docs && rm -rf ../.getzilla/config',
                'cd .grok && rm hooks/_lib.py',
                'cd docs; rm ../AGENTS.md',
                'cd docs || rm AGENTS.md',
                'cd "$X" && rm notes.md',
                'cd ~ && rm notes.md',
            )
            for command in denied:
                allowed, reason = self.check(root, command)
                self.assertFalse(allowed, f'{command}: {reason}')
            for command in ('cd docs && rm notes.md', 'rm docs/notes.md', 'cd docs && ls'):
                allowed, reason = self.check(root, command)
                self.assertTrue(allowed, f'{command}: {reason}')

    def test_code_running_git_config_is_refused(self):
        # #214: these keys make a later plain `git commit` or `git status` run a program.
        with project_copy() as root:
            for command in (
                'git config core.hooksPath /tmp/h',
                'git config --local filter.x.clean ./run',
                'git config core.fsmonitor ./watch',
                'git config core.sshCommand ./ssh',
                'git config core.worktree ../other',
                'git config diff.x.textconv ./conv',
                'git config alias.ship push',
            ):
                allowed, reason = self.check(root, command)
                self.assertFalse(allowed, f'{command}: {reason}')
                self.assertIn('code-running git config', reason or '')
            for command in ('git config --get core.hooksPath', 'git config user.name Bot', 'git config --list'):
                allowed, reason = self.check(root, command)
                self.assertTrue(allowed, f'{command}: {reason}')

    def test_moving_a_local_protected_branch_is_refused(self):
        with project_copy() as root:
            for command in (
                'git update-ref refs/heads/main HEAD',
                'git update-ref --stdin',
                'git branch -f main HEAD~1',
                'git branch -D master',
                'git checkout -B main',
                'git switch -C main origin/main',
                'git symbolic-ref refs/heads/main refs/heads/feature',
                'cd docs && git branch --force main HEAD',
            ):
                allowed, reason = self.check(root, command)
                self.assertFalse(allowed, f'{command}: {reason}')
                self.assertIn('protected branch', reason or '')
            for command in (
                'git branch -f feature HEAD', 'git update-ref refs/heads/feature HEAD', 'git checkout -B topic',
                'git branch main-copy', 'git symbolic-ref HEAD refs/heads/main', 'git checkout main',
            ):
                allowed, reason = self.check(root, command)
                self.assertTrue(allowed, f'{command}: {reason}')

    def test_a_cd_the_tracker_cannot_follow_makes_relative_writes_blind(self):
        with project_copy() as root:
            (root / 'docs').mkdir(exist_ok=True)
            for command in (
                'pushd docs && popd && rm AGENTS.md',
                '( cd docs; rm ../AGENTS.md )',
                '{ cd docs; rm ../AGENTS.md; }',
                'if cd docs; then rm ../AGENTS.md; fi',
                'builtin cd docs && rm ../AGENTS.md',
                'bash -c "cd docs && rm ../AGENTS.md"',
                'env -C docs rm ../AGENTS.md',
                'printf x >> .git/config',
                'cp hook .git/hooks/pre-commit',
                '(rm AGENTS.md)', 'cd docs && (rm ../AGENTS.md)', '(cd docs); rm AGENTS.md',
                '{ rm AGENTS.md; }', 'if true; then rm AGENTS.md; fi',
            ):
                allowed, reason = self.check(root, command)
                self.assertFalse(allowed, f'{command}: {reason}')
            for command in ('(cd docs && ls)', 'bash -c "cd docs && ls"', 'cat .git/config'):
                allowed, reason = self.check(root, command)
                self.assertTrue(allowed, f'{command}: {reason}')

    def test_a_quoted_cd_is_followed_and_the_word_cd_in_text_is_not_a_cd(self):
        with project_copy() as root:
            (root / 'docs').mkdir(exist_ok=True)
            for command in (
                "'cd' docs && rm ../AGENTS.md", '"cd" docs && rm ../AGENTS.md', '\\cd docs && rm ../AGENTS.md',
                'eval "cd docs" && rm ../AGENTS.md', 'pushd docs && pushd +1 && rm AGENTS.md',
                'case x in x) cd docs;; esac; rm ../AGENTS.md', 'f() { cd docs; }; f && rm ../AGENTS.md',
                'function f { cd docs; }; f; rm ../AGENTS.md', 'command -p cd docs && rm ../AGENTS.md',
                'X=cd; eval "$X docs"; rm ../AGENTS.md',
                'printf x >> .git/config.worktree',
            ):
                allowed, reason = self.check(root, command)
                self.assertFalse(allowed, f'{command}: {reason}')
            for command in (
                'echo "use cd here" > notes.txt', 'git commit -m "fix cd parsing" && echo ok > out.txt',
                'grep -rn cd src > hits.txt',
            ):
                allowed, reason = self.check(root, command)
                self.assertTrue(allowed, f'{command}: {reason}')

    def test_a_fetch_that_fast_forwards_main_from_its_remote_is_a_sync(self):
        with project_copy() as root:
            for command in ('git fetch origin main:main', 'git fetch origin "refs/heads/*:refs/remotes/origin/*"'):
                allowed, reason = self.check(root, command)
                self.assertTrue(allowed, f'{command}: {reason}')
            for command in ("git fetch origin '+refs/heads/*:refs/heads/*'", 'git pull origin +HEAD:main',
                            'git fetch origin feature:main'):
                allowed, reason = self.check(root, command)
                self.assertFalse(allowed, f'{command}: {reason}')

    def test_every_spelling_of_a_protected_ref_move_is_refused(self):
        with project_copy() as root:
            for command in (
                'git fetch . HEAD:main', 'git fetch origin +HEAD:refs/heads/main', 'git branch --move=main x',
                'git checkout -Bmain', 'git checkout --force-create=main', 'git switch -cmain',
                'git branch -fmain', 'git update-ref -m msg refs/heads/main HEAD', 'git worktree add -B main ../wt',
                'git checkout -B Main', 'git branch -C feature main',
            ):
                allowed, reason = self.check(root, command)
                self.assertFalse(allowed, f'{command}: {reason}')
            for command in (
                'git branch -c main main-copy', 'git branch --copy main backup', 'git fetch origin main',
                'git update-ref -m main refs/heads/feature HEAD', 'git worktree add ../wt main',
                'git branch -D feature/main-fix', 'git branch -m old new',
            ):
                allowed, reason = self.check(root, command)
                self.assertTrue(allowed, f'{command}: {reason}')

    def test_git_config_reads_and_removals_pass_and_more_code_keys_are_refused(self):
        with project_copy() as root:
            for command in ('git config core.pager', 'git config core.hooksPath', 'git config --unset core.hooksPath',
                            'git config unset core.hooksPath', 'git config get core.editor'):
                allowed, reason = self.check(root, command)
                self.assertTrue(allowed, f'{command}: {reason}')
            for command in ('git config credential.https://x.helper ./h', 'git config core.alternateRefsCommand ./c',
                            'git config remote.origin.uploadpack ./u', 'git config pager.log ./p',
                            'git config set core.hooksPath h', 'git config --file .git/config core.editor ./e',
                            'git config --add filter.x.smudge ./s'):
                allowed, reason = self.check(root, command)
                self.assertFalse(allowed, f'{command}: {reason}')

    def test_wrapper_retains_workflow_dispatch_forbidden_invariant(self):
        source = (ROOT / '.getzilla/getzilla/policy.py').read_text(encoding='utf-8')
        self.assertIn('workflow-dispatch', source)
        self.assertIn('forbidden', source.lower())


if __name__ == '__main__':
    unittest.main()
