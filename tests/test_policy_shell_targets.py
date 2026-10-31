import sys
import os
import shutil
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.policy import evaluate_pre_tool
from tests._support import project_copy


class PythonScannerPolicyTests(unittest.TestCase):
    """Classify literal fixture commands; never import or launch a scanner."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        config = self.root / '.getzilla/config'
        config.mkdir(parents=True)
        (config / 'policy.json').write_text('{}\n')
        (self.root / '.env').write_text('FIXTURE_ONLY=not-a-credential\n')

    def check(self, command):
        return evaluate_pre_tool(self.root, {'tool_name': 'Bash', 'tool_input': {'command': command}})

    def test_literal_bandit_arguments_keep_input_and_output_roles(self):
        commands = (
            'python3 -m bandit -c bandit.yaml -q -f json -- example.py',
            'python3 -I -W ignore -X dev -m bandit -c bandit.yaml -r -- .getzilla/getzilla',
            'python3 -Imbandit -cbandit.yaml -fjson -o report.json -- example.py',
            'python3 -Xdev -Wignore -m bandit -c bandit.yaml -- example.py',
            'python3 --check-hash-based-pycs=never -m bandit -c=bandit.yaml -o=report.json -- example.py',
            'python3 -m bandit --configfile bandit.yaml --quiet --format json --recursive -- example.py',
            'python3 -m bandit --configfile=bandit.yaml --silent --output=report.json -- example.py',
            'python3 -m bandit -c bandit.yaml -o - -- example.py',
            'python3 -m bandit -c bandit.yaml -o .getzilla/runtime/scratch/report.json -- example.py',
        )
        for command in commands:
            with self.subTest(command=command):
                allowed, reason = self.check(command)
                self.assertTrue(allowed, reason)

    def test_bandit_outputs_use_existing_protected_target_guard(self):
        for output in ('-o AGENTS.md', '-oAGENTS.md', '-o=AGENTS.md',
                       '--output AGENTS.md', '--output=AGENTS.md'):
            with self.subTest(output=output):
                command = 'python3 -m bandit --configfile bandit.yaml ' + output + ' -- example.py'
                allowed, reason = self.check(command)
                self.assertFalse(allowed)
                self.assertIn('shell mutation targeting AGENTS.md;', reason)
        allowed, reason = self.check(
            'python3 -m bandit -c bandit.yaml -o .getzilla/runtime/changes/report.json -- example.py')
        self.assertFalse(allowed)
        self.assertIn('shell mutation targeting .getzilla/runtime/changes/report.json;', reason)
        for outputs in ('-o AGENTS.md -o report.json', '-o report.json --output=AGENTS.md'):
            with self.subTest(outputs=outputs):
                allowed, reason = self.check('python3 -m bandit -c bandit.yaml ' + outputs + ' -- example.py')
                self.assertFalse(allowed)
                self.assertIn('shell mutation targeting AGENTS.md;', reason)

    def test_bandit_program_options_respect_data_boundaries(self):
        commands = (
            'python3 -m bandit -c bandit.yaml -- -o AGENTS.md',
            'python3 -m bandit -c bandit.yaml -- --output=AGENTS.md',
            'python3 -m bandit --configfile=-oAGENTS.md -- AGENTS.md',
            'python3 -m bandit -c bandit.yaml -o report.json -- --output-file AGENTS.md',
        )
        for command in commands:
            with self.subTest(command=command):
                allowed, reason = self.check(command)
                self.assertTrue(allowed, reason)

    def test_unknown_bandit_forms_remain_opaque(self):
        commands = (
            'python3 -m bandit -c bandit.yaml --output-file=AGENTS.md',
            'python3 -m bandit -c bandit.yaml --out=AGENTS.md',
            'python3 -m bandit -c bandit.yaml --unknown-output AGENTS.md',
            'python3 -m bandit -c bandit.yaml -f custom',
            'python3 -m bandit -c bandit.yaml -qoAGENTS.md',
            'python3 -m bandit -c bandit.yaml -o',
            'python3 -m bandit -c bandit.yaml --output',
            'python3 -m bandit -c bandit.yaml -o "$OUTPUT"',
            'python3 -m bandit -c bandit.yaml -- *.py',
            'python3 --unknown -m bandit -c bandit.yaml',
            'python3 -X pycache_prefix=.getzilla/config -m bandit -c bandit.yaml',
            'python3 -Xpresite=fixture_setup -m bandit -c bandit.yaml',
            'python3 -W ignore::fixture_setup.Warning -m bandit -c bandit.yaml',
            'python3 -X pycache_prefix=.getzilla/config -m bandit --configfile bandit.yaml',
            'python3 -W ignore::fixture_setup.Warning -m bandit --configfile bandit.yaml',
            'python3 -c "print(1)" -m bandit -c bandit.yaml',
            'python3 /dev/stdin -m bandit -c bandit.yaml',
            'python3 -m "$MODULE" -c bandit.yaml',
            'env python3 -m bandit -c bandit.yaml',
            'nice python3 -m bandit -c bandit.yaml',
            "sh -c 'python3 -m bandit -c bandit.yaml'",
            'launcher python3 -m bandit -c bandit.yaml',
            'python3 -m bandit -qoAGENTS.md -- example.py',
            'python3 -m bandit --out AGENTS.md -- example.py',
            'python3 -m bandit --out=AGENTS.md -- example.py',
            'python3 -m bandit --output-fileAGENTS.md -- example.py',
        )
        for command in commands:
            with self.subTest(command=command):
                allowed, reason = self.check(command)
                self.assertFalse(allowed)
                self.assertIn('opaque control-plane shell mutation', reason)

    def test_other_python_program_arguments_keep_existing_refusals(self):
        for command in ('python3 -m fixture_check -c bandit.yaml',
                        'python3 fixture_check.py -c bandit.yaml',
                        'python3 -m bandit.__main__ -c bandit.yaml'):
            with self.subTest(command=command):
                self.assertFalse(self.check(command)[0])

    def test_bandit_inputs_still_use_secret_read_guard(self):
        for command in ('python3 -m bandit -c .env -- example.py',
                        'python3 -m bandit --configfile=.env -- example.py',
                        'python3 -m bandit -c bandit.yaml -- .env'):
            with self.subTest(command=command):
                allowed, reason = self.check(command)
                self.assertFalse(allowed)
                self.assertIn('secret', reason.lower())

    def test_bandit_protected_redirection_remains_denied(self):
        for suffix in ('> AGENTS.md', '2> AGENTS.md', '>> AGENTS.md'):
            with self.subTest(suffix=suffix):
                allowed, reason = self.check('python3 -m bandit -c bandit.yaml -- example.py ' + suffix)
                self.assertFalse(allowed)
                self.assertIn('shell mutation targeting AGENTS.md;', reason)


@unittest.skipIf(os.name == 'nt', 'Supported scratch pip syntax is POSIX-only')
class ScratchPipPolicyTest(unittest.TestCase):
    def setUp(self):
        # The policy supports system Python paths, while the test runner can live in a CI
        # tool cache. Inspect this supported interpreter's metadata; never execute it.
        base_python = Path('/usr/bin/python3')
        if not base_python.is_file() or not os.access(base_python, os.X_OK):
            self.skipTest('scratch pip fixture needs /usr/bin/python3 metadata')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        config = self.root / '.getzilla/config'
        config.mkdir(parents=True)
        shutil.copy2(ROOT / '.getzilla/config/policy.json', config)
        self.requirements = config / 'python-test-requirements.txt'
        self.requirements.write_text('# tools\npytest==9.1.1\ncoverage==7.15.4\n')
        self.venv = self.root / '.getzilla/runtime/scratch/tools'
        (self.venv / 'bin').mkdir(parents=True)
        self.venv.chmod(0o700)
        for parent in self.venv.parents:
            if parent == self.root:
                break
            parent.chmod(0o755)
        (self.venv / 'bin/python').symlink_to(base_python)
        (self.venv / 'bin/\U0001d70bthon').symlink_to(base_python)
        (self.venv / 'lib').mkdir()
        (self.venv / 'lib64').symlink_to('lib', target_is_directory=True)
        (self.venv / 'pyvenv.cfg').write_text(
            f'home = {base_python.parent}\n'
            f'executable = {base_python}\ninclude-system-site-packages = false\n')
        self.command = ('PIP_CONFIG_FILE=/dev/null .getzilla/runtime/scratch/tools/bin/python -I -m pip '
                        '--isolated install --only-binary=:all: --no-cache-dir --disable-pip-version-check --ignore-installed '
                        '-r .getzilla/config/python-test-requirements.txt')

    def check(self, command):
        return evaluate_pre_tool(self.root, {'tool_name': 'Bash', 'tool_input': {'command': command}})

    def test_pinned_scratch_install_reads_requirements_and_writes_only_venv(self):
        allowed, reason = self.check(self.command)
        self.assertTrue(allowed, reason)
        second = self.root / '.getzilla/config/python-quality-requirements.txt'
        second.write_text('ruff==0.16.3\nbandit==1.9.4\n')
        allowed, reason = self.check(self.command + ' -r .getzilla/config/python-quality-requirements.txt')
        self.assertTrue(allowed, reason)

    def test_fixture_does_not_depend_on_the_test_runner_python_location(self):
        case = ScratchPipPolicyTest()
        try:
            with mock.patch.object(sys, 'executable', '/opt/hostedtoolcache/Python/3.13.17/x64/bin/python'):
                case.setUp()
            allowed, reason = case.check(case.command)
            self.assertTrue(allowed, reason)
        finally:
            case.doCleanups()

    def test_unsupported_pip_arguments_and_shell_forms_are_refused(self):
        variants = [self.command + suffix for suffix in (
            ' --target .getzilla/config', ' --prefix .grok', ' --root /tmp/root',
            ' --log AGENTS.md', ' --report README.md', ' --cache-dir .getzilla/config',
            ' --python /usr/bin/python3', ' -e .', ' .', ' git+https://example.invalid/repo',
            ' pytest', ' > AGENTS.md', ' && echo done', ' ; echo done', ' --no-binary=:all:',
            ' --target=.grok', ' --report=README.md', ' --prefix=.getzilla', ' --root=.grok',
            ' --log=AGENTS.md', ' --cache-dir=.grok', ' -t .grok',
        )]
        variants += [self.command.replace(flag, '') for flag in
                     ('PIP_CONFIG_FILE=/dev/null ', '-I ', '--isolated ', '--only-binary=:all: ',
                      '--no-cache-dir ', '--ignore-installed ')]
        variants += [self.command.replace('tools/bin/python', '../tools/bin/python'),
                     self.command.replace('tools/bin/python', '$VENV/bin/python')]
        for command in variants:
            with self.subTest(command=command):
                allowed, reason = self.check(command)
                self.assertFalse(allowed, reason)

    def test_nested_requirements_and_non_pins_are_refused(self):
        for content in ('-r other.txt\n', '--target .grok\n', '-e .\n', 'pytest>=9\n',
                        'pkg @ https://example.invalid/pkg.whl\n', 'pytest==9.1.1; python_version>="3"\n'):
            with self.subTest(content=content):
                self.requirements.write_text(content)
                self.assertFalse(self.check(self.command)[0])

    def test_venv_directory_escape_is_refused(self):
        external = self.root / 'external'
        external.mkdir()
        (self.venv / 'lib').rmdir()
        (self.venv / 'lib').symlink_to(external, target_is_directory=True)
        self.assertFalse(self.check(self.command)[0])

    def test_inline_program_guard_remains(self):
        self.assertFalse(self.check('python3 -c "open(\'AGENTS.md\', \'w\').write(\'x\')"')[0])

    def test_system_site_and_foreign_interpreters_are_refused(self):
        cfg = self.venv / 'pyvenv.cfg'
        original = cfg.read_text()
        cfg.write_text(original.replace('false', 'true'))
        self.assertFalse(self.check(self.command)[0])
        cfg.write_text(original)
        interpreter = self.venv / 'bin/python'
        interpreter.unlink()
        interpreter.symlink_to('/bin/sh')
        self.assertFalse(self.check(self.command)[0])

    def test_linked_requirements_and_venv_files_are_refused(self):
        original = self.requirements.read_text()
        target = self.root / 'pins.txt'
        target.write_text(original)
        self.requirements.unlink()
        self.requirements.symlink_to(target)
        self.assertFalse(self.check(self.command)[0])
        self.requirements.unlink()
        self.requirements.write_text(original)
        os.link(target, self.venv / 'shared.txt')
        self.assertFalse(self.check(self.command)[0])

    def test_supported_form_is_explained_when_pip_is_refused(self):
        allowed, reason = self.check(self.command + ' --prefix .grok')
        self.assertFalse(allowed)
        self.assertIn('Supported pip form:', reason)

    def test_uv_pip_installs_stay_denied_with_supported_pip_guidance(self):
        arguments = (' --python .getzilla/runtime/scratch/tools/bin/python '
                     '-r .getzilla/config/python-test-requirements.txt')
        for prefix in ('uv pip install', 'uv --offline pip install',
                       'uv --directory . pip install', 'uv pip --offline install',
                       'uv --color never --cache-dir /tmp/uv-cache pip install'):
            with self.subTest(prefix=prefix):
                allowed, reason = self.check(prefix + arguments)
                self.assertFalse(allowed, reason)
                self.assertIn('Supported pip form:', reason)

    def test_both_reported_uv_forms_remain_denied_with_actionable_guidance(self):
        prefix = 'uv pip install --python .getzilla/runtime/scratch/pr231-py314/bin/python '
        for arguments in (
            '-r .getzilla/config/python-test-requirements.txt -r .getzilla/config/python-quality-requirements.txt',
            'pytest==9.1.1 pytest-xdist==3.8.0 pytest-cov==7.1.0 coverage==7.15.4 '
            'jsonschema==4.26.0 ruff==0.16.3 bandit==1.9.4',
        ):
            with self.subTest(arguments=arguments):
                allowed, reason = self.check(prefix + arguments)
                self.assertFalse(allowed, reason)
                self.assertIn('Supported pip form:', reason)

    def test_uv_run_tool_and_help_are_not_pip_installs(self):
        from getzilla.shell_targets import is_pip_install

        for command in ('uv run pip install ruff', 'uv tool install ruff', 'uv help pip install',
                        'uv --offline tool install ruff', 'uv --directory pip install ruff'):
            with self.subTest(command=command):
                self.assertFalse(is_pip_install(command))

    def test_shared_venv_and_writable_ancestors_are_refused(self):
        self.venv.chmod(0o775)
        self.assertFalse(self.check(self.command)[0])
        self.venv.chmod(0o700)
        self.venv.parent.chmod(0o777)
        self.assertFalse(self.check(self.command)[0])


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
                'cd . > AGENTS.md', 'pushd . >> AGENTS.md',
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
