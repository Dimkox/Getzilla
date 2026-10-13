import importlib.util
import sys
import unittest

from tests._support import PROJECT, project_copy, run_hook


def load_hook(name):
    hooks = PROJECT / '.grok/hooks'
    sys.path.insert(0, str(hooks))
    spec = importlib.util.spec_from_file_location('argument_probe_' + name, hooks / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CommandArgumentRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib = load_hook('_lib')

    def test_local_scan_target_is_an_argument_not_source_builtin(self):
        commands = (
            'trivy config --exit-code 1 .',
            'taskset -c 20-23 timeout 180s trivy config --exit-code 1 --skip-dirs .git --skip-dirs .getzilla/runtime .',
            'python3 -m unittest discover .',
            'printf %s source',
        )
        for command in commands:
            with self.subTest(command=command):
                context = self.lib.root_context(
                    {'cwd': str(PROJECT)},
                    {'command': command, 'workdir': str(PROJECT)},
                    'Bash',
                )
                self.assertTrue(context.sensitive_safe, context.command_workdirs)

    def test_actual_dynamic_shell_dispatch_remains_ambiguous(self):
        for command in (
            '. fixture.sh', 'source fixture.sh', 'eval fixture',
            'true && . fixture.sh', 'true && command . fixture.sh',
            'timeout 5s command source fixture.sh',
        ):
            with self.subTest(command=command):
                aliases = self.lib._command_directory_aliases(command)
                self.assertIn('<ambiguous>', aliases.values())

    def test_quoted_metacharacters_are_literal_arguments(self):
        for command in (
            "rg 'left|right' docs",
            "python3 -c 'print(1); print(2)'",
            'printf %s "literal (value); left|right"',
            "printf %s '$(literal)'",
        ):
            with self.subTest(command=command):
                aliases = self.lib._command_directory_aliases(command)
                self.assertNotIn('<ambiguous>', aliases.values())

    def test_real_operators_and_substitutions_remain_ambiguous(self):
        for command in (
            'true; false', 'true | false', '(true)',
            'printf %s "$(fixture)"', 'printf %s `fixture`',
        ):
            with self.subTest(command=command):
                aliases = self.lib._command_directory_aliases(command)
                self.assertIn('<ambiguous>', aliases.values())

    def test_native_payload_reaches_policy_without_executing_its_command(self):
        with project_copy() as root:
            payload = {'cwd': str(root), 'session_id': 'root-argument-fixture',
                       'tool_name': 'exec_command', 'tool_input': {'workdir': str(root)}}
            for command in ('trivy config --exit-code 1 .', "rg 'left|right' docs"):
                with self.subTest(command=command):
                    payload['tool_input']['cmd'] = command
                    code, result, error = run_hook(root, 'pre_tool_use.py', payload)
                    self.assertEqual(code, 0, error)
                    self.assertEqual(result['decision'], 'allow', result)
            payload['tool_input']['cmd'] = 'git push origin main'
            code, result, error = run_hook(root, 'pre_tool_use.py', payload)
            self.assertEqual(code, 0, error)
            self.assertEqual(result['decision'], 'deny', result)


class IndependentDenialObjectiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib = load_hook('_lib')
        cls.hook = load_hook('pre_tool_use')

    def objective(self, command, action='ambiguous-sensitive-shell'):
        context = self.lib.RootContext(str(PROJECT), PROJECT, {}, None, 'ambiguous-command-root')
        return self.hook._denial_fingerprints(
            'fixture-session', 'Bash', {'command': command},
            'fixture ambiguous root', context, action,
        )[1]

    def test_unrelated_ambiguous_commands_have_independent_retry_budgets(self):
        commands = ('rg pattern first', 'python3 -c fixture', 'trivy config first', 'rg pattern second')
        self.assertEqual(len({self.objective(command) for command in commands}), len(commands))

    def test_cosmetic_rewrite_keeps_same_objective(self):
        self.assertEqual(self.objective('rg pattern first'), self.objective("rg   'pattern'  first"))

    def test_known_sensitive_action_keeps_existing_grouping(self):
        self.assertEqual(
            self.objective('fixture first', 'external-write'),
            self.objective('fixture second', 'external-write'),
        )


if __name__ == '__main__':
    unittest.main()
