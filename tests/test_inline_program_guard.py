"""Consumer S1 regressions exercise the native hook, without executing command payloads."""
from __future__ import annotations

import importlib
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / ".getzilla"), str(ROOT / ".grok/hooks")]
hooks = importlib.import_module("_lib")
pre = importlib.import_module("pre_tool_use")
state = importlib.import_module("getzilla.state")


class InlineProgramGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="inline-guard-")  # outside the repository: parallel tests copy its runtime
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.root = Path(cls.scratch.name)
        (cls.root / ".getzilla/config").mkdir(parents=True)
        (cls.root / ".getzilla/config/policy.json").write_text("{}\n")
        (cls.root / ".gitignore").write_text(".getzilla/runtime/\n")
        (cls.root / "README.md").write_text("Private native-hook fixture.\n")
        for relative in ("scripts", "nested/deeper", "ordinary/dev", "ordinary/proc/self/fd"):
            (cls.root / relative).mkdir(parents=True, exist_ok=True)
        for relative in ("stdin", "scripts/stdin", "ordinary/dev/stdin", "ordinary/proc/self/fd/0"):
            (cls.root / relative).write_text("Reviewable fixture; never executed.\n")
        for args in (("init", "-q"), ("config", "user.name", "Guard fixture"),
                     ("config", "user.email", "fixture@invalid.example"),
                     ("remote", "add", "origin", "https://github.com/fixture/guard.git"),
                     ("add", "."), ("commit", "-qm", "private fixture")):
            subprocess.run(["git", *args], cwd=cls.root, check=True, capture_output=True)
        state.set_active_route(cls.root, {"route_id": "inline-guard-fixture", "allowed_agents": ["bitrix_implementer"]})

    def denied(self, command, *, workdir=None):
        payload = {"tool_name": "exec_command", "tool_input": {"cmd": command, "workdir": str(workdir or self.root)},
                   "cwd": str(self.root), "session_id": "inline-guard-fixture"}
        return self.denied_payload(payload)

    def denied_payload(self, payload):
        output = []
        # Only observer/ledger bookkeeping is synthetic; parser, root resolution and policy run normally.
        with (mock.patch.object(pre, "read_payload", return_value=payload),
              mock.patch.object(pre, "emit", side_effect=output.append),
              mock.patch.object(pre, "_record_denial", return_value=(1, 1)),
              mock.patch("getzilla.agent_lifecycle.observe_tool")):
            pre.main()
        self.assertEqual(len(output), 1, output)
        result = output[0]
        return result.get("decision") == "deny" or result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    def test_php_inline_and_stdin_forms_fail_closed(self):
        commands = (
            "php -r 'echo 1;'", "php -r'echo 1;'", "php -nr'echo 1;'", "php8.3 -r'echo 1;'",
            "php -R'echo 1;'", "php -B'echo 1;' -F script.php", "php -F script.php -E'echo 1;'",
            "php --run='echo 1;'", "php --process-code='echo 1;'", "php --begin='echo 1;' -F script.php",
            "php --end='echo 1;' -F script.php", "php -a", "php", "php --", "php -- script.php",
            "php < payload.txt", "php 0<payload.txt", "0<payload.txt php", "php > output.txt",
            "php -n -d memory_limit=256M < payload.txt > output.txt", "php -f /dev/stdin",
            "php --file=php://stdin", "php -f /proc/self/fd/0", "php --unknown-option script.php",
            "sh -c 'php < payload.txt'", "nice -n 5 php < payload.txt",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(self.denied(command), command)
                self.assertIn("command.inline-program", hooks._command_directory_aliases(command))

    def test_python_inline_and_stdin_forms_fail_closed(self):
        commands = (
            "python3 -c 'print(1)'", "python3 -Bc'print(1)'", "python3 -- - < payload.txt",
            "python3 -B -- -", "python3 -W ignore -- -", "python3 -X dev -- -",
            "python3 --check-hash-based-pycs always -- -", "python3 --check-hash-based-pycs=never -- -",
            "python3", "python3 --", "python3 -B < payload.txt", "python3 0<payload.txt",
            "python3 > output.txt", "python3 /dev/stdin", "pypy3 /dev/fd/0",
            "python3.12 /proc/self/fd/0", "python3 -m", "python3 -W", "python3 --unknown-option script.py",
            "python3 -i script.py", "sh -c 'python3 -- - < payload.txt'",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(self.denied(command), command)
                self.assertIn("command.inline-program", hooks._command_directory_aliases(command))

    def test_reviewable_files_modules_and_diagnostics_remain_allowed(self):
        commands = (
            "php script.php", "php -n -d memory_limit=256M script.php", "php -l script.php",
            "php -f script.php", "php -fscript.php", "php --file=script.php", "php -F script.php < input.txt",
            "php -f script.php -- -r literal-data", "php script.php -r literal-data",
            "php -d '-r' script.php", "php -S 127.0.0.1:8087 -t public router.php", "php -S 127.0.0.1:8087",
            "php script.php < input.txt > output.txt", "php --version", "php --help", "php --ini",
            "python3 script.py", "python3 -B -X dev -W ignore script.py", "python3 -m unittest tests.test_getzilla_consumer_policy",
            "python3 -Imunittest tests.test_getzilla_consumer_policy", "python3 -- script.py",
            "python3 --check-hash-based-pycs always script.py", "python3 --check-hash-based-pycs=never script.py",
            "python3 -Xdev -Wignore script.py", "python3 script.py -c literal-data",
            "python3 -m json.tool < input.json", "python3 script.py 0<input.txt 1>output.txt",
            "python3 --version", "python3 --help-all", "git status --short",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertFalse(self.denied(command), command)
                self.assertNotIn("command.inline-program", hooks._command_directory_aliases(command))

    def test_native_hook_controls_depend_on_the_guard(self):
        for command in ("php -r'echo 1;'", "php < payload.txt", "python3 -- - < payload.txt"):
            with self.subTest(command=command):
                self.assertTrue(self.denied(command))
                with mock.patch.object(hooks, "_runs_inline_program", return_value=False):
                    self.assertFalse(self.denied(command), "Removing the guard must flip the verdict")

    def test_literal_bandit_argument_contract_reaches_native_policy(self):
        # These are command strings passed to the hook; no scanner is imported or executed.
        commands = (
            "python3 -m bandit -c bandit.yaml -q -f json -- example.py",
            "python3 -Imbandit -cbandit.yaml -o report.json -- example.py",
            "python3 -B -X dev -W ignore -m bandit --configfile=bandit.yaml --output=report.json -- example.py",
            "python3 -m bandit -c bandit.yaml -- -o AGENTS.md",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertFalse(self.denied(command), command)
                self.assertNotIn("command.inline-program", hooks._command_directory_aliases(command))

    def test_bandit_contract_preserves_native_denials(self):
        commands = (
            "python3 -m bandit -c bandit.yaml -o AGENTS.md",
            "python3 -m bandit --configfile bandit.yaml -o=AGENTS.md",
            "python3 -m bandit -c bandit.yaml --output=AGENTS.md",
            "python3 -m bandit -c bandit.yaml --output-file=AGENTS.md",
            "python3 -m bandit -c bandit.yaml > AGENTS.md",
            "python3 -m bandit -c bandit.yaml -- .env",
            "python3 -c 'print(1)' -m bandit -c bandit.yaml",
            "python3 -Bc'print(1)' -m bandit -c bandit.yaml",
            "python3 -i -m bandit -c bandit.yaml",
            "python3 --unknown -m bandit -c bandit.yaml",
            "python3 -X pycache_prefix=.getzilla/config -m bandit -c bandit.yaml",
            "python3 -W ignore::fixture_setup.Warning -m bandit -c bandit.yaml",
            "python3 -X pycache_prefix=.getzilla/config -m bandit --configfile bandit.yaml",
            "python3 /dev/stdin -m bandit -c bandit.yaml",
            'python3 -m "$MODULE" -c bandit.yaml',
            "nice python3 -m bandit -c bandit.yaml",
            "sh -c 'python3 -m bandit -c bandit.yaml'",
            "python3 fixture_check.py -c bandit.yaml",
            "python3 -m bandit -qoAGENTS.md -- example.py",
            "python3 -m bandit --out AGENTS.md -- example.py",
            "python3 -m bandit --output-fileAGENTS.md -- example.py",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(self.denied(command), command)

    def test_wrapped_bandit_outputs_reach_native_policy_without_short_config(self):
        for command in ('nice python3 -m unittest', "sh -c 'python3 -m unittest'"):
            self.assertFalse(self.denied(command), command)
        for config in ('', '--configfile bandit.yaml '):
            for output in ('-o AGENTS.md', '-oAGENTS.md'):
                inner = 'python3 -m bandit ' + config + output + ' -- example.py'
                self.assertTrue(self.denied(inner), 'Direct protected output control')
                for command in ('nice ' + inner, 'sh -c ' + shlex.quote(inner)):
                    with self.subTest(command=command):
                        self.assertNotIn('command.inline-program', hooks._command_directory_aliases(command))
                        self.assertTrue(self.denied(command), command)

    def test_attached_scanner_paths_reach_native_secret_policy(self):
        for option in ('-cpublic.yaml', '-opublic.json', '-c.env.example', '-o.env.example'):
            command = 'python3 -m bandit ' + option + ' -- example.py'
            self.assertFalse(self.denied(command), command)
        for option in ('-c .env', '-c.env', '-c=.env', '--configfile=.env',
                       '-o .env', '-o.env', '-o=.env', '--output=.env'):
            with self.subTest(option=option):
                command = 'python3 -m bandit ' + option + ' -- example.py'
                self.assertNotIn('command.inline-program', hooks._command_directory_aliases(command))
                self.assertTrue(self.denied(command), command)

    def test_scanner_directory_relative_secrets_reach_native_policy(self):
        policy = self.root / '.getzilla/config/policy.json'
        original = policy.read_text()
        self.addCleanup(policy.write_text, original)
        policy.write_text('{"secret_read_paths": ["nested/fixture-sensitive.json"]}\n')
        for operand in (
            '-c fixture-sensitive.json -- example.py',
            '-cfixture-sensitive.json -- example.py',
            '--configfile=fixture-sensitive.json -- example.py',
            '-o fixture-sensitive.json -- example.py',
            '-ofixture-sensitive.json -- example.py',
            '--output=fixture-sensitive.json -- example.py',
            'fixture-sensitive.json', '-- fixture-sensitive.json',
        ):
            for prefix in ('cd nested && ', 'cd nested; '):
                command = prefix + 'python3 -m bandit ' + operand
                with self.subTest(command=command):
                    if prefix.endswith('&& '):
                        self.assertNotIn('command.inline-program', hooks._command_directory_aliases(
                            command, cwd=str(self.root)))
                    self.assertTrue(self.denied(command), command)
        self.assertFalse(self.denied(
            'cd nested && python3 -m bandit -cpublic.yaml -opublic.json -- example.py'))
        # Native root resolution already refuses ambiguous || directory branches.
        self.assertTrue(self.denied(
            'cd nested || python3 -m bandit -cfixture-sensitive.json -- example.py'))
        self.assertTrue(self.denied('cd "$DESTINATION" && python3 -m bandit -- example.py'))
        policy.write_text('{}\n')
        self.assertFalse(self.denied(
            'cd nested && python3 -m bandit -c.env.example -o.env.example -- example.py'))

    def test_scanner_paths_use_validated_native_execution_directory(self):
        policy = self.root / '.getzilla/config/policy.json'
        original = policy.read_text()
        self.addCleanup(policy.write_text, original)
        policy.write_text('{"secret_read_paths": ["nested/fixture-sensitive.json", '
                          '"nested/deeper/fixture-sensitive.json"]}\n')
        contexts = (
            ({'cwd': str(self.root)}, {'workdir': str(self.root / 'nested')}, self.root / 'nested'),
            ({'cwd': str(self.root / 'nested')}, {'workdir': 'deeper'}, self.root / 'nested/deeper'),
            ({'cwd': str(self.root / 'nested')}, {}, self.root / 'nested'),
            ({'cwd': str(self.root / 'nested'), 'workspaceRoot': str(self.root)}, {}, self.root / 'nested'),
            ({'workspaceRoot': str(self.root)}, {'workdir': str(self.root / 'nested')}, self.root / 'nested'),
        )
        for session, directories, actual_cwd in contexts:
            payload = {'tool_name': 'exec_command', 'session_id': 'inline-guard-fixture', **session}
            for operand in ('-cfixture-sensitive.json -- example.py',
                            '--configfile=fixture-sensitive.json -- example.py',
                            '-ofixture-sensitive.json -- example.py', '-- fixture-sensitive.json'):
                with self.subTest(session=session, directories=directories, operand=operand):
                    payload['tool_input'] = {'cmd': 'python3 -m bandit ' + operand, **directories}
                    self.assertTrue(self.denied_payload(payload), payload)
            protected = shlex.quote(os.path.relpath(self.root / 'AGENTS.md', actual_cwd))
            payload['tool_input'] = {'cmd': 'python3 -m bandit -o ' + protected, **directories}
            self.assertTrue(self.denied_payload(payload), payload)
            payload['tool_input'] = {'cmd': 'python3 -m bandit -cpublic.yaml -opublic.json -- example.py', **directories}
            self.assertFalse(self.denied_payload(payload), payload)

        # Untrusted tool fields cannot replace the separately propagated native cwd.
        payload = {'tool_name': 'exec_command', 'cwd': str(self.root), 'session_id': 'inline-guard-fixture',
                   'tool_input': {'cmd': 'python3 -m bandit -cfixture-sensitive.json -- example.py',
                                  'workdir': str(self.root / 'nested'), 'execution_cwd': str(self.root)}}
        self.assertTrue(self.denied_payload(payload), payload)
        for session, directories in (
            ({'cwd': str(self.root)}, {'workdir': str(self.root / 'nested'), 'cwd': str(self.root)}),
            ({'workspaceRoot': str(self.root)}, {}),
            ({'workspaceRoot': str(self.root)}, {'workdir': 'nested'}),
        ):
            payload = {'tool_name': 'exec_command', 'session_id': 'inline-guard-fixture', **session,
                       'tool_input': {'cmd': 'python3 -m bandit -- example.py', **directories}}
            with self.subTest(unresolved=payload):
                self.assertTrue(self.denied_payload(payload), payload)
        payload = {'tool_name': 'exec_command', 'workspaceRoot': str(self.root),
                   'tool_input': {'cmd': 'nice python3 -m unittest'}}
        self.assertFalse(self.denied_payload(payload), 'Ordinary wrapped Python keeps its existing decision')

    def test_native_scanner_mixed_directory_branch_refusal_is_retained(self):
        for prefix in ('cd nested || true; ', 'cd nested || true && '):
            for operand in ('-cfixture-sensitive.json -- example.py',
                            '--configfile=fixture-sensitive.json -- example.py',
                            '-ofixture-sensitive.json -- example.py', '-- fixture-sensitive.json'):
                command = prefix + 'python3 -m bandit ' + operand
                with self.subTest(command=command):
                    self.assertTrue(self.denied(command), command)

    def test_native_scanner_rejects_skipped_directory_joins(self):
        policy = self.root / '.getzilla/config/policy.json'
        original = policy.read_text()
        self.addCleanup(policy.write_text, original)
        policy.write_text('{"secret_read_paths": ["nested/fixture-sensitive.json"]}\n')
        for separator in ('; ', '\n', ' & '):
            for operand in ('-cfixture-sensitive.json -- example.py',
                            '--configfile=fixture-sensitive.json -- example.py',
                            '-ofixture-sensitive.json -- example.py', '-- fixture-sensitive.json'):
                command = 'false && cd deeper && true' + separator + 'python3 -m bandit ' + operand
                with self.subTest(command=command):
                    self.assertTrue(self.denied(command, workdir=self.root / 'nested'), command)
        self.assertFalse(self.denied(
            'cd deeper && true && python3 -m bandit -cpublic.yaml -- example.py',
            workdir=self.root / 'nested'))

    def test_lexical_stream_and_descriptor_aliases_fail_closed(self):
        paths = (
            "/dev/./stdin", "/dev//stdin", "/dev/../dev/stdin", "//dev/stdin", "///dev/stdin",
            "/dev/./fd/0", "/dev//fd/0", "/proc/self/./fd/0", "/proc/self/fd/../fd/0",
            "/proc/123/fd/0", "/proc/thread-self/fd/0", "/proc/thread-self/./fd/0",
            "/proc/self/task/456/fd/0", "/proc/123/task/456/fd/0", "/proc/123/task/456/./fd/0",
        )
        for path in paths:
            for command in ("php --file=" + shlex.quote(path), "python3 -- " + shlex.quote(path)):
                with self.subTest(command=command):
                    self.assertTrue(self.denied(command), command)
        # Exact review reproductions, including PHP's separate -f argument.
        for command in ("php -f /dev/./stdin", "php -f /dev//stdin", "python3 /dev/./stdin"):
            with self.subTest(command=command):
                self.assertTrue(self.denied(command), command)

    def test_relative_stream_aliases_follow_native_workdir_and_literal_cd(self):
        for directory in (self.root, self.root / "nested/deeper"):
            for target in ("/dev/./stdin", "/dev/./fd/0", "/proc/thread-self/fd/0", "/proc/self/task/456/fd/0"):
                relative = shlex.quote(os.path.relpath(target, directory))
                with self.subTest(directory=str(directory), target=target):
                    self.assertTrue(self.denied("python3 " + relative, workdir=directory))
                    self.assertTrue(self.denied("php -f " + relative, workdir=directory))
        relative = shlex.quote(os.path.relpath("/dev/stdin", self.root / "nested/deeper"))
        for command in ("cd nested/deeper && php -f " + relative,
                        "cd nested; cd deeper; python3 " + relative,
                        "sh -c " + shlex.quote("cd nested/deeper; python3 " + relative),
                        "cd /dev; php -f ./stdin",
                        "php -f ./stdin"):
            with self.subTest(command=command):
                self.assertTrue(self.denied(command, workdir="/dev" if command == "php -f ./stdin" else None))

    def test_ordinary_program_paths_named_stdin_remain_allowed(self):
        for command in ("php -f ./stdin", "python3 ./scripts/../stdin", "php --file=scripts/./stdin",
                        "python3 ordinary/dev/stdin", "php -f ordinary/proc/self/fd/0",
                        "cd scripts && python3 ./stdin", "cd scripts; php -f ../stdin",
                        "sh -c 'cd scripts; python3 ./stdin'",
                        "python3 " + shlex.quote(str(self.root / "ordinary/dev/stdin"))):
            with self.subTest(command=command):
                self.assertFalse(self.denied(command), command)
        self.assertFalse(self.denied("python3 ../../stdin", workdir=self.root / "nested/deeper"))

    def test_native_alias_controls_depend_on_lexical_normalization(self):
        for command in ("php -f /dev/./stdin", "python3 -- /dev//stdin", "php --file=/dev/../dev/stdin"):
            with self.subTest(command=command):
                self.assertTrue(self.denied(command))
                with mock.patch.object(hooks, "_lexical_program_path", side_effect=lambda value: value):
                    self.assertFalse(self.denied(command), "Removing normalization must expose the reported alias")

    def test_shell_expanded_program_selectors_fail_closed(self):
        commands = (
            "php -f ~/../../dev/stdin < payload.txt", "python3 ~/../../dev/stdin < payload.txt",
            "python3 ~root/program.py", "php -f ~+/program.php", "python3 ~-/program.py",
            "nice -n 5 php -f ~/../../dev/stdin", "timeout 5 python3 ~/../../dev/stdin",
            "sh -c 'python3 ~/../../dev/stdin'",
            'php --file="$PROGRAM"', 'php -f"$PROGRAM"', 'php -f "$PROGRAM"',
            'python3 "$PROGRAM"', 'python3 -- "$PROGRAM"', 'python3 -m "$MODULE"',
            "python3 *.py", "php -f ./script?.php", "python3 ./{one,two}.py",
            "python3 ./script[12].py", 'cd "$DIRECTORY"; python3 script.py',
            'sh -c "$COMMAND"',
            "python3 FILE=~/program.py", "php -f FILE=literal:~/program.php",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(self.denied(command), command)

    def test_literal_program_paths_and_expanded_script_data_remain_allowed(self):
        commands = (
            "php -f '~/../../dev/stdin' < payload.txt", "python3 '~/../../dev/stdin' < payload.txt",
            'php -f "~/../../dev/stdin"', 'python3 "~/../../dev/stdin"',
            r"python3 \~/../../dev/stdin", r"php -f \~/../../dev/stdin",
            "php --file='~/../../dev/stdin'", 'php --file="~/../../dev/stdin"',
            "php -f'~/../../dev/stdin'", "python3 '$PROGRAM'", r'python3 "\$PROGRAM"',
            "python3 '*.py'", r"php -f ./script\?.php", "python3 './script[12].py'",
            'python3 script.py "$DATA"', "python3 script.py ~/../../dev/stdin",
            'python3 -m unittest "$DATA"', 'php script.php "$DATA"',
            'php -f script.php "$DATA"', 'php -f script.php -- "$DATA"',
            "php script.php *.php", "nice -n 5 python3 '~/../../dev/stdin'",
            "sh -c 'python3 script.py \"$DATA\"'",
            "python3 'FILE=~/program.py'", "python3 script.py FILE=~/data.txt",
            'MODE="$DATA" python3 script.py', "CACHE=~/cache php script.php",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertFalse(self.denied(command), command)

    def test_expansion_keeps_existing_interpreter_inline_options_denied(self):
        for command in ('node --eval="$PROGRAM"', 'bun --eval="$PROGRAM"',
                        'perl -e"$PROGRAM"', 'ruby -e"$PROGRAM"'):
            with self.subTest(command=command):
                self.assertTrue(self.denied(command), command)

    def test_expanded_program_controls_depend_on_token_provenance(self):
        for command in ("php -f ~/../../dev/stdin < payload.txt", "python3 ~/../../dev/stdin < payload.txt",
                        'php --file="$PROGRAM"', 'python3 "$PROGRAM"'):
            with self.subTest(command=command):
                self.assertTrue(self.denied(command))
                with mock.patch.object(hooks, "_opaque_shell_words", side_effect=lambda command: command):
                    self.assertFalse(self.denied(command), "Removing token provenance must expose an opaque program")

    def test_installed_hook_is_the_subject(self):
        self.assertEqual(Path(hooks.__file__).resolve(), ROOT / ".grok/hooks/_lib.py")
        self.assertEqual(Path(pre.__file__).resolve(), ROOT / ".grok/hooks/pre_tool_use.py")


if __name__ == "__main__":
    unittest.main()
