"""Installer427 regressions with explicit inert command/configuration effects."""
import sys
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import toolchain
from getzilla.agent_setup import configure

SPEC = dict(id='python3', name='Python', required=True, commands=['python3', 'python'],
            version_args=['--version'], minimum='3.10', built='3.12.3')


class InstallerProbeReadinessTests(unittest.TestCase):
    def check(self, responses):
        with patch.object(toolchain, 'command_exists', return_value=True), \
                patch.object(toolchain, 'run', side_effect=responses):
            return toolchain.check_tool(SPEC)

    def test_failed_or_unparseable_first_candidate_continues(self):
        for bad in (SimpleNamespace(returncode=1, stdout='Python 99.0.0', stderr='failed'),
                    SimpleNamespace(returncode=124, stdout='Python 99.0.0', stderr='timeout'),
                    SimpleNamespace(returncode=0, stdout='Store alias build 20261117', stderr='')):
            result = self.check([bad, SimpleNamespace(returncode=0, stdout='Python 3.14.1', stderr='')])
            self.assertEqual(result.status, 'pass')
            self.assertEqual(result.found, '3.14.1')
            self.assertTrue(result.command.endswith('python'))

    def test_unknown_actual_version_never_passes(self):
        result = self.check([SimpleNamespace(returncode=0, stdout='build 12345', stderr='')] * 2)
        self.assertEqual(result.status, 'fail')
        self.assertIsNone(result.found)

    def test_nonzero_banners_never_pass(self):
        result = self.check([SimpleNamespace(returncode=1, stdout='Python 3.14.1', stderr='')] * 2)
        self.assertEqual(result.status, 'fail')

    def test_git_windows_build_identity_is_not_discarded(self):
        with patch.object(toolchain, 'command_exists', return_value=True), patch.object(toolchain, 'run',
                return_value=SimpleNamespace(returncode=0, stdout='git version 2.56.1.windows.2', stderr='')):
            self.assertEqual(toolchain.detect_command(dict(id='git', commands=['git']))[1], '2.56.1.windows.2')

    def test_missing_credentials_and_native_login_are_pending(self):
        # These branches must not inspect or write the supplied home.
        with patch('getzilla.agent_setup._write_private', side_effect=AssertionError('unexpected write')):
            self.assertEqual(configure('qwen', 'openrouter', Path('/unused'), key=None).status,
                             'pending-credentials')
            self.assertEqual(configure('copilot', 'native', Path('/unused'), key=None).status,
                             'pending-authentication')

    def test_actual_timeout_exception_continues_to_valid_alias(self):
        result = self.check([subprocess.TimeoutExpired(['owned-python3', '--version'], 10),
                             SimpleNamespace(returncode=0, stdout='Python 4.0.0', stderr='')])
        self.assertEqual(result.found, '4.0.0')
        self.assertEqual(result.status, 'pass')

    def test_agent_version_records(self):
        # Linux --version captures for qwen, claude and codex. Gemini uses yargs
        # version(getVersion()). Copilot stable output: github/copilot-cli#4534.
        records = {'qwen': ('0.28.4', '0.28.4'), 'claude': ('2.1.201 (Claude Code)', '2.1.201'),
                   'codex': ('codex-cli 0.172.0', '0.172.0'), 'gemini': ('0.38.0', '0.38.0'),
                   'copilot': ('GitHub Copilot CLI 1.0.80.', '1.0.80')}
        for command, (banner, expected) in records.items():
            with self.subTest(command=command):
                actual = toolchain.parse_tool_version(command, banner+'\r\n')
                self.assertEqual(actual, expected)
                self.assertIsNone(toolchain.parse_tool_version(command, 'dependency '+banner))
                self.assertIsNone(toolchain.parse_tool_version(command, banner+'\n'+banner.replace(actual, '8.8.8')))
                self.assertIsNone(toolchain.parse_tool_version(command, banner.replace(actual, actual+'+dev')))
