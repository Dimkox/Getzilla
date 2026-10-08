"""One-command installers: scripts/install.sh and scripts/install.ps1.

The shell installer is exercised end to end against a local clone of this
repository (no network: Grok install skipped, Git and Python already present).
The PowerShell installer is checked statically here; it is parsed and run under
pwsh when that is available on the host.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHELL = ROOT / 'scripts/install.sh'
POWERSHELL = ROOT / 'scripts/install.ps1'
RAW = 'https://raw.githubusercontent.com/Dimkox/Getzilla/main/scripts/'


def _toolchain_windows_install(tool: str) -> str:
    toolchain = json.loads((ROOT / '.getzilla/config/toolchain.json').read_text(encoding='utf-8'))
    item = next(entry for entry in toolchain['tools'] if entry['id'] == tool)
    return item['install']['windows']


def _clean_env(**extra: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith('GETZILLA_')}
    env.update(extra)
    return env


class InstallScriptContractTests(unittest.TestCase):
    def test_documented_one_liners_point_at_the_shipped_scripts(self) -> None:
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        quickstart = (ROOT / 'QUICKSTART.md').read_text(encoding='utf-8')
        for text in (readme, quickstart):
            self.assertIn(f'irm {RAW}install.ps1 | iex', text)
            self.assertIn(f'curl -fsSL {RAW}install.sh | bash', text)
        self.assertIn(f'irm {RAW}install.ps1 | iex', POWERSHELL.read_text(encoding='utf-8'))
        self.assertIn(f'curl -fsSL {RAW}install.sh | bash', SHELL.read_text(encoding='utf-8'))

    def test_shell_installer_only_acts_from_main(self) -> None:
        text = SHELL.read_text(encoding='utf-8')
        self.assertTrue(text.startswith('#!/usr/bin/env bash\n'))
        self.assertIn('  set -euo pipefail\n', text)
        self.assertTrue(text.rstrip().endswith('main "$@"'))
        # A truncated download must not run anything: no command outside functions.
        code = re.sub(r'<<EOF\n.*?\nEOF\n', '<<EOF\n', text, flags=re.S)
        body = [line for line in code.splitlines() if line and not line.startswith(('#', ' ', '}'))]
        self.assertTrue(all(re.match(r'^[a-z_]+\(\) \{', line) or line == 'main "$@"' for line in body), body)

    def test_powershell_installer_never_exits_the_callers_session(self) -> None:
        text = POWERSHELL.read_text(encoding='utf-8')
        self.assertIsNone(re.search(r'(?im)^\s*exit\b', text))
        self.assertTrue(text.rstrip().endswith('}'))
        self.assertIn('    Install-Getzilla\n', text)
        # The vendor installer runs in a child process, not via iex in this session.
        self.assertIn("-Command 'irm https://x.ai/cli/install.ps1 | iex'", text)

    def test_powershell_installer_uses_the_toolchain_package_ids(self) -> None:
        text = POWERSHELL.read_text(encoding='utf-8')
        self.assertIn("'Git.Git'", text)
        self.assertIn('--id Git.Git', _toolchain_windows_install('git'))
        python_ids = set(re.findall(r"'Python\.Python\.3\.(\d+)'", text))
        self.assertEqual(len(python_ids), 1)
        self.assertGreaterEqual(int(python_ids.pop()), 10)
        self.assertIn('/python-3.13.16-amd64.exe', text)
        self.assertIn('InstallAllUsers=0', text)

    def test_both_installers_offer_the_same_agents_and_settings(self) -> None:
        shell = SHELL.read_text(encoding='utf-8')
        powershell = POWERSHELL.read_text(encoding='utf-8')
        for text in (shell, powershell):
            for name in ('GETZILLA_AGENT', 'GETZILLA_PROVIDER', 'GETZILLA_MODEL', 'OPENROUTER_API_KEY',
                         'GETZILLA_SKIP_AGENT', 'GETZILLA_NONINTERACTIVE', 'getzilla_setup_agent.py', '--key-stdin',
                         '@qwen-code/qwen-code@latest', '@openai/codex@latest', 'https://openrouter.ai/keys',
                         '@google/gemini-cli@latest', '@github/copilot@latest', 'GEMINI_API_KEY',
                         'COPILOT_GITHUB_TOKEN', 'qwen, codex, claude, gemini, copilot or grok'):
                self.assertIn(name, text)
        self.assertIn('https://claude.ai/install.sh', shell)
        self.assertIn("-Command 'irm https://claude.ai/install.ps1 | iex'", powershell)
        self.assertIn('-AsSecureString', powershell)
        self.assertIn("$MinimumPowerShell = [version]'7.4'", powershell)
        self.assertIn("Invoke-Winget 'Microsoft.PowerShell'", powershell)
        toolchain = json.loads((ROOT / '.getzilla/config/toolchain.json').read_text(encoding='utf-8'))
        pwsh = next(item for item in toolchain['tools'] if item['id'] == 'pwsh')
        self.assertEqual(pwsh['minimum'], '7.4')
        self.assertIn('Microsoft.PowerShell', pwsh['install']['windows'])
        node = next(item for item in toolchain['tools'] if item['id'] == 'node')
        self.assertEqual(node['minimum'], '20.0')
        self.assertIn('read -rs key </dev/tty', shell)

    @unittest.skipIf(shutil.which('pwsh') is None, 'pwsh is not installed')
    def test_powershell_minimum_version_check_accepts_the_host_pwsh(self) -> None:
        command = (
            f"$ast = [System.Management.Automation.Language.Parser]::ParseFile('{POWERSHELL}', [ref]$null, [ref]$null); "
            '$ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | '
            'ForEach-Object { Invoke-Expression $_.Extent.Text }; '
            "$MinimumPowerShell = [version]'7.4'; "
            'function Test-Winget { $false }; Install-PowerShell7'
        )
        result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stdout, r'==> PowerShell: 7\.\d+')

    @unittest.skipIf(shutil.which('pwsh') is None, 'pwsh is not installed')
    def test_powershell_installer_parses(self) -> None:
        command = (
            '$errors = $null; '
            f"[void][System.Management.Automation.Language.Parser]::ParseFile('{POWERSHELL}', [ref]$null, [ref]$errors); "
            'if ($errors.Count) { $errors | ForEach-Object { $_.Message }; exit 1 }'
        )
        result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipIf(sys.platform == 'win32' or shutil.which('bash') is None or shutil.which('git') is None,
                 'needs bash and git')
class InstallScriptEndToEndTests(unittest.TestCase):
    def _run(self, home: Path, **extra: str) -> subprocess.CompletedProcess[str]:
        env = _clean_env(
            GETZILLA_HOME=str(home),
            GETZILLA_REPO=ROOT.as_uri(),
            GETZILLA_REF=subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=ROOT, capture_output=True, text=True, check=True
            ).stdout.strip(),
            GETZILLA_SKIP_AGENT='1',
            **extra,
        )
        return subprocess.run(['bash', str(SHELL)], env=env, capture_output=True, text=True, timeout=600)

    def test_installs_from_a_local_clone_and_reports_ready(self) -> None:
        if subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=ROOT, capture_output=True,
                          text=True).stdout.strip() == 'HEAD':
            self.skipTest('detached checkout: no branch to clone')
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'Getzilla'
            project = Path(tmp) / 'project'
            project.mkdir()
            result = self._run(home, GETZILLA_PROJECT=str(project))
            self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
            self.assertIn('Getzilla is ready in', result.stdout)
            self.assertIn('Install plan for', result.stdout)
            self.assertTrue((home / 'scripts/install_into.py').is_file())
            self.assertEqual(sorted(path.name for path in project.iterdir()), [])  # plan is read-only

            again = self._run(home)
            self.assertEqual(again.returncode, 0, again.stdout[-2000:] + again.stderr[-2000:])
            self.assertIn('Updating Getzilla in', again.stdout)

    def test_rejects_an_unknown_agent_before_downloading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'Getzilla'
            result = self._run(home, GETZILLA_AGENT='cursor')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('GETZILLA_AGENT must be qwen, codex, claude, gemini, copilot or grok', result.stderr)
            self.assertFalse(home.exists())

    def test_defaults_to_qwen_with_openrouter_and_configures_from_the_key(self) -> None:
        if subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=ROOT, capture_output=True,
                          text=True).stdout.strip() == 'HEAD':
            self.skipTest('detached checkout: no branch to clone')
        key = 'sk-or-v1-feedfacefeedfacefeedfacefeedface'
        with tempfile.TemporaryDirectory() as tmp:
            user_home = Path(tmp) / 'user'
            user_home.mkdir()
            env = _clean_env(
                HOME=str(user_home),
                GETZILLA_HOME=str(Path(tmp) / 'Getzilla'),
                GETZILLA_REPO=ROOT.as_uri(),
                GETZILLA_REF=subprocess.run(
                    ['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=ROOT, capture_output=True, text=True,
                    check=True,
                ).stdout.strip(),
                GETZILLA_NONINTERACTIVE='1',
                OPENROUTER_API_KEY=key,
                PATH=f'{Path(tmp) / "bin"}:{os.environ["PATH"]}',
            )
            fake_bin = Path(tmp) / 'bin'
            fake_bin.mkdir()
            (fake_bin / 'qwen').write_text('#!/bin/sh\nexit 0\n')
            (fake_bin / 'qwen').chmod(0o755)
            result = subprocess.run(['bash', str(SHELL)], env=env, capture_output=True, text=True, timeout=600)
            self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
            self.assertIn('Coding agent: qwen (models: openrouter)', result.stdout)
            self.assertIn('Qwen Code: already installed.', result.stdout)
            self.assertNotIn(key, result.stdout + result.stderr)
            self.assertIn(f"export OPENROUTER_API_KEY='{key}'",
                          (user_home / '.getzilla/openrouter.env').read_text(encoding='utf-8'))
            self.assertIn('.getzilla/openrouter.env', (user_home / '.bashrc').read_text(encoding='utf-8'))
            self.assertIn('In your project run: qwen', result.stdout)

    def test_refuses_a_foreign_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'occupied'
            home.mkdir()
            (home / 'keep.txt').write_text('mine', encoding='utf-8')
            result = self._run(home)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('is not a Getzilla checkout', result.stderr)
            self.assertEqual((home / 'keep.txt').read_text(encoding='utf-8'), 'mine')


if __name__ == '__main__':
    unittest.main()
