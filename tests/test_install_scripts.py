"""One-command installers: scripts/install.sh and scripts/install.ps1.

The shell installer is exercised end to end against a local clone of this
repository, in a throwaway HOME and without network: the security data and the
workflow baseline come from a fixture mirror (GETZILLA_UPDATE_MIRROR), pip
from stand-in wheels, and every proxy variable points at a closed port.
GETZILLA_E2E_TOOLCHAINS=1 adds one run against the real download hosts.
The PowerShell installer is checked statically here; it is parsed and run under
pwsh when that is available on the host.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tests._support import offline_mirror

ROOT = Path(__file__).resolve().parents[1]
SHELL = ROOT / 'scripts/install.sh'
POWERSHELL = ROOT / 'scripts/install.ps1'
RAW = 'https://raw.githubusercontent.com/Dimkox/Getzilla/main/scripts/'
E2E = os.environ.get('GETZILLA_E2E_TOOLCHAINS') == '1'
# Any HTTP(S) request the offline installer still makes fails at once instead of downloading.
NO_NETWORK = {name: 'http://127.0.0.1:9' for name in
              ('http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')}


def _toolchain_windows_install(tool: str) -> str:
    toolchain = json.loads((ROOT / '.getzilla/config/toolchain.json').read_text(encoding='utf-8'))
    item = next(entry for entry in toolchain['tools'] if entry['id'] == tool)
    return item['install']['windows']


def _clean_env(**extra: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith('GETZILLA_')}
    env.update(extra)
    return env


def _wheelhouse(base: Path) -> Path:
    """Empty stand-in wheels at the pinned versions of Getzilla's test and quality tools, for pip offline."""
    house = base / 'wheels'
    house.mkdir()
    for name in ('python-test-requirements.txt', 'python-quality-requirements.txt'):
        for line in (ROOT / '.getzilla/config' / name).read_text(encoding='utf-8').splitlines():
            requirement = line.split('#', 1)[0].strip()
            if not requirement:
                continue
            project, version = requirement.split('==')
            dist = re.sub(r'[-_.]+', '_', project).lower()
            info = f'{dist}-{version}.dist-info'
            with zipfile.ZipFile(house / f'{dist}-{version}-py3-none-any.whl', 'w') as wheel:
                wheel.writestr(f'{info}/METADATA', f'Metadata-Version: 2.1\nName: {project}\nVersion: {version}\n')
                wheel.writestr(f'{info}/WHEEL', 'Wheel-Version: 1.0\nGenerator: getzilla-tests\n'
                                                'Root-Is-Purelib: true\nTag: py3-none-any\n')
                wheel.writestr(f'{info}/RECORD', f'{info}/METADATA,,\n{info}/WHEEL,,\n{info}/RECORD,,\n')
    return house


def _branch() -> str:
    return subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=ROOT, capture_output=True, text=True,
                          check=True).stdout.strip()


class InstallScriptContractTests(unittest.TestCase):
    def test_documented_install_checks_sha256_of_the_pinned_installer_before_running_it(self) -> None:
        # Issue #63: the documented install path must not pipe an unverified download into a shell.
        # Install commands use the observed immutable publication, which can precede the source candidate.
        state = json.loads((ROOT / 'PROJECT_STATE.json').read_text(encoding='utf-8'))
        published = state['published_release']
        tag = published['tag']
        self.assertEqual(published['repository'], 'Dimkox/Getzilla')
        self.assertEqual(state['latest_published_release'], tag)
        self.assertRegex(tag, r'^v[0-9]+\.[0-9]+\.[0-9]+$')
        self.assertRegex(published['tag_object'], r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')
        self.assertEqual(state['product_version'], (ROOT / 'VERSION').read_text(encoding='utf-8').strip())
        version = tag.removeprefix('v')
        pinned = f'https://raw.githubusercontent.com/Dimkox/Getzilla/{tag}/scripts/'
        # The documented commands fetch the published installers, so they carry the published
        # digests (bound to the tag bytes by the test below), never the source candidate's.
        self.assertEqual(set(published['installers']), {'scripts/install.sh', 'scripts/install.ps1'})
        sh_digest = published['installers']['scripts/install.sh']['sha256']
        ps_digest = published['installers']['scripts/install.ps1']['sha256']
        for digest in (sh_digest, ps_digest):
            self.assertRegex(digest, r'^[0-9a-f]{64}$')
        # Source installers equal the published ones or are a declared candidate of this version:
        # an undeclared installer change still fails.
        source = {
            'scripts/install.sh': {'sha256': hashlib.sha256(SHELL.read_bytes()).hexdigest()},
            'scripts/install.ps1': {'sha256': hashlib.sha256(POWERSHELL.read_bytes()).hexdigest()},
        }
        if source != published['installers']:
            candidate = state.get('source_installers') or {}
            self.assertEqual(candidate.get('status'), 'source_candidate')
            self.assertEqual(candidate.get('version'), state['product_version'])
            self.assertEqual(candidate.get('installers'), source)
        for name in ('README.md', 'QUICKSTART.md'):
            text = (ROOT / name).read_text(encoding='utf-8')
            with self.subTest(document=name):
                self.assertNotIn(f'{RAW}install.sh | bash', text)
                self.assertNotIn(f'{RAW}install.ps1 | iex', text)
                self.assertNotRegex(text, r'Getzilla/[^/\s]+/scripts/install\.(sh \| *(ba)?sh|ps1 \| *iex)')
                sh_fetch = text.index(f'curl -fsSLo getzilla-install.sh {pinned}install.sh')
                sh_run = f'GETZILLA_REF=v{version} bash getzilla-install.sh'
                lines = text.splitlines()
                # The check and the run must be one fail-stop command line (`check && run`), so a
                # line-by-line paste cannot reach the installer after a failed check (Linux and macOS).
                for tool in ('sha256sum -c -', 'shasum -a 256 -c -'):
                    line = f'echo "{sh_digest}  getzilla-install.sh" | {tool} && {sh_run}'
                    self.assertIn(line, lines)
                    self.assertLess(sh_fetch, text.index(line))
                for line in lines:
                    if 'bash getzilla-install.sh' in line:
                        self.assertRegex(line, rf'^echo "{sh_digest}  getzilla-install\.sh" \| (sha256sum|shasum -a 256) -c - && ')
                ps_fetch = text.index(f'Invoke-WebRequest -UseBasicParsing {pinned}install.ps1 -OutFile $f')
                ps_line = (
                    f"if ((Get-FileHash $f -Algorithm SHA256).Hash -eq '{ps_digest.upper()}') "
                    f"{{ $env:GETZILLA_REF = 'v{version}'; Invoke-Expression (Get-Content -Raw $f) }} "
                    "else { throw 'install.ps1 SHA-256 mismatch: do not run it' }"
                )
                self.assertIn(ps_line, lines)
                self.assertLess(ps_fetch, text.index(ps_line))
                self.assertEqual([line for line in lines if 'Invoke-Expression (Get-Content -Raw $f)' in line], [ps_line])

    def test_published_installer_digests_are_the_bytes_at_the_published_tag(self) -> None:
        state = json.loads((ROOT / 'PROJECT_STATE.json').read_text(encoding='utf-8'))
        published = state['published_release']
        if not (ROOT / '.git').exists():
            self.skipTest('a release archive carries no Git history to read the published tag from')
        tag = published['tag']
        resolved = subprocess.run(['git', 'rev-parse', '--verify', '--quiet', f'refs/tags/{tag}'],
                                  cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(resolved.returncode, 0, f'tag {tag} is not available locally; CI checks out with fetch-depth: 0')
        self.assertEqual(resolved.stdout.strip(), published['tag_object'])
        for path, record in published['installers'].items():
            blob = subprocess.run(['git', 'cat-file', 'blob', f'{tag}:{path}'], cwd=ROOT,
                                  capture_output=True, check=False)
            self.assertEqual(blob.returncode, 0, path)
            self.assertEqual(hashlib.sha256(blob.stdout).hexdigest(), record['sha256'], path)

    def test_published_install_contract_allows_a_new_source_version_without_git_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix='getzilla-install-contract-') as temporary:
            root = Path(temporary)
            for relative in ('VERSION', 'PROJECT_STATE.json', 'README.md', 'QUICKSTART.md',
                             'scripts/install.sh', 'scripts/install.ps1'):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            state = json.loads((root / 'PROJECT_STATE.json').read_text(encoding='utf-8'))
            state['product_version'] = '9.9.9'
            if 'source_installers' in state:  # the declared candidate follows the source version
                state['source_installers']['version'] = '9.9.9'
            (root / 'VERSION').write_text('9.9.9\n', encoding='utf-8')
            (root / 'PROJECT_STATE.json').write_text(json.dumps(state), encoding='utf-8')
            self.assertFalse((root / '.git').exists())
            with patch.dict(globals(), ROOT=root, SHELL=root / 'scripts/install.sh',
                            POWERSHELL=root / 'scripts/install.ps1'):
                self.test_documented_install_checks_sha256_of_the_pinned_installer_before_running_it()
                for field, invalid in (('repository', 'other/project'), ('tag', 'main'),
                                       ('tag_object', 'HEAD'), ('installers', {})):
                    mutated = json.loads(json.dumps(state))
                    mutated['published_release'][field] = invalid
                    (root / 'PROJECT_STATE.json').write_text(json.dumps(mutated), encoding='utf-8')
                    with self.assertRaises(AssertionError):
                        self.test_documented_install_checks_sha256_of_the_pinned_installer_before_running_it()
                (root / 'PROJECT_STATE.json').write_text(json.dumps(state), encoding='utf-8')
                (root / 'scripts/install.sh').write_bytes(b'changed unpublished installer\n')
                with self.assertRaises(AssertionError):
                    self.test_documented_install_checks_sha256_of_the_pinned_installer_before_running_it()

    def test_hashed_installers_keep_lf_endings_in_every_checkout(self) -> None:
        # The documented digests hash the repository bytes; an eol rule keeps Windows checkouts identical.
        rules = (ROOT / '.gitattributes').read_text(encoding='utf-8').splitlines()
        for path in ('scripts/install.sh', 'scripts/install.ps1'):
            self.assertIn(f'{path} text eol=lf', rules)

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
        # Python comes per user from the pinned python.org installer, never through winget: winget's
        # install waited on a hidden elevation prompt in a clean Windows Sandbox.
        self.assertNotRegex(text, r"Invoke-Winget 'Python\.Python")
        self.assertIn('/python-3.13.16-amd64.exe', text)
        # Only needed MSI packages (each signature check can wait ~2 minutes on a fresh Windows), a
        # 30-minute ceiling with progress, and a log for diagnosis.
        for switch in ('InstallAllUsers=0', 'Include_launcher=0', 'InstallLauncherAllUsers=0', 'Include_tcltk=0',
                       'Include_dev=0',
                       "'/log'", 'while (-not $process.WaitForExit(30000))', 'New-TimeSpan -Minutes 30'):
            self.assertIn(switch, text)
        self.assertNotIn('Start-Process -FilePath $installer -Wait', text)

    def test_both_installers_offer_the_same_agents_and_settings(self) -> None:
        shell = SHELL.read_text(encoding='utf-8')
        powershell = POWERSHELL.read_text(encoding='utf-8')
        for text in (shell, powershell):
            for name in ('GETZILLA_AGENT', 'GETZILLA_PROVIDER', 'GETZILLA_MODEL', 'OPENROUTER_API_KEY',
                         'GETZILLA_SKIP_AGENT', 'GETZILLA_NONINTERACTIVE', 'getzilla_setup_agent.py', '--key-stdin',
                         '@qwen-code/qwen-code@latest', '@openai/codex@latest', 'https://openrouter.ai/keys',
                         '@google/gemini-cli@latest', '@github/copilot@latest', 'GEMINI_API_KEY',
                         'COPILOT_GITHUB_TOKEN', 'qwen, codex, claude, gemini, copilot or grok',
                         'scripts/getzilla_update.py', 'getzilla_baseline.py'):
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

    def test_powershell_installer_installs_winget_or_falls_back_to_direct_downloads(self) -> None:
        text = POWERSHELL.read_text(encoding='utf-8')
        for needle in ('    Initialize-Winget\n', 'releases/download/v1.29.380/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle',
                       'releases/download/v1.29.380/DesktopAppInstaller_Dependencies.zip',
                       'Add-AppxPackage -Path $package -DependencyPath $paths', 'GETZILLA_SKIP_WINGET',
                       'https://nodejs.org/dist/v24.20.0/node-v24.20.0-win-x64.zip'):
            self.assertIn(needle, text)
        self.assertLess(text.index('    Initialize-Winget\n'), text.index('    if (-not (Get-Command git'))

    def test_both_installers_always_refresh_vulnerability_data(self) -> None:
        # The CVE database, OpenGrep and the pinned workflow baseline are part of a working install:
        # installed on every run without a question, and a failure stops the install (owner decision
        # 2026-10-16: mandatory, no option to skip).
        shell = SHELL.read_text(encoding='utf-8')
        powershell = POWERSHELL.read_text(encoding='utf-8')
        self.assertIn('scripts/getzilla_update.py --only osv --only opengrep', shell)
        self.assertIn("@('scripts/getzilla_update.py', '--only', 'osv', '--only', 'opengrep')", powershell)
        self.assertLess(shell.index('  update_security_data "$home" "$python"\n'),
                        shell.index('  install_workflow_baseline "$home" "$python"\n'))
        self.assertLess(powershell.index('    Update-SecurityData $Python $GetzillaHome\n'),
                        powershell.index('    Install-WorkflowBaseline $Python $GetzillaHome\n'))
        for text in (shell, powershell):
            self.assertNotIn('to their latest versions now? [y/N]', text)
            self.assertNotIn('WARNING: vulnerability data is not up to date', text)

    def test_shell_installer_prefers_pinned_node_archive_over_old_distro_packages(self) -> None:
        # Ubuntu 24.04 ships Node.js 18: a bare install never got an agent CLI from apt.
        text = SHELL.read_text(encoding='utf-8')
        digests = re.findall(r'node-v24\.20\.0-(?:linux|darwin)-(?:x64|arm64)\.tar\.gz ([0-9a-f]{64})', text)
        self.assertEqual(len(digests), 4)
        self.assertIn('checksum_ok "$tmp/$name" "$digest"', text)
        self.assertIn('npm config set prefix "$HOME/.local"', text)
        body = text[text.index('ensure_node() {'):]
        self.assertLess(body.index('install_node_archive'), body.index('apt-get install -y nodejs npm'))

    def test_powershell_fallback_downloads_are_pinned_and_verified(self) -> None:
        # Unauthenticated GitHub API calls hit the 60/hour per-IP limit behind shared NAT and fetched
        # an unreviewed "latest" build; every fallback is now an exact release with its SHA-256.
        text = POWERSHELL.read_text(encoding='utf-8')
        self.assertNotIn('api.github.com', text)
        self.assertNotIn('releases/latest', text)
        self.assertNotIn('nodejs.org/dist/index.json', text)
        pins = re.findall(r"'([a-z0-9-]+)'\s*=\s*@\{ Url = '(https://[^']+)'; Sha256 = '([0-9a-f]*)' \}", text)
        self.assertEqual({key for key, _, _ in pins}, {
            'winget', 'winget-dependencies', 'git-x64', 'git-arm64', 'python-x64', 'python-arm64',
            'pwsh-x64', 'pwsh-arm64', 'node-x64', 'node-arm64',
        })
        for key, url, digest in pins:
            with self.subTest(pin=key):
                self.assertRegex(digest, r'^[0-9a-f]{64}$')
                self.assertNotIn('latest', url)
        self.assertIn('(Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()', text)
        self.assertNotRegex(text, r'Get-Download \$[a-z]+\.browser_download_url')
        for call in ("Get-PinnedDownload ('git-' + (Get-WindowsArchitecture))",
                     "Get-PinnedDownload ('python-' + (Get-WindowsArchitecture))",
                     "Get-PinnedDownload ('pwsh-' + (Get-WindowsArchitecture))",
                     "Get-PinnedDownload ('node-' + (Get-WindowsArchitecture))",
                     "Get-PinnedDownload 'winget'", "Get-PinnedDownload 'winget-dependencies'"):
            self.assertIn(call, text)

    def test_powershell_5_native_calls_avoid_quote_stripping_and_mojibake(self) -> None:
        # Windows PowerShell 5.1 strips double quotes inside native arguments and decodes piped
        # native output with the OEM code page; both broke a real bare install.
        text = POWERSHELL.read_text(encoding='utf-8')
        self.assertNotRegex(text, r"node(\.exe)? -e '[^']*\"")
        self.assertIn('& node --version 2>$null', text)
        self.assertIn('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8', text)

    @unittest.skipIf(shutil.which('pwsh') is None, 'pwsh is not installed')
    def test_powershell_no_winget_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / 'deps'
            for arch in ('x64', 'arm64', 'x86'):
                (deps / arch).mkdir(parents=True)
                (deps / arch / f'Microsoft.VCLibs.140.00.UWPDesktop_14.0_{arch}.appx').write_text('x')
                (deps / arch / f'Microsoft.UI.Xaml.2.8_8.2310_{arch}.appx').write_text('x')
            archive = Path(tmp) / 'node.zip'
            shutil.make_archive(str(archive.with_suffix('')), 'zip', root_dir=ROOT / 'tests', base_dir='fixtures')
            command = (
                f"$ast = [System.Management.Automation.Language.Parser]::ParseFile('{POWERSHELL}', [ref]$null, [ref]$null); "
                '$ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | '
                'ForEach-Object { Invoke-Expression $_.Extent.Text }; '
                "$env:PROCESSOR_ARCHITEW6432 = $null; $env:PROCESSOR_ARCHITECTURE = 'ARM64'; 'arch=' + (Get-WindowsArchitecture); "
                f"'deps=' + ((Select-WingetDependencies '{deps}' 'arm64' | ForEach-Object {{ Split-Path $_ -Leaf }}) -join ','); "
                f"$env:LOCALAPPDATA = '{tmp}'; 'program=' + (Expand-ToUserPrograms '{archive}' 'nodejs'); "
                "function Test-Winget { $false }; $env:GETZILLA_SKIP_WINGET = '1'; Initialize-Winget"
            )
            result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True,
                                    timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('arch=arm64', result.stdout)
            deps_line = next(line for line in result.stdout.splitlines() if line.startswith('deps='))
            self.assertEqual(sorted(deps_line[5:].split(',')), [
                'Microsoft.UI.Xaml.2.8_8.2310_arm64.appx', 'Microsoft.VCLibs.140.00.UWPDesktop_14.0_arm64.appx',
            ])
            program = Path(tmp) / 'Programs' / 'nodejs'
            self.assertIn(f'program={program}', result.stdout)
            self.assertTrue(any(program.iterdir()))
            self.assertFalse(archive.exists())
            self.assertIn('skipping its installation (GETZILLA_SKIP_WINGET=1)', result.stdout)

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
    def setUp(self) -> None:
        # A throwaway HOME: the installer links ~/.local/bin/getzilla, keeps its state in ~/.getzilla and
        # writes shell profiles and agent settings, none of which may touch the account running the tests.
        self.tmp = Path(tempfile.mkdtemp(prefix='getzilla-install-e2e-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.user_home = self.tmp / 'user'
        self.user_home.mkdir()
        self.fake_bin = self.tmp / 'bin'
        self.fake_bin.mkdir()
        # The pinned uv, so the installer does not reach PyPI; Spec Kit's `uv tool install` succeeds.
        (self.fake_bin / 'uv').write_text('#!/bin/sh\n[ "$1" = "--version" ] && echo "uv 0.11.12" && exit 0\nexit 0\n')
        (self.fake_bin / 'uv').chmod(0o755)
        self._offline: dict[str, str] = {}

    def _require_branch(self) -> None:
        if _branch() == 'HEAD':
            self.skipTest('detached checkout: no branch to clone')

    def _install(self, home: Path, *, network: bool = False, **extra: str) -> subprocess.CompletedProcess[str]:
        env = _clean_env(HOME=str(self.user_home), GETZILLA_HOME=str(home), GETZILLA_REPO=ROOT.as_uri(),
                         GETZILLA_REF=_branch(), PATH=f'{self.fake_bin}:{os.environ["PATH"]}')
        if not network:
            if not self._offline:
                self._offline = {'GETZILLA_UPDATE_MIRROR': str(offline_mirror(self.tmp)), 'PIP_NO_INDEX': '1',
                                 'PIP_FIND_LINKS': str(_wheelhouse(self.tmp)), **NO_NETWORK}
            for name in ('no_proxy', 'NO_PROXY'):
                env.pop(name, None)
            env.update(self._offline)
        env.update(extra)
        # Own process group: on a timeout the updater and its downloads stop with the installer
        # instead of running on as orphans (a killed updater also left a stale update.lock).
        process = subprocess.Popen(['bash', str(SHELL)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=3600 if network else 600)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def _run(self, home: Path, **extra: str) -> subprocess.CompletedProcess[str]:
        return self._install(home, GETZILLA_SKIP_AGENT='1', **extra)

    def test_installs_from_a_local_clone_and_reports_ready(self) -> None:
        self._require_branch()
        home = self.tmp / 'Getzilla'
        project = self.tmp / 'project'
        project.mkdir()
        result = self._run(home, GETZILLA_PROJECT=str(project))
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        self.assertIn('Getzilla is ready in', result.stdout)
        self.assertIn('Install plan for', result.stdout)
        self.assertIn(f'Python environment: {home}/.venv', result.stdout)
        self.assertIn('Installing the pinned workflow baseline', result.stdout)
        self.assertIn('Offline mirror', result.stdout)
        state = self.user_home / '.getzilla'
        self.assertFalse((state / 'update.lock').exists())
        self.assertEqual(sorted(path.parent.name for path in state.glob('osv/*/all.zip')),
                         sorted(['PyPI', 'npm', 'Go', 'crates.io', 'Packagist', 'RubyGems']))
        self.assertTrue(os.access(state / 'bin/opengrep', os.X_OK))
        self.assertEqual(sorted(path.name for path in (state / 'baseline').iterdir()), ['bmad', 'spec-kit', 'superpowers'])
        self.assertEqual((self.user_home / '.local/bin/getzilla').readlink(), home / 'bin/getzilla')
        self.assertTrue((home / 'scripts/install_into.py').is_file())
        self.assertEqual(sorted(path.name for path in project.iterdir()), [])  # plan is read-only

        again = self._run(home)
        self.assertEqual(again.returncode, 0, again.stdout[-2000:] + again.stderr[-2000:])
        self.assertIn('Updating Getzilla in', again.stdout)
        self.assertIn('already installed, sha256 verified', again.stdout)

    def test_rejects_an_unknown_agent_before_downloading(self) -> None:
        home = self.tmp / 'Getzilla'
        result = self._run(home, GETZILLA_AGENT='cursor')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('GETZILLA_AGENT must be qwen, codex, claude, gemini, copilot or grok', result.stderr)
        self.assertFalse(home.exists())

    def test_defaults_to_qwen_with_openrouter_and_configures_from_the_key(self) -> None:
        self._require_branch()
        key = 'sk-or-v1-feedfacefeedfacefeedfacefeedface'
        (self.fake_bin / 'qwen').write_text('#!/bin/sh\nexit 0\n')
        (self.fake_bin / 'qwen').chmod(0o755)
        result = self._install(self.tmp / 'Getzilla', GETZILLA_NONINTERACTIVE='1', OPENROUTER_API_KEY=key)
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        self.assertIn('Coding agent: qwen (models: openrouter)', result.stdout)
        self.assertIn('Qwen Code: already installed.', result.stdout)
        self.assertNotIn(key, result.stdout + result.stderr)
        self.assertIn(f"export OPENROUTER_API_KEY='{key}'",
                      (self.user_home / '.getzilla/openrouter.env').read_text(encoding='utf-8'))
        self.assertIn('.getzilla/openrouter.env', (self.user_home / '.bashrc').read_text(encoding='utf-8'))
        self.assertIn('In your project run: qwen', result.stdout)

    def test_refuses_a_foreign_folder(self) -> None:
        home = self.tmp / 'occupied'
        home.mkdir()
        (home / 'keep.txt').write_text('mine', encoding='utf-8')
        result = self._run(home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('is not a Getzilla checkout', result.stderr)
        self.assertEqual((home / 'keep.txt').read_text(encoding='utf-8'), 'mine')

    @unittest.skipUnless(E2E, 'downloads the OSV database, OpenGrep, the pinned workflow sources and PyPI tools')
    def test_installs_the_real_security_data_and_baseline_from_the_network(self) -> None:
        self._require_branch()
        if str(ROOT / '.getzilla') not in sys.path:
            sys.path.insert(0, str(ROOT / '.getzilla'))
        from getzilla import baseline, updater

        home = self.tmp / 'Getzilla'
        result = self._install(home, network=True, GETZILLA_SKIP_AGENT='1')
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        self.assertIn('Getzilla is ready in', result.stdout)
        self.assertNotIn('Offline mirror', result.stdout)
        state = self.user_home / '.getzilla'
        for ecosystem in updater.OSV_ECOSYSTEMS:
            with zipfile.ZipFile(state / 'osv' / ecosystem / 'all.zip') as archive:
                self.assertGreater(len(archive.namelist()), 100, ecosystem)
        asset = updater.OPENGREP_ASSETS[updater._platform_key()]
        self.assertEqual(hashlib.sha256((state / 'bin/opengrep').read_bytes()).hexdigest(), asset[1])
        for component_id, item in baseline.components().items():
            head = subprocess.run(['git', '-C', str(state / 'baseline' / component_id), 'rev-parse', 'HEAD'],
                                  capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(head, item['pinned_commit'], component_id)
        self.assertTrue((home / '.venv/bin/ruff').is_file())


if __name__ == '__main__':
    unittest.main()
