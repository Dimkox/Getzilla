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

import ast
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

from tests._support import missing_history, offline_mirror

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
            project, version = requirement.split(';', 1)[0].strip().split('==')
            project, _, extra = project.partition('[')
            extras = extra.removesuffix(']').split(',') if extra else []
            dist = re.sub(r'[-_.]+', '_', project).lower()
            info = f'{dist}-{version}.dist-info'
            with zipfile.ZipFile(house / f'{dist}-{version}-py3-none-any.whl', 'w') as wheel:
                metadata = f'Metadata-Version: 2.1\nName: {project}\nVersion: {version}\n'
                metadata += ''.join(f'Provides-Extra: {name}\n' for name in extras)
                wheel.writestr(f'{info}/METADATA', metadata)
                wheel.writestr(f'{info}/WHEEL', 'Wheel-Version: 1.0\nGenerator: getzilla-tests\n'
                                                'Root-Is-Purelib: true\nTag: py3-none-any\n')
                wheel.writestr(f'{info}/RECORD', f'{info}/METADATA,,\n{info}/WHEEL,,\n{info}/RECORD,,\n')
    return house


def _branch() -> str:
    return subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=ROOT, capture_output=True, text=True,
                          check=True).stdout.strip()


class InstallScriptContractTests(unittest.TestCase):
    def test_offline_wheelhouse_uses_pin_version_without_marker_data(self):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-marker-wheels-', dir=scratch) as owned:
            base = Path(owned)
            source = base / 'source'
            config = source / '.getzilla/config'
            config.mkdir(parents=True)
            (config / 'python-test-requirements.txt').write_text(
                'typing-extensions==4.16.0; python_version < "3.13"\ncoverage[toml]==7.15.4\n')
            (config / 'python-quality-requirements.txt').write_text('ruff==0.16.3\n')
            with patch(__name__ + '.ROOT', source):
                house = _wheelhouse(base)
            wheel = house / 'typing_extensions-4.16.0-py3-none-any.whl'
            self.assertTrue(wheel.is_file(), sorted(path.name for path in house.iterdir()))
            with zipfile.ZipFile(wheel) as archive:
                metadata = archive.read('typing_extensions-4.16.0.dist-info/METADATA').decode()
            self.assertIn('Version: 4.16.0\n', metadata)
            self.assertNotIn('python_version', metadata)
            coverage = house / 'coverage-7.15.4-py3-none-any.whl'
            self.assertTrue(coverage.is_file(), sorted(path.name for path in house.iterdir()))
            with zipfile.ZipFile(coverage) as archive:
                metadata = archive.read('coverage-7.15.4.dist-info/METADATA').decode()
            self.assertIn('Provides-Extra: toml\n', metadata)

    @unittest.skipIf(sys.platform == 'win32' or shutil.which('bash') is None,
                     'public shell configuration boundary needs POSIX bash; PowerShell has separate controls')
    def test_configure_agent_is_one_local_configuration_child_without_model_execution(self):
        # This is the cost contract's existing one-shot boundary, not a model
        # call budget or authority to execute a configured coding agent.
        text = SHELL.read_text(encoding='utf-8')
        function = re.search(r'^configure_agent\(\) \{.*?^\}', text, re.M | re.S)
        self.assertIsNotNone(function)
        self.assertEqual(len(re.findall(r'^\s*configure_agent\b', text, re.M)), 2)
        self.assertNotRegex(function.group(), r'(?m)^\s*(?:for|while|until)\b')
        with tempfile.TemporaryDirectory(prefix='public-configure-boundary-') as temporary:
            root = Path(temporary)
            capture = root / 'public-argv.txt'
            child = root / 'public-python'
            child.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$PUBLIC_CAPTURE"\n', encoding='utf-8', newline='\n')
            child.chmod(0o700)
            # No ambient environment or key reaches this inert public child.
            env = {'PATH': os.defpath, 'HOME': str(root), 'PUBLIC_CAPTURE': str(capture)}
            command = ('say() { :; }; can_ask() { return 1; };\n' + function.group() +
                       '\nconfigure_agent "$1" "$2" qwen openrouter\n')
            result = subprocess.run(['bash', '-eu', '-c', command, 'public-boundary', str(root), str(child)],
                                    env=env, capture_output=True, text=True, encoding='utf-8', timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(capture.read_text(encoding='utf-8').splitlines(),
                             ['scripts/getzilla_setup_agent.py', '--agent', 'qwen', '--provider', 'openrouter'])

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
        if resolved.returncode != 0:
            missing_history(f'tag {tag}')
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
        # The selected managed installer is a child; no vendor code runs via iex.
        self.assertIn("Join-Path $GetzillaHome 'scripts/getzilla_install_managed.py'", text)
        self.assertIn('Invoke-Python $Python $arguments', text)
        self.assertNotIn("-Command 'irm https://x.ai/cli/install.ps1 | iex'", text)

    def test_powershell_installer_uses_the_toolchain_package_ids(self) -> None:
        text = POWERSHELL.read_text(encoding='utf-8')
        self.assertIn('--id Git.Git', _toolchain_windows_install('git'))
        self.assertNotRegex(text, r"Invoke-Winget 'Python\.Python")
        # Bootstrap component identities now select verified per-user current ZIPs.
        for component, function in (('git','Install-Git'), ('python','Install-Python'), ('pwsh','Install-PowerShell7')):
            self.assertRegex(text, rf"function {function} \{{[^\n]*Install-CurrentRuntime '{component}'")
        self.assertIn("$metadataUrl = 'https://www.python.org/ftp/python/index-windows.json'", text)
        self.assertIn("Expand-ToUserPrograms (Get-PinnedDownload", text)
        self.assertIn('actual version probe failed', text)
        self.assertIn('PATH conflict: expected', text)
        self.assertIn('no old-family fallback', text)

    def test_both_installers_offer_the_same_agents_and_settings(self) -> None:
        shell = SHELL.read_text(encoding='utf-8')
        powershell = POWERSHELL.read_text(encoding='utf-8')
        for text in (shell, powershell):
            for name in ('GETZILLA_AGENT', 'GETZILLA_PROVIDER', 'GETZILLA_MODEL', 'OPENROUTER_API_KEY',
                         'GETZILLA_SKIP_AGENT', 'GETZILLA_NONINTERACTIVE', 'getzilla_setup_agent.py', '--key-stdin',
                         'https://openrouter.ai/keys', 'GEMINI_API_KEY', 'COPILOT_GITHUB_TOKEN',
                         'qwen, codex, claude, gemini, copilot or grok', 'scripts/getzilla_update.py',
                         'getzilla_baseline.py', 'scripts/getzilla_install_managed.py'):
                self.assertIn(name, text)
        # Current exact package resolution replaces @latest and vendor shell pipes.
        tree = ast.parse((ROOT/'.getzilla/getzilla/managed_software.py').read_text())
        packages = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                        and any(isinstance(v, ast.Name) and v.id == 'AGENT_PACKAGES' for v in n.targets))
        self.assertEqual(packages, {'qwen':'@qwen-code/qwen-code', 'codex':'@openai/codex',
                                   'gemini':'@google/gemini-cli', 'copilot':'@github/copilot'})
        for text in (shell, powershell):
            self.assertNotRegex(text, r'npm install[^\n]*@latest')
            self.assertNotIn('irm https://claude.ai/install.ps1 | iex', text)
        self.assertIn('-AsSecureString', powershell)
        self.assertIn('read -rs key </dev/tty', shell)
        toolchain = json.loads((ROOT/'.getzilla/config/toolchain.json').read_text())
        tools = {item['id']:item for item in toolchain['tools']}
        self.assertEqual(tools['pwsh']['minimum'], '7.4')
        self.assertEqual(tools['node']['minimum'], '20.0')
        self.assertIn('Microsoft.PowerShell', tools['pwsh']['install']['windows'])

    def test_powershell_installer_installs_winget_or_falls_back_to_direct_downloads(self) -> None:
        text = POWERSHELL.read_text(encoding='utf-8')
        main = text[text.index('function Install-Getzilla {'):text.index('function Write-Step')]
        # The non-admin direct path is now primary, including reruns with winget present.
        self.assertNotIn('Initialize-Winget', main)
        self.assertNotIn('Invoke-Winget', main)
        for call in ('    Install-Git\n', '$Python = @(Install-Python)', '    Install-PowerShell7\n'):
            self.assertIn(call, main)
        self.assertLess(main.index('Install-Git'), main.index('Get-GetzillaSource -Repo'))
        self.assertIn('function Initialize-Winget', text)  # Existing explicit helper remains available.
        self.assertIn('GETZILLA_SKIP_WINGET', text)
        self.assertIn('function Expand-ToUserPrograms', text)

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
        text = SHELL.read_text(encoding='utf-8')
        # The pin is freshly resolved and hash-qualified; old distro Node cannot replace it.
        body = text[text.index('install_agent() {'):text.index('configure_agent() {')]
        self.assertIn('scripts/getzilla_install_managed.py', body)
        self.assertIn('Current selected managed software is incomplete', body)
        self.assertNotIn('apt-get install -y nodejs npm', text)
        self.assertNotIn('node-v24.20.0', text)
        managed = (ROOT/'.getzilla/getzilla/managed_software.py').read_text()
        self.assertIn("releases.node_release(fetch, system, arch)", managed)
        self.assertIn('install_runtime', managed)
        self.assertIn("root/'bin'", (ROOT/'.getzilla/getzilla/managed_npm.py').read_text())

    def test_powershell_fallback_downloads_are_pinned_and_verified(self) -> None:
        text = POWERSHELL.read_text(encoding='utf-8')
        target = text[text.index('function Get-CurrentRuntimeTarget'):text.index('function Install-CurrentRuntime')]
        # Official stable metadata creates an exact URL and hash before acquisition.
        for needle in ('api.github.com/repos/', 'nodejs.org/dist/index.json', 'SHASUMS256.txt',
                       '$target = @{ Url = $url; Sha256 = $sha; Version = $version; Metadata = $metadataUrl }',
                       'no older compatible fallback', 'current stable identity is invalid'):
            self.assertIn(needle, text)
        self.assertIn("$script:ResolvedRuntimeTargets = @{}", text)
        self.assertIn('Get-CurrentRuntimeTarget $Key', text)
        self.assertIn('(Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()', text)
        self.assertIn('if ($actual -ne $pin.Sha256)', text)
        self.assertIn('Remove-Item -Force $path', text)
        self.assertIn("$sha -notmatch '^[a-f0-9]{64}$'", target)
        self.assertNotRegex(text, r'Get-Download \$[a-z]+\.browser_download_url')

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
        # Even a sufficient host must route through fresh exact resolution. The child
        # substitutes that effect, so this contract never installs onto the test host.
        library = POWERSHELL.read_text(encoding='utf-8').split('\ntry {\n    Install-Getzilla')[0]
        with tempfile.TemporaryDirectory(prefix='owned-pwsh-current-wrapper-') as directory:
            path = Path(directory)/'library.ps1'
            path.write_text(library, encoding='utf-8')
            command = (f". '{path}'; $script:calls=0; "
                       "function Install-CurrentRuntime($Component) { if ($Component -cne 'pwsh') { throw 'wrong component' }; $script:calls++ }; "
                       "Install-PowerShell7; Install-PowerShell7; if ($script:calls -ne 2) { throw 'rerun skipped current resolution' }; "
                       "'owned-current-pwsh:PASS'")
            result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('owned-current-pwsh:PASS', result.stdout)

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
        (self.fake_bin / 'uv').write_text(
            '#!/bin/sh\n[ "$1" = "--version" ] && echo "uv 0.11.12" && exit 0\n'
            'if [ "$1" = "tool" ] && [ "$2" = "dir" ] && [ "$3" = "--bin" ]; then dirname "$0"; fi\n'
            'exit 0\n')
        (self.fake_bin / 'uv').chmod(0o755)
        self._offline: dict[str, str] = {}

    def _owned_python_launcher(self) -> Path:
        # Fixture assembly substitutes component acquisition, never a production
        # freshness switch. Other checkout/provider/security scripts stay real.
        launcher = self.fake_bin / 'python3'
        program = r'''import json,os,runpy,shutil,sys
from pathlib import Path
arguments=sys.argv[1:]
owned=Path(os.environ['OWNED_INSTALL_FIXTURE']).resolve()
def audit(event,args):
    if event.startswith('socket.'):
        raise AssertionError('offline installer fixture denies network')
    if event=='subprocess.Popen':
        command=args[1]
        if not isinstance(command,(list,tuple)) or any('http://' in str(v) or 'https://' in str(v) for v in command):
            raise AssertionError('offline installer fixture denies transport process')
sys.addaudithook(audit)
if arguments[:1]==['--version']:
    print('Python '+sys.version.split()[0]);raise SystemExit(0)
if arguments[:1]==['-c']:
    assert len(arguments)==2 and arguments[1]=="import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
    raise SystemExit(0)
assert arguments and not arguments[0].startswith('-'), 'unknown Python acquisition effect'
script=Path(arguments[0]).resolve()
assert script.is_relative_to(owned) and script.parent.name=='scripts', 'foreign script'
if script.name=='getzilla_install_managed.py':
    args=arguments[1:];home=Path(args[args.index('--home')+1]).resolve()
    assert home.is_relative_to(owned) and script.parent.parent==home
    selected=[v for i,v in enumerate(args) if i and args[i-1]=='--agent']
    assert selected in ([],['qwen'])
    expected=(['--environment-only','--home',str(home)] if '--environment-only' in args else
              (['--verify-only','--home',str(home)] if '--verify-only' in args else ['--home',str(home)]))
    if selected:expected+=['--agent','qwen']
    assert args==expected, 'unknown managed acquisition arguments'
    with (owned/'managed-calls.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(args)+'\n')
    if '--environment-only' in args:
        python=home/'.venv/bin/python';python.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(__file__,python);python.chmod(0o755)
        print('Python environment: '+str(home/'.venv'))
    print(json.dumps({'status':'complete','scope':'owned component acquisition fixture'}))
    raise SystemExit(0)
assert script.name in {'getzilla_setup_agent.py','getzilla_update.py','getzilla_doctor.py','install_into.py'}, 'unknown installer Python boundary'
sys.path[:0]=[str(script.parent),str(script.parent.parent/'.getzilla')]
if script.name=='getzilla_update.py':
    args=arguments[1:]
    assert args in (['--only','osv','--only','opengrep'],['--only','baseline']), 'unknown acquisition boundary'
    with (owned/'component-calls.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(args)+'\n')
    from getzilla import updater
    from getzilla.baseline import install_user,components
    mirror=updater.Mirror.from_environ()
    assert mirror is not None
    state=Path.home()/'.getzilla'
    if args==['--only','baseline']:
        config={name:{**item,'pinned_commit':mirror.baseline[name]} for name,item in components().items()}
        rows=install_user(state,config=config,locate=mirror.url)
    else:
        rows=updater.update_osv(mirror.fetch,state,source_database=mirror.root/'osv')
        assets={key:(asset,mirror.opengrep.get(asset,digest)) for key,(asset,digest) in updater.OPENGREP_ASSETS.items()}
        rows+=updater.update_opengrep(mirror.fetch,state,assets=assets)
    assert all(row.status in ('ok','pass') for row in rows), 'owned component data preparation failed'
    print('Owned-current acquisition callback; fixture assembly only. Offline mirror data, not current upstream acceptance.')
    for row in rows:print(row.detail)
    raise SystemExit(0)
sys.argv=arguments
runpy.run_path(str(script),run_name='__main__')
'''
        launcher.write_text('#!' + sys.executable + '\n' + program, encoding='utf-8', newline='\n')
        launcher.chmod(0o755)
        return launcher

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
        if not network:
            self._owned_python_launcher()
            env['OWNED_INSTALL_FIXTURE'] = str(self.tmp)
        env.update(extra)
        # Own process group: on a timeout the updater and its downloads stop with the installer
        # instead of running on as orphans (a killed updater also left a stale update.lock).
        process = subprocess.Popen(['bash', str(SHELL)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True, umask=0o022)
        try:
            stdout, stderr = process.communicate(timeout=3600 if network else 60)
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
        self.assertIn('Resolving the current verified workflow baseline', result.stdout)
        self.assertIn('Offline mirror', result.stdout)
        state = self.user_home / '.getzilla'
        self.assertFalse((state / 'update.lock').exists())
        from getzilla import updater
        self.assertEqual(sorted(path.parent.name for path in state.glob('osv/*/all.zip')),
                         sorted(updater.OSV_ECOSYSTEMS))
        self.assertTrue(os.access(state / 'bin/opengrep', os.X_OK))
        self.assertEqual(sorted(path.name for path in (state / 'baseline').iterdir()), ['bmad', 'spec-kit', 'superpowers'])
        self.assertEqual((self.user_home / '.local/bin/getzilla').readlink(), home / 'bin/getzilla')
        self.assertTrue((home / 'scripts/install_into.py').is_file())
        self.assertEqual(sorted(path.name for path in project.iterdir()), [])  # plan is read-only

        again = self._run(home)
        self.assertEqual(again.returncode, 0, again.stdout[-2000:] + again.stderr[-2000:])
        self.assertIn('Updating Getzilla in', again.stdout)
        self.assertIn('already installed, sha256 verified', again.stdout)
        calls = [json.loads(line) for line in (self.tmp/'managed-calls.jsonl').read_text().splitlines()]
        self.assertEqual(calls, [['--environment-only','--home',str(home)], ['--home',str(home)],
                                ['--verify-only','--home',str(home)]] * 2)
        components = [json.loads(line) for line in (self.tmp/'component-calls.jsonl').read_text().splitlines()]
        self.assertEqual(components, [['--only','osv','--only','opengrep'], ['--only','baseline']] * 2)

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
        self.assertIn('owned component acquisition fixture', result.stdout)
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
