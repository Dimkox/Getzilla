"""S02-S04: Rust, .NET and PowerShell are checked with pinned toolchains, or say exactly why not."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import stack_runners  # noqa: E402
from getzilla.stack_toolchains import Blocker, Toolchain, ensure_toolchain, missing_requirements  # noqa: E402
from getzilla.stacks import RUNNERS, StackContext, load_registry  # noqa: E402
from getzilla.verification import CheckResult  # noqa: E402

REGISTRY = load_registry(ROOT)
E2E = os.environ.get('GETZILLA_E2E_TOOLCHAINS') == '1'


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')


class Recorder:
    """Stands in for _command_check: records (cwd, name, argv, env) and returns a passing check."""

    def __init__(self, outputs: dict[str, tuple[int, str]] | None = None) -> None:
        self.calls: list[tuple[Path, str, list[str], dict[str, str]]] = []
        self.outputs = outputs or {}

    def __call__(self, cwd, name, command, timeout=300, *, env=None):
        self.calls.append((Path(cwd), name, list(command), dict(env or {})))
        code, stdout = self.outputs.get(name.split(':')[0], (0, ''))
        return CheckResult(name, 'pass' if code == 0 else 'fail', f'exit={code}', command=command, stdout=stdout)


class RunnerCase(unittest.TestCase):
    stack = ''

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.home = self.root / '.tc'
        self.toolchain = Toolchain(self.stack, '1.0.0', self.home, (self.home / 'bin',), {'TC': '1'})

    def run_stack(self, mode: str, files: list[str], *, toolchain=None, outputs=None) -> tuple[list, Recorder, StackContext]:
        recorder = Recorder(outputs)
        context = StackContext(self.root, mode, REGISTRY[self.stack], files, CheckResult, recorder,
                               lambda _stack, _version: toolchain or self.toolchain)
        return RUNNERS[self.stack](context), recorder, context


class RustTests(RunnerCase):
    stack = 'rust'

    def test_fast_and_pr_commands_with_the_toolchain_on_path(self) -> None:
        _write(self.root, {'Cargo.toml': '[package]\nname = "x"\n', 'Cargo.lock': '', 'src/main.rs': 'fn main() {}\n'})
        results, recorder, context = self.run_stack('fast', ['src/main.rs'])
        self.assertEqual([check.name for check in results], ['cargo-fmt', 'cargo-clippy'])
        self.assertEqual(recorder.calls[1][2], ['cargo', 'clippy', '--all-targets', '--locked'])
        self.assertTrue(all(call[3]['PATH'].startswith(str(self.home / 'bin')) and call[3]['TC'] == '1' for call in recorder.calls))
        self.assertEqual(context.notes['version_source'], 'stacks.json')
        results, recorder, _ = self.run_stack('pr', ['src/main.rs'])
        self.assertEqual([check.name for check in results], ['cargo-fmt', 'cargo-clippy', 'cargo-build', 'cargo-test'])
        self.assertEqual(recorder.calls[-1][2], ['cargo', 'test', '--locked'])

    def test_missing_lockfile_is_a_gap_that_fails_pr(self) -> None:
        _write(self.root, {'Cargo.toml': '[package]\nname = "x"\n', 'src/lib.rs': ''})
        results, recorder, _ = self.run_stack('pr', ['src/lib.rs'])
        self.assertEqual((results[0].name, results[0].status, results[0].summary), ('cargo-lockfile', 'fail', 'CARGO_LOCK_MISSING'))
        self.assertNotIn('--locked', recorder.calls[1][2])

    def test_clippy_warnings_are_findings_not_failures(self) -> None:
        _write(self.root, {'Cargo.toml': '', 'Cargo.lock': '', 'src/lib.rs': ''})
        results, _, _ = self.run_stack('fast', ['src/lib.rs'], outputs={'cargo-clippy': (0, 'warning: unused\nwarning: x\n')})
        clippy = next(check for check in results if check.name == 'cargo-clippy')
        self.assertEqual(clippy.status, 'pass')
        self.assertEqual(clippy.details[0]['code'], 'stack-warnings')

    def test_workspace_member_runs_at_the_workspace_root_once(self) -> None:
        _write(self.root, {'Cargo.toml': '[workspace]\nmembers = ["crates/a"]\n', 'Cargo.lock': '',
                           'crates/a/Cargo.toml': '[package]\nname = "a"\n', 'crates/a/src/lib.rs': ''})
        results, recorder, _ = self.run_stack('fast', ['crates/a/src/lib.rs'])
        self.assertEqual({call[0] for call in recorder.calls}, {self.root})

    def test_toolchain_refusal_is_a_failing_check_with_the_reason(self) -> None:
        _write(self.root, {'Cargo.toml': '', 'src/lib.rs': ''})
        blocker = Blocker('TOOLCHAIN_NEEDS_ADMIN:msvc-build-tools', 'needs MSVC', 'winget install X')
        results, recorder, _ = self.run_stack('pr', ['src/lib.rs'], toolchain=blocker)
        self.assertEqual([(check.name, check.status, check.summary) for check in results],
                         [('toolchain:rust', 'fail', 'TOOLCHAIN_NEEDS_ADMIN:msvc-build-tools')])
        self.assertEqual(results[0].details[0]['command'], 'winget install X')
        self.assertEqual(recorder.calls, [])

    def test_windows_without_build_tools_needs_admin_and_gnu_does_not(self) -> None:
        spec = REGISTRY['rust'].toolchain
        absent = lambda *_args: subprocess.CompletedProcess([], 1, '', '')  # noqa: E731
        with mock.patch.dict(os.environ, {'ProgramFiles(x86)': str(self.root / 'none')}):
            blocker = missing_requirements(spec, '1.99.1', 'windows-x64', lambda _name: None, absent)
            self.assertEqual(blocker.code, 'TOOLCHAIN_NEEDS_ADMIN:msvc-build-tools')
            self.assertIn('VCTools', blocker.command)
            self.assertIsNone(missing_requirements(spec, '1.99.1-x86_64-pc-windows-gnu', 'windows-x64', lambda _n: None, absent))
            self.assertIsNone(missing_requirements(spec, '1.99.1', 'linux-x64', lambda _n: None, absent))
        installer = self.root / 'vs' / 'Microsoft Visual Studio' / 'Installer' / 'vswhere.exe'
        installer.parent.mkdir(parents=True)
        installer.write_text('', encoding='utf-8')
        found = lambda *_args: subprocess.CompletedProcess([], 0, 'C:\\BuildTools\n', '')  # noqa: E731
        with mock.patch.dict(os.environ, {'ProgramFiles(x86)': str(self.root / 'vs')}):
            self.assertIsNone(missing_requirements(spec, '1.99.1', 'windows-x64', lambda _name: None, found))

    def test_rustup_installer_verifies_and_never_touches_the_profile(self) -> None:
        init = b'#!/bin/sh\nexit 0\n'
        spec = json.loads(json.dumps(REGISTRY['rust'].toolchain))
        source = spec['source']
        source['pinned'] = {source['rustup_version']: {'linux-x64': hashlib.sha256(init).hexdigest()}}
        url = source['url'].format(rustup_version=source['rustup_version'], target='x86_64-unknown-linux-gnu', binary='rustup-init')
        seen: list[list[str]] = []

        def fetch(address: str, destination: Path) -> None:
            data = {url: init, url + '.sha256': f'{hashlib.sha256(init).hexdigest()} *./rustup-init\n'.encode()}
            destination.write_bytes(data[address])

        def run(command, env, _cwd):
            seen.append(command)
            self.assertEqual(env['CARGO_HOME'].split(os.sep)[-1], 'cargo')
            Path(env['CARGO_HOME'], 'bin').mkdir(parents=True)
            return subprocess.CompletedProcess(command, 0, '', '')

        with mock.patch.dict(os.environ, {'GETZILLA_TOOLCHAIN_CACHE': str(self.root / 'cache'), 'HOME': str(self.root)}):
            result = ensure_toolchain('rust', spec, '1.99.1', fetch=fetch, run=run, key='linux-x64', root=self.root / 'tcs')
        assert isinstance(result, Toolchain), result
        self.assertIn('--no-modify-path', seen[0])
        self.assertEqual(seen[0][seen[0].index('--default-toolchain') + 1], '1.99.1')
        self.assertTrue((result.home / 'cargo' / 'bin').is_dir())
        self.assertEqual(result.env['CARGO_HOME'], str(result.home / 'cargo'))
        self.assertFalse(any((self.root / name).exists() for name in ('.profile', '.bashrc', '.cargo')))

    @unittest.skipUnless(E2E, 'downloads rustup and a Rust toolchain from static.rust-lang.org')
    def test_real_rust_toolchain_checks_a_crate(self) -> None:
        if shutil.which('cc') is None:
            self.skipTest('no C linker for cargo build')
        _write(self.root, {'Cargo.toml': '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n',
                           'src/lib.rs': 'pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n\n#[test]\nfn adds() {\n    assert_eq!(add(1, 2), 3);\n}\n'})
        from getzilla.verification import _command_check
        subprocess.run(['git', 'init', '-q'], cwd=self.root, check=True)
        spec = REGISTRY['rust'].toolchain
        toolchain = ensure_toolchain('rust', spec, spec['default_version'])
        assert isinstance(toolchain, Toolchain), toolchain
        generate = subprocess.run(['cargo', 'generate-lockfile'], cwd=self.root, env=toolchain.process_env(), capture_output=True, text=True)
        self.assertEqual(generate.returncode, 0, generate.stderr)
        context = StackContext(self.root, 'pr', REGISTRY['rust'], ['src/lib.rs'], CheckResult, _command_check,
                               lambda stack, version: ensure_toolchain(stack.id, stack.toolchain, version))
        results = RUNNERS['rust'](context)
        self.assertEqual([(check.name, check.status) for check in results],
                         [('cargo-fmt', 'pass'), ('cargo-clippy', 'pass'), ('cargo-build', 'pass'), ('cargo-test', 'pass')],
                         [check.stderr[-400:] for check in results])


class DotnetTests(RunnerCase):
    stack = 'dotnet'

    def test_pr_restore_build_test_format_and_vulnerabilities(self) -> None:
        _write(self.root, {'App.sln': '', 'src/App/App.csproj': '<Project Sdk="Microsoft.NET.Sdk"></Project>',
                           'src/App/packages.lock.json': '{}', 'src/App/Program.cs': ''})
        results, recorder, _ = self.run_stack('pr', ['src/App/Program.cs'])
        self.assertEqual([check.name for check in results],
                         ['dotnet-restore', 'dotnet-build', 'dotnet-test', 'dotnet-format', 'nuget-vulnerabilities'])
        self.assertEqual(recorder.calls[0][2], ['dotnet', 'restore', 'App.sln', '--locked-mode'])
        self.assertEqual(recorder.calls[0][0], self.root)

    def test_vulnerable_package_fails_and_fast_mode_reports_unknown_dependencies(self) -> None:
        _write(self.root, {'App.csproj': '<Project Sdk="Microsoft.NET.Sdk"></Project>', 'Program.cs': ''})
        report = {'projects': [{'path': 'App.csproj', 'frameworks': [{'framework': 'net10.0', 'topLevelPackages': [
            {'id': 'Newtonsoft.Json', 'resolvedVersion': '12.0.1',
             'vulnerabilities': [{'severity': 'High', 'advisoryurl': 'https://github.com/advisories/GHSA-5crp-9r3c-p9vr'}]}]}]}]}
        results, _, _ = self.run_stack('pr', ['Program.cs'], outputs={'nuget-vulnerabilities': (0, json.dumps(report))})
        vulnerable = next(check for check in results if check.name == 'nuget-vulnerabilities')
        self.assertEqual(vulnerable.status, 'fail')
        self.assertIn('Newtonsoft.Json 12.0.1', vulnerable.details[0]['message'])
        results, _, _ = self.run_stack('fast', ['Program.cs'])
        self.assertEqual([(check.name, check.status, check.summary) for check in results][-1],
                         ('nuget-dependencies', 'skip', 'NUGET_DEPENDENCIES_UNKNOWN'))

    def test_workloads_are_refused_explicitly(self) -> None:
        _write(self.root, {'Mobile.csproj': '<Project><PropertyGroup><UseMaui>true</UseMaui>'
                                            '<TargetFrameworks>net10.0-android</TargetFrameworks></PropertyGroup></Project>'})
        results, _, _ = self.run_stack('pr', ['Mobile.csproj'])
        self.assertEqual((results[0].status, results[0].summary), ('fail', 'DOTNET_WORKLOAD_NOT_SUPPORTED'))

    def test_global_json_pins_the_sdk(self) -> None:
        _write(self.root, {'global.json': json.dumps({'sdk': {'version': '8.0.426'}}), 'A.csproj': '<Project/>'})
        _, _, context = self.run_stack('fast', ['A.csproj'])
        self.assertEqual((context.notes['toolchain_version'], context.notes['version_source']), ('8.0.426', 'global.json'))

    def test_registry_pins_match_the_recorded_microsoft_manifest(self) -> None:
        recorded = json.loads((ROOT / 'tests' / 'fixtures' / 'stacks' / 'dotnet' / 'sdk-10.0.402-files.json').read_text(encoding='utf-8'))
        source = REGISTRY['dotnet'].toolchain['source']
        by_name = {item['url'].rsplit('/', 1)[-1]: item['hash'] for item in recorded}
        for key, digest in source['pinned']['10.0.402'].items():
            self.assertEqual(by_name[source['archives'][key].format(version='10.0.402')], digest, key)

    @unittest.skipUnless(E2E, 'downloads the .NET SDK from builds.dotnet.microsoft.com')
    def test_real_dotnet_sdk_builds_and_tests(self) -> None:
        from getzilla.verification import _command_check
        spec = REGISTRY['dotnet'].toolchain
        toolchain = ensure_toolchain('dotnet', spec, spec['default_version'])
        assert isinstance(toolchain, Toolchain), toolchain
        env = toolchain.process_env()
        for command in (['dotnet', 'new', 'classlib', '-n', 'Lib', '-o', 'Lib'], ['dotnet', 'new', 'xunit', '-n', 'Lib.Tests', '-o', 'Lib.Tests'],
                        ['dotnet', 'new', 'sln', '-n', 'Demo'], ['dotnet', 'sln', 'Demo.slnx' if (self.root / 'Demo.slnx').exists() else 'Demo.sln', 'add', 'Lib/Lib.csproj', 'Lib.Tests/Lib.Tests.csproj']):
            if command[:2] == ['dotnet', 'sln']:
                command[2] = 'Demo.slnx' if (self.root / 'Demo.slnx').exists() else 'Demo.sln'
            made = subprocess.run(command, cwd=self.root, env=env, capture_output=True, text=True)
            self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        context = StackContext(self.root, 'pr', REGISTRY['dotnet'], ['Lib/Class1.cs'], CheckResult, _command_check,
                               lambda stack, version: ensure_toolchain(stack.id, stack.toolchain, version))
        results = RUNNERS['dotnet'](context)
        self.assertEqual([(check.name, check.status) for check in results],
                         [('dotnet-restore', 'pass'), ('dotnet-build', 'pass'), ('dotnet-test', 'pass'),
                          ('dotnet-format', 'pass'), ('nuget-vulnerabilities', 'pass')],
                         [(check.name, check.stdout[-300:], check.stderr[-300:]) for check in results])


class PowerShellTests(RunnerCase):
    stack = 'powershell'

    def test_analyzer_and_pester_on_the_project_scripts_only(self) -> None:
        _write(self.root, {'build.ps1': 'Write-Output 1\n', 'tests/build.Tests.ps1': 'Describe x {}\n',
                           'node_modules/x/evil.ps1': '', '.getzilla/runtime/worktrees/a/copy.ps1': ''})
        subprocess.run(['git', 'init', '-q'], cwd=self.root, check=True)
        with mock.patch.object(stack_runners, 'powershell_interpreter', return_value='pwsh'):
            results, recorder, context = self.run_stack('pr', ['build.ps1'])
        self.assertEqual([check.name for check in results], ['psscriptanalyzer', 'pester'])
        analyzer = recorder.calls[0][2][-1]
        self.assertIn("'build.ps1'", analyzer)
        self.assertNotIn('evil.ps1', analyzer)
        self.assertNotIn('copy.ps1', analyzer)
        self.assertIn('-RequiredVersion 1.25.0', analyzer)
        self.assertIn('-RequiredVersion 5.9.1', recorder.calls[1][2][-1])
        self.assertEqual(context.notes['interpreter'], 'pwsh')

    def test_no_powershell_is_a_failure_with_install_advice(self) -> None:
        _write(self.root, {'a.ps1': ''})
        with mock.patch.object(stack_runners, 'powershell_interpreter', return_value=None):
            results, recorder, _ = self.run_stack('pr', ['a.ps1'])
        self.assertEqual((results[0].name, results[0].status, results[0].summary), ('toolchain:powershell', 'fail', 'TOOLCHAIN_UNAVAILABLE'))
        self.assertIn('Microsoft.PowerShell', results[0].details[0]['command'])
        self.assertEqual(recorder.calls, [])

    def test_gallery_modules_are_verified_by_sha512(self) -> None:
        def nupkg(module: str) -> bytes:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as bundle:
                bundle.writestr(f'{module}.psd1', '@{}')
                bundle.writestr(f'{module}.nuspec', '<package/>')
                bundle.writestr('[Content_Types].xml', '<Types/>')
            return buffer.getvalue()

        spec = json.loads(json.dumps(REGISTRY['powershell'].toolchain))
        packages = {name: nupkg(name) for name in spec['source']['modules']}
        for name, data in packages.items():
            spec['source']['modules'][name]['hash'] = base64.b64encode(hashlib.sha512(data).digest()).decode()

        def fetch(url: str, destination: Path) -> None:
            destination.write_bytes(next(data for name, data in packages.items() if f'/{name}/' in url))

        with mock.patch.dict(os.environ, {'GETZILLA_TOOLCHAIN_CACHE': str(self.root / 'cache')}):
            result = ensure_toolchain('powershell', spec, spec['default_version'], fetch=fetch, key='linux-x64', root=self.root / 'tcs')
            assert isinstance(result, Toolchain), result
            module = result.home / 'modules' / 'Pester' / '5.9.1'
            self.assertTrue((module / 'Pester.psd1').is_file())
            self.assertFalse((module / 'Pester.nuspec').exists())
            self.assertTrue(result.env['PSModulePath'].startswith(str(result.home / 'modules')))
            spec['source']['modules']['Pester']['hash'] = base64.b64encode(b'\0' * 64).decode()
            tampered = ensure_toolchain('powershell', spec, 'other', fetch=fetch, key='linux-x64', root=self.root / 'tcs')
        assert isinstance(tampered, Blocker)
        self.assertEqual(tampered.code, 'TOOLCHAIN_CHECKSUM_MISMATCH')

    @unittest.skipUnless(E2E and shutil.which('pwsh'), 'downloads PSScriptAnalyzer and Pester from the PowerShell Gallery')
    def test_real_modules_analyze_getzillas_own_installers(self) -> None:
        from getzilla.verification import _command_check
        context = StackContext(ROOT, 'fast', REGISTRY['powershell'], ['scripts/install.ps1'], CheckResult, _command_check,
                               lambda stack, version: ensure_toolchain(stack.id, stack.toolchain, version))
        results = RUNNERS['powershell'](context)
        self.assertEqual([(check.name, check.status) for check in results], [('psscriptanalyzer', 'pass')],
                         [check.stdout[-3000:] + check.stderr[-1000:] for check in results])
        self.assertTrue(results[0].stdout.startswith('powershell 7.'), results[0].stdout[:200])


if __name__ == '__main__':
    unittest.main()
