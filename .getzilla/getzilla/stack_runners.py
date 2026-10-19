"""Checks for stacks that have no built-in verifier: Rust, .NET and PowerShell (stacks.json).

Each runner gets a :class:`~getzilla.stacks.StackContext`, obtains the stack's pinned toolchain
(a failing ``toolchain:<stack>`` check says why when it cannot), and runs the project's own
build, test, lint and format tools with that toolchain on PATH for the check process only.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .stack_toolchains import (
    INSTALLERS, Blocker, Fetch, Run, Toolchain, ToolchainError, Which, _publish, cache_root, download_verified,
    unpack,
)
from .stacks import RUNNERS, StackContext

# -- shared ---------------------------------------------------------------------------------------

def _project_dirs(context: StackContext, patterns: tuple[str, ...]) -> list[Path]:
    """Shallowest directories holding a build file for the touched files (one per independent project)."""
    from .stacks import tree_files

    files = [path for path in tree_files(context.root) if any(PurePosixPath(path).match(p) for p in patterns)]
    dirs = sorted({PurePosixPath(path).parent for path in files}, key=lambda path: (len(path.parts), str(path)))
    roots: list[PurePosixPath] = []
    for candidate in dirs:
        if not any(candidate == root or root in candidate.parents for root in roots):
            roots.append(candidate)
    touched = [PurePosixPath(path) for path in context.files]
    chosen = [root for root in roots if any(root == PurePosixPath('.') or root in path.parents or path.parent == root
                                            for path in touched)]
    return [context.root / str(root) for root in (chosen or roots)]


def _label(context: StackContext, directory: Path) -> str:
    relative = directory.relative_to(context.root).as_posix()
    return '' if relative == '.' else f':{relative}'


def _gap(context: StackContext, name: str, code: str, path: str, message: str) -> Any:
    refused = context.mode in {'pr', 'release'}
    return context.make(name, 'fail' if refused else 'skip', code, details=[{
        'severity': 'error' if refused else 'warning', 'code': code, 'path': path, 'message': message,
    }])


def _warnings(check: Any, pattern: str) -> Any:
    count = len(re.findall(pattern, f'{check.stdout}\n{check.stderr}', re.MULTILINE))
    if count:
        check.details.append({'severity': 'warning', 'code': 'stack-warnings', 'path': check.name,
                              'message': f'{count} warning(s) reported; they block only when the project denies them'})
    return check


# -- Rust -----------------------------------------------------------------------------------------

def _rustup_digest(source: Mapping[str, Any], key: str, url: str, fetch: Fetch) -> str:
    pinned = (source.get('pinned') or {}).get(source['rustup_version'], {}).get(key)
    try:
        with tempfile.TemporaryDirectory(prefix='getzilla-rustup-') as tmp:
            target = Path(tmp) / 'sha256'
            fetch(url + '.sha256', target)
            published = target.read_text(encoding='utf-8').split()[0]
    except (OSError, ValueError, IndexError) as error:
        if pinned:
            return pinned
        raise ToolchainError('TOOLCHAIN_UNAVAILABLE', f'rustup checksum unavailable: {error}') from error
    if pinned and pinned.lower() != published.lower():
        raise ToolchainError('TOOLCHAIN_CHECKSUM_MISMATCH', 'published rustup-init sha256 differs from stacks.json')
    return pinned or published


def _install_rustup(stack: str, version: str, spec: Mapping[str, Any], key: str, home: Path, fetch: Fetch,
                    run: Run, which: Which) -> dict[str, Any]:
    source = spec['source']
    target = (source.get('targets') or {}).get(key)
    if not target:
        raise ToolchainError(f'TOOLCHAIN_UNSUPPORTED_PLATFORM:{key}', f'rustup has no official build for {key}')
    binary = 'rustup-init.exe' if key.startswith('windows') else 'rustup-init'
    url = source['url'].format(rustup_version=source['rustup_version'], target=target, binary=binary)
    digest = _rustup_digest(source, key, url, fetch)
    init = download_verified(url, digest, 'sha256', cache_root(stack) / 'downloads' / source['rustup_version'] / target / binary, fetch)
    os.chmod(init, 0o700)  # owner-only: the verified installer runs once, as this user
    staging = Path(tempfile.mkdtemp(prefix=f'.staging-{version}-', dir=home.parent))
    try:
        env = {key_: value for key_, value in os.environ.items() if key_ not in {'RUSTUP_TOOLCHAIN', 'CARGO', 'RUSTC'}}
        env.update(RUSTUP_HOME=str(staging / 'rustup'), CARGO_HOME=str(staging / 'cargo'), RUSTUP_INIT_SKIP_PATH_CHECK='yes')
        command = [str(init), '-y', '--no-modify-path', '--no-update-default-toolchain', '--profile', 'minimal',
                   '--default-toolchain', version]
        for component in source.get('components', []):
            command += ['--component', component]
        proc = run(command, env, None)
        if proc.returncode != 0:
            raise ToolchainError('TOOLCHAIN_UNAVAILABLE', f'rustup-init exit={proc.returncode}: {(proc.stderr or proc.stdout)[-800:]}')
        record = {'schema': 'getzilla-toolchain-v1', 'stack': stack, 'version': version, 'platform': key, 'source': url,
                  'algorithm': 'sha256', 'digest': digest, 'rustup_version': source['rustup_version']}
        _publish(staging, home, record)
        return record
    finally:
        shutil.rmtree(staging, ignore_errors=True)


INSTALLERS['rustup'] = _install_rustup


def rust_checks(context: StackContext) -> list[Any]:
    toolchain = context.toolchain()
    if not isinstance(toolchain, Toolchain):
        return [toolchain]
    env = toolchain.process_env()
    results: list[Any] = []
    for directory in _project_dirs(context, ('Cargo.toml',)):
        label = _label(context, directory)
        locked = (directory / 'Cargo.lock').is_file()
        if not locked:
            results.append(_gap(context, f'cargo-lockfile{label}', 'CARGO_LOCK_MISSING', f'{directory.name}/Cargo.toml',
                                'no Cargo.lock: dependency versions are not reproducible and OSV cannot read them'))
        lock = ['--locked'] if locked else []
        results.append(context.command(directory, f'cargo-fmt{label}', ['cargo', 'fmt', '--all', '--', '--check'], 900, env=env))
        clippy = context.command(directory, f'cargo-clippy{label}', ['cargo', 'clippy', '--all-targets', *lock], 1800, env=env)
        results.append(_warnings(clippy, r'^warning:'))
        if context.mode in {'pr', 'release'}:
            results.append(context.command(directory, f'cargo-build{label}', ['cargo', 'build', *lock], 3600, env=env))
            results.append(context.command(directory, f'cargo-test{label}', ['cargo', 'test', *lock], 3600, env=env))
    return results


RUNNERS['rust'] = rust_checks


# -- .NET -----------------------------------------------------------------------------------------

DOTNET_PROJECTS = ('*.sln', '*.slnx', '*.csproj', '*.fsproj')
# Workloads need extra SDK packs (MAUI, mobile, WebAssembly); Getzilla does not install them.
DOTNET_WORKLOAD = re.compile(
    r'<UseMaui>\s*true|Sdk="Microsoft\.NET\.Sdk\.BlazorWebAssembly"|<RuntimeIdentifiers?>[^<]*browser-wasm'
    r'|<TargetFrameworks?>[^<]*-(?:android|ios|maccatalyst|tizen)', re.IGNORECASE)


def _dotnet_target(directory: Path) -> Path | None:
    for pattern in ('*.slnx', '*.sln', '*.csproj', '*.fsproj'):
        found = sorted(directory.glob(pattern))
        if found:
            return found[0]
    return None


def dotnet_checks(context: StackContext) -> list[Any]:
    results: list[Any] = []
    directories = _project_dirs(context, DOTNET_PROJECTS)
    for directory in directories:
        for project in sorted(directory.rglob('*.*proj')):
            if DOTNET_WORKLOAD.search(project.read_text(encoding='utf-8', errors='replace')):
                relative = project.relative_to(context.root).as_posix()
                results.append(_gap(context, f'dotnet-workload:{relative}', 'DOTNET_WORKLOAD_NOT_SUPPORTED', relative,
                                    'this project needs an SDK workload (MAUI, mobile or WebAssembly) that Getzilla does not install'))
    toolchain = context.toolchain()
    if not isinstance(toolchain, Toolchain):
        return [*results, toolchain]
    env = toolchain.process_env()
    for directory in directories:
        target = _dotnet_target(directory)
        if target is None:
            continue
        label = _label(context, directory)
        name = target.name
        if context.mode in {'pr', 'release'}:
            locked = any(directory.rglob('packages.lock.json'))
            restore = ['dotnet', 'restore', name, *(['--locked-mode'] if locked else [])]
            results.append(context.command(directory, f'dotnet-restore{label}', restore, 1800, env=env))
            results.append(context.command(directory, f'dotnet-build{label}', ['dotnet', 'build', name, '--no-restore'], 3600, env=env))
            results.append(context.command(directory, f'dotnet-test{label}', ['dotnet', 'test', name, '--no-build'], 3600, env=env))
            results.append(context.command(directory, f'dotnet-format{label}',
                                           ['dotnet', 'format', name, '--verify-no-changes', '--no-restore'], 1800, env=env))
            vulnerable = context.command(directory, f'nuget-vulnerabilities{label}',
                                         ['dotnet', 'list', name, 'package', '--vulnerable', '--include-transitive',
                                          '--format', 'json'], 900, env=env)
            results.append(_nuget_findings(vulnerable))
        else:
            results.append(context.command(directory, f'dotnet-format{label}', ['dotnet', 'format', name, '--verify-no-changes'],
                                           1800, env=env))
            if not any(directory.rglob('packages.lock.json')):
                results.append(_gap(context, f'nuget-dependencies{label}', 'NUGET_DEPENDENCIES_UNKNOWN', name,
                                    'no packages.lock.json: NuGet dependencies are checked for vulnerabilities only in pr mode'))
    return results


def _nuget_findings(check: Any) -> Any:
    """``dotnet list package --vulnerable`` exits 0 with findings; any reported advisory fails the check."""
    import json

    try:
        data = json.loads(check.stdout or '{}')
    except ValueError:
        return check
    for project in data.get('projects', []):
        for framework in project.get('frameworks', []):
            for package in [*framework.get('topLevelPackages', []), *framework.get('transitivePackages', [])]:
                for advisory in package.get('vulnerabilities', []):
                    check.details.append({'severity': 'error', 'code': 'known-vulnerability', 'path': project.get('path', ''),
                                          'message': f"{package.get('id')} {package.get('resolvedVersion')}: "
                                                     f"{advisory.get('severity')} {advisory.get('advisoryurl')}"})
    if any(item['code'] == 'known-vulnerability' for item in check.details):
        check.status, check.summary = 'fail', f'{len(check.details)} vulnerable NuGet package(s)'
    return check


RUNNERS['dotnet'] = dotnet_checks


# -- PowerShell -----------------------------------------------------------------------------------

def _install_psgallery(stack: str, version: str, spec: Mapping[str, Any], key: str, home: Path, fetch: Fetch,
                       run: Run, which: Which) -> dict[str, Any]:
    """Pinned modules from the PowerShell Gallery; each .nupkg must match its recorded SHA-512."""
    source = spec['source']
    staging = Path(tempfile.mkdtemp(prefix=f'.staging-{version}-', dir=home.parent))
    try:
        record: dict[str, Any] = {'schema': 'getzilla-toolchain-v1', 'stack': stack, 'version': version, 'platform': key,
                                  'algorithm': source['algorithm'], 'modules': {}}
        for module, pin in source['modules'].items():
            url = source['url'].format(module=module, version=pin['version'])
            package = download_verified(url, pin['hash'], source['algorithm'],
                                        cache_root(stack) / 'downloads' / f"{module.lower()}.{pin['version']}.nupkg", fetch)
            target = staging / 'modules' / module / pin['version']
            unpack(package, target)
            for metadata in ('[Content_Types].xml', '_rels', 'package', f'{module}.nuspec'):
                path = target / metadata
                shutil.rmtree(path) if path.is_dir() else path.unlink(missing_ok=True)
            record['modules'][module] = {'version': pin['version'], 'source': url, 'digest': pin['hash']}
        _publish(staging, home, record)
        return record
    finally:
        shutil.rmtree(staging, ignore_errors=True)


INSTALLERS['psgallery'] = _install_psgallery


def powershell_interpreter(spec: Mapping[str, Any], which: Any = shutil.which) -> str | None:
    for name in spec['source'].get('interpreters', ['pwsh', 'powershell']):
        found = which(name)
        if found:
            return found
    return None


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def powershell_checks(context: StackContext) -> list[Any]:
    spec = context.stack.toolchain
    assert spec is not None
    interpreter = powershell_interpreter(spec)
    if interpreter is None:
        blocker = Blocker('TOOLCHAIN_UNAVAILABLE', 'neither pwsh (PowerShell 7) nor Windows PowerShell is installed',
                          'winget install --id Microsoft.PowerShell -e   (Linux: https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux)')
        return [context.make('toolchain:powershell', 'fail', blocker.code, details=[blocker.detail('stack:powershell')])]
    toolchain = context.toolchain()
    if not isinstance(toolchain, Toolchain):
        return [toolchain]
    env = toolchain.process_env()
    modules = spec['source']['modules']
    from .stacks import tree_files

    # The project's own scripts only: never runtime worktrees, dependencies or fixtures.
    scripts = [path for path in tree_files(context.root) if context.stack.owns(path)]
    settings = context.root / 'PSScriptAnalyzerSettings.psd1'
    files = '@(' + ', '.join(_ps_literal(path) for path in scripts) + ')'
    analyzer = (
        "$ErrorActionPreference = 'Stop'; "
        f"Import-Module PSScriptAnalyzer -RequiredVersion {modules['PSScriptAnalyzer']['version']}; "
        "Write-Output ('powershell ' + $PSVersionTable.PSVersion.ToString()); "
        f"$found = {files} | ForEach-Object {{ Invoke-ScriptAnalyzer -Path $_ -Severity Error,Warning"
        + (f" -Settings {_ps_literal(str(settings))}" if settings.is_file() else '') + " }; "
        "$found | ForEach-Object { '{0}:{1} {2} {3} {4}' -f $_.ScriptName, $_.Line, $_.Severity, $_.RuleName, $_.Message }; "
        "if ($found) { exit 1 }"
    )
    command = [interpreter, '-NoProfile', '-NonInteractive', '-Command', analyzer]
    results = [context.command(context.root, 'psscriptanalyzer', command, 1800, env=env)]
    context.notes.update(interpreter=interpreter, scripts=len(scripts))
    tests = [path for path in scripts if path.endswith('.Tests.ps1')]
    if context.mode in {'pr', 'release'} and tests:
        pester = (
            "$ErrorActionPreference = 'Stop'; "
            f"Import-Module Pester -RequiredVersion {modules['Pester']['version']}; "
            f"$result = Invoke-Pester -Path @({', '.join(_ps_literal(path) for path in tests)}) -PassThru -Output Detailed; "
            "if ($result.FailedCount -gt 0 -or $result.Result -ne 'Passed') { exit 1 }"
        )
        results.append(context.command(context.root, 'pester', [interpreter, '-NoProfile', '-NonInteractive', '-Command', pester],
                                       1800, env=env))
    return results


RUNNERS['powershell'] = powershell_checks


# -- Go -------------------------------------------------------------------------------------------

def go_checks(context: StackContext) -> list[Any]:
    toolchain = context.toolchain()
    if not isinstance(toolchain, Toolchain):
        return [toolchain]
    env = toolchain.process_env()
    results: list[Any] = []
    for directory in _project_dirs(context, ('go.mod',)):
        label = _label(context, directory)
        formatted = context.command(directory, f'gofmt{label}', ['gofmt', '-l', '.'], 900, env=env)
        unformatted = [line for line in (formatted.stdout or '').splitlines() if line.strip()]
        if formatted.status == 'pass' and unformatted:
            formatted.status, formatted.summary = 'fail', f'{len(unformatted)} file(s) need gofmt'
            formatted.details.extend({'severity': 'error', 'code': 'gofmt', 'path': path,
                                      'message': 'not gofmt-formatted'} for path in unformatted[:50])
        results.append(formatted)
        results.append(context.command(directory, f'go-vet{label}', ['go', 'vet', './...'], 1800, env=env))
        if context.mode in {'pr', 'release'}:
            results.append(context.command(directory, f'go-build{label}', ['go', 'build', './...'], 3600, env=env))
            results.append(context.command(directory, f'go-test{label}', ['go', 'test', './...'], 3600, env=env))
    return results


RUNNERS['go'] = go_checks


# -- Java / Kotlin ---------------------------------------------------------------------------------

JAVA_BUILDS = ('pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts')


def _wrapper(directory: Path) -> tuple[str, list[str]] | None:
    windows = os.name == 'nt'
    if any((directory / name).is_file() for name in ('build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts')):
        script = directory / ('gradlew.bat' if windows else 'gradlew')
        return ('gradle', [str(script), 'check', '--no-daemon']) if script.is_file() else None
    script = directory / ('mvnw.cmd' if windows else 'mvnw')
    return ('maven', [str(script), '-B', '-ntp', 'verify']) if script.is_file() else None


def java_checks(context: StackContext) -> list[Any]:
    if context.mode not in {'pr', 'release'}:
        return [context.make('java', 'skip', 'Java builds run in pr and release mode', details=[{
            'severity': 'info', 'code': 'java-pr-only', 'path': 'java',
            'message': 'the project wrapper build (mvnw verify / gradlew check) runs in pr and release mode'}])]
    results: list[Any] = []
    directories = _project_dirs(context, JAVA_BUILDS)
    for directory in directories:
        label = _label(context, directory)
        relative = directory.relative_to(context.root).as_posix()
        if _wrapper(directory) is None:
            results.append(_gap(context, f'java-wrapper{label}', 'BUILD_WRAPPER_MISSING', relative,
                                'no mvnw or gradlew: Getzilla builds Java only through the project wrapper, '
                                'never with a global Maven or Gradle'))
        if (directory / 'pom.xml').is_file() and not (directory / 'gradle.lockfile').is_file():
            results.append(_gap(context, f'maven-dependencies{label}', 'MAVEN_DEPENDENCIES_UNKNOWN', relative,
                                'Maven has no lockfile: dependency versions are not reproducible and OSV cannot read them'))
    toolchain = context.toolchain()
    if not isinstance(toolchain, Toolchain):
        return [*results, toolchain]
    env = toolchain.process_env()
    for directory in directories:
        found = _wrapper(directory)
        if found is None:
            continue
        tool, command = found
        results.append(context.command(directory, f'{tool}-build{_label(context, directory)}', command, 3600, env=env))
    return results


RUNNERS['java'] = java_checks
