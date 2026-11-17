"""Installer join: resolve all selected current targets, activate exact bytes, inspect actual paths."""
from __future__ import annotations

import importlib.metadata
import json
import os
import platform
import re
import shutil
import sys
from pathlib import Path

from . import latest_releases as releases
from .managed_environment import PROJECTS, execute
from .managed_npm import install_npm, install_agent, publish_command
from .managed_runtime import install as install_runtime
from .managed_source_build import install_source
from .toolchain import parse_tool_version

AGENT_PACKAGES = {'qwen': '@qwen-code/qwen-code', 'codex': '@openai/codex',
                  'gemini': '@google/gemini-cli', 'copilot': '@github/copilot'}
TOOLS = {'php', 'composer', 'syft', 'trivy', 'cosign', 'gh', 'jscpd', 'docker'}


def _host(system=None, architecture=None):
    system = system or ('windows' if os.name == 'nt' else sys.platform)
    system = 'linux' if system.startswith('linux') else system
    arch = (architecture or platform.machine()).lower()
    return system, {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64'}.get(arch, arch)


def _github_tool(component, fetch, system, arch):
    repo = {'syft': 'anchore/syft', 'trivy': 'aquasecurity/trivy', 'cosign': 'sigstore/cosign',
            'gh': 'cli/cli', 'pwsh': 'PowerShell/PowerShell'}[component]
    release = releases.github_release(repo, fetch)
    version = release['version']
    cpu = {'x64': 'amd64', 'arm64': 'arm64'}.get(arch)
    if not cpu:
        raise ValueError(f'{component}: native architecture {arch} unsupported')
    if component == 'syft':
        name = f'syft_{version}_{system}_{cpu}.'+('zip' if system == 'windows' else 'tar.gz')
    elif component == 'trivy':
        os_label = {'windows': 'Windows', 'linux': 'Linux', 'darwin': 'macOS'}[system]
        name = f'trivy_{version}_{os_label}-'+('64bit' if cpu == 'amd64' else 'ARM64')+('.zip' if system == 'windows' else '.tar.gz')
    elif component == 'cosign':
        name = f'cosign-{system}-{cpu}'+('.exe' if system == 'windows' else '')
    elif component == 'gh':
        name = f'gh_{version}_{system}_{cpu}.'+('zip' if system == 'windows' else 'tar.gz')
    else:
        name = f'PowerShell-{version}-win-{arch}.zip' if system == 'windows' else f'powershell-{version}-{system}-{arch}.tar.gz'
    return releases.github_asset(release, name, component=component)


def plan(fetch, *, system, arch, agent, tools):
    selected = set(tools)
    if selected - TOOLS:
        raise ValueError('unknown selected managed tools: '+','.join(sorted(selected-TOOLS)))
    if 'composer' in selected:
        selected.add('php')
    resolvers = {
        'python': lambda: releases.python_windows(fetch, arch) if system == 'windows' else releases.python_source(fetch),
        'git': lambda: releases.git_windows(fetch, arch) if system == 'windows' else releases.git_source(fetch),
        'node': lambda: releases.node_release(fetch, system, arch),
        'npm': lambda: releases.npm_release('npm', fetch),
    }
    if system == 'windows':
        resolvers['pwsh'] = lambda: _github_tool('pwsh', fetch, system, arch)
    for tool in sorted(selected):
        if tool == 'php':
            def php():
                return releases.php_windows(fetch, arch) if system == 'windows' else releases.php_source(fetch)
            resolvers[tool] = php
        elif tool == 'composer':
            resolvers[tool] = lambda: releases.composer_release(fetch)
        elif tool == 'jscpd':
            resolvers[tool] = lambda: releases.npm_release('jscpd', fetch)
        elif tool == 'docker':
            resolvers[tool] = lambda: (_ for _ in ()).throw(ValueError('Docker service/operator activation is outside this per-user installer; explicit current runtime proof required'))
        else:
            resolvers[tool] = lambda t=tool: _github_tool(t, fetch, system, arch)
    if agent in AGENT_PACKAGES:
        resolvers['agent:'+agent] = lambda: releases.npm_release(AGENT_PACKAGES[agent], fetch)
    elif agent == 'claude':
        resolvers['agent:claude'] = lambda: releases.claude_release(fetch, system, arch, musl=platform.libc_ver()[0] == 'musl')
    elif agent:
        message = ('official Grok stable pointer lacks a published artifact integrity contract' if agent == 'grok' else
                   'Claude newest stable channel/manifest signature adapter is not established')
        resolvers['agent:'+agent] = lambda: (_ for _ in ()).throw(ValueError(message+'; software incomplete, no unchecked vendor script'))
    targets, errors = {}, []
    for component, resolve in resolvers.items():
        try:
            targets[component] = resolve()
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(dict(component=component, status='incomplete', error=str(exc)))
    return targets, errors


def ensure_python(root, *, fetch, run=execute, system=None, architecture=None):
    system, arch = _host(system, architecture)
    target = releases.python_windows(fetch, arch) if system == 'windows' else releases.python_source(fetch)
    # A fresh authoritative exact comparison permits reuse, never presence/minimum.
    base = Path(getattr(sys, '_base_executable', sys.executable))
    actual = run([str(base), '--version'], None)
    if actual.returncode == 0 and parse_tool_version('python3', (actual.stdout or '')+'\n'+(actual.stderr or '')) == target.version:
        return base
    raw = fetch(target.url)
    if system == 'windows':
        return install_runtime(target, raw, root, executable='python.exe', run=run)
    return install_source(target, raw, root, run=run)


def verify_environment(home, fetch):
    expected_python = home/'.venv'/('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not expected_python.is_file() or not Path(sys.executable).samefile(expected_python):
        raise ValueError('installer is not executing under Getzilla actual managed .venv interpreter')
    expected = {name: releases.pypi_version(name, fetch) for name in PROJECTS}
    actual = {name: importlib.metadata.version(name) for name in PROJECTS}
    if actual != expected:
        raise ValueError('actual managed quality versions differ from freshly resolved current targets: '+json.dumps(dict(target=expected, actual=actual)))
    return dict(component='python-environment', status='complete', path=str(expected_python), actual=actual, target=expected)


def install_software(root, home, *, agent=None, tools=(), fetch=None, run=execute, which=shutil.which,
                     system=None, architecture=None, verify_only=False):
    from .updater import _release_fetch
    fetch = fetch or _release_fetch
    system, arch = _host(system, architecture)
    targets, records = plan(fetch, system=system, arch=arch, agent=agent, tools=tools)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    paths = {}
    if not verify_only:
        os.environ['PATH'] = str(root/'bin')+os.pathsep+os.environ.get('PATH', '')
    for component in ('python', 'git', 'pwsh', 'node', 'npm', 'php', 'composer', 'syft', 'trivy', 'cosign', 'gh', 'jscpd',
                      *(['agent:'+agent] if agent else [])):
        if component not in targets:
            continue
        target = targets[component]
        command = component.removeprefix('agent:')
        try:
            if verify_only:
                path = which(command)
                allowed = [root/'bin'/(command+'.cmd' if system == 'windows' else command)]
                if component == 'python':
                    allowed += [home/'.venv'/('Scripts/python.exe' if system == 'windows' else 'bin/python')]
                if not path or Path(path) not in allowed:
                    raise ValueError(f'PATH shadowing/unverified active path: actual={path}; expected={allowed}')
                version_args = ['-v'] if component == 'php' else ['version'] if component in {'cosign', 'syft'} else ['--version']
                result = run([path, *version_args], None)
                actual = parse_tool_version('python3' if command == 'python' else command,
                                            (result.stdout or '')+'\n'+(result.stderr or ''))
                if component.startswith('agent:'):
                    match = re.search(r'(?<![\w.])'+re.escape(target.version)+r'(?![\w.])', result.stdout or '')
                    actual = target.version if match else None
                if result.returncode or actual != target.version:
                    raise ValueError(f'active version mismatch: target={target.version}, actual={actual}, exit={result.returncode}')
                paths[component] = Path(path)
            elif component == 'npm':
                node = paths['node']
                path = install_npm(target, fetch(target.url), root, node, run=run, node_version=targets['node'].version)
                paths[component] = path
                publish_command(root, 'npm', [str(node), str(path)])
                publish_command(root, 'npx', [str(node), str(path.parent/'npx-cli.js')])
            elif component == 'agent:claude':
                path = install_runtime(target, fetch(target.url), root, executable=target.filename, run=run)
                paths[component] = path
                publish_command(root, 'claude', [str(path)])
            elif component.startswith('agent:') or component == 'jscpd':
                if component == 'jscpd' and target.version != '4.0.5':
                    raise ValueError(f'latest jscpd {target.version}: consumer schema adapter supports4.0.5; no old-version fallback')
                path = install_agent(target, root, paths['node'], paths['npm'], command=command, fetch=fetch, run=run,
                                     node_version=targets['node'].version)
                paths[component] = path
            elif component == 'composer':
                php = paths['php']
                result = run([str(php), '-v'], None)
                version = parse_tool_version('php', result.stdout or '')
                parts = [int(p) for p in (version or '0.0.0').split('.')]
                if result.returncode or (parts+[0, 0])[:3][0]*10000+(parts+[0, 0])[:3][1]*100+(parts+[0, 0])[:3][2] < target.requirements['php']:
                    raise ValueError('current Composer is incompatible with actual PHP; no LTS fallback')
                path = install_runtime(target, fetch(target.url), root, executable='composer.phar', launcher=(str(php),), run=run)
                paths[component] = path
                publish_command(root, 'composer', [str(php), str(path)])
            else:
                if component == 'python' and system != 'windows':
                    # The managed environment already uses the freshly installed
                    # base Python. Avoid rebuilding that same exact target twice.
                    base = Path(getattr(sys, '_base_executable', sys.executable))
                    probe = run([str(base), '--version'], None)
                    if probe.returncode == 0 and parse_tool_version('python3', probe.stdout or '') == target.version:
                        path = base
                    else:
                        path = install_source(target, fetch(target.url), root, run=run)
                elif component in {'git', 'php'} and system != 'windows':
                    path = install_source(target, fetch(target.url), root, run=run)
                else:
                    executable = {'git': 'cmd/git.exe', 'gh': 'bin/gh.exe' if system == 'windows' else 'bin/gh',
                                  'node': 'node.exe' if system == 'windows' else 'bin/node'}.get(component,
                                  component+('.exe' if system == 'windows' else ''))
                    args = ('-v',) if component == 'php' else ('version',) if component in {'syft', 'cosign'} else ('--version',)
                    path = install_runtime(target, fetch(target.url), root, executable=executable, run=run, version_args=args)
                paths[component] = path
                if component != 'python':
                    publish_command(root, command, [str(path)])
            records.append(dict(component=component, status='complete', target=target.version, actual=target.version,
                                path=str(paths[component]), origin=target.metadata_url, metadata_sha256=target.metadata_sha256))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            records.append(dict(component=component, status='incomplete', target=target.version, error=str(exc)))
    try:
        records.append(verify_environment(home, fetch))
    except (OSError, ValueError, importlib.metadata.PackageNotFoundError) as exc:
        records.append(dict(component='python-environment', status='incomplete', error=str(exc)))
    return dict(status='complete' if all(r['status'] == 'complete' for r in records) else 'incomplete',
                tool_bin=str(root/'bin'), components=records)
