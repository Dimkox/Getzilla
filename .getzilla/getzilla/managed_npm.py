"""Exact user-managed npm/agents with complete integrity and narrow lifecycle policy."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import tempfile
from pathlib import Path

from .latest_releases import Target, npm_release
from .managed_environment import execute
from .managed_runtime import directory as managed_directory, entries, install
from .skill_sandbox import validate_npm_lock


def _node_engine(target, node, npm, node_version, run, *, environment=None):
    constraint = target.requirements.get('node')
    if constraint:
        semver = npm.parent.parent/'node_modules/semver'
        if not semver.is_dir():
            raise ValueError('current verified npm semver adapter layout is unsupported')
        program = 'const s=require(process.argv[1]);process.exit(s.satisfies(process.argv[2],process.argv[3])?0:2)'
        result = run([str(node), '-e', program, str(semver), node_version, constraint], None, env=environment)
        if result.returncode:
            raise ValueError(f'{target.component} {target.version} requires Node {constraint}; actual current Node {node_version}; no older fallback')


def install_npm(target: Target, data: bytes, root: Path, node: Path, *, run=execute, node_version=None) -> Path:
    files, _ = entries(target, data)
    package = json.loads(files.get('package.json', (b'{}',))[0])
    if package.get('name') != 'npm' or package.get('version') != target.version:
        raise ValueError('npm verified archive package identity differs from exact target')
    path = install(target, data, root, executable='bin/npm-cli.js', launcher=(str(node),), run=run)
    if node_version is not None:
        _node_engine(target, node, path, node_version, run)
    return path


def publish_command(root: Path, command: str, arguments: list[str]) -> Path:
    """CAS protects user customizations; this ledger never qualifies upstream code."""
    from .updater import _replace_bytes
    if not re.fullmatch('[a-z][a-z0-9-]*', command) or any('\n' in a or '\r' in a or '\0' in a for a in arguments):
        raise ValueError('unsafe managed command')
    bin_directory = root/'bin'
    managed_directory(bin_directory)
    path = bin_directory/(command+'.cmd' if os.name == 'nt' else command)
    ledger_path = root/'managed-command-hashes.json'
    if ledger_path.is_symlink() or path.is_symlink():
        raise ValueError(f'user command link conflict: {path}')
    ledger = json.loads(ledger_path.read_text()) if ledger_path.exists() else {}
    if type(ledger) is not dict:
        raise ValueError('invalid managed command custody')
    if os.name == 'nt':
        body = ('@echo off\r\nrem Getzilla managed command\r\n' +
                ' '.join('"'+a.replace('%', '%%').replace('"', '""')+'"' for a in arguments)+' %*\r\n').encode()
    else:
        body = ('#!/bin/sh\n# Getzilla managed command\nexec '+shlex.join(arguments)+' "$@"\n').encode()
    if path.exists():
        current = path.read_bytes()
        if current != body and hashlib.sha256(current).hexdigest() != ledger.get(command):
            raise ValueError(f'user command CAS conflict: {path}')
    _replace_bytes(path, body, mode=0o755)
    ledger[command] = hashlib.sha256(body).hexdigest()
    _replace_bytes(ledger_path, (json.dumps(ledger, sort_keys=True)+'\n').encode(), mode=0o600)
    return path


def install_agent(target: Target, root: Path, node: Path, npm: Path, *, command: str, fetch, run=execute, node_version=None) -> Path:
    """Lock without scripts, verify every official tarball, audit, then scoped activation."""
    stage_parent = root/'agents'/command
    managed_directory(stage_parent)
    if any(p.is_symlink() for p in (root, root/'agents', stage_parent)):
        raise ValueError('linked managed agent root')
    stage = Path(tempfile.mkdtemp(prefix=target.version+'-', dir=stage_parent))
    package = dict(name='getzilla-owned-agent', version='1.0.0', private=True, dependencies={target.component: target.version})
    (stage/'package.json').write_text(json.dumps(package)+'\n')
    private = stage/'private-home'
    private.mkdir(mode=0o700)
    env = {k: v for k, v in os.environ.items() if k in ('SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT')}
    env.update(PATH=str(node.parent)+os.pathsep+os.defpath, HOME=str(private), USERPROFILE=str(private),
               APPDATA=str(private), LOCALAPPDATA=str(private), NPM_CONFIG_USERCONFIG=str(private/'absent-npmrc'),
               NPM_CONFIG_CACHE=str(stage/'cache'), NPM_CONFIG_FUND='false')
    if node_version is not None:
        _node_engine(target, node, npm, node_version, run, environment=env)
    prefix = [str(node), str(npm)]

    def checked(arguments, phase):
        result = run([*prefix, *arguments], stage, env=env)
        if result.returncode:
            raise ValueError(f'{command} {target.version} {phase}: {(result.stderr or result.stdout)[-400:]}')
        return result

    common = ['--prefix', str(stage), '--registry=https://registry.npmjs.org', '--fetch-retries=0', '--fetch-timeout=20000']
    checked(['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', *common], 'resolve exact closure')
    lock_path = stage/'package-lock.json'
    if lock_path.stat().st_size > 2*1024*1024:
        raise ValueError('agent dependency lock exceeds byte bound')
    lock = json.loads(lock_path.read_text())
    validate_npm_lock(lock)
    if lock['packages'].get('', {}).get('dependencies') != package['dependencies']:
        raise ValueError('agent lock selected a different direct target')
    direct = lock['packages'].get('node_modules/'+target.component, {})
    if direct.get('version') != target.version or direct.get('integrity') != target.integrity:
        raise ValueError('agent direct lock identity/integrity differs from fresh target')
    artifacts = stage/'verified-tarballs'
    artifacts.mkdir(mode=0o700)
    total = 0
    for i, (name, row) in enumerate(lock['packages'].items()):
        if name == '':
            continue
        package_name = name.rsplit('node_modules/', 1)[-1]
        selected = npm_release(package_name, fetch, version=row.get('version'))
        if selected.url != row.get('resolved') or selected.integrity != row.get('integrity'):
            raise ValueError('agent dependency origin/integrity differs from official exact registry metadata')
        raw = fetch(selected.url)
        selected.verify(raw)
        total += len(raw)
        if len(raw) > 128*1024*1024 or total > 512*1024*1024:
            raise ValueError('agent artifact byte bound exceeded')
        path = artifacts/(str(i)+'.tgz')
        path.write_bytes(raw)
        checked(['cache', 'add', str(path), '--ignore-scripts', '--offline', *common], 'seed verified artifact cache')
    checked(['ci', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', *common], 'install verified closure')
    checked(['audit', 'signatures', *common], 'verify registry signatures/provenance')
    if command == 'copilot':
        # Official Copilot requires its root lifecycle; no unrelated package scripts run.
        checked(['rebuild', '@github/copilot', '--offline', '--ignore-scripts=false', '--no-audit', '--no-fund', *common],
                'run qualified Copilot lifecycle')
    directory = stage/'node_modules'/target.component
    installed = json.loads((directory/'package.json').read_text())
    if installed.get('name') != target.component or installed.get('version') != target.version:
        raise ValueError('installed agent identity differs from fresh target')
    bins = installed.get('bin', {})
    relative = bins if type(bins) is str else bins.get(command)
    if type(relative) is not str or any(p in ('', '.', '..') for p in relative.split('/')) or relative.startswith('/') or '\\' in relative:
        raise ValueError('unsupported agent executable layout')
    executable = directory/relative
    if executable.is_symlink() or not executable.is_file():
        raise ValueError('agent executable is missing/linked')
    result = run([str(node), str(executable), '--version'], stage, env=env)
    if result.returncode or not re.search(r'(?<![\w.])'+re.escape(target.version)+r'(?![\w.])', result.stdout or ''):
        raise ValueError(f'{command} target={target.version}: actual software version probe failed')
    return publish_command(root, command, [str(node), str(executable)])
