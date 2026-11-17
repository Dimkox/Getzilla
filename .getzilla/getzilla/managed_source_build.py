"""Explicit per-user source build from official expected SHA256, never old fallback.

GPG/Sigstore material is not claimed verified. No artifact hash is self-computed
and promoted to upstream authority. The native build runs only after byte checks.
"""
from __future__ import annotations

import os
import json
import hashlib
import re
import stat
import tempfile
from pathlib import Path

from .latest_releases import Target
from .managed_environment import execute
from .managed_runtime import directory, entries, MAX_FILES, MAX_BYTES, MAX_FILE_BYTES
from .toolchain import parse_tool_version


def _inventory(prefix):
    result, total = {}, 0
    for parent, dirs, names in os.walk(prefix, followlinks=False):
        for name in [*dirs, *names]:
            path = Path(parent)/name
            relative = path.relative_to(prefix).as_posix()
            if len(result) >= MAX_FILES:
                raise ValueError('source build custody inventory bound')
            if path.is_symlink():
                if not path.resolve().is_relative_to(prefix.resolve()):
                    raise ValueError('source build link leaves owned prefix')
                result[relative] = dict(link=os.readlink(path))
            elif path.is_file():
                info = path.stat()
                total += info.st_size
                if info.st_size > MAX_FILE_BYTES or total > MAX_BYTES or info.st_nlink != 1:
                    raise ValueError('source build custody byte/link bound')
                result[relative] = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), mode=stat.S_IMODE(info.st_mode))
            elif not path.is_dir():
                raise ValueError('special source build output')
    return result


def _probe(target, executable, stage, env, run):
    result = run([str(executable), '--version'], stage, env=env)
    actual = parse_tool_version('python3' if target.component == 'python' else target.component,
                               (result.stdout or '')+'\n'+(result.stderr or ''))
    if result.returncode or actual != target.version:
        raise ValueError(f'{target.component} target={target.version}: built actual={actual}; no fallback')


def install_source(target: Target, data: bytes, root: Path, *, run=execute) -> Path:
    files, links = entries(target, data)
    if target.component not in {'python', 'git', 'php'} or 'configure' not in files:
        raise ValueError('current source build layout unsupported')
    parent = root/'source-builds'
    directory(parent)
    if root.is_symlink() or parent.is_symlink():
        raise ValueError('linked source-build root')
    hint = parent/(target.component+'-'+target.sha256+'.json')
    if hint.exists():
        if hint.is_symlink() or hint.stat().st_size > 1024:
            raise ValueError('invalid local source-build locator')
        locator = json.loads(hint.read_text())
        name = locator.get('stage', '')
        if not re.fullmatch(re.escape(target.component+'-'+target.version+'-')+r'[A-Za-z0-9_-]+', name):
            raise ValueError('local source-build locator leaves exact target namespace')
        stage = parent/name
        directory(stage)
        record_path = stage/'build-custody.json'
        if record_path.is_symlink() or record_path.stat().st_size > 2*1024*1024:
            raise ValueError('local source-build custody unavailable/exceeds bounds')
        record = json.loads(record_path.read_text())
        if record.get('source') != dict(component=target.component, version=target.version, sha256=target.sha256, url=target.url):
            raise ValueError('local build source differs from fresh official target')
        prefix = stage/'installed'
        directory(prefix)
        if _inventory(prefix) != record.get('files'):
            raise ValueError('local source-build user/custody conflict; files preserved')
        executable = prefix/('bin/python3' if target.component == 'python' else 'bin/'+target.component)
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'SystemRoot', 'WINDIR', 'LD_LIBRARY_PATH')}
        env.update(HOME=str(stage/'private-home'), USERPROFILE=str(stage/'private-home'), PYTHONNOUSERSITE='1')
        _probe(target, executable, stage, env, run)
        if _inventory(prefix) != record['files']:
            raise ValueError('local source build changed during actual probe')
        return executable
    stage = Path(tempfile.mkdtemp(prefix=target.component+'-'+target.version+'-', dir=parent))
    source, prefix = stage/'source', stage/'installed'
    source.mkdir(mode=0o700)
    for name, (body, mode) in files.items():
        path = source/name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(body)
        path.chmod(mode)
    for name, link in links.items():
        path = source/name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.symlink_to(link)
    # Fixed program/argv from a verified official archive; no user shell payload.
    commands = [['./configure', '--prefix='+str(prefix)]]
    if target.component == 'python':
        commands[0].append('--with-ensurepip=install')
        commands += [['make', '-j4'], ['make', 'install']]
        executable = prefix/'bin/python3'
    elif target.component == 'php':
        commands[0] += ['--enable-cli', '--disable-cgi', '--without-pear', '--with-openssl', '--with-zlib', '--with-curl', '--enable-mbstring']
        commands += [['make', '-j4'], ['make', 'install']]
        executable = prefix/'bin/php'
    else:
        commands += [['make', '-j4', 'NO_TCLTK=YesPlease', 'NO_GETTEXT=YesPlease'],
                     ['make', 'install', 'NO_TCLTK=YesPlease', 'NO_GETTEXT=YesPlease']]
        executable = prefix/'bin/git'
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'SystemRoot', 'WINDIR', 'LD_LIBRARY_PATH')}
    private = stage/'private-home'
    private.mkdir(mode=0o700)
    env.update(HOME=str(private), USERPROFILE=str(private), PYTHONNOUSERSITE='1',
               PIP_CONFIG_FILE=os.devnull, PIP_NO_INPUT='1')
    for command in commands:
        result = run(command, source, env=env)
        if result.returncode:
            raise ValueError(f'{target.component} {target.version}: verified source build failed; '
                             f'check compiler/development prerequisites: {(result.stderr or result.stdout)[-500:]}')
    if not executable.is_file() or not executable.resolve().is_relative_to(prefix.resolve()):
        raise ValueError('built runtime executable is missing or outside the owned prefix')
    _probe(target, executable, source, env, run)
    # This is local build custody, not a publisher's compiled binary attestation.
    # The next invocation revalidates fresh official source integrity first.
    from .updater import _replace_bytes
    record = dict(source=dict(component=target.component, version=target.version, sha256=target.sha256, url=target.url),
                  files=_inventory(prefix), claim='local-source-build-custody')
    _replace_bytes(stage/'build-custody.json', json.dumps(record, sort_keys=True).encode(), mode=0o600)
    _replace_bytes(hint, json.dumps(dict(stage=stage.name)).encode(), mode=0o600)
    return executable
