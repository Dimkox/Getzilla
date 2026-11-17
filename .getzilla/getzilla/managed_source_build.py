"""Explicit per-user source build from official expected SHA256, never old fallback.

GPG/Sigstore material is not claimed verified. No artifact hash is self-computed
and promoted to upstream authority. The native build runs only after byte checks.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .latest_releases import Target
from .managed_environment import execute
from .managed_runtime import directory, entries
from .toolchain import parse_tool_version


def install_source(target: Target, data: bytes, root: Path, *, run=execute) -> Path:
    files, links = entries(target, data)
    if target.component not in {'python', 'git'} or 'configure' not in files:
        raise ValueError('current source build layout unsupported')
    parent = root/'source-builds'
    directory(parent)
    if root.is_symlink() or parent.is_symlink():
        raise ValueError('linked source-build root')
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
    result = run([str(executable), '--version'], source, env=env)
    actual = parse_tool_version('python3' if target.component == 'python' else 'git',
                                (result.stdout or '')+'\n'+(result.stderr or ''))
    if result.returncode or actual != target.version:
        raise ValueError(f'{target.component} target={target.version}: built actual={actual}; no fallback')
    return executable
