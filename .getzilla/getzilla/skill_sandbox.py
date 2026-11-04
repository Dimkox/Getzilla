"""Offline generation helpers; ordinary bootstrap consumes fixed assets instead.

No fallback runs an ambient installer. Native execution is supported only by the
explicit Linux Bubblewrap generator; its artifacts need normal source review.
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .component_state import BoundRoot, ComponentStateError, path_parts

MAX_FILE_BYTES = 2097152
MAX_TOTAL_BYTES = 16777216
MAX_FILES = 4096
SANDBOX_TMPFS = '/tmp'  # nosec B108 # new tmpfs inside the disposable namespace
AGENTS = {'bmad': {'claude-code', 'codex', 'qwen', 'gemini', 'grok', 'github-copilot'},
          'spec-kit': {'claude', 'codex', 'qwen', 'gemini', 'grok', 'copilot'}}
OUTPUT_PREFIXES = ('_bmad/', '_bmad-output/', '.specify/', '.agents/', '.claude/', '.codex/',
                   '.qwen/', '.gemini/', '.grok/', '.github/')


def validate_npm_lock(lock):
    if (type(lock) is not dict or lock.get('lockfileVersion') != 3
            or type(lock.get('packages')) is not dict or not 1 <= len(lock['packages']) <= 4096):
        raise ValueError('INVALID_DEPENDENCY_LOCK')
    for name, item in lock['packages'].items():
        if name == '':
            continue
        path_parts(name)
        if not name.startswith('node_modules/') or type(item) is not dict:
            raise ValueError('INVALID_DEPENDENCY_LOCK')
        if item.get('dev') is True:
            continue
        url = urlsplit(str(item.get('resolved', '')))
        integrity = item.get('integrity', '')
        if (url.scheme != 'https' or url.netloc != 'registry.npmjs.org' or url.username or url.password
                or url.query or url.fragment or not url.path.endswith('.tgz')
                or type(integrity) is not str or not integrity.startswith('sha512-')):
            raise ValueError('UNQUALIFIED_DEPENDENCY_ORIGIN')
        try:
            value = base64.b64decode(integrity.removeprefix('sha512-'), validate=True)
        except ValueError as exc:
            raise ValueError('INVALID_DEPENDENCY_INTEGRITY') from exc
        if len(value) != 64:
            raise ValueError('INVALID_DEPENDENCY_INTEGRITY')


def sandbox_command(component: str, source: Path, deps: Path, stage: Path, agent: str, *, script='sh') -> list[str]:
    if component not in AGENTS or agent not in AGENTS[component] or script not in {'sh', 'ps'}:
        raise ValueError('UNSUPPORTED_GENERATION_VARIANT')
    if sys.platform != 'linux' or any(not Path(path).is_dir() for path in (source, deps, stage)):
        raise ValueError('UNQUALIFIED_NATIVE_GENERATOR')
    if (len({path.resolve() for path in (source, deps, stage)}) != 3
            or any(stage.resolve().is_relative_to(path.resolve()) or path.resolve().is_relative_to(stage.resolve())
                   for path in (source, deps))):
        raise ValueError('OVERLAPPING_GENERATOR_ROOTS')
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--cap-drop', 'ALL']
    for path in ('/usr', '/lib', '/lib64'):
        if Path(path).exists():
            command += ['--ro-bind', path, path]
    command += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', SANDBOX_TMPFS,
                '--ro-bind', str(source.resolve()), '/source', '--ro-bind', str(deps.resolve()), '/deps',
                '--bind', str(stage.resolve()), '/work', '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin',
                '--setenv', 'HOME', SANDBOX_TMPFS, '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
                '--setenv', 'PYTHONPATH', '/source/src:/deps', '--chdir', '/work', '--',
                '/usr/bin/prlimit', '--core=0', '--as=2147483648', '--cpu=20', '--nproc=1024',
                '--nofile=256', '--fsize=16777216', '--']
    if component == 'bmad':
        command += ['/usr/bin/node', '--jitless', '--max-old-space-size=128', '--v8-pool-size=1',
                    '/source/tools/installer/bmad-cli.js', 'install', '--directory', '/work', '--tools', agent, '--yes']
    else:
        command += ['/usr/bin/python3', '-c', 'from specify_cli import main; main()', 'init', '--here',
                    '--integration', agent, '--non-interactive', '--ignore-agent-tools', '--script', script]
    return command


def read_stage(root: Path) -> tuple[tuple[str, bytes], ...]:
    # BoundRoot inventories require a named directory. Bind its parent, while
    # rejecting a linked root and keeping all descriptor validation in that API.
    if root.is_symlink():
        raise ValueError('UNSAFE_STAGE_ROOT')
    result, total = [], 0
    try:
        with BoundRoot(root.parent) as binding:
            names = binding.files(root.name, recursive=True)
            if len(names) > MAX_FILES:
                raise ValueError('STAGE_FILE_LIMIT')
            for name in names:
                relative = name.removeprefix(root.name + '/')
                path_parts(relative)
                if (not relative.startswith(OUTPUT_PREFIXES) or any(part in {'.git', '.env'} for part in relative.split('/'))
                        or relative.lower().endswith(('.pem', '.key', '.p12', '.pfx'))):
                    raise ValueError('UNSUPPORTED_STAGE_OUTPUT')
                file = binding.read(name, limit=MAX_FILE_BYTES)
                if file is None:
                    raise ValueError('STAGE_CHANGED')
                total += len(file.content)
                if total > MAX_TOTAL_BYTES:
                    raise ValueError('STAGE_BYTE_LIMIT')
                if file.mode & ~0o777 or file.mode & 0o022:
                    raise ValueError('UNSAFE_STAGE_MODE')
                result.append((relative, file.content))
            if binding.files(root.name, recursive=True) != names:
                raise ValueError('STAGE_CHANGED')
    except (ComponentStateError, OSError) as exc:
        raise ValueError('UNSAFE_STAGE_OUTPUT') from exc
    if not result:
        raise ValueError('EMPTY_STAGE_OUTPUT')
    return tuple(result)
