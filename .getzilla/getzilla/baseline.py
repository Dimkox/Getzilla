"""Mandatory baseline: security data plus pinned Superpowers, BMAD and Spec Kit for the agent in use.

`install_user` fetches the configured exact source pins. `apply_project` consumes
reviewable generated assets tied to those pins, full archive hashes, dependency locks,
and fixed generation commands. It never invokes ambient npx/specify or upstream code.
No native sandbox is required on consumer machines. Semantic safety remains unqualified.
`inspect` reports missing baseline data; it does not claim tools or permissions exist.
"""
from __future__ import annotations

import json
import stat
import sys
import tempfile
from contextlib import contextmanager
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from . import STACK_DIR, fsx, state
from .policy import evaluate_pre_tool
from .managed_runtime import directory as managed_directory

TOOLCHAIN = STACK_DIR / 'config' / 'toolchain.json'
BASELINE_DIR = 'baseline'
SKILL_SOURCE = '.agents/skills'
AGENT_SKILL_DIRS = {'claude': '.claude/skills', 'qwen': '.qwen/skills', 'gemini': '.gemini/skills',
                    'grok': '.grok/skills', 'codex': '.agents/skills'}
AGENTS = ('claude', 'codex', 'qwen', 'gemini', 'grok', 'copilot')

Runner = Callable[[list[str], Path | None], subprocess.CompletedProcess]


@dataclass(frozen=True)
class Step:
    component: str
    status: str  # ok, fail, skip
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {'component': self.component, 'status': self.status, 'detail': self.detail}


def _env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update({'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1'})
    return env


def default_runner(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding='utf-8', errors='replace',
                              check=False, env=_env(), timeout=1800)
    except FileNotFoundError:
        return subprocess.CompletedProcess(command, 127, '', f'executable not found: {Path(command[0]).name}')


def components(path: Path = TOOLCHAIN) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding='utf-8'))
    return {str(item['id']): item for item in data['workflow_sources']['components']}


def _tail(process: subprocess.CompletedProcess) -> str:
    text = ((process.stderr or '') + (process.stdout or '')).strip().splitlines()
    return text[-1][:300] if text else f'exit {process.returncode}'


def pinned_checkout(home: Path) -> Path:
    return home / BASELINE_DIR


def _head(run: Runner, target: Path) -> str | None:
    process = run(['git', '-C', str(target), 'rev-parse', 'HEAD'], None)
    return (process.stdout or '').strip() if process.returncode == 0 else None


def _upstream(url: str) -> str:
    return url


_CACHE_WINDOWS = os.name == 'nt'


def _cache_file_id(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_size,
            info.st_mtime_ns, info.st_nlink, stat.S_IMODE(info.st_mode))


def _cache_open_leaf(directory, name, path):
    if not fsx.WINDOWS:
        return fsx.open_at(directory, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_CLOEXEC)
    # An O_RDONLY CRT handle lacks FILE_WRITE_ATTRIBUTES. Ask only for attribute
    # access on this checked leaf, with reparse traversal disabled.
    import ctypes
    import msvcrt
    from ctypes import wintypes
    native = ctypes.WinDLL('kernel32', use_last_error=True)
    create = native.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    handle = create(str(path), 0x180, 7, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | fsx.O_BINARY | fsx.O_NOINHERIT)
    except BaseException:
        native.CloseHandle.argtypes = [wintypes.HANDLE]
        native.CloseHandle(handle)
        raise


def _cache_readonly(fd, readonly):
    """Change only this held regular file's ReadOnly bit, never its parent."""
    if hasattr(os, 'fchmod'):
        mode = stat.S_IMODE(os.fstat(fd).st_mode)
        os.fchmod(fd, mode & ~stat.S_IWRITE if readonly else mode | stat.S_IWRITE)
        return
    # Older native Windows Python lacks fchmod. Keep the same handle identity
    # instead of falling back to a path-based chmod that can follow a swap.
    import ctypes
    import msvcrt
    from ctypes import wintypes
    class BasicInfo(ctypes.Structure):
        _fields_ = [('creation', ctypes.c_longlong), ('access', ctypes.c_longlong),
                    ('write', ctypes.c_longlong), ('change', ctypes.c_longlong), ('attributes', wintypes.DWORD)]
    native = ctypes.WinDLL('kernel32', use_last_error=True)
    value = BasicInfo()
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(fd))
    for operation in ('GetFileInformationByHandleEx', 'SetFileInformationByHandle'):
        function = getattr(native, operation)
        function.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        function.restype = wintypes.BOOL
        if operation.startswith('Set'):
            value.attributes = value.attributes | 1 if readonly else value.attributes & ~1
        if not function(handle, 0, ctypes.byref(value), ctypes.sizeof(value)):
            raise ctypes.WinError(ctypes.get_last_error())


def remove_owned_cache(target: Path, parent: Path, identity) -> None:
    """Remove one proved cache root; only genuine Windows ReadOnly unlink retries."""
    target, parent = Path(target).absolute(), Path(parent).absolute()
    if target.parent != parent:
        raise ValueError('CACHE_ROOT_OUTSIDE_OWNED_PARENT')
    with fsx.ReadOnlyBoundRoot(parent) as outer, fsx.ReadOnlyBoundRoot(target) as bound:
        root_info = os.lstat(target)
        if fsx.effective_uid() is not None and root_info.st_uid != fsx.effective_uid():
            raise ValueError('UNOWNED_CACHE_ROOT')
        if fsx._identity(root_info) != identity:
            raise ValueError('CACHE_ROOT_IDENTITY_CHANGED')
        inventory = {}
        def walk_error(error):
            raise error
        for directory, dirs, names in os.walk(target, followlinks=False, onerror=walk_error):
            for name in [*dirs, *names]:
                path = Path(directory)/name
                relative = path.relative_to(target).as_posix()
                fsx.path_parts(relative)
                info = os.lstat(path)
                if (fsx.is_link(info) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                        or stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                    raise ValueError('UNSAFE_CACHE_LINK_OR_SPECIAL_ENTRY')
                if fsx.effective_uid() is not None and info.st_uid != fsx.effective_uid():
                    raise ValueError('UNOWNED_CACHE_ENTRY')
                inventory[relative] = _cache_file_id(info)
                if len(inventory) > 20000:
                    raise ValueError('CACHE_INVENTORY_BOUNDS')
        def authorize(path):
            if state.route_authority_present(parent):
                state.require_route_owner(parent)
                allowed, _ = evaluate_pre_tool(parent, {'tool_name': 'Write', 'tool_input': {'file_path': str(path)}})
                if not allowed:
                    raise ValueError('CACHE_CLEANUP_AUTHORITY_REQUIRED')
        def retry(function, failed, error):
            failure = error[1] if isinstance(error, tuple) else error
            path = Path(failed).absolute()
            if (not _CACHE_WINDOWS or not isinstance(failure, PermissionError) or getattr(failure, 'winerror', None) != 5
                    or function not in (os.unlink, os.remove) or not path.is_relative_to(target)):
                raise failure
            relative = path.relative_to(target).as_posix()
            with bound.parent(relative) as (directory, name, check):
                check()
                outer.check()
                info = os.lstat(path)
                if (relative not in inventory or _cache_file_id(info) != inventory[relative] or fsx.is_link(info)
                        or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or not getattr(info, 'st_file_attributes', 0) & 1):
                    raise failure
                descriptor = _cache_open_leaf(directory, name, path)
                try:
                    opened = os.fstat(descriptor)
                    if fsx.is_link(opened) or _cache_file_id(opened) != inventory[relative]:
                        raise ValueError('CACHE_LEAF_IDENTITY_CHANGED')
                    check()
                    outer.check()
                    authorize(path)
                    _cache_readonly(descriptor, False)
                    expected = _cache_file_id(os.fstat(descriptor))
                finally:
                    os.close(descriptor)
                check()
                outer.check()
                current = os.lstat(path)
                if fsx.is_link(current) or _cache_file_id(current) != expected or current.st_nlink != 1:
                    raise ValueError('CACHE_LEAF_CHANGED_BEFORE_RETRY')
                function(str(path))  # One retry. An ACL/other failure still propagates.
        with state.task_transition(parent):
            outer.check()
            bound.check()
            authorize(target)
            for relative in inventory:
                authorize(target/relative)
            if sys.version_info >= (3, 12):
                shutil.rmtree(target, onexc=retry)
            else:
                shutil.rmtree(target, onerror=retry)
            outer.check()


@contextmanager
def temporary_cache(parent: Path, *, prefix='current-'):
    """A fresh private cache and its exact root identity stay owned in this scope."""
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    identity = fsx._identity(os.lstat(path))
    try:
        yield path
    finally:
        remove_owned_cache(path, parent, identity)


def _replaceable_cache(run, target, origin):
    # An old public cache is not adopted from its directory name alone. Preserve
    # user modifications, ignored/untracked files, and a foreign Git origin.
    remote = run(['git', '-C', str(target), 'config', '--get', 'remote.origin.url'], None)
    clean = run(['git', '-c', 'core.fsmonitor=false', '-C', str(target), 'status', '--porcelain=v1',
                 '--untracked-files=all', '--ignored=matching'], None)
    return remote.returncode == clean.returncode == 0 and (remote.stdout or '').strip() == origin and not (clean.stdout or '').strip()


def install_user(home: Path, *, run: Runner = default_runner, which: Callable[[str], str | None] = shutil.which,
                 config: Mapping[str, Mapping[str, Any]] | None = None,
                 locate: Callable[[str], str] = _upstream) -> list[Step]:
    """Pinned workflow sources and tools for this user; a mismatch or a missing prerequisite fails.

    ``locate`` maps each upstream Git URL to the one to use (the updater's offline mirror).
    """
    config = config or components()
    steps: list[Step] = []
    root = pinned_checkout(home)
    try:
        managed_directory(root)
    except (OSError, ValueError) as exc:
        return [Step('baseline:cache', 'fail', str(exc))]
    for component_id, component in sorted(config.items()):
        if component_id not in {'superpowers', 'bmad', 'spec-kit'}:
            steps.append(Step('baseline:cache', 'fail', 'UNKNOWN_CACHE_COMPONENT'))
            continue
        target = root / component_id
        expected = component['pinned_commit']
        try:
            with fsx.ReadOnlyBoundRoot(root):
                if os.path.lexists(target) and fsx.is_link(os.lstat(target)):
                    raise ValueError('UNSAFE_CACHE_ROOT')
        except (OSError, ValueError) as exc:
            steps.append(Step(f'baseline:{component_id}', 'fail', str(exc)))
            continue
        if target.is_dir() and _head(run, target) == expected:
            steps.append(Step(f'baseline:{component_id}', 'ok', f"{component['pinned']} ({expected[:12]}, already installed)"))
            continue
        if target.exists():
            try:
                origin = locate(f"https://github.com/{component['repository']}.git")
                if not _replaceable_cache(run, target, origin):
                    raise ValueError('USER_OR_UNPROVED_CACHE_PRESERVED')
                remove_owned_cache(target, root, fsx._identity(os.lstat(target)))
            except (OSError, ValueError) as exc:
                steps.append(Step(f'baseline:{component_id}', 'fail', 'CACHE_CLEANUP_FAILED: '+str(exc)))
                continue
        process = run(['git', '-c', 'advice.detachedHead=false', 'clone', '-q', '--depth', '1', '--branch',
                       component['upstream_tag'], locate(f"https://github.com/{component['repository']}.git"), str(target)],
                      None)
        if process.returncode != 0:
            steps.append(Step(f'baseline:{component_id}', 'fail', f"clone {component['upstream_tag']}: {_tail(process)}"))
            continue
        head = _head(run, target)
        if head != expected:
            try:
                remove_owned_cache(target, root, fsx._identity(os.lstat(target)))
            except (OSError, ValueError) as exc:
                steps.append(Step(f'baseline:{component_id}', 'fail', 'PINNED_COMMIT_MISMATCH; CACHE_CLEANUP_FAILED: '+str(exc)))
                continue
            steps.append(Step(f'baseline:{component_id}', 'fail',
                              f"PINNED_COMMIT_MISMATCH: {component['upstream_tag']} is {head}, expected {expected}"))
            continue
        steps.append(Step(f'baseline:{component_id}', 'ok', f"{component['pinned']} ({expected[:12]})"))
    from .baseline_assets import load
    for component_id in ('superpowers', 'bmad', 'spec-kit'):
        try:
            load(component_id, 'claude')
        except ValueError as exc:
            steps.append(Step(f'baseline:{component_id}-assets', 'fail', str(exc)))
        else:
            steps.append(Step(f'baseline:{component_id}-assets', 'ok',
                              'bound generated assets; no ambient workflow CLI installed or required'))

    return steps


def apply_project(project: Path, agent: str, home: Path, *, run: Runner = default_runner,
                  config: Mapping[str, Mapping[str, Any]] | None = None, windows: bool = os.name == 'nt') -> list[Step]:
    """Validate the whole pinned asset batch, then copy data without running upstream tools.

    Existing BMAD/Spec Kit directories remain untouched. Imported skill prose is
    not semantic approval and never grants tool, network or secret permissions.
    """
    from .baseline_assets import load, materialize, preflight_destination
    if agent not in AGENTS:
        return [Step('project:agent', 'fail', f'unknown agent {agent!r}; expected one of {", ".join(AGENTS)}')]
    config = config or components()
    prepared = []
    try:
        for component_id in ('superpowers', 'bmad', 'spec-kit'):
            spec = config[component_id]
            if _head(run, pinned_checkout(home) / component_id) != spec['pinned_commit']:
                raise ValueError('PINNED_COMMIT_MISMATCH:' + component_id)
            payload = load(component_id, agent, windows=windows)
            if spec.get('asset_inputs', {}).get('source_commit') != spec['pinned_commit']:
                raise ValueError('ASSET_SOURCE_BINDING_MISMATCH:' + component_id)
            preflight_destination(project, payload)
            prepared.append(payload)
    except (ValueError, KeyError, OSError) as exc:
        return [Step('project:preflight', 'fail', 'NEEDS_REVIEW:' + str(exc)[:200])]
    steps = []
    for payload in prepared:
        try:
            result = materialize(project, payload)
        except (ValueError, OSError) as exc:
            steps.append(Step('project:' + payload.component, 'fail', str(exc)[:200]))
            break
        detail = (f"{result['marker']} already present; left as it is; byte custody unqualified" if result['status'] == 'preserved'
                  else f"{result['added']} bound asset files added; semantic safety unqualified; no native execution")
        steps.append(Step('project:' + payload.component, 'ok', detail))
    return steps


@dataclass
class BaselineStatus:
    complete: bool
    missing: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {'complete': self.complete, 'missing': self.missing, 'details': self.details}


def inspect(home: Path, project: Path | None = None, agent: str | None = None, *,
            run: Runner = default_runner, which: Callable[[str], str | None] = shutil.which,
            environ: Mapping[str, str] | None = None) -> BaselineStatus:
    if (home/'workflow-current.json').exists():
        # Presence chooses a stricter current-source check. Its JSON never grants
        # source authority; official metadata and exact objects are rederived.
        from .current_workflows import inspect_current
        return inspect_current(home, project, agent)
    env = os.environ if environ is None else environ
    config = components()
    missing: list[str] = []
    details: dict[str, Any] = {}
    osv = Path(env.get('GETZILLA_OSV_DB') or home / 'osv')
    osv_ok = env.get('GETZILLA_OSV_ONLINE', '').strip() == '1' or any(osv.glob('*/all.zip'))
    opengrep_ok = any((home / 'bin' / name).is_file() for name in ('opengrep', 'opengrep.exe')) or bool(which('opengrep'))
    details['security'] = {'osv': osv_ok, 'opengrep': opengrep_ok}
    if not osv_ok:
        missing.append('SECURITY_BASELINE_MISSING:osv')
    if not opengrep_ok:
        missing.append('SECURITY_BASELINE_MISSING:opengrep')
    pinned = {}
    for component_id, component in sorted(config.items()):
        head = _head(run, pinned_checkout(home) / component_id) if (pinned_checkout(home) / component_id).is_dir() else None
        pinned[component_id] = {'expected': component['pinned_commit'], 'installed': head}
        if head != component['pinned_commit']:
            missing.append(f'WORKFLOW_BASELINE_MISSING:{component_id}')
    details['workflow'] = pinned
    if project is not None:
        skills = pinned_checkout(home) / 'superpowers' / 'skills'
        names = sorted(path.name for path in skills.iterdir() if path.is_dir()) if skills.is_dir() else []
        project_state = {
            'superpowers': bool(names) and all((project / SKILL_SOURCE / name / 'SKILL.md').is_file() for name in names),
            'bmad': (project / '_bmad').is_dir(),
            'spec-kit': (project / '.specify').is_dir(),
        }
        if agent in AGENT_SKILL_DIRS and names:
            project_state['agent_skills'] = all((project / AGENT_SKILL_DIRS[agent] / name / 'SKILL.md').is_file()
                                                for name in names)
        details['project'] = project_state
        missing.extend(f'PROJECT_BASELINE_MISSING:{name}' for name, ok in project_state.items() if not ok)
    return BaselineStatus(not missing, missing, details)


def detect_agent(project: Path, environ: Mapping[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    chosen = env.get('GETZILLA_AGENT', '').strip().lower()
    if chosen in AGENTS:
        return chosen
    for agent, marker in (('claude', '.claude'), ('codex', '.codex'), ('qwen', '.qwen'), ('gemini', '.gemini'),
                          ('grok', '.grok/agents')):
        if (project / marker).exists():
            return agent
    return 'qwen'
