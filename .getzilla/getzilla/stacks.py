"""Project stacks from the registry (`.getzilla/config/stacks.json`) and their verification.

Each stack the project contains is either checked or reported. A stack is checked by Getzilla's
built-in checks (``verified_by: builtin:<name>``) or by a runner registered in :data:`RUNNERS`.
Any other detected stack is ``STACK_NOT_VERIFIED:<id>``: in ``pr`` and ``release`` that refuses
verification when the change touches the stack's files, so an unchecked language is never a
silent pass. Only stacks the change touches are checked, so an unrelated toolchain is never
downloaded for a change that cannot affect it.
"""
from __future__ import annotations

import fnmatch
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from .stack_toolchains import Blocker, Toolchain, ensure_toolchain, resolve_version

REGISTRY = '.getzilla/config/stacks.json'
NOT_VERIFIED = 'STACK_NOT_VERIFIED'
UNTOUCHED_SUMMARY = 'no changed files of this stack'
# Dependency and build output, vendored trees and test fixtures say nothing about the project's stacks.
SKIP_DIRS = frozenset({'.git', 'node_modules', 'vendor', '.venv', 'venv', 'target', 'bin', 'obj', 'dist', 'build',
                       '__pycache__', 'fixtures', 'testdata'})
SKIP_PREFIXES = ('.getzilla/runtime/',)
MAX_WALK_FILES = 200000


@dataclass(frozen=True)
class Stack:
    id: str
    markers: tuple[str, ...]
    extensions: tuple[str, ...]
    verified_by: str | None = None
    osv_ecosystem: str | None = None
    toolchain: Mapping[str, Any] | None = None

    def is_marker(self, path: str) -> bool:
        name = PurePosixPath(path).name
        return any(fnmatch.fnmatchcase(name, marker) for marker in self.markers)

    def owns(self, path: str) -> bool:
        return self.is_marker(path) or PurePosixPath(path).suffix.lower() in self.extensions


@dataclass
class StackContext:
    """What a stack runner gets: the project, the change, and how to make checks and get tools."""
    root: Path
    mode: str
    stack: Stack
    files: list[str]
    make: Callable[..., Any]
    command: Callable[..., Any]
    ensure: Callable[[Stack, str], Toolchain | Blocker]
    notes: dict[str, Any] = field(default_factory=dict)

    def toolchain(self) -> Toolchain | Any:
        """The toolchain, or a failing check named ``toolchain:<stack>`` that says why there is none."""
        assert self.stack.toolchain is not None
        version, source = resolve_version(self.root, self.stack.toolchain)
        self.notes.update(toolchain_version=version, version_source=source)
        result = self.ensure(self.stack, version)
        if isinstance(result, Blocker):
            self.notes['toolchain_blocker'] = result.code
            return self.make(f'toolchain:{self.stack.id}', 'fail', result.code, details=[result.detail(f'stack:{self.stack.id}')])
        self.notes['toolchain_home'] = str(result.home)
        return result


Runner = Callable[[StackContext], list[Any]]
# Stack id -> runner. A registered runner turns a detected stack from "not verified" into checks.
RUNNERS: dict[str, Runner] = {}


def load_registry(root: Path | None = None) -> dict[str, Stack]:
    candidates = [root / REGISTRY] if root else []
    candidates.append(Path(__file__).resolve().parents[1] / 'config' / 'stacks.json')
    for path in candidates:
        if path.is_file():
            data = json.loads(path.read_text(encoding='utf-8'))
            return {
                stack_id: Stack(stack_id, tuple(item.get('markers', ())), tuple(ext.lower() for ext in item.get('extensions', ())),
                                item.get('verified_by'), item.get('osv_ecosystem'), item.get('toolchain'))
                for stack_id, item in data.get('stacks', {}).items()
            }
    return {}


def _skipped(path: str) -> bool:
    return path.startswith(SKIP_PREFIXES) or any(part in SKIP_DIRS for part in PurePosixPath(path).parts[:-1])


def tree_files(root: Path) -> list[str]:
    """Tracked and untracked, not ignored files; a plain walk outside git."""
    try:
        proc = subprocess.run(['git', 'ls-files', '-co', '--exclude-standard', '-z'], cwd=root,
                              capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        proc = None
    if proc is not None and proc.returncode == 0:
        return [path for path in proc.stdout.decode('utf-8', 'replace').split('\0') if path and not _skipped(path)]
    found: list[str] = []
    for directory, dirs, names in os.walk(root):
        base = Path(directory).relative_to(root)
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        found.extend((base / name).as_posix() for name in names)
        if len(found) > MAX_WALK_FILES:
            break
    return [path for path in found if not _skipped(path)]


def detect_stacks(root: Path, registry: Mapping[str, Stack] | None = None, files: list[str] | None = None) -> list[Stack]:
    registry = load_registry(root) if registry is None else registry
    files = tree_files(root) if files is None else files
    return [stack for stack in registry.values() if any(stack.is_marker(path) for path in files)]


def default_ensure(stack: Stack, version: str) -> Toolchain | Blocker:
    assert stack.toolchain is not None
    return ensure_toolchain(stack.id, stack.toolchain, version)


def stack_checks(root: Path, mode: str, changed: list[str], *, make: Callable[..., Any], command: Callable[..., Any],
                 registry: Mapping[str, Stack] | None = None, runners: Mapping[str, Runner] | None = None,
                 ensure: Callable[[Stack, str], Toolchain | Blocker] | None = None,
                 files: list[str] | None = None) -> tuple[list[Any], dict[str, Any]]:
    """Checks for every stack the change touches, plus an honest line for every other detected stack."""
    registry = load_registry(root) if registry is None else registry
    runners = RUNNERS if runners is None else runners
    ensure = ensure or default_ensure
    detected = detect_stacks(root, registry, files)
    metadata: dict[str, Any] = {'detected': [stack.id for stack in detected], 'checked': [], 'builtin': [],
                                'not_verified': [], 'untouched': [], 'details': {}}
    results: list[Any] = []
    for stack in detected:
        touched = [path for path in changed if stack.owns(path)]
        if stack.verified_by:
            metadata['builtin'].append(stack.id)
            continue
        if not touched:
            metadata['untouched'].append(stack.id)
            if stack.id not in runners:
                metadata['not_verified'].append(stack.id)
            results.append(make(f'stack:{stack.id}', 'skip', UNTOUCHED_SUMMARY, details=[{
                'severity': 'info', 'code': f'{NOT_VERIFIED}:{stack.id}' if stack.id not in runners else 'stack-untouched',
                'path': stack.id, 'message': f'{stack.id}: the change does not touch this stack; its checks did not run',
            }]))
            continue
        if stack.id not in runners:
            metadata['not_verified'].append(stack.id)
            refused = mode in {'pr', 'release'}
            results.append(make(f'stack:{stack.id}', 'fail' if refused else 'skip', f'{NOT_VERIFIED}:{stack.id}', details=[{
                'severity': 'error' if refused else 'warning', 'code': f'{NOT_VERIFIED}:{stack.id}', 'path': touched[0],
                'message': f'Getzilla has no checks for {stack.id} yet; {len(touched)} changed file(s) are not verified',
            }]))
            continue
        context = StackContext(root, mode, stack, touched, make, command, ensure)
        results.extend(runners[stack.id](context))
        metadata['checked'].append(stack.id)
        metadata['details'][stack.id] = context.notes
    return results, metadata
