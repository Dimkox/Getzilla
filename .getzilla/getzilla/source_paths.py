"""Portable path and filesystem alias rules for Zero-Git admission (path profile portable-v1).

A path is admitted only when it means the same single file on Linux, macOS and native Windows:
relative POSIX separators, NFC, no reserved Windows names or alias spellings, no case collision
with another admitted path. Nothing is renamed or normalised silently: a violation blocks.
"""
from __future__ import annotations

import os
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from . import fsx
from .source_models import FilesystemCapabilities, Finding

_RESERVED = re.compile(r'^(?:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]|CONIN\$|CONOUT\$)(?:\..*)?$', re.IGNORECASE)
_FORBIDDEN_CHARACTERS = set('<>:"|?*\\')
_MAX_COMPONENT = 255
_MAX_PATH = 4096


@dataclass(frozen=True)
class PathValidationResult:
    ok: bool
    blockers: tuple[Finding, ...]


def path_problem(path: str) -> str | None:
    """Reason code why `path` is not a portable-v1 relative path, or None when it is."""
    if not isinstance(path, str) or not path:
        return 'PATH_EMPTY'
    if '\x00' in path:
        return 'PATH_NUL'
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        return 'PATH_CONTROL_CHARACTER'
    if path.startswith('/') or re.match(r'^[A-Za-z]:', path):
        return 'PATH_ABSOLUTE'
    if len(path.encode('utf-8', 'surrogatepass')) > _MAX_PATH:
        return 'PATH_TOO_LONG'
    try:
        path.encode('utf-8')
    except UnicodeEncodeError:
        return 'PATH_NOT_UTF8'
    if unicodedata.normalize('NFC', path) != path:
        return 'PATH_NOT_NFC'
    for part in path.split('/'):
        if part in {'', '.', '..'}:
            return 'PATH_TRAVERSAL_OR_EMPTY_COMPONENT'
        if len(part.encode('utf-8')) > _MAX_COMPONENT:
            return 'PATH_COMPONENT_TOO_LONG'
        if _FORBIDDEN_CHARACTERS.intersection(part):
            return 'PATH_WINDOWS_FORBIDDEN_CHARACTER'
        if part.endswith(('.', ' ')):
            return 'PATH_WINDOWS_TRAILING_DOT_OR_SPACE'
        if _RESERVED.match(part):
            return 'PATH_WINDOWS_RESERVED_NAME'
    return None


def validate_paths(paths: Iterable[str]) -> PathValidationResult:
    """Every path portable, and no two paths collide under case folding (none is chosen)."""
    blockers: set[tuple[str, str]] = set()
    files: dict[str, list[str]] = {}
    directories: dict[str, set[str]] = {}
    users: dict[str, list[str]] = {}
    for path in paths:
        problem = path_problem(path)
        if problem:
            blockers.add((_redact_path(path), problem))
            continue
        files.setdefault(path.casefold(), []).append(path)
        parts = path.split('/')
        for depth in range(1, len(parts)):
            prefix = '/'.join(parts[:depth])
            directories.setdefault(prefix.casefold(), set()).add(prefix)
            users.setdefault(prefix.casefold(), []).append(path)
    for group in files.values():
        if len(group) > 1:
            blockers.update((path, 'PATH_CASE_COLLISION') for path in group)
    for key, spellings in directories.items():
        if len(spellings) > 1:  # "Src/a.py" and "src/b.py": two directories on Linux, one on Windows
            blockers.update((path, 'PATH_CASE_COLLISION') for path in users[key])
        if key in files:  # "a" as a file and "A/x" under a directory
            blockers.update((path, 'PATH_FILE_DIRECTORY_COLLISION') for path in files[key] + users[key])
    ordered = sorted(blockers)
    return PathValidationResult(not ordered, tuple(Finding(path=path, reason_code=code) for path, code in ordered))


def _redact_path(path: object) -> str:
    """A displayable form of a rejected path that cannot inject control sequences into reports."""
    text = path if isinstance(path, str) else repr(path)
    return text.encode('unicode_escape', 'backslashreplace').decode('ascii')[:512]


def probe_filesystem(root: Path) -> FilesystemCapabilities:
    """What this host can prove about the source filesystem, without writing to it."""
    notes: list[str] = []
    nofollow = bool(fsx.O_NOFOLLOW) or fsx.WINDOWS
    if fsx.WINDOWS:
        notes.append('Windows: links, junctions and reparse points are detected by lstat and refused')
    atomic = sys.platform.startswith('linux') or fsx.WINDOWS or sys.platform == 'darwin'
    if not atomic:
        notes.append('no atomic no-replace rename on this platform')
    try:
        info = os.lstat(root)
        hardlinks = hasattr(info, 'st_nlink')
    except OSError:
        hardlinks = False
    return FilesystemCapabilities(
        platform=sys.platform, nofollow_reads=nofollow, link_detection=True,
        hardlink_detection=hardlinks, atomic_no_replace_publish=atomic, notes=tuple(notes),
    )


def _real(path: Path) -> Path:
    """Resolve the existing part of `path` and re-append the rest (the target may not exist)."""
    path = Path(os.path.abspath(path))
    missing: list[str] = []
    probe = path
    while not probe.exists():
        missing.append(probe.name)
        if probe.parent == probe:
            break
        probe = probe.parent
    resolved = probe.resolve()
    for name in reversed(missing):
        resolved = resolved / name
    return resolved


def source_target_problem(source: Path, target: Path) -> str | None:
    """Source and target must be disjoint: not equal, not nested, not one object under two names."""
    real_source, real_target = _real(source), _real(target)
    key = (lambda value: os.path.normcase(str(value))) if fsx.WINDOWS or sys.platform == 'darwin' else str
    s, t = key(real_source), key(real_target)
    if s == t:
        return 'TARGET_IS_SOURCE'
    if t.startswith(s.rstrip(os.sep) + os.sep):
        return 'TARGET_INSIDE_SOURCE'
    if s.startswith(t.rstrip(os.sep) + os.sep):
        return 'SOURCE_INSIDE_TARGET'
    if real_target.exists():
        try:
            if os.path.samefile(real_source, real_target):
                return 'TARGET_ALIASES_SOURCE'
        except OSError:
            return 'TARGET_IDENTITY_UNKNOWN'
    return None
