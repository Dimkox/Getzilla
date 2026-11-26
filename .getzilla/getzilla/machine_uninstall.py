"""Helpers that remove what the one-command installer wrote to a machine.

scripts/getzilla_self_uninstall.py builds its plan from these functions.
Each helper touches only Getzilla-owned bytes and refuses unsafe targets.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from . import agent_setup

PATH_MARKER = '# Getzilla: tools in ~/.getzilla/bin'
PROFILES = ('.bashrc', '.zshrc', '.bash_profile', '.profile')
AGENT_FILES = ('.qwen/settings.json', '.claude/settings.json', '.codex/config.toml')
ENV_NAMES = (agent_setup.KEY_ENV, agent_setup.CLAUDE_TOKEN_ENV, *agent_setup.AGENT_KEY_ENV.values(),
             'GETZILLA_OSV_DB')


def is_checkout(path: Path) -> bool:
    """True for a Getzilla source checkout, so a wrong --home cannot remove another folder."""
    return (path / 'scripts' / 'getzilla_cli.py').is_file() and (path / '.getzilla' / 'getzilla').is_dir()


def unsafe_target(path: Path, user_home: Path) -> bool:
    """True for the user home, a filesystem root or any parent of the user home."""
    resolved = path.resolve()
    home = user_home.resolve()
    return resolved == home or resolved == Path(resolved.anchor) or home.is_relative_to(resolved)


def dirty_files(checkout: Path) -> list[str]:
    """Tracked files with uncommitted changes; an unreadable Git state counts as clean."""
    if not (checkout / '.git').exists():
        return []
    try:
        result = subprocess.run(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'],
                                capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def strip_path_block(profile: Path, *, apply: bool) -> bool:
    """Remove the PATH_MARKER line and the PATH line after it. Return True if the profile has them."""
    if not profile.is_file():
        return False
    lines = profile.read_text(encoding='utf-8').splitlines(keepends=True)
    kept: list[str] = []
    after_marker = False
    for line in lines:
        if line.strip() == PATH_MARKER:
            after_marker = True
            if kept and not kept[-1].strip():
                kept.pop()  # the updater writes a blank line before the marker
            continue
        if after_marker and '.getzilla/bin' in line:
            after_marker = False
            continue
        after_marker = False
        kept.append(line)
    if kept == lines:
        return False
    if apply:
        agent_setup._write_private(profile, ''.join(kept))
    return True


def has_key_block(profile: Path) -> bool:
    return profile.is_file() and agent_setup.PROFILE_MARKER in profile.read_text(encoding='utf-8')


def owned_link(link: Path, checkout: Path) -> bool:
    """True only for the ~/.local/bin/getzilla link that points into this checkout."""
    return link.is_symlink() and Path(os.readlink(link)) == checkout / 'bin' / 'getzilla'


def inside(entry: str, roots: list[Path]) -> bool:
    """True when a PATH entry is one of the roots or below one of them (case-insensitive on Windows)."""
    text = os.path.normcase(os.path.normpath(os.path.expandvars(entry)))
    for root in roots:
        base = os.path.normcase(os.path.normpath(str(root)))
        if text == base or text.startswith(base.rstrip(os.sep) + os.sep):
            return True
    return False


def _make_writable(function, path, _info) -> None:
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    function(path)


def remove_tree(path: Path) -> None:
    """Remove a file, a link or a folder; read-only Git objects on Windows are made writable first."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path, onerror=_make_writable)


def windows_user_path() -> tuple[list[str], int]:
    """Entries and value type of the Windows user PATH (HKCU\\Environment)."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment') as key:
        try:
            value, kind = winreg.QueryValueEx(key, 'Path')
        except FileNotFoundError:
            return [], winreg.REG_EXPAND_SZ
    return [part for part in str(value).split(';') if part], kind


def set_windows_user_path(parts: list[str], kind: int) -> None:
    """Write the user PATH and tell running programs that the environment changed."""
    import ctypes
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, 'Path', 0, kind, ';'.join(parts))
    result = ctypes.c_ulong()
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, 'Environment', 0x0002, 5000, ctypes.byref(result))


def used_by_this_python(path: Path) -> bool:
    """Windows cannot remove the running interpreter or its folder; scripts/uninstall.ps1 does it later."""
    if os.name != 'nt':
        return False
    running = (sys.executable, getattr(sys, '_base_executable', ''), sys.prefix, sys.base_prefix)
    return any(item and Path(item).resolve().is_relative_to(path.resolve()) for item in running)
