"""Prospective workflow storage; tracked packages remain readable history."""
from __future__ import annotations
import re
import shutil
from pathlib import Path

RUNTIME_CHANGES = '.getzilla/runtime/changes'
LEGACY_CHANGES = 'engineering/changes'
CHANGE_ID = re.compile(r'[A-Za-zА-Яа-яЁё0-9][A-Za-zА-Яа-яЁё0-9_-]{0,127}')


def valid_package_path(relative: object, change_id: object) -> bool:
    return (isinstance(change_id, str) and bool(CHANGE_ID.fullmatch(change_id))
            and relative in {f'{RUNTIME_CHANGES}/{change_id}', f'{LEGACY_CHANGES}/{change_id}'})


def change_directory(root: Path, change_id: str, *, writable: bool = False) -> Path:
    if not valid_package_path(f'{RUNTIME_CHANGES}/{change_id}', change_id):
        raise ValueError('invalid change identity')
    runtime = root / RUNTIME_CHANGES / change_id
    legacy = root / LEGACY_CHANGES / change_id
    selected = runtime if runtime.exists() or writable or not legacy.exists() else legacy
    current = root
    for part in selected.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise ValueError('workflow package path must not contain symlinks')
    if writable and not runtime.exists() and legacy.exists():
        current = root
        for part in legacy.relative_to(root).parts:
            current /= part
            if current.is_symlink():
                raise ValueError('legacy workflow package path contains symlinks')
        if any(item.is_symlink() for item in legacy.rglob('*')):
            raise ValueError('legacy workflow package contains symlinks')
        shutil.copytree(legacy, runtime)
    return selected
