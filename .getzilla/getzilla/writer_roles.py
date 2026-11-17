"""Canonical writer-role configuration without the shell policy engine."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from .util import load_json

WRITE_ROLES = {
    'general_implementer', 'php_implementer', 'bitrix_implementer', 'frontend_implementer',
    'integration_implementer', 'data_implementer', 'ai_implementer',
}


def parse_write_roles(data: Any, *, defaults: set[str] | None = None) -> set[str]:
    """Return configured nonempty roles, or a fresh copy of the fallback set."""
    if isinstance(data, dict):
        roles = data.get('write_roles')
        if isinstance(roles, list):
            names = {str(item).strip() for item in roles if isinstance(item, str) and item.strip()}
            if names:
                return names
    return set(WRITE_ROLES if defaults is None else defaults)


def write_roles(root: Path, *, read_json: Callable[[Path, Any], Any] | None = None,
                defaults: set[str] | None = None) -> set[str]:
    """Read the existing routing configuration through its trusted JSON adapter."""
    reader = load_json if read_json is None else read_json
    return parse_write_roles(reader(root / '.getzilla/config/routing.json', None), defaults=defaults)
