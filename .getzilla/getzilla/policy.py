from __future__ import annotations

from pathlib import Path
from typing import Any

from . import _policy_legacy as _legacy
from . import fsx
from ._policy_legacy import *  # noqa: F401,F403
from ._policy_legacy import (
    DEFAULT_CONTROL_PLANE as _LEGACY_CONTROL_PLANE,
    DEFAULT_SECRET_READ as _LEGACY_SECRET_READ,
    DESTRUCTIVE_COMMANDS as _LEGACY_DESTRUCTIVE_COMMANDS,
    SIDE_EFFECT_TOOL as _LEGACY_SIDE_EFFECT_TOOL,
    _configured_patterns as _legacy_configured_patterns,
    _destructive_pattern as _legacy_destructive_pattern,
    _http_write_resource as _legacy_http_write_resource,
    evaluate_pre_tool as _legacy_evaluate_pre_tool,
    load_json as _legacy_load_json,
    production_action as _legacy_production_action,
    shell_secret_reference as _legacy_shell_secret_reference,
)
from .shell_targets import control_plane_shell_mutation

WORKFLOW_DISPATCH_POLICY = 'workflow-dispatch is forbidden'


def sensitive_action(root: Path, event: dict[str, Any]) -> str | None:
    tool = str(event.get('tool_name', ''))
    tool_input = event.get('tool_input') or {}
    lowered_tool = tool.lower()
    if tool in {'apply_patch', 'Edit', 'Write'} or any(
        word in lowered_tool for word in ('write_file', 'edit_file', 'delete_file')
    ):
        return 'protected-path-write'
    if tool.startswith('mcp__') and _LEGACY_SIDE_EFFECT_TOOL.search(tool):
        return 'external-write'
    if tool != 'Bash':
        return None
    command = str(tool_input.get('command', '')) if isinstance(tool_input, dict) else str(tool_input)
    action = _legacy_production_action(command)
    if action:
        return action
    if _legacy_http_write_resource(command):
        return 'external-write'
    config = _legacy_load_json(root / '.getzilla/config/policy.json', {}) or {}
    patterns = _legacy_configured_patterns(
        config if isinstance(config, dict) else {},
        'destructive_command_patterns',
        _LEGACY_DESTRUCTIVE_COMMANDS,
    )
    if _legacy_destructive_pattern(command, patterns) is not None:
        return 'destructive-command'
    secret_read = _legacy_configured_patterns(
        config if isinstance(config, dict) else {},
        'secret_read_paths',
        _LEGACY_SECRET_READ,
    )
    if _legacy_shell_secret_reference(root, command, secret_read) is not None:
        return 'secret-read'
    return None


def _shell_mutation(root: Path, command: str, control_plane: list[str]) -> tuple[list[str], bool]:
    protected_targets, opaque = control_plane_shell_mutation(root, command, control_plane)
    if fsx.WINDOWS and '\\' in command:
        # POSIX shlex drops unquoted backslashes, so `rm C:\repo\.grok\x` names no
        # target. Windows also accepts '/' as the separator: the union of both
        # readings is enforced, never the more permissive one.
        folded_targets, folded_opaque = control_plane_shell_mutation(
            root, command.replace('\\', '/'), control_plane,
        )
        protected_targets = list(dict.fromkeys([*protected_targets, *folded_targets]))
        opaque = opaque or folded_opaque
    return protected_targets, opaque


def evaluate_pre_tool(root: Path, event: dict[str, Any]) -> tuple[bool, str | None]:
    tool = str(event.get('tool_name', ''))
    tool_input = event.get('tool_input') or {}
    if tool != 'Bash':
        return _legacy_evaluate_pre_tool(root, event)

    config = _legacy_load_json(root / '.getzilla/config/policy.json', {}) or {}
    if not isinstance(config, dict):
        config = {}
    control_plane = _legacy_configured_patterns(
        config,
        'control_plane_paths',
        _LEGACY_CONTROL_PLANE,
    )
    command = str(tool_input.get('command', '')) if isinstance(tool_input, dict) else str(tool_input)
    protected_targets, opaque = _shell_mutation(root, command, control_plane)
    if protected_targets:
        targets = ', '.join(protected_targets)
        return False, (
            f'Blocked control-plane shell mutation targeting {targets}; use a structured write '
            '(Edit/Write/apply_patch) with an exact protected-path grant for each target.'
        )
    if opaque:
        return False, (
            'Blocked opaque control-plane shell mutation; split the command or use Edit/Write/apply_patch '
            'so targets are explicit repository-relative paths. Do not create a protected-path grant until '
            'the exact targets are known.'
        )

    # The legacy evaluator still owns destructive, production, external-write, route and MCP policy.
    # The structured target parser above supersedes only its old substring-based shell guard.
    return _legacy_evaluate_pre_tool(
        root,
        event,
        _skip_substring_control_plane_guard=True,
    )


def __getattr__(name: str) -> Any:
    return getattr(_legacy, name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_legacy)))
