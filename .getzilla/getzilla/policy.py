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
    mcp_side_effect as _legacy_mcp_side_effect,
    _configured_patterns as _legacy_configured_patterns,
    _destructive_pattern as _legacy_destructive_pattern,
    _http_write_resource as _legacy_http_write_resource,
    evaluate_pre_tool as _legacy_evaluate_pre_tool,
    load_json as _legacy_load_json,
    production_action as _legacy_production_action,
    shell_secret_reference as _legacy_shell_secret_reference,
    _COMMAND_SCAN_BYTE_LIMIT as _LEGACY_COMMAND_LIMIT,
)
from .shell_targets import control_plane_shell_mutation, protected_ref_move, is_pip_install, PIP_INSTALL_HINT

WORKFLOW_DISPATCH_POLICY = 'workflow-dispatch is forbidden'
_UNSPECIFIED_CWD = object()


def _execution_directory(root: Path, value: object) -> Path | None:
    # Old direct callers use the repository root. Native callers always supply a value;
    # explicit None remains unknown and cannot silently become root-relative authority.
    if value is _UNSPECIFIED_CWD:
        return root
    return value if isinstance(value, Path) and value.is_absolute() else None


def _readings_differ(command: str) -> bool:
    """On Windows a backslash is a separator to cmd.exe/PowerShell and an escape to Git Bash."""
    return fsx.WINDOWS and '\\' in command


def sensitive_action(
    root: Path, event: dict[str, Any], *, execution_cwd: object = _UNSPECIFIED_CWD,
) -> str | None:
    tool = str(event.get('tool_name', ''))
    tool_input = event.get('tool_input') or {}
    lowered_tool = tool.lower()
    if tool in {'apply_patch', 'Edit', 'Write'} or any(
        word in lowered_tool for word in ('write_file', 'edit_file', 'delete_file')
    ):
        return 'protected-path-write'
    if _legacy_mcp_side_effect(tool, root):
        return 'external-write'
    if tool != 'Bash':
        return None
    command = str(tool_input.get('command', '')) if isinstance(tool_input, dict) else str(tool_input)
    if len(command) > _LEGACY_COMMAND_LIMIT:
        return 'oversize-command'
    directory = _execution_directory(root, execution_cwd)
    action = _bash_sensitive_action(root, command, execution_cwd=directory)
    if action is None and _readings_differ(command):
        # Git Bash's reading of backslashes is classified too (see evaluate_pre_tool).
        with _legacy.posix_reading():
            action = _bash_sensitive_action(root, command, execution_cwd=directory)
    return action


def _bash_sensitive_action(root: Path, command: str, *, execution_cwd: Path | None) -> str | None:
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
    if execution_cwd is None:
        control_plane = _legacy_configured_patterns(
            config if isinstance(config, dict) else {}, 'control_plane_paths', _LEGACY_CONTROL_PLANE,
        )
        targets, opaque = _shell_mutation(root, command, control_plane, execution_cwd=None)
        if targets or opaque:
            return 'unresolved-shell-directory'
    return None


def _shell_mutation(
    root: Path, command: str, control_plane: list[str], *, execution_cwd: Path | None,
) -> tuple[list[str], bool]:
    initial_base = '' if execution_cwd is None or execution_cwd == root else execution_cwd.as_posix()
    protected_targets, opaque = control_plane_shell_mutation(
        root, command, control_plane, initial_base=initial_base, initial_unknown=execution_cwd is None,
    )
    if fsx.WINDOWS and '\\' in command:
        # POSIX shlex drops unquoted backslashes, so `rm C:\repo\.grok\x` names no
        # target. Windows also accepts '/' as the separator: the union of both
        # readings is enforced, never the more permissive one.
        folded_targets, folded_opaque = control_plane_shell_mutation(
            root, command.replace('\\', '/'), control_plane,
            initial_base=initial_base, initial_unknown=execution_cwd is None,
        )
        protected_targets = list(dict.fromkeys([*protected_targets, *folded_targets]))
        opaque = opaque or folded_opaque
    return protected_targets, opaque


def evaluate_pre_tool(
    root: Path, event: dict[str, Any], *, execution_cwd: object = _UNSPECIFIED_CWD,
) -> tuple[bool, str | None]:
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
    if len(command) > _LEGACY_COMMAND_LIMIT:
        return False, f'Blocked a Bash command longer than {_LEGACY_COMMAND_LIMIT} characters before parsing it.'
    protected_targets, opaque = _shell_mutation(
        root, command, control_plane, execution_cwd=_execution_directory(root, execution_cwd),
    )
    if not _legacy.creates_hardlink(command):
        # A new hardlink in scratch would be a second name for its source inode (#102).
        protected_targets = [target for target in protected_targets if not _legacy.agent_scratch(root, target)]
    if protected_targets:
        targets = ', '.join(protected_targets)
        hint = f' {_legacy.SCRATCH_HINT}' if any(t.startswith('.getzilla/runtime/') for t in protected_targets) else ''
        return False, (
            f'Blocked control-plane shell mutation targeting {targets}; use a structured write '
            f'(Edit/Write/apply_patch) with an exact protected-path grant for each target.{hint}'
        )
    if opaque:
        # A Git command in a review copy can be pointed at the live tree by that copy's own config or
        # hooks, so it stays refused; the snapshot tool makes and removes copies instead (#183).
        hint = (' For a review copy, run `getzilla cleanup snapshot <commit>`, edit it with Edit/Write, and '
                'remove it with `getzilla cleanup snapshot --remove <path>`.') if _legacy.AGENT_SCRATCH in command else ''
        if is_pip_install(command):
            hint = PIP_INSTALL_HINT
        return False, (
            'Blocked opaque control-plane shell mutation; split the command or use Edit/Write/apply_patch '
            'so targets are explicit repository-relative paths. Do not create a protected-path grant until '
            'the exact targets are known.' + hint
        )
    moved = protected_ref_move(command)
    if moved:
        return False, (
            f'Blocked a local move, rename or delete of protected branch {moved}: diffs, reviews and '
            'verification compare against it. Work on your own branch; main changes only through a merged PR.'
        )

    # The legacy evaluator still owns destructive, production, external-write, route and MCP policy.
    # The structured target parser above supersedes only its old substring-based shell guard.
    verdict = _legacy_evaluate_pre_tool(root, event, _skip_substring_control_plane_guard=True)
    if verdict[0] and _readings_differ(command):
        # Claude Code runs Git Bash on Windows, where `cat .e\nv` reads .env: the union of
        # both readings is enforced, never the more permissive one.
        with _legacy.posix_reading():
            posix = _legacy_evaluate_pre_tool(root, event, _skip_substring_control_plane_guard=True)
        if not posix[0]:
            return posix
    return verdict


def __getattr__(name: str) -> Any:
    return getattr(_legacy, name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_legacy)))
