"""General task scope/time admission. Local delegation is never merge authority.

The owner delegates actual normalized arguments through the existing exact grant
mechanism. The hook cannot originate consent or extend a deadline. Safe local
observation/bootstrap remains usable before task delegation. Unsupported opaque
transports are rejected by the mandatory hook before reaching this module.
"""

from datetime import datetime, timezone
import hashlib
import json
import math
import re
from pathlib import Path
import shlex

from .state import approvals_path, get_active_route, has_valid_approval, runtime_lock
from .util import load_json, dump_json

SCOPE = "task-execution"
ACTION = "task-tool-execute"
OBSERVATION_TOOLS = frozenset({"Read", "Glob", "Grep", "LS"})
OBSERVATION_COMMANDS = frozenset({"pwd", "ls", "cat", "rg", "nproc", "lscpu"})
GIT_OBSERVATIONS = frozenset({"status", "diff", "log", "show", "rev-parse"})
BOOTSTRAP_SCRIPTS = frozenset({"scripts/getzilla_status.py", "scripts/getzilla_doctor.py"})


def task_execution_resource(tool: str, inputs: dict) -> str:
    if not isinstance(tool, str) or not tool or not isinstance(inputs, dict):
        raise ValueError("invalid actual task tool arguments")
    encoded = json.dumps(inputs, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError("task tool arguments exceed bound")
    return f"tool:{tool}:sha256:" + hashlib.sha256(encoded).hexdigest()


def _inside(root, raw):
    if not isinstance(raw, str) or not raw or "$" in raw or "`" in raw:
        return False
    try:
        path = Path(raw)
        resolved = (path if path.is_absolute() else root / path).resolve()
        resolved.relative_to(root.resolve())
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def _safe_observation(root, tool, inputs):
    from ._policy_legacy import _extract_paths

    if tool in OBSERVATION_TOOLS:
        paths = _extract_paths(inputs)
        if tool == "Glob" and "pattern" in inputs:
            paths.append(inputs["pattern"])
        return all(_inside(root, path) for path in paths)
    if tool != "Bash":
        return False
    command = inputs.get("command")
    if not isinstance(command, str) or any(token in command for token in ("$", "`", "\n")):
        return False
    try:
        parser = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        parser.whitespace_split = True
        words = list(parser)
    except ValueError:
        return False
    if not words or any(any(char in word for char in ";&|<>") for word in words):
        return False
    if words[0] == "git":
        return (
            len(words) > 1
            and words[1] in GIT_OBSERVATIONS
            and not any(word.startswith(("--output", "--ext-diff", "--textconv", "--no-index")) for word in words[2:])
        )
    if words[0] in {"python3", "python", "py"}:
        return len(words) == 2 and words[1] in BOOTSTRAP_SCRIPTS
    if words[0] not in OBSERVATION_COMMANDS:
        return False
    if words[0] == "rg" and any(word == "--pre" or word.startswith("--pre=") for word in words[1:]):
        return False
    # Read operands stay inside the effective project. Existing policy still
    # blocks secrets before this observation exception can allow anything.
    return all(word.startswith("-") or _inside(root, word) for word in words[1:])


def _remaining(root, resource):
    if not has_valid_approval(root, SCOPE, action=ACTION, resource=resource):
        return None
    records = load_json(approvals_path(root), [])
    now = datetime.now(timezone.utc)
    remaining = []
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict) or record.get("scope") != SCOPE or resource not in record.get("resources", []):
            continue
        if record.get("source") not in {"explicit-user-consent", "standing-user-consent"}:
            continue
        if not isinstance(record.get("id"), str) or not re.fullmatch("[0-9a-f]{16}", record["id"]):
            continue
        used = record.get("consumed_resources", [])
        if not isinstance(used, list) or any(not isinstance(item, str) for item in used) or resource in used:
            continue
        try:
            created = datetime.fromisoformat(record["created_at"])
            expires = datetime.fromisoformat(record["expires_at"])
            if created.tzinfo is None or expires.tzinfo is None or not created <= now < expires:
                continue
            if not 0 < (expires - created).total_seconds() <= 86400:
                continue
            # has_valid_approval must validate this exact record, not another
            # stale record with the same resource but a longer deadline.
            from .state import _active_change_id, _repository_identity
            from .util import git_head, tree_fingerprint

            route = get_active_route(root) or {}
            if any(
                record.get(k) != v
                for k, v in {
                    "schema_version": 2,
                    "authorization": "delegated-local-grant",
                    "repository": _repository_identity(root),
                    "route_id": route.get("route_id"),
                    "change_id": _active_change_id(root),
                    "git_head": git_head(root),
                    "grant_binding_digest": tree_fingerprint(root),
                }.items()
            ) or ACTION not in record.get("actions", []):
                continue
            remaining.append(((expires - datetime.now(timezone.utc)).total_seconds(), record.get("id")))
        except (KeyError, TypeError, ValueError, RuntimeError):
            continue
    return max(remaining) if remaining else None


def _bounded_shell(inputs, remaining, raw_tool):
    timeout = inputs.get("timeout_ms", inputs.get("timeout"))
    if raw_tool == "Bash" and type(timeout) is int and 0 < timeout <= min(600000, math.floor(remaining * 1000)):
        return True
    command = inputs.get("command")
    if isinstance(command, str) and any(char in command for char in ("$", "`", "\n", ";", "&", "|")):
        return False
    try:
        words = shlex.split(command) if isinstance(command, str) else []
        if len(words) < 4 or words[:2] != ["/usr/bin/timeout", "--signal=KILL"]:
            return False
        seconds = float(words[2].removesuffix("s"))
        return math.isfinite(seconds) and 0 < seconds <= min(600, remaining)
    except (ValueError, TypeError):
        return False


def evaluate_task_execution(
    root: Path, tool: str, inputs: dict, *, raw_tool: str | None = None
) -> tuple[bool, str | None]:
    if _safe_observation(root, tool, inputs):
        return True, None
    route = get_active_route(root)
    if not isinstance(route, dict) or route.get("schema_version") != 1 or not route.get("route_id"):
        return False, "Task execution denied: mandatory task route missing or invalid."
    try:
        resource = task_execution_resource(tool, inputs)
        # Persist one-shot consumption before the host side effect. A lost
        # response cannot silently authorize a second write or grant renewal.
        with runtime_lock(root, "approvals"):
            admission = _remaining(root, resource)
            if admission is None or admission[0] <= 0:
                return (
                    False,
                    "Task execution denied: exact owner-delegated scope or time allowance missing, expired, consumed or stale.",
                )
            remaining, grant_id = admission
            if tool == "Bash" and not _bounded_shell(inputs, remaining, raw_tool):
                return False, "Task execution denied: actual shell timeout must fit the remaining owner time allowance."
            records = load_json(approvals_path(root), [])
            for record in records:
                if record.get("id") == grant_id:
                    record["consumed_resources"] = [*record.get("consumed_resources", []), resource]
                    dump_json(approvals_path(root), records)
                    return True, None
            return False, "Task execution denied: delegated scope changed during admission."
    except (ValueError, TypeError, RuntimeError, OSError):
        return False, "Task execution denied: scope/time authority invalid."
