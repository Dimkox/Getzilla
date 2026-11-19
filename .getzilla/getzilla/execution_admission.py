"""General task scope/time admission. Local delegation is never merge authority.

The canonical execution registry owns exact source/session/task bindings,
immutable arguments, deadlines and one-use claims. Historical per-tool grant
records are not a second execution ledger. Safe observations remain available;
effects require an explicit qualified backend through execution.submit.
"""

import hashlib
import json
import re
from pathlib import Path
import shlex


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


def evaluate_task_execution(
    root: Path, tool: str, inputs: dict, *, raw_tool: str | None = None
) -> tuple[bool, str | None]:
    """Compatibility observation API; it never issues a second dispatch claim.

    Managed effects use execution.submit with a trusted caller and an explicitly
    qualified cooperative backend. A boolean hook verdict cannot carry that
    backend's source/session/deadline and single-use dispatch capability.
    """
    if not isinstance(tool, str) or not isinstance(inputs, dict):
        return False, "Legacy execution arguments are invalid."
    from ._policy_legacy import evaluate_pre_tool
    allowed, reason = evaluate_pre_tool(root, {'tool_name': tool, 'tool_input': inputs}, execution_cwd=root)
    if not allowed:
        return allowed, reason
    if _safe_observation(root, tool, inputs):
        return True, None
    return False, ("Legacy task execution verdict is unsupported for effects; use the canonical "
                   "execution.submit registry with a trusted caller and a qualified cooperative backend.")
