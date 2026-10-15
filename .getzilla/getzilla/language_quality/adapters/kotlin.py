"""Pure plans for detekt 1.23.8 and the ktlint 1.7.1 JSON report contract.

The core supplies a pinned launcher and a sandbox whose cwd is the package.
This module never executes tools or creates reports. Gradle results stay ERROR
until a report artifact proves lint execution: ignoreFailures, NO-SOURCE and
SKIPPED can all yield exit code zero.
"""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from ..models import AdapterCapabilities, AdapterRequest, AdapterResult, Diagnostic, ToolOutput

_MAX_REPORT_CHARS = 2 * 1024 * 1024
_MAX_DIAGNOSTICS = 10_000
_TASK = re.compile(r":?[A-Za-z0-9_][A-Za-z0-9_.-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)*")
_TASK_NAMES = {"detekt": {"detekt", "detektMain", "detektTest"}, "ktlint": {"ktlintCheck"}}


def capabilities(tool_id: str, driver: str) -> AdapterCapabilities:
    if tool_id not in _TASK_NAMES or driver not in {"cli", "gradle"}:
        raise ValueError("unsupported Kotlin tool or driver")
    return AdapterCapabilities(incremental=tool_id == "ktlint" and driver == "cli")


def _path(value: str, *, kotlin_file: bool = False) -> str:
    if not isinstance(value, str) or not value or value.startswith(("/", "-", "!", "~")):
        raise ValueError("expected a package-relative path")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("control characters in path")
    if any(char in value for char in "\\:*?[]{}!,;") or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("ambiguous path or pattern is not supported")
    if kotlin_file and PurePosixPath(value).suffix not in {".kt", ".kts"}:
        raise ValueError("expected a Kotlin source file")
    return value


def _validate(request: AdapterRequest) -> None:
    capability = capabilities(request.tool_id, request.driver)
    if request.scope not in {"changed", "full"}:
        raise ValueError("unknown scope")
    if request.scope == "changed" and not capability.incremental:
        raise ValueError("this Kotlin driver requires a full package scope")
    launcher = request.launcher
    if not isinstance(launcher, tuple) or not launcher or any(
        not isinstance(part, str) or not part or any(ord(char) < 32 or ord(char) == 127 for char in part)
        for part in launcher
    ):
        raise ValueError("invalid pinned launcher")
    # A launcher is a binary or java -jar <pinned jar>, never extra tool options.
    java_jar = (
        len(launcher) == 3 and PurePosixPath(launcher[0]).name in {"java", "java.exe"}
        and launcher[1] == "-jar" and launcher[2].endswith(".jar")
    )
    if len(launcher) != 1 and not java_jar:
        raise ValueError("launcher contains unsupported tool arguments")
    if request.config_path is not None:
        _path(request.config_path)
    if request.driver == "gradle":
        if java_jar or PurePosixPath(launcher[0]).name.lower() in {"gradlew", "gradlew.bat", "gradlew.cmd"}:
            raise ValueError("use an installed Gradle binary, not the downloading wrapper")
        if request.config_path is not None:
            raise ValueError("Gradle configuration belongs to its pinned project task")
        task = request.task
        if not isinstance(task, str) or not _TASK.fullmatch(task) or task.split(":")[-1] not in _TASK_NAMES[request.tool_id]:
            raise ValueError("expected an exact supported Kotlin check task")
    elif request.task is not None:
        raise ValueError("a Gradle task cannot be used with the CLI driver")
    if request.scope == "changed":
        if not isinstance(request.files, tuple) or not request.files:
            raise ValueError("changed scope requires source files")
        for path in request.files:
            _path(path, kotlin_file=True)
        if len(set(request.files)) != len(request.files):
            raise ValueError("duplicate changed source path")


def build_argv(request: AdapterRequest) -> tuple[str, ...]:
    """Build check-only argv; the shared planner owns any scope fallback."""
    _validate(request)
    if request.driver == "gradle":
        return (*request.launcher, "--offline", "--no-daemon", "--console=plain",
                "--no-build-cache", "--rerun-tasks", "--no-parallel", "--max-workers=1", request.task)
    if request.tool_id == "detekt":
        args = (*request.launcher, "--input", ".", "--max-issues", "0")
        return (*args, "--config", request.config_path) if request.config_path is not None else args
    args = (*request.launcher, "--reporter=json", "--log-level=none", "--relative")
    if request.config_path is not None:
        args = (*args, f"--editorconfig={request.config_path}")
    # No patterns means the CLI's package-wide Kotlin scan. A literal dot is not
    # a recursive glob in ktlint, so do not pass the generic full-scope target.
    return (*args, "--", *request.files) if request.scope == "changed" else args


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> object:
    raise ValueError("non-finite JSON constant")


def _ktlint_diagnostics(request: AdapterRequest, report: str) -> tuple[Diagnostic, ...]:
    payload = json.loads(report, object_pairs_hook=_object, parse_constant=_constant)
    if not isinstance(payload, list):
        raise ValueError("ktlint JSON must contain an array")
    diagnostics: list[Diagnostic] = []
    seen: set[str] = set()
    for entry in payload:
        if not isinstance(entry, dict):
            raise ValueError("invalid ktlint file record")
        path = _path(entry.get("file"), kotlin_file=True)
        if path in seen or (request.scope == "changed" and path not in request.files):
            raise ValueError("duplicate or out-of-scope ktlint path")
        seen.add(path)
        errors = entry.get("errors")
        if not isinstance(errors, list) or not errors:
            raise ValueError("ktlint file record has no errors")
        for error in errors:
            if not isinstance(error, dict):
                raise ValueError("invalid ktlint diagnostic")
            line, column = error.get("line"), error.get("column")
            rule, message = error.get("rule"), error.get("message")
            if type(line) is not int or type(column) is not int or line < 1 or column < 1:
                raise ValueError("invalid ktlint location")
            # The CLI emits empty rule IDs for parse and rule-engine exceptions.
            # These mean incomplete analysis, not an ordinary lint violation.
            if not isinstance(rule, str) or not rule.strip() or not isinstance(message, str) or not message.strip():
                raise ValueError("missing rule or diagnostic text")
            diagnostics.append(Diagnostic("error", rule, message, path, line, column))
            if len(diagnostics) > _MAX_DIAGNOSTICS:
                raise ValueError("ktlint diagnostic limit exceeded")
    return tuple(diagnostics)


def normalize(request: AdapterRequest, output: ToolOutput) -> AdapterResult:
    """Normalize only bounded completed output, without choosing enforcement."""
    _validate(request)
    if type(output.returncode) is not int or not isinstance(output.stdout, str) or not isinstance(output.stderr, str):
        return AdapterResult("ERROR", "invalid Kotlin tool output")
    if len(output.stdout) + len(output.stderr) > _MAX_REPORT_CHARS:
        return AdapterResult("ERROR", "Kotlin tool output exceeded the adapter limit")
    if request.driver == "gradle":
        return AdapterResult("ERROR", f"Gradle exit {output.returncode}: a structured report artifact is required to prove lint execution")
    if request.tool_id == "detekt":
        status = {0: "PASS", 2: "FAIL"}.get(output.returncode, "ERROR")
        return AdapterResult(status, f"detekt exit {output.returncode}; exit-code evidence only, no structured findings")
    if output.returncode not in {0, 1}:
        return AdapterResult("ERROR", f"ktlint execution failed with exit {output.returncode}")
    streams = [stream.strip() for stream in (output.stdout, output.stderr) if stream.strip()]
    if len(streams) != 1:
        return AdapterResult("ERROR", "ktlint requires exactly one complete JSON report stream")
    try:
        diagnostics = _ktlint_diagnostics(request, streams[0])
    except (ValueError, TypeError, RecursionError):
        return AdapterResult("ERROR", "invalid or incomplete ktlint JSON report")
    if bool(diagnostics) != (output.returncode == 1):
        return AdapterResult("ERROR", "ktlint exit code and JSON report disagree")
    return AdapterResult("FAIL" if diagnostics else "PASS", f"ktlint reported {len(diagnostics)} violations", diagnostics)
