"""Pure CLI adapter for ESLint 9/10 built-in JSON reports.

The core supplies a pinned launcher, package cwd and isolated execution. This
module never searches for tools, runs config code, installs packages or fixes
source. CLI and JSON contracts: https://eslint.org/docs/v9.x/use/command-line-interface
and https://eslint.org/docs/latest/integrate/nodejs-api#-lintresult-type.
"""
from __future__ import annotations

import json
from pathlib import PurePosixPath

from ..models import (
    AdapterCapabilities,
    AdapterRequest,
    AdapterResult,
    Diagnostic,
    ToolOutput,
)

_PACKAGE_MANAGERS = frozenset({"npm", "npx", "yarn", "pnpm", "bun", "bunx", "corepack"})


def capabilities(tool_id: str, driver: str) -> AdapterCapabilities:
    if tool_id != "eslint" or driver != "cli":
        raise ValueError("ESLint requires tool_id=eslint and driver=cli")
    return AdapterCapabilities(incremental=True)


def _safe_text(value: object) -> bool:
    return isinstance(value, str) and bool(value) and not any(ord(char) < 32 or ord(char) == 127 for char in value)


def _relative_file(value: object) -> str:
    if not _safe_text(value) or "\\" in value or value.startswith("/"):
        raise ValueError("ESLint input paths must be normalized relative paths")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts) or ":" in parts[0]:
        raise ValueError("ESLint input paths must stay within the package")
    return f"./{value}"


def build_argv(request: AdapterRequest) -> tuple[str, ...]:
    """Plan a read-only command; files/config are relative to the package cwd."""
    capabilities(request.tool_id, request.driver)
    if request.scope not in ("changed", "full") or request.task is not None:
        raise ValueError("ESLint requires a changed/full scope and no task")
    if not isinstance(request.launcher, tuple) or not request.launcher:
        raise ValueError("ESLint requires a verified launcher tuple")
    for part in request.launcher:
        if not _safe_text(part) or part.startswith("-"):
            raise ValueError("ESLint launcher cannot contain options or control characters")
        name = PurePosixPath(part.replace("\\", "/")).name.lower()
        if name.removesuffix(".exe").removesuffix(".cmd") in _PACKAGE_MANAGERS:
            raise ValueError("ESLint must not run through a package manager")
    if not isinstance(request.files, tuple):
        raise ValueError("ESLint files must be a tuple")
    files = tuple(_relative_file(path) for path in request.files)
    if len(set(files)) != len(files):
        raise ValueError("ESLint files must be unique")
    if request.scope == "changed" and not files:
        raise ValueError("ESLint changed scope requires explicit files")
    argv = [*request.launcher, "--format", "json", "--no-color", "--exit-on-fatal-error"]
    # Even without --cache, ESLint removes the cache at cache-location. Keep
    # that operation outside the read-only workspace, in the core's private tmpfs.
    argv.extend(("--cache-location", "/tmp/getzilla-eslint-cache"))
    if request.config_path is not None:
        argv.extend(("--config", _relative_file(request.config_path)))
    argv.append("--")
    argv.extend(files if request.scope == "changed" else (".",))
    return tuple(argv)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("invalid diagnostic count")
    return value


def _position(message: dict, field: str) -> int | None:
    value = message.get(field)
    if value is not None and (type(value) is not int or value < 1):
        raise ValueError("invalid diagnostic position")
    return value


def _diagnostic(message: object, path: str) -> tuple[Diagnostic, bool]:
    if not isinstance(message, dict):
        raise ValueError("invalid message object")
    severity = message.get("severity")
    if type(severity) is not int or severity not in {1, 2}:
        raise ValueError("invalid message severity")
    text = message.get("message")
    rule = message.get("ruleId")
    fatal = message.get("fatal", False)
    if not isinstance(text, str) or not text or "ruleId" not in message:
        raise ValueError("missing diagnostic text or rule")
    if rule is not None and (not isinstance(rule, str) or not rule):
        raise ValueError("invalid diagnostic rule")
    if type(fatal) is not bool or (fatal and severity != 2):
        raise ValueError("invalid fatal diagnostic")
    return Diagnostic(
        severity="error" if severity == 2 else "warning",
        code=rule or ("eslint/fatal" if fatal else "eslint/core"),
        message=text, path=path,
        line=_position(message, "line"), column=_position(message, "column"),
    ), fatal


def _read_reports(stdout: str) -> tuple[tuple[Diagnostic, ...], int, int, int, int]:
    reports = json.loads(stdout, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    if not isinstance(reports, list) or not reports:
        raise ValueError("missing file results")
    diagnostics: list[Diagnostic] = []
    paths: set[str] = set()
    total_errors = total_warnings = total_fatal = 0
    for report in reports:
        if not isinstance(report, dict):
            raise ValueError("invalid file result")
        path = report.get("filePath")
        if not _safe_text(path) or "\\" in path or ".." in path.split("/"):
            raise ValueError("invalid report path")
        if path in paths:
            raise ValueError("duplicate file result")
        paths.add(path)
        messages = report.get("messages")
        if not isinstance(messages, list):
            raise ValueError("missing message list")
        errors = _count(report.get("errorCount"))
        warnings = _count(report.get("warningCount"))
        fatal_errors = _count(report.get("fatalErrorCount"))
        for field, maximum in (("fixableErrorCount", errors), ("fixableWarningCount", warnings)):
            if field in report and _count(report[field]) > maximum:
                raise ValueError("inconsistent fixable count")
        file_errors = file_warnings = file_fatal = 0
        for message in messages:
            diagnostic, fatal = _diagnostic(message, path)
            diagnostics.append(diagnostic)
            file_errors += diagnostic.severity == "error"
            file_warnings += diagnostic.severity == "warning"
            file_fatal += fatal
        if (errors, warnings, fatal_errors) != (file_errors, file_warnings, file_fatal):
            raise ValueError("diagnostic counts disagree with messages")
        total_errors += errors
        total_warnings += warnings
        total_fatal += fatal_errors
    return tuple(diagnostics), total_errors, total_warnings, total_fatal, len(reports)


def normalize(request: AdapterRequest, output: ToolOutput) -> AdapterResult:
    """Keep operational failures separate from valid lint violations."""
    build_argv(request)
    if type(output.returncode) is not int or output.returncode not in {0, 1, 2}:
        return AdapterResult("ERROR", "ESLint did not complete with a documented exit code")
    if not isinstance(output.stdout, str) or not isinstance(output.stderr, str):
        return AdapterResult("ERROR", "ESLint returned invalid output streams")
    try:
        diagnostics, errors, warnings, fatal, files = _read_reports(output.stdout)
    except (ValueError, TypeError, RecursionError):
        return AdapterResult("ERROR", "ESLint returned no complete valid JSON file report")
    if fatal:
        return AdapterResult("ERROR", "ESLint reported a fatal parsing error", diagnostics)
    if output.returncode == 2:
        return AdapterResult("ERROR", "ESLint reported a configuration or internal error", diagnostics)
    if output.returncode == 0 and errors:
        return AdapterResult("ERROR", "ESLint exit code disagrees with reported errors", diagnostics)
    if output.returncode == 1 and not (errors or warnings):
        return AdapterResult("ERROR", "ESLint failed without any reported violation", diagnostics)
    summary = f"ESLint reported {errors} errors and {warnings} warnings in {files} files"
    return AdapterResult("FAIL" if output.returncode == 1 else "PASS", summary, diagnostics)
