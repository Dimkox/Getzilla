"""Versioned pure adapter contract for optional language quality gates."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ToolId = Literal["eslint", "detekt", "ktlint", "dart_analyzer", "dart_format", "swiftlint", "swiftformat"]
Driver = Literal["cli", "gradle", "dart", "flutter"]


@dataclass(frozen=True)
class AdapterCapabilities:
    incremental: bool
    full: bool = True


@dataclass(frozen=True)
class AdapterRequest:
    tool_id: ToolId
    driver: Driver
    launcher: tuple[str, ...]
    scope: Literal["changed", "full"]
    files: tuple[str, ...]
    config_path: str | None = None
    task: str | None = None


@dataclass(frozen=True)
class ToolOutput:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class Diagnostic:
    severity: Literal["error", "warning", "info"]
    code: str
    message: str
    path: str | None = None
    line: int | None = None
    column: int | None = None


@dataclass(frozen=True)
class AdapterResult:
    status: Literal["PASS", "FAIL", "ERROR"]
    summary: str
    diagnostics: tuple[Diagnostic, ...] = ()
