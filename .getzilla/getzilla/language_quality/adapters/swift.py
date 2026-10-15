"""Pure plans and JSON diagnostics for SwiftLint and Nick Lockwood's SwiftFormat.

The shared executor supplies a pinned CLI in a read-only, network-free sandbox.
These adapters neither execute tools nor compile an Apple application.
"""
from __future__ import annotations

import json
from pathlib import PurePosixPath

from ..models import AdapterCapabilities, AdapterRequest, AdapterResult, Diagnostic, ToolOutput


def capabilities(tool_id: str, driver: str) -> AdapterCapabilities:
    """Both native CLIs accept an explicit list of Swift source files."""
    if tool_id not in ('swiftlint', 'swiftformat') or driver != 'cli':
        raise ValueError('unsupported Swift tool or driver')
    return AdapterCapabilities(incremental=True)


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value) and not any(ord(char) < 32 or ord(char) == 127 for char in value)


def _relative_path(value: object) -> str:
    if not _text(value) or '\\' in value:
        raise ValueError('invalid package-relative path')
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ('', '.', '..') for part in value.split('/')):
        raise ValueError('invalid package-relative path')
    return './' + value


def build_argv(request: AdapterRequest) -> tuple[str, ...]:
    """Return check-only argv. The core validates file existence and confinement."""
    capabilities(request.tool_id, request.driver)
    if (not isinstance(request.launcher, tuple) or not request.launcher
            or not all(_text(part) for part in request.launcher)
            or not isinstance(request.files, tuple)
            or request.task is not None or request.scope not in ('changed', 'full')):
        raise ValueError('invalid Swift adapter request')
    if request.scope == 'changed':
        if not request.files:
            raise ValueError('changed scope requires explicit Swift files')
        targets = tuple(_relative_path(path) for path in request.files)
        if any(not path.endswith('.swift') for path in request.files):
            raise ValueError('changed scope requires Swift source files')
    else:
        targets = ('.',)
    if request.tool_id == 'swiftlint':
        args = ('lint', '--strict', '--force-exclude', '--no-cache', '--reporter', 'json', '--quiet')
    else:
        args = ('--lint', '--cache', 'ignore', '--reporter', 'json', '--quiet')
    if request.config_path is not None:
        args += ('--config', _relative_path(request.config_path))
    return (*request.launcher, *args, *targets)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError('non-finite JSON value')


def _position(value: object, *, nullable: bool) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not int or value < (0 if nullable else 1):
        raise ValueError('invalid diagnostic position')
    return value or None


def _diagnostic(tool_id: str, item: object) -> Diagnostic:
    if not isinstance(item, dict):
        raise ValueError('invalid diagnostic')
    required = {'file', 'line', 'rule_id', 'reason'}
    if tool_id == 'swiftlint':
        required.update(('character', 'severity'))
    if not required.issubset(item) or not _text(item['rule_id']) or not _text(item['reason']):
        raise ValueError('invalid diagnostic fields')
    path = item['file']
    if path is not None and not _text(path):
        raise ValueError('invalid diagnostic path')
    line = _position(item['line'], nullable=tool_id == 'swiftlint')
    column = None
    severity = 'warning'
    if tool_id == 'swiftlint':
        if item['severity'] not in ('Error', 'Warning'):
            raise ValueError('invalid diagnostic severity')
        severity = item['severity'].lower()
        column = _position(item['character'], nullable=True)
    return Diagnostic(severity=severity, code=item['rule_id'], message=item['reason'],
                      path=path, line=line, column=column)


def normalize(request: AdapterRequest, output: ToolOutput) -> AdapterResult:
    """Never treat an exit code alone, malformed output or a crash as a clean run."""
    try:
        build_argv(request)
    except (TypeError, ValueError):
        return AdapterResult('ERROR', 'Invalid Swift adapter request')
    violation_exit = 2 if request.tool_id == 'swiftlint' else 1
    if type(output.returncode) is not int or output.returncode not in (0, violation_exit):
        return AdapterResult('ERROR', 'Swift tool failed to execute a lint check')
    if not isinstance(output.stdout, str) or len(output.stdout) > 1_048_576:
        return AdapterResult('ERROR', 'Swift JSON report is missing or exceeds the output bound')
    try:
        records = json.loads(output.stdout, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if not isinstance(records, list) or len(records) > 10_000:
            raise ValueError('invalid JSON report array')
        diagnostics = tuple(_diagnostic(request.tool_id, item) for item in records)
    except (TypeError, ValueError, RecursionError):
        return AdapterResult('ERROR', 'Swift tool returned an invalid JSON report')
    if diagnostics:
        return AdapterResult('FAIL', f'{request.tool_id} reported {len(diagnostics)} violation(s)', diagnostics)
    if output.returncode:
        return AdapterResult('ERROR', 'Swift tool reported a lint failure without diagnostics')
    return AdapterResult('PASS', f'{request.tool_id} reported no violations')
