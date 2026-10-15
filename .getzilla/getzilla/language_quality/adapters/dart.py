"""Pure command planning and output parsing for Dart and Flutter checks.

CLI contracts: dart.dev/tools/dart-analyze and dart.dev/tools/dart-format.
Machine escaping and exit codes follow dart-lang/sdk's analyze.dart.
Flutter's ordinary analyze output follows flutter_tools/commands/analyze_once.dart
and dart/analysis.dart. Its --machine flag does not select a machine diagnostic
format for this operation. Unknown output remains ERROR, including SDK drift.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from ..models import AdapterCapabilities, AdapterRequest, AdapterResult, Diagnostic, ToolOutput

_SEVERITY_EXIT = {'INFO': 1, 'WARNING': 2, 'ERROR': 3}
_FLUTTER_DIAGNOSTIC = re.compile(
    r'\s*(error|warning|info) (•|-) (.+) \2 (.+):([1-9][0-9]*):([1-9][0-9]*) '
    r'\2 ([a-z_][a-z0-9_]*)'
)
_FLUTTER_SUMMARY = re.compile(r'([1-9][0-9]*) issues? found\. \(ran in [0-9]+\.[0-9]+s\)')
_FLUTTER_CLEAN = re.compile(r'No issues found! \(ran in [0-9]+\.[0-9]+s\)')
_FORMAT_SUMMARY = re.compile(
    r'Formatted ([1-9][0-9]*) files? \(([0-9]+) changed\) in [0-9]+\.[0-9]+ seconds\.'
)


def capabilities(tool_id: str, driver: str) -> AdapterCapabilities:
    if tool_id == 'dart_analyzer' and driver in ('dart', 'flutter'):
        # Cross-file references and analyzer plugins require the whole package.
        return AdapterCapabilities(incremental=False)
    if tool_id == 'dart_format' and driver == 'dart':
        # Flutter projects use their pinned bundled Dart executable for format.
        return AdapterCapabilities(incremental=True)
    raise ValueError('unsupported Dart tool or driver')


def _plain(value: object) -> bool:
    return isinstance(value, str) and bool(value) and all(
        ord(character) >= 32 and ord(character) != 127 for character in value
    )


def _source_path(value: object) -> bool:
    if not _plain(value) or '\\' in value or ':' in value:
        return False
    path = PurePosixPath(value)
    return (not path.is_absolute() and path.as_posix() == value
            and all(part not in ('.', '..') for part in path.parts)
            and value.endswith('.dart'))


def _validate(request: AdapterRequest) -> None:
    if not isinstance(request, AdapterRequest):
        raise ValueError('invalid adapter request')
    capability = capabilities(request.tool_id, request.driver)
    if (not isinstance(request.launcher, tuple) or not request.launcher
            or not all(_plain(part) for part in request.launcher)):
        raise ValueError('invalid verified launcher')
    if request.scope not in ('changed', 'full') or request.task is not None:
        raise ValueError('unsupported scope or task')
    if request.config_path not in (None, 'analysis_options.yaml'):
        raise ValueError('Dart uses the package analysis_options.yaml')
    if (not isinstance(request.files, tuple)
            or not all(_source_path(path) for path in request.files)
            or len(set(request.files)) != len(request.files)):
        raise ValueError('invalid package-relative Dart source paths')
    if request.scope == 'changed' and (not capability.incremental or not request.files):
        raise ValueError('full package scope required')


def build_argv(request: AdapterRequest) -> tuple[str, ...]:
    """Build one check; launcher trust and sandbox execution belong to the core."""
    _validate(request)
    prefix = (*request.launcher, '--suppress-analytics')
    if request.tool_id == 'dart_format':
        targets = tuple('./' + path for path in request.files) if request.scope == 'changed' else ('.',)
        return (*prefix, 'format', '--output=none', '--set-exit-if-changed',
                '--show=changed', '--summary=line', *targets)
    if request.driver == 'flutter':
        return (*prefix, '--no-color', '--no-wrap', '--no-version-check',
                'analyze', '--no-pub', '--no-preamble', '--fatal-infos', '--fatal-warnings', '.')
    return (*prefix, 'analyze', '--format=machine', '--fatal-infos', '--fatal-warnings', '.')


def _lines(text: str) -> list[str]:
    lines = [line.rstrip('\r') for line in text.split('\n') if line.strip()]
    if any(len(line) > 65536 or any(ord(c) < 32 and c != '\t' or ord(c) == 127
                                  for c in line) for line in lines):
        raise ValueError('unsupported diagnostic characters or size')
    return lines


def _machine_fields(line: str) -> list[str]:
    fields, current = [], []
    escaped = False
    escapes = {'n': '\n', 'r': '\r', '\\': '\\', '|': '|'}
    for character in line:
        if escaped:
            if character not in escapes:
                raise ValueError('unknown machine escape')
            current.append(escapes[character])
            escaped = False
        elif character == '\\':
            escaped = True
        elif character == '|':
            fields.append(''.join(current))
            current = []
        else:
            current.append(character)
    fields.append(''.join(current))
    if escaped or len(fields) != 8:
        raise ValueError('invalid machine record')
    return fields


def _dart_analyzer(output: ToolOutput) -> AdapterResult:
    if output.stderr.strip() or output.returncode not in (0, 1, 2, 3):
        raise ValueError('Dart analyzer execution error')
    diagnostics = []
    expected_exit = 0
    for text in _lines(output.stdout):
        severity, kind, code, path, line, column, length, message = _machine_fields(text)
        if (severity not in _SEVERITY_EXIT or not re.fullmatch(r'[A-Z_]*', kind)
                or not re.fullmatch(r'[A-Z][A-Z0-9_]*', code) or not _plain(path)
                or not re.fullmatch(r'[1-9][0-9]*', line)
                or not re.fullmatch(r'[1-9][0-9]*', column)
                or not re.fullmatch(r'[0-9]+', length) or not message):
            raise ValueError('invalid machine diagnostic')
        diagnostics.append(Diagnostic(severity=severity.lower(), code=code, message=message,
                                      path=path, line=int(line), column=int(column)))
        expected_exit = max(expected_exit, _SEVERITY_EXIT[severity])
    if output.returncode != expected_exit:
        raise ValueError('Dart analyzer exit code contradicts diagnostics')
    return _result(diagnostics, 'Dart analysis')


def _flutter_analyzer(output: ToolOutput) -> AdapterResult:
    if output.returncode not in (0, 1):
        raise ValueError('Flutter analyzer execution error')
    diagnostics = []
    summary_count = None
    for stream, text in (('stdout', output.stdout), ('stderr', output.stderr)):
        for line in _lines(text):
            line = line.strip()
            if summary_count is not None:
                raise ValueError('unexpected output after Flutter summary')
            summary = _FLUTTER_SUMMARY.fullmatch(line)
            if summary or _FLUTTER_CLEAN.fullmatch(line):
                summary_count = int(summary[1]) if summary else 0
                continue
            match = _FLUTTER_DIAGNOSTIC.fullmatch(line)
            if stream != 'stdout' or not match or not _plain(match[4]):
                raise ValueError('unknown Flutter analyzer output')
            severity, _, message, path, row, column, code = match.groups()
            diagnostics.append(Diagnostic(severity=severity, code=code, message=message,
                                          path=path, line=int(row), column=int(column)))
    if summary_count != len(diagnostics) or output.returncode != int(bool(diagnostics)):
        raise ValueError('Flutter analyzer summary or exit code is incomplete')
    return _result(diagnostics, 'Flutter analysis')


def _formatter(output: ToolOutput) -> AdapterResult:
    if output.stderr.strip() or output.returncode not in (0, 1):
        raise ValueError('Dart formatter execution error')
    lines = _lines(output.stdout)
    summary = _FORMAT_SUMMARY.fullmatch(lines[-1]) if lines else None
    if summary is None:
        raise ValueError('Dart formatter did not report processed files')
    processed, changed = int(summary[1]), int(summary[2])
    paths = []
    for line in lines[:-1]:
        if not line.startswith('Changed ') or not _plain(line[8:]):
            raise ValueError('unknown Dart formatter output')
        paths.append(line[8:])
    if (changed != len(paths) or len(set(paths)) != len(paths) or changed > processed
            or output.returncode != int(bool(changed))):
        raise ValueError('Dart formatter summary or exit code contradicts diagnostics')
    return _result([Diagnostic(severity='warning', code='dart_format',
                               message='File requires formatting.', path=path) for path in paths],
                   'Dart formatting')


def _result(diagnostics: list[Diagnostic], label: str) -> AdapterResult:
    for diagnostic in diagnostics:
        name = PurePosixPath((diagnostic.path or '').replace('\\', '/')).name
        if diagnostic.severity == 'error' and name in (
                'analysis_options.yaml', 'pubspec.yaml', 'package_config.json'):
            return AdapterResult(status='ERROR', summary=f'{label}: invalid package configuration.',
                                 diagnostics=tuple(diagnostics))
    return AdapterResult(status='FAIL' if diagnostics else 'PASS',
                         summary=f'{label}: {len(diagnostics)} issue(s).',
                         diagnostics=tuple(diagnostics))


def normalize(request: AdapterRequest, output: ToolOutput) -> AdapterResult:
    """Accept only complete supported output; never turn process errors into PASS."""
    try:
        _validate(request)
        if (not isinstance(output, ToolOutput) or type(output.returncode) is not int
                or not isinstance(output.stdout, str) or not isinstance(output.stderr, str)
                or len(output.stdout) + len(output.stderr) > 1048576):
            raise ValueError('invalid or oversized tool output')
        if request.tool_id == 'dart_format':
            return _formatter(output)
        if request.driver == 'flutter':
            return _flutter_analyzer(output)
        return _dart_analyzer(output)
    except (ValueError, TypeError):
        return AdapterResult(status='ERROR', summary='Invalid request or unsupported Dart/Flutter output.')
