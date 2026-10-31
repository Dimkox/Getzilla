"""Opt-in execution of project-authored verification and mutation checks."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

from .interpreter import venv_python
from .python_test_runner import RunCancelled, execute
from .util import git_head, resolve_command, tool_search_path
from .verification_tool_reports import evaluate_criteria, parse_report
from .verification_tool_workspace import (
    WorkspaceError, checked_path, copy_source, fingerprint, linked, read_report, runtime_parent,
)


CONFIG = '.getzilla-verification.json'
CATALOG = {
    'playwright': {'license': 'Apache-2.0', 'format': 'playwright-json', 'kind': 'tests'},
    'schemathesis': {'license': 'MIT', 'format': 'schemathesis-json', 'kind': 'api'},
    'hypothesis': {'license': 'MPL-2.0', 'format': 'junit', 'kind': 'tests'},
    'fast-check': {'license': 'MIT', 'format': 'junit', 'kind': 'tests'},
    'mutmut': {'license': 'BSD-3-Clause', 'format': 'mutmut-json', 'kind': 'mutations'},
    'strykerjs': {'license': 'Apache-2.0', 'format': 'stryker-json', 'kind': 'mutations'},
    'testcontainers-python': {'license': 'Apache-2.0', 'format': 'junit', 'kind': 'tests'},
}


class ConfigurationError(ValueError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError(f'duplicate configuration key: {key}')
        result[key] = value
    return result


def _require(condition, message):
    if not condition:
        raise ConfigurationError(message)


def _check(root: Path, value: object) -> dict:
    _require(isinstance(value, dict), 'each check must be an object')
    allowed = {'id', 'tool', 'commands', 'cwd', 'timeout_seconds', 'enabled', 'modes', 'criteria'}
    _require(set(value) <= allowed and {'id', 'tool', 'commands'} <= set(value), 'unknown or missing check fields')
    result = {'cwd': '.', 'timeout_seconds': 300, 'enabled': True, 'modes': ['pr', 'release'], 'criteria': {}, **value}
    _require(isinstance(result['id'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', result['id']), 'invalid check id')
    _require(isinstance(result['tool'], str) and result['tool'] in CATALOG, 'unknown verification tool')
    _require(type(result['enabled']) is bool, 'enabled must be boolean')
    _require(type(result['timeout_seconds']) is int and 1 <= result['timeout_seconds'] <= 3600, 'timeout_seconds must be 1..3600')
    modes = result['modes']
    _require(isinstance(modes, list) and modes and all(isinstance(m, str) and m in {'fast', 'pr', 'release'} for m in modes)
             and len(modes) == len(set(modes)), 'invalid or duplicate modes')
    commands = result['commands']
    _require(isinstance(commands, list) and 1 <= len(commands) <= 4, 'commands must contain 1..4 argv arrays')
    for argv in commands:
        _require(isinstance(argv, list) and 1 <= len(argv) <= 128 and all(
            isinstance(arg, str) and arg and len(arg) <= 8192 and '\0' not in arg for arg in argv), 'invalid command argv')
    if result['tool'] == 'strykerjs':
        _require(len(commands) == 1 and '--' not in commands[0],
                 'Stryker needs one command accepting managed --force and --incrementalFile options')
    _require(isinstance(result['cwd'], str), 'cwd must be a relative directory')
    try:
        _require(checked_path(root, result['cwd']).is_dir(), 'cwd does not exist')
    except (OSError, WorkspaceError) as exc:
        raise ConfigurationError(str(exc)) from exc
    criteria = result['criteria']
    _require(isinstance(criteria, dict) and len(criteria) <= 1000, 'criteria must be a mapping')
    for key, tests in criteria.items():
        _require(isinstance(key, str) and 0 < len(key) <= 128 and isinstance(tests, list) and 1 <= len(tests) <= 1000
                 and all(isinstance(test, str) and 0 < len(test) <= 2048 for test in tests), 'invalid criterion test IDs')
        _require(len(tests) == len(set(tests)), 'duplicate criterion test ID')
    _require(not criteria or CATALOG[result['tool']]['kind'] == 'tests', 'aggregate API/mutation reports cannot bind individual criteria')
    return result


def load_checks(root: Path, mode: str) -> list[dict]:
    path = root / CONFIG
    if not path.exists() and not linked(path):
        return []
    try:
        _require(not linked(path) and path.is_file(), 'configuration must be a regular non-linked file')
        with path.open('rb') as handle:
            raw = handle.read(128 * 1024 + 1)
        _require(len(raw) <= 128 * 1024, 'configuration exceeds 128 KiB')
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
        _require(isinstance(data, dict) and set(data) == {'schema_version', 'checks'}, 'invalid configuration fields')
        _require(type(data['schema_version']) is int and data['schema_version'] == 1, 'unsupported schema_version')
        _require(isinstance(data['checks'], list) and len(data['checks']) <= 64, 'checks must be a list of at most 64 entries')
        checks = [_check(root, value) for value in data['checks']]
        _require(len({value['id'] for value in checks}) == len(checks), 'duplicate check id')
        return [value for value in checks if value['enabled'] and mode in value['modes']]
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ConfigurationError(str(exc)) from exc


def _execution(proc) -> dict:
    return {key: getattr(proc, key) for key in ('command', 'returncode', 'terminal_state', 'seconds', 'cleanup_error')}


def _run(root: Path, check: dict, result: dict, detail: dict, directory: Path) -> None:
    tool = check['tool']
    isolated = CATALOG[tool]['kind'] == 'mutations' or tool == 'schemathesis'
    project = root
    if isolated:
        project = directory / 'source'
        copy_source(root, project, link_node_modules=tool == 'strykerjs')
    cwd = checked_path(project, check['cwd'])
    report = (cwd / 'mutants/mutmut-cicd-stats.json' if tool == 'mutmut' else
              cwd / 'reports/mutation/mutation.json' if tool == 'strykerjs' else
              directory / ('report.xml' if CATALOG[tool]['format'] == 'junit' else 'report.json'))
    # A copied custom report must not masquerade as output from this invocation.
    if report.exists() or linked(report):
        raise WorkspaceError('fresh report path already exists')
    python = venv_python(root / check['cwd']) or venv_python(root)
    replacements = {'{report}': str(report), '{output_dir}': str(directory),
                    '{project}': str(project), '{python}': str(python) if python else sys.executable}
    environment = os.environ.copy()
    environment['PATH'] = os.pathsep.join([str((python or Path(sys.executable)).parent), tool_search_path(environment.get('PATH', ''))])
    scratch = directory / 'tmp'
    scratch.mkdir()
    environment.update(TMPDIR=str(scratch), TEMP=str(scratch), TMP=str(scratch),
                       PYTHONDONTWRITEBYTECODE='1', HYPOTHESIS_STORAGE_DIRECTORY=str(directory / 'hypothesis'),
                       PLAYWRIGHT_JSON_OUTPUT_FILE=str(report), CI='1')
    deadline = time.monotonic() + check['timeout_seconds']
    for argv in check['commands']:
        command = []
        for arg in argv:
            for key, value in replacements.items():
                arg = arg.replace(key, value)
            command.append(arg)
        result['command'] = command
        if tool == 'strykerjs':
            # Force reruns and prevent old out-of-scope mutants from entering a fresh report.
            command.extend(['--force', '--incrementalFile', str(directory / 'stryker-incremental.json')])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result['summary'] = 'check timeout budget exhausted'
            return
        try:
            proc = execute(resolve_command(command, environment['PATH']), cwd, environment, timeout=remaining)
        except RunCancelled as exc:
            if exc.result:
                detail['executions'].append(_execution(exc.result))
                result.update(stdout=exc.result.stdout[-12000:], stderr=exc.result.stderr[-12000:])
            result.update(status='cancelled', summary='verification tool interrupted')
            raise
        detail['executions'].append(_execution(proc))
        result.update(stdout=(result['stdout'] + proc.stdout)[-12000:], stderr=(result['stderr'] + proc.stderr)[-12000:])
        if proc.returncode != 0 or proc.cleanup_error or proc.terminal_state != 'completed':
            result['summary'] = f'command failed: exit={proc.returncode}, terminal={proc.terminal_state}'
            return
    raw = read_report(report, directory)
    detail['report_sha256'] = hashlib.sha256(raw).hexdigest()
    parsed = parse_report(CATALOG[tool]['format'], raw.decode('utf-8'))
    detail['report'] = parsed
    detail['criteria'] = evaluate_criteria(parsed, check['criteria'])
    passed = parsed['status'] == 'pass' and all(item['status'] == 'pass' for item in detail['criteria'])
    result.update(status='pass' if passed else 'fail', summary='executed report and criteria passed' if passed else 'report or acceptance criterion refused')


def run_check(root: Path, check: dict) -> dict:
    root = root.resolve()
    detail = {'tool': check['tool'], 'executions': [], 'criteria': []}
    result = {'name': 'tool:' + check['id'], 'status': 'fail', 'summary': 'check not completed',
              'command': None, 'stdout': '', 'stderr': '', 'details': [detail]}
    try:
        parent = runtime_parent(root)
        before = fingerprint(root)
        detail.update(source_commit=git_head(root), source_fingerprint=before)
        with tempfile.TemporaryDirectory(prefix='run-', dir=parent) as temporary:
            _run(root, check, result, detail, Path(temporary))
        if fingerprint(root) != before:
            result.update(status='fail', summary='project source changed during tool execution')
    except RunCancelled as exc:
        # The integration boundary converts these dictionaries to its CheckResult type.
        exc.checks = [result]
        raise
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        result.update(status='fail', summary=f'report/execution error: {type(exc).__name__}: {str(exc)[:512]}')
    return result


def planned_checks(root: Path, mode: str, *, make):
    """Yield lazy callbacks so the verifier can refuse later checks before execution."""
    try:
        checks = load_checks(root, mode)
    except ConfigurationError as exc:
        failure = make(name='verification-tools-config', status='fail', summary=str(exc))
        yield failure.name, lambda: failure
        return
    for check in checks:
        def run_selected(selected=check):
            try:
                return make(**run_check(root, selected))
            except RunCancelled as exc:
                exc.checks = [make(**item) if isinstance(item, dict) else item for item in exc.checks]
                raise
        yield 'tool:' + check['id'], run_selected
