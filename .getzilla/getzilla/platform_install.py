"""Native installer observations; these never confer independent security authority."""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

MATRIX_PATH = '.getzilla/config/platform-support.json'
MAX_RESULT_BYTES = 65536
MAX_COMMANDS = 128
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_CELL_LOG_BYTES = 64 * 1024 * 1024
PAIRS = {(system, arch) for system in ('linux', 'macos', 'windows') for arch in ('x64', 'arm64')}


def _unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def decode_result(raw: bytes) -> dict:
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError('platform result exceeds byte limit')
    def number(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError('invalid JSON number')
        return value

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                           parse_float=number, parse_constant=number)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid or too deeply nested platform JSON') from error
    if not isinstance(value, dict):
        raise ValueError('platform result must be an object')
    return value


def load_contract(root: Path) -> dict:
    from .architecture import _read_regular_bytes
    value = decode_result(_read_regular_bytes(root, MATRIX_PATH, label='platform support inventory'))
    cells = value.get('cells', [])
    if (type(value.get('schema_version')) is not int or value['schema_version'] != 1
            or not isinstance(cells, list) or len(cells) != 6
            or any(not isinstance(c, dict) for c in cells)
            or any(not isinstance(c.get(key), str) for c in cells for key in ('id', 'os', 'arch'))
            or {(c.get('os'), c.get('arch')) for c in cells} != PAIRS
            or len({c.get('id') for c in cells}) != 6):
        raise ValueError('platform inventory must contain the six unique native pairs')
    for cell in cells:
        if (cell.get('id') != f"{cell['os']}-{cell['arch']}"
                or type(cell.get('required')) is not bool or type(cell.get('supported')) is not bool
                or (cell['required'] and not cell['supported'])
                or not isinstance(cell.get('runner'), str)
                or not re.fullmatch(r'(?:ubuntu|macos|windows)-[A-Za-z0-9.-]+', cell['runner'])
                or (not cell['supported'] and not cell.get('reason'))):
            raise ValueError('invalid platform support declaration')
    stable = value.get('previous_stable')
    if (not isinstance(stable, dict) or set(stable) != {'tag', 'commit', 'tag_object'}
            or not isinstance(stable['tag'], str) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', stable['tag'])
            or any(not isinstance(stable[key], str) or not re.fullmatch(r'(?:[a-f0-9]{40}|[a-f0-9]{64})', stable[key])
                   for key in ('commit', 'tag_object'))):
        raise ValueError('previous stable must name an immutable tag/object/commit')
    return value


def load_matrix(root: Path) -> list[dict]:
    return load_contract(root)['cells']


def native_platform(system: str, machine: str) -> tuple[str, str]:
    system = {'darwin': 'macos'}.get(system.lower(), system.lower())
    machine = {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64'}.get(machine.lower(), machine.lower())
    if (system, machine) not in PAIRS:
        raise ValueError('unknown native OS or architecture')
    return system, machine


def select_platforms(matrix: list[dict], requested: list[str] | None) -> list[dict]:
    names = ['linux-x64'] if requested is None else requested
    if not names or len(names) != len(set(names)):
        raise ValueError('select unique explicit platform IDs')
    known = {cell['id']: cell for cell in matrix}
    if any(name not in known or not known[name]['supported'] for name in names):
        raise ValueError('unknown or unsupported platform selection')
    return [known[name] for name in names]


def command_evidence(record: dict) -> dict[str, dict]:
    """Validate bounded command structure; completeness flags alone prove nothing."""
    commands = record.get('commands')
    if not isinstance(commands, list) or not 2 <= len(commands) <= MAX_COMMANDS:
        raise ValueError('missing or oversized command evidence')
    by_log = {}
    fields = {'exit', 'logs_complete', 'cleanup_confirmed', 'log', 'observed_bytes',
              'retained_bytes', 'dropped_bytes', 'seconds', 'sha256'}
    for index, command in enumerate(commands, 1):
        if (not isinstance(command, dict) or set(command) != fields
                or command['log'] != f'{index:03d}.log'
                or type(command['exit']) is not int or command['exit'] != 0
                or command['logs_complete'] is not True or command['cleanup_confirmed'] is not True
                or any(type(command[key]) is not int for key in ('observed_bytes', 'retained_bytes', 'dropped_bytes'))
                or not 0 <= command['retained_bytes'] <= MAX_LOG_BYTES
                or command['observed_bytes'] != command['retained_bytes'] or command['dropped_bytes'] != 0
                or type(command['seconds']) not in (int, float)
                or not 0 <= command['seconds'] <= 86400
                or not isinstance(command['sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', command['sha256'])):
            raise ValueError('invalid, duplicate or incomplete command evidence')
        by_log[command['log']] = command
    if sum(command['retained_bytes'] for command in commands) > MAX_CELL_LOG_BYTES:
        raise ValueError('platform command log byte budget exceeded')
    scenarios = record.get('scenarios')
    if not isinstance(scenarios, dict) or set(scenarios) != {'clean', 'upgrade'}:
        raise ValueError('missing scenario command evidence')
    seen = set()
    for checks in scenarios.values():
        logs = checks.get('logs') if isinstance(checks, dict) else None
        if (not isinstance(logs, list) or not 1 <= len(logs) <= MAX_COMMANDS
                or any(not isinstance(log, str) or log not in by_log or log in seen for log in logs)
                or len(set(logs)) != len(logs)
                or not sum(by_log[log]['retained_bytes'] for log in logs)):
            raise ValueError('empty, duplicate or unbound scenario log evidence')
        seen.update(logs)
    return by_log


def load_artifacts(root: Path, *, maximum: int) -> list[dict]:
    """Consume one bounded artifact directory per cell through checked no-follow IO."""
    from . import fsx
    from .component_state import BoundRoot
    records = []
    with BoundRoot(root) as binding:
        with fsx.scandir(binding.handle) as entries:
            for entry in entries:
                if len(records) >= maximum:
                    raise ValueError('unexpected or duplicate platform result artifacts')
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', entry.name):
                    raise ValueError('unsafe platform artifact directory')
                relative = f'{entry.name}/result.json'
                result = binding.read(relative, limit=MAX_RESULT_BYTES)
                if result is None:
                    raise ValueError('missing platform observation')
                record = decode_result(result.content)
                commands = command_evidence(record)
                # Downloaded Actions artifacts contain only result.json and flat log files.
                with binding.parent(relative) as (directory, _, check):
                    names = set()
                    with fsx.scandir(directory) as files:
                        for child in files:
                            if len(names) >= MAX_COMMANDS + 1:
                                raise ValueError('platform artifact entry budget exceeded')
                            names.add(child.name)
                    if names != {'result.json', *commands}:
                        raise ValueError('missing, unexpected or nested platform log artifact')
                    check()
                for name, command in commands.items():
                    snapshot = binding.read(f'{entry.name}/{name}', limit=MAX_LOG_BYTES)
                    if (snapshot is None or len(snapshot.content) != command['retained_bytes']
                            or snapshot.sha256 != command['sha256']):
                        raise ValueError('missing or corrupt platform command log artifact')
                if binding.read(relative, limit=MAX_RESULT_BYTES) != result:
                    raise ValueError('platform observation changed during log validation')
                binding.check()
                records.append(record)
    return records


def validate_results(records: list[dict], *, matrix: list[dict], required: list[str], head: str, tree: str,
                     repository: str, run_id: str, run_attempt: str, version: str, cli_sha256: str,
                     managed_sha256: str, stable: dict, job_result: str = 'success') -> list[str]:
    """Fail closed on required native cells. A pass here is only an Actions observation."""
    problems = []
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}', repository):
        problems.append('missing or malformed candidate repository identity')
    if (not re.fullmatch(r'[1-9][0-9]{0,19}', run_id)
            or not re.fullmatch(r'[1-9][0-9]{0,19}', run_attempt)):
        problems.append('missing or malformed exact Actions run/attempt identity')
    selected = {cell['id']: cell for cell in select_platforms(matrix, required)}
    if job_result != 'success':
        problems.append('required platform job did not succeed')
    by_cell = {}
    for record in records:
        if (not isinstance(record, dict) or not isinstance(record.get('cell'), str)
                or record['cell'] not in selected):
            problems.append('unexpected platform record')
            continue
        name = record['cell']
        if name in by_cell:
            problems.append(f'{name}: duplicate result')
        by_cell[name] = record
    for name, cell in selected.items():
        record = by_cell.get(name)
        if record is None:
            problems.append(f'{name}: missing result')
            continue
        expected = {'schema': 'getzilla-platform-install-v1', 'head': head, 'tree': tree,
                    'repository': repository,
                    'head_after': head, 'tree_after': tree, 'source_clean': True,
                    'run_id': run_id, 'run_attempt': run_attempt, 'os': cell['os'], 'arch': cell['arch'],
                    'authority': 'observations-only'}
        if (record.get('error') is not None
                or any(type(record.get(key)) is not type(value) or record.get(key) != value
                       for key, value in expected.items())):
            problems.append(f'{name}: source, native platform, run or authority mismatch')
        if record.get('stable') != stable:
            problems.append(f'{name}: previous stable identity mismatch')
        try:
            command_evidence(record)
        except ValueError as error:
            problems.append(f'{name}: {error}')
        scenarios = record.get('scenarios')
        if not isinstance(scenarios, dict) or set(scenarios) != {'clean', 'upgrade'}:
            problems.append(f'{name}: missing clean installation or upgrade')
            continue
        for scenario, checks in scenarios.items():
            wanted = {'status': 'pass', 'installed_head': head, 'version': version,
                      'cli_sha256': cli_sha256, 'managed_sha256': managed_sha256,
                      'installer_exit': 0, 'cli_exit': 0,
                      'doctor_exit': 0, 'logs_complete': True, 'agents': ['qwen']}
            if scenario == 'upgrade':
                wanted.update(user_preserved=True, settings_preserved=True, update_exit=0,
                              from_head=stable['commit'], from_version=stable['tag'].removeprefix('v'))
            if (not isinstance(checks, dict)
                    or any(type(checks.get(key)) is not type(value) or checks.get(key) != value
                           for key, value in wanted.items())):
                problems.append(f'{name}/{scenario}: failed, skipped or incomplete checks')
    return problems
