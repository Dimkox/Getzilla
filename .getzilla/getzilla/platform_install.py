"""Native installer observations; these never confer independent security authority."""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

MATRIX_PATH = '.getzilla/config/platform-support.json'
MAX_RESULT_BYTES = 65536
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
        if not isinstance(record, dict) or record.get('cell') not in selected:
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
