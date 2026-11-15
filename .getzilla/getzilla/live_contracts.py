"""Pure invocation and retained-artifact contracts; these grant no execution credit."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import stat
import time

FILE_LIMIT = 128
FILE_BYTES = 2 * 1024 * 1024
TOTAL_BYTES = 32 * 1024 * 1024
CELLS = {'factory': {'factory-postgres-exit'}, 'trust-ci': {'trust-ci-postgres', 'trust-ci-postgres-restart'},
         'lifecycle': {'factory-lifecycle'}}
NAMES = frozenset({'invocation.json', 'observer.json', 'command.log', 'controller-validation.json',
    'factory-resources.json', 'factory-ack.json', 'factory-suite.json', 'factory-restart.json',
    'trust-ci-resources.json', 'trust-ci-ack.json', 'trust-ci-suite.json', 'trust-ci-restart.json',
    'lifecycle.json', 'lifecycle-resource-index.json', 'lifecycle-cleanup-ledger.json',
    'protected-resources.json', 'protected-ack.json', 'protected-evidence.txt'})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def ci_binding(*, head, tree, run_id, attempt, cell, producer_sha256):
    """Derive the expected CI invocation from the consumer's own job/source inputs."""
    if (cell not in CELLS or not all(isinstance(v, str) and re.fullmatch('[0-9a-f]{40}', v) for v in (head, tree))
            or not isinstance(producer_sha256, str) or not re.fullmatch('[0-9a-f]{64}', producer_sha256)
            or not all(isinstance(v, str) and re.fullmatch('[1-9][0-9]{0,19}', v) for v in (run_id, attempt))):
        raise ValueError('CI invocation requires exact source and job identities')
    body = dict(head=head, tree=tree, run_id=run_id, attempt=attempt, cell=cell, producer_sha256=producer_sha256)
    nonce = digest(body)[:32]
    return dict(body, nonce=nonce, namespace='gz-' + cell + '-' + nonce[:12])


def normalize_live_record(record, invocation, expected):
    if (not isinstance(record, dict) or record.get('schema') != 'getzilla-live-acceptance-v1'
            or record.get('binding') != expected or invocation != expected
            or expected.get('cell') not in CELLS):
        raise ValueError('Live artifact differs from independently expected invocation')
    return dict(record, source={'head': expected['head'], 'tree': expected['tree']},
                run_id=expected['run_id'], attempt=expected['attempt'], cell=expected['cell'],
                evidence_kind='retained-controller-observation', fresh_execution_credit=False)


def evidence_name(name):
    plain = name.removesuffix('.envelope.json')
    return plain in NAMES or re.fullmatch(r'gz-[a-z0-9-]+-(resources|sample|ack)\.json', plain) is not None


def read_bytes(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > FILE_BYTES:
        raise ValueError('Live evidence is not a bounded regular file')
    with path.open('rb') as stream:
        content = stream.read(FILE_BYTES + 1)
        after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(content) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
        raise ValueError('Live evidence changed during read')
    return content


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError('Duplicate retained evidence field')
        result[key] = value
    return result


def read_json(path):
    value = json.loads(read_bytes(path), object_pairs_hook=_pairs)
    if not isinstance(value, dict):
        raise ValueError('Live evidence requires an object')
    return value


def evidence_inventory(output):
    paths = sorted(p for p in Path(output).iterdir() if evidence_name(p.name))
    if not 1 <= len(paths) < FILE_LIMIT:
        raise ValueError('Complete live file inventory exceeds unchanged128-file limit')
    result, total = [], 0
    for p in paths:
        content = read_bytes(p)
        total += len(content)
        if total > TOTAL_BYTES:
            raise ValueError('Complete live file bytes exceed existing aggregate limit')
        result.append({'path': p.name, 'sha256': hashlib.sha256(content).hexdigest()})
    return result


def cleanup_ledger(binding, entries):
    if not isinstance(entries, dict) or not 1 <= len(entries) <= 101:
        raise ValueError('Cleanup ledger entries are incomplete or excessive')
    ledger = {'schema': 'getzilla-cleanup-ledger-v1', 'binding': binding, 'acks': dict(entries)}
    if len(canonical(ledger)) > FILE_BYTES:
        raise ValueError('Whole cleanup ledger exceeds existing file bound')
    for name, raw in entries.items():
        if (Path(name).name != name or not name.endswith('-ack.json') or not isinstance(raw, str)
                or len(raw.encode()) > 4096):
            raise ValueError('Cleanup ledger has an unsafe raw acknowledgement')
        item = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(item, dict) or item.get('cleanup') != 'removed':
            raise ValueError('Cleanup ledger cannot claim uncertain cleanup')
    return ledger


def ledger_ack(ledger, binding, name, journal):
    if (set(ledger) != {'schema', 'binding', 'acks'} or ledger['schema'] != 'getzilla-cleanup-ledger-v1'
            or ledger['binding'] != binding):
        raise ValueError('Cleanup ledger invocation differs')
    cleanup_ledger(binding, ledger['acks'])
    value = json.loads(ledger['acks'][name], object_pairs_hook=_pairs)
    if (set(value) != {'cleanup', 'namespace', 'nonce'} or value['cleanup'] != 'removed'
            or value['namespace'] != journal['namespace'] or value['nonce'] != journal['nonce']):
        raise ValueError('Cleanup acknowledgement differs from original resource owner')
    return value


def cycle_budget(mode):
    if mode not in {'sigint', 'sigterm', 'failure', 'timeout', 'kill'}:
        raise ValueError('Unknown lifecycle mode')
    # Reserve cleanup inside, never after, the original35/45-second allocation.
    total = 35 if mode == 'timeout' else 45
    return total - 10, 10


def finish_owned(owner, primary, acknowledge):
    try:
        owner.cleanup()
        acknowledge(owner)
    except BaseException as error:
        if primary is None:
            return error
        BaseException.add_note(primary, 'Owned cleanup unconfirmed: ' + type(error).__name__)
    return primary


def controller_observation(binding, component_files, *, parser_evidence_sha256=None):
    """Retain an earlier controller decision; never reconstruct a measured parser object."""
    if (not isinstance(component_files, dict) or not component_files
            or any(not evidence_name(k) or not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v)
                   for k, v in component_files.items())
            or binding['cell'] == 'factory' and (not isinstance(parser_evidence_sha256, str)
                or not re.fullmatch('[0-9a-f]{64}', parser_evidence_sha256))):
        raise ValueError('Incomplete controller observation')
    return {'schema': 'getzilla-live-controller-observation-v1', 'binding': binding, 'status': 'pass',
            'component_files': dict(component_files), 'parser_evidence_sha256': parser_evidence_sha256,
            'boundary': 'Earlier controller measurement; retained JSON grants no fresh execution credit'}


def recorded_suite_valid(suite, binding):
    """Check retained accounting only. Actual execution uses accepted_suite with measured facts."""
    try:
        names = ('expected_ids', 'collected_ids', 'required_ids', 'started', 'executed', 'missing_required', 'inapplicable_ids')
        if (suite['schema'] != 'getzilla-live-suite-v1' or suite['binding'] != binding or suite['status'] != 'pass'
                or suite['source_stable'] is not True or suite['requirements_complete'] is not True):
            return False
        for key in names:
            values = suite[key]
            if (not isinstance(values, list) or len(values) > 10000
                    or any(not isinstance(v, str) or not v or len(v) > 2048 for v in values)
                    or len(values) != len(set(values))):
                return False
        expected, collected, required, started, executed = (set(suite[k]) for k in names[:5])
        skips = suite['skipped']
        if not isinstance(skips, list) or any(not isinstance(r, dict) or set(r) != {'id', 'reason', 'applicability'} for r in skips):
            return False
        skipped = {r['id'] for r in skips}
        allowances = suite['allowed_skips']
        if (not isinstance(allowances, dict) or len(skips) != len(skipped)
                or skipped != set(allowances) or skipped != set(suite['inapplicable_ids'])
                or any(allowances[r['id']] != {'reason': r['reason'], 'rule': r['applicability']} for r in skips)
                or not expected or expected != collected or collected != started
                or executed != started - skipped or required != expected - skipped
                or suite['missing_required'] or suite['problems']):
            return False
        if (type(suite['tests_run']) is not int or suite['tests_run'] != len(started)
                or any(type(suite[k]) is not int or suite[k] != 0 for k in ('failures', 'errors', 'loader_errors'))):
            return False
        inventory = suite['source_inventory']
        return (isinstance(inventory, dict) and bool(inventory)
                and all(isinstance(k, str) and isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v)
                        for k, v in inventory.items()))
    except (KeyError, TypeError, ValueError):
        return False


def read_live_record(directory, expected, *, expected_source_inventory=None, expected_ids=None):
    """Read a historical CI observation under independently supplied exact context."""
    directory = Path(directory)
    record = read_json(directory / 'manifest.json')
    result = normalize_live_record(record, read_json(directory / 'invocation.json'), expected)
    entries = record.get('files')
    if (not isinstance(entries, list) or not 1 <= len(entries) < FILE_LIMIT
            or any(not isinstance(r, dict) or set(r) != {'path', 'sha256'}
                   or not isinstance(r['path'], str) or Path(r['path']).name != r['path']
                   or not evidence_name(r['path']) for r in entries)
            or len({r['path'] for r in entries}) != len(entries)):
        raise ValueError('Incomplete retained live file inventory')
    names = {r['path']: r['sha256'] for r in entries}
    total = 0
    for name, sha in names.items():
        content = read_bytes(directory / name)
        total += len(content)
        if total > TOTAL_BYTES or hashlib.sha256(content).hexdigest() != sha:
            raise ValueError('Retained file bytes differ or exceed aggregate bound')
    if not {'invocation.json', 'observer.json', 'controller-validation.json'} <= names.keys():
        raise ValueError('Original invocation/controller/observer custody is missing')
    controller = read_json(directory / 'controller-validation.json')
    wanted = controller_observation(expected, controller['component_files'],
                                   parser_evidence_sha256=controller['parser_evidence_sha256'])
    if controller != wanted or any(names.get(k) != v for k, v in controller['component_files'].items()):
        raise ValueError('Retained controller decision or component bytes differ')
    cell = expected['cell']
    if cell != 'lifecycle':
        suite = read_json(directory / (cell + '-suite.json'))
        if (not recorded_suite_valid(suite, expected) or expected_source_inventory is None
                or suite['source_inventory'] != expected_source_inventory or not isinstance(expected_ids, list)
                or set(suite['expected_ids']) != set(expected_ids)):
            raise ValueError('Retained suite differs from complete current source/accounting')
        if cell == 'factory' and digest(suite['applicability']) != controller['parser_evidence_sha256']:
            raise ValueError('Retained parser observation differs; no fresh measurement is inferred')
        for name in (cell + '-suite.json', cell + '-restart.json'):
            envelope = read_json(directory / (name + '.envelope.json'))
            if envelope['binding'] != expected or envelope['report'] != {'path': name, 'sha256': names[name]}:
                raise ValueError('Retained component invocation/report differs')
            journal = envelope['journal']
            if journal != {'path': cell + '-resources.json', 'sha256': names[cell + '-resources.json']}:
                raise ValueError('Retained component original journal differs')
        resource_owner = read_json(directory / (cell + '-resources.json'))
        if (resource_owner.get('cleanup_status') != 'removed' or not resource_owner.get('resources')
                or any(row.get('status') != 'removed' for row in resource_owner['resources'])):
            raise ValueError('Retained original resource cleanup is incomplete')
        restart = read_json(directory / (cell + '-restart.json'))
        if restart['binding'] != expected or restart['status'] != 'pass' or len(restart['restarts']) != (2 if cell == 'factory' else 1):
            raise ValueError('Retained restart observation is incomplete')
        from datetime import datetime
        for row in restart['restarts']:
            before, after = datetime.fromisoformat(row['before']), datetime.fromisoformat(row['after'])
            if (before.utcoffset() is None or after.utcoffset() is None or before >= after
                    or not isinstance(row['cluster'], str) or not row['cluster'].isdigit()
                    or cell == 'trust-ci' and not row['synthetic_job_id']):
                raise ValueError('Retained restart identity or chronology differs')
    else:
        report = read_json(directory / 'lifecycle.json')
        index = read_json(directory / 'lifecycle-resource-index.json')
        journals = {name for name in names if name.endswith('-resources.json')}
        if (report['binding'] != expected or report['status'] != 'pass' or index['binding'] != expected
                or len(journals) != 101 or index['journals'] != {name: names[name] for name in journals}
                or index['cleanup_ledger_sha256'] != names.get('lifecycle-cleanup-ledger.json')):
            raise ValueError('Complete lifecycle journal/ledger custody differs')
        rows = report['cycles']
        if (not isinstance(rows, list) or len(rows) != 100
                or report['resources_before'] != report['resources_after']):
            raise ValueError('Retained lifecycle is not the complete100-cycle observation')
        ledger = read_json(directory / 'lifecycle-cleanup-ledger.json')
        wanted_acks = {'protected-ack.json'} | {expected['namespace'] + f'-c{n}-ack.json' for n in range(1, 96)}
        if set(ledger['acks']) != wanted_acks:
            raise ValueError('Whole normal/protected cleanup ledger is incomplete')
        for n, row in enumerate(rows, 1):
            mode = {96: 'sigint', 97: 'sigterm', 98: 'failure', 99: 'timeout', 100: 'kill'}.get(n, 'normal')
            if (row.get('cycle') != n or row.get('mode') != mode or row.get('status') != 'pass'
                    or row.get('disposable_remaining') != 0 or row.get('protected_unchanged') is not True
                    or row.get('payload_bytes') != 1024 or row.get('directory_payload_bytes') != 1024):
                raise ValueError('Retained cycle observation is missing or failed')
            journal_name = expected['namespace'] + f'-c{n}-resources.json'
            journal = read_json(directory / journal_name)
            if journal.get('cleanup_status') != 'removed' or any(r.get('status') != 'removed' for r in journal['resources']):
                raise ValueError('Original cycle resource cleanup remains uncertain')
            if n <= 95:
                ledger_ack(ledger, expected, journal_name.replace('-resources.json', '-ack.json'), journal)
        protected = read_json(directory / 'protected-resources.json')
        ledger_ack(ledger, expected, 'protected-ack.json', protected)
    return result


def source_inventory(root, subtree):
    """Bound one explicitly selected source subtree; no dependency/policy collection."""
    if subtree != 'trust-ci':
        raise ValueError('Unknown live source subtree')
    root = Path(root)
    result, total, visited = {}, 0, 0
    deadline = time.monotonic() + 3
    for path in (root / subtree).rglob('*'):
        visited += 1
        if visited > 20000 or time.monotonic() > deadline:
            raise ValueError('Explicit source inventory exceeds existing entry/time bound')
        if {'__pycache__', '.pytest_cache', '.venv', 'runtime', '.git'} & set(path.parts):
            continue
        if path.is_symlink():
            raise ValueError('Live source inventory refuses links')
        if not path.is_file() or path.suffix in {'.pyc', '.pyo'}:
            continue
        content = read_bytes(path)
        total += len(content)
        if total > 16 * 1024 * 1024:
            raise ValueError('Explicit source inventory exceeds existing byte bound')
        result[path.relative_to(root).as_posix()] = hashlib.sha256(content).hexdigest()
    if not result:
        raise ValueError('Explicit live source inventory is empty')
    return result


def trust_source_contract(root):
    root = Path(root)
    inventory = source_inventory(root, 'trust-ci')
    path = root / 'trust-ci/tests/test_postgres_integration.py'
    tree = ast.parse(read_bytes(path))
    expected = sorted(path.stem + '.' + cls.name + '.' + method.name
        for cls in tree.body if isinstance(cls, ast.ClassDef)
        for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_'))
    if not expected:
        raise ValueError('Trust source declares no required PostgreSQL cases')
    return inventory, expected


def wheelhouse_command(python, lock, output):
    return [str(python), '-m', 'pip', 'download', '--disable-pip-version-check', '--no-cache-dir',
            '--timeout', '15', '--retries', '0', '--require-hashes', '--only-binary=:all:', '--no-deps',
            '--platform', 'manylinux_2_28_x86_64', '--platform', 'manylinux2014_x86_64',
            '--python-version', '3.13', '--implementation', 'cp', '--abi', 'cp313',
            '--dest', str(output), '-r', str(lock)]


def validate_wheelhouse(path, lock):
    path, lock = Path(path), Path(lock)
    if path.is_symlink() or not path.is_dir():
        raise ValueError('GETZILLA_LIVE_WHEELHOUSE must name a pre-acquired owned offline directory')
    allowed = set(re.findall(r'--hash=sha256:([0-9a-f]{64})', lock.read_text()))
    files = list(path.iterdir())
    if not allowed or not 1 <= len(files) <= 256:
        raise ValueError('Hash-locked offline wheelhouse is absent or excessive')
    total, result = 0, {}
    for p in files:
        before = p.lstat()
        total += before.st_size
        if (not stat.S_ISREG(before.st_mode) or p.suffix != '.whl' or total > 64 * 1024 * 1024):
            raise ValueError('Offline wheelhouse bytes are unsafe, unselected or excessive')
        sha = hashlib.sha256()
        with p.open('rb') as stream:
            while chunk := stream.read(65536):
                sha.update(chunk)
        after = p.lstat()
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or sha.hexdigest() not in allowed):
            raise ValueError('Offline wheel is changed or not selected by the original hash lock')
        result[p.name] = sha.hexdigest()
    return result
