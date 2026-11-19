"""Bounded offline replay evidence. This module grants no release or model authority."""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from importlib.machinery import SourceFileLoader, SourcelessFileLoader
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
import uuid
from zipimport import zipimporter

from . import fsx

MAX_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 512 * 1024
MAX_CASES = 100
MAX_ASSERTIONS = 32
MAX_HISTORY = 32
MAX_BASELINE_BYTES = MAX_HISTORY * (MAX_REPORT_BYTES + 8192)
CONFIG = '.getzilla-evals.json'
STATUSES = {'pass', 'fail', 'invalid', 'timeout', 'not_run', 'unsupported'}
IDENTITIES = {'model', 'prompt', 'tool', 'index', 'config', 'source'}
OPS = {'equals', 'contains', 'not_contains', 'exists'}


class EvalError(ValueError):
    """A public reason code, never an input value or raw payload."""


def _require(condition, reason):
    if not condition:
        raise EvalError(reason)


def _bytes(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    """SHA-256 of canonical, finite JSON."""
    return hashlib.sha256(_bytes(value)).hexdigest()


def _runner_digest():
    # Lean installs keep this module in getzilla.zip and __init__.py outside it.
    # Read through this module's loader, not the package loader or a virtual Path.
    try:
        loader = globals().get('__loader__')
        _require(type(loader) in {SourceFileLoader, SourcelessFileLoader, zipimporter}
                 and __name__ == 'getzilla.agent_evals', 'runner_source_unavailable')
        filename = loader.get_filename(__name__)
        _require(filename == __file__ and filename.replace('\\', '/').endswith(
            ('/getzilla/agent_evals.py', '/getzilla/agent_evals.pyc')), 'runner_source_unavailable')
        source = filename[:-1] if filename.endswith('.pyc') else filename
        raw = loader.get_data(source)
        _require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'runner_source_unavailable')
        compile(raw, source, 'exec', dont_inherit=True)
        return hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, SyntaxError, TypeError, AttributeError, RecursionError) as exc:
        raise EvalError('runner_source_unavailable') from exc


def _unique(pairs):
    value = {}
    for key, item in pairs:
        _require(key not in value, 'duplicate_json_key')
        value[key] = item
    return value


def _invalid_constant(_value):
    raise EvalError('nonfinite_json')


def _finite_float(text):
    value = float(text)
    _require(math.isfinite(value), 'nonfinite_json')
    return value


def _json_depth(value):
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        _require(depth <= 64, 'json_depth_limit')
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)


def _parts(relative):
    _require(isinstance(relative, str) and 0 < len(relative) <= 512 and '\\' not in relative
             and ':' not in relative and '\0' not in relative, 'invalid_path')
    parts = relative.split('/')
    _require(not PurePosixPath(relative).is_absolute() and all(p not in {'', '.', '..'} for p in parts), 'invalid_path')
    return parts


def _file_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _inode(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _read_at(directory, name, limit, check=lambda: None, *, raw_bytes=False):
    """Read one selected name using its held parent; never reopen that parent."""
    try:
        check()
        named = fsx.lstat_at(directory, name)
        _require(not fsx.is_link(named) and stat.S_ISREG(named.st_mode), 'input_size_or_type')
        fd = fsx.open_at(directory, name, os.O_RDONLY | fsx.O_NONBLOCK | fsx.O_NOFOLLOW | fsx.O_BINARY | fsx.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as handle:
            before = os.fstat(handle.fileno())
            _require(_file_identity(before) == _file_identity(named) and before.st_size <= limit, 'input_size_or_type')
            raw = handle.read(limit + 1)
            _require(len(raw) <= limit and len(raw) == before.st_size
                     and _file_identity(before) == _file_identity(os.fstat(handle.fileno()))
                     and _file_identity(before) == _file_identity(fsx.lstat_at(directory, name)), 'input_changed_or_large')
        check()
        if raw_bytes:
            return raw, hashlib.sha256(raw).hexdigest(), _file_identity(before)
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_invalid_constant, parse_float=_finite_float)
        _json_depth(value)
        return value, hashlib.sha256(raw).hexdigest(), _file_identity(before)
    except FileNotFoundError as exc:
        raise EvalError('input_missing') from exc
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, EvalError):
            raise
        raise EvalError('input_unreadable_or_invalid_json') from exc


def _read(root, relative, limit=MAX_BYTES):
    """Read regular files through directory handles; never follow links or wait on FIFOs."""
    parts = _parts(relative)
    directory = None
    try:
        directory = fsx.open_dir(root)
        for part in parts[:-1]:
            child = fsx.open_dir_at(directory, part)
            fsx.close_dir(directory)
            directory = child
        value, sha, _identity = _read_at(directory, parts[-1], limit)
        return value, sha
    except FileNotFoundError as exc:
        raise EvalError('input_missing') from exc
    except OSError as exc:
        raise EvalError('input_unreadable_or_invalid_json') from exc
    finally:
        fsx.close_dir(directory)


@contextmanager
def _baseline_parent(path):
    """Hold every ancestor, and revalidate its name against the held inode.

    fsx's Windows path adapter is insufficient for race-safe baseline transactions.
    Refuse that operation rather than simulate descriptor-relative authority.
    Parents must already exist; this operation never creates directories.
    """
    _require(os.name == 'posix' and not fsx.WINDOWS, 'baseline_descriptor_unsupported')
    path = Path(path)
    _require('..' not in path.parts, 'invalid_path')
    path = path.absolute()
    _parts(path.name)
    handles = []
    chain = []
    try:
        anchor = fsx.open_dir(path.anchor, flags=fsx.O_CLOEXEC)
        handles.append(anchor)
        expected_anchor = _inode(fsx.fstat_dir(anchor))
        directory = anchor

        def check():
            _require(_inode(fsx.fstat_dir(anchor)) == expected_anchor, 'baseline_namespace_changed')
            for parent, name, child, expected in chain:
                named = fsx.lstat_at(parent, name)
                _require(not fsx.is_link(named) and _inode(named) == expected
                         and _inode(fsx.fstat_dir(child)) == expected, 'baseline_namespace_changed')

        for name in path.parts[1:-1]:
            check()
            named = fsx.lstat_at(directory, name)
            _require(not fsx.is_link(named) and stat.S_ISDIR(named.st_mode), 'baseline_parent')
            child = fsx.open_dir_at(directory, name, flags=fsx.O_CLOEXEC)
            handles.append(child)
            _require(_inode(fsx.fstat_dir(child)) == _inode(named), 'baseline_namespace_changed')
            chain.append((directory, name, child, _inode(named)))
            directory = child
        check()
        _require(fsx.fstat_dir(directory).st_uid == os.geteuid(), 'baseline_parent_owner')
        yield directory, path.name, check
        check()
    except FileNotFoundError as exc:
        raise EvalError('input_missing') from exc
    except OSError as exc:
        raise EvalError('baseline_namespace_or_io') from exc
    finally:
        for handle in reversed(handles):
            fsx.close_dir(handle)


@contextmanager
def _baseline_lock(directory, *, exclusive):
    """Retain a kernel lock on the held parent; no lock pathname is mutated."""
    try:
        fsx.lock_file(directory, exclusive=exclusive, blocking=False)
    except BlockingIOError as exc:
        raise EvalError('baseline_acceptance_busy') from exc
    except (OSError, NotImplementedError) as exc:
        raise EvalError('baseline_lock_unsupported') from exc
    try:
        yield
    finally:
        try:
            fsx.unlock_file(directory)
        except OSError as exc:
            raise EvalError('baseline_lock_unavailable') from exc


def _fields(value, required, optional=(), reason='schema'):
    _require(isinstance(value, dict) and set(required) <= set(value) <= set(required) | set(optional), reason)


def _label(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}', value))


def _sha(value, size=64):
    return isinstance(value, str) and bool(re.fullmatch('[0-9a-f]{' + str(size) + '}', value))


def _version(value):
    _fields(value, {'id', 'version'}, reason='version_schema')
    _require(_label(value['id']) and _label(value['version']), 'version_schema')


def _manifest(value):
    _fields(value, {'schema_version', 'suite_id', 'dataset', 'adapter', 'grader', 'comparator',
                    'protocol', 'identities', 'cases'}, reason='manifest_schema')
    _require(type(value['schema_version']) is int and value['schema_version'] == 1 and _label(value['suite_id']), 'manifest_schema')
    for name in ('dataset', 'adapter', 'grader', 'comparator'):
        _version(value[name])
    protocol = value['protocol']
    _fields(protocol, {'id', 'version', 'variables', 'repetitions'}, reason='protocol_schema')
    _require(_label(protocol['id']) and _label(protocol['version']) and type(protocol['repetitions']) is int
             and protocol['repetitions'] == 1, 'offline_repetitions_must_be_one')
    variables = protocol['variables']
    _require(isinstance(variables, list) and all(isinstance(v, str) and v in IDENTITIES for v in variables)
             and len(set(variables)) == len(variables), 'protocol_variables')
    identities = value['identities']
    _fields(identities, IDENTITIES, reason='identity_schema')
    _require(all(_label(identities[k]) for k in IDENTITIES - {'source'}), 'identity_schema')
    _fields(identities['source'], {'commit', 'tree'}, reason='source_identity')
    _require(all(_sha(v, 40) for v in identities['source'].values()), 'source_identity')
    cases = value['cases']
    _require(isinstance(cases, list) and 1 <= len(cases) <= MAX_CASES, 'empty_or_large_cohort')
    seen = set()
    for case in cases:
        _fields(case, {'id', 'path', 'sha256'}, reason='case_reference_schema')
        _require(_label(case['id']) and _sha(case['sha256']), 'case_reference_schema')
        _require(case['id'] not in seen, 'duplicate_case_id')
        seen.add(case['id'])
        _parts(case['path'])
    return value


def _path(value):
    _require(isinstance(value, list) and len(value) <= 16 and all(
        (isinstance(v, str) and 0 < len(v) <= 128) or (type(v) is int and 0 <= v <= 10000) for v in value), 'assertion_path')


def _case(value, expected_id):
    _fields(value, {'schema_version', 'id', 'source', 'input', 'assertions'}, {'signals'}, reason='case_schema')
    _require(type(value['schema_version']) is int and value['schema_version'] == 1 and value['id'] == expected_id
             and _label(value['source']), 'case_schema')
    assertions = value['assertions']
    _require(isinstance(assertions, list) and 1 <= len(assertions) <= MAX_ASSERTIONS, 'empty_or_large_assertions')
    seen = set()
    for assertion in assertions:
        _fields(assertion, {'id', 'op', 'path'}, {'expected'}, reason='assertion_schema')
        _require(_label(assertion['id']) and _label(assertion['op']), 'assertion_schema')
        _require(assertion['id'] not in seen, 'duplicate_assertion_id')
        seen.add(assertion['id'])
        _path(assertion['path'])
        if assertion['op'] in OPS:
            _require(('expected' in assertion) == (assertion['op'] != 'exists'), 'assertion_schema')
        if assertion['op'] in {'contains', 'not_contains'}:
            _require(isinstance(assertion['expected'], str) and len(assertion['expected']) <= 8192, 'assertion_schema')
    signals = value.get('signals', [])
    _require(isinstance(signals, list) and len(signals) <= 16, 'signals_schema')
    seen = set()
    for signal in signals:
        _fields(signal, {'id', 'kind', 'path'}, reason='signals_schema')
        _require(_label(signal['id']) and signal['id'] not in seen and isinstance(signal['kind'], str) and signal['kind'] in {'length', 'reported_confidence'}, 'signals_schema')
        seen.add(signal['id'])
        _path(signal['path'])
    return value


def _outputs(value, cases):
    _fields(value, {'schema_version', 'outputs'}, reason='outputs_schema')
    _require(type(value['schema_version']) is int and value['schema_version'] == 1 and isinstance(value['outputs'], list)
             and len(value['outputs']) <= MAX_CASES, 'outputs_schema')
    result = {}
    for item in value['outputs']:
        _fields(item, {'case_id', 'case_sha256', 'output'}, {'latency_ms', 'usage'}, reason='output_schema')
        _require(isinstance(item['case_id'], str) and item['case_id'] in cases and _sha(item['case_sha256']), 'output_schema')
        _require(item['case_id'] not in result, 'duplicate_output_id')
        result[item['case_id']] = item
        if 'latency_ms' in item:
            _require(_bounded_number(item['latency_ms'], 0, 86400000), 'latency_schema')
        if 'usage' in item:
            _fields(item['usage'], {'input_tokens', 'output_tokens'}, reason='usage_schema')
            _require(all(type(v) is int and 0 <= v <= 10**12 for v in item['usage'].values()), 'usage_schema')
    return result


def _lookup(value, path):
    for part in path:
        if isinstance(value, dict) and isinstance(part, str) and part in value:
            value = value[part]
        elif isinstance(value, list) and type(part) is int and part < len(value):
            value = value[part]
        else:
            return False, None
    return True, value


def _assertion(assertion, output):
    result = {'id': assertion['id'], 'assertion_digest': digest(assertion), 'op': assertion['op']}
    if assertion['op'] not in OPS:
        return {**result, 'status': 'unsupported', 'reason': 'unsupported_assertion'}
    exists, actual = _lookup(output, assertion['path'])
    op = assertion['op']
    if op == 'exists':
        passed = exists
    elif op == 'equals':
        # JSON types remain distinct: true does not equal 1.
        passed = exists and _bytes(actual) == _bytes(assertion['expected'])
    elif not exists or not isinstance(actual, str):
        return {**result, 'status': 'fail', 'reason': 'assertion_type_or_path'}
    else:
        contains = assertion['expected'] in actual
        passed = contains if op == 'contains' else not contains
    return {**result, 'status': 'pass' if passed else 'fail', 'reason': 'matched' if passed else 'assertion_mismatch'}


def _aggregate(statuses):
    return next((s for s in ('invalid', 'unsupported', 'timeout', 'not_run', 'fail') if s in statuses), 'pass')


def _bounded_number(value, minimum, maximum):
    # Check integer bounds before math.isfinite, which coerces integers to floats.
    return type(value) in {int, float} and minimum <= value <= maximum and math.isfinite(value)


def _signal(signal, output):
    exists, value = _lookup(output, signal['path'])
    if exists and signal['kind'] == 'reported_confidence' and type(value) in {int, float}:
        _require(_bounded_number(value, 0, 1), 'signal_numeric_range')
    valid = exists and (isinstance(value, (str, list, dict)) if signal['kind'] == 'length'
                       else _bounded_number(value, 0, 1))
    result = {'id': signal['id'], 'kind': signal['kind'], 'status': 'observed' if valid else 'unavailable'}
    if valid:
        result['value'] = len(value) if signal['kind'] == 'length' else value
    return result


def replay(root: Path, manifest_path: str, outputs_path: str, *, timeout_seconds: float = 10) -> dict:
    """Replay bounded recorded JSON with deterministic executable assertions only."""
    started = time.monotonic()
    canonical = {'schema_version': 1, 'kind': 'offline-recorded-replay', 'status': 'invalid', 'cases': []}
    telemetry = {'latency_observed': 0, 'usage_observed': 0, 'case_count': 0}
    try:
        _require(_bounded_number(timeout_seconds, 0, 60), 'timeout_budget')
        manifest, manifest_sha = _read(root, manifest_path)
        manifest = _manifest(manifest)
        canonical['identity'] = {'manifest_sha256': manifest_sha, 'experiment': manifest['identities'],
                                 'runner_sha256': _runner_digest()}
        contract = {k: manifest[k] for k in ('suite_id', 'dataset', 'adapter', 'grader', 'comparator', 'protocol')}
        contract['cases'] = sorted([{'id': c['id'], 'sha256': c['sha256']} for c in manifest['cases']], key=lambda c: c['id'])
        canonical.update(contract=contract, contract_digest=digest(contract))
        recording, recording_sha = _read(root, outputs_path)
        canonical['identity']['recording_sha256'] = recording_sha
        outputs = _outputs(recording, {c['id'] for c in manifest['cases']})
        unsupported = any(manifest[k] != {'id': name, 'version': '1'} for k, name in (
            ('adapter', 'recorded-output'), ('grader', 'deterministic'), ('comparator', 'paired-verdict')))
        for ref in sorted(manifest['cases'], key=lambda c: c['id']):
            result = {'id': ref['id'], 'case_sha256': ref['sha256'], 'status': 'invalid',
                      'reason': 'invalid_case', 'assertions': [], 'signals': []}
            canonical['cases'].append(result)
            if time.monotonic() - started >= timeout_seconds:
                result.update(status='timeout', reason='replay_budget_exhausted')
                continue
            try:
                case, case_sha = _read(root, ref['path'])
                _require(case_sha == ref['sha256'], 'case_hash_mismatch')
                case = _case(case, ref['id'])
                result['source'] = case['source']
                result['input_digest'] = digest(case['input'])
                if unsupported:
                    result.update(status='unsupported', reason='unsupported_adapter_grader_or_comparator')
                    continue
                item = outputs.get(ref['id'])
                if item is None:
                    result.update(status='not_run', reason='missing_output')
                    continue
                _require(item['case_sha256'] == ref['sha256'], 'output_case_hash_mismatch')
                output = item['output']
                result['output_digest'] = digest(output)
                result['assertions'] = [_assertion(a, output) for a in case['assertions']]
                result['signals'] = [_signal(s, output) for s in case.get('signals', [])]
                result['status'] = _aggregate({a['status'] for a in result['assertions']})
                result['reason'] = 'graded'
                telemetry['latency_observed'] += int('latency_ms' in item)
                telemetry['usage_observed'] += int('usage' in item)
                if time.monotonic() - started >= timeout_seconds:
                    result.update(status='timeout', reason='replay_budget_exhausted')
            except EvalError as exc:
                result.update(status='invalid', reason=str(exc))
        canonical['status'] = _aggregate({c['status'] for c in canonical['cases']})
    except EvalError as exc:
        canonical.update(status='invalid', reason=str(exc))
    except (TypeError, ValueError, OverflowError, RecursionError, OSError):
        canonical.update(status='invalid', reason='invalid_input')
    telemetry['case_count'] = len(canonical['cases'])
    telemetry['seconds'] = round(time.monotonic() - started, 6)
    canonical['counts'] = dict(sorted(Counter(c['status'] for c in canonical['cases']).items()))
    report = {'schema_version': 1, 'canonical': canonical, 'result_digest': digest(canonical),
              'run': {'id': str(uuid.uuid4()), 'timestamp': datetime.now(timezone.utc).isoformat()},
              'telemetry': telemetry, 'qualification': 'recorded-output-only', 'release_authority': False,
              'references': ['https://github.com/Dimkox/Getzilla/issues/152', 'https://github.com/Dimkox/Getzilla/issues/200']}
    return _bounded_report(report)


def _bounded_report(report):
    """Cap the complete export, including comparison, with an explicit refusal."""
    if len(_bytes(report)) + 1 <= MAX_REPORT_BYTES:
        return report
    original_digest = report['result_digest']
    canonical = {'schema_version': 1, 'kind': 'offline-recorded-replay', 'status': 'invalid',
                 'reason': 'report_size_limit', 'cases': [], 'omitted_result_digest': original_digest}
    result = {**report, 'canonical': canonical, 'result_digest': digest(canonical)}
    if 'comparison' in result:
        result['comparison'] = {'status': 'inconclusive', 'reason': 'report_size_limit',
                                'candidate_digest': original_digest, 'release_authority': False}
    return result


def attach_comparison(report, baseline_path):
    return _bounded_report({**report, 'comparison': compare(report, baseline_path)})


def _study(value, manifest):
    _fields(value, {'schema_version', 'manifest_sha256', 'cases', 'judgments', 'measurements'}, reason='study_schema')
    _require(type(value['schema_version']) is int and value['schema_version'] == 1
             and _sha(value['manifest_sha256']), 'study_schema')
    refs = {row['id']: row for row in manifest['cases']}
    _require(isinstance(value['cases'], list) and len(value['cases']) == len(refs), 'study_cohort')
    cases, pairs = {}, {}
    for row in value['cases']:
        _fields(row, {'id', 'pair', 'family', 'variant', 'incident', 'oracle_test'}, reason='study_case')
        _require(isinstance(row['id'], str) and row['id'] in refs and row['id'] not in cases
                 and _label(row['pair']) and _label(row['family'])
                 and isinstance(row['variant'], str) and row['variant'] in {'faulty', 'clean'}, 'study_case')
        incident = row['incident']
        _fields(incident, {'commit', 'path', 'sha256'}, reason='incident_identity')
        _require(_sha(incident['commit'], 40) and _sha(incident['sha256']), 'incident_identity')
        _parts(incident['path'])
        _require(isinstance(row['oracle_test'], str) and len(row['oracle_test']) <= 512
                 and re.fullmatch(r'tests/[A-Za-z0-9_./-]+\.py::[A-Za-z0-9_.]+', row['oracle_test']), 'oracle_reference')
        cases[row['id']] = row
        pairs.setdefault(row['pair'], []).append(row)
    for pair in pairs.values():
        _require(len(pair) == 2 and {r['variant'] for r in pair} == {'faulty', 'clean'}
                 and pair[0]['family'] == pair[1]['family'] and pair[0]['incident'] == pair[1]['incident']
                 and pair[0]['oracle_test'] == pair[1]['oracle_test'], 'study_pair')
    families, incidents = {}, {}
    for row in cases.values():
        identity = digest(row['incident'])
        _require(families.get(row['family'], identity) == identity
                 and incidents.get(identity, row['family']) == row['family'], 'incident_family_alias')
        families[row['family']], incidents[identity] = identity, row['family']
    _require(isinstance(value['judgments'], list) and len(value['judgments']) <= MAX_CASES, 'judgments_schema')
    judgments = {}
    for row in value['judgments']:
        _fields(row, {'case_id', 'case_sha256', 'recording_sha256', 'status', 'oracle_status', 'evidence_sha256'}, reason='judgment_schema')
        _require(isinstance(row['case_id'], str) and row['case_id'] in cases and row['case_id'] not in judgments
                 and all(_sha(row[k]) for k in ('case_sha256', 'recording_sha256', 'evidence_sha256'))
                 and isinstance(row['status'], str) and row['status'] in {'synthetic', 'confirmed', 'disputed', 'pending'}
                 and isinstance(row['oracle_status'], str) and row['oracle_status'] in {'pass', 'fail', 'not_run'}, 'judgment_schema')
        judgments[row['case_id']] = row
    return cases, judgments


def _review_measurements(rows):
    _require(isinstance(rows, list) and len(rows) <= MAX_CASES * 4, 'measurements_schema')
    operations = {}
    for row in rows:
        _fields(row, {'operation_id', 'stage', 'seconds', 'kind', 'amount', 'currency', 'source_ref'}, reason='measurement_schema')
        _require(_label(row['operation_id']) and _label(row['source_ref'])
                 and isinstance(row['stage'], str) and row['stage'] in {'critic', 'oracle', 'adjudication', 'case-production'}
                 and isinstance(row['kind'], str) and row['kind'] in {'observed', 'reservation', 'unknown'}
                 and (row['seconds'] is None or _bounded_number(row['seconds'], 0, 86400))
                 and (row['amount'] is None or _bounded_number(row['amount'], 0, 10**12))
                 and (row['currency'] is None or isinstance(row['currency'], str)
                      and re.fullmatch('[A-Z]{3}', row['currency'])), 'measurement_schema')
        previous = operations.get(row['operation_id'])
        _require(previous is None or previous == row, 'conflicting_operation')
        operations[row['operation_id']] = row
    seconds, costs, unknown = {}, {}, 0
    for row in operations.values():
        if row['seconds'] is not None:
            seconds[row['stage']] = seconds.get(row['stage'], 0) + row['seconds']
        if row['kind'] == 'observed' and row['amount'] is not None and row['currency'] is not None:
            costs[row['currency']] = costs.get(row['currency'], 0) + row['amount']
        else:
            unknown += 1
    return {'operations': len(operations), 'seconds_by_stage': seconds,
            'time_unknown_operations': sum(r['seconds'] is None for r in operations.values()),
            'observed_cost_by_currency': costs, 'unknown_cost_operations': unknown,
            'total_usd': costs.get('USD') if not unknown and set(costs) == {'USD'} else None,
            'source_references': [{k: r[k] for k in ('operation_id', 'kind', 'source_ref')}
                                  for r in sorted(operations.values(), key=lambda r: r['operation_id'])],
            'provenance': 'recorded-declarations-not-a-billing-attestation'}


def _critic_provenance(root, source, observation):
    """Project existing native evidence without granting identity or independence authority."""
    result = {'independence': 'unknown', 'author_history': 'incomplete', 'model_family': None,
              'blinding': 'unknown', 'source_binding': None, 'known_author_overlap': None,
              'workflow_instance': None, 'report_authorship': 'not_attested', 'reason': 'native_review_not_observed'}
    if observation is None:
        return result
    _fields(observation, {'agent_id', 'generation', 'report', 'reviewed_context'}, reason='review_observation_schema')
    _require(_label(observation['agent_id']) and _label(observation['generation'])
             and _sha(observation['reviewed_context']), 'review_observation_schema')
    _parts(observation['report'])
    from .continuity import task_identity
    from .review_source import review_source_binding
    from .state import get_active_route, agent_state_path
    route = get_active_route(root) or {}
    native_path = agent_state_path(root).relative_to(root).as_posix()
    state, native_sha = _read(root, native_path)
    _require(isinstance(state, dict), 'native_history_schema')
    history = state.get('history', [])
    active = state.get('active', {})
    _require(isinstance(history, list) and len(history) <= 200
             and isinstance(active, dict) and len(active) <= MAX_CASES, 'native_history_schema')
    records = [*history, *({'agent_id': key, **row} for key, row in active.items() if isinstance(row, dict))]
    same_task = [r for r in records if isinstance(r, dict) and r.get('route_id') == route.get('route_id')
                 and r.get('task_id') == task_identity(route) and r.get('workspace') == str(root.resolve())]
    reviewer = [r for r in same_task if r.get('agent_id') == observation['agent_id']
                and r.get('generation') == observation['generation'] and r.get('authority_epoch') == route.get('authority_epoch')
                and r.get('agent_type') in route.get('review_agents', [])]
    if not reviewer:
        return {**result, 'reason': 'selected_reviewer_instance_not_observed'}
    authors = {r.get('agent_id') for r in same_task if r.get('agent_type') == route.get('write_agent')}
    binding = review_source_binding(root, source['commit'], observation['report'],
                                    reviewed_context=observation['reviewed_context'])
    _require(binding['reviewed_tree'] == source['tree'], 'review_source_tree_mismatch')
    _require(_read(root, native_path)[1] == native_sha, 'native_history_changed')
    return {**result, 'source_binding': binding, 'workflow_instance': {
                'agent_id': observation['agent_id'], 'generation': observation['generation'],
                'route_id': route['route_id'], 'task_id': task_identity(route), 'authority_epoch': route.get('authority_epoch')},
            'known_author_overlap': observation['agent_id'] in authors if authors else None,
            'reason': 'bounded-native-history-is-not-complete-source-cohort-recording-authorship'}


def review_quality(root: Path, manifest_path: str, outputs_path: str, study_path: str, *, observation=None, timeout_seconds=10):
    """Project paired critic judgments through the existing replay; execute no model or oracle."""
    report = replay(root, manifest_path, outputs_path, timeout_seconds=timeout_seconds)
    report.update(qualification='algorithm-only-recorded-judgments', runtime_detection_quality=None,
                  human_final_acceptance='not_observed', integration_status='native-telemetry-accounting-pending')
    report['critic_provenance'] = _critic_provenance(root, {}, None)
    try:
        manifest, manifest_sha = _read(root, manifest_path)
        manifest = _manifest(manifest)
        outputs, recording_sha = _read(root, outputs_path)
        outputs = _outputs(outputs, {c['id'] for c in manifest['cases']})
        study, study_sha = _read(root, study_path)
        cases, judgments = _study(study, manifest)
        identity = report['canonical'].get('identity', {})
        _require(study['manifest_sha256'] == manifest_sha == identity.get('manifest_sha256')
                 and recording_sha == identity.get('recording_sha256'), 'study_input_drift')
        graded = {r['id']: r for r in report['canonical']['cases']}
        counts = dict.fromkeys(('TP', 'FN', 'FP', 'TN'), 0)
        families, unresolved = {}, []
        refs = {r['id']: r for r in manifest['cases']}
        for identifier, case in sorted(cases.items()):
            family = families.setdefault(case['family'], {'family': case['family'], 'planned': 0, 'resolved': 0,
                                                         'counts': dict.fromkeys(('TP', 'FN', 'FP', 'TN'), 0)})
            family['planned'] += 1
            judgment, item, verdict = judgments.get(identifier), outputs.get(identifier), graded.get(identifier, {})
            reason = None
            if judgment is None or judgment['status'] not in {'synthetic', 'confirmed'}:
                reason = 'judgment_unresolved'
            elif judgment['case_sha256'] != refs[identifier]['sha256'] or judgment['recording_sha256'] != recording_sha:
                reason = 'judgment_binding_drift'
            elif judgment['oracle_status'] != 'pass':
                reason = 'oracle_not_passing'
            elif item is None or verdict.get('status') not in {'pass', 'fail'} or verdict.get('reason') != 'graded':
                reason = 'replay_unresolved'
            finding = item.get('output', {}).get('finding') if item and isinstance(item.get('output'), dict) else None
            if reason is None and (not isinstance(finding, str) or finding not in {'detected', 'clear'}):
                reason = 'finding_unknown'
            if reason:
                unresolved.append({'id': identifier, 'reason': reason})
                continue
            faulty, detected = case['variant'] == 'faulty', finding == 'detected'
            outcome = ('TP' if detected else 'FN') if faulty else ('FP' if detected else 'TN')
            counts[outcome] += 1
            family['counts'][outcome] += 1
            family['resolved'] += 1
        def ratio(numerator, denominator):
            return numerator / denominator if denominator else None
        resolved = sum(counts.values())
        quality = {'status': 'observed', 'study_sha256': study_sha,
                   'planned': {'cases': len(cases), 'faulty': sum(c['variant'] == 'faulty' for c in cases.values()),
                               'clean': sum(c['variant'] == 'clean' for c in cases.values()),
                               'pairs': len({c['pair'] for c in cases.values()}), 'incident_families': len(families)},
                   'resolved': resolved, 'coverage': ratio(resolved, len(cases)), 'counts': counts,
                   'rates': {'precision': ratio(counts['TP'], counts['TP'] + counts['FP']),
                             'recall': ratio(counts['TP'], counts['TP'] + counts['FN']),
                             'false_positive_rate': ratio(counts['FP'], counts['FP'] + counts['TN'])},
                   'families': sorted(families.values(), key=lambda r: r['family']), 'unresolved': unresolved,
                   'judgments': 'recorded-declarations-not-independent-adjudication-proof',
                   'measurements': _review_measurements(study['measurements'])}
        report['critic_provenance'] = _critic_provenance(root, manifest['identities']['source'], observation)
        report['quality'] = quality
    except (EvalError, OSError, ValueError, RuntimeError, TypeError, KeyError, RecursionError) as exc:
        report['quality'] = {'status': 'invalid', 'reason': str(exc) if isinstance(exc, EvalError) else 'quality_evidence_unavailable'}
    if len(_bytes(report)) + 1 > MAX_REPORT_BYTES:
        report['quality'] = {'status': 'invalid', 'reason': 'report_size_limit'}
        report['critic_provenance'] = _critic_provenance(root, {}, None)
    report['quality_digest'] = digest(report['quality'])
    return _bounded_report(report)


def _report(report, *, passing=False):
    _require(isinstance(report, dict) and isinstance(report.get('canonical'), dict)
             and report.get('result_digest') == digest(report['canonical']), 'result_digest_mismatch')
    value = report['canonical']
    _require(value.get('kind') == 'offline-recorded-replay' and type(value.get('schema_version')) is int
             and value['schema_version'] == 1 and isinstance(value.get('status'), str)
             and value['status'] in STATUSES and isinstance(value.get('cases'), list)
             and len(value['cases']) <= MAX_CASES, 'result_schema')
    seen = set()
    for case in value['cases']:
        _require(isinstance(case, dict) and _label(case.get('id')) and case['id'] not in seen
                 and isinstance(case.get('status'), str) and case['status'] in STATUSES
                 and _sha(case.get('case_sha256')) and isinstance(case.get('assertions'), list)
                 and len(case['assertions']) <= MAX_ASSERTIONS, 'result_case_schema')
        seen.add(case['id'])
        assertions = set()
        for assertion in case['assertions']:
            _require(isinstance(assertion, dict) and _label(assertion.get('id'))
                     and assertion['id'] not in assertions and isinstance(assertion.get('status'), str)
                     and assertion['status'] in STATUSES and _sha(assertion.get('assertion_digest')), 'result_assertion_schema')
            assertions.add(assertion['id'])
        # A grading error or exhausted budget can interrupt a case after its
        # assertions ran. Successful/completed verdicts must match those facts.
        if case['assertions']:
            _require(case['status'] in {'invalid', 'timeout'}
                     or case['status'] == _aggregate({a['status'] for a in case['assertions']}),
                     'result_case_verdict')
        else:
            _require(case['status'] not in {'pass', 'fail'}, 'result_case_verdict')
    # Outer input failures and report-size refusals can have no complete cohort.
    _require((value['status'] == 'invalid' and isinstance(value.get('reason'), str))
             or (value['cases'] and value['status'] == _aggregate({c['status'] for c in value['cases']})),
             'result_overall_verdict')
    if passing:
        _require(value['status'] == 'pass' and value['cases']
                 and all(c['status'] == 'pass' and c['assertions']
                         and all(a['status'] == 'pass' for a in c['assertions']) for c in value['cases']), 'baseline_requires_passing_run')
        _require(value.get('contract_digest') == digest(value.get('contract')), 'result_contract')
        contract = value.get('contract')
        _fields(contract, {'suite_id', 'dataset', 'adapter', 'grader', 'comparator', 'protocol', 'cases'}, reason='result_contract')
        identity = value.get('identity')
        _fields(identity, {'manifest_sha256', 'recording_sha256', 'runner_sha256', 'experiment'}, reason='result_identity')
        _require(all(_sha(identity[k]) for k in ('manifest_sha256', 'recording_sha256', 'runner_sha256')), 'result_identity')
        # Reuse the manifest contract instead of maintaining a second schema.
        refs = [{'id': c['id'], 'sha256': c['case_sha256'], 'path': 'case.json'} for c in value['cases']]
        _manifest({'schema_version': 1, **contract, 'identities': identity['experiment'], 'cases': refs})
        expected = sorted([{'id': c['id'], 'sha256': c['case_sha256']} for c in value['cases']], key=lambda c: c['id'])
        _require(contract['cases'] == expected, 'result_cohort')
    return value


def _decode_baseline(raw):
    """Read V1 unchanged, or V2/legacy-prefix complete append frames only."""
    try:
        text = raw.decode('utf-8')
        decoder = json.JSONDecoder(object_pairs_hook=_unique, parse_constant=_invalid_constant, parse_float=_finite_float)
        header, end = decoder.raw_decode(text, len(text) - len(text.lstrip()))
        _json_depth(header)
        _fields(header, {'schema_version', 'history'}, reason='baseline_schema')
        _require(type(header['schema_version']) is int and header['schema_version'] in {1, 2}
                 and isinstance(header['history'], list), 'baseline_schema')
        if header['schema_version'] == 2:
            _require(not header['history'], 'baseline_schema')
        tail = text[end:]
        frames = [line for line in tail.split('\n') if line.strip()]
        if frames:
            _require(tail.lstrip(' \t\r').startswith('\n') and raw.endswith(b'\n'), 'baseline_incomplete_append')
        _require(header['schema_version'] == 1 or frames, 'baseline_incomplete_append')
        _require(len(frames) % 2 == 0, 'baseline_incomplete_append')
        _require(len(header['history']) + len(frames) // 2 <= MAX_HISTORY, 'baseline_history_limit')
        history = list(header['history'])
        for offset in range(0, len(frames), 2):
            entry, commit = [json.loads(line, object_pairs_hook=_unique, parse_constant=_invalid_constant,
                                        parse_float=_finite_float) for line in frames[offset:offset + 2]]
            _json_depth(entry)
            _fields(commit, {'schema_version', 'commit'}, reason='baseline_commit_mismatch')
            _require(type(commit['schema_version']) is int and commit['schema_version'] == 2
                     and isinstance(entry, dict) and _sha(entry.get('acceptance_digest'))
                     and commit['commit'] == entry['acceptance_digest'], 'baseline_commit_mismatch')
            history.append(entry)
        value = {'schema_version': 1, 'history': history}
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, EvalError):
            raise
        raise EvalError('baseline_incomplete_append' if not raw.endswith(b'\n') else 'baseline_schema') from exc
    _fields(value, {'schema_version', 'history'}, reason='baseline_schema')
    _require(type(value['schema_version']) is int and value['schema_version'] == 1 and isinstance(value['history'], list) and 1 <= len(value['history']) <= MAX_HISTORY, 'baseline_schema')
    previous = None
    for item in value['history']:
        _fields(item, {'canonical', 'result_digest', 'reason', 'scope', 'accepted_at', 'previous_digest', 'acceptance_digest'}, reason='baseline_schema')
        _report(item, passing=True)
        _require(item['previous_digest'] == previous and item['acceptance_digest'] == digest({k: v for k, v in item.items() if k != 'acceptance_digest'}), 'baseline_history_digest')
        previous = item['acceptance_digest']
    return value



def _baseline_at(directory, name, check):
    raw, _sha, identity = _read_at(directory, name, MAX_BASELINE_BYTES, check, raw_bytes=True)
    value = _decode_baseline(raw)
    check()
    return value, identity


def _baseline(path):
    with _baseline_parent(path) as (directory, name, check):
        with _baseline_lock(directory, exclusive=False):
            value, _identity = _baseline_at(directory, name, check)
    return value


def compare(report: dict, baseline_path: Path) -> dict:
    """Pair the same declared cohort and grader; disclose both exact identities."""
    candidate = _report(report)
    result = {'status': 'incomparable', 'candidate_digest': report['result_digest'], 'pairs': [], 'release_authority': False}
    try:
        stored = _baseline(baseline_path)
    except EvalError as exc:
        return {**result, 'status': 'baseline_missing' if str(exc) == 'input_missing' else 'incomparable', 'reason': str(exc)}
    baseline = stored['history'][-1]
    control = baseline['canonical']
    result.update(baseline_id=baseline['acceptance_digest'], baseline_digest=baseline['result_digest'],
                  sample_size=len(control['cases']), baseline_identity=control['identity'], candidate_identity=candidate.get('identity'))
    if candidate.get('contract_digest') != control['contract_digest'] or candidate.get('contract') != control['contract']:
        return {**result, 'reason': 'cohort_or_grading_contract_changed'}
    variables = control['contract']['protocol']['variables']
    changed = sorted(k for k in IDENTITIES if candidate['identity']['experiment'][k] != control['identity']['experiment'][k])
    result['changed_variables'] = changed
    if set(changed) - set(variables):
        return {**result, 'reason': 'undeclared_identity_change'}
    if candidate['identity']['runner_sha256'] != control['identity']['runner_sha256']:
        return {**result, 'reason': 'runner_implementation_changed'}
    controls = {c['id']: c for c in control['cases']}
    if set(controls) != {c['id'] for c in candidate['cases']}:
        return {**result, 'reason': 'incomplete_cohort'}
    for case in candidate['cases']:
        old = controls[case['id']]
        was_pass = {a['id'] for a in old['assertions'] if a['status'] == 'pass'}
        now_pass = {a['id'] for a in case['assertions'] if a['status'] == 'pass'}
        result['pairs'].append({'id': case['id'], 'baseline': old['status'], 'candidate': case['status'],
                                'regressed_assertions': sorted(was_pass - now_pass)})
    status = candidate['status']
    result.update(status='pass' if status == 'pass' else 'regression' if status == 'fail' else 'inconclusive',
                  reason='paired_deterministic_verdicts')
    return result


def _append_baseline(directory, name, check, previous_raw, previous_identity, entry):
    """Append only to the admitted object; never replace, truncate or unlink a leaf."""
    prefix = previous_raw if previous_identity is not None else _bytes({'schema_version': 2, 'history': []})
    appended = (b'' if prefix.endswith(b'\n') else b'\n') + _bytes(entry) + b'\n'
    commit = _bytes({'schema_version': 2, 'commit': entry['acceptance_digest']}) + b'\n'
    expected = prefix + appended + commit
    _require(len(expected) <= MAX_BASELINE_BYTES, 'baseline_history_limit')
    flags = os.O_RDWR | os.O_APPEND | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC
    if previous_identity is None:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = fsx.open_at(directory, name, flags, 0o600)
    try:
        before = os.fstat(descriptor)
        inode = _inode(before)
        if previous_identity is not None:
            _require(_file_identity(before) == previous_identity, 'baseline_file_replaced')
        def custody():
            check()
            info = os.fstat(descriptor)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                     and stat.S_IMODE(info.st_mode) in {0o600, 0o644}
                     and _inode(info) == inode and _inode(fsx.lstat_at(directory, name)) == inode,
                     'baseline_file_replaced')
        def write_all(raw):
            pending = memoryview(raw)
            while pending:
                custody()
                count = os.write(descriptor, pending)
                _require(type(count) is int and 0 < count <= len(pending), 'baseline_write_unavailable')
                pending = pending[count:]
        write_all(appended if previous_identity is not None else prefix + appended)
        os.fsync(descriptor)  # No commit marker is issued before the prepared entry is durable.
        custody()
        write_all(commit)
        os.fsync(descriptor)
        os.fsync(directory)
        custody()
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks, total = [], 0
        while True:
            custody()
            chunk = os.read(descriptor, min(65536, MAX_BASELINE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            _require(total <= MAX_BASELINE_BYTES, 'baseline_file_replaced')
            chunks.append(chunk)
        custody()
        _require(b''.join(chunks) == expected, 'baseline_file_replaced')
    finally:
        os.close(descriptor)



def accept_baseline(path: Path, report: dict, *, reason: str, scope: str) -> dict:
    """Local acceptance with lock-mediated append visibility, not atomic leaf-CAS."""
    canonical = _report(report, passing=True)
    _require(all(isinstance(v, str) and 1 <= len(v) <= 512 and '\0' not in v for v in (reason, scope)), 'acceptance_reason_and_scope_required')
    with _baseline_parent(path) as (directory, name, check):
        with _baseline_lock(directory, exclusive=True):
            check()
            try:
                fsx.lstat_at(directory, name + '.lock')
            except FileNotFoundError:
                pass
            else:
                raise EvalError('baseline_acceptance_busy')  # Never remove a legacy or foreign lock.
            try:
                previous_raw, _sha, previous_identity = _read_at(directory, name, MAX_BASELINE_BYTES, check, raw_bytes=True)
                stored = _decode_baseline(previous_raw)
            except EvalError as exc:
                if str(exc) != 'input_missing':
                    raise
                stored, previous_identity = {'schema_version': 1, 'history': []}, None
                previous_raw = b''
            _require(len(stored['history']) < MAX_HISTORY, 'baseline_history_limit')
            previous = stored['history'][-1]['acceptance_digest'] if stored['history'] else None
            entry = {'canonical': canonical, 'result_digest': report['result_digest'], 'reason': reason, 'scope': scope,
                     'accepted_at': datetime.now(timezone.utc).isoformat(), 'previous_digest': previous}
            entry['acceptance_digest'] = digest(entry)
            try:
                _append_baseline(directory, name, check, previous_raw, previous_identity, entry)
            except FileExistsError as exc:
                raise EvalError('baseline_file_replaced') from exc
            except OSError as exc:
                raise EvalError('baseline_write_unavailable') from exc
            check()
            return {'status': 'accepted', 'baseline_id': entry['acceptance_digest'], 'result_digest': report['result_digest'],
                    'previous_digest': previous, 'release_authority': False}


def render_text(report: dict) -> str:
    report = _bounded_report(report)
    value = report['canonical']
    lines = [f"{value['status'].upper()} offline recorded replay {report['result_digest']}"]
    for case in value['cases']:
        lines.append(f"{case['status'].upper()} {case['id']}: {case['reason']}")
        lines.extend(f"  {a['status'].upper()} {a['id']}: {a['reason']}" for a in case['assertions'])
    if 'reason' in value:
        lines.append(value['reason'])
    if 'comparison' in report:
        lines.append(f"BASELINE {report['comparison']['status']}")
    telemetry = report['telemetry']
    lines.append(f"Coverage: latency {telemetry['latency_observed']}/{telemetry['case_count']}; usage {telemetry['usage_observed']}/{telemetry['case_count']}")
    lines.append('Recorded outputs only. No model qualification or release authority. See issues #152 and #200.')
    return '\n'.join(lines)


def required_suites(root: Path, mode: str) -> list[dict]:
    """Optional suite checks for the existing verifier; no config means no work."""
    path = root / CONFIG
    if not path.exists() and not path.is_symlink():
        return []
    try:
        config, _ = _read(root, CONFIG)
        _fields(config, {'schema_version', 'suites'}, reason='suite_config_schema')
        _require(type(config['schema_version']) is int and config['schema_version'] == 1
                 and isinstance(config['suites'], list) and 1 <= len(config['suites']) <= 16, 'suite_config_schema')
        checks = []
        seen = set()
        for suite in config['suites']:
            _fields(suite, {'id', 'manifest', 'outputs', 'baseline', 'modes'}, reason='suite_config_schema')
            _require(_label(suite['id']) and suite['id'] not in seen, 'suite_config_id')
            seen.add(suite['id'])
            for key in ('manifest', 'outputs', 'baseline'):
                _parts(suite[key])
            _require(isinstance(suite['modes'], list) and suite['modes'] and all(
                isinstance(m, str) and m in {'fast', 'pr', 'release'} for m in suite['modes']), 'suite_config_modes')
            if mode not in suite['modes']:
                continue
            report = replay(root, suite['manifest'], suite['outputs'])
            report = attach_comparison(report, root / suite['baseline'])
            checks.append({'name': 'agent-eval:' + suite['id'], 'status': 'pass' if report['canonical']['status'] == 'pass'
                           and report['comparison']['status'] == 'pass' else 'fail',
                           'summary': 'offline replay ' + report['canonical']['status'] + '; baseline ' + report['comparison']['status'],
                           'details': [{'result_digest': report['result_digest'], 'canonical': report['canonical'],
                                        'comparison': report['comparison'], 'telemetry': report['telemetry']}]})
        return checks
    except EvalError as exc:
        return [{'name': 'agent-eval:configuration', 'status': 'fail', 'summary': str(exc), 'details': []}]
