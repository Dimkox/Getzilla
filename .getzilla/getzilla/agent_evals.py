"""Bounded offline replay evidence. This module grants no release or model authority."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import time
import uuid

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
    loader = globals().get('__loader__')
    _require(callable(getattr(loader, 'get_data', None)), 'runner_source_unavailable')
    return hashlib.sha256(loader.get_data(__file__)).hexdigest()


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
        fd = fsx.open_at(directory, parts[-1], os.O_RDONLY | fsx.O_NONBLOCK | fsx.O_NOFOLLOW | fsx.O_BINARY)
        with os.fdopen(fd, 'rb') as handle:
            before = os.fstat(handle.fileno())
            _require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'input_size_or_type')
            raw = handle.read(limit + 1)
            after = os.fstat(handle.fileno())
            _require(len(raw) <= limit and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                     (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input_changed_or_large')
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_invalid_constant, parse_float=_finite_float)
        _json_depth(value)
        return value, hashlib.sha256(raw).hexdigest()
    except FileNotFoundError as exc:
        raise EvalError('input_missing') from exc
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, EvalError):
            raise
        raise EvalError('input_unreadable_or_invalid_json') from exc
    finally:
        fsx.close_dir(directory)


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
            _require(type(item['latency_ms']) in {int, float} and math.isfinite(item['latency_ms'])
                     and 0 <= item['latency_ms'] <= 86400000, 'latency_schema')
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


def _signal(signal, output):
    exists, value = _lookup(output, signal['path'])
    valid = exists and (isinstance(value, (str, list, dict)) if signal['kind'] == 'length'
                       else type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 1)
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
        _require(type(timeout_seconds) in {int, float} and math.isfinite(timeout_seconds) and 0 <= timeout_seconds <= 60, 'timeout_budget')
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
    except (TypeError, ValueError, RecursionError, OSError):
        canonical.update(status='invalid', reason='invalid_input')
    telemetry['case_count'] = len(canonical['cases'])
    telemetry['seconds'] = round(time.monotonic() - started, 6)
    canonical['counts'] = dict(sorted(Counter(c['status'] for c in canonical['cases']).items()))
    report = {'schema_version': 1, 'canonical': canonical, 'result_digest': digest(canonical),
              'run': {'id': str(uuid.uuid4()), 'timestamp': datetime.now(timezone.utc).isoformat()},
              'telemetry': telemetry, 'qualification': 'recorded-output-only', 'release_authority': False,
              'references': ['https://github.com/Dimkox/Getzilla/issues/152', 'https://github.com/Dimkox/Getzilla/issues/200']}
    if len(_bytes(report)) + 1 > MAX_REPORT_BYTES:
        report['canonical'] = {'schema_version': 1, 'kind': 'offline-recorded-replay', 'status': 'invalid',
                               'reason': 'report_size_limit', 'cases': []}
        report['result_digest'] = digest(report['canonical'])
    return report


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


def _baseline(path):
    value, _ = _read(path.parent, path.name, MAX_BASELINE_BYTES)
    _fields(value, {'schema_version', 'history'}, reason='baseline_schema')
    _require(type(value['schema_version']) is int and value['schema_version'] == 1 and isinstance(value['history'], list) and 1 <= len(value['history']) <= MAX_HISTORY, 'baseline_schema')
    previous = None
    for item in value['history']:
        _fields(item, {'canonical', 'result_digest', 'reason', 'scope', 'accepted_at', 'previous_digest', 'acceptance_digest'}, reason='baseline_schema')
        _report(item, passing=True)
        _require(item['previous_digest'] == previous and item['acceptance_digest'] == digest({k: v for k, v in item.items() if k != 'acceptance_digest'}), 'baseline_history_digest')
        previous = item['acceptance_digest']
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


def accept_baseline(path: Path, report: dict, *, reason: str, scope: str) -> dict:
    """Explicit local acceptance only. Preserve every predecessor; never accept a red run."""
    canonical = _report(report, passing=True)
    _require(all(isinstance(v, str) and 1 <= len(v) <= 512 and '\0' not in v for v in (reason, scope)), 'acceptance_reason_and_scope_required')
    # Baseline parents must already exist and must not contain links.
    _parts(path.name)
    _require(path.parent.is_dir() and not any(p.is_symlink() for p in (path.parent, *path.parent.parents)), 'baseline_parent')
    lock = path.with_name(path.name + '.lock')
    descriptor = None
    temporary = None
    try:
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW, 0o600)
        try:
            stored = _baseline(path)
        except EvalError as exc:
            if str(exc) != 'input_missing':
                raise
            stored = {'schema_version': 1, 'history': []}
        _require(len(stored['history']) < MAX_HISTORY, 'baseline_history_limit')
        previous = stored['history'][-1]['acceptance_digest'] if stored['history'] else None
        entry = {'canonical': canonical, 'result_digest': report['result_digest'], 'reason': reason, 'scope': scope,
                 'accepted_at': datetime.now(timezone.utc).isoformat(), 'previous_digest': previous}
        entry['acceptance_digest'] = digest(entry)
        stored['history'].append(entry)
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.eval-baseline-', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(_bytes(stored) + b'\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        return {'status': 'accepted', 'baseline_id': entry['acceptance_digest'], 'result_digest': report['result_digest'],
                'previous_digest': previous, 'release_authority': False}
    except FileExistsError as exc:
        raise EvalError('baseline_acceptance_busy') from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if descriptor is not None:
            os.close(descriptor)
            lock.unlink(missing_ok=True)


def render_text(report: dict) -> str:
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
            # Resolve the baseline parent safely even though comparison itself uses a Path.
            baseline_parts = _parts(suite['baseline'])
            parent = root
            for part in baseline_parts[:-1]:
                parent = parent / part
                _require(not parent.is_symlink(), 'invalid_path')
            report['comparison'] = compare(report, root / suite['baseline'])
            checks.append({'name': 'agent-eval:' + suite['id'], 'status': 'pass' if report['canonical']['status'] == 'pass'
                           and report['comparison']['status'] == 'pass' else 'fail',
                           'summary': 'offline replay ' + report['canonical']['status'] + '; baseline ' + report['comparison']['status'],
                           'details': [{'result_digest': report['result_digest'], 'canonical': report['canonical'],
                                        'comparison': report['comparison'], 'telemetry': report['telemetry']}]})
        return checks
    except EvalError as exc:
        return [{'name': 'agent-eval:configuration', 'status': 'fail', 'summary': str(exc), 'details': []}]
