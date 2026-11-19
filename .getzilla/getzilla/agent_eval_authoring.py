"""Bounded offline replay evidence. This module grants no release or model authority."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat

from . import fsx



def _study(value, manifest):
    from .agent_evals import MAX_CASES, _fields, _label, _parts, _require, _sha, digest
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
    from .agent_evals import MAX_CASES, _bounded_number, _fields, _label, _require
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
    from .agent_evals import MAX_CASES, _fields, _label, _parts, _read, _require, _sha
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
    from .agent_evals import EvalError, MAX_REPORT_BYTES, _bounded_report, _bytes, _manifest, _outputs, _read, _require, digest, replay
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


def _append_baseline(directory, name, check, previous_raw, previous_identity, entry):
    """Append only to the admitted object; never replace, truncate or unlink a leaf."""
    from .agent_evals import MAX_BASELINE_BYTES, _bytes, _file_identity, _inode, _require
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
    from .agent_evals import EvalError, MAX_BASELINE_BYTES, MAX_HISTORY, _baseline_lock, _baseline_parent, _decode_baseline, _read_at, _report, _require, digest
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

