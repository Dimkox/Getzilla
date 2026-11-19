"""Shared diagnostic bounds. Output is never review, CI or full-report evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .package_status import read_package_file

PREVIEW_BYTES = 4096
RESPONSE_BYTES = 32768
MAX_ARTIFACT_BYTES = 65536
MAX_HISTORICAL_CHARS = 4 * 1024 * 1024
MAX_JOBS = 256
_CREDENTIAL = re.compile(r'(?i)(?:password|secret|token|api[_-]?key)\s*[:=]|PRIVATE KEY|AKIA[0-9A-Z]{16}')
_ARTIFACT = re.compile(r'\.getzilla/runtime/par/[A-Za-z0-9_-]{1,128}/[0-9]{3}\.log')
_COUNTERS = ('observed_bytes', 'retained_bytes', 'dropped_bytes')
_FIELDS = frozenset({'schema_version', 'status', 'preview', *_COUNTERS, 'counters_known', 'truncated',
                     'preview_truncated', 'complete_output', 'artifact_available', 'artifact', 'omitted_jobs',
                     'unavailable_reason', 'evidence_authority'})
_LEGACY = frozenset({'stdout', 'stderr', 'jobs', 'preview', *_COUNTERS, 'truncated', 'preview_truncated',
                     'complete_output', 'artifact', 'log', 'log_error', 'index', 'exit', 'seconds'})


def utf8_tail(data: bytes, limit: int) -> str:
    return data[-limit:].decode('utf-8', 'ignore') if limit else ''


def credential_preview(data: bytes) -> str:
    text = utf8_tail(data, PREVIEW_BYTES)
    return '[preview withheld: possible credential]' if _CREDENTIAL.search(text) else text


def _base(status='unavailable', reason='output_not_recorded'):
    return {'schema_version': 1, 'status': status, 'preview': '', 'observed_bytes': None,
            'retained_bytes': None, 'dropped_bytes': None, 'counters_known': False, 'truncated': status == 'invalid',
            'preview_truncated': False, 'complete_output': False, 'artifact_available': False,
            'artifact': None, 'omitted_jobs': 0, 'unavailable_reason': reason, 'evidence_authority': False}


def _reference(value):
    if value is None:
        return None
    if (not isinstance(value, dict) or set(value) != {'path', 'sha256', 'size', 'device', 'inode', 'mtime_ns'}
            or not isinstance(value['path'], str) or not _ARTIFACT.fullmatch(value['path'])
            or not isinstance(value['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', value['sha256'])
            or any(type(value[key]) is not int or value[key] < 0 for key in ('size', 'device', 'inode', 'mtime_ns'))
            or value['size'] > MAX_ARTIFACT_BYTES):
        raise ValueError('invalid artifact')
    return dict(value)


def _counters(value):
    supplied = [key in value for key in _COUNTERS]
    if not any(supplied):
        return None
    if not all(supplied):
        raise ValueError('partial counters')
    values = [value[key] for key in _COUNTERS]
    if value.get('counters_known') is False and values == [None, None, None]:
        return None
    if (any(type(item) is not int or not 0 <= item <= 2**63 - 1 for item in values)
            or values[0] != values[1] + values[2]):
        raise ValueError('invalid counters')
    return values


def normalize_output(value: object) -> dict:
    """Normalize before context/serialization; never resolve historical log strings."""
    if value is None:
        return _base()
    try:
        if not isinstance(value, dict):
            raise ValueError('invalid output')
        modern = 'schema_version' in value
        if modern:
            if (type(value['schema_version']) is not int or value['schema_version'] != 1
                    or set(value) != _FIELDS or value['status'] not in {'available', 'unavailable', 'invalid'}):
                raise ValueError('unknown output schema')
            if value['status'] != 'available':
                return _base(value['status'], 'invalid_output' if value['status'] == 'invalid' else 'output_not_recorded')
            counts = _counters(value)
            reference = _reference(value['artifact'])
            text = value['preview']
            if (not isinstance(text, str) or len(text) > MAX_HISTORICAL_CHARS
                    or any(0xD800 <= ord(character) <= 0xDFFF for character in text)
                    or any(type(value[key]) is not bool for key in ('counters_known', 'truncated',
                           'preview_truncated', 'complete_output', 'artifact_available', 'evidence_authority'))
                    or type(value['omitted_jobs']) is not int or not 0 <= value['omitted_jobs'] <= 2**63 - 1
                    or value['counters_known'] != (counts is not None)):
                raise ValueError('invalid normalized output')
            if value['complete_output'] and (counts is None or counts[1] != len(text.encode())
                                             or counts[2] or value['preview_truncated'] or value['truncated']):
                raise ValueError('contradictory normalized completeness')
            result = dict(value, artifact=reference, artifact_available=False, evidence_authority=False)
            raw = text.encode()
            result['preview'] = credential_preview(raw)
            if len(raw) > PREVIEW_BYTES:
                result.update(preview_truncated=True, truncated=True, complete_output=False)
            if counts is None or result['truncated'] or counts[2] or result['preview'] != text:
                result['complete_output'] = False
            if result['unavailable_reason'] not in {None, 'artifact_unavailable'}:
                raise ValueError('invalid reason')
            return result
        elif set(value) - _LEGACY or not value:
            raise ValueError('unknown historical fields')
        artifact = _reference(value.get('artifact'))
        jobs = value.get('jobs')
        if jobs is not None and (not isinstance(jobs, list) or any(not isinstance(job, dict) for job in jobs[:MAX_JOBS])):
            raise ValueError('invalid jobs')
        inputs = jobs[:MAX_JOBS] if jobs is not None else [value]
        omitted = max(0, len(jobs) - MAX_JOBS) if jobs is not None else 0
        tail = b''
        raw_bytes = 0
        withheld = False
        known = True
        totals = [0, 0, 0]
        truncated = omitted > 0
        for item in inputs:
            if set(item) - (_FIELDS if modern else _LEGACY):
                raise ValueError('unknown job fields')
            counts = _counters(item)
            known &= counts is not None
            if counts is not None:
                totals = [left + right for left, right in zip(totals, counts)]
                if any(total > 2**63 - 1 for total in totals):
                    raise ValueError('invalid counters')
            for flag in ('truncated', 'preview_truncated', 'complete_output'):
                if flag in item and type(item[flag]) is not bool:
                    raise ValueError('invalid flag')
            if counts is not None and item.get('complete_output') is True and (counts[2] or item.get('truncated')):
                raise ValueError('contradictory completeness')
            truncated |= bool(item.get('truncated') or item.get('preview_truncated'))
            texts = [item[key] for key in ('stdout', 'stderr') if key in item]
            if not texts:
                texts = [item.get('preview', '')]
            for text in texts:
                if (not isinstance(text, str) or len(text) > MAX_HISTORICAL_CHARS
                        or any(0xD800 <= ord(character) <= 0xDFFF for character in text)):
                    raise ValueError('invalid text')
                encoded = text.encode('utf-8')
                raw_bytes += len(encoded)
                withheld |= bool(_CREDENTIAL.search(text))
                tail = (tail + encoded[-PREVIEW_BYTES:])[-PREVIEW_BYTES:]
        known &= omitted == 0
        preview_truncated = raw_bytes > PREVIEW_BYTES or truncated or known and totals[1] > raw_bytes
        text = credential_preview(tail)
        if withheld:
            text = '[preview withheld: possible credential]'
        elif preview_truncated:
            marker = '[preview truncated]\n'
            text = marker + utf8_tail(tail, PREVIEW_BYTES - len(marker.encode()))
        result = _base('available', None)
        result.update(preview=text, truncated=bool(truncated or preview_truncated or known and totals[2]),
                      preview_truncated=preview_truncated, artifact=artifact, omitted_jobs=omitted,
                      counters_known=known)
        if known:
            result.update(zip(_COUNTERS, totals))
        result['complete_output'] = bool(known and not result['truncated'] and not withheld
                                         and not value.get('log_error') and totals[1] == raw_bytes)
        if len(json.dumps(result, ensure_ascii=False).encode()) > RESPONSE_BYTES:
            raise ValueError('envelope too large')
        return result
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError):
        result = _base('invalid', 'invalid_output')
        result['truncated'] = True
        return result


def capture_artifact(root: Path, relative: str):
    from .execution import ExecutionError
    if not isinstance(relative, str) or not _ARTIFACT.fullmatch(relative):
        raise ExecutionError('output_unavailable')
    try:
        raw = read_package_file(root, relative, limit=MAX_ARTIFACT_BYTES, single_link=True)
        info = (root / relative).lstat()
        return {'path': relative, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
                'device': info.st_dev, 'inode': info.st_ino, 'mtime_ns': info.st_mtime_ns}
    except (OSError, ValueError) as error:
        raise ExecutionError('output_unavailable') from error


def read_output(root: Path, caller, execution_id: str, max_bytes: int = PREVIEW_BYTES):
    from .execution import ExecutionError, _authorize, _caller, _find
    from .execution_store import load_registry
    if type(max_bytes) is not int or not 1 <= max_bytes <= PREVIEW_BYTES:
        raise ExecutionError('invalid_output_limit')
    _caller(root, caller)
    record = _find(load_registry(root), execution_id)
    _authorize(root, caller, record)
    result = normalize_output(None if record['expired'] else record['output'])
    reference = result['artifact']
    if reference is not None:
        try:
            observed = capture_artifact(root, reference['path'])
            if observed != reference:
                raise ExecutionError('output_unavailable')
            raw = read_package_file(root, reference['path'], limit=MAX_ARTIFACT_BYTES, single_link=True)
            # Recheck the captured namespace after the second bounded read too.
            if capture_artifact(root, reference['path']) != reference:
                raise ExecutionError('output_unavailable')
            result = normalize_output({'stdout': raw.decode('utf-8', 'strict'), 'observed_bytes': len(raw),
                                       'retained_bytes': len(raw), 'dropped_bytes': 0})
            result['artifact_available'] = True
        except (OSError, ValueError, UnicodeError):
            result['status'] = 'unavailable'
            result['artifact_available'] = False
            result['complete_output'] = False
            result['unavailable_reason'] = 'artifact_unavailable'
    preview = result['preview'].encode()
    result['preview'] = utf8_tail(preview, max_bytes)
    if len(preview) > max_bytes:
        result.update(preview_truncated=True, truncated=True, complete_output=False)
    return result
