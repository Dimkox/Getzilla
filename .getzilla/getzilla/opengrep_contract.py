"""Bounded OpenGrep report/target projection; no filesystem or execution authority."""
from __future__ import annotations

import json
import math
import re
import unicodedata

MAX_REPORT = 2 * 1024 * 1024  # never exceed the existing owned runner's combined output cap
MAX_TARGETS = 100_000
VERSION = '1.30.1'


class OpenGrepError(ValueError):
    """Closed local classification; scanner text is never an authority/error channel."""


def _path(value: object) -> str:
    if (not isinstance(value, str) or not value or len(value) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or any(char in value for char in '\\:')
            or any(part in {'', '.', '..'} for part in value.split('/'))
            or unicodedata.normalize('NFC', value) != value):
        raise OpenGrepError('invalid_target')
    try:
        value.encode('utf-8')
    except UnicodeError:
        raise OpenGrepError('invalid_target') from None
    return value


def targets(paths: object) -> tuple[str, ...]:
    if not isinstance(paths, (list, tuple)) or not 0 < len(paths) <= MAX_TARGETS:
        raise OpenGrepError('invalid_target_roster')
    result = tuple(_path(path) for path in paths)
    if len({path.casefold() for path in result}) != len(result):
        raise OpenGrepError('duplicate_target')
    return tuple(sorted(result))


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise OpenGrepError('invalid_report')
        result[key] = value
    return result


def _constant(_value):
    raise OpenGrepError('invalid_report')


def _float(value):
    result = float(value)
    if not math.isfinite(result):
        raise OpenGrepError('invalid_report')
    return result


def decode_report(raw: str) -> dict:
    try:
        if not isinstance(raw, str) or len(raw.encode('utf-8')) > MAX_REPORT:
            raise OpenGrepError('invalid_report')
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
        if not isinstance(value, dict):
            raise OpenGrepError('invalid_report')
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise OpenGrepError('invalid_report') from None


def validate_report(report: object, expected: object, returncode: int) -> dict:
    required = targets(expected)
    if type(returncode) is not int or returncode not in {0, 1}:
        raise OpenGrepError('scanner_failed')
    if not isinstance(report, dict) or report.get('version') != VERSION:
        raise OpenGrepError('invalid_report')
    errors = report.get('errors')
    if not isinstance(errors, list):
        raise OpenGrepError('invalid_report')
    if errors:
        raise OpenGrepError('analysis_diagnostics')
    findings = report.get('results')
    paths = report.get('paths')
    if not isinstance(findings, list) or not isinstance(paths, dict):
        raise OpenGrepError('invalid_report')
    observed = targets(paths.get('scanned'))
    if observed != required:
        raise OpenGrepError('target_coverage_incomplete')
    if report.get('skipped_rules', []) != [] or paths.get('skipped', []) != []:
        raise OpenGrepError('analysis_incomplete')
    details = []
    for item in findings:
        if not isinstance(item, dict):
            raise OpenGrepError('invalid_finding')
        rule, path, start, extra = (item.get(key) for key in ('check_id', 'path', 'start', 'extra'))
        if (not isinstance(rule, str) or not rule or len(rule) > 4096
                or _path(path) not in required or not isinstance(start, dict)
                or type(start.get('line')) is not int or start['line'] < 1
                or not isinstance(extra, dict) or extra.get('is_ignored', False) is not False
                or not isinstance(extra.get('message', ''), str)
                or not isinstance(extra.get('severity', ''), str)):
            raise OpenGrepError('invalid_finding')
        if len(details) < 200:
            details.append({'rule': rule, 'path': path, 'line': str(start['line']),
                            'severity': extra.get('severity', '')[:64], 'message': extra.get('message', '')[:300]})
    if returncode and not findings:
        raise OpenGrepError('scanner_failed')
    return {'outcome': 'finding' if findings else 'pass', 'findings': details,
            'finding_count': len(findings), 'coverage': {'expected': list(required), 'observed': list(observed)}}


def project_core_report(report: object, source_bindings: dict, rule_metadata: dict, returncode: int) -> dict:
    """Project only the pinned core schema; bindings are live producer inputs, not authority."""
    if not isinstance(report, dict) or report.get('version') != VERSION or not isinstance(report.get('errors'), list):
        raise OpenGrepError('invalid_report')
    if report['errors']:
        raise OpenGrepError('analysis_diagnostics')
    if type(returncode) is not int or returncode != 0:
        raise OpenGrepError('scanner_failed')
    if (set(report) != {'version', 'results', 'errors', 'paths', 'rules_by_engine', 'engine_requested',
                       'interfile_languages_used', 'skipped_rules'}
            or report['engine_requested'] != 'OSS' or report['interfile_languages_used'] != []
            or report['skipped_rules'] != [] or not isinstance(report['results'], list)
            or not isinstance(source_bindings, dict) or not source_bindings or not isinstance(rule_metadata, dict)
            or not rule_metadata or len(rule_metadata) > MAX_TARGETS):
        raise OpenGrepError('unsupported_core_schema')
    logical = targets(list(source_bindings.values()))
    if any(not isinstance(path, str) or not re.fullmatch(r'/proc/self/fd/[0-9]+', path)
           or int(path.rsplit('/', 1)[1]) < 3 for path in source_bindings):
        raise OpenGrepError('invalid_source_binding')
    paths = report['paths']
    if (not isinstance(paths, dict) or set(paths) != {'scanned'} or not isinstance(paths['scanned'], list)
            or not all(isinstance(path, str) for path in paths['scanned'])
            or len(paths['scanned']) != len(source_bindings)
            or len(set(paths['scanned'])) != len(paths['scanned'])
            or set(paths['scanned']) != set(source_bindings)):
        raise OpenGrepError('target_coverage_incomplete')
    rules = report['rules_by_engine']
    if (not isinstance(rules, list) or len(rules) != len(rule_metadata)
            or any(not isinstance(row, list) or len(row) != 2 or not isinstance(row[0], str)
                   or row[1] != 'OSS' for row in rules)
            or len({row[0] for row in rules}) != len(rules)
            or {row[0] for row in rules} != set(rule_metadata)):
        raise OpenGrepError('rule_coverage_incomplete')
    for key, metadata in rule_metadata.items():
        if (not isinstance(key, str) or not key or not isinstance(metadata, dict)
                or set(metadata) != {'id', 'severity', 'message'}
                or any(not isinstance(value, str) or len(value) > 4096 for value in metadata.values())
                or not metadata['id']):
            raise OpenGrepError('invalid_rule_binding')
    findings = []
    for item in report['results']:
        if (not isinstance(item, dict) or set(item) != {'check_id', 'path', 'start', 'end', 'extra'}
                or not isinstance(item['check_id'], str) or item['check_id'] not in rule_metadata
                or not isinstance(item['path'], str) or item['path'] not in source_bindings):
            raise OpenGrepError('invalid_finding')
        for position in (item['start'], item['end']):
            if (not isinstance(position, dict) or set(position) != {'line', 'col', 'offset'}
                    or any(type(position[key]) is not int for key in position)
                    or position['line'] < 1 or position['col'] < 1 or position['offset'] < 0):
                raise OpenGrepError('invalid_finding')
        if (item['end']['offset'] < item['start']['offset']
                or item['end']['line'] < item['start']['line']):
            raise OpenGrepError('invalid_finding')
        extra = item['extra']
        if (not isinstance(extra, dict) or extra.get('engine_kind') != 'OSS'
                or extra.get('is_ignored') is not False
                or not isinstance(extra.get('metavars'), dict)
                or not set(extra) <= {'metavars', 'engine_kind', 'is_ignored', 'message', 'metadata',
                                      'severity', 'fix', 'dataflow_trace', 'validation_state'}):
            raise OpenGrepError('unsupported_core_finding')
        metadata = rule_metadata[item['check_id']]
        findings.append({'check_id': metadata['id'], 'path': source_bindings[item['path']],
                         'start': item['start'], 'extra': {'message': extra.get('message', metadata['message']),
                                                         'severity': extra.get('severity', metadata['severity'])}})
    projected = {'version': VERSION, 'results': findings, 'errors': [],
                 'paths': {'scanned': list(logical)}}
    return validate_report(projected, logical, 0)
