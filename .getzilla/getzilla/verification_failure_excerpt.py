"""Pure bounded pytest failure excerpts."""
from __future__ import annotations

import hashlib
import json
import re

from .process_limits import OUTPUT_LIMIT


def policy_diagnostic(allowed, reason):
    """Closed assertion context only; never retain the command or refusal value."""
    decision = 'allow' if allowed is True else 'deny' if allowed is False else 'unavailable'
    category = 'other'
    if type(reason) is str and len(reason) <= 4096:
        for code, prefixes in (
            ('budget', ('Policy resource budget exhausted:',)),
            ('grant', ('No active approval', 'Missing approval', 'Approval', 'Direct external write requires')),
            ('secret', ('Blocked secret', 'Secret read', 'Blocked a secret')),
            ('degraded', ('Getzilla policy did not load,',)),
        ):
            if reason.startswith(prefixes):
                category = code
                break
        if reason.startswith('Sensitive action ') and ': root resolution status is ' in reason:
            category = 'root'
    return 'GETZILLA_POLICY_DIAGNOSTIC decision=' + decision + ' reason=' + category


def valid_policy_diagnostic(value):
    return (type(value) is dict and set(value) == {'decision', 'reason'}
            and type(value['decision']) is str and value['decision'] in {'allow', 'deny', 'unavailable'}
            and type(value['reason']) is str and value['reason'] in {'budget', 'grant', 'secret', 'root', 'degraded', 'other'})


def policy_exception_diagnostic(error):
    """Observe one real builtin assertion value, never a report's captured sections."""
    if (type(error) is not AssertionError or len(error.args) != 1
            or type(error.args[0]) is not str or len(error.args[0]) > 4096):
        return None
    match = re.fullmatch(
        r'(?:(?:False != True|True != False|False is not true|True is not false) : )?'
        r'GETZILLA_POLICY_DIAGNOSTIC decision=(allow|deny|unavailable) '
        r'reason=(budget|grant|secret|root|degraded|other)', error.args[0])
    return dict(zip(('decision', 'reason'), match.groups())) if match else None


MAX_FACTORY_DIAGNOSTIC_BYTES = 768
_FACTORY_MARKER = 'GETZILLA_FACTORY_DIAGNOSTIC '
_FACTORY_COUNTS = ('collected', 'executed', 'skipped', 'required', 'failures',
                   'errors', 'loader_errors', 'unqualified_skips', 'missing_required')
_FACTORY_REASONS = {'none', 'report-unavailable', 'source-unstable', 'required-missing',
                    'unqualified-skip', 'loader-error', 'test-problems', 'tests-failed', 'unit-failed'}
_FACTORY_PHASES = {'case', 'setUpClass', 'tearDownClass', 'setUpModule', 'tearDownModule',
                   'unqualified_fixture', 'other'}
_FACTORY_KINDS = {'failure', 'error', 'expected_failure', 'unexpected_success', 'other'}
_FACTORY_ERRORS = {'AssertionError', 'RuntimeError', 'OSError', 'ValueError', 'TypeError',
                   'KeyError', 'ImportError', 'AttributeError', 'PermissionError',
                   'FileNotFoundError', 'TimeoutError', 'NotADirectoryError', 'IsADirectoryError', 'other'}


def _factory_count(value):
    if type(value) is list:
        value = len(value)
    return value if type(value) is int and 0 <= value <= 10000 else None


def _factory_digest(value):
    return value if type(value) is str and re.fullmatch('[0-9a-f]{64}', value) else None


def _factory_json(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True, ensure_ascii=True)


def _factory_keys(value, names):
    return (type(value) is dict and len(value) == len(names)
            and all(type(key) is str for key in value) and set(value) == set(names))


def factory_diagnostic(evidence, *, outcome=None, digests=None):
    """Pure observation: no source reads, private values, identity or PASS authority.

    Factory schema3 and the existing compact installed-child summary use the
    same closed projection. Arbitrary problem IDs are SHA256 only; the already
    retained declared/collected inventory can correlate them independently.
    """
    source = (evidence if type(evidence) is dict and len(evidence) <= 64
              and all(type(key) is str for key in evidence) else {})
    status = outcome if type(outcome) is str and outcome in {'pass', 'fail', 'skip'} else source.get('status')
    status = status if type(status) is str and status in {'pass', 'fail', 'skip'} else 'unavailable'
    counts = {key: _factory_count(source.get(key)) for key in _FACTORY_COUNTS}
    counts['skipped'] = _factory_count(source.get('skipped', source.get('qualified_skips')))
    counts['required'] = _factory_count(source.get('required', source.get('required_ids')))
    supplied = (digests if type(digests) is dict and len(digests) <= 2
                and all(type(key) is str for key in digests) else {})
    hashes = {key: _factory_digest(supplied.get(key, source.get(key + '_digest')))
              for key in ('collected_ids', 'source_inventory')}
    raw = source.get('problems')
    total = len(raw) if type(raw) is list and len(raw) <= 10000 else None
    problems = []
    omitted_fields = max(0, len(source) - sum(key in source for key in (
        *_FACTORY_COUNTS, 'qualified_skips', 'required_ids', 'status', 'problems',
        'source_stable', 'collected_ids_digest', 'source_inventory_digest')))
    if (total and type(raw[0]) is dict and len(raw[0]) <= 16
            and all(type(key) is str for key in raw[0])):
        first = raw[0]
        identifier = first.get('id')
        try:
            identity_hash = (hashlib.sha256(identifier.encode('utf-8')).hexdigest()
                             if type(identifier) is str and len(identifier) <= 2048 else None)
        except UnicodeError:
            identity_hash = None
        def code(name, allowed):
            value = first.get(name)
            return value if type(value) is str and value in allowed else 'other'
        problems.append({'id_sha256': identity_hash, 'phase': code('phase', _FACTORY_PHASES),
                         'kind': code('kind', _FACTORY_KINDS), 'exception': code('exception', _FACTORY_ERRORS),
                         'frames_omitted': (_factory_count(first.get('frames'))
                                            if type(first.get('frames')) is list and len(first['frames']) <= 32 else None)})
        omitted_fields += max(0, len(first) - sum(key in first for key in ('id', 'phase', 'kind', 'exception', 'frames')))
    if not source or total is None:
        reason = 'report-unavailable'
    elif source.get('source_stable') is False:
        reason = 'source-unstable'
    elif counts['missing_required']:
        reason = 'required-missing'
    elif counts['unqualified_skips']:
        reason = 'unqualified-skip'
    elif counts['loader_errors']:
        reason = 'loader-error'
    elif total:
        reason = 'test-problems'
    elif counts['failures'] or counts['errors']:
        reason = 'tests-failed'
    else:
        reason = 'none' if status == 'pass' else 'unit-failed'
    value = {'kind': 'factory', 'version': 1, 'status': status, 'reason': reason,
             'counts': counts, 'digests': hashes, 'problems': problems,
             'omitted': {'problems': total - len(problems) if total is not None else None,
                         'fields': omitted_fields}}
    if len(_factory_json(value).encode()) > MAX_FACTORY_DIAGNOSTIC_BYTES:
        value['problems'] = []
        value['omitted']['problems'] = total
    return value


def valid_factory_diagnostic(value):
    """Closed validation at both private progress readers; never qualify evidence."""
    if (not _factory_keys(value, {'kind', 'version', 'status', 'reason', 'counts', 'digests', 'problems', 'omitted'})
            or type(value['kind']) is not str or value['kind'] != 'factory'
            or type(value['version']) is not int or value['version'] != 1
            or type(value['status']) is not str or value['status'] not in {'pass', 'fail', 'skip', 'unavailable'}
            or type(value['reason']) is not str or value['reason'] not in _FACTORY_REASONS
            or not _factory_keys(value['counts'], _FACTORY_COUNTS)
            or not _factory_keys(value['digests'], {'collected_ids', 'source_inventory'})
            or not _factory_keys(value['omitted'], {'problems', 'fields'})
            or type(value['problems']) is not list or len(value['problems']) > 1):
        return False
    if any(item is not None and (type(item) is not int or not 0 <= item <= 10000)
           for item in (*value['counts'].values(), *value['omitted'].values())):
        return False
    if any(item is not None and _factory_digest(item) is None for item in value['digests'].values()):
        return False
    for problem in value['problems']:
        if (not _factory_keys(problem, {'id_sha256', 'phase', 'kind', 'exception', 'frames_omitted'})
                or problem['id_sha256'] is not None and _factory_digest(problem['id_sha256']) is None
                or type(problem['phase']) is not str or problem['phase'] not in _FACTORY_PHASES
                or type(problem['kind']) is not str or problem['kind'] not in _FACTORY_KINDS
                or type(problem['exception']) is not str or problem['exception'] not in _FACTORY_ERRORS
                or problem['frames_omitted'] is not None and (type(problem['frames_omitted']) is not int
                                                            or not 0 <= problem['frames_omitted'] <= 32)):
            return False
    return len(_factory_json(value).encode()) <= MAX_FACTORY_DIAGNOSTIC_BYTES


def factory_assertion_message(evidence):
    """Safe msg for a scoped unittest longMessage=False status assertion."""
    value = evidence.get('factory_diagnostic') if type(evidence) is dict else None
    if not valid_factory_diagnostic(value):
        value = factory_diagnostic(evidence)
    return _FACTORY_MARKER + _factory_json(value)


def factory_exception_diagnostic(error):
    """Accept only one real builtin assertion value, never captured output."""
    if (type(error) is not AssertionError or len(error.args) != 1 or type(error.args[0]) is not str
            or len(error.args[0]) > 4096 or not error.args[0].startswith(_FACTORY_MARKER)):
        return None
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate diagnostic field')
            value[key] = item
        return value
    try:
        raw = error.args[0][len(_FACTORY_MARKER):]
        value = json.loads(raw, object_pairs_hook=pairs)
        return value if valid_factory_diagnostic(value) and _factory_json(value) == raw else None
    except (ValueError, TypeError, RecursionError):
        return None


def _pytest_summary_identity(line: str, trusted: dict[str, tuple[int, set[str]]]) -> tuple[str, str, str] | None:
    """Descriptions are arbitrary data; return only an unambiguous source-bound node."""
    if len(line) > 1024:
        return None
    node_pattern = r'(tests/[A-Za-z0-9_./-]+\.py(?:::[A-Za-z_][A-Za-z0-9_]*)*)(?=\[|\s|$)'
    if line.startswith('SUBFAILED'):
        if not re.match(r'^SUBFAILED[\[(]', line):
            return None
        candidates = list(re.finditer(r'(?:^|\s)' + node_pattern, line))
        if len(candidates) != 1:
            return None
        # Consume only balanced description groups. A sole node-looking value
        # inside a malformed description must not become a reported identity.
        rest = line[len('SUBFAILED'):]
        while rest.startswith(('[', '(')):
            stack: list[str] = []
            for index, character in enumerate(rest):
                if character in '[(':
                    stack.append(character)
                    if len(stack) > 8:
                        return None
                elif character in '])':
                    if not stack or stack.pop() != {']': '[', ')': '('}[character]:
                        return None
                    if not stack:
                        rest = rest[index + 1:].lstrip(' ')
                        break
            else:
                return None
        match = re.fullmatch(node_pattern + r'(?:\[[^\n]*\])?(?: - .*)?', rest)
        if not match:
            return None
        kind, node = 'SUBFAILED', match.group(1)
    else:
        match = re.match(r'^(FAILED|ERROR)\s+' + node_pattern, line)
        if not match:
            return None
        kind, node = match.groups()
    path, *names = node.split('::')
    if (len(path) > 512 or any(part in {'', '.', '..'} for part in path.split('/'))
            or path not in trusted or any(len(name) > 128 for name in names)):
        return None
    name = '::'.join(names)
    return kind, path, name if name in trusted[path][1] else ''


def _pytest_terminal_counts(line: str) -> dict[str, int | None] | None:
    """Backend-reported counts only, never unique methods/subcases or qualification."""
    if len(line) > 1024:
        return None
    line = line.strip()
    if line.startswith('=') or line.endswith('='):
        if not re.fullmatch(r'={3,} .+ ={3,}', line):
            return None
        line = line.strip('=').strip()
    label = r'(?:failed|passed|errors?|skipped|warnings?|xfailed|xpassed|deselected|subtests (?:passed|failed|skipped))'
    item = r'[0-9]{1,9} ' + label
    match = re.fullmatch(r'(' + item + r'(?:, ' + item + r')*) in [0-9]{1,8}(?:\.[0-9]{1,6})?s'
                         r'(?: \([0-9]{1,3}:[0-9]{2}(?::[0-9]{2})?\))?', line)
    if not match:
        return None
    result: dict[str, int | None] = dict.fromkeys(('failed', 'passed', 'errors', 'skipped'))
    seen = set()
    for statistic in match.group(1).split(', '):
        number, name = statistic.split(' ', 1)
        name = 'errors' if name == 'error' else name
        if name in seen:
            return None
        seen.add(name)
        if name in result:
            result[name] = int(number)
    return result


def _core_output_excerpt(output: str, *, failed: bool,
                         trusted: dict[str, tuple[int, set[str]]] | None = None,
                         pytest_output: bool = False) -> str:
    """Keep bounded reported pytest metadata, not values or execution authority."""
    oversized = len(output) > OUTPUT_LIMIT
    normalized = re.sub(r'\x1b\[[0-9;]*m', '', output[:OUTPUT_LIMIT]) if failed else output
    if not failed or (not pytest_output and not re.search(
            r'(?m)^={3,}\s*(?:FAILURES|ERRORS)\s*={3,}\s*$', normalized)):
        return output[-12000:]
    trusted = trusted or {}
    locations: list[str] = []
    summaries: list[str] = []
    identities: list[str] = []
    count_candidates: list[tuple[int, dict[str, int | None]]] = []
    omitted = oversized
    captured = False
    summary_section = False
    safe_errors = {'AssertionError', 'TimeoutError', 'RuntimeError', 'ValueError', 'TypeError',
                   'KeyError', 'ImportError', 'AttributeError', 'PermissionError', 'FileNotFoundError'}
    lines = normalized.split('\n')
    last_line = max((index for index, line in enumerate(lines) if line.strip()), default=-1)
    for index, raw_line in enumerate(lines):
        line = raw_line.rstrip('\r').replace('\\', '/')
        if len(line) > 1024 or any(ord(character) < 32 for character in line):
            omitted = True
            continue
        if re.match(r'^-{3,}\s*Captured\b', line):
            captured = True
            continue
        if re.match(r'^={3,}\s*short test summary info\s*={3,}', line):
            captured = False
            summary_section = True
            continue
        if captured:
            omitted = True
            continue
        counts = _pytest_terminal_counts(line)
        if counts is not None:
            count_candidates.append((index, counts))
            if len(count_candidates) > 2:
                count_candidates = count_candidates[:2]
        location = re.match(r'^(tests/[A-Za-z0-9_./-]+\.py):([0-9]+)(?::\s*([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Failure)))?', line)
        node = _pytest_summary_identity(line, trusted)
        if location and not summary_section:
            path, number, error = location.groups()
            if (path not in trusted or any(part in {'', '.', '..'} for part in path.split('/'))
                    or len(number) > 9 or not 1 <= int(number) <= trusted[path][0]):
                continue
            if len(locations) < 100:
                locations.append(path + ':' + number + (': ' + error if error in safe_errors else ''))
            else:
                omitted = True
        elif node:
            kind, path, name = node
            if len(summaries) < 20:
                summaries.append(kind + ' ' + path + ('::' + name if name else ''))
            else:
                omitted = True
            identity = path + '::' + name if name else ''
            if identity and identity not in identities:
                if len(identities) < 20 and len(json.dumps(identities + [identity])) <= 2400:
                    identities.append(identity)
                else:
                    omitted = True
    trace = '\n'.join(locations)
    summary = '\n'.join(summaries)
    if len(trace) > 5500 or len(summary) > 2500:
        omitted = True
    reported_counts = (count_candidates[0][1] if not oversized and len(count_candidates) == 1
                       and count_candidates[0][0] == last_line else
                       dict.fromkeys(('failed', 'passed', 'errors', 'skipped')))
    parts = ['[sanitized pytest failure locations; values and captured output omitted]',
             trace[:5500], summary[:2500],
             'pytest_failure_ids=' + json.dumps(identities or None),
             'pytest_reported_terminal_counts=' + json.dumps(reported_counts, sort_keys=True)]
    if omitted:
        parts.append('[additional failure locations omitted]')
    return '\n'.join(part for part in parts if part)
