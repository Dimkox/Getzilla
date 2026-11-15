"""Pure bounded pytest failure excerpts."""
from __future__ import annotations

import json
import re

from .process_limits import OUTPUT_LIMIT


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
