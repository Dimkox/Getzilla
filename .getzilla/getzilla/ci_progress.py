"""Advisory early stop for repeated GitHub CI actions without progress (#153).

The guard observes `gh` commands in Bash only, after ordinary policy authorization. It never makes a
network call, never grants authority and stores no raw command, output or session ID. State comes only
from structured JSON output; text output gives no state. Observations of another head or an older
attempt are historical: they never count, never block and never satisfy a resume condition.
"""
from __future__ import annotations

import json
import re
import secrets
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone

from . import session_progress as progress

STATE_NAME = 'session-external.json'
MAX_RUNS, MAX_BLOCKS, MAX_OUTPUT, MAX_ITEMS = 64, 64, 65_536, 100
TTL, POLL_LIMIT, MAX_RECOVERIES = progress.TTL, 3, 16
BACKOFF, RATE_BACKOFF = (30, 120), (60, 300)
STATUSES = frozenset({'queued', 'in_progress', 'waiting', 'requested', 'pending', 'completed'})
CONCLUSIONS = frozenset({'success', 'failure', 'cancelled', 'skipped', 'timed_out', 'action_required', 'neutral',
                         'stale', 'startup_failure'})
FAILED = frozenset({'failure', 'timed_out', 'startup_failure'})
CLASSES = frozenset({'external-pending', 'deterministic', 'transient', 'transient-exhausted', 'poll'})
_RUN_FIELDS = frozenset({'scope', 'repo', 'ident', 'max_attempt', 'head', 'status', 'conclusion', 'updated', 'seen',
                         'failures', 'at'})
_BLOCK_FIELDS = frozenset({'scope', 'cls', 'run', 'need', 'count', 'token', 'next_at', 'at', 'revision', 'retry',
                           'recoveries'})
_ID = re.compile(r'[1-9][0-9]{0,19}')
_SHA = re.compile(r'[0-9a-f]{40}')
_REPO = re.compile(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}')
_ENDPOINT = re.compile(r'repos/(?P<repo>[^/\s]+/[^/\s]+)/actions/runs/(?P<run>[0-9]+)'
                       r'(?:/attempts/(?P<attempt>[0-9]+))?(?P<rest>/jobs|/logs|/rerun|/rerun-failed-jobs|/cancel)?')
_TRANSIENT = re.compile(r'\bHTTP 429\b|\bHTTP 5\d\d\b|secondary rate limit|api rate limit exceeded|econnreset'
                        r'|connection reset|etimedout|i/o timeout|tls handshake timeout|rpc failed'
                        r'|unexpected (?:eof|disconnect)|could not resolve host|no such host'
                        r'|temporary failure in name resolution|(?:connection|operation|request) timed out', re.I)
_RATE = re.compile(r'\bHTTP 429\b|rate limit', re.I)
_DETERMINISTIC = re.compile(r'\bHTTP 4(?!29\b)\d\d\b|resource not accessible by integration'
                            r'|must (?:be authenticated|have admin rights)|\bnot found\b|traceback|assertionerror', re.I)
_RUN_OPTIONS = {'view': ({'--json', '--attempt', '--job', '-j', '-R', '--repo'}, {'--log', '--log-failed', '-v', '--verbose', '--exit-status'}),
                'list': ({'--json', '-L', '--limit', '-b', '--branch', '-c', '--commit', '-w', '--workflow', '-s',
                          '--status', '-e', '--event', '-u', '--user', '-R', '--repo', '--created'}, {'-a', '--all'}),
                'watch': ({'-i', '--interval', '-R', '--repo'}, {'--exit-status', '--compact'}),
                'rerun': ({'-j', '--job', '-R', '--repo'}, {'--failed', '-d', '--debug'}),
                'cancel': ({'-R', '--repo'}, set())}


@dataclass(frozen=True)
class Interaction:
    kind: str           # poll | wait | mutation | log
    target: str         # run | runs | pr
    ident: str | None   # run or pull request number
    op: str | None      # rerun | cancel for mutations
    structured: bool    # JSON output that can form a state token
    repo: str
    attempt: int | None
    key: str            # canonical operation identity


@dataclass(frozen=True)
class RunState:
    ident: str
    attempt: int | None
    head: str | None
    status: str | None
    conclusion: str | None
    updated: int | None
    signature: str | None


def _words(command):
    if not isinstance(command, str) or not command.strip() or len(command) > 20_000 or re.search(r'[\n\r$`;&|<>\\]', command):
        return None
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    return words if words and words[0] == 'gh' else None


def _options(words, values, flags):
    """Operands and options of a known command; an unknown option makes the command unmodelled."""
    operands, found = [], {}
    index = 0
    while index < len(words):
        word = words[index]
        name, _, inline = word.partition('=')
        if word.startswith('-') and name in values:
            if inline:
                found[name] = inline
            elif index + 1 < len(words):
                index += 1
                found[name] = words[index]
            else:
                return None
        elif word.startswith('-') and word in flags:
            found[word] = True
        elif word.startswith('-'):
            return None
        else:
            operands.append(word)
        index += 1
    return operands, found


def _repo(value):
    """An explicit owner/name, or None for any other value (the command then stays unmodelled)."""
    return value if isinstance(value, str) and _REPO.fullmatch(value) else None


def classify(command: str) -> Interaction | None:
    words = _words(command)
    if words is None:
        return None
    rest, repo = words[1:], '.'
    while rest[:1] and rest[0] in {'-R', '--repo'} or rest[:1] and rest[0].startswith('--repo='):
        if '=' in rest[0]:
            repo, rest = _repo(rest[0].split('=', 1)[1]), rest[1:]
        elif len(rest) >= 2:
            repo, rest = _repo(rest[1]), rest[2:]
        else:
            return None
        if repo is None:
            return None
    if len(rest) < 2:
        return None
    group, verb, tail = rest[0], rest[1], rest[2:]
    key = ' '.join(['gh', repo, *rest])
    if group == 'run' and verb in _RUN_OPTIONS:
        parsed = _options(tail, *_RUN_OPTIONS[verb])
        if parsed is None:
            return None
        operands, options = parsed
        if '-R' in options or '--repo' in options:
            repo = _repo(options.get('-R') or options.get('--repo'))
            if repo is None:
                return None
        if verb == 'list':
            return None if operands else Interaction('poll', 'runs', None, None, '--json' in options, repo, None, key)
        if len(operands) != 1 or not _ID.fullmatch(operands[0]):
            return None
        ident, attempt = operands[0], options.get('--attempt')
        if attempt is not None and not _ID.fullmatch(str(attempt)):
            return None
        attempt = int(attempt) if attempt else None
        if verb == 'watch':
            return Interaction('wait', 'run', ident, None, False, repo, None, key)
        if verb in {'rerun', 'cancel'}:
            return Interaction('mutation', 'run', ident, verb, False, repo, None, key)
        if '--log' in options or '--log-failed' in options:
            return Interaction('log', 'run', ident, None, False, repo, attempt, key)
        return Interaction('poll', 'run', ident, None, '--json' in options, repo, attempt, key)
    if group == 'pr' and verb == 'checks':
        parsed = _options(tail, {'-R', '--repo', '-i', '--interval', '--json'}, {'--watch', '--required', '--fail-fast'})
        if parsed is None or len(parsed[0]) > 1 or parsed[0] and not _ID.fullmatch(parsed[0][0]):
            return None
        operands, options = parsed
        if '-R' in options or '--repo' in options:
            repo = _repo(options.get('-R') or options.get('--repo'))
            if repo is None:
                return None
        ident = operands[0] if operands else None
        # `gh pr checks` output has no head SHA: it is never a state token.
        return Interaction('wait' if '--watch' in options else 'poll', 'pr', ident, None, False, repo, None, key)
    if group == 'api':
        return _api(rest[1:], repo, key)
    return None


def _api(tail, repo, key):
    parsed = _options(tail, {'-X', '--method', '-H', '--header', '-q', '--jq', '-t', '--template', '-R', '--repo'},
                      {'--paginate', '-i', '--include', '--silent'})
    if parsed is None or len(parsed[0]) != 1:
        return None
    (endpoint,), options = parsed
    method = str(options.get('-X') or options.get('--method') or 'GET').upper()
    match = _ENDPOINT.fullmatch(endpoint.lstrip('/').split('?', 1)[0])
    if not match:
        return None
    owner = match.group('repo')
    repo = '.' if owner == '{owner}/{repo}' else _repo(owner)
    if repo is None:
        return None
    ident, rest = match.group('run'), match.group('rest') or ''
    attempt = int(match.group('attempt')) if match.group('attempt') else None
    if not _ID.fullmatch(ident) or attempt is not None and not 1 <= attempt <= 1000:
        return None
    shaped = any(name in options for name in ('-q', '--jq', '-t', '--template', '-i', '--include'))
    if method == 'POST' and rest in {'/rerun', '/rerun-failed-jobs', '/cancel'} and attempt is None:
        return Interaction('mutation', 'run', ident, 'cancel' if rest == '/cancel' else 'rerun', False, repo, None, key)
    if method != 'GET':
        return None
    if rest == '/logs':
        return Interaction('log', 'run', ident, None, False, repo, attempt, key)
    if rest in {'', '/jobs'}:
        return Interaction('poll', 'run', ident, None, not shaped, repo, attempt, key)
    return None


def _time(value):
    if not isinstance(value, str) or len(value) > 32:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return int(parsed.astimezone(timezone.utc).timestamp())


def _signature(item):
    jobs = item.get('jobs')
    if not isinstance(jobs, list) or not 0 < len(jobs) <= 256:
        return None
    failed = []
    for job in jobs:
        if not isinstance(job, dict) or not isinstance(job.get('name'), str) or len(job['name']) > 256:
            return None
        if job.get('conclusion') not in FAILED:
            continue
        steps = job.get('steps') if isinstance(job.get('steps'), list) else []
        step = next((row.get('name') for row in steps if isinstance(row, dict) and row.get('conclusion') in FAILED
                     and isinstance(row.get('name'), str) and len(row['name']) <= 256), '')
        failed.append([job['name'], step])
    return progress._digest('ci-failure', sorted(failed)) if failed else None


def _run(item):
    if not isinstance(item, dict):
        return None
    ident = item.get('databaseId', item.get('id'))
    if type(ident) is not int or not 1 <= ident <= 10**19:
        return None
    attempt = item.get('attempt', item.get('run_attempt'))
    head = item.get('headSha', item.get('head_sha'))
    status = item.get('status')
    conclusion = item.get('conclusion') or None
    updated = item.get('updatedAt', item.get('updated_at'))
    if (attempt is not None and (type(attempt) is not int or not 1 <= attempt <= 1000)
            or head is not None and (not isinstance(head, str) or not _SHA.fullmatch(head))
            or status is not None and status not in STATUSES
            or conclusion is not None and conclusion not in CONCLUSIONS
            or updated is not None and _time(updated) is None):
        return None
    return RunState(str(ident), attempt, head, status, conclusion, _time(updated), _signature(item))


def _strict(text):
    def reject(value):
        raise ValueError(f'non-finite JSON constant {value}')
    return json.loads(text, object_pairs_hook=progress._pairs, parse_constant=reject)


def parse_runs(text: str) -> list[RunState]:
    """Run states from one JSON object, an array, a REST wrapper or JSON lines; anything else gives none."""
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_OUTPUT:
        return []
    try:
        documents = [_strict(text)]
    except (ValueError, RecursionError):
        try:
            documents = [_strict(line) for line in text.splitlines() if line.strip()]
        except (ValueError, RecursionError):
            return []
    items = []
    for document in documents:
        if isinstance(document, dict) and isinstance(document.get('workflow_runs'), list):
            document = document['workflow_runs']
        items.extend(document if isinstance(document, list) else [document])
    if not items or len(items) > MAX_ITEMS:
        return []
    runs = [_run(item) for item in items]
    return [] if any(run is None for run in runs) else runs


def _empty():
    return {'version': 1, 'runs': {}, 'blocks': {}}


def _validate(state):
    if not isinstance(state, dict) or set(state) != {'version', 'runs', 'blocks'} or state['version'] != 1 or type(state['version']) is not int:
        raise ValueError('invalid-external-schema')
    runs, blocks = state['runs'], state['blocks']
    if not isinstance(runs, dict) or not isinstance(blocks, dict) or len(runs) > MAX_RUNS or len(blocks) > MAX_BLOCKS:
        raise ValueError('invalid-external-bound')
    for key, row in runs.items():
        if (not progress._hex(key) or not isinstance(row, dict) or set(row) != _RUN_FIELDS or not progress._hex(row['scope'])
                or not isinstance(row['repo'], str) or not isinstance(row['ident'], str) or not _ID.fullmatch(row['ident'])
                or type(row['max_attempt']) is not int or not 0 <= row['max_attempt'] <= 1001
                or row['head'] is not None and not (isinstance(row['head'], str) and _SHA.fullmatch(row['head']))
                or row['status'] is not None and row['status'] not in STATUSES
                or row['conclusion'] is not None and row['conclusion'] not in CONCLUSIONS
                or any(row[name] is not None and type(row[name]) is not int for name in ('updated', 'seen'))
                or type(row['at']) is not int or not isinstance(row['failures'], list) or len(row['failures']) > 4):
            raise ValueError('invalid-external-run')
        for failure in row['failures']:
            if (not isinstance(failure, list) or len(failure) != 3 or type(failure[0]) is not int
                    or not (isinstance(failure[1], str) and _SHA.fullmatch(failure[1])) or not progress._hex(failure[2])):
                raise ValueError('invalid-external-failure')
    for key, row in blocks.items():
        if (not progress._hex(key) or not isinstance(row, dict) or set(row) != _BLOCK_FIELDS or not progress._hex(row['scope'])
                or row['cls'] not in CLASSES or row['run'] is not None and not progress._hex(row['run'])
                or any(row[name] is not None and type(row[name]) is not int for name in ('need', 'next_at'))
                or type(row['count']) is not int or not 0 <= row['count'] <= progress.MAX_COUNT
                or row['token'] is not None and not progress._hex(row['token'])
                or type(row['at']) is not int or not progress._hex(row['revision']) or type(row['retry']) is not bool
                or not isinstance(row['recoveries'], list) or len(row['recoveries']) > MAX_RECOVERIES
                or any(not progress._hex(value) for value in row['recoveries'])):
            raise ValueError('invalid-external-block')


def _store(root, *, write=False):
    return progress._store(root, write=write, name=STATE_NAME, validate=_validate, empty=_empty)


def _run_key(scope, repo, ident):
    return progress._digest('ci-run', [scope, repo, ident])


def _op_key(scope, interaction):
    return progress._digest('ci-operation', [scope, interaction.key])


def _completed(response):
    """(exit code, text) of a completed result with the same rules as local checks; None otherwise."""
    if progress._outcome(response) is None:
        return None
    code = next(response[key] for key in ('exit_code', 'exitCode', 'returncode') if key in response)
    text = next((response[key] for key in ('stdout', 'output', 'aggregated_output') if isinstance(response.get(key), str)
                 and response[key]), '')
    errors = response.get('stderr') if isinstance(response.get('stderr'), str) else ''
    return code, text[:MAX_OUTPUT + 1], (text[:8192] + '\n' + text[-8192:] + '\n' + errors[:8192])


def _prune(state, now):
    for table in ('runs', 'blocks'):
        for key in [key for key, row in state[table].items() if abs(now - row['at']) > TTL]:
            del state[table][key]


_FULL = 'Getzilla: CI observation unrecorded because all available slots are protected.'


def _reserve(state, *, block=None, run=None):
    """Make room for a whole operation before removing any existing rows."""
    victims = []
    if block is not None and block not in state['blocks'] and len(state['blocks']) >= MAX_BLOCKS:
        harmless = [(row['at'], key) for key, row in state['blocks'].items()
                    if row['cls'] == 'poll' and row['count'] < POLL_LIMIT]
        if not harmless:
            return False
        victims.append(('blocks', min(harmless)[1]))
    if run is not None and run not in state['runs'] and len(state['runs']) >= MAX_RUNS:
        referenced = {row['run'] for row in state['blocks'].values()}
        harmless = [(row['at'], key) for key, row in state['runs'].items() if key not in referenced]
        if not harmless:
            return False
        victims.append(('runs', min(harmless)[1]))
    for table, victim in victims:
        del state[table][victim]
    return True


def _new_run(scope, interaction, now):
    return {'scope': scope, 'repo': interaction.repo, 'ident': interaction.ident, 'max_attempt': 0, 'head': None,
            'status': None, 'conclusion': None, 'updated': None, 'seen': None, 'failures': [], 'at': now}


def _block(scope, cls, now, *, run=None, need=None, token=None, next_at=None, count=1):
    return {'scope': scope, 'cls': cls, 'run': run, 'need': need, 'count': count, 'token': token, 'next_at': next_at,
            'at': now, 'revision': secrets.token_hex(32), 'retry': False, 'recoveries': []}


def _historical(run, row, head):
    if run.head is not None and run.head != head:
        return f'head {run.head[:12]} is not the current head {head[:12]}'
    if row and run.attempt is not None and run.attempt < row['max_attempt']:
        return f'attempt {run.attempt} is older than attempt {row["max_attempt"]}'
    if (row and run.attempt is not None and run.attempt == row['max_attempt'] and run.updated is not None
            and row['updated'] is not None and run.updated < row['updated']):
        return 'it is older than the last recorded state of the same attempt'
    return None


def _record(state, scope, interaction, run, now):
    key = _run_key(scope, interaction.repo, run.ident)
    if not _reserve(state, run=key):
        return False
    row = state['runs'].get(key) or {**_new_run(scope, interaction, now), 'ident': run.ident}
    row.update(max_attempt=max(row['max_attempt'], run.attempt or 0), head=run.head or row['head'],
               status=run.status or row['status'], conclusion=run.conclusion, updated=run.updated or row['updated'],
               seen=now, at=now)
    if run.status == 'completed' and run.conclusion in FAILED and run.signature and run.attempt and run.head:
        failures = [item for item in row['failures'] if item[0] != run.attempt] + [[run.attempt, run.head, run.signature]]
        row['failures'] = sorted(failures)[-4:]
    elif run.status == 'completed' and run.attempt and run.conclusion in CONCLUSIONS - FAILED:
        row['failures'] = [item for item in row['failures'] if item[0] > run.attempt]
    state['runs'][key] = row
    if run.status == 'completed':
        for op, pending in list(state['blocks'].items()):
            if (pending['cls'] == 'external-pending' and pending['run'] == key
                    and run.attempt >= (pending['need'] or 1) and now > pending['at']):
                del state['blocks'][op]
    return True


def _wait_advice(interaction):
    target = interaction.ident or '<run-id>'
    return (f'Wait without model calls: `gh run watch {target} --exit-status --interval 30` in the foreground, then one '
            f'`gh run view {target} --json databaseId,attempt,headSha,status,conclusion,updatedAt,jobs`.')


def _recovery(key, block):
    return (f'Loop ID: {key}. Revision: {block["revision"]}. To retry with a new diagnosis use '
            '`getzilla agent progress-recover --session-id <current-session>` with that loop ID and revision. '
            'Ordinary authorization still applies.')


def observe(root, scope, inputs, response, head, *, now=None) -> str:
    """Record one completed `gh` result; return an advisory hint or an empty string."""
    interaction = classify(inputs.get('command')) if isinstance(inputs, dict) else None
    if interaction is None or not progress._hex(scope) or not (isinstance(head, str) and _SHA.fullmatch(head)):
        return ''
    done = _completed(response) if isinstance(response, dict) else None
    if done is None:
        return ''
    code, text, sample = done
    now = progress._clock(now)
    hints = []
    with _store(root, write=True) as state:
        _prune(state, now)
        key = _op_key(scope, interaction)
        block = state['blocks'].get(key)
        transient = bool(code) and interaction.kind != 'wait' and bool(_TRANSIENT.search(sample)) and not _DETERMINISTIC.search(sample)
        if code == 0 and block and block['cls'] in {'transient', 'transient-exhausted'}:
            del state['blocks'][key]  # a success ends the transient budget
            block = None
        if transient and not (block and block['cls'] == 'external-pending' and interaction.kind == 'mutation'):
            if not _reserve(state, block=key):
                return _FULL
            schedule = RATE_BACKOFF if _RATE.search(sample) else BACKOFF
            count = (block['count'] + 1) if block and block['cls'] == 'transient' else 1
            if count > len(schedule):
                state['blocks'][key] = _block(scope, 'transient-exhausted', now, count=count)
                hints.append('Getzilla: transient retry budget used; the next unchanged attempt is stopped.')
            else:
                state['blocks'][key] = _block(scope, 'transient', now, count=count, next_at=now + schedule[count - 1])
                hints.append(f'Getzilla: transient network failure; retry {count} of {len(schedule)} after {schedule[count - 1]} s.')
        elif interaction.kind == 'wait' and (code == 0 or not (_TRANSIENT.search(sample) or _DETERMINISTIC.search(sample))):
            # A wait ends only when it really waited: success, or the watched run failing (not a gh error).
            for poll in [name for name, row in state['blocks'].items() if row['scope'] == scope and row['cls'] == 'poll']:
                del state['blocks'][poll]
        elif interaction.kind == 'mutation':
            run_key = _run_key(scope, interaction.repo, interaction.ident)
            if not _reserve(state, block=key, run=run_key):
                return _FULL
            row = state['runs'].get(run_key) or _new_run(scope, interaction, now)
            if code == 0 and interaction.op == 'rerun':
                row.update(max_attempt=max(row['max_attempt'], 1) + 1, status='queued', conclusion=None, seen=None, at=now)
            row['at'] = now
            state['runs'][run_key] = row
            pending = _block(scope, 'external-pending', now, run=run_key, need=max(row['max_attempt'], 1))
            if code and block:
                pending['recoveries'] = block['recoveries']
            state['blocks'][key] = pending
        elif code == 0 and interaction.kind == 'log':
            row = state['runs'].get(_run_key(scope, interaction.repo, interaction.ident))
            if row is None:
                hints.append(f'Getzilla: run {interaction.ident} was not observed; this log is unbound evidence. '
                             'Poll its state with `--json` before acting on it.')
            elif row['head'] and row['head'] != head:
                hints.append(f'Getzilla: historical CI evidence: run {interaction.ident} ran head {row["head"][:12]}, '
                             f'not the current head {head[:12]}; it does not count as a current failure.')
            elif interaction.attempt is not None and interaction.attempt < row['max_attempt']:
                hints.append(f'Getzilla: historical CI evidence: attempt {interaction.attempt} of run {interaction.ident} is '
                             f'older than attempt {row["max_attempt"]}.')
        elif code == 0 and interaction.kind == 'poll' and interaction.structured:
            fresh = []
            for run in parse_runs(text):
                row = state['runs'].get(_run_key(scope, interaction.repo, run.ident))
                if interaction.attempt is not None and (run.attempt != interaction.attempt
                        or row and interaction.attempt < row['max_attempt']):
                    hints.append('Getzilla: historical or unbound attempt-specific CI poll; not counted.')
                    continue
                reason = _historical(run, row, head)
                if reason:
                    hints.append(f'Getzilla: historical CI evidence: run {run.ident} {reason}; not counted.')
                    continue
                if run.head == head and run.attempt is not None and run.status is not None:
                    if not _record(state, scope, interaction, run, now):
                        if _FULL not in hints:
                            hints.append(_FULL)
                        continue
                fresh.append(run)
            if fresh and not _reserve(state, block=key):
                hints.append(_FULL)
            elif fresh:
                token = progress._digest('ci-state', sorted([run.ident, run.attempt, run.head, run.status, run.conclusion]
                                                            for run in fresh))
                terminal = all(run.status == 'completed' for run in fresh)
                count = (block['count'] + 1) if block and block['cls'] == 'poll' and block['token'] == token and not terminal else int(not terminal)
                state['blocks'][key] = _block(scope, 'poll', now, token=token, count=count)
                if count >= POLL_LIMIT:
                    hints.append(f'Getzilla: {count} unchanged CI state polls; the next unchanged poll is stopped. '
                                 + _wait_advice(interaction))
    return '\n'.join(hints)


def _consume(block, now):
    if block['retry']:
        block.update(retry=False, at=now, revision=secrets.token_hex(32))
        return True
    return False


def refusal(root, scope, inputs, head, *, now=None) -> str | None:
    """An advisory refusal for an unchanged `gh` action without progress; None allows it."""
    interaction = classify(inputs.get('command')) if isinstance(inputs, dict) else None
    if interaction is None or interaction.kind == 'wait' or not progress._hex(scope):
        return None
    now = progress._clock(now)
    with _store(root, write=True) as state:
        _prune(state, now)
        key = _op_key(scope, interaction)
        block = state['blocks'].get(key)
        if block and block['cls'] == 'transient':
            if now >= block['next_at'] or _consume(block, now):
                return None
            moment = datetime.fromtimestamp(block['next_at'], timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            return f'Getzilla: transient failure pacing; retry after {moment}. ' + _recovery(key, block)
        if block and block['cls'] == 'transient-exhausted':
            return None if _consume(block, now) else (
                'Getzilla: transient retry budget used; the failure repeats. Read it and name a new hypothesis. '
                + _recovery(key, block))
        if block and block['cls'] == 'poll' and block['count'] >= POLL_LIMIT:
            return None if _consume(block, now) else (
                f'Getzilla: unchanged CI state after {block["count"]} polls; this poll cannot show progress. '
                + _wait_advice(interaction) + ' ' + _recovery(key, block))
        if block and block['cls'] == 'external-pending':
            if not _consume(block, now):
                condition = f'gh-run:{interaction.repo}:{interaction.ident}:attempt>={block["need"]}:completed'
                return (f'Getzilla: the last `{interaction.op}` of run {interaction.ident} is unresolved; an identical '
                        f'request cannot give a different result. Resume condition: {condition}. '
                        + _wait_advice(interaction) + ' ' + _recovery(key, block))
            else:
                return None
        if interaction.kind == 'mutation' and interaction.op == 'rerun' and isinstance(head, str):
            row = state['runs'].get(_run_key(scope, interaction.repo, interaction.ident))
            failures = row['failures'][-2:] if row else []
            # The two newest completed attempts: consecutive, both failed, same head and signature.
            if (len(failures) == 2 and all(item[1] == head for item in failures) and failures[0][2] == failures[1][2]
                    and failures[1][0] == row['max_attempt'] and failures[0][0] == failures[1][0] - 1):
                block = state['blocks'].get(key)
                if not block or block['cls'] != 'deterministic':
                    if not _reserve(state, block=key):
                        return 'Getzilla: repeat failure; recovery is unavailable while the observation ledger is full.'
                    block = state['blocks'][key] = _block(scope, 'deterministic', now, run=_run_key(scope, interaction.repo,
                                                                                                   interaction.ident))
                if _consume(block, now):
                    return None
                return (f'Getzilla: attempts {failures[0][0]} and {failures[1][0]} of run {interaction.ident} failed with the '
                        'same failure on the same head; another rerun cannot give a different result. Change the source '
                        'or name a new hypothesis. ' + _recovery(key, block))
    return None


def inspect(root, scope, *, now=None) -> list[dict]:
    now, rows = progress._clock(now), []
    if not progress._hex(scope):
        return rows
    with _store(root) as state:
        for key, block in state['blocks'].items():
            if block['scope'] != scope:
                continue
            blocking = (block['cls'] in {'external-pending', 'deterministic', 'transient-exhausted'}
                        or block['cls'] == 'poll' and block['count'] >= POLL_LIMIT
                        or block['cls'] == 'transient' and (block['next_at'] or 0) > now)
            status = ('expired' if abs(now - block['at']) > TTL else 'retry-available' if block['retry']
                      else 'blocked' if blocking else 'observing')
            rows.append({'loop_id': key, 'revision': block['revision'], 'class': block['cls'], 'count': block['count'],
                         'status': status, 'last_observed_at': block['at']})
    return rows


def recover(root, scope, loop_id, revision, reason, evidence, *, now=None) -> dict | None:
    """One retry for a named new diagnosis; None when the ID is not an external block."""
    if not all(progress._hex(value) for value in (scope, loop_id, revision)) or reason not in progress.REASONS:
        raise ValueError('invalid-recovery-target')
    if not isinstance(evidence, str) or not evidence.strip() or len(evidence) > 4096:
        raise ValueError('new-diagnosis-required')
    now, diagnosis = progress._clock(now), progress._digest('diagnosis', evidence.strip())
    with _store(root, write=True) as state:
        block = state['blocks'].get(loop_id)
        if block is None:
            return None
        if (block['scope'] != scope or block['revision'] != revision or abs(now - block['at']) > TTL or block['retry']
                or diagnosis in block['recoveries'] or len(block['recoveries']) >= MAX_RECOVERIES):
            raise ValueError('stale-or-reused-recovery')
        block['recoveries'].append(diagnosis)
        block.update(retry=True, revision=secrets.token_hex(32), at=now)
        return {'loop_id': loop_id, 'revision': block['revision'], 'retry_available': True,
                'control': 'local-observation-only', 'success_asserted': False}
