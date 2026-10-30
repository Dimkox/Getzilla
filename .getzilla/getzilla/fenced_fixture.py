"""Two-container, no-network Codex fixture with checkpoint-bound retry.

This synthetic harness is not a live adapter. The Docker daemon is trusted.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import shutil
import subprocess
from pathlib import Path

from . import controlled_fixture as fixture
from . import model_continuation_state as journal
from .model_continuation import load_policy


_SCAN = '''
import hashlib, os, stat, sys
def fail(error):
    raise error
digests = []
for root in ('/state', '/work'):
    h = hashlib.sha256()
    total = 0
    count = 0
    root_stat = os.lstat(root)
    if not stat.S_ISDIR(root_stat.st_mode):
        sys.exit(4)
    h.update(os.fsencode(root) + b'\\0' + str(root_stat.st_mode).encode() + b'\\0')
    for base, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        before_dir = os.lstat(base)
        dirs.sort()
        files.sort()
        for name in dirs + files:
            count += 1
            if count > 4096:
                sys.exit(4)
            path = os.path.join(base, name)
            item = os.lstat(path)
            if stat.S_ISLNK(item.st_mode) or not (stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode)):
                sys.exit(4)
            if stat.S_ISREG(item.st_mode) and item.st_nlink != 1:
                sys.exit(4)
            h.update(os.fsencode(path) + b'\\0' + str(item.st_mode).encode() + b'\\0')
            if stat.S_ISREG(item.st_mode):
                total += item.st_size
                if total > 134217728:
                    sys.exit(4)
                with open(path, 'rb') as stream:
                    data = stream.read(item.st_size + 1)
                after = os.lstat(path)
                if len(data) != item.st_size or (item.st_ino, item.st_size, item.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                    sys.exit(4)
                h.update(hashlib.sha256(data).digest())
        after_dir = os.lstat(base)
        if (before_dir.st_ino, before_dir.st_mtime_ns, before_dir.st_mode) != (after_dir.st_ino, after_dir.st_mtime_ns, after_dir.st_mode):
            sys.exit(4)
    digests.append(h.hexdigest())
print('\\n'.join(digests))
'''


def _inspect(docker, ident):
    value = json.loads(fixture._command([docker, 'inspect', ident]))
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise fixture.FixtureError('invalid_container')
    return value[0]


def _mounts(volumes, readonly=False):
    suffix = ',readonly' if readonly else ''
    return [part for name, target in zip(volumes, (fixture.CONTAINER_TMP + '/codex', '/work'))
            for part in ('--mount', 'type=volume,src=' + name + ',dst=' + target + suffix)]


def _valid(info, ident, image, nonce, volumes, phase, thread):
    try:
        host, config = info['HostConfig'], info['Config']
        if (info['Id'] != ident or info['Image'] != image
                or config['User'] != '65534:65534' or config.get('Entrypoint') not in (None, [])
                or config['Cmd'] != ['python', '-u', '/fixture.py']
                or config['Labels'].get('getzilla.owner') != nonce
                or host['NetworkMode'] != 'none' or host['ReadonlyRootfs'] is not True
                or host['Privileged'] is not False or host['CapDrop'] != ['ALL']
                or host.get('CapAdd') not in (None, []) or host.get('Devices') not in (None, [])
                or host.get('DeviceRequests') not in (None, []) or host.get('VolumesFrom') not in (None, [])
                or host['RestartPolicy'] != {'Name': 'no', 'MaximumRetryCount': 0}
                or host['PidsLimit'] != 64 or host['Memory'] != 536870912 or host['NanoCpus'] != 2000000000
                or host['SecurityOpt'] != ['no-new-privileges']
                or host['Tmpfs'] != {fixture.CONTAINER_TMP: 'rw,nosuid,nodev,size=64m,mode=1777'}
                or host['PidMode'] not in ('', 'private') or host['IpcMode'] not in ('', 'private')):
            return False
        env = config['Env']
        allowed = fixture._ENV_KEYS | {'GETZILLA_FIXTURE_PHASE', 'GETZILLA_FIXTURE_THREAD', 'GETZILLA_HOST_BROKER'}
        if not isinstance(env, list) or any(not isinstance(x, str) or '=' not in x or x.split('=', 1)[0] not in allowed for x in env):
            return False
        values = dict(x.split('=', 1) for x in env)
        if (len(values) != len(env) or values.get('HOME') != fixture.CONTAINER_TMP
                or values.get('CODEX_HOME') != fixture.CONTAINER_TMP + '/codex'
                or values.get('GETZILLA_CONTROLLED_GATE') != '1'
                or values.get('GETZILLA_HOST_BROKER') != '1'
                or values.get('GETZILLA_FIXTURE_NONCE') != nonce
                or values.get('GETZILLA_FIXTURE_PHASE') != phase
                or values.get('GETZILLA_FIXTURE_THREAD', '') != thread):
            return False
        mounts = info['Mounts']
        expected = dict(zip((fixture.CONTAINER_TMP + '/codex', '/work'), volumes))
        return (isinstance(mounts, list) and len(mounts) == 2
                and all(item['Type'] == 'volume' and item['RW'] is True
                        and expected.get(item['Destination']) == item['Name'] for item in mounts)
                and len({item['Destination'] for item in mounts}) == 2)
    except (KeyError, TypeError, AttributeError):
        return False


def _helper(docker, image, volumes, program, *, root=False):
    mounts = [part for name, target in zip(volumes, ('/state', '/work'))
              for part in ('--mount', 'type=volume,src=' + name + ',dst=' + target + ('' if root else ',readonly'))]
    args = [docker, 'create', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '512m', '--cpus', '2']
    if root:
        args += ['--cap-add', 'CHOWN']
    args += ['--user', '0' if root else '65534:65534', *mounts, '--entrypoint', 'python', image, '-c', program]
    ident = fixture._command(args)
    if not re.fullmatch(r'[a-f0-9]{64}', ident):
        raise fixture.FixtureError('invalid_container')
    try:
        return fixture._command([docker, 'start', '-a', ident], timeout=60)
    finally:
        fixture._command([docker, 'rm', '-fv', ident])


def _checkpoint(docker, image, volumes):
    result = _helper(docker, image, volumes, _SCAN).splitlines()
    if len(result) != 2 or any(not re.fullmatch(r'[a-f0-9]{64}', item) for item in result):
        raise fixture.FixtureError('checkpoint_invalid')
    return tuple(result)


def _volume_names(root, binding):
    identity = journal._digest([str(Path(root).resolve()), journal._binding(binding)])[:32]
    return ['getzilla-fixture-' + identity + '-state', 'getzilla-fixture-' + identity + '-work']


def _create(docker, image, volumes, nonce, phase, thread=''):
    args = [docker, 'create', '-i', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--label', 'getzilla.owner=' + nonce, '--restart', 'no', '--security-opt', 'no-new-privileges', '--pids-limit', '64',
            '--memory', '512m', '--cpus', '2', '--user', '65534:65534',
            '--tmpfs', fixture.CONTAINER_TMP + ':rw,nosuid,nodev,size=64m,mode=1777',
            *_mounts(volumes), '-e', 'HOME=' + fixture.CONTAINER_TMP,
            '-e', 'CODEX_HOME=' + fixture.CONTAINER_TMP + '/codex',
            '-e', 'GETZILLA_CONTROLLED_GATE=1', '-e', 'GETZILLA_FIXTURE_NONCE=' + nonce,
            '-e', 'GETZILLA_HOST_BROKER=1',
            '-e', 'GETZILLA_FIXTURE_PHASE=' + phase]
    if thread:
        args += ['-e', 'GETZILLA_FIXTURE_THREAD=' + thread]
    args += [image, 'python', '-u', '/fixture.py']
    ident = fixture._command(args)
    if not re.fullmatch(r'[a-f0-9]{64}', ident):
        raise fixture.FixtureError('invalid_container')
    try:
        info = _inspect(docker, ident)
        if not _valid(info, ident, image, nonce, volumes, phase, thread):
            raise fixture.FixtureError('invalid_container')
    except (fixture.FixtureError, ValueError, TypeError):
        fixture._command([docker, 'rm', '-fv', ident])
        raise
    return ident


def _stopped(docker, ident, image, nonce, volumes, phase, thread):
    info = _inspect(docker, ident)
    return (fixture._container_stopped(info, ident, image, nonce)
            and _valid(info, ident, image, nonce, volumes, phase, thread))


def _exclusive_volumes(docker, volumes, expected):
    for volume in volumes:
        actual = fixture._command([docker, 'ps', '-a', '--no-trunc', '--filter', 'volume=' + volume,
                                   '--format', '{{.ID}}']).splitlines()
        if len(actual) != len(expected) or set(actual) != set(expected):
            return False
    return True


def _valid_second_events(events, thread, turn):
    if not isinstance(events, list) or len(events) > 128:
        return False
    filtered = []
    turn_started = False
    goal_seen = False
    for event in events:
        if not isinstance(event, dict) or 'id' in event or not isinstance(event.get('params'), dict):
            return False
        if event.get('method') == 'deprecationNotice':
            if (turn_started or set(event['params']) != {'summary', 'details'}
                    or not isinstance(event['params']['summary'], str)
                    or not isinstance(event['params']['details'], (str, type(None)))):
                return False
        elif event.get('method') == 'thread/goal/cleared':
            if (turn_started or goal_seen or set(event['params']) != {'threadId'}
                    or event['params']['threadId'] != thread):
                return False
            goal_seen = True
        else:
            if event.get('method') == 'turn/started':
                turn_started = True
            filtered.append(event)
    return fixture._second_valid(filtered, thread, turn)


def _valid_model_request(frame, nonce, model):
    return (isinstance(frame, dict)
            and set(frame) == {'type', 'version', 'nonce', 'model', 'path', 'stream', 'tool_types'}
            and frame['type'] == 'model_request' and type(frame['version']) is int and frame['version'] == 1
            and frame['nonce'] == nonce and frame['model'] == model and frame['path'] == '/v1/responses'
            and frame['stream'] is True and isinstance(frame['tool_types'], list)
            and len(frame['tool_types']) <= 64 and all(item == 'function' for item in frame['tool_types']))


def _admit_model_request(root, binding, pipe, nonce, generation, revision, model):
    frame = pipe.read()
    if not _valid_model_request(frame, nonce, model):
        raise fixture.FixtureError('model_request_denied')
    loaded = load_policy(root)
    if (loaded.policy is None or not loaded.policy.enabled or type(generation) is not int
            or not 1 <= generation <= len(loaded.policy.candidates)
            or loaded.policy.candidates[generation - 1].model != model
            or loaded.policy.candidates[generation - 1].provider != 'local_fixture'
            or loaded.policy.candidates[generation - 1].account_ref != 'synthetic'):
        raise fixture.FixtureError('model_request_denied')
    claim = journal.consume_controlled_request(root, binding, generation, revision)
    if not claim['claimed']:
        raise fixture.FixtureError('request_claim_denied')
    if journal.check_controlled_send(root, binding, generation, claim['revision']) is not None:
        raise fixture.FixtureError('request_claim_denied')
    if model == 'fixture-a':
        body = json.dumps({'error': {'message': 'synthetic rate limit', 'type': 'rate_limit_error',
                                     'code': 'rate_limit_exceeded'}})
        pipe.respond(nonce, 429, 'application/json', body)
    else:
        frames = [
            {'type': 'response.created', 'response': {'id': 'r1'}},
            {'type': 'response.output_item.done', 'item': {'type': 'message', 'role': 'assistant', 'id': 'm1',
             'content': [{'type': 'output_text', 'text': 'synthetic-ok'}]}},
            {'type': 'response.completed', 'response': {'id': 'r1', 'usage': {'input_tokens': 1,
             'input_tokens_details': None, 'output_tokens': 1, 'output_tokens_details': None, 'total_tokens': 2}}},
        ]
        body = ''.join('event: ' + item['type'] + '\ndata: ' + json.dumps(item) + '\n\n' for item in frames)
        pipe.respond(nonce, 200, 'text/event-stream', body)
    return claim['revision']


def run(root: Path, binding: journal.Binding, budget: journal.TaskBudget) -> dict:
    docker = shutil.which('docker', path='/usr/bin:/bin')
    codex = shutil.which('codex')
    script = Path(__file__).resolve().parents[2] / 'tests/fixtures/codex_loopback_probe.py'
    policy = load_policy(root).policy
    if (not docker or not codex or not script.is_file() or policy is None or not policy.enabled
            or len(policy.candidates) != 2 or [x.model for x in policy.candidates] != ['fixture-a', 'fixture-b']
            or any(x.provider != 'local_fixture' or x.account_ref != 'synthetic' for x in policy.candidates)):
        raise fixture.FixtureError('fixture_unavailable')
    codex = str(Path(codex).resolve())
    recovery = None
    try:
        with open(codex, 'rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != fixture.CODEX_SHA256:
                raise fixture.FixtureError('codex_unqualified')
        try:
            journal.create_controlled_chain(root, binding, journal.Usage(1, '0'), budget)
        except journal.JournalError as error:
            if str(error) != 'task_already_recorded':
                raise
            recovery = journal.inspect_controlled_chain(root, binding)
    except (OSError, journal.JournalError):
        raise fixture.FixtureError('fixture_failed') from None
    if recovery is not None:
        if recovery['attempts'][-1]['state'] == 'succeeded':
            return {'state': 'fixture_succeeded', 'dispatch_permitted': False}
        limits = recovery['limits']
        if (type(budget) is not journal.TaskBudget or not journal._integer(budget.max_attempts)
                or not journal._integer(budget.max_requests) or not journal._integer(budget.deadline_epoch, journal.MAX_EPOCH_SECONDS)
                or limits['attempts'] > budget.max_attempts or limits['requests'] > budget.max_requests
                or limits['deadline'] > budget.deadline_epoch
                or limits['cost_micros'] > journal.money_micros(budget.max_cost_usd, ceiling=True)
                or recovery['state'] != 'open'):
            raise fixture.FixtureError('recovery_required')
        valid = (recovery['generation'] == 1 and recovery['attempts'][-1]['state'] == 'failed') or (
            recovery['generation'] == 2 and recovery['attempts'][-1]['state'] == 'reserved_unknown')
        if not valid or 'fence_1' not in recovery['events']:
            raise fixture.FixtureError('recovery_required')
    nonce = secrets.token_hex(16)
    volumes = _volume_names(root, binding)
    created_volumes = []
    image = None
    image_owned = False
    containers = []
    processes = []
    lines = []
    second = None
    success = False
    cleanup_failed = False
    preserve_volumes = False
    fence_ready = False
    a = None
    try:
        if recovery is None:
            image = fixture._immutable_image(docker, script, codex)
            image_owned = True
            for name in volumes:
                if fixture._command([docker, 'volume', 'create', '--label', 'getzilla.owner=' + nonce, name]) != name:
                    raise fixture.FixtureError('invalid_volume')
                volume = json.loads(fixture._command([docker, 'volume', 'inspect', name]))
                if (not isinstance(volume, list) or len(volume) != 1 or volume[0].get('Name') != name
                        or (volume[0].get('Labels') or {}).get('getzilla.owner') != nonce):
                    raise fixture.FixtureError('invalid_volume')
                created_volumes.append(name)
            _helper(docker, image, volumes, "import os; os.chown('/state',65534,65534); os.chown('/work',65534,65534)", root=True)
            baseline = _checkpoint(docker, image, volumes)
            a = _create(docker, image, volumes, nonce, 'a')
            containers.append(a)
            first = journal.consume_controlled_send(root, binding, 1, 1)
            if not first['claimed']:
                raise fixture.FixtureError('claim_denied')
            proc_a = subprocess.Popen([docker, 'start', '-ai', a], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin'}, bufsize=0)
            processes.append(proc_a)
            preserve_volumes = True
            pipe_a = fixture._Lines(proc_a)
            lines.append(pipe_a)
            if pipe_a.read() != {'type': 'before_a', 'version': 1, 'nonce': nonce}:
                raise fixture.FixtureError('invalid_frame')
            if journal.check_controlled_send(root, binding, 1, first['revision']) is not None:
                raise fixture.FixtureError('claim_denied')
            pipe_a.allow(nonce)
            first_revision = _admit_model_request(root, binding, pipe_a, nonce, 1, first['revision'], 'fixture-a')
            frame = pipe_a.read()
            if not fixture._first_valid(frame, nonce) or not re.fullmatch(r'[A-Za-z0-9-]{1,64}', frame['thread']):
                raise fixture.FixtureError('unreconciled_effect')
            if proc_a.wait(timeout=15) != 0 or not _stopped(docker, a, image, nonce, volumes, 'a', ''):
                raise fixture.FixtureError('shutdown_uncertain')
            if not _exclusive_volumes(docker, volumes, [a]):
                raise fixture.FixtureError('volume_not_exclusive')
            checkpoint = _checkpoint(docker, image, volumes)
            if checkpoint != _checkpoint(docker, image, volumes) or checkpoint[1] != baseline[1]:
                raise fixture.FixtureError('checkpoint_changed')
            checkpoint_digest = hashlib.sha256((''.join(checkpoint)).encode('ascii')).hexdigest()
            terminal = journal.record_controlled_terminal(root, binding, 1, first_revision, 'rate_limit')
            recorded = journal.record_controlled_fence(root, binding, 1, terminal['revision'], a, checkpoint_digest, frame['thread'])
            if recorded['state'] != 'fence_recorded':
                raise fixture.FixtureError('fence_denied')
            fence_ready = True
            reserved = journal.reserve_fenced_next(root, binding, recorded['revision'], journal.Usage(1, '0'), a, checkpoint_digest)
        else:
            preserve_volumes = True
            evidence = recovery['events']['fence_1']['evidence']
            a = evidence['container_id']
            checkpoint_digest = evidence['checkpoint_digest']
            frame = {'thread': evidence['thread_id']}
            labels = []
            for name in volumes:
                volume = json.loads(fixture._command([docker, 'volume', 'inspect', name]))
                if not isinstance(volume, list) or len(volume) != 1 or volume[0].get('Name') != name:
                    raise fixture.FixtureError('invalid_volume')
                labels.append((volume[0].get('Labels') or {}).get('getzilla.owner'))
                created_volumes.append(name)
            if len(set(labels)) != 1 or not isinstance(labels[0], str) or not re.fullmatch(r'[a-f0-9]{32}', labels[0]):
                raise fixture.FixtureError('invalid_volume')
            nonce = labels[0]
            owned = fixture._command([docker, 'ps', '-a', '--no-trunc', '--filter',
                                      'label=getzilla.owner=' + nonce, '--format', '{{.ID}}']).splitlines()
            if owned != [a]:
                raise fixture.FixtureError('recovery_required')
            info = _inspect(docker, a)
            image = info.get('Image')
            if not isinstance(image, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
                raise fixture.FixtureError('invalid_image')
            if not _stopped(docker, a, image, nonce, volumes, 'a', ''):
                raise fixture.FixtureError('shutdown_uncertain')
            if not _exclusive_volumes(docker, volumes, [a]):
                raise fixture.FixtureError('volume_not_exclusive')
            containers.append(a)
            fence_ready = True
            image_owned = True
            program = ("import hashlib; from pathlib import Path; "
                       "print(hashlib.sha256(Path('/fixture.py').read_bytes()).hexdigest()); "
                       "print(hashlib.sha256(Path('/fixture-codex').read_bytes()).hexdigest())")
            if _helper(docker, image, volumes, program).splitlines() != [fixture.FIXTURE_SHA256, fixture.CODEX_SHA256]:
                raise fixture.FixtureError('image_mismatch')
            checkpoint = _checkpoint(docker, image, volumes)
            if (checkpoint != _checkpoint(docker, image, volumes)
                    or hashlib.sha256((''.join(checkpoint)).encode('ascii')).hexdigest() != checkpoint_digest):
                raise fixture.FixtureError('checkpoint_changed')
            if recovery['generation'] == 1:
                reserved = journal.reserve_fenced_next(root, binding, recovery['revision'], journal.Usage(1, '0'), a, checkpoint_digest)
            else:
                reserved = {'state': 'reserved_unknown', 'revision': recovery['revision']}
        if reserved.get('state') != 'reserved_unknown':
            raise fixture.FixtureError('budget_denied')
        b = _create(docker, image, volumes, nonce, 'b', frame['thread'])
        containers.append(b)
        if not _exclusive_volumes(docker, volumes, [a, b]) or _checkpoint(docker, image, volumes) != checkpoint:
            raise fixture.FixtureError('checkpoint_changed')
        second = journal.consume_controlled_send(root, binding, 2, reserved['revision'])
        if not second['claimed']:
            raise fixture.FixtureError('claim_denied')
        proc_b = subprocess.Popen([docker, 'start', '-ai', b], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin'}, bufsize=0)
        processes.append(proc_b)
        pipe_b = fixture._Lines(proc_b)
        lines.append(pipe_b)
        if pipe_b.read() != {'type': 'before_fenced_b', 'version': 1, 'nonce': nonce, 'thread': frame['thread']}:
            raise fixture.FixtureError('invalid_frame')
        if journal.check_controlled_send(root, binding, 2, second['revision']) is not None:
            raise fixture.FixtureError('claim_denied')
        pipe_b.allow(nonce)
        second_revision = _admit_model_request(root, binding, pipe_b, nonce, 2, second['revision'], 'fixture-b')
        result = pipe_b.read()
        if (result.get('type') != 'fenced_b_result' or result.get('version') != 1 or result.get('nonce') != nonce
                or result.get('thread') != frame['thread'] or result.get('server_requests') != []
                or not isinstance(result.get('synthetic_requests'), list)
                or len(result['synthetic_requests']) != 1 or result['synthetic_requests'][0].get('model') != 'fixture-b'
                or not isinstance(result.get('second_turn_id'), str)
                or result.get('second_turn', {}).get('status') != 'completed'):
            raise fixture.FixtureError('fixture_failed')
        events = result.get('events')
        if not _valid_second_events(events, frame['thread'], result['second_turn_id']):
            raise fixture.FixtureError('invalid_second_events')
        final_turn = events[-1]['params']['turn']
        observed_turn = result['second_turn']
        if (set(observed_turn) != {'status', 'error_info', 'items'} or observed_turn['error_info'] is not None
                or observed_turn['items'] != final_turn.get('items')):
            raise fixture.FixtureError('invalid_second_events')
        if proc_b.wait(timeout=15) != 0 or not _stopped(docker, b, image, nonce, volumes, 'b', frame['thread']):
            raise fixture.FixtureError('shutdown_uncertain')
        if not _exclusive_volumes(docker, volumes, [a, b]):
            raise fixture.FixtureError('volume_not_exclusive')
        success = True
        preserve_volumes = False
    except fixture.FixtureError:
        raise
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        raise fixture.FixtureError('fixture_failed') from None
    finally:
        for pipe in lines:
            try:
                pipe.close()
            except OSError:
                cleanup_failed = True
        for process in processes:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    cleanup_failed = True
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        cleanup_failed = True
        for ident in containers:
            if preserve_volumes and fence_ready and ident == a:
                continue
            try:
                fixture._command([docker, 'rm', '-fv', ident])
            except fixture.FixtureError:
                cleanup_failed = True
        if not preserve_volumes and not cleanup_failed:
            for name in created_volumes:
                try:
                    fixture._command([docker, 'volume', 'rm', name])
                except fixture.FixtureError:
                    cleanup_failed = True
        if image and image_owned and not (preserve_volumes and fence_ready):
            try:
                fixture._command([docker, 'image', 'rm', image])
            except fixture.FixtureError:
                cleanup_failed = True
        if cleanup_failed:
            raise fixture.FixtureError('cleanup_uncertain')
    if not success:
        raise fixture.FixtureError('fixture_failed')
    terminal = journal.record_controlled_terminal(root, binding, 2, second_revision, 'success')
    if terminal.get('state') != 'succeeded':
        raise fixture.FixtureError('terminal_unrecorded')
    return {'state': 'fixture_succeeded', 'dispatch_permitted': False}
