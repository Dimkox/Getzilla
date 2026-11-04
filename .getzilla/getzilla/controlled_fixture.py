"""Run a fixed, synthetic Codex fixture in a network-isolated container.

This is not a live adapter and never grants live dispatch authority. A failed
or interrupted run leaves the host journal consumed and cannot be replayed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from . import model_continuation_state as journal
from .codex_continuation import TurnObserver
from .model_continuation import load_policy

IMAGE = 'sha256:623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487'
CONTRACT_SHA256 = 'd08934d1aa8e857c34e21b3c7ac8fb89c822a9c35f224876678c1ca5a7ce4e3e'
CODEX_SHA256 = 'c06a67fd8ac76508dc78bd99ce20c9f317b8d568beda59485f3f4134df9962d5'
FIXTURE_SHA256 = '5fba526ae5fc2f899db04961029b0c632ebc928630a959ca9568b1e135c38080'
MAX_FRAME = 65536
# This is a private tmpfs inside the verified isolated container, not a host path.
CONTAINER_TMP = '/tmp'  # nosec B108
_ENV_KEYS = frozenset({'PATH', 'LANG', 'GPG_KEY', 'PYTHON_VERSION', 'PYTHON_SHA256',
                       'HOME', 'CODEX_HOME', 'GETZILLA_CONTROLLED_GATE', 'GETZILLA_FIXTURE_NONCE'})


class FixtureError(ValueError):
    """Fixed diagnostic; never include process output or filesystem paths."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError('invalid_frame')
        result[key] = value
    return result


def _container_stopped(info, container_id, image, nonce):
    """Confirm the owned container is stopped; external effects remain unknown."""
    try:
        state = info['State']
        return (info['Id'] == container_id and info['Image'] == image
                and info['Config']['Labels'].get('getzilla.owner') == nonce
                and state['Running'] is False and state['Restarting'] is False
                and state['Dead'] is False and state['Status'] == 'exited'
                and type(state['Pid']) is int and state['Pid'] == 0)
    except (KeyError, TypeError, AttributeError):
        return False


def _reject_constant(_):
    raise FixtureError('invalid_frame')


def _validate_container(info, image, mounts, nonce):
    try:
        host, config = info['HostConfig'], info['Config']
        if (info['Image'] != image or config['User'] != '65534:65534' or config.get('Entrypoint') not in (None, [])
                or config['Cmd'] != ['python', '-u', '/fixture.py']
                or host['NetworkMode'] != 'none' or host['ReadonlyRootfs'] is not True
                or host['Privileged'] is not False or host['CapDrop'] != ['ALL'] or host.get('CapAdd') not in (None, [])
                or host['PidsLimit'] != 64 or host['Memory'] != 536870912 or host['NanoCpus'] != 2000000000
                or host.get('CpusetCpus') != _cpu_set()
                or host.get('Devices') not in (None, []) or host.get('DeviceRequests') not in (None, [])
                or host.get('VolumesFrom') not in (None, [])
                or host['Tmpfs'] != {CONTAINER_TMP: 'rw,nosuid,nodev,size=64m,mode=1777',
                                     '/work': 'rw,nosuid,nodev,size=64m,mode=1777'}
                or host['SecurityOpt'] != ['no-new-privileges']
                or host['PidMode'] not in ('', 'private') or host['IpcMode'] not in ('', 'private')):
            return False
        env = config['Env']
        if not isinstance(env, list) or any(not isinstance(item, str) or '=' not in item or item.split('=', 1)[0] not in _ENV_KEYS for item in env):
            return False
        values = dict(item.split('=', 1) for item in env)
        if (len(values) != len(env) or values.get('HOME') != CONTAINER_TMP or values.get('CODEX_HOME') != CONTAINER_TMP + '/codex'
                or values.get('GETZILLA_CONTROLLED_GATE') != '1' or values.get('GETZILLA_FIXTURE_NONCE') != nonce):
            return False
        actual = info['Mounts']
        if not isinstance(actual, list) or len(actual) != len(mounts):
            return False
        return (len({item['Destination'] for item in actual}) == len(mounts)
                and all(item['Type'] == 'bind' and item['RW'] is False
                        and mounts.get(item['Destination']) == item['Source'] for item in actual))
    except (KeyError, TypeError, ValueError):
        return False


def _command(args, timeout=60):
    try:
        with tempfile.TemporaryFile() as output:
            subprocess.run(_docker_argv(args), stdin=subprocess.DEVNULL, stdout=output,
                           stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin'},
                           timeout=timeout, check=True)
            output.seek(0)
            data = output.read(MAX_FRAME + 1)
        if len(data) > MAX_FRAME:
            raise FixtureError('oversized_output')
        return data.decode('utf-8').strip()
    except subprocess.TimeoutExpired:
        raise FixtureError('container_timeout') from None
    except subprocess.CalledProcessError:
        raise FixtureError('container_command_failed') from None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise FixtureError('container_unavailable') from None


def _docker_argv(args):
    # Ignore saved Docker contexts as well as endpoint environment selectors.
    return [args[0], '--host', 'unix:///var/run/docker.sock', *args[1:]]


def _cpu_set():
    available = set(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else set(range(os.cpu_count() or 0))
    value = os.environ.get('GETZILLA_FIXTURE_CPUSET', ','.join(map(str, sorted(available)[:2])))
    if not re.fullmatch(r'[0-9]+,[0-9]+', value):
        raise FixtureError('fixture_cpu_unavailable')
    chosen = [int(item) for item in value.split(',')]
    if len(set(chosen)) != 2 or not set(chosen) <= available:
        raise FixtureError('fixture_cpu_unavailable')
    return ','.join(map(str, sorted(chosen)))


def _image_contract():
    folder = Path(__file__).resolve().parents[2] / 'tests/fixtures'
    try:
        with (folder/'codex-fixture-contract.json').open('rb') as handle:
            raw = handle.read(65537)
        if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != CONTRACT_SHA256:
            raise FixtureError('image_contract_unqualified')
        contract = json.loads(raw, object_pairs_hook=_pairs)
        with (folder/'codex-fixture.Dockerfile').open('rb') as handle:
            recipe = handle.read(8193)
        if (len(recipe) > 8192 or hashlib.sha256(recipe).hexdigest() != contract['dockerfile_sha256']
                or contract['base_image_id'] != IMAGE or contract['base_reference'] != 'python@'+IMAGE
                or contract['codex_sha256'] != CODEX_SHA256 or contract['fixture_sha256'] != FIXTURE_SHA256):
            raise FixtureError('image_contract_unqualified')
        return contract, recipe
    except (OSError, KeyError, ValueError, TypeError):
        raise FixtureError('image_contract_unqualified') from None


def _base_image(docker, contract):
    try:
        info = json.loads(_command([docker, 'image', 'inspect', contract['base_reference']]))
        if (not isinstance(info, list) or len(info) != 1 or info[0]['Id'] != IMAGE
                or contract['base_reference'] not in info[0]['RepoDigests']
                or (info[0]['Os'], info[0]['Architecture']) != ('linux', 'amd64')):
            raise FixtureError('base_image_unqualified')
    except (KeyError, TypeError, ValueError):
        raise FixtureError('base_image_unqualified') from None


def _bound_image(docker, image, contract, owner=None):
    try:
        info = json.loads(_command([docker, 'image', 'inspect', image]))
        labels = info[0]['Config']['Labels']
        if (len(info) != 1 or info[0]['Id'] != image or not re.fullmatch(r'sha256:[a-f0-9]{64}', image)
                or (info[0]['Os'], info[0]['Architecture']) != ('linux', 'amd64')
                or labels['getzilla.fixture.contract'] != CONTRACT_SHA256
                or labels['getzilla.fixture.base'] != contract['base_image_id']
                or not re.fullmatch(r'[a-f0-9]{32}', labels['getzilla.fixture'])
                or owner is not None and labels['getzilla.fixture'] != owner):
            raise FixtureError('image_mismatch')
        return True
    except (IndexError, KeyError, TypeError, ValueError):
        raise FixtureError('image_mismatch') from None


def _owned_image(docker, image, owner):
    try:
        info = json.loads(_command([docker, 'image', 'inspect', image]))
        return len(info) == 1 and info[0]['Id'] == image and info[0]['Config']['Labels']['getzilla.fixture'] == owner
    except (FixtureError, KeyError, IndexError, TypeError, ValueError):
        return False


def _copy_input(source, destination, expected, error):
    try:
        descriptor = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as handle, destination.open('xb') as output:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 512*1024*1024:
                raise FixtureError(error)
            digest = hashlib.sha256()
            count = 0
            while data := handle.read(65536):
                count += len(data)
                if count > 512*1024*1024:
                    raise FixtureError(error)
                digest.update(data)
                output.write(data)
            if count != info.st_size or digest.hexdigest() != expected:
                raise FixtureError(error)
        destination.chmod(0o555 if error == 'codex_unqualified' else 0o444)
        os.utime(destination, (0, 0))
    except OSError:
        raise FixtureError(error) from None


def _immutable_image(docker, fixture, codex):
    """Build a closed offline recipe, then bind its observed ID and exact inputs."""
    checker = None
    image = None
    accepted = False
    owner = secrets.token_hex(16)
    contract, recipe = _image_contract()
    try:
        with tempfile.TemporaryDirectory(prefix='getzilla-fixture-build-') as temporary:
            folder = Path(temporary)
            context = folder/'context'
            context.mkdir(mode=0o700)
            _copy_input(codex, context/'fixture-codex', CODEX_SHA256, 'codex_unqualified')
            _copy_input(fixture, context/'fixture.py', FIXTURE_SHA256, 'fixture_unqualified')
            (context/'Dockerfile').write_bytes(recipe)
            source = Path(__file__).resolve().parents[2]/'tests/fixtures/codex-fixture-contract.json'
            _copy_input(source, context/'fixture-contract.json', CONTRACT_SHA256, 'image_contract_unqualified')
            os.utime(context/'Dockerfile', (0, 0))
            _base_image(docker, contract)
            identity = folder/'image-id'
            _command([docker, 'build', '--builder', 'default', '--quiet', '--pull=false', '--network=none', '--platform', 'linux/amd64',
                      '--build-arg', 'SOURCE_DATE_EPOCH=0', '--label', 'getzilla.fixture='+owner,
                      '--label', 'getzilla.fixture.contract='+CONTRACT_SHA256,
                      '--label', 'getzilla.fixture.base='+IMAGE, '--iidfile', str(identity),
                      '--file', str(context/'Dockerfile'), str(context)], timeout=180)
            with identity.open('r', encoding='ascii') as handle:
                image = handle.read(128).strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
            raise FixtureError('invalid_image')
        _bound_image(docker, image, contract, owner)
        program = ('import hashlib; from pathlib import Path; '
                   'import platform; print(platform.python_version()); '
                   "print(hashlib.sha256(Path('/fixture-contract.json').read_bytes()).hexdigest()); "
                   "print(hashlib.sha256(Path('/fixture.py').read_bytes()).hexdigest()); "
                   "print(hashlib.sha256(Path('/fixture-codex').read_bytes()).hexdigest())")
        checker = _command([docker, 'create', '--pull', 'never', '--network', 'none', '--read-only',
                            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64',
                            '--memory', '512m', '--cpus', '2', '--cpuset-cpus', _cpu_set(),
                            '--user', '65534:65534', '--label', 'getzilla.owner='+owner,
                            '--entrypoint', 'python', image, '-c', program])
        if not re.fullmatch(r'[a-f0-9]{64}', checker):
            raise FixtureError('invalid_container')
        hashes = _command([docker, 'start', '-a', checker], timeout=60).splitlines()
        if hashes != [contract['python_version'], CONTRACT_SHA256, FIXTURE_SHA256, CODEX_SHA256]:
            raise FixtureError('image_mismatch')
        accepted = True
        return image
    finally:
        cleanup_failed = False
        for container in (checker,):
            if isinstance(container, str) and re.fullmatch(r'[a-f0-9]{64}', container):
                try:
                    _command([docker, 'rm', '-fv', container])
                except FixtureError:
                    cleanup_failed = True
        if (not accepted or cleanup_failed) and isinstance(image, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', image):
            if not _owned_image(docker, image, owner):
                cleanup_failed = True
            else:
                try:
                    _command([docker, 'image', 'rm', image])
                except FixtureError:
                    cleanup_failed = True
        if cleanup_failed:
            raise FixtureError('cleanup_uncertain') from None


class _Lines:
    def __init__(self, process):
        self.process = process
        self.buffer = b''
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ)

    def read(self, timeout=45):
        deadline = time.monotonic() + timeout
        while b'\n' not in self.buffer:
            if not self.selector.select(max(0, deadline - time.monotonic())):
                raise FixtureError('fixture_timeout')
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise FixtureError('fixture_closed')
            self.buffer += chunk
            if len(self.buffer) > MAX_FRAME:
                raise FixtureError('oversized_output')
        line, self.buffer = self.buffer.split(b'\n', 1)
        try:
            value = json.loads(line, object_pairs_hook=_pairs, parse_constant=_reject_constant)
        except (ValueError, UnicodeError):
            raise FixtureError('invalid_frame') from None
        if not isinstance(value, dict):
            raise FixtureError('invalid_frame')
        return value

    def allow(self, nonce):
        try:
            self.process.stdin.write((json.dumps({'allow': True, 'nonce': nonce}, separators=(',', ':')) + '\n').encode())
            self.process.stdin.flush()
        except (OSError, ValueError):
            raise FixtureError('fixture_closed') from None

    def respond(self, nonce, status, content_type, body):
        if (status not in (200, 429) or content_type not in ('application/json', 'text/event-stream')
                or not isinstance(body, str)):
            raise FixtureError('invalid_frame')
        frame = json.dumps({'allow': True, 'nonce': nonce, 'status': status,
                            'content_type': content_type, 'body': body}, separators=(',', ':')) + '\n'
        if len(frame.encode('utf-8')) > MAX_FRAME:
            raise FixtureError('oversized_output')
        try:
            self.process.stdin.write(frame.encode('utf-8'))
            self.process.stdin.flush()
        except (OSError, ValueError):
            raise FixtureError('fixture_closed') from None

    def close(self):
        self.selector.close()


def _first_valid(frame, nonce):
    try:
        info = frame['first']['error_info']
        items = frame['first']['items']
        valid = (set(frame) == {'type', 'version', 'nonce', 'thread', 'turn', 'first', 'retry_flags', 'item_types', 'server_requests', 'events'}
                and frame['type'] == 'before_b' and type(frame['version']) is int and frame['version'] == 1 and frame['nonce'] == nonce
                and isinstance(frame['thread'], str) and bool(frame['thread']) and isinstance(frame['turn'], str) and bool(frame['turn'])
                and frame['first']['status'] == 'failed' and isinstance(info, dict)
                and set(info) == {'responseTooManyFailedAttempts'}
                and set(info['responseTooManyFailedAttempts']) == {'httpStatusCode'}
                and type(info['responseTooManyFailedAttempts']['httpStatusCode']) is int
                and info['responseTooManyFailedAttempts']['httpStatusCode'] == 429
                and frame['retry_flags'] == [False] and type(frame['retry_flags'][0]) is bool and frame['server_requests'] == []
                and isinstance(frame['item_types'], list) and all(t in ('userMessage', 'agentMessage', 'reasoning') for t in frame['item_types'])
                and isinstance(items, list) and all(isinstance(item, dict) and item.get('type') in ('userMessage', 'agentMessage', 'reasoning') for item in items)
                and isinstance(frame['events'], list) and len(frame['events']) <= 128)
        if not valid:
            return False
        observer = TurnObserver(frame['thread'], frame['turn'])
        for event in frame['events']:
            observer.observe(event)
        terminal = [event for event in frame['events'] if isinstance(event, dict) and event.get('method') == 'turn/completed']
        return (observer.eligible and len(terminal) == 1 and frame['events'][-1] is terminal[0]
                and json.dumps(observer._error, sort_keys=True) == json.dumps(info, sort_keys=True)
                and json.dumps(terminal[0]['params']['turn']['error']['codexErrorInfo'], sort_keys=True) == json.dumps(info, sort_keys=True))
    except (KeyError, TypeError, ValueError):
        return False


def _second_valid(events, thread, turn):
    """Accept only correlated, effect-free success notifications."""
    from .codex_continuation import _GLOBAL_ADVISORY, _global_advisory
    complete = False
    started = False
    for event in events:
        if complete:
            return False
        if not isinstance(event, dict) or 'id' in event or not isinstance(event.get('params'), dict):
            return False
        method, params = event.get('method'), event['params']
        if not isinstance(method, str):
            return False
        if method in _GLOBAL_ADVISORY:
            if not _global_advisory(method, params):
                return False
        elif method in ('warning', 'thread/status/changed'):
            if (params.get('threadId') != thread or (method == 'warning' and not isinstance(params.get('message'), str))
                    or (method == 'thread/status/changed' and not isinstance(params.get('status'), dict))):
                return False
        elif method == 'thread/tokenUsage/updated':
            if not started or params.get('threadId') != thread or params.get('turnId') != turn or not isinstance(params.get('tokenUsage'), dict):
                return False
        elif method in ('item/started', 'item/completed'):
            item = params.get('item')
            if (not started or params.get('threadId') != thread or params.get('turnId') != turn or not isinstance(item, dict)
                    or item.get('type') not in ('userMessage', 'agentMessage', 'reasoning')):
                return False
        elif method in ('turn/started', 'turn/completed'):
            current = params.get('turn')
            if (params.get('threadId') != thread or not isinstance(current, dict) or current.get('id') != turn
                    or current.get('status') != ('inProgress' if method == 'turn/started' else 'completed')):
                return False
            if method == 'turn/completed':
                if not started or complete or current.get('error') is not None or not isinstance(current.get('items'), list):
                    return False
                if any(not isinstance(item, dict) or item.get('type') not in ('userMessage', 'agentMessage', 'reasoning') for item in current['items']):
                    return False
                complete = True
            else:
                if started:
                    return False
                started = True
        else:
            return False
    return complete


def run(root: Path, binding: journal.Binding, budget: journal.TaskBudget) -> dict:
    """Run the fixed local fixture once. No input or credentials enter the container."""
    docker = shutil.which('docker', path='/usr/bin:/bin')
    codex = shutil.which('codex')
    fixture = Path(__file__).resolve().parents[2] / 'tests/fixtures/codex_loopback_probe.py'
    if not docker or not codex or not fixture.is_file():
        raise FixtureError('fixture_unavailable')
    policy = load_policy(root).policy
    if (policy is None or not policy.enabled or len(policy.candidates) != 2
            or [candidate.model for candidate in policy.candidates] != ['fixture-a', 'fixture-b']
            or any(candidate.provider != 'local_fixture' or candidate.account_ref != 'synthetic' for candidate in policy.candidates)):
        raise FixtureError('fixture_policy_invalid')
    codex = str(Path(codex).resolve())
    try:
        with open(codex, 'rb') as executable:
            if hashlib.file_digest(executable, 'sha256').hexdigest() != CODEX_SHA256:
                raise FixtureError('codex_unqualified')
    except OSError:
        raise FixtureError('fixture_unavailable') from None
    nonce = secrets.token_hex(16)
    try:
        journal.create_controlled_chain(root, binding, journal.Usage(1, '0'), budget)
    except journal.JournalError:
        raise FixtureError('fixture_failed') from None
    image = _immutable_image(docker, fixture, codex)
    mounts = {}
    args = [docker, 'create', '-i', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--label', 'getzilla.owner=' + nonce,
            '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '512m',
            '--cpus', '2', '--cpuset-cpus', _cpu_set(), '--user', '65534:65534', '--tmpfs', CONTAINER_TMP + ':rw,nosuid,nodev,size=64m,mode=1777',
            '--tmpfs', '/work:rw,nosuid,nodev,size=64m,mode=1777', '-e', 'HOME=' + CONTAINER_TMP, '-e', 'CODEX_HOME=' + CONTAINER_TMP + '/codex',
            '-e', 'GETZILLA_CONTROLLED_GATE=1', '-e', 'GETZILLA_FIXTURE_NONCE=' + nonce,
            image, 'python', '-u', '/fixture.py']
    try:
        container_id = _command(args)
    except FixtureError:
        _command([docker, 'image', 'rm', image])
        raise
    if not re.fullmatch(r'[a-f0-9]{64}', container_id):
        _command([docker, 'image', 'rm', image])
        raise FixtureError('invalid_container')
    process = None
    lines = None
    success = False
    try:
        info = json.loads(_command([docker, 'inspect', container_id]))
        if not isinstance(info, list) or len(info) != 1 or not _validate_container(info[0], image, mounts, nonce):
            raise FixtureError('invalid_container')
        first = journal.consume_controlled_send(root, binding, 1, 1)
        if not first['claimed']:
            raise FixtureError('claim_denied')
        process = subprocess.Popen(_docker_argv([docker, 'start', '-ai', container_id]), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env={'PATH': '/usr/bin:/bin'}, bufsize=0)
        lines = _Lines(process)
        if lines.read() != {'type': 'before_a', 'version': 1, 'nonce': nonce}:
            raise FixtureError('invalid_frame')
        if journal.check_controlled_send(root, binding, 1, first['revision']) is not None:
            raise FixtureError('claim_denied')
        lines.allow(nonce)
        frame = lines.read()
        if not _first_valid(frame, nonce):
            raise FixtureError('unreconciled_effect')
        terminal = journal.record_controlled_terminal(root, binding, 1, first['revision'], 'rate_limit')
        reserved = journal.reserve_controlled_next(root, binding, terminal['revision'], journal.Usage(1, '0'))
        if reserved.get('state') != 'reserved_unknown':
            raise FixtureError('budget_denied')
        second = journal.consume_controlled_send(root, binding, 2, reserved['revision'])
        if not second['claimed']:
            raise FixtureError('claim_denied')
        if journal.check_controlled_send(root, binding, 2, second['revision']) is not None:
            raise FixtureError('claim_denied')
        lines.allow(nonce)
        result = lines.read()
        requests = result.get('synthetic_requests')
        allowed_methods = {'configWarning', 'remoteControl/status/changed', 'thread/started', 'warning',
                           'thread/status/changed', 'turn/started', 'item/started', 'item/completed',
                           'thread/tokenUsage/updated', 'account/rateLimits/updated', 'error', 'turn/completed'}
        events = result.get('events')
        if (type(result.get('version')) is not int or result['version'] != 1 or result.get('nonce') != nonce
                or result.get('thread') != frame['thread'] or result.get('turn') != frame['turn']
                or not isinstance(result.get('second_turn_id'), str) or not result['second_turn_id']
                or not isinstance(events, list) or len(events) > 128 or events[:len(frame['events'])] != frame['events']
                or result.get('second_turn', {}).get('status') != 'completed' or result.get('request_count') != 2
                or not isinstance(requests, list) or len(requests) != 2
                or [item.get('model') for item in requests] != ['fixture-a', 'fixture-b']
                or result.get('server_requests') != [] or not isinstance(result.get('event_methods'), list)
                or any(method not in allowed_methods for method in result['event_methods'])
                or not isinstance(result.get('item_types'), list)
                or any(item not in ('userMessage', 'agentMessage', 'reasoning') for item in result['item_types'])
                or not isinstance(result['second_turn'].get('items'), list)
                or any(not isinstance(item, dict) or item.get('type') not in ('userMessage', 'agentMessage', 'reasoning')
                       for item in result['second_turn']['items'])):
            raise FixtureError('fixture_failed')
        second_events = events[len(frame['events']):]
        if not _second_valid(second_events, frame['thread'], result['second_turn_id']):
            raise FixtureError('fixture_failed')
        if process.wait(timeout=15) != 0:
            raise FixtureError('fixture_failed')
        stopped = json.loads(_command([docker, 'inspect', container_id]))
        if (not isinstance(stopped, list) or len(stopped) != 1
                or not _container_stopped(stopped[0], container_id, image, nonce)
                or not _validate_container(stopped[0], image, mounts, nonce)):
            raise FixtureError('shutdown_uncertain')
        success = True
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        raise FixtureError('fixture_failed') from None
    finally:
        if lines is not None:
            lines.close()
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                success = False
        if process is not None:
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        success = False
        for args in ([docker, 'rm', '-fv', container_id], [docker, 'image', 'rm', image]):
            try:
                _command(args, timeout=15)
            except FixtureError:
                success = False
    if not success:
        raise FixtureError('cleanup_uncertain')
    terminal = journal.record_controlled_terminal(root, binding, 2, second['revision'], 'success')
    if terminal.get('state') != 'succeeded':
        raise FixtureError('terminal_unrecorded')
    return {'state': 'fixture_succeeded', 'dispatch_permitted': False}


def run_fenced(root: Path, binding: journal.Binding, budget: journal.TaskBudget) -> dict:
    """Run the two-container synthetic fixture; never authorizes live dispatch."""
    from .fenced_fixture import run as run_two_containers
    return run_two_containers(root, binding, budget)
