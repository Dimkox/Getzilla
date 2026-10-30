"""Network-isolated Codex observation. This never authorizes live dispatch."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import tempfile
from pathlib import Path
from contextlib import ExitStack, contextmanager

from . import controlled_fixture as fixture
from . import fenced_fixture as fence
from . import model_continuation_state as journal
from . import fsx
from .codex_continuation import MAX_FRAME, OwnedJsonlPeer, ProtocolError


@contextmanager
def _operation(root):
    """Serialize allocation, recovery, close and cleanup across processes."""
    if fsx.WINDOWS:
        raise ProtocolError('durability_unsupported')
    try:
        with ExitStack() as stack:
            directory = fsx.open_dir(root)
            stack.callback(fsx.close_dir, directory)
            for name in ('.getzilla', 'runtime', 'model-continuation'):
                child = fsx.open_dir_at(directory, name)
                stack.callback(fsx.close_dir, child)
                if journal._identity(fsx.lstat_at(directory, name)) != journal._identity(fsx.fstat_dir(child)):
                    raise ProtocolError('directory_replaced')
                directory = child
            info = fsx.fstat_dir(directory)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ProtocolError('unsafe_directory')
            fd = fsx.open_at(directory, 'native-operation.lock', os.O_RDWR | os.O_CREAT | fsx.O_NOFOLLOW, 0o600)
            stack.callback(os.close, fd)
            journal._regular(os.fstat(fd))
            if journal._identity(os.fstat(fd)) != journal._identity(fsx.lstat_at(directory, 'native-operation.lock')):
                raise ProtocolError('lock_replaced')
            try:
                fsx.lock_file(fd, blocking=False)
            except BlockingIOError:
                raise ProtocolError('native_busy') from None
            stack.callback(fsx.unlock_file, fd)
            yield
    except OSError:
        raise ProtocolError('lock_unavailable') from None


def _docker():
    executable = shutil.which('docker', path='/usr/bin:/bin')
    if not executable:
        raise ProtocolError('container_unavailable')
    return executable


def _volumes(nonce):
    return ['getzilla-native-' + nonce + '-state', 'getzilla-native-' + nonce + '-work']


def _name(nonce, role):
    return 'getzilla-native-' + nonce + '-' + role


def _helper(docker, image, volumes, nonce, program, *, root=False):
    mounts = [part for name, target in zip(volumes, ('/state', '/work'))
              for part in ('--mount', 'type=volume,src=' + name + ',dst=' + target + ('' if root else ',readonly'))]
    args = [docker, 'create', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--name', _name(nonce, 'helper'), '--label', 'getzilla.owner=' + nonce,
            '--label', 'getzilla.native.role=helper', '--security-opt', 'no-new-privileges',
            '--pids-limit', '64', '--memory', '512m', '--cpus', '2']
    if root:
        args += ['--cap-add', 'CHOWN']
    args += ['--user', '0' if root else '65534:65534', *mounts, '--entrypoint', 'python', image, '-c', program]
    ident = fixture._command(args)
    if not re.fullmatch(r'[a-f0-9]{64}', ident):
        raise ProtocolError('container_unverified')
    try:
        return fixture._command([docker, 'start', '-a', ident], timeout=60)
    finally:
        fixture._command([docker, 'rm', '-fv', ident])


def _build(docker, codex, script, nonce):
    staging = fixture._command([docker, 'create', '--pull', 'never', '--network', 'none',
                                '--name', _name(nonce, 'staging'), '--label', 'getzilla.owner=' + nonce,
                                '--label', 'getzilla.native.role=staging', fixture.IMAGE])
    if not re.fullmatch(r'[a-f0-9]{64}', staging):
        raise ProtocolError('container_unverified')
    try:
        with tempfile.TemporaryDirectory() as temp:
            script_copy, codex_copy = Path(temp) / 'script', Path(temp) / 'codex'
            shutil.copyfile(script, script_copy)
            shutil.copyfile(codex, codex_copy)
            script_copy.chmod(0o644)
            codex_copy.chmod(0o755)
            fixture._command([docker, 'cp', str(script_copy), staging + ':/fixture.py'])
            fixture._command([docker, 'cp', str(codex_copy), staging + ':/fixture-codex'])
        image = fixture._command([docker, 'commit', '--change', 'LABEL getzilla.owner=' + nonce,
                                  '--change', 'LABEL getzilla.native.role=image', staging, 'getzilla-native-' + nonce + ':work'])
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
            raise ProtocolError('image_unverified')
    finally:
        fixture._command([docker, 'rm', '-fv', staging])
    program = ("import hashlib; from pathlib import Path; "
               "print(hashlib.sha256(Path('/fixture.py').read_bytes()).hexdigest()); "
               "print(hashlib.sha256(Path('/fixture-codex').read_bytes()).hexdigest())")
    if _helper(docker, image, [], nonce, program).splitlines() != [fixture.FIXTURE_SHA256, fixture.CODEX_SHA256]:
        raise ProtocolError('image_unverified')
    return image


def _validate(docker, record, *, stopped=False):
    ident, nonce = record['container_id'], record['owner_nonce']
    image, volumes = 'sha256:' + record['image_id'], _volumes(nonce)
    try:
        info = fence._inspect(docker, ident)
        host, config, mounts = info['HostConfig'], info['Config'], info['Mounts']
        expected = dict(zip(('/tmp/codex', '/work'), volumes))
        valid = (info['Id'] == ident and info['Image'] == image
                 and info['Name'] == '/' + _name(nonce, 'main')
                 and config['Labels'].get('getzilla.owner') == nonce
                 and config['Labels'].get('getzilla.native.role') == 'main'
                 and config['User'] == '65534:65534' and config['Entrypoint'] == ['/fixture-codex']
                 and config['Cmd'] == ['app-server'] and host['NetworkMode'] == 'none'
                 and host['ReadonlyRootfs'] is True and host['Privileged'] is False
                 and host['CapDrop'] == ['ALL'] and host.get('CapAdd') in (None, [])
                 and host.get('Devices') in (None, []) and host.get('DeviceRequests') in (None, [])
                 and host.get('VolumesFrom') in (None, [])
                 and host['RestartPolicy'] == {'Name': 'no', 'MaximumRetryCount': 0}
                 and host['PidsLimit'] == 64 and host['Memory'] == 536870912 and host['NanoCpus'] == 2000000000
                 and host['SecurityOpt'] == ['no-new-privileges']
                 and host['Tmpfs'] == {'/tmp': 'rw,nosuid,nodev,size=64m,mode=1777'}
                 and host['PidMode'] in ('', 'private') and host['IpcMode'] in ('', 'private')
                 and isinstance(mounts, list) and len(mounts) == 2
                 and all(m['Type'] == 'volume' and m['RW'] is True
                         and expected.get(m['Destination']) == m['Name'] for m in mounts)
                 and len({m['Destination'] for m in mounts}) == 2)
        env = config['Env']
        allowed = fixture._ENV_KEYS - {'GETZILLA_CONTROLLED_GATE', 'GETZILLA_FIXTURE_NONCE'}
        valid = (valid and isinstance(env, list)
                 and all(isinstance(item, str) and '=' in item and item.split('=', 1)[0] in allowed for item in env))
        values = dict(item.split('=', 1) for item in env)
        valid = valid and len(values) == len(env) and values.get('HOME') == '/tmp' and values.get('CODEX_HOME') == '/tmp/codex'
        if stopped:
            valid = valid and fixture._container_stopped(info, ident, image, nonce)
        if not valid or not fence._exclusive_volumes(docker, volumes, [ident]):
            raise ProtocolError('container_unverified')
        for name in volumes:
            volume = json.loads(fixture._command([docker, 'volume', 'inspect', name]))
            if len(volume) != 1 or volume[0]['Name'] != name or volume[0]['Labels'].get('getzilla.owner') != nonce:
                raise ProtocolError('container_unverified')
        return volumes
    except (KeyError, TypeError, ValueError, fixture.FixtureError):
        raise ProtocolError('container_unverified') from None


def _digest_checkpoint(docker, image, volumes, nonce):
    first = _helper(docker, image, volumes, nonce, fence._SCAN).splitlines()
    if (len(first) != 2 or any(not re.fullmatch(r'[a-f0-9]{64}', item) for item in first)
            or first != _helper(docker, image, volumes, nonce, fence._SCAN).splitlines()):
        raise ProtocolError('checkpoint_changed')
    return hashlib.sha256(''.join(first).encode('ascii')).hexdigest()


class NativePeer(OwnedJsonlPeer):
    def __init__(self, process, timeout, root, binding, generation, revision, record):
        super().__init__(process, timeout)
        self._root, self._binding, self._generation = root, binding, generation
        self._revision, self._record = revision, record

    async def close(self):
        with _operation(self._root):
            return await self._close_owned()

    async def _close_owned(self):
        docker = _docker()
        try:
            volumes = _validate(docker, self._record)
            state = journal.inspect_chain(self._root, self._binding)
            pending = journal.record_native_phase(self._root, self._binding, self._generation, state['revision'],
                                                   self._record['container_id'], 'checkpoint_start')
            if pending['state'] != 'checkpoint_started':
                raise ProtocolError('journal_denied')
            fixture._command([docker, 'stop', '--time', '3', self._record['container_id']], timeout=15)
            await asyncio.wait_for(self._process.wait(), self._timeout)
            _validate(docker, self._record, stopped=True)
            digest = _digest_checkpoint(docker, 'sha256:' + self._record['image_id'], volumes, self._record['owner_nonce'])
            _validate(docker, self._record, stopped=True)
            state = journal.inspect_chain(self._root, self._binding)
            current = journal.inspect_native_container(self._root, self._binding, state['revision'], self._generation)
            if current['container_id'] != self._record['container_id']:
                raise ProtocolError('container_unverified')
            result = journal.record_native_checkpoint(self._root, self._binding, self._generation,
                                                      state['revision'], self._record['container_id'], digest)
            if result['state'] != 'checkpoint_recorded':
                raise ProtocolError('journal_denied')
            return result
        finally:
            self._process._transport.close()


async def start(root, binding, generation, revision, *, timeout=10):
    with _operation(root):
        return await _start(root, binding, generation, revision, timeout=timeout)


async def _start(root, binding, generation, revision, *, timeout=10):
    docker = _docker()
    codex = shutil.which('codex')
    script = Path(__file__).resolve().parents[2] / 'tests/fixtures/codex_loopback_probe.py'
    if not codex or not script.is_file() or not 0 < timeout <= 60:
        raise ProtocolError('invalid_configuration')
    codex = Path(codex).resolve()
    with codex.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != fixture.CODEX_SHA256:
            raise ProtocolError('codex_unqualified')
    nonce = secrets.token_hex(16)
    claim = journal.claim_native_start(root, binding, generation, revision, nonce)
    if not claim['claimed']:
        raise ProtocolError('journal_denied')
    image = _build(docker, codex, script, nonce)
    volumes = _volumes(nonce)
    for volume in volumes:
        if fixture._command([docker, 'volume', 'create', '--label', 'getzilla.owner=' + nonce, volume]) != volume:
            raise ProtocolError('container_unverified')
    _helper(docker, image, volumes, nonce, "import os; os.chown('/state',65534,65534); os.chown('/work',65534,65534)", root=True)
    args = [docker, 'create', '-i', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--name', _name(nonce, 'main'), '--label', 'getzilla.owner=' + nonce,
            '--label', 'getzilla.native.role=main', '--restart', 'no', '--security-opt', 'no-new-privileges',
            '--pids-limit', '64', '--memory', '512m', '--cpus', '2', '--user', '65534:65534',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m,mode=1777', *fence._mounts(volumes),
            '-e', 'HOME=/tmp', '-e', 'CODEX_HOME=/tmp/codex', '--entrypoint', '/fixture-codex', image, 'app-server']
    ident = fixture._command(args)
    if not re.fullmatch(r'[a-f0-9]{64}', ident):
        raise ProtocolError('container_unverified')
    record = {'container_id': ident, 'image_id': image[7:], 'owner_nonce': nonce}
    _validate(docker, record)
    result = journal.record_native_container(root, binding, generation, claim['revision'], ident, image[7:], nonce)
    if result['state'] != 'container_recorded':
        raise ProtocolError('journal_denied')
    _validate(docker, record)
    process = await asyncio.create_subprocess_exec(docker, 'start', '-ai', ident, stdin=asyncio.subprocess.PIPE,
                                                   stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                                                   limit=MAX_FRAME + 1, env={'PATH': '/usr/bin:/bin'})
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        if fence._inspect(docker, ident).get('State', {}).get('Running') is True:
            break
        if process.returncode is not None or asyncio.get_running_loop().time() >= deadline:
            raise ProtocolError('operation_unknown')
        await asyncio.sleep(0.05)
    started = journal.record_native_phase(root, binding, generation, result['revision'], ident, 'started')
    if started['state'] != 'native_started':
        raise ProtocolError('journal_denied')
    return NativePeer(process, timeout, root, binding, generation, started['revision'], record)


def recover(root, binding, generation, revision):
    with _operation(root):
        return _recover(root, binding, generation, revision)


def _recover(root, binding, generation, revision):
    docker = _docker()
    record = journal.inspect_native_container(root, binding, revision, generation)
    chain = journal.inspect_chain(root, binding)
    if 'started_' + str(generation) not in chain['events']:
        raise ProtocolError('operation_unknown')
    if ('checkpoint_start_' + str(generation) in chain['events'] and record['checkpoint_digest'] is None):
        raise ProtocolError('operation_unknown')
    volumes = _validate(docker, record)
    if record['checkpoint_digest'] is None:
        pending = journal.record_native_phase(root, binding, generation, revision, record['container_id'], 'checkpoint_start')
        if pending['state'] != 'checkpoint_started':
            raise ProtocolError('journal_denied')
        revision = pending['revision']
        fixture._command([docker, 'stop', '--time', '3', record['container_id']], timeout=15)
    _validate(docker, record, stopped=True)
    digest = _digest_checkpoint(docker, 'sha256:' + record['image_id'], volumes, record['owner_nonce'])
    _validate(docker, record, stopped=True)
    if record['checkpoint_digest'] is None:
        result = journal.record_native_checkpoint(root, binding, generation, revision, record['container_id'], digest)
        if result['state'] != 'checkpoint_recorded':
            raise ProtocolError('journal_denied')
        revision = result['revision']
    elif digest != record['checkpoint_digest']:
        raise ProtocolError('checkpoint_changed')
    return {'state': 'container_stopped', 'revision': revision, 'dispatch_permitted': False}


def cleanup(root, binding, generation, revision):
    with _operation(root):
        return _cleanup(root, binding, generation, revision)


def _cleanup(root, binding, generation, revision):
    docker = _docker()
    chain = journal.inspect_chain(root, binding)
    if ('started_' + str(generation) not in chain['events']
            or ('checkpoint_start_' + str(generation) in chain['events']
                and 'checkpoint_' + str(generation) not in chain['events'])):
        raise ProtocolError('operation_unknown')
    transition = journal.claim_native_cleanup(root, binding, generation, revision)
    if transition['state'] != 'cleanup_started':
        raise ProtocolError('journal_denied')
    intent = journal.inspect_native_intent(root, binding, generation)
    nonce = intent['owner_nonce']
    chain = journal.inspect_chain(root, binding)
    recorded = chain['events'].get('container_' + str(generation), {}).get('evidence', {})
    for role in ('helper', 'staging', 'main'):
        name = _name(nonce, role)
        containers = fixture._command([docker, 'ps', '-a', '--no-trunc', '--filter',
                                       'name=^/' + name + '$', '--format', '{{.ID}}']).splitlines()
        if len(containers) > 1:
            raise ProtocolError('container_unverified')
        for ident in containers:
            if role != 'main' or not recorded:
                raise ProtocolError('resource_identity_unknown')
            if not re.fullmatch(r'[a-f0-9]{64}', ident):
                raise ProtocolError('container_unverified')
            info = fence._inspect(docker, ident)
            labels = info.get('Config', {}).get('Labels') or {}
            if (info.get('Id') != ident or info.get('Name') != '/' + name
                    or (role == 'main' and recorded and recorded.get('container_id') != ident)
                    or labels.get('getzilla.owner') != nonce or labels.get('getzilla.native.role') != role):
                raise ProtocolError('container_unverified')
            fixture._command([docker, 'rm', '-f', ident])
    listed = fixture._command([docker, 'volume', 'ls', '--filter', 'label=getzilla.owner=' + nonce,
                              '--format', '{{.Name}}']).splitlines()
    if any(name not in _volumes(nonce) for name in listed) or len(set(listed)) != len(listed):
        raise ProtocolError('volume_unverified')
    for name in listed:
        details = json.loads(fixture._command([docker, 'volume', 'inspect', name]))
        if len(details) != 1 or details[0].get('Name') != name or (details[0].get('Labels') or {}).get('getzilla.owner') != nonce:
            raise ProtocolError('volume_unverified')
    images = fixture._command([docker, 'image', 'ls', '--no-trunc', '--filter', 'label=getzilla.owner=' + nonce,
                               '--format', '{{.ID}}']).splitlines()
    expected_image = 'sha256:' + recorded['image_id']
    for image in set(images):
        if image != expected_image:
            continue
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
            raise ProtocolError('image_unverified')
        details = json.loads(fixture._command([docker, 'image', 'inspect', image]))
        if (len(details) != 1 or details[0].get('Id') != image
                or (details[0].get('Config', {}).get('Labels') or {}).get('getzilla.owner') != nonce):
            raise ProtocolError('image_unverified')
        fixture._command([docker, 'image', 'rm', image])
    if listed:
        raise ProtocolError('manual_volume_cleanup_required')
