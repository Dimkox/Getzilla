"""Network-isolated Codex observation. This never authorizes live dispatch."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import shutil
from pathlib import Path

from . import controlled_fixture as fixture
from . import fenced_fixture as fence
from . import model_continuation_state as journal
from .codex_continuation import MAX_FRAME, OwnedJsonlPeer, ProtocolError


def _docker():
    executable = shutil.which('docker', path='/usr/bin:/bin')
    if not executable:
        raise ProtocolError('container_unavailable')
    return executable


def _volumes(nonce):
    return ['getzilla-native-' + nonce + '-state', 'getzilla-native-' + nonce + '-work']


def _validate(docker, record, *, stopped=False):
    ident, nonce = record['container_id'], record['owner_nonce']
    image, volumes = 'sha256:' + record['image_id'], _volumes(nonce)
    try:
        info = fence._inspect(docker, ident)
        host, config, mounts = info['HostConfig'], info['Config'], info['Mounts']
        expected = dict(zip(('/tmp/codex', '/work'), volumes))
        valid = (info['Id'] == ident and info['Image'] == image
                 and config['Labels'].get('getzilla.owner') == nonce
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


def _digest_checkpoint(docker, image, volumes):
    first = fence._checkpoint(docker, image, volumes)
    if first != fence._checkpoint(docker, image, volumes):
        raise ProtocolError('checkpoint_changed')
    return hashlib.sha256(''.join(first).encode('ascii')).hexdigest()


class NativePeer(OwnedJsonlPeer):
    def __init__(self, process, timeout, root, binding, generation, revision, record):
        super().__init__(process, timeout)
        self._root, self._binding, self._generation = root, binding, generation
        self._revision, self._record = revision, record

    async def close(self):
        docker = _docker()
        try:
            volumes = _validate(docker, self._record)
            fixture._command([docker, 'stop', '--time', '3', self._record['container_id']], timeout=15)
            await asyncio.wait_for(self._process.wait(), self._timeout)
            _validate(docker, self._record, stopped=True)
            digest = _digest_checkpoint(docker, 'sha256:' + self._record['image_id'], volumes)
            _validate(docker, self._record, stopped=True)
            return journal.record_native_checkpoint(self._root, self._binding, self._generation,
                                                    self._revision, self._record['container_id'], digest)
        finally:
            self._process._transport.close()


async def start(root, binding, generation, revision, *, timeout=10):
    docker = _docker()
    codex = shutil.which('codex')
    script = Path(__file__).resolve().parents[2] / 'tests/fixtures/codex_loopback_probe.py'
    if not codex or not script.is_file() or not 0 < timeout <= 60:
        raise ProtocolError('invalid_configuration')
    codex = Path(codex).resolve()
    with codex.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != fixture.CODEX_SHA256:
            raise ProtocolError('codex_unqualified')
    image = fixture._immutable_image(docker, script, str(codex))
    nonce = secrets.token_hex(16)
    volumes = _volumes(nonce)
    for volume in volumes:
        if fixture._command([docker, 'volume', 'create', '--label', 'getzilla.owner=' + nonce, volume]) != volume:
            raise ProtocolError('container_unverified')
    fence._helper(docker, image, volumes, "import os; os.chown('/state',65534,65534); os.chown('/work',65534,65534)", root=True)
    args = [docker, 'create', '-i', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--label', 'getzilla.owner=' + nonce, '--restart', 'no', '--security-opt', 'no-new-privileges',
            '--pids-limit', '64', '--memory', '512m', '--cpus', '2', '--user', '65534:65534',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m,mode=1777', *fence._mounts(volumes),
            '-e', 'HOME=/tmp', '-e', 'CODEX_HOME=/tmp/codex', '--entrypoint', '/fixture-codex', image, 'app-server']
    ident = fixture._command(args)
    if not re.fullmatch(r'[a-f0-9]{64}', ident):
        raise ProtocolError('container_unverified')
    record = {'container_id': ident, 'image_id': image[7:], 'owner_nonce': nonce}
    _validate(docker, record)
    result = journal.record_native_container(root, binding, generation, revision, ident, image[7:], nonce)
    if result['state'] != 'container_recorded':
        raise ProtocolError('journal_denied')
    _validate(docker, record)
    process = await asyncio.create_subprocess_exec(docker, 'start', '-ai', ident, stdin=asyncio.subprocess.PIPE,
                                                   stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                                                   limit=MAX_FRAME + 1, env={'PATH': '/usr/bin:/bin'})
    return NativePeer(process, timeout, root, binding, generation, result['revision'], record)


def recover(root, binding, generation, revision):
    docker = _docker()
    record = journal.inspect_native_container(root, binding, revision, generation)
    volumes = _validate(docker, record)
    if record['checkpoint_digest'] is None:
        fixture._command([docker, 'stop', '--time', '3', record['container_id']], timeout=15)
    _validate(docker, record, stopped=True)
    digest = _digest_checkpoint(docker, 'sha256:' + record['image_id'], volumes)
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
    recover(root, binding, generation, revision)
    docker = _docker()
    record = journal.inspect_native_container(root, binding, revision, generation)
    fixture._command([docker, 'rm', record['container_id']])
    for volume in _volumes(record['owner_nonce']):
        fixture._command([docker, 'volume', 'rm', volume])
    fixture._command([docker, 'image', 'rm', 'sha256:' + record['image_id']])
