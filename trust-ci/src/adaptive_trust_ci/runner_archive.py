"""Digest-bound transfer of a linux/amd64 runner to a classic offline daemon."""
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
MANIFESTS = {OCI_MANIFEST, 'application/vnd.docker.distribution.manifest.v2+json'}
INDEXES = {'application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'}
CONFIGS = {'application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'}
LAYERS = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip',
          'application/vnd.docker.image.rootfs.diff.tar.gzip'}
MAX_JSON = 4 << 20
MAX_LAYER = 1 << 30
MAX_TOTAL = 4 << 30


def hex_digest(value):
    if not isinstance(value, str) or not re.fullmatch('sha256:[0-9a-f]{64}', value):
        raise ValueError('missing exact sha256 digest')
    return value[7:]


def _name(key):
    return 'blobs/sha256/' + hex_digest(key)


def _descriptor(entry, allowed, maximum):
    key = entry['digest']
    hex_digest(key)
    size = entry['size']
    if (entry.get('mediaType') not in allowed or type(size) is not int or not 0 < size <= maximum
            or 'urls' in entry or 'data' in entry):
        raise ValueError('unsupported runner blob descriptor')
    return key, size


def _put(tar, name, stream, size):
    info = tarfile.TarInfo(name)
    info.size = size
    tar.addfile(info, stream)


def _transfer(source, output, pin, config_pin, *, docker_format):
    def document(kind, key, size=None):
        with source(kind, key) as f:
            data = f.read(MAX_JSON + 1)
        if (len(data) > MAX_JSON or (size is not None and len(data) != size)
                or hashlib.sha256(data).hexdigest() != hex_digest(key)):
            raise ValueError('runner metadata digest or size mismatch')
        if not docker_format or kind == 'blobs':
            _put(output, _name(key), io.BytesIO(data), len(data))
        return json.loads(data)

    manifest = document('manifests', pin)
    if manifest.get('mediaType') in INDEXES and manifest.get('schemaVersion') == 2:
        choices = [d for d in manifest['manifests'] if d.get('platform') == {'os': 'linux', 'architecture': 'amd64'}]
        if len(choices) != 1:
            raise ValueError('expected exactly one linux/amd64 image')
        key, size = _descriptor(choices[0], MANIFESTS, MAX_JSON)
        manifest = document('manifests', key, size)
    if manifest.get('mediaType') not in MANIFESTS or manifest.get('schemaVersion') != 2:
        raise ValueError('unsupported runner manifest')
    key, size = _descriptor(manifest['config'], CONFIGS, MAX_JSON)
    if key != config_pin:
        raise ValueError('manifest config does not match policy')
    config = document('blobs', key, size)
    if (config.get('os'), config.get('architecture')) != ('linux', 'amd64'):
        raise ValueError('wrong runner platform')
    layers = manifest['layers']
    if not isinstance(layers, list) or not 1 <= len(layers) <= 128:
        raise ValueError('invalid runner layer count')
    members = []
    written = set()
    total = 0
    for layer in layers:
        key, size = _descriptor(layer, LAYERS, MAX_LAYER)
        members.append(_name(key))
        if key in written:
            continue
        written.add(key)
        total += size
        if total > MAX_TOTAL:
            raise ValueError('runner exceeds transfer limit')
        with source('blobs', key) as stream:
            reader = _HashReader(stream)
            _put(output, _name(key), reader, size)
            if stream.read(1) or reader.digest.hexdigest() != hex_digest(key):
                raise ValueError('runner layer digest or size mismatch')
    if docker_format:
        data = json.dumps([dict(Config=_name(config_pin), Layers=members, RepoTags=[])]).encode()
        _put(output, 'manifest.json', io.BytesIO(data), len(data))


class _HashReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()

    def read(self, count):
        data = self.stream.read(count)
        self.digest.update(data)
        return data


def fetch_archive(source, manifest, config, destination):
    destination = Path(destination)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
        name = stream.name
    try:
        with tarfile.open(name, 'w', format=tarfile.USTAR_FORMAT) as tar:
            _transfer(source, tar, manifest, config, docker_format=False)
        os.chmod(name, 0o444)
        os.replace(name, destination)
    finally:
        Path(name).unlink(missing_ok=True)


def load_archive(path, manifest, config, docker=subprocess.run):
    # Docker only sees a privately staged, reconstructed archive. An input tag,
    # extra image, alternate manifest or changed layer can never reach load.
    if Path(path).stat().st_size > MAX_TOTAL + 4 * MAX_JSON:
        raise ValueError('runner archive exceeds limit')
    with tempfile.TemporaryFile() as staged, tarfile.open(path, 'r|') as bundle:
        @contextmanager
        def source(kind, key):
            member = bundle.next()
            maximum = MAX_JSON if kind == 'manifests' or key == config else MAX_LAYER
            if (member is None or member.type != tarfile.REGTYPE or member.name != _name(key)
                    or not 0 < member.size <= maximum):
                raise ValueError('unexpected runner archive member')
            with bundle.extractfile(member) as stream:
                yield stream

        with tarfile.open(fileobj=staged, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            _transfer(source, tar, manifest, config, docker_format=True)
        if bundle.next() is not None:
            raise ValueError('unexpected additional runner archive members')
        staged.seek(0)
        docker(['docker', 'load'], stdin=staged, check=True, timeout=600)
        result = docker(['docker', 'image', 'inspect', '--format', '{{.Id}}', config],
                        check=True, text=True, capture_output=True, timeout=30)
        if result.stdout != config + '\n':
            raise ValueError('loaded runner ID differs from signed config digest')
