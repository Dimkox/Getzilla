"""Closed declarations for the opt-in Linux local-static preview profile."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass

PROFILE = 'linux-local-static-v1'
LIMITS = {'artifact_bytes': 2 * 1024 * 1024, 'file_bytes': 256 * 1024, 'files': 64,
          'requests': 256, 'served_bytes': 8 * 1024 * 1024, 'request_bytes': 1024,
          'io_seconds': .25, 'cpu_seconds': 2, 'memory_bytes': 128 * 1024 * 1024,
          'descriptors': 32, 'output_bytes': 0, 'concurrency': 1, 'spend': 0}
CAPABILITIES = {'static': 'local-profile', 'public-hosting': 'unsupported',
                'web-api': 'unsupported', 'worker': 'unsupported', 'database': 'unsupported'}
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}\Z')
_HEX = re.compile(r'[0-9a-f]{64}\Z')


class PreviewError(RuntimeError):
    """Fixed safe reason code; never includes artifact data."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def artifact(files):
    if type(files) is not dict or not 1 <= len(files) <= LIMITS['files']:
        raise PreviewError('artifact_limits')
    owned, total = {}, 0
    for name, content in files.items():
        if (type(name) is not str or len(name) > 160 or not re.fullmatch(r'[A-Za-z0-9_./-]+', name)
                or any(part in ('', '.', '..') for part in name.split('/'))):
            raise PreviewError('artifact_path')
        if type(content) is not bytes or len(content) > LIMITS['file_bytes']:
            raise PreviewError('artifact_limits')
        total += len(content)
        if total > LIMITS['artifact_bytes']:
            raise PreviewError('artifact_limits')
        owned[name] = content
    if 'index.html' not in owned:
        raise PreviewError('artifact_index_missing')
    return owned, digest({name: hashlib.sha256(value).hexdigest() for name, value in owned.items()})


@dataclass(frozen=True)
class PreviewManifest:
    schema_version: int
    profile: str
    tenant: str
    project: str
    repository: str
    task: str
    run: str
    owner: str
    authority_epoch: int
    context_revision: int
    source_sha: str
    source_tree: str
    artifact_digest: str
    config_digest: str
    runtime_digest: str
    build_digest: str
    dependency_digest: str
    dataset_digest: str
    budget_ref: str
    generation: int
    key: str
    ttl: int = 60

    def validate(self):
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise PreviewError('manifest_version')
        if self.profile != PROFILE:
            raise PreviewError('unsupported_profile')
        for field in ('tenant', 'project', 'repository', 'task', 'run', 'owner', 'budget_ref', 'key'):
            if type(getattr(self, field)) is not str or not _ID.fullmatch(getattr(self, field)):
                raise PreviewError('manifest_identity')
        for field in ('artifact_digest', 'config_digest', 'runtime_digest', 'build_digest', 'dependency_digest', 'dataset_digest'):
            if type(getattr(self, field)) is not str or not _HEX.fullmatch(getattr(self, field)):
                raise PreviewError('manifest_digest')
        for field in ('source_sha', 'source_tree'):
            if type(getattr(self, field)) is not str or not re.fullmatch(r'[0-9a-f]{40}', getattr(self, field)):
                raise PreviewError('manifest_source')
        for field, low, high in (('ttl', 1, 300), ('generation', 1, 2**31), ('authority_epoch', 0, 2**31), ('context_revision', 0, 2**31)):
            value = getattr(self, field)
            if type(value) is not int or not low <= value <= high:
                raise PreviewError('manifest_limits')
        if self.config_digest != digest({'limits': LIMITS, 'capabilities': CAPABILITIES}):
            raise PreviewError('manifest_config')
        if (self.build_digest != digest({'mode': 'prebuilt-static', 'artifact': self.artifact_digest})
                or self.dependency_digest != digest([]) or self.dataset_digest != digest(None)):
            raise PreviewError('unsupported_dependencies')

    @property
    def identity(self):
        self.validate()
        return digest(asdict(self))
