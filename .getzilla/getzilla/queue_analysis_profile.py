"""Reviewed, source-bound resource profiles; proof rules are unchanged."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import NamedTuple

from .architecture import ArchitectureError
from . import fsx

POLICY_PATH = 'architecture/queue-analysis-profile.json'
SELF_ANCHOR = 'e99548d7cefca730cfad63c2f8cea1afe67bacd8'
POLICY_SOURCE = b'{"schema_version":1,"profile":"getzilla-self-v1","repository":"Dimkox/Getzilla"}\n'


class QueueAnalysisProfile(NamedTuple):
    name: str
    module_limit: int
    byte_limit: int
    source_digest: str
    binding: str = ''
    node_limit: int = 400_000
    depth_limit: int = 8


CONSUMER_PROFILE = QueueAnalysisProfile('consumer-v1', 64, 2097152, '')
GETZILLA_SELF_PROFILE = QueueAnalysisProfile('getzilla-self-v1', 128, 4194304,
                                            hashlib.sha256(POLICY_SOURCE).hexdigest(),
                                            node_limit=600_000, depth_limit=16)


def _select_profile(root: Path, diff, side: str) -> QueueAnalysisProfile:
    """A copied declaration alone grants no larger analysis resource budget."""
    from .architecture_diff import _GitOperation, _git
    root = Path(root).resolve(strict=True)
    with fsx.ReadOnlyBoundRoot(root) as owner:
        observed = owner.read(POLICY_PATH, limit=4096)
        if observed is None:
            return CONSUMER_PROFILE
        with _GitOperation(root) as scope:
            revision = 'HEAD' if side == 'head' else diff.base_sha
            raw = observed.content
            if raw != POLICY_SOURCE:
                raise ArchitectureError('queue analysis source policy differs from reviewed policy', code='fitness')
            head = _git(root, ['rev-parse', '--verify', 'HEAD^{commit}'], limit=128, _scope=scope)
            input_revision = (head if side == 'head' else _git(
                root, ['rev-parse', '--verify', revision + '^{commit}'], limit=128, _scope=scope))
            ancestry = _git(root, ['merge-base', '--all', SELF_ANCHOR, 'HEAD'],
                            allow_failure=True, limit=128, _scope=scope)
            if head is None or ancestry != (SELF_ANCHOR + '\n').encode():
                raise ArchitectureError('queue self profile requires exact Getzilla source ancestry', code='fitness')
            if owner.read(POLICY_PATH, limit=4096) != observed:
                raise ArchitectureError('queue analysis source policy changed', code='fitness')
            scope.check()
            identity = hashlib.sha256(str(root).encode() + b'\0' + side.encode() + b'\0' + head + input_revision + raw).hexdigest()
            return GETZILLA_SELF_PROFILE._replace(binding=identity)


def select_profile(root: Path, diff, side: str) -> QueueAnalysisProfile:
    try:
        return _select_profile(root, diff, side)
    except (OSError, fsx.ComponentStateError) as error:
        raise ArchitectureError('queue analysis source policy custody unavailable', code='io') from error
