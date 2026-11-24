"""Offline source facts and fail-closed MCP admission; neither confers authority."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from contextlib import ExitStack
from dataclasses import dataclass
import re

MCP_IDENTITY_UNVERIFIED = (
    'mcp_identity_unverified: external MCP identity is unsupported. '
    'A tool name, policy declaration or operation grant does not prove endpoint provenance.'
)

# References to existing identities and consumers, not another component registry.
# Read only these public source files; never follow config paths or payload values.
_SOURCES = (
    ('.getzilla/config/policy.json', 'tool-policy', 'policy.evaluate_pre_tool', 'declaration'),
    ('.getzilla/config/toolchain.json', 'toolchain', 'toolchain.check_toolchain', 'minimum-and-tested-version'),
    ('.getzilla/config/model-continuation.json', 'model-candidates', 'model_continuation.load_policy', 'declaration'),
    ('.getzilla/config/optional-modules.json', 'optional-modules', 'optional_modules', 'declaration'),
    ('.getzilla/config/skill-catalog.json', 'skill-provenance', 'skill_preflight', 'declaration'),
    ('.getzilla/config/python-test-requirements.txt', 'test-dependencies', 'verification', 'declared-versions'),
    ('.getzilla/config/python-quality-requirements.txt', 'quality-dependencies', 'verification', 'declared-versions'),
    ('factory/src/getzilla_factory/model_rotator_registry.py', 'model-list-provenance', 'model_rotator_registry', 'upstream-commit-and-hashes'),
    ('factory/src/getzilla_factory/landing_http.py', 'provider-profiles', 'landing_live_executors', 'profile-digest-model-aliases-mixed'),
    ('factory/src/getzilla_factory/settings.py', 'credential-contract', 'FactorySettings', 'source-contract-only'),
    ('factory/src/getzilla_factory/service.py', 'factory-stop-authority', 'FactoryService.set_kill', 'source-contract-only'),
    ('trust-ci/scripts/verify-supply-chain.sh', 'deployment-provenance', 'trust-ci-deployment-verifier', 'signed-image-manifest-contract'),
)
_MAX_SOURCE_BYTES = 262_144
_MAX_TOTAL_BYTES = 1_048_576
_PUBLIC_MODES = frozenset({0o444, 0o644, 0o555, 0o755})


class PublicSourceError(ValueError):
    def __init__(self, code='unqualified'):
        super().__init__(code)
        self.code = code


def _source_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _public_file(info, owner):
    return (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) in _PUBLIC_MODES
            and info.st_uid == owner and info.st_nlink == 1)


def read_public_source(root: Path, relative: str, limit: int) -> bytes:
    """Admit source metadata on a stable descriptor before reading and hashing.

    This workflow check rejects known private modes, aliases and changed files.
    It is not OS confinement against a same-UID actor who rewrites all custody.
    Windows POSIX mode/uid fields do not prove ACL custody, so stay unqualified.
    """
    from . import fsx

    if (fsx.WINDOWS or relative not in {entry[0] for entry in _SOURCES}
            or not root.is_absolute() or '..' in root.parts
            or type(limit) is not int or not 0 <= limit <= _MAX_SOURCE_BYTES):
        raise PublicSourceError()
    try:
        source_root = root.lstat()
        if not stat.S_ISDIR(source_root.st_mode) or fsx.is_link(source_root):
            raise PublicSourceError()
        owner = source_root.st_uid  # Actual source-root custody, never request metadata.
        with ExitStack() as stack:
            directory = fsx.open_dir(root.anchor, flags=fsx.O_CLOEXEC)
            stack.callback(fsx.close_dir, directory)
            bindings = []
            for part, inside in [*((part, False) for part in root.parts[1:]),
                                  *((part, True) for part in relative.split('/')[:-1])]:
                parent = directory
                directory = fsx.open_dir_at(parent, part, flags=fsx.O_CLOEXEC)
                stack.callback(fsx.close_dir, directory)
                info = fsx.fstat_dir(directory)
                sticky_system_parent = not inside and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                # Read-only local observation, not authenticated group membership or an ACL proof.
                same_group_directory = not info.st_mode & 0o002 and info.st_gid == source_root.st_gid
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in ({owner} if inside else {0, owner})
                        or (info.st_mode & 0o022 and not (sticky_system_parent or same_group_directory))):
                    raise PublicSourceError()
                bindings.append((parent, part, _directory_identity(info)))
            if _directory_identity(root.lstat()) != _directory_identity(source_root):
                raise PublicSourceError()
            name = relative.rsplit('/', 1)[-1]
            named = fsx.lstat_at(directory, name)
            if not _public_file(named, owner) or named.st_size > limit:
                raise PublicSourceError()
            descriptor = fsx.open_at(directory, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
            stack.callback(os.close, descriptor)
            opened = os.fstat(descriptor)
            identity = _source_identity(opened)

            def unchanged():
                current = os.fstat(descriptor)
                if (not _public_file(current, owner) or _source_identity(current) != identity
                        or _source_identity(fsx.lstat_at(directory, name)) != identity
                        or any(_directory_identity(fsx.lstat_at(parent, part)) != saved
                               for parent, part, saved in bindings)):
                    raise PublicSourceError()

            if not _public_file(opened, owner) or identity != _source_identity(named):
                raise PublicSourceError()
            chunks, total = [], 0
            while True:
                unchanged()
                chunk = os.read(descriptor, min(65_536, limit + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise PublicSourceError()
                chunks.append(chunk)
            unchanged()
            if total != opened.st_size:
                raise PublicSourceError()
            return b''.join(chunks)
    except FileNotFoundError:
        raise PublicSourceError('missing') from None
    except OSError:
        raise PublicSourceError() from None


@dataclass(frozen=True)
class ManagedToolIdentity:
    source_digest: str
    executable_digest: str
    version: str
    dependency_digest: str
    credential_scope_digest: str
    profile: str = 'managed-stdio-v1'


def check_tool_trust(root: Path, event: dict, *, managed_adapter=None) -> tuple[bool, str | None]:
    """Only an actual trusted native call port can qualify managed stdio identity.

    Hook payloads cannot supply the port. Native bypass, disabled modules and
    unsupported remote profiles remain unqualified; credentials are not read.
    """
    name = event.get('tool_name')
    if not isinstance(name, str) or not name.startswith('mcp__'):
        return True, None
    try:
        if managed_adapter is None:
            return False, MCP_IDENTITY_UNVERIFIED
        proof = managed_adapter.attest_tool(root, event)
        if (type(proof) is not ManagedToolIdentity or proof.profile != 'managed-stdio-v1'
                or not isinstance(proof.version, str) or not 1 <= len(proof.version) <= 128
                or any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) for value in
                       (proof.source_digest, proof.executable_digest, proof.dependency_digest, proof.credential_scope_digest))):
            return False, MCP_IDENTITY_UNVERIFIED
        return True, None
    except (ValueError, OSError, AttributeError, TypeError):
        return False, MCP_IDENTITY_UNVERIFIED


def audit(root: Path) -> dict:
    """Hash a closed, bounded source inventory without executing its contents.

    Missing optional/candidate source stays missing. No result establishes
    installed identity, credential scope, current provider version or trust.
    """
    entries = []
    total = 0
    for path, kind, consumer, pin in _SOURCES:
        entry = {'path': path, 'kind': kind, 'consumer': consumer, 'pin_kind': pin,
                 'state': 'unqualified', 'sha256': None, 'bytes': None}
        try:
            raw = read_public_source(root, path, min(_MAX_SOURCE_BYTES, _MAX_TOTAL_BYTES - total))
        except PublicSourceError as error:
            entry['state'] = error.code
        else:
            total += len(raw)
            entry.update(state='observed', sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        entries.append(entry)
    return {
        'schema_version': 1, 'authority': 'none', 'mcp_identity': 'unsupported',
        'credential_scope': 'unverified-source-contract-only',
        'stop_status': 'not_observed', 'sources': entries,
        'audit_complete': all(entry['state'] == 'observed' for entry in entries),
        'source_identity': 'sha256-of-observed-source-bytes',
        'limitations': ['Only closed source paths with public mode, root-owner and single-link metadata are admitted.',
                        'Metadata custody is a local workflow observation, not OS isolation against same-UID or group-writer replacement.',
                        'Windows ACL custody is unsupported and remains unqualified.',
                        'Source declarations do not prove installed tool or endpoint identity.',
                        'Model aliases and upstream model lists do not pin served weights.',
                        'Stop contracts do not prove active-process or remote cancellation.'],
    }
