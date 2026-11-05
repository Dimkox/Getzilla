"""One explicit adapter selection and a conservative file ownership ledger.

Reading never adopts a legacy installation. Directory descriptors and identity
checks detect replaced parents; they do not isolate against a hostile process
running as the same OS user. Windows uses fsx's checked path handles.
"""
from __future__ import annotations

import hashlib
import errno
import json
import math
import os
import re
import stat
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from . import fsx

MANIFEST = '.getzilla/managed-components.json'
V1 = 'getzilla-managed-components-v1'
V2 = 'getzilla-managed-components-v2'
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_FILES = 20_000
STACK_SYNC_RECORD = '.getzilla/AGBP_SYNC.json'
LEGACY_STACK_SYNC_RECORD = '.grok-stack/AGBP_SYNC.json'
MAX_SYNC_RECORD_BYTES = 65536
LEGACY_PATH_RULES = (
    (re.compile(r'^\.grok-stack/adaptive_grok/'), '.getzilla/getzilla/'),
    (re.compile(r'^\.grok-stack/'), '.getzilla/'),
    (re.compile(r'^scripts/grok_([a-z_]+)\.py$'), r'scripts/getzilla_\1.py'),
    (re.compile(r'^factory/src/adaptive_factory/'), 'factory/src/getzilla_factory/'),
    (re.compile(r'^(\.agents|\.grok)/skills/adaptive-delivery/'), r'\1/skills/getzilla-delivery/'),
)
AGENT_COMPONENT_PATHS = {
    'claude': ('.claude/',), 'codex': ('.codex/',), 'qwen': ('.qwen/',),
    'gemini': ('.gemini/',), 'grok': ('.grok/skills/',),
    'copilot': ('.github/hooks/', '.github/agents/'),
    'cursor': ('.cursor/', '.grok/cursor-rules/'),
}
KNOWN_AGENTS = tuple(AGENT_COMPONENT_PATHS)
EXTRA_COMPONENT_PATHS = {
    'entire': ('/integrations/getzilla_entire/',),
    'bitrix': ('/skills/bitrix-development/', '/agents/bitrix_'),
    'seo-landing': ('/skills/seo-landing/',),
}
KNOWN_EXTRAS = tuple(EXTRA_COMPONENT_PATHS)
COMPLIANCE_COMPONENT_PATHS = {
    'eu-ai-act': ('.getzilla/compliance/eu-ai-act/', '.getzilla/templates/eu-ai-act/',
                  'scripts/getzilla_audit_bundle.py', 'scripts/getzilla_compliance.py'),
}
KNOWN_COMPLIANCE = tuple(COMPLIANCE_COMPONENT_PATHS)
COMPONENTS = frozenset({'core', 'factory', *(f'agent:{name}' for name in KNOWN_AGENTS),
                        *(f'extra:{name}' for name in KNOWN_EXTRAS),
                        *(f'compliance:{name}' for name in KNOWN_COMPLIANCE)})


class ComponentStateError(ValueError):
    """Unsafe, ambiguous or unsupported component state; no implicit reset."""


class _FileSnapshotChanged(ComponentStateError):
    """A bounded regular file was atomically replaced; its bytes were discarded."""


def agent_of(path: str) -> str | None:
    if path.startswith('.grok/agents/') and path.endswith('.md'):
        return 'grok'
    return next((name for name, prefixes in AGENT_COMPONENT_PATHS.items() if path.startswith(prefixes)), None)


# Exact siblings used by Factory's published runtime and offline controls. Keep
# their ownership with Factory without publishing unrelated source trees.
FACTORY_SUPPORT_FILES = frozenset({
    'engineering/contracts/openapi/factory-result-admission.v2.json',
    'scripts/getzilla_m8.py',
    'scripts/getzilla_landing_publish.py',
    'delivery/src/getzilla_delivery/landing_filesystem.py',
    'delivery/src/getzilla_delivery/landing_publication.py',
    'delivery/src/getzilla_delivery/landing_publication_contracts.py',
})


def module_name(value: object) -> bool:
    return type(value) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', value) is not None


def module_component(value: object) -> bool:
    return type(value) is str and value.startswith('module:') and module_name(value[7:])


def _module_state(value: object, name: str) -> None:
    fields = {'schema_version', 'version', 'enabled', 'manifest_sha256', 'registry_sha256', 'publisher',
              'license', 'entitlement', 'dependencies', 'permissions', 'grants', 'transaction'}
    if (type(value) is not dict or type(value.get('schema_version')) is not int
            or value['schema_version'] not in (1, 2)
            or set(value) != fields | ({'runtime'} if value['schema_version'] == 2 else set())):
        raise ComponentStateError(f'invalid module state: {name}')
    def version(v):
        return type(v) is str and re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', v) is not None
    def scope(v):
        return type(v) is str and re.fullmatch(r'[a-z][a-z0-9_.:-]{0,127}', v) is not None
    if (not version(value['version']) or type(value['enabled']) is not bool
            or not all(type(value[k]) is str and re.fullmatch('[0-9a-f]{64}', value[k]) for k in ('manifest_sha256', 'registry_sha256'))
            or not module_name(value['publisher']) or type(value['license']) is not str or not scope(value['license'].lower())
            or value['entitlement'] is not None and not scope(value['entitlement'])
            or type(value['dependencies']) is not dict or len(value['dependencies']) > 32
            or any(not module_name(k) or not version(v) for k, v in value['dependencies'].items())
            or type(value['transaction']) is not str or re.fullmatch('[0-9a-f]{32}', value['transaction']) is None):
        raise ComponentStateError(f'invalid module identity: {name}')
    for field in ('permissions', 'grants'):
        items = value[field]
        if type(items) is not list or len(items) > 32 or any(not scope(item) for item in items) or len(set(items)) != len(items):
            raise ComponentStateError(f'invalid module scopes: {name}')
    if (set(value['grants']) != set(value['permissions']) if value['enabled'] else bool(value['grants'])):
        raise ComponentStateError(f'invalid module activation: {name}')
    if value['schema_version'] == 2:
        runtime = value['runtime']
        runtime_fields = {'schema_version', 'state', 'descriptor_sha256', 'generation', 'owner_handle', 'request_digest', 'native_fragments'}
        if (type(runtime) is not dict or set(runtime) != runtime_fields
                or type(runtime['schema_version']) is not int or runtime['schema_version'] != 1
                or type(runtime['state']) is not str
                or runtime['state'] not in {'installed-disabled', 'enabling', 'enabled', 'quiescing', 'disabled-conflict', 'recovery-required'}
                or type(runtime['descriptor_sha256']) is not str or re.fullmatch('[0-9a-f]{64}', runtime['descriptor_sha256']) is None
                or runtime['native_fragments'] != []
                or value['enabled'] != (runtime['state'] == 'enabled')):
            raise ComponentStateError(f'invalid runtime state: {name}')
        if runtime['state'] == 'installed-disabled':
            valid = all(runtime[k] is None for k in ('generation', 'owner_handle', 'request_digest'))
        else:
            valid = (type(runtime['generation']) is str and re.fullmatch('[0-9a-f]{32}', runtime['generation']) is not None
                     and type(runtime['owner_handle']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', runtime['owner_handle']) is not None
                     and type(runtime['request_digest']) is str and re.fullmatch('[0-9a-f]{64}', runtime['request_digest']) is not None)
        if not valid:
            raise ComponentStateError(f'invalid runtime ownership: {name}')


def component_of(path: str) -> str:
    parts = path.split('/')
    if len(parts) >= 4 and parts[:2] == ['.getzilla', 'modules'] and module_name(parts[2]):
        return 'module:' + parts[2]
    if path.startswith('factory/') or path in FACTORY_SUPPORT_FILES:
        return 'factory'
    for name, markers in EXTRA_COMPONENT_PATHS.items():
        if any(marker in '/' + path for marker in markers):
            return f'extra:{name}'
    for name, prefixes in COMPLIANCE_COMPONENT_PATHS.items():
        if path.startswith(prefixes):
            return f'compliance:{name}'
    agent = agent_of(path)
    return f'agent:{agent}' if agent else 'core'


def validate_agents(agents: object) -> tuple[str, ...]:
    if type(agents) not in (list, tuple) or any(type(name) is not str or name not in KNOWN_AGENTS for name in agents):
        raise ComponentStateError('agents must be a list of known adapter names')
    if len(agents) != len(set(agents)):
        raise ComponentStateError('duplicate adapter names are not allowed')
    return tuple(agents)


def parse_agents(value: str) -> tuple[str, ...]:
    """CLI spelling: an empty string means an explicit empty selection."""
    return validate_agents([] if value == '' else [part.strip() for part in value.split(',')])


def path_parts(relative: str) -> tuple[str, ...]:
    if type(relative) is not str or not relative or len(relative) > 4096:
        raise ComponentStateError('invalid component path')
    parts = tuple(relative.split('/'))
    if len(parts) > 64 or any(not part or part in {'.', '..'} or part.endswith((' ', '.'))
                             or any(ord(char) < 32 or char in '\\:' for char in part) for part in parts):
        raise ComponentStateError(f'invalid component path: {relative!r}')
    devices = {'con', 'prn', 'aux', 'nul', *(f'com{number}' for number in range(1, 10)),
               *(f'lpt{number}' for number in range(1, 10))}
    if any(part.split('.')[0].casefold() in devices for part in parts):
        raise ComponentStateError(f'reserved device path: {relative!r}')
    return parts


def _ledger_path(path: str) -> None:
    parts = path_parts(path)
    folded = path.casefold()
    if (parts[0].casefold() == '.git' or folded == MANIFEST
            or folded.startswith('.getzilla/runtime/')
            and path not in {'.getzilla/runtime/.gitignore', '.getzilla/runtime/.gitkeep'}):
        raise ComponentStateError(f'component ledger cannot own {path!r}')


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ComponentStateError(f'duplicate manifest key: {key!r}')
        result[key] = value
    return result


def decode_manifest(content: bytes) -> dict[str, Any]:
    if len(content) > MAX_MANIFEST_BYTES:
        raise ComponentStateError('component manifest exceeds the size limit')
    try:
        data = json.loads(content.decode('utf-8'), object_pairs_hook=_unique)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ComponentStateError(f'invalid component manifest: {exc}') from exc
    if type(data) is not dict or data.get('schema_version') not in (V1, V2):
        raise ComponentStateError('unsupported component manifest schema')
    selected = data['schema_version'] == V2
    if set(data) != {'schema_version', 'components'} | ({'agents'} if selected else set()):
        raise ComponentStateError('unexpected or missing component manifest fields')
    if selected:
        if type(data['agents']) is not list:
            raise ComponentStateError('manifest agents must be an array')
        validate_agents(data['agents'])
    records = data['components']
    if type(records) is not dict or any(name not in COMPONENTS and not module_component(name) for name in records):
        raise ComponentStateError('invalid component records')
    seen: set[str] = set()
    for name, record in records.items():
        is_module = module_component(name)
        fields = {'files', 'added_at', 'source_version'} | ({'owned'} if selected else set()) | ({'module'} if is_module else set())
        if type(record) is not dict or 'files' not in record or not set(record) <= fields:
            raise ComponentStateError(f'invalid record for {name}')
        if is_module:
            if not selected or 'module' not in record:
                raise ComponentStateError('optional modules require selected v2 ownership state')
            _module_state(record['module'], name)
        files = record['files']
        if type(files) is not list or len(files) > MAX_FILES:
            raise ComponentStateError(f'invalid file list for {name}')
        for path in files:
            _ledger_path(path)
            if is_module and component_of(path) != name:
                raise ComponentStateError('module file escapes its owned namespace')
            if path.casefold() in seen:
                raise ComponentStateError(f'duplicate component file: {path}')
            seen.add(path.casefold())
        if len(seen) > MAX_FILES:
            raise ComponentStateError('too many component files')
        for field in ('added_at', 'source_version'):
            if field in record and not (field == 'source_version' and record[field] is None):
                if type(record[field]) is not str or len(record[field]) > 256:
                    raise ComponentStateError(f'invalid {field} for {name}')
        owned = record.get('owned', {})
        if type(owned) is not dict or not set(owned) <= set(files):
            raise ComponentStateError(f'invalid ownership ledger for {name}')
        for path, proof in owned.items():
            if component_of(path) != name or type(proof) is not dict or set(proof) != {'sha256', 'mode'}:
                raise ComponentStateError(f'invalid ownership record: {path}')
            if type(proof['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', proof['sha256']):
                raise ComponentStateError(f'invalid ownership digest: {path}')
            if type(proof['mode']) is not int or not 0 <= proof['mode'] <= 0o777:
                raise ComponentStateError(f'invalid ownership mode: {path}')
    return data


def encode_manifest(manifest: dict[str, Any]) -> bytes:
    data = (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode('utf-8')
    decode_manifest(data)
    return data


def legacy_to_current_path(path: str) -> str:
    """Map an existing pre-rename keep declaration to its current managed path."""
    for pattern, replacement in LEGACY_PATH_RULES:
        matcher = re.compile(pattern.pattern, pattern.flags | re.IGNORECASE) if fsx.WINDOWS else pattern
        mapped, count = matcher.subn(replacement, path)
        if count:
            return mapped
    return path


def decode_keep_contract(content: bytes | None, *, legacy: bool = False) -> tuple[frozenset[str], dict[str, str]]:
    """The existing AGBP_SYNC keep contract, shared by installer and generator."""
    if content is None:
        return frozenset(), {}
    if len(content) > MAX_SYNC_RECORD_BYTES:
        raise ComponentStateError('stack sync record exceeds the size limit')
    try:
        record = json.loads(content.decode('utf-8'), object_pairs_hook=_unique)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ComponentStateError(f'stack sync record is not valid UTF-8 JSON: {exc}') from exc
    if type(record) is not dict or set(record) - {'schema_version', 'kept_local', 'kept_local_sha256'}:
        raise ComponentStateError('stack sync record has unknown shape or keys')
    version = record.get('schema_version', 1)
    if type(version) is not int or version != 1:
        raise ComponentStateError('stack sync record schema_version must be 1')
    paths = record.get('kept_local', [])
    if type(paths) is not list or len(paths) > MAX_FILES:
        raise ComponentStateError('stack sync record kept_local must be a bounded list')
    for path in paths:
        path_parts(path)
    if len({path.casefold() for path in paths}) != len(paths):
        raise ComponentStateError('stack sync record kept_local has duplicates or case aliases')
    digests = record.get('kept_local_sha256', {})
    if type(digests) is not dict or set(digests) - set(paths):
        raise ComponentStateError('stack sync record kept_local_sha256 must map declared paths only')
    if any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None for value in digests.values()):
        raise ComponentStateError('stack sync record kept_local_sha256 has invalid digest')
    if legacy:
        paths = [legacy_to_current_path(path) for path in paths]
        if len({path.casefold() for path in paths}) != len(paths):
            raise ComponentStateError('legacy stack sync record kept_local collides after the Getzilla rename')
        digests = {legacy_to_current_path(path): digest for path, digest in digests.items()}
    return frozenset(paths), dict(digests)


def read_keep_contract(binding: BoundRoot | ComponentTransaction) -> tuple[frozenset[str], dict[str, str]]:
    current = binding.read(STACK_SYNC_RECORD, limit=MAX_SYNC_RECORD_BYTES)
    if current is not None:
        return decode_keep_contract(current.content)
    legacy = binding.read(LEGACY_STACK_SYNC_RECORD, limit=MAX_SYNC_RECORD_BYTES)
    return decode_keep_contract(legacy.content if legacy else None, legacy=True)


def match_kept_local(kept: frozenset[str], digests: dict[str, str], managed: Iterable[str]) -> tuple[frozenset[str], dict[str, str]]:
    """Match Windows path spelling to the exact managed inventory without losing keep intent."""
    if not fsx.WINDOWS:
        return kept, digests
    canonical: dict[str, str] = {}
    for path in managed:
        key = path.casefold()
        if key in canonical and canonical[key] != path:
            raise ComponentStateError('managed inventory contains ambiguous Windows path aliases')
        canonical[key] = path
    mapped = {path: canonical.get(path.casefold(), path) for path in kept}
    return frozenset(mapped.values()), {mapped[path]: digest for path, digest in digests.items()}


def kept_file_state(path: str, current: bytes | None, desired: bytes | None, digest: str | None) -> str:
    """Validate a declared digest before accepting even identical incoming bytes."""
    if current is None:
        return 'absent'
    if digest is not None and hashlib.sha256(current).hexdigest() != digest:
        raise ComponentStateError(f'kept path digest no longer matches its declared divergence: {path}')
    if desired is None:
        return 'unmanaged'
    if current == desired:
        return 'identical'
    if digest is not None:
        return 'divergent'
    raise ComponentStateError(f'kept path conflicts with the stack update, which would change it: {path}')


def validate_manifest_publication(current: FileSnapshot | None, planned: bytes | None,
                                  kept: frozenset[str], digests: dict[str, str]) -> None:
    """Include target-state publication in keep preflight before any product effect."""
    kept, digests = match_kept_local(kept, digests, (MANIFEST,))
    if MANIFEST not in kept:
        return
    kept_file_state(MANIFEST, current.content if current else None, None, digests.get(MANIFEST))
    if planned is not None and (current is None or current.content != planned or not mode_matches(current.mode, 0o644)):
        raise ComponentStateError('kept component manifest would change; reconcile the keep declaration before updating selection or ownership')


@dataclass(frozen=True)
class ManifestState:
    kind: str
    manifest: dict[str, Any]

    @property
    def agents(self) -> tuple[str, ...] | None:
        return tuple(self.manifest['agents']) if self.kind == 'selected' else None

    def require_selection(self) -> tuple[str, ...]:
        if self.agents is None:
            raise ComponentStateError('adapter selection is unresolved; run getzilla components adopt --agents <complete-list> '
                                      '(use --agents \'\' for none), then commit the manifest before updating')
        return self.agents


def mode_matches(actual: int, expected: int) -> bool:
    return bool(actual & stat.S_IWRITE) == bool(expected & stat.S_IWUSR) if fsx.WINDOWS else stat.S_IMODE(actual) == expected


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    mode = (info.st_mode & stat.S_IWRITE) if fsx.WINDOWS else stat.S_IMODE(info.st_mode)
    return (*_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink, mode)


def _guard_identity(info: os.stat_result) -> tuple[int, ...]:
    # A newly created guard can receive its final mode while another writer
    # opens it. Its stable inode, empty content and permissions matter, not ctime.
    mode = (info.st_mode & stat.S_IWRITE) if fsx.WINDOWS else stat.S_IMODE(info.st_mode)
    return (*_identity(info), info.st_size, info.st_nlink, mode, info.st_uid)


@dataclass(frozen=True)
class FileSnapshot:
    content: bytes
    mode: int
    identity: tuple[int, ...]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


class BoundRoot:
    """Hold ancestry from the filesystem anchor; all child access is relative."""

    def __init__(self, root: Path) -> None:
        self.path = Path(fsx.system_canonical(root))
        self._handles: list[fsx.DirHandle] = []
        self._chain: list[tuple[fsx.DirHandle, str, fsx.DirHandle, tuple[int, int, int]]] = []
        try:
            if fsx.WINDOWS:
                info = os.lstat(self.path.anchor)
                if not stat.S_ISDIR(info.st_mode):
                    raise ComponentStateError('filesystem anchor is not a directory')
                anchor: fsx.DirHandle = fsx.WindowsDirectory(self.path.anchor, info)
            else:
                anchor = fsx.open_dir(self.path.anchor, flags=fsx.O_CLOEXEC)
            self._handles.append(anchor)
            self._anchor_identity = _identity(os.lstat(self.path.anchor))
            current = anchor
            for part in self.path.parts[1:]:
                child, identity = self._child(current, part)
                self._handles.append(child)
                self._chain.append((current, part, child, identity))
                current = child
            self.handle = current
            self.check()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _child(parent: fsx.DirHandle, name: str) -> tuple[fsx.DirHandle, tuple[int, int, int]]:
        before = fsx.lstat_at(parent, name)
        if fsx.is_link(before) or not stat.S_ISDIR(before.st_mode):
            raise ComponentStateError(f'unsafe directory: {name}')
        child = fsx.open_dir_at(parent, name, flags=fsx.O_CLOEXEC)
        try:
            if _identity(before) != _identity(fsx.fstat_dir(child)):
                raise ComponentStateError(f'directory changed: {name}')
        except BaseException:
            fsx.close_dir(child)
            raise
        return child, _identity(before)

    @staticmethod
    def _check_chain(chain: list[tuple[fsx.DirHandle, str, fsx.DirHandle, tuple[int, int, int]]]) -> None:
        for parent, name, child, expected in chain:
            try:
                named = fsx.lstat_at(parent, name)
                if fsx.is_link(named) or _identity(named) != expected or _identity(fsx.fstat_dir(child)) != expected:
                    raise ComponentStateError(f'directory binding changed: {name}')
            except OSError as exc:
                raise ComponentStateError(f'directory binding changed: {name}: {exc}') from exc

    def check(self) -> None:
        if _identity(os.lstat(self.path.anchor)) != self._anchor_identity:
            raise ComponentStateError('filesystem anchor changed')
        self._check_chain(self._chain)

    @contextmanager
    def parent(self, relative: str, *, create: bool = False,
               before_write: Callable[[], None] | None = None) -> Iterator[tuple[fsx.DirHandle, str, Any]]:
        parts = path_parts(relative)
        handles: list[fsx.DirHandle] = []
        chain: list[tuple[fsx.DirHandle, str, fsx.DirHandle, tuple[int, int, int]]] = []
        current = self.handle
        def check() -> None:
            self.check()
            self._check_chain(chain)
        try:
            for index, name in enumerate(parts[:-1]):
                check()
                try:
                    child, identity = self._child(current, name)
                except FileNotFoundError:
                    if not create:
                        raise
                    if before_write is not None:
                        before_write()
                    try:
                        mode = 0o700 if parts[:index + 1] == ('.getzilla', 'runtime') else 0o755
                        fsx.mkdir_at(current, name, mode)
                    except FileExistsError:
                        pass
                    child, identity = self._child(current, name)
                handles.append(child)
                chain.append((current, name, child, identity))
                current = child
            check()
            yield current, parts[-1], check
        finally:
            for handle in reversed(handles):
                fsx.close_dir(handle)

    def read(self, relative: str, *, limit: int = MAX_FILE_BYTES) -> FileSnapshot | None:
        found = False
        try:
            with self.parent(relative) as (parent, name, check):
                def changed(message: str, original: os.stat_result, observed: os.stat_result,
                            *, detached: bool = False) -> None:
                    # Only a safe named replacement can warrant a fresh read.
                    # In-place writes, unsafe files and ancestry changes refuse.
                    check()
                    named = fsx.lstat_at(parent, name)
                    allowed_links = (0, 1) if detached else (1,)
                    if (fsx.is_link(named) or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                            or named.st_size > limit or not stat.S_ISREG(observed.st_mode)
                            or observed.st_nlink not in allowed_links or observed.st_size > limit
                            or (named.st_dev, named.st_ino) == (original.st_dev, original.st_ino)):
                        raise ComponentStateError(message)
                    check()
                    raise _FileSnapshotChanged(message)

                before = fsx.lstat_at(parent, name)
                found = True
                if fsx.is_link(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise ComponentStateError(f'expected a regular single-link file: {relative}')
                if before.st_size > limit:
                    raise ComponentStateError(f'file exceeds size limit: {relative}')
                descriptor = fsx.open_at(parent, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
                try:
                    opened = os.fstat(descriptor)
                    if _file_identity(before) != _file_identity(opened):
                        changed(f'file changed while opening: {relative}', before, opened)
                    chunks: list[bytes] = []
                    remaining = limit + 1
                    while remaining:
                        chunk = os.read(descriptor, min(remaining, 65536))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    content = b''.join(chunks)
                    if len(content) > limit:
                        raise ComponentStateError(f'file exceeded size limit: {relative}')
                    after = os.fstat(descriptor)
                    if _file_identity(after) != _file_identity(opened):
                        changed(f'file changed while reading: {relative}', opened, after, detached=True)
                    check()
                    if _file_identity(fsx.lstat_at(parent, name)) != _file_identity(opened):
                        changed(f'file changed while reading: {relative}', opened, after, detached=True)
                    return FileSnapshot(content, stat.S_IMODE(opened.st_mode), _file_identity(opened))
                finally:
                    os.close(descriptor)
        except FileNotFoundError as exc:
            if found:
                raise ComponentStateError(f'file disappeared while reading: {relative}') from exc
            return None
        except OSError as exc:
            raise ComponentStateError(f'cannot safely read {relative}: {exc}') from exc

    def files(self, relative: str, *, recursive: bool = False) -> list[str]:
        """Bounded inventory with no linked directories or special files."""
        path_parts(relative)
        result: list[str] = []
        pending = [relative]
        entries = 0
        while pending:
            directory = pending.pop()
            opened = False
            try:
                with self.parent(directory + '/.inventory') as (parent, _name, check):
                    opened = True
                    with fsx.scandir(parent) as listing:
                        names = []
                        for entry in listing:
                            entries += 1
                            if entries > MAX_FILES:
                                raise ComponentStateError('component source inventory exceeds the entry limit')
                            names.append(entry.name)
                    names.sort()
                    check()
                    for name in names:
                        path = directory + '/' + name
                        path_parts(path)
                        info = fsx.lstat_at(parent, name)
                        if fsx.is_link(info):
                            raise ComponentStateError(f'linked component source: {path}')
                        if stat.S_ISDIR(info.st_mode):
                            if recursive:
                                pending.append(path)
                        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                            result.append(path)
                        else:
                            raise ComponentStateError(f'unsafe component source: {path}')
                    check()
            except FileNotFoundError:
                if opened or directory != relative:
                    raise ComponentStateError(f'component source disappeared: {directory}') from None
                return []
            except OSError as exc:
                raise ComponentStateError(f'cannot inspect component sources: {exc}') from exc
        return sorted(result)

    def write(self, relative: str, content: bytes, mode: int, *, expected: FileSnapshot | None,
              before_publish: Callable[[], None]) -> None:
        """Publish a staged file. An absent target is never overwritten."""
        path_parts(relative)
        if type(content) is not bytes or len(content) > MAX_FILE_BYTES or type(mode) is not int or not 0 <= mode <= 0o777:
            raise ComponentStateError('invalid file publication')
        before_publish()
        with self.parent(relative, create=True, before_write=before_publish) as (parent, name, check):
            temporary = f'.getzilla-component-{uuid.uuid4().hex}.tmp'
            descriptor: int | None = None
            temporary_identity: tuple[int, int, int] | None = None
            try:
                if self.read(relative) != expected:
                    raise ComponentStateError(f'file changed before publication: {relative}')
                descriptor = fsx.open_at(parent, temporary,
                                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW | fsx.O_CLOEXEC, 0o600)
                temporary_identity = _identity(os.fstat(descriptor))
                data = memoryview(content)
                while data:
                    written = os.write(descriptor, data)
                    if written <= 0:
                        raise ComponentStateError(f'incomplete temporary write: {relative}')
                    data = data[written:]
                fsx.fchmod(descriptor, mode)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = None
                check()
                before_publish()
                if self.read(relative) != expected:
                    raise ComponentStateError(f'file changed before publication: {relative}')
                check()
                before_publish()
                if expected is None:
                    # link is atomic no-replace on POSIX and NTFS; the private
                    # temporary name is removed before success is reported.
                    fsx.link_at(parent, temporary, parent, name)
                    fsx.unlink_at(parent, temporary)
                else:
                    fsx.replace_at(parent, temporary, parent, name)
                temporary_identity = None
                fsx.fsync_dir(parent)
                check()
                before_publish()
            except OSError as exc:
                raise ComponentStateError(f'cannot publish {relative}: {exc}') from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if temporary_identity is not None:
                    try:
                        info = fsx.lstat_at(parent, temporary)
                        if _identity(info) == temporary_identity and not fsx.is_link(info):
                            fsx.unlink_at(parent, temporary)
                    except FileNotFoundError:
                        pass

    def remove(self, relative: str, *, expected: FileSnapshot, before_publish: Callable[[], None]) -> None:
        before_publish()
        with self.parent(relative) as (parent, name, check):
            if self.read(relative) != expected:
                raise ComponentStateError(f'file changed before retirement: {relative}')
            check()
            before_publish()
            fsx.unlink_at(parent, name)
            fsx.fsync_dir(parent)
            check()
            before_publish()

    def close(self) -> None:
        for handle in reversed(self._handles):
            fsx.close_dir(handle)
        self._handles.clear()

    def __enter__(self) -> BoundRoot:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def read_state(root: Path, *, binding: BoundRoot | ComponentTransaction | None = None) -> ManifestState:
    if binding is None:
        try:
            with BoundRoot(root) as bound:
                return read_state(root, binding=bound)
        except OSError as exc:
            raise ComponentStateError(f'cannot bind project root: {exc}') from exc
    snapshot = binding.read(MANIFEST, limit=MAX_MANIFEST_BYTES)
    if snapshot is None:
        return ManifestState('absent', {'schema_version': V1, 'components': {}})
    manifest = decode_manifest(snapshot.content)
    return ManifestState('selected' if manifest['schema_version'] == V2 else 'legacy', manifest)


class ComponentTransaction:
    """Cooperative writer boundary; all operations recheck the retained guard."""

    def __init__(self, binding: BoundRoot, guard_check: Callable[[], None]) -> None:
        self.binding = binding
        self.path = binding.path
        self.check = guard_check

    def read(self, relative: str, *, limit: int = MAX_FILE_BYTES) -> FileSnapshot | None:
        self.check()
        result = self.binding.read(relative, limit=limit)
        self.check()
        return result

    def write(self, relative: str, content: bytes, mode: int, *, expected: FileSnapshot | None) -> None:
        self.binding.write(relative, content, mode, expected=expected, before_publish=self.check)

    def remove(self, relative: str, *, expected: FileSnapshot) -> None:
        self.binding.remove(relative, expected=expected, before_publish=self.check)

    def files(self, relative: str, *, recursive: bool = False) -> list[str]:
        self.check()
        result = self.binding.files(relative, recursive=recursive)
        self.check()
        return result


@contextmanager
def component_transaction(root: Path, *, timeout: float = 5.0) -> Iterator[ComponentTransaction]:
    """Serialize component writers; the empty lock file remains after release.

    Validation precedes guard creation. Later refusal can leave administrative
    directories/guard. This is advisory locking, not a multi-file transaction
    or OS isolation against arbitrary Git commands or hostile same-user writes.
    """
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 <= timeout <= 60:
        raise ComponentStateError('component lock timeout must be between 0 and 60 seconds')
    try:
        with BoundRoot(root) as binding:
            for attempt in range(3):
                try:
                    read_state(root, binding=binding)
                    break
                except _FileSnapshotChanged:
                    if attempt == 2:
                        raise
            with binding.parent('.getzilla/runtime/.components.guard.lock', create=True) as (parent, name, parent_check):
                descriptor: int | None = None
                locked = False
                try:
                    try:
                        descriptor = fsx.open_at(parent, name, os.O_RDWR | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW | fsx.O_CLOEXEC, 0o600)
                        fsx.fchmod(descriptor, 0o600)
                    except FileExistsError:
                        before = fsx.lstat_at(parent, name)
                        if fsx.is_link(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                            raise ComponentStateError('unsafe component writer guard')
                        descriptor = fsx.open_at(parent, name, os.O_RDWR | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
                        if _guard_identity(before) != _guard_identity(os.fstat(descriptor)):
                            raise ComponentStateError('component writer guard changed during open')
                    opened = os.fstat(descriptor)
                    uid = fsx.effective_uid()
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size != 0
                            or not mode_matches(opened.st_mode, 0o600)
                            or uid is not None and opened.st_uid != uid):
                        raise ComponentStateError('unsafe component writer guard')
                    identity = _guard_identity(opened)
                    def check() -> None:
                        parent_check()
                        try:
                            named = fsx.lstat_at(parent, name)
                            if fsx.is_link(named) or _guard_identity(named) != identity or _guard_identity(os.fstat(descriptor)) != identity:
                                raise ComponentStateError('component writer guard changed')
                        except OSError as exc:
                            raise ComponentStateError(f'component writer guard changed: {exc}') from exc
                    deadline = time.monotonic() + timeout
                    busy = {errno.EAGAIN, errno.EWOULDBLOCK} | ({errno.EACCES} if fsx.WINDOWS else set())
                    contended = False
                    while True:
                        check()
                        if contended and time.monotonic() >= deadline:
                            raise ComponentStateError('component writer is busy; retry when it finishes')
                        try:
                            fsx.lock_file(descriptor, blocking=False)
                            locked = True
                            break
                        except OSError as exc:
                            if exc.errno not in busy:
                                raise ComponentStateError(f'component lock failed: {exc}') from exc
                            contended = True
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise ComponentStateError('component writer is busy; retry when it finishes') from exc
                            time.sleep(min(0.02, remaining))
                    transaction = ComponentTransaction(binding, check)
                    check()
                    read_state(root, binding=transaction)
                    yield transaction
                    check()
                finally:
                    if descriptor is not None:
                        try:
                            if locked:
                                fsx.unlock_file(descriptor)
                        finally:
                            os.close(descriptor)
    except OSError as exc:
        raise ComponentStateError(f'cannot bind component transaction: {exc}') from exc


def record_owned(manifest: dict[str, Any], path: str, content: bytes, mode: int) -> None:
    """Record only bytes actually published or positively matched to a baseline."""
    _ledger_path(path)
    name = component_of(path)
    record = manifest['components'].setdefault(name, {'files': [], 'owned': {}})
    record['files'] = sorted(set(record['files']) | {path})
    record.setdefault('owned', {})[path] = {'sha256': hashlib.sha256(content).hexdigest(), 'mode': mode}


def owned_proof(manifest: dict[str, Any], path: str) -> dict[str, Any] | None:
    return manifest['components'].get(component_of(path), {}).get('owned', {}).get(path)


def matches_owned(snapshot: FileSnapshot | None, proof: dict[str, Any] | None) -> bool:
    return (snapshot is not None and proof is not None and snapshot.sha256 == proof['sha256']
            and mode_matches(snapshot.mode, proof['mode']))


def fresh_manifest(agents: tuple[str, ...], entries: Any) -> dict[str, Any]:
    manifest: dict[str, Any] = {'schema_version': V2, 'agents': list(validate_agents(agents)), 'components': {}}
    for entry in entries:
        if entry.path != MANIFEST:
            record_owned(manifest, entry.path, entry.content, entry.mode)
    encode_manifest(manifest)
    return manifest
