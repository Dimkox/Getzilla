"""Fixed upstream-generated assets: no installer execution on consumer machines."""
from __future__ import annotations

import io
import csv
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import STACK_DIR, state
from .component_state import BoundRoot, ComponentStateError, component_transaction, mode_matches, path_parts
from .policy import evaluate_pre_tool
from .skill_preflight import canonical, digest, parse_json
from .skill_sandbox import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, OUTPUT_PREFIXES

MAX_MANIFEST_BYTES = 524288
_AGENTS = {'claude', 'codex', 'qwen', 'gemini', 'grok', 'copilot'}
ENGINE_ARCHIVE = '.getzilla/getzilla.zip'
BLOB_PREFIX = '.getzilla/templates/baseline/blobs/'
ARCHIVE_LIMIT = 16 * 1024 * 1024


def archive_entries(raw: bytes) -> dict[str, tuple[bytes, int]]:
    """Decode the existing source container; no extraction or code execution."""
    if type(raw) is not bytes or len(raw) > ARCHIVE_LIMIT:
        raise ValueError('ASSET_ARCHIVE_BOUNDS')
    result, total = {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if not 1 <= len(archive.infolist()) <= MAX_FILES:
                raise ValueError('ASSET_ARCHIVE_BOUNDS')
            for member in archive.infolist():
                name = member.filename
                path_parts(name)
                logical = '.getzilla/' + name
                resource = re.fullmatch(r'templates/baseline/blobs/([a-f0-9]{64})\.txt', name)
                code = re.fullmatch(r'getzilla/(?:[A-Za-z_][A-Za-z0-9_]*/)*[A-Za-z_][A-Za-z0-9_]*\.py', name)
                mode = member.external_attr >> 16
                if (not (resource or code) or '\\' in name or logical in result or member.is_dir()
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or stat.S_IMODE(mode) != 0o644
                        or member.flag_bits & 1 or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or member.file_size > MAX_FILE_BYTES):
                    raise ValueError('UNSAFE_ASSET_ARCHIVE_MEMBER')
                total += member.file_size
                if total > ARCHIVE_LIMIT:
                    raise ValueError('ASSET_ARCHIVE_BOUNDS')
                with archive.open(member) as stream:
                    body = stream.read(MAX_FILE_BYTES + 1)
                if len(body) != member.file_size or resource and digest(body) != resource[1]:
                    raise ValueError('ASSET_ARCHIVE_HASH')
                if b'\0' in body:
                    raise ValueError('UNSAFE_ASSET_ARCHIVE_MEMBER')
                body.decode('utf-8')
                result[logical] = (body, 0o644)
    except (OSError, zipfile.BadZipFile, UnicodeError, RuntimeError) as exc:
        raise ValueError('INVALID_ASSET_ARCHIVE') from exc
    return result


def read_archive(binding: BoundRoot):
    """Keep the descriptor-bound container snapshot paired with its actual members."""
    snapshot = binding.read(ENGINE_ARCHIVE, limit=ARCHIVE_LIMIT)
    if snapshot is None:
        return None
    if snapshot.mode & 0o111:
        raise ValueError('UNSAFE_ASSET_ARCHIVE')
    entries = archive_entries(snapshot.content)
    if binding.read(ENGINE_ARCHIVE, limit=ARCHIVE_LIMIT) != snapshot:
        raise ValueError('ASSET_ARCHIVE_CHANGED')
    return snapshot, entries


def validate_resources(entries, read):
    """All configured manifests must have their complete closed resource set."""
    packed = {path: body for path, (body, _mode) in entries.items() if path.startswith(BLOB_PREFIX)}
    config = parse_json(read('.getzilla/config/toolchain.json'), limit=1048576)
    expected = {}
    for component in config['workflow_sources']['components']:
        for record in component['generated_assets'].values():
            if not re.fullmatch(r'\.getzilla/templates/baseline/[a-z0-9-]+\.json', record['path']):
                raise ValueError('INVALID_ASSET_CONFIG')
            raw = read(record['path'])
            if digest(raw) != record['sha256']:
                raise ValueError('ASSET_HASH_MISMATCH')
            metadata = parse_json(raw, limit=MAX_MANIFEST_BYTES)
            for item in metadata['files']:
                if not re.fullmatch('[a-f0-9]{64}', item['sha256']):
                    raise ValueError('INVALID_ASSET_CONFIG')
                path = BLOB_PREFIX + item['sha256'] + '.txt'
                if path in expected and expected[path] != item['bytes']:
                    raise ValueError('ASSET_CONTENT_MISMATCH')
                expected[path] = item['bytes']
    if not packed:
        # Legacy Python-only containers are valid only with the complete loose
        # resource closure. An empty set is not proof of unrelated content.
        packed = {path: read(path) for path in expected}
        entries = {path: (body, 0o644) for path, body in packed.items()}
    if (set(expected) != set(packed)
            or any(len(packed[path]) != size or digest(packed[path]) != path[len(BLOB_PREFIX):-4]
                   or not mode_matches(entries[path][1], 0o644) for path, size in expected.items())):
        raise ValueError('INCOMPLETE_ASSET_ARCHIVE')


@dataclass(frozen=True)
class AssetPayload:
    component: str
    agent: str
    asset_digest: str
    files: tuple[tuple[str, bytes, int], ...]
    semantic_safety_qualified: bool = False
    permissions_granted: bool = False


def load(component: str, agent: str, *, windows=False, source_root: Path | None = None) -> AssetPayload:
    source_root = STACK_DIR.parent if source_root is None else source_root
    try:
        with BoundRoot(source_root) as binding:
            archived = read_archive(binding)
            if archived is not None:
                def read_metadata(path):
                    file = binding.read(path, limit=MAX_FILE_BYTES if path.startswith(BLOB_PREFIX) else 1048576)
                    if file is None:
                        raise ValueError('MISSING_ASSET_MANIFEST')
                    if path.startswith(BLOB_PREFIX) and not mode_matches(file.mode, 0o644):
                        raise ValueError('ASSET_MODE_MISMATCH')
                    return file.content
                validate_resources(archived[1], read_metadata)
            raw_config = binding.read('.getzilla/config/toolchain.json', limit=1048576)
            if raw_config is None:
                raise ValueError('MISSING_ASSET_CONFIG')
            config = parse_json(raw_config.content, limit=1048576)
            spec = next(item for item in config['workflow_sources']['components'] if item['id'] == component)
            script = 'ps' if windows and component == 'spec-kit' else 'sh'
            record = spec['generated_assets'][agent + '-' + script]
            if (set(record) != {'path', 'sha256', 'argv_sha256'}
                    or not record['path'].startswith('.getzilla/templates/baseline/')
                    or not record['path'].endswith('.json')
                    or not re.fullmatch(r'[a-f0-9]{64}', record['sha256'])):
                raise ValueError('INVALID_ASSET_CONFIG')
            document = binding.read(record['path'], limit=MAX_MANIFEST_BYTES)
            if document is None or digest(document.content) != record['sha256']:
                raise ValueError('ASSET_HASH_MISMATCH')
            metadata = parse_json(document.content, limit=MAX_MANIFEST_BYTES)
            if (type(metadata) is not dict
                    or set(metadata) != {'schema_version', 'component', 'agent', 'script', 'binding', 'generator', 'argv',
                                         'semantic_safety', 'permissions_granted', 'files'}
                    or type(metadata['schema_version']) is not int or metadata['schema_version'] != 1
                    or metadata['component'] != component or metadata['agent'] != agent or metadata['script'] != script
                    or metadata['binding'] != spec['asset_inputs']
                    or metadata['binding']['source_commit'] != spec['pinned_commit']
                    or metadata['semantic_safety'] != 'unqualified' or metadata['permissions_granted'] is not False
                    or metadata['generator'] != ('closed-source-materialization-v1' if component == 'superpowers'
                                                 else 'linux-bubblewrap-offline-v1')
                    or digest(canonical(metadata['argv'])) != record['argv_sha256']
                    or type(metadata['files']) is not list or not 1 <= len(metadata['files']) <= MAX_FILES):
                raise ValueError('ASSET_SOURCE_BINDING_MISMATCH')
            result, seen, cache, total = [], set(), {}, 0
            for item in metadata['files']:
                if type(item) is not dict or set(item) != {'path', 'sha256', 'bytes', 'mode'}:
                    raise ValueError('ASSET_MANIFEST_FIELDS')
                name = item['path']
                path_parts(name)
                if (name in seen or not name.startswith(OUTPUT_PREFIXES)
                        or item['mode'] not in {0o644, 0o755}
                        or type(item['bytes']) is not int or not 0 <= item['bytes'] <= MAX_FILE_BYTES
                        or type(item['sha256']) is not str or not re.fullmatch(r'[a-f0-9]{64}', item['sha256'])
                        or any(part in {'.git', '.env'} for part in name.split('/'))):
                    raise ValueError('UNSAFE_ASSET_ENTRY')
                seen.add(name)
                total += item['bytes']
                if total > MAX_TOTAL_BYTES:
                    raise ValueError('ASSET_INVENTORY_BOUNDS')
                content = cache.get(item['sha256'])
                if content is None:
                    blob = binding.read('.getzilla/templates/baseline/blobs/' + item['sha256'] + '.txt',
                                        limit=MAX_FILE_BYTES)
                    packed = archived[1].get(BLOB_PREFIX + item['sha256'] + '.txt') if archived else None
                    if blob is not None and packed is not None and (blob.content, blob.mode) != packed:
                        raise ValueError('CONFLICTING_ASSET_REPRESENTATIONS')
                    if blob is None and packed is None:
                        raise ValueError('MISSING_ASSET_BLOB')
                    content = blob.content if blob is not None else packed[0]
                    if blob is not None and blob.mode & 0o111 or b'\0' in content:
                        raise ValueError('UNSUPPORTED_ASSET_BLOB')
                    try:
                        content.decode('utf-8')
                    except UnicodeError as exc:
                        raise ValueError('UNSUPPORTED_ASSET_BLOB') from exc
                    cache[item['sha256']] = content
                if len(content) != item['bytes'] or digest(content) != item['sha256']:
                    raise ValueError('ASSET_CONTENT_MISMATCH')
                result.append((name, content, item['mode']))
            if archived and binding.read(ENGINE_ARCHIVE, limit=ARCHIVE_LIMIT) != archived[0]:
                raise ValueError('ASSET_ARCHIVE_CHANGED')
        return AssetPayload(component, agent, record['sha256'], tuple(result))
    except (ComponentStateError, OSError, KeyError, TypeError, StopIteration) as exc:
        raise ValueError('UNQUALIFIED_BASELINE_ASSETS') from exc


def preflight_destination(project: Path, payload: AssetPayload) -> bool:
    if not isinstance(payload, AssetPayload):
        raise ValueError('BOUND_ASSET_PAYLOAD_REQUIRED')
    if payload.component not in {'superpowers', 'bmad', 'spec-kit'} or payload.agent not in _AGENTS:
        raise ValueError('UNKNOWN_BASELINE_COMPONENT')
    # This public API does not treat a dataclass constructor, or caller-supplied
    # status/digest fields, as evidence that bytes are from the shipped artifact.
    variants = (False, True) if payload.component == 'spec-kit' else (False,)
    if not any(payload == load(payload.component, payload.agent, windows=windows) for windows in variants):
        raise ValueError('BOUND_ASSET_PAYLOAD_REQUIRED')
    marker = '_bmad' if payload.component == 'bmad' else '.specify'
    try:
        with BoundRoot(project) as binding:
            # Every adapter shares the component's native destination markers.
            # A failed owned copy is not an unrelated user's preserved directory.
            for agent in sorted(_AGENTS):
                intent = binding.read(_intent_path(payload, agent=agent), limit=4096)
                if intent is None:
                    continue
                record = parse_json(intent.content, limit=4096)
                if (type(record) is not dict or set(record) != {'schema_version', 'status', 'asset_digest'}
                        or type(record['schema_version']) is not int or record['schema_version'] != 1
                        or record['status'] not in {'incomplete', 'complete'}
                        or type(record['asset_digest']) is not str
                        or not re.fullmatch(r'[a-f0-9]{64}', record['asset_digest'])):
                    raise ValueError('INVALID_BASELINE_DIAGNOSTIC')
                if record['status'] == 'incomplete':
                    raise ValueError('INTERRUPTED_BASELINE_MATERIALIZATION')
            if payload.component != 'superpowers':
                try:
                    with binding.parent(marker + '/.existing'):
                        return True
                except FileNotFoundError:
                    pass
            for name, content, mode in payload.files:
                current = binding.read(name)
                if current is not None and (payload.component != 'superpowers' or current.content != content or not mode_matches(current.mode, mode)):
                    raise ValueError('BASELINE_ASSET_CONFLICT')
        return False
    except (ComponentStateError, OSError) as exc:
        raise ValueError('UNSAFE_BASELINE_DESTINATION') from exc


def _intent_path(payload, *, agent=None):
    # A finite denial-only diagnostic, never a permission/approval ledger.
    return '.getzilla/runtime/baseline-assets/' + payload.component + '-' + (agent or payload.agent) + '.json'


def materialize(project: Path, payload: AssetPayload) -> dict:
    if preflight_destination(project, payload):
        return {'status': 'preserved', 'added': 0, 'marker': '_bmad' if payload.component == 'bmad' else '.specify'}
    try:
        marker = '_bmad' if payload.component == 'bmad' else '.specify' if payload.component == 'spec-kit' else '.agents/skills'
        prepared = []
        for name, content, mode in payload.files:
            if payload.component == 'bmad' and name in {'_bmad/core/config.yaml', '_bmad/bmm/config.yaml'}:
                content = re.sub(rb'(?m)^project_name: work$',
                                 lambda _match: b'project_name: ' + json.dumps(project.name, ensure_ascii=True).encode(), content)
            prepared.append((name, content, mode))
        if payload.component == 'bmad':
            rendered_hashes = {name.removeprefix('_bmad/'): digest(content) for name, content, _ in prepared}
            fixed = []
            for name, content, mode in prepared:
                if name == '_bmad/_config/files-manifest.csv':
                    rows = list(csv.reader(io.StringIO(content.decode('utf-8'))))
                    for row in rows:
                        if len(row) == 5 and row[3] in rendered_hashes:
                            row[4] = rendered_hashes[row[3]]
                    output = io.StringIO(newline='')
                    csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator='\n').writerows(rows)
                    content = output.getvalue().encode('utf-8')
                fixed.append((name, content, mode))
            prepared = fixed

        def authorize(name):
            # Preserve the existing explicitly invoked unrouted initializer. In an
            # active native task, consume its existing canonical owner and policy.
            if state.route_authority_present(project):
                state.require_route_owner(project)
                allowed, _reason = evaluate_pre_tool(project, {'tool_name': 'Write', 'tool_input': {'file_path': name}})
                if not allowed:
                    raise ValueError('BASELINE_AUTHORITY_REQUIRED')

        for name, _content, _mode in prepared:
            authorize(name)
        with component_transaction(project) as transaction:
            # Recheck the full preflight under the same writer guard before intent.
            if preflight_destination(project, payload):
                return {'status': 'preserved', 'added': 0, 'marker': marker}
            for name, content, mode in prepared:
                current = transaction.read(name)
                if current is not None and (payload.component != 'superpowers' or current.content != content or not mode_matches(current.mode, mode)):
                    raise ValueError('BASELINE_ASSET_CONFLICT')
            intent_path = _intent_path(payload)
            diagnostic = transaction.read(intent_path, limit=4096)
            record = {'schema_version': 1, 'status': 'incomplete', 'asset_digest': payload.asset_digest}
            transaction.write(intent_path, canonical(record), 0o600, expected=diagnostic)
            pending = transaction.read(intent_path, limit=4096)
            added = 0
            for name, content, mode in prepared:
                # One local publication under the existing canonical lock is its
                # admission point; no arbitrary/native backend runs under it.
                with state.task_transition(project):
                    authorize(name)
                    current = transaction.read(name)
                    if current is not None:
                        if current.content != content or not mode_matches(current.mode, mode):
                            raise ValueError('BASELINE_ASSET_CONFLICT')
                        continue
                    transaction.write(name, content, mode, expected=None)
                    added += 1
            # Report custody only for freshly observed bytes and exact modes.
            # An uncooperative writer is not fenced by this local transaction.
            observed = {}
            for name, content, mode in prepared:
                current = transaction.read(name)
                if current is None or current.content != content or not mode_matches(current.mode, mode):
                    raise ValueError('BASELINE_ASSET_CONFLICT')
                observed[name] = {'digest': current.sha256, 'mode': current.mode}
            record['status'] = 'complete'
            transaction.write(intent_path, canonical(record), 0o600, expected=pending)
        return {'status': 'ok', 'added': added, 'marker': marker,
                'asset_digest': payload.asset_digest, 'semantic_safety': 'unqualified',
                'materialized_digest': digest(canonical(observed)),
                'permissions_granted': False, 'native_execution': False}
    except (ComponentStateError, OSError) as exc:
        raise ValueError('UNSAFE_BASELINE_DESTINATION') from exc
