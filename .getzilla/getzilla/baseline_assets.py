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
from .component_state import BoundRoot, ComponentStateError, component_transaction, path_parts
from .policy import evaluate_pre_tool
from .skill_preflight import canonical, digest, parse_json
from .skill_sandbox import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, OUTPUT_PREFIXES

MAX_ARCHIVE_BYTES = 2097152
_AGENTS = {'claude', 'codex', 'qwen', 'gemini', 'grok', 'copilot'}


@dataclass(frozen=True)
class AssetPayload:
    component: str
    agent: str
    archive_digest: str
    files: tuple[tuple[str, bytes, int], ...]
    semantic_safety_qualified: bool = False
    permissions_granted: bool = False


def load(component: str, agent: str, *, windows=False, source_root: Path | None = None) -> AssetPayload:
    source_root = STACK_DIR.parent if source_root is None else source_root
    try:
        with BoundRoot(source_root) as binding:
            raw_config = binding.read('.getzilla/config/toolchain.json', limit=1048576)
            if raw_config is None:
                raise ValueError('MISSING_ASSET_CONFIG')
            config = parse_json(raw_config.content, limit=1048576)
            components = config['workflow_sources']['components']
            spec = next(item for item in components if item['id'] == component)
            script = 'ps' if windows and component == 'spec-kit' else 'sh'
            record = spec['generated_assets'][agent + '-' + script]
            if (set(record) != {'path', 'sha256', 'argv_sha256'}
                    or not record['path'].startswith('.getzilla/templates/baseline/')
                    or not re.fullmatch(r'[a-f0-9]{64}', record['sha256'])):
                raise ValueError('INVALID_ASSET_CONFIG')
            archive = binding.read(record['path'], limit=MAX_ARCHIVE_BYTES)
            if archive is None or digest(archive.content) != record['sha256']:
                raise ValueError('ASSET_HASH_MISMATCH')
        result = []
        with zipfile.ZipFile(io.BytesIO(archive.content)) as zipped:
            infos = zipped.infolist()
            names = [item.filename for item in infos]
            if (not 2 <= len(infos) <= MAX_FILES + 1 or len(set(names)) != len(names)
                    or sum(item.file_size for item in infos) > MAX_TOTAL_BYTES + 524288):
                raise ValueError('ASSET_INVENTORY_BOUNDS')
            metadata_info = zipped.getinfo('_getzilla_bundle.json')
            if metadata_info.file_size > 524288:
                raise ValueError('ASSET_METADATA_BOUNDS')
            metadata = parse_json(zipped.read(metadata_info), limit=524288)
            if (set(metadata) != {'schema_version', 'component', 'agent', 'script', 'binding', 'generator', 'argv',
                                 'semantic_safety', 'permissions_granted', 'files'}
                    or metadata['schema_version'] != 1 or metadata['component'] != component
                    or metadata['agent'] != agent or metadata['script'] != script
                    or metadata['binding'] != spec['asset_inputs']
                    or metadata['binding']['source_commit'] != spec['pinned_commit']
                    or metadata['semantic_safety'] != 'unqualified' or metadata['permissions_granted'] is not False
                    or metadata['generator'] != ('closed-source-materialization-v1' if component == 'superpowers'
                                                 else 'linux-bubblewrap-offline-v1')
                    or digest(canonical(metadata['argv'])) != record['argv_sha256']
                    or type(metadata['files']) is not list):
                raise ValueError('ASSET_SOURCE_BINDING_MISMATCH')
            manifest = {}
            for item in metadata['files']:
                if type(item) is not dict or set(item) != {'path', 'sha256', 'bytes', 'mode'}:
                    raise ValueError('ASSET_MANIFEST_FIELDS')
                name = item['path']
                path_parts(name)
                if (name in manifest or not name.startswith(OUTPUT_PREFIXES)
                        or item['mode'] not in {0o644, 0o755}
                        or type(item['bytes']) is not int or not 0 <= item['bytes'] <= MAX_FILE_BYTES
                        or any(part in {'.git', '.env'} for part in name.split('/'))):
                    raise ValueError('UNSAFE_ASSET_ENTRY')
                manifest[name] = item
            if set(manifest) != set(names) - {'_getzilla_bundle.json'}:
                raise ValueError('ASSET_MANIFEST_INCOMPLETE')
            for name, item in sorted(manifest.items()):
                info = zipped.getinfo(name)
                if (info.file_size != item['bytes'] or stat.S_IFMT(info.external_attr >> 16) != stat.S_IFREG
                        or stat.S_IMODE(info.external_attr >> 16) != item['mode']):
                    raise ValueError('UNSAFE_ASSET_ENTRY')
                content = zipped.read(info)
                if digest(content) != item['sha256']:
                    raise ValueError('ASSET_CONTENT_MISMATCH')
                result.append((name, content, item['mode']))
        return AssetPayload(component, agent, record['sha256'], tuple(result))
    except (ComponentStateError, OSError, KeyError, TypeError, StopIteration, zipfile.BadZipFile) as exc:
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
            intent = binding.read(_intent_path(payload), limit=4096)
            if intent is not None:
                record = parse_json(intent.content, limit=4096)
                if (type(record) is not dict or set(record) != {'schema_version', 'status', 'archive_digest'}
                        or record['schema_version'] != 1 or record['status'] not in {'incomplete', 'complete'}
                        or type(record['archive_digest']) is not str
                        or not re.fullmatch(r'[a-f0-9]{64}', record['archive_digest'])):
                    raise ValueError('INVALID_BASELINE_DIAGNOSTIC')
                if record['status'] == 'incomplete':
                    raise ValueError('INTERRUPTED_BASELINE_MATERIALIZATION')
            if payload.component != 'superpowers':
                try:
                    with binding.parent(marker + '/.existing'):
                        return True
                except FileNotFoundError:
                    pass
            for name, content, _mode in payload.files:
                current = binding.read(name)
                if current is not None and (payload.component != 'superpowers' or current.content != content):
                    raise ValueError('BASELINE_ASSET_CONFLICT')
        return False
    except (ComponentStateError, OSError) as exc:
        raise ValueError('UNSAFE_BASELINE_DESTINATION') from exc


def _intent_path(payload):
    # A finite denial-only diagnostic, never a permission/approval ledger.
    return '.getzilla/runtime/baseline-assets/' + payload.component + '-' + payload.agent + '.json'


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
            for name, content, _mode in prepared:
                current = transaction.read(name)
                if current is not None and (payload.component != 'superpowers' or current.content != content):
                    raise ValueError('BASELINE_ASSET_CONFLICT')
            intent_path = _intent_path(payload)
            diagnostic = transaction.read(intent_path, limit=4096)
            record = {'schema_version': 1, 'status': 'incomplete', 'archive_digest': payload.archive_digest}
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
                        if current.content != content:
                            raise ValueError('BASELINE_ASSET_CONFLICT')
                        continue
                    transaction.write(name, content, mode, expected=None)
                    added += 1
            record['status'] = 'complete'
            transaction.write(intent_path, canonical(record), 0o600, expected=pending)
        return {'status': 'ok', 'added': added, 'marker': marker,
                'archive_digest': payload.archive_digest, 'semantic_safety': 'unqualified',
                'materialized_digest': digest(canonical({name: {'digest': digest(content), 'mode': mode}
                                                        for name, content, mode in prepared})),
                'permissions_granted': False, 'native_execution': False}
    except (ComponentStateError, OSError) as exc:
        raise ValueError('UNSAFE_BASELINE_DESTINATION') from exc
