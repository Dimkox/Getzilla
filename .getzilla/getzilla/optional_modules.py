"""Passive, explicit optional modules using the existing component writer and ledger."""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import uuid

from .component_state import (
    MANIFEST, MAX_FILE_BYTES, BoundRoot, ComponentStateError, FileSnapshot,
    component_of, component_transaction, decode_manifest, encode_manifest, matches_owned,
    mode_matches, module_name, owned_proof, path_parts, read_keep_contract, read_state,
    record_owned, validate_manifest_publication, match_kept_local, kept_file_state,
)

REGISTRY = '.getzilla/config/optional-modules.json'
PENDING = '.getzilla/runtime/modules/pending.json'
LAST = '.getzilla/runtime/modules/last.json'
HISTORY = '.getzilla/runtime/modules/history'
CORE_API = 1
MAX_MODULES = 32
MAX_ARTIFACT_FILE = 1024 * 1024
MAX_BATCH_BYTES = 4 * 1024 * 1024
MAX_HISTORY = 32


class ModuleError(ComponentStateError):
    """A bounded public reason; never include artifact contents or credentials."""


def _need(condition, reason):
    if not condition:
        raise ModuleError(reason)


def _fields(value, fields, reason):
    _need(type(value) is dict and set(value) == set(fields), reason)


def _version(value):
    return type(value) is str and re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', value) is not None


def _scope(value):
    return type(value) is str and re.fullmatch(r'[a-z][a-z0-9_.:-]{0,127}', value) is not None


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def _digest(value):
    return hashlib.sha256(_bytes(value)).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def _nonfinite(_value):
    raise ModuleError('nonfinite_json')


def _float(text):
    value = float(text)
    _need(math.isfinite(value), 'nonfinite_json')
    return value


def _json(content):
    try:
        return json.loads(content, object_pairs_hook=_unique, parse_constant=_nonfinite, parse_float=_float)
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ModuleError):
            raise
        raise ModuleError('invalid_module_json') from exc


@dataclass
class Registry:
    source: Path
    data: dict
    sha256: str


def load_registry(source: Path, registry_path: str = REGISTRY) -> Registry:
    try:
        with BoundRoot(source) as binding:
            snapshot = binding.read(registry_path, limit=MAX_ARTIFACT_FILE)
        _need(snapshot is not None, 'registry_missing')
        data = _json(snapshot.content)
        _fields(data, {'schema_version', 'core_api', 'publishers', 'modules'}, 'registry_schema')
        _need(type(data['schema_version']) is int and data['schema_version'] == 1
              and type(data['core_api']) is int and data['core_api'] == CORE_API, 'registry_api')
        _need(type(data['publishers']) is dict and 1 <= len(data['publishers']) <= 16, 'registry_publishers')
        for publisher, record in data['publishers'].items():
            _need(module_name(publisher), 'registry_publisher')
            _fields(record, {'licenses'}, 'publisher_schema')
            _need(type(record['licenses']) is list and 1 <= len(record['licenses']) <= 16
                  and all(type(x) is str and _scope(x.lower()) for x in record['licenses']), 'publisher_licenses')
        _need(type(data['modules']) is dict and len(data['modules']) <= MAX_MODULES, 'registry_modules')
        for name, record in data['modules'].items():
            _need(module_name(name), 'module_id')
            _fields(record, {'publisher', 'versions'}, 'registry_module_schema')
            _need(type(record['publisher']) is str and record['publisher'] in data['publishers']
                  and type(record['versions']) is dict and 1 <= len(record['versions']) <= 32, 'registry_versions')
            for version, entry in record['versions'].items():
                _need(_version(version), 'module_version')
                _fields(entry, {'manifest', 'sha256'}, 'registry_artifact_schema')
                _need(entry['manifest'] == f'.getzilla/optional-modules/{name}/{version}/module.json'
                      and _sha(entry['sha256']), 'artifact_location_or_hash')
        return Registry(Path(source), data, snapshot.sha256)
    except (OSError, ComponentStateError) as exc:
        if isinstance(exc, ModuleError):
            raise
        raise ModuleError('registry_unavailable') from exc


def _artifact(registry, name, version):
    _need(module_name(name) and _version(version), 'module_request')
    record = registry.data['modules'].get(name)
    _need(record is not None and version in record['versions'], 'module_or_version_unavailable')
    entry = record['versions'][version]
    with BoundRoot(registry.source) as source:
        snapshot = source.read(entry['manifest'], limit=MAX_ARTIFACT_FILE)
        _need(snapshot is not None and snapshot.sha256 == entry['sha256'], 'artifact_manifest_hash')
        value = _json(snapshot.content)
        _fields(value, {'schema_version', 'id', 'version', 'publisher', 'core_api', 'license', 'entitlement',
                        'dependencies', 'permissions', 'hooks', 'files'}, 'module_manifest_schema')
        _need(type(value['schema_version']) is int and value['schema_version'] == 1 and value['id'] == name
              and value['version'] == version and value['publisher'] == record['publisher'], 'module_identity')
        _fields(value['core_api'], {'min', 'max'}, 'core_api_schema')
        _need(all(type(v) is int for v in value['core_api'].values())
              and 1 <= value['core_api']['min'] <= CORE_API <= value['core_api']['max'] <= 9999, 'core_api_incompatible')
        _need(type(value['license']) is str and value['license'] in registry.data['publishers'][record['publisher']]['licenses'], 'license_not_allowed')
        _need(value['entitlement'] is None or _scope(value['entitlement']), 'entitlement_schema')
        _need(value['license'] != 'LicenseRef-Proprietary' or value['entitlement'] is not None, 'licensed_capability_missing')
        _need(value['hooks'] == 'declarative-v1', 'executable_hooks_unsupported')
        deps = value['dependencies']
        _need(type(deps) is dict and len(deps) <= MAX_MODULES and all(module_name(k) and _version(v) for k, v in deps.items()), 'dependency_schema')
        scopes = value['permissions']
        _need(type(scopes) is list and len(scopes) <= 32 and all(_scope(s) for s in scopes)
              and len(set(scopes)) == len(scopes), 'permissions_schema')
        files = value['files']
        _need(type(files) is list and 1 <= len(files) <= 128, 'artifact_files')
        seen = {'module.json'}
        contents = {'module.json': (snapshot.content, 0o644, False)}
        total = len(snapshot.content)
        for item in files:
            _fields(item, {'path', 'sha256', 'mode', 'mutable'}, 'artifact_file_schema')
            parts = path_parts(item['path'])
            folded = item['path'].casefold()
            _need(folded not in seen and _sha(item['sha256']) and type(item['mode']) is int
                  and item['mode'] in {0o644, 0o755} and type(item['mutable']) is bool, 'artifact_file_identity')
            _need(not any('/'.join(parts[:n]).casefold() in seen for n in range(1, len(parts)))
                  and not any(p.startswith(folded + '/') for p in seen), 'artifact_path_collision')
            seen.add(folded)
            artifact_path = entry['manifest'].rsplit('/', 1)[0] + '/' + item['path']
            file = source.read(artifact_path, limit=MAX_ARTIFACT_FILE)
            _need(file is not None and file.sha256 == item['sha256'], 'artifact_file_hash')
            total += len(file.content)
            _need(total <= MAX_BATCH_BYTES, 'artifact_size_limit')
            contents[item['path']] = (file.content, item['mode'], item['mutable'])
        _need('LICENSE' in contents, 'artifact_license_file_missing')
        return value, snapshot.sha256, contents


def _entitled(root, name, metadata, verifier):
    capability = metadata['entitlement']
    if capability is None:
        return
    _need(callable(verifier), 'entitlement_adapter_required')
    try:
        proof = verifier(root.absolute(), name, metadata['version'], capability)
    except Exception as exc:
        raise ModuleError('entitlement_adapter_failed') from exc
    expected = {'verified': True, 'project': str(root.absolute()), 'module': name,
                'version': metadata['version'], 'capability': capability}
    _need(type(proof) is dict and proof == expected and proof['verified'] is True, 'entitlement_not_verified')


def _modules(manifest):
    return {name[7:]: record for name, record in manifest['components'].items() if name.startswith('module:')}


def _resolve(registry, requests, installed, operation):
    resolved = {}
    visiting = set()
    order = []
    def visit(name, version):
        _need(name not in visiting, 'dependency_cycle')
        if name in resolved:
            _need(resolved[name][0]['version'] == version, 'dependency_version_conflict')
            return
        _need(len(resolved) + len(visiting) < MAX_MODULES, 'dependency_limit')
        if name in installed and installed[name]['module']['version'] != version:
            _need(operation == 'update', 'installed_dependency_version_conflict')
        visiting.add(name)
        artifact = _artifact(registry, name, version)
        for dependency, pin in sorted(artifact[0]['dependencies'].items()):
            visit(dependency, pin)
        visiting.remove(name)
        resolved[name] = artifact
        order.append(name)
    for name, version in sorted(requests.items()):
        visit(name, version)
    for name, record in installed.items():
        descriptor = resolved[name][0] if name in resolved else record['module']
        for dependency, version in descriptor['dependencies'].items():
            chosen = resolved[dependency][0]['version'] if dependency in resolved else installed.get(dependency, {}).get('module', {}).get('version')
            _need(chosen == version, 'installed_dependent_conflict')
    return order, resolved


def _pack(snapshot):
    return None if snapshot is None else {'content': base64.b64encode(snapshot.content).decode(), 'mode': snapshot.mode,
                                         'sha256': snapshot.sha256}


def _unpack(value):
    if value is None:
        return None
    _fields(value, {'content', 'mode', 'sha256'}, 'journal_snapshot_schema')
    _need(type(value['content']) is str and len(value['content']) <= MAX_FILE_BYTES * 2
          and type(value['mode']) is int and 0 <= value['mode'] <= 0o777 and _sha(value['sha256']), 'journal_snapshot')
    try:
        raw = base64.b64decode(value['content'], validate=True)
    except (ValueError, TypeError) as exc:
        raise ModuleError('journal_content_encoding') from exc
    _need(len(raw) <= MAX_FILE_BYTES and hashlib.sha256(raw).hexdigest() == value['sha256'], 'journal_content_hash')
    return raw, value['mode']


def _matches(current, value):
    if value is None:
        return current is None
    unpacked = _unpack(value)
    return current is not None and current.content == unpacked[0] and mode_matches(current.mode, unpacked[1])


@dataclass
class Plan:
    report: dict
    before: FileSnapshot
    after: bytes
    changes: list
    affected: list


def _plan(root, binding, operation, requests, source, registry_path, grants, entitlement, transaction):
    _need(operation in {'install', 'update', 'enable', 'disable', 'uninstall'}, 'module_operation')
    _need(type(requests) is dict and 1 <= len(requests) <= MAX_MODULES and all(module_name(k) for k in requests), 'module_requests')
    _need(type(grants) in (list, tuple) and len(grants) <= 32 and all(_scope(s) for s in grants) and len(set(grants)) == len(grants), 'grants_schema')
    _need(binding.read(PENDING) is None, 'module_recovery_required')
    state = read_state(root, binding=binding)
    state.require_selection()
    original = binding.read(MANIFEST)
    _need(original is not None, 'module_requires_owned_core')
    manifest = copy.deepcopy(state.manifest)
    installed = _modules(manifest)
    changes = []
    preserved = []
    affected = []
    report = {'operation': operation, 'status': 'planned', 'dependency_order': [], 'preserved': preserved,
              'files': 0, 'bytes': 0, 'artifacts': {}, 'workers': 0, 'external_dependencies_installed': 0, 'external_authority': False}
    kept, keep_digests = read_keep_contract(binding)
    _pointer(binding.read(LAST))
    def change(path, desired, mode, before):
        changes.append({'path': path, 'before': before, 'after': desired, 'mode': mode})
    if operation in {'install', 'update'}:
        _need(source is not None and all(_version(v) for v in requests.values()), 'module_version_required')
        registry = load_registry(source, registry_path)
        if operation == 'update':
            _need(set(requests) <= set(installed), 'module_not_installed')
        order, artifacts = _resolve(registry, requests, installed, operation)
        report['dependency_order'] = order
        report['artifacts'] = {name: {'version': artifact[0]['version'], 'files': len(artifact[2]),
                                     'bytes': sum(len(item[0]) for item in artifact[2].values())}
                               for name, artifact in artifacts.items()}
        known = {MANIFEST, *(path for r in installed.values() for path in r['files']),
                 *(f'.getzilla/modules/{name}/{path}' for name, artifact in artifacts.items() for path in artifact[2])}
        kept, keep_digests = match_kept_local(kept, keep_digests, known)
        for name in order:
            descriptor, sha, files = artifacts[name]
            old = installed.get(name)
            if old is not None:
                _descriptor(binding, name, old, compatible=False)
            if old is not None and old['module']['version'] == descriptor['version']:
                _need(old['module']['manifest_sha256'] == sha, 'immutable_version_changed')
                continue
            _need(operation == 'update' or old is None, 'module_already_installed')
            _entitled(root, name, descriptor, entitlement)
            prefix = f'.getzilla/modules/{name}/'
            record = {'files': [], 'owned': {}, 'module': {
                'schema_version': 1, 'version': descriptor['version'], 'enabled': False,
                'manifest_sha256': sha, 'registry_sha256': registry.sha256, 'publisher': descriptor['publisher'],
                'license': descriptor['license'], 'entitlement': descriptor['entitlement'],
                'dependencies': descriptor['dependencies'], 'permissions': descriptor['permissions'], 'grants': [],
                'transaction': transaction}}
            manifest['components']['module:' + name] = record
            for relative, (content, mode, mutable) in sorted(files.items()):
                path = prefix + relative
                current = binding.read(path)
                proof = old.get('owned', {}).get(path) if old else None
                if path in kept:
                    kept_file_state(path, current.content if current else None, content, keep_digests.get(path))
                    _need(current is not None, 'kept_module_file_missing')
                    preserved.append(path)
                    record['files'].append(path)
                    continue
                if current is not None and not matches_owned(current, proof):
                    _need(mutable, 'module_ownership_conflict')
                    preserved.append(path)
                    record['files'].append(path)
                    continue
                if current is None or current.content != content or not mode_matches(current.mode, mode):
                    change(path, content, mode, current)
                record_owned(manifest, path, content, mode)
            for path in (old or {}).get('files', []):
                if path in record['files']:
                    continue
                current = binding.read(path)
                if path not in kept and matches_owned(current, old.get('owned', {}).get(path)):
                    change(path, None, 0o644, current)
                elif current is not None:
                    preserved.append(path)
            affected.append(name)
    else:
        _need(all(value is None or _version(value) for value in requests.values()), 'module_request_version')
        _need(set(requests) <= set(installed), 'module_not_installed')
        _need(all(v is None or installed[k]['module']['version'] == v for k, v in requests.items()), 'installed_module_version_mismatch')
        kept, keep_digests = match_kept_local(kept, keep_digests, {MANIFEST, *(path for r in installed.values() for path in r['files'])})
        selected = set(requests)
        if operation == 'enable':
            def dependencies(name):
                for dependency, version in installed[name]['module']['dependencies'].items():
                    _need(dependency in installed and installed[dependency]['module']['version'] == version, 'dependency_unavailable')
                    if dependency not in selected:
                        selected.add(dependency)
                        dependencies(dependency)
            for name in list(selected):
                dependencies(name)
            required = set().union(*(set(installed[name]['module']['permissions']) for name in selected))
            _need(set(grants) == required, 'explicit_scoped_grants_required')
        if operation in {'disable', 'uninstall'}:
            for name, record in installed.items():
                if name not in selected:
                    linked = set(record['module']['dependencies']) & selected
                    _need(not linked or operation == 'disable' and not record['module']['enabled'], 'module_has_dependents')
        for name in sorted(selected):
            record = manifest['components']['module:' + name]
            if operation == 'enable':
                _validate_installed(binding, name, record)
                _entitled(root, name, record['module'], entitlement)
                if record['module']['enabled']:
                    continue
                record['module']['enabled'] = True
                record['module']['grants'] = list(record['module']['permissions'])
            elif operation == 'disable':
                if not record['module']['enabled']:
                    continue
                record['module']['enabled'] = False
                record['module']['grants'] = []
            else:
                for path in record['files']:
                    current = binding.read(path)
                    if path not in kept and matches_owned(current, record.get('owned', {}).get(path)):
                        change(path, None, 0o644, current)
                    elif current is not None:
                        preserved.append(path)
                del manifest['components']['module:' + name]
            if operation != 'uninstall':
                record['module']['transaction'] = transaction
            affected.append(name)
    encoded = encode_manifest(manifest)
    validate_manifest_publication(original, encoded if encoded != original.content else None, kept, keep_digests)
    report['files'] = len(changes)
    report['bytes'] = sum(len(c['after'] or b'') for c in changes)
    _need(sum(len(c['after'] or b'') + len(c['before'].content if c['before'] else b'') for c in changes) <= MAX_BATCH_BYTES, 'module_batch_size')
    report['rollback_available'] = len(binding.files(HISTORY)) < MAX_HISTORY
    if affected:
        _need(report['rollback_available'] or operation == 'disable', 'module_history_limit')
    return Plan(report, original, encoded, changes, affected)


def _descriptor(binding, name, record, *, compatible=True):
    prefix = f'.getzilla/modules/{name}/'
    descriptor_path = prefix + 'module.json'
    descriptor = binding.read(descriptor_path)
    _need(descriptor is not None and descriptor.sha256 == record['module']['manifest_sha256']
          and matches_owned(descriptor, record.get('owned', {}).get(descriptor_path)), 'module_manifest_modified')
    value = _json(descriptor.content)
    _fields(value, {'schema_version', 'id', 'version', 'publisher', 'core_api', 'license', 'entitlement',
                    'dependencies', 'permissions', 'hooks', 'files'}, 'module_manifest_schema')
    _need(value['id'] == name and type(value['schema_version']) is int and value['schema_version'] == 1
          and value['hooks'] == 'declarative-v1', 'module_manifest_identity')
    _need(all(value[field] == record['module'][field] for field in
              ('version', 'publisher', 'license', 'entitlement', 'dependencies', 'permissions')), 'module_ledger_descriptor_mismatch')
    _fields(value['core_api'], {'min', 'max'}, 'core_api_schema')
    _need(all(type(v) is int for v in value['core_api'].values())
          and 1 <= value['core_api']['min'] <= value['core_api']['max'] <= 9999, 'core_api_schema')
    if compatible:
        _need(value['core_api']['min'] <= CORE_API <= value['core_api']['max'], 'core_api_incompatible')
    _need(type(value['files']) is list and 1 <= len(value['files']) <= 128, 'module_inventory')
    expected = {descriptor_path: {'sha256': descriptor.sha256, 'mode': 0o644}}
    mutable = set()
    for item in value['files']:
        _fields(item, {'path', 'sha256', 'mode', 'mutable'}, 'artifact_file_schema')
        path_parts(item['path'])
        path = prefix + item['path']
        _need(path.casefold() not in {x.casefold() for x in expected} and _sha(item['sha256'])
              and type(item['mode']) is int and item['mode'] in {0o644, 0o755} and type(item['mutable']) is bool, 'module_inventory')
        expected[path] = {'sha256': item['sha256'], 'mode': item['mode']}
        if item['mutable']:
            mutable.add(path)
    _need(set(record['files']) == set(expected), 'module_inventory_mismatch')
    for path, proof in record.get('owned', {}).items():
        _need(proof == expected.get(path), 'module_ownership_descriptor_mismatch')
    return mutable


def _validate_installed(binding, name, record):
    mutable = _descriptor(binding, name, record)
    for path in record['files']:
        if path not in mutable:
            _need(matches_owned(binding.read(path), record.get('owned', {}).get(path)), 'module_file_modified')


def _pointer(snapshot):
    if snapshot is None:
        return None
    _need(mode_matches(snapshot.mode, 0o600), 'module_history_pointer')
    value = _json(snapshot.content)
    _fields(value, {'schema_version', 'transaction', 'status'}, 'module_history_pointer')
    _need(type(value['schema_version']) is int and value['schema_version'] == 1
          and type(value['status']) is str and value['status'] in {'applied', 'rolled_back', 'revoked_without_history'}
          and type(value['transaction']) is str and re.fullmatch('[0-9a-f]{32}', value['transaction']) is not None, 'module_history_pointer')
    return value


def plan_modules(root, operation, requests, *, source=None, registry_path=REGISTRY, grants=(), entitlement=None):
    try:
        with BoundRoot(root) as binding:
            return _plan(root, binding, operation, requests, source, registry_path, grants, entitlement, uuid.uuid4().hex).report
    except (ValueError, OSError, TypeError, RecursionError) as exc:
        if isinstance(exc, ModuleError):
            raise
        raise ModuleError('module_preflight_failed') from exc


def _journal(plan, transaction):
    data = {'schema_version': 1, 'transaction': transaction, 'affected': plan.affected,
            'before_manifest': _pack(plan.before),
            'after_manifest': {'content': base64.b64encode(plan.after).decode(), 'mode': 0o644, 'sha256': hashlib.sha256(plan.after).hexdigest()},
            'changes': [{'path': c['path'], 'before': _pack(c['before']), 'after': None if c['after'] is None else {
                'content': base64.b64encode(c['after']).decode(), 'mode': c['mode'], 'sha256': hashlib.sha256(c['after']).hexdigest()}}
                for c in plan.changes]}
    data['digest'] = _digest(data)
    raw = _bytes(data)
    _need(len(raw) <= MAX_FILE_BYTES, 'module_journal_size')
    return raw


def _read_journal(binding, path):
    snapshot = binding.read(path)
    _need(snapshot is not None and mode_matches(snapshot.mode, 0o600), 'module_journal_unavailable')
    data = _json(snapshot.content)
    _fields(data, {'schema_version', 'transaction', 'affected', 'before_manifest', 'after_manifest', 'changes', 'digest'}, 'module_journal_schema')
    _need(type(data['schema_version']) is int and data['schema_version'] == 1
          and type(data['transaction']) is str and re.fullmatch('[0-9a-f]{32}', data['transaction']) is not None
          and data['digest'] == _digest({k: v for k, v in data.items() if k != 'digest'}), 'module_journal_digest')
    _need(type(data['affected']) is list and 1 <= len(data['affected']) <= MAX_MODULES
          and all(module_name(x) for x in data['affected']) and len(set(data['affected'])) == len(data['affected']), 'module_journal_modules')
    before_raw, _before_mode = _unpack(data['before_manifest'])
    after_raw, _after_mode = _unpack(data['after_manifest'])
    before, after = decode_manifest(before_raw), decode_manifest(after_raw)
    _need(before['schema_version'] == after['schema_version'] and before.get('agents') == after.get('agents'), 'journal_selection_change')
    before_core = {k: v for k, v in before['components'].items() if not k.startswith('module:') or k[7:] not in data['affected']}
    after_core = {k: v for k, v in after['components'].items() if not k.startswith('module:') or k[7:] not in data['affected']}
    _need(before_core == after_core, 'journal_changes_unrelated_components')
    _need(type(data['changes']) is list and len(data['changes']) <= 2 * MAX_MODULES * 129, 'journal_changes_limit')
    seen = set()
    for change in data['changes']:
        _fields(change, {'path', 'before', 'after'}, 'journal_change_schema')
        path_parts(change['path'])
        _need(component_of(change['path']) in {'module:' + name for name in data['affected']}
              and change['path'].casefold() not in seen, 'journal_path_escape')
        seen.add(change['path'].casefold())
        for field, manifest in (('before', before), ('after', after)):
            if change[field] is not None:
                raw, mode = _unpack(change[field])
                proof = owned_proof(manifest, change['path'])
                _need(proof is not None and proof == {'sha256': hashlib.sha256(raw).hexdigest(), 'mode': mode}, 'journal_ownership_mismatch')
    return snapshot, data


def _rollback_preflight(transaction, journal):
    current_manifest = transaction.read(MANIFEST)
    original_raw, original_mode = _unpack(journal['before_manifest'])
    original = decode_manifest(original_raw)
    for name in journal['affected']:
        record = original['components'].get('module:' + name)
        if record is not None:
            record['module']['enabled'] = False
            record['module']['grants'] = []
    target_manifest = encode_manifest(original)
    _need(current_manifest is not None and (any(_matches(current_manifest, value) for value in (
        journal['before_manifest'], journal['after_manifest']))
        or current_manifest.content == target_manifest and mode_matches(current_manifest.mode, original_mode)),
        'rollback_ledger_changed')
    kept, digests = read_keep_contract(transaction)
    kept, digests = match_kept_local(kept, digests, {MANIFEST, *(change['path'] for change in journal['changes'])})
    validate_manifest_publication(current_manifest, target_manifest if target_manifest != current_manifest.content else None, kept, digests)
    observations = []
    for change in journal['changes']:
        current = transaction.read(change['path'])
        _need(_matches(current, change['before']) or _matches(current, change['after']), 'rollback_user_change_conflict')
        if change['path'] in kept:
            kept_file_state(change['path'], current.content if current else None, None, digests.get(change['path']))
            _need(_matches(current, change['before']), 'rollback_kept_file_conflict')
        observations.append((change, current))
    already = (current_manifest.content == target_manifest and mode_matches(current_manifest.mode, original_mode)
               and all(_matches(current, change['before']) for change, current in observations))
    return current_manifest, target_manifest, original_mode, observations, already


def _rollback_locked(transaction, journal, *, status):
    current_manifest, target_manifest, original_mode, observations, already = _rollback_preflight(transaction, journal)
    for change, current in reversed(observations):
        desired = change['before']
        if _matches(current, desired):
            continue
        if desired is None:
            transaction.remove(change['path'], expected=current)
        else:
            content, mode = _unpack(desired)
            transaction.write(change['path'], content, mode, expected=current)
    if current_manifest.content != target_manifest or not mode_matches(current_manifest.mode, original_mode):
        transaction.write(MANIFEST, target_manifest, original_mode, expected=current_manifest)
    pointer = transaction.read(LAST)
    _pointer(pointer)
    transaction.write(LAST, _bytes({'schema_version': 1, 'transaction': journal['transaction'], 'status': 'rolled_back'}), 0o600, expected=pointer)
    pending = transaction.read(PENDING)
    if pending is not None:
        transaction.remove(PENDING, expected=pending)
    return {'status': 'already_rolled_back' if already and status == 'rolled_back' else status, 'workers': 0, 'external_authority': False}


def manage_modules(root, operation, requests, *, source=None, registry_path=REGISTRY, grants=(), entitlement=None):
    transaction_id = uuid.uuid4().hex
    try:
        with BoundRoot(root) as binding:
            initial = _plan(root, binding, operation, requests, source, registry_path, grants, entitlement, transaction_id)
            if not initial.affected:
                return {**initial.report, 'status': 'unchanged'}
            _journal(initial, transaction_id)
        with component_transaction(root) as transaction:
            plan = _plan(root, transaction, operation, requests, source, registry_path, grants, entitlement, transaction_id)
            if not plan.affected:
                return {**plan.report, 'status': 'unchanged'}
            raw = _journal(plan, transaction_id)
            transaction.write(PENDING, raw, 0o600, expected=None)
            try:
                for change in plan.changes:
                    if change['after'] is None:
                        transaction.remove(change['path'], expected=change['before'])
                    else:
                        transaction.write(change['path'], change['after'], change['mode'], expected=change['before'])
                transaction.write(MANIFEST, plan.after, 0o644, expected=plan.before)
                if plan.report['rollback_available']:
                    transaction.write(f'{HISTORY}/{transaction_id}.json', raw, 0o600, expected=None)
                pointer_status = 'applied' if plan.report['rollback_available'] else 'revoked_without_history'
                transaction.write(LAST, _bytes({'schema_version': 1, 'transaction': transaction_id, 'status': pointer_status}), 0o600, expected=transaction.read(LAST))
                transaction.remove(PENDING, expected=transaction.read(PENDING))
            except (OSError, ValueError) as exc:
                try:
                    if transaction.read(PENDING) is None:
                        _need(_completed(transaction, plan, transaction_id, raw), 'module_failed_state_inspection_required')
                        return {**plan.report, 'status': 'applied', 'transaction': transaction_id, 'completion': 'verified_after_cleanup_error'}
                    _snapshot, journal = _read_journal(transaction, PENDING)
                    _rollback_locked(transaction, journal, status='recovered')
                except (OSError, ValueError) as recovery:
                    raise ModuleError('module_failed_recovery_required') from recovery
                raise ModuleError('module_failed_rolled_back') from exc
            return {**plan.report, 'status': 'applied', 'transaction': transaction_id}
    except (ValueError, OSError, TypeError, RecursionError) as exc:
        if isinstance(exc, ModuleError):
            raise
        raise ModuleError('module_operation_refused') from exc


def recover_modules(root):
    try:
        with BoundRoot(root) as binding:
            if binding.read(PENDING) is None:
                return {'status': 'nothing_to_recover'}
            _read_journal(binding, PENDING)
        with component_transaction(root) as transaction:
            _snapshot, journal = _read_journal(transaction, PENDING)
            return _rollback_locked(transaction, journal, status='recovered')
    except (ValueError, OSError, TypeError, RecursionError) as exc:
        if isinstance(exc, ModuleError):
            raise
        raise ModuleError('module_recovery_refused') from exc


def _completed(transaction, plan, transaction_id, raw):
    current = transaction.read(MANIFEST)
    _need(current is not None and current.content == plan.after and mode_matches(current.mode, 0o644), 'module_completion_ledger')
    for change in plan.changes:
        current = transaction.read(change['path'])
        _need(current is None if change['after'] is None else current is not None
              and current.content == change['after'] and mode_matches(current.mode, change['mode']), 'module_completion_file')
    pointer = _pointer(transaction.read(LAST))
    expected = 'applied' if plan.report['rollback_available'] else 'revoked_without_history'
    _need(pointer is not None and pointer['transaction'] == transaction_id and pointer['status'] == expected, 'module_completion_pointer')
    if plan.report['rollback_available']:
        history = transaction.read(f'{HISTORY}/{transaction_id}.json')
        _need(history is not None and history.content == raw and mode_matches(history.mode, 0o600), 'module_completion_history')
    return True


def _last_journal(binding):
    _need(binding.read(PENDING) is None, 'module_recovery_required')
    pointer = _pointer(binding.read(LAST))
    _need(pointer is not None, 'module_history_missing')
    _need(pointer['status'] != 'revoked_without_history', 'module_rollback_unavailable_at_capacity')
    snapshot, journal = _read_journal(binding, f"{HISTORY}/{pointer['transaction']}.json")
    _need(journal['transaction'] == pointer['transaction'], 'module_history_pointer')
    _rollback_preflight(binding, journal)
    return snapshot, journal


def rollback_modules(root):
    try:
        with BoundRoot(root) as binding:
            _last_journal(binding)
        with component_transaction(root) as transaction:
            snapshot, journal = _last_journal(transaction)
            transaction.write(PENDING, snapshot.content, 0o600, expected=None)
            return _rollback_locked(transaction, journal, status='rolled_back')
    except (ValueError, OSError, TypeError, RecursionError) as exc:
        if isinstance(exc, ModuleError):
            raise
        raise ModuleError('module_rollback_refused') from exc


def module_status(root):
    try:
        with BoundRoot(root) as binding:
            state = read_state(root, binding=binding)
            modules = {name: copy.deepcopy(record['module']) for name, record in _modules(state.manifest).items()}
            return {'schema_version': 1, 'core_api': CORE_API, 'modules': modules, 'recovery_required': binding.read(PENDING) is not None,
                    'workers': 0, 'external_dependencies_installed': 0, 'external_authority': False}
    except (ValueError, OSError, TypeError, RecursionError) as exc:
        raise ModuleError('module_state_unavailable') from exc


def admit_module(root, name, *, permission=None, entitlement=None):
    result = {'allowed': False, 'module': name, 'external_authority': False, 'workers': 0}
    try:
        with BoundRoot(root) as binding:
            _need(module_name(name), 'module_id')
            _need(binding.read(PENDING) is None, 'module_recovery_required')
            observed = binding.read(MANIFEST)
            records = _modules(read_state(root, binding=binding).manifest)
            visiting, checked = set(), set()
            def validate(selected):
                if selected in checked:
                    return
                _need(selected not in visiting and len(checked) + len(visiting) < MAX_MODULES, 'module_dependency_invalid')
                record = records.get(selected)
                _need(record is not None and record['module']['enabled'], 'module_disabled_or_missing')
                visiting.add(selected)
                _validate_installed(binding, selected, record)
                _entitled(root, selected, record['module'], entitlement)
                for dependency, version in record['module']['dependencies'].items():
                    _need(dependency in records and records[dependency]['module']['version'] == version, 'module_dependency_invalid')
                    validate(dependency)
                visiting.remove(selected)
                checked.add(selected)
            validate(name)
            record = records[name]
            _need(permission is None or permission in record['module']['grants'], 'module_scope_not_granted')
            _need(binding.read(PENDING) is None and binding.read(MANIFEST) == observed, 'module_state_changed')
            return {**result, 'allowed': True, 'version': record['module']['version'], 'manifest_sha256': record['module']['manifest_sha256']}
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        return {**result, 'reason': 'module_admission_refused'}
