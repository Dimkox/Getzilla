"""Source-bound, bounded skill assessment. Results never confer authority.

The supported interview language is declarative JSON, not arbitrary Markdown or
native code. Unmodeled instructions require review even when their bytes are pinned.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .component_state import BoundRoot, ComponentStateError, path_parts

MAX_FILES = 128
MAX_FILE_BYTES = 262144
MAX_TOTAL_BYTES = 1048576
MAX_SKILLS = 64
MAX_DESCRIPTOR_BYTES = 65536
CATALOG_PATH = '.getzilla/config/skill-catalog.json'
DESCRIPTOR = 'getzilla-skill.json'
_ID = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')
_REPOSITORY = re.compile(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z')
_HEX = re.compile(r'[a-f0-9]{64}\Z')
_REVISION = re.compile(r'[a-f0-9]{40}\Z')
_NATIVE = re.compile(r'---\nname: ([a-z][a-z0-9-]{0,63})\ndescription: Declared skill constraints\.\n---\n```json\n(.*)\n```\n?\Z', re.S)
_MODELED_CONSTRAINTS = {'tone': {'concise', 'verbose'}, 'language': {'en', 'ru'}, 'format': {'plain', 'markdown'}}
_OVERRIDE = re.compile(r'ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|'
                       r'you\s+are\s+now\s+(?:the\s+)?(?:system|administrator)|'
                       r'(?:this\s+skill\s+is|automatically)\s+approved|'
                       r'(?:read|extract|send|upload)\s+(?:all\s+)?(?:secrets|credentials)', re.I)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def parse_json(raw: bytes, *, limit: int = MAX_DESCRIPTOR_BYTES):
    if type(raw) is not bytes or len(raw) > limit:
        raise ValueError('JSON byte limit')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (UnicodeError, RecursionError, TypeError) as exc:
        raise ValueError('invalid JSON') from exc


def _path(value):
    if type(value) is not str or len(value) > 240 or any(c in value for c in '*?[]\\\x00\r\n'):
        raise ValueError('invalid path')
    parts = path_parts(value)
    if len(parts) > 12 or any(part.startswith('.') for part in parts):
        raise ValueError('hidden/deep path')
    return value


@dataclass(frozen=True)
class SkillSnapshot:
    files: tuple[tuple[str, bytes], ...]

    def __post_init__(self):
        if type(self.files) is not tuple or not 1 <= len(self.files) <= MAX_FILES:
            raise ValueError('skill file count')
        seen = set()
        total = 0
        for item in self.files:
            if type(item) is not tuple or len(item) != 2:
                raise ValueError('invalid snapshot entry')
            name, content = item
            _path(name)
            if name in seen or type(content) is not bytes or len(content) > MAX_FILE_BYTES:
                raise ValueError('invalid snapshot file')
            seen.add(name)
            total += len(content)
        if total > MAX_TOTAL_BYTES or 'SKILL.md' not in seen:
            raise ValueError('invalid skill inventory')

    @classmethod
    def create(cls, files: Mapping[str, bytes]) -> SkillSnapshot:
        return cls(tuple(sorted(files.items())))

    @property
    def digest(self) -> str:
        return digest(canonical({name: digest(content) for name, content in self.files}))

    @property
    def total_bytes(self) -> int:
        return sum(len(content) for _, content in self.files)


def read_snapshot(root: Path, relative: str) -> SkillSnapshot:
    path_parts(relative)
    if len(relative) > 240 or len(relative.split('/')) > 12:
        raise ValueError('source path bounds')
    try:
        with BoundRoot(root) as binding:
            names = binding.files(relative, recursive=True)
            if len(names) > MAX_FILES:
                raise ValueError('skill file count')
            files = {}
            for name in names:
                short = name.removeprefix(relative + '/')
                _path(short)
                if short == DESCRIPTOR:
                    continue
                if short.lower().endswith(('.pem', '.key', '.p12', '.pfx')):
                    raise ValueError('credential-like skill source')
                value = binding.read(name, limit=MAX_FILE_BYTES)
                if value is None:
                    raise ValueError('skill source disappeared')
                files[short] = value.content
            # A changed directory inventory must not silently omit a late file.
            if binding.files(relative, recursive=True) != names:
                raise ValueError('skill inventory changed')
        return SkillSnapshot.create(files)
    except ComponentStateError as exc:
        raise ValueError('unsafe skill source') from exc


def _source(value):
    if (type(value) is not dict or set(value) != {'repository', 'revision'}
            or not isinstance(value['repository'], str) or not _REPOSITORY.fullmatch(value['repository'])
            or not isinstance(value['revision'], str) or not _REVISION.fullmatch(value['revision'])):
        raise ValueError('invalid source')


def _dependencies(value):
    if type(value) is not list or len(value) > 32:
        raise ValueError('dependency count')
    seen = set()
    for dep in value:
        if type(dep) is not dict or set(dep) != {'id', 'repository', 'revision', 'digest'}:
            raise ValueError('dependency fields')
        _source({key: dep[key] for key in ('repository', 'revision')})
        if not isinstance(dep['id'], str) or not _ID.fullmatch(dep['id']) or dep['id'] in seen:
            raise ValueError('dependency id')
        if not isinstance(dep['digest'], str) or not _HEX.fullmatch(dep['digest']):
            raise ValueError('dependency digest')
        seen.add(dep['id'])


def _constraints(value):
    if type(value) is not dict or len(value) > 32:
        raise ValueError('constraint count')
    for key, item in value.items():
        if (not _ID.fullmatch(key) or type(item) is not str or not re.fullmatch(r'[a-z0-9-]{1,64}', item)):
            raise ValueError('invalid constraint')


def native_contract(raw: bytes):
    try:
        match = _NATIVE.fullmatch(raw.decode('utf-8').replace('\r\n', '\n'))
        if not match:
            return None
        return match.group(1), parse_json(match.group(2).encode(), limit=MAX_FILE_BYTES)
    except (ValueError, UnicodeError):
        return None


def _descriptor(raw):
    data = parse_json(raw)
    if (type(data) is not dict or set(data) != {'schema_version', 'id', 'version', 'source', 'files',
                                              'capabilities', 'constraints', 'dependencies'}
            or type(data['schema_version']) is not int or data['schema_version'] != 1
            or type(data['id']) is not str or not _ID.fullmatch(data['id'])
            or type(data['version']) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', data['version'])):
        raise ValueError('descriptor fields')
    _source(data['source'])
    _dependencies(data['dependencies'])
    _constraints(data['constraints'])
    if type(data['files']) is not dict or not 1 <= len(data['files']) <= MAX_FILES:
        raise ValueError('files manifest')
    for name, value in data['files'].items():
        _path(name)
        if type(value) is not str or not _HEX.fullmatch(value):
            raise ValueError('file digest')
    if type(data['capabilities']) is not list or len(data['capabilities']) > 32:
        raise ValueError('capability count')
    seen = set()
    for cap in data['capabilities']:
        if (type(cap) is not dict or set(cap) != {'operation', 'resource', 'exclusive'}
                or type(cap['operation']) is not str or cap['operation'] not in
                {'read', 'write', 'shell', 'network', 'secret', 'production', 'mcp'}
                or type(cap['exclusive']) is not bool):
            raise ValueError('capability fields')
        _path(cap['resource'])
        key = (cap['operation'], cap['resource'])
        if key in seen:
            raise ValueError('duplicate capability')
        seen.add(key)
    return data


def catalog_entries(raw: bytes) -> list[dict]:
    data = parse_json(raw, limit=MAX_TOTAL_BYTES)
    if (type(data) is not dict or set(data) != {'schema_version', 'skills'}
            or type(data['schema_version']) is not int or data['schema_version'] != 1
            or type(data['skills']) is not list or len(data['skills']) > MAX_SKILLS):
        raise ValueError('invalid catalog')
    seen = set()
    for item in data['skills']:
        if type(item) is not dict or set(item) != {'id', 'source', 'snapshot_digest', 'descriptor_digest', 'dependencies'}:
            raise ValueError('catalog fields')
        if type(item['id']) is not str or not _ID.fullmatch(item['id']) or item['id'] in seen:
            raise ValueError('catalog id')
        seen.add(item['id'])
        _source(item['source'])
        _dependencies(item['dependencies'])
        if any(type(item[key]) is not str or not _HEX.fullmatch(item[key])
               for key in ('snapshot_digest', 'descriptor_digest')):
            raise ValueError('catalog digest')
    return data['skills']


@dataclass(frozen=True)
class Assessment:
    skill_id: str
    snapshot_digest: str
    descriptor_digest: str
    catalog_digest: str
    verdict: str
    reasons: tuple[str, ...]
    observations: tuple[str, ...] = ()
    constraints: tuple[tuple[str, str], ...] = ()
    capabilities: tuple[tuple[str, str, bool], ...] = ()
    permissions_granted: bool = False
    semantic_safety: str = 'unqualified'

    def to_dict(self):
        return {'schema_version': 1, 'skill_id': self.skill_id, 'snapshot_digest': self.snapshot_digest,
                'descriptor_digest': self.descriptor_digest, 'catalog_digest': self.catalog_digest,
                'verdict': self.verdict, 'reasons': list(self.reasons), 'observations': list(self.observations),
                'permissions_granted': False, 'semantic_safety': 'unqualified',
                'dependency_qualification': 'declared-pins-only', 'evidence_valid': False}


def assess(snapshot: SkillSnapshot, descriptor: bytes, catalog: bytes, *, existing=()) -> Assessment:
    if not isinstance(snapshot, SkillSnapshot):
        raise ValueError('snapshot required')
    if type(descriptor) is not bytes or type(catalog) is not bytes:
        raise ValueError('owned metadata bytes required')
    if len(descriptor) > MAX_DESCRIPTOR_BYTES or len(catalog) > MAX_TOTAL_BYTES:
        raise ValueError('metadata byte limit')
    reasons, observations = set(), set()
    data = None
    try:
        data = _descriptor(descriptor)
    except (ValueError, TypeError, KeyError):
        reasons.add('INVALID_DESCRIPTOR')
    try:
        entries = catalog_entries(catalog)
    except (ValueError, TypeError, KeyError):
        entries = []
        reasons.add('INVALID_CATALOG')
    if type(existing) not in (tuple, list) or len(existing) > MAX_SKILLS or any(not isinstance(i, Assessment) for i in existing):
        raise ValueError('existing skill context required')
    if data:
        if any(key not in _MODELED_CONSTRAINTS or value not in _MODELED_CONSTRAINTS[key]
               for key, value in data['constraints'].items()):
            reasons.add('UNMODELED_CONSTRAINT')
        manifest = {name: digest(content) for name, content in snapshot.files}
        if manifest != data['files']:
            reasons.add('SOURCE_HASH_MISMATCH')
        entry = next((entry for entry in entries if entry['id'] == data['id']), None)
        if entry is None:
            reasons.add('UNREGISTERED_SOURCE')
        else:
            if (entry['snapshot_digest'] != snapshot.digest or entry['descriptor_digest'] != digest(descriptor)
                    or entry['source'] != data['source']):
                reasons.add('CATALOG_HASH_MISMATCH')
            if entry['dependencies'] != data['dependencies']:
                reasons.add('DEPENDENCY_PROVENANCE_MISMATCH')
        for cap in data['capabilities']:
            if cap['operation'] != 'read':
                reasons.add('UNSUPPORTED_CAPABILITY')
        for other in existing:
            if other.verdict != 'allow':
                reasons.add('UNQUALIFIED_EXISTING_SKILL')
            if other.skill_id == data['id'] and other.descriptor_digest != digest(descriptor):
                reasons.add('DUPLICATE_SKILL_CONFLICT')
            for key, value in other.constraints:
                if key in data['constraints'] and data['constraints'][key] != value:
                    reasons.add('INSTRUCTION_CONFLICT')
            for operation, resource, exclusive in other.capabilities:
                for cap in data['capabilities']:
                    if (cap['operation'], cap['resource']) == (operation, resource):
                        if exclusive or cap['exclusive']:
                            reasons.add('EXCLUSIVE_PRIVILEGE_CONFLICT')
                        else:
                            observations.add('OVERLAPPING_READ')
    for name, raw in snapshot.files:
        try:
            text = raw.decode('utf-8')
        except UnicodeError:
            reasons.add('INVALID_UTF8')
            continue
        if _OVERRIDE.search(text):
            reasons.add('INSTRUCTION_OVERRIDE')
        if name == 'SKILL.md':
            try:
                wrapped = native_contract(raw)
                instructions = wrapped[1] if wrapped else parse_json(raw, limit=MAX_FILE_BYTES)
                if wrapped and data and wrapped[0] != data['id']:
                    reasons.add('DECLARATION_CONFLICT')
                if (type(instructions) is not dict or set(instructions) != {'schema_version', 'constraints'}
                        or type(instructions['schema_version']) is not int or instructions['schema_version'] != 1):
                    raise ValueError('unsupported instruction language')
                _constraints(instructions['constraints'])
                if data and instructions['constraints'] != data['constraints']:
                    reasons.add('DECLARATION_CONFLICT')
            except (ValueError, KeyError, TypeError):
                reasons.add('UNMODELED_INSTRUCTIONS')
        else:
            # References can carry instructions too; no implicit trust by extension.
            reasons.add('UNMODELED_REFERENCES')
    review_reasons = {'UNREGISTERED_SOURCE', 'UNMODELED_INSTRUCTIONS', 'UNMODELED_REFERENCES',
                      'UNQUALIFIED_EXISTING_SKILL', 'UNMODELED_CONSTRAINT'}
    verdict = 'deny' if reasons - review_reasons else 'needs_review' if reasons else 'allow'
    return Assessment(data['id'] if data else 'unknown', snapshot.digest,
                      digest(descriptor), digest(catalog), verdict, tuple(sorted(reasons)),
                      tuple(sorted(observations)), tuple(sorted(data['constraints'].items())) if data else (),
                      tuple((i['operation'], i['resource'], i['exclusive']) for i in data['capabilities']) if data else ())
