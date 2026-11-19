"""Fixed inert private-research source-use data. No execution or global license grant."""
from __future__ import annotations

import hashlib
import json
from importlib.resources import files

from .security_artifacts import ArtifactError, safe_parts

PROFILE = 'public-research162/cpython312-linux-amd64'
MANIFEST_PATH = '.getzilla/config/retrieval-research-runtime-v1.json'
CATALOG_PATH = '.getzilla/getzilla/research_conditions_v1.json'
MANIFEST_SHA256 = '7f205d7cf800d4e045305344eab3ebbee4b177005912613f74110412807c926f'
CATALOG_SHA256 = '5dd595a2755d3cdd4d0178e5ed7946a3412c4369f57f18c10218a9ed51c32a26'
IMAGE_CONDITIONS_SHA256 = '961be08c61fe53bac425ba5acefafce7ed7fe21df43800955f6a987935730004'
MAX_CATALOG_BYTES = 262144
_FIELDS = frozenset({'schema_version', 'kind', 'profile', 'manifest', 'manifest_sha256',
    'project_repository', 'wheels', 'inspection_wheels', 'models', 'profiles',
    'dependency_exceptions', 'retained_source_terms', 'image_conditions_sha256', 'assurance',
    'native_sdk_closure_complete', 'cryptographic_compilation_verified'})


def _fail():
    raise ArtifactError('research-conditions-unavailable', 'fixed private research source-use catalog is missing or changed')


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            _fail()
        result[key] = value
    return result


def _decode(raw):
    try:
        if type(raw) is not bytes or len(raw) > MAX_CATALOG_BYTES:
            _fail()
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: _fail())
        pending, nodes = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if nodes > 200000 or depth > 32:
                _fail()
            if type(item) is dict:
                pending.extend((x, depth + 1) for x in item.values())
            elif type(item) is list:
                pending.extend((x, depth + 1) for x in item)
        if (type(value) is not dict or set(value) != _FIELDS
                or value['schema_version'] != 1
                or value['kind'] != 'getzilla-private-research-conditions/v1'
                or value['profile'] != PROFILE or value['manifest'] != MANIFEST_PATH
                or value['project_repository'] != 'github.com/Dimkox/Getzilla'
                or value['native_sdk_closure_complete'] is not False
                or value['cryptographic_compilation_verified'] is not False
                or type(value['wheels']) is not list or len(value['wheels']) != 29
                or type(value['inspection_wheels']) is not list or len(value['inspection_wheels']) != 2
                or type(value['profiles']) is not dict or len(value['profiles']) != 29
                or type(value['dependency_exceptions']) is not list or len(value['dependency_exceptions']) != 29
                or type(value['retained_source_terms']) is not dict or len(value['retained_source_terms']) > 1024
                or set(value['models']) != {'minilm', 'bge_m3'}):
            _fail()
        for path, pin in value['retained_source_terms'].items():
            safe_parts(path)
            if (type(pin) is not dict or set(pin) != {'bytes', 'sha256'}
                    or type(pin['bytes']) is not int or not 0 < pin['bytes'] <= 262144
                    or type(pin['sha256']) is not str or len(pin['sha256']) != 64):
                _fail()
        return value
    except (ValueError, UnicodeError, TypeError, KeyError):
        _fail()


def _resource_bytes(name, expected):
    try:
        with files('getzilla').joinpath(name).open('rb') as stream:
            raw = stream.read(MAX_CATALOG_BYTES + 1)
        if (type(raw) is not bytes or len(raw) > MAX_CATALOG_BYTES
                or hashlib.sha256(raw).hexdigest() != expected):
            _fail()
    except (OSError, ValueError):
        _fail()
    return raw


def catalog_bytes():
    """Read and hash the actual fixed package resource, including zipimport."""
    return _resource_bytes('research_conditions_v1.json', CATALOG_SHA256)


def image_conditions_bytes():
    return _resource_bytes('research_image_conditions_v1.json', IMAGE_CONDITIONS_SHA256)


def image_conditions():
    value = json.loads(image_conditions_bytes().decode('utf-8'), object_pairs_hook=_pairs,
                       parse_constant=lambda _: _fail())
    if (set(value) != {'schema_version', 'kind', 'profile', 'project_repository',
                       'manifest_sha256', 'subject', 'python_version', 'python_source_sha256',
                       'python_terms', 'packages', 'use', 'native_sdk_closure_complete',
                       'cryptographic_compilation_verified', 'assurance'}
            or value['schema_version'] != 1 or value['profile'] != PROFILE
            or value['kind'] != 'getzilla-private-research-image-source-conditions/v1'
            or value['manifest_sha256'] != MANIFEST_SHA256
            or value['project_repository'] != 'github.com/Dimkox/Getzilla'
            or value['python_version'] != '3.12.15' or len(value['packages']) != 105
            or value['use'] != 'private-unmodified-no-conveyance'
            or value['native_sdk_closure_complete'] is not False
            or value['cryptographic_compilation_verified'] is not False):
        _fail()
    return value


def load_catalog():
    raw = catalog_bytes()
    value = _decode(raw)
    if (value['manifest_sha256'] != MANIFEST_SHA256
            or value['image_conditions_sha256'] != IMAGE_CONDITIONS_SHA256):
        _fail()
    return value


def condition_profile(name):
    if type(name) is not str or not name.startswith('retrieval-research162-'):
        return None
    return load_catalog()['profiles'].get(name)


def validate_subject(subject):
    if (subject['manifest'] != MANIFEST_PATH or subject['manifest_sha256'] != MANIFEST_SHA256
            or subject['usage'] != 'retrieval-research' or subject['distribution'] != 'internal'
            or subject['delivery_kind'] != 'source-use' or subject['profile'] != PROFILE
            or subject['abi'] != 'cpython-312-x86_64-linux-gnu'):
        _fail()
