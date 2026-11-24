"""Exact native-local policy input projection; hashes are data, not permission.

Only held native source reads and the real host select these inputs. A serialized
profile/digest cannot enroll a task or authorize collection or disclosure.
"""
from __future__ import annotations

from pathlib import Path

from ..trace_contracts import RETRIEVAL_READ_PROFILES
from .budget import RetrievalError
from .contracts import digest, sha

BASE_INPUTS = ('.getzilla/config/policy.json', '.getzilla/managed-components.json')
CONTINUATION = '.getzilla/config/model-continuation.json'


def _decode(raw):
    from ..spec import _parse_canonical_json
    return _parse_canonical_json(raw, Path('native_read_policy_input'))


def validate_policy(raw):
    try:
        value = _decode(raw)
        if (type(value) is not dict or value.get('schema_version') != 2
                or type(value.get('secret_read_paths')) is not list
                or any(type(item) is not str for item in value['secret_read_paths'])):
            raise ValueError
        return value
    except (ValueError, TypeError, UnicodeError):
        raise RetrievalError('policy_unavailable') from None


def input_paths(manifest, profile, continuation):
    if type(profile) is not str or profile not in RETRIEVAL_READ_PROFILES:
        raise RetrievalError('policy_unavailable')
    if type(manifest) is not dict or type(manifest.get('components')) is not dict:
        raise RetrievalError('policy_unavailable')
    selected = ['context-retrieval']
    if profile != 'native-local-stdout':
        selected.append('context-hook-' + profile.removeprefix('native-hook-'))
    paths = list(BASE_INPUTS)
    for name in selected:
        record = manifest['components'].get('module:' + name)
        if type(record) is not dict or type(record.get('files')) is not list or len(record['files']) > 8:
            raise RetrievalError('policy_unavailable')
        for path in record['files']:
            if (type(path) is not str or not path.startswith('.getzilla/modules/' + name + '/')
                    or len(path) > 1024 or '\\' in path or '\0' in path
                    or any(part in {'', '.', '..'} for part in path.split('/'))):
                raise RetrievalError('policy_unavailable')
            paths.append(path)
    if continuation:
        paths.append(CONTINUATION)
    if len(paths) != len(set(paths)):
        raise RetrievalError('policy_unavailable')
    return tuple(paths)


def policy_digest(profile, metadata):
    """Bind the profile, exact ordered path identity and actual raw-byte hash."""
    try:
        validate_policy(metadata[BASE_INPUTS[0]])
        manifest = _decode(metadata[BASE_INPUTS[1]])
        paths = input_paths(manifest, profile, CONTINUATION in metadata)
        if tuple(metadata) != paths or any(type(metadata[path]) is not bytes for path in paths):
            raise ValueError
        return digest({'definition': 'native-local-read-policy-inputs-v1', 'profile': profile,
                       'inputs': [{'path': path, 'sha256': sha(metadata[path])} for path in paths]})
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise RetrievalError('policy_unavailable') from None


def current_policy_digest(anchor, profile):
    """Use current owned no-follow source bytes, never request-supplied paths."""
    base = {path: anchor.read(path, 1048576, source=True) for path in BASE_INPUTS}
    paths = input_paths(_decode(base[BASE_INPUTS[1]]), profile,
                        anchor.exists(CONTINUATION, source=True))
    metadata = {path: base[path] if path in base else anchor.read(path, 1048576, source=True)
                for path in paths}
    return policy_digest(profile, metadata)
