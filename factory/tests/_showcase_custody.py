"""Closed source custody checks; filesystem outputs are not source authority."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat


PREFIX = 'side-projects/seo-landing-showcase/'
SOURCE_NAMES = {'ASSETS.md', 'README.md', 'SERVER-SETUP.md', 'browser-contract.mjs',
                'cleanup-owned-directory.py', 'index.html', 'styles.css'}
RENDER_NAMES = {'ASSETS.md', 'SERVER-SETUP.md', 'index.html', 'styles.css'}
HISTORICAL_RECORD_SHA = '85cb10e8ef9d148d458ee0cf51338f6171b5d091e79d6964a66a9b6f930dc013'
RENDER_SHA = 'e4586c99715bd597b00077f4f40b02740dc8c9c2c4bb36d2276a06c0c08ef4eb'


def validate_showcase(root: Path, manifest: dict, tracked: list[str]) -> None:
    if (set(manifest) != {'schema_version', 'historical', 'published_rendering', 'current_tool_revision', 'current_files'}
            or manifest['schema_version'] != 'showcase-source-custody/v1'
            or type(manifest['current_tool_revision']) is not int or manifest['current_tool_revision'] != 1):
        raise ValueError('unknown showcase custody contract')
    # This is immutable historical source metadata, not fresh ZIP verification.
    historical = json.dumps(manifest['historical'], sort_keys=True, separators=(',', ':')).encode()
    if hashlib.sha256(historical).hexdigest() != HISTORICAL_RECORD_SHA:
        raise ValueError('historical showcase source custody changed')
    expected = {PREFIX + name for name in SOURCE_NAMES}
    if set(manifest['current_files']) != expected or set(tracked) != expected or len(tracked) != len(expected):
        raise ValueError('unknown or missing tracked showcase source')
    bodies = {}
    for name in sorted(expected):
        path = root / name
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError('nonregular showcase source')
        bodies[name] = path.read_bytes()
        if hashlib.sha256(bodies[name]).hexdigest() != manifest['current_files'][name]:
            raise ValueError('current showcase source digest changed')
    rendered = sorted(PREFIX + name for name in RENDER_NAMES)
    if manifest['published_rendering'] != {'file_count': 4, 'aggregate_sha256': RENDER_SHA, 'paths': rendered}:
        raise ValueError('published rendering custody changed')
    digest = hashlib.sha256()
    for name in rendered:
        encoded = name.encode()
        body = bodies[name]
        if hashlib.sha256(body).hexdigest() != manifest['historical']['files'][name]:
            raise ValueError('published rendering source changed')
        digest.update(len(encoded).to_bytes(4, 'big'))
        digest.update(encoded)
        digest.update(len(body).to_bytes(8, 'big'))
        digest.update(body)
    if digest.hexdigest() != RENDER_SHA:
        raise ValueError('published rendering aggregate changed')
