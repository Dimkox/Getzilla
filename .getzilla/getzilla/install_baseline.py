"""Immutable release fingerprints, never executable historical installer code."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .architecture import _read_regular_bytes
from .component_state import _ledger_path

RELEASE = 'v2.3.0'
CATALOG = '.getzilla/config/install-baseline-v2.3.0.json'
CATALOG_SHA256 = '36d434f705fa955baa9a5553485ed9d7defe7618279d61e332280eeddc7a46af'
# Permission-bearing inputs must never gain vendor status from an arbitrary old ledger.
POLICY_PATHS = frozenset({'.grok/config.toml', '.codex/config.toml', '.qwen/settings.json',
                          '.claude/settings.json', '.gemini/settings.json', '.grok/hooks.json',
                          '.codex/hooks.json', '.grok/codex-hooks.json'})


def load_baseline(home: Path, release: str) -> dict[str, dict]:
    if release != RELEASE:
        raise ValueError('unknown baseline release; only v2.3.0 is qualified')
    raw = _read_regular_bytes(home, CATALOG, label='trusted install baseline')
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != CATALOG_SHA256:
        raise ValueError('trusted baseline catalog digest mismatch')
    # The digest pins the complete closed JSON document, including release provenance.
    value = json.loads(raw)
    if (value['schema'] != 'getzilla-trusted-install-baseline-v1'
            or value['release']['tag'] != RELEASE
            or value['release']['commit'] != '2bb417431f1e4b9494e4af71ebf27adb1d04d898'
            or value['release']['tag_object'] != '815aeabc5d215d65e72651692a6457920de9fa71'
            or value['release']['archive_sha256'] != '782219f8f74525a882f14ff2f457ee553ee725a6ba9ae434296c39be77946c11'):
        raise ValueError('unqualified baseline provenance')
    for path in value['files']:
        _ledger_path(path)
    return value['files']
