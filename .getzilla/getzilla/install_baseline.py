"""Immutable release fingerprints, never executable historical installer code."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from .architecture import _read_regular_bytes
from .component_state import _ledger_path

RELEASE = 'v2.3.0'
CATALOG = '.getzilla/config/install-baseline-v2.3.0.json'
CATALOG_SHA256 = '03951fa0b6e0c8ef296592cdb768c5b7eb098c73b403f0a3728d50330987eafe'
# Permission-bearing inputs must never gain vendor status from an arbitrary old ledger.
POLICY_PATHS = frozenset({'.grok/config.toml', '.codex/config.toml', '.qwen/settings.json',
                          '.claude/settings.json', '.gemini/settings.json', '.grok/hooks.json',
                          '.codex/hooks.json', '.grok/codex-hooks.json'})


def load_baseline(home: Path, release: str, *, include_runtime_anchors: bool = False) -> dict[str, dict]:
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
    files = dict(value['files'])
    if include_runtime_anchors:
        # Git installs ship these anchors. The published ZIP omits .gitignore;
        # keep them separate from the common 695-file restoration payload.
        files.update(value['git_runtime_anchors'])
    for path in files:
        _ledger_path(path)
    return files


def restore_release_payload(home: Path, historical_source: Path, target: Path) -> dict:
    """Restore only qualified old vendor bytes to an absent target; execute no old code."""
    import importlib.util
    from .component_state import BoundRoot

    catalog = load_baseline(home, RELEASE)
    if len(catalog) != 695:
        raise ValueError('historical restoration requires the complete qualified vendor catalog')
    identity = subprocess.check_output(['git', '--no-optional-locks', '-C', str(historical_source),
                    'rev-parse', 'HEAD', 'refs/tags/v2.3.0'], text=True, encoding='utf-8', timeout=20).splitlines()
    if identity != ['2bb417431f1e4b9494e4af71ebf27adb1d04d898',
                    '815aeabc5d215d65e72651692a6457920de9fa71']:
        raise ValueError('historical source identity differs from the published release')
    spec = importlib.util.spec_from_file_location('getzilla_current_payload_publisher', home/'scripts/install_into.py')
    installer = importlib.util.module_from_spec(spec)
    # Dataclasses resolve their owning module while the reviewed publisher loads.
    import sys
    sys.modules[spec.name] = installer
    spec.loader.exec_module(installer)
    shims = {'post_tool_use.py', 'pre_compact.py', 'pre_tool_use.py', 'session_end.py', 'session_start.py',
             'stop_gate.py', 'subagent_start.py', 'subagent_stop.py', 'user_prompt_submit.py'}
    entries = []
    total = 0
    with BoundRoot(historical_source) as source:
        for path, proof in sorted(catalog.items()):
            origin = ('.getzilla/templates/consumer-AGENTS.md.tmpl' if path == 'AGENTS.md' else
                      '.getzilla/templates/consumer-factory-README.md.tmpl' if path == 'factory/README.md' else
                      '.getzilla/templates/hook_root_shim.py' if path in shims else path)
            snapshot = source.read(origin)
            if snapshot is None:
                raise ValueError(f'missing historical release input: {path}')
            content = installer._render_managed_agents(snapshot.content).encode() if path == 'AGENTS.md' else snapshot.content
            total += len(content)
            if total > 64*1024*1024 or hashlib.sha256(content).hexdigest() != proof['sha256']:
                raise ValueError(f'historical payload differs from qualified vendor bytes: {path}')
            entries.append(installer.InstallEntry(path, content, proof['mode']))
        source.check()
    # These exact65 operational bytes were produced by both qualified v2.3.0 materializers.
    sync = b'{"kept_local": [], "kept_local_sha256": {}, "schema_version": 1}\n'
    if hashlib.sha256(sync).hexdigest() != '8b0608c8e4520f41c8856728c8458f0e22eb134572eab5a71eb1fa709317d234':
        raise ValueError('historical operational record mismatch')
    entries.append(installer.InstallEntry('.getzilla/AGBP_SYNC.json', sync, 0o644))
    try:
        installer._materialize_new(historical_source, target, include_dependencies=False, include_optional=False,
            selection=installer.PayloadSelection(('qwen',)), prepared_payload=tuple(entries))
    except installer.UnsafeInstallTarget as error:
        raise ValueError(f'historical restoration refused: {error}') from error
    return {'baseline_mode': 'restored-v230-artifact', 'release': RELEASE,
            'source_commit': identity[0], 'vendor_files': len(catalog), 'vendor_bytes': total,
            'catalog_sha256': CATALOG_SHA256, 'historical_installer_create': 'unsupported',
            'operational_record_sha256': hashlib.sha256(sync).hexdigest()}
