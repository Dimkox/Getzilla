"""Components that are not installed up front are added when they are needed, from the same Getzilla version.

A project gets the core plus the agent it uses. When another agent is set up (`getzilla
setup-agent` inside the project) or a command needs `factory/`, the missing component is copied
from the local Getzilla checkout (`GETZILLA_HOME`), never from the network, and never over an
existing file. Every addition is recorded in `.getzilla/managed-components.json` and shows up in
`git status` like any other change.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST = '.getzilla/managed-components.json'
# A synced project has the sync record; a fresh install has the core package and no record.
INSTALLED_MARKERS = ('.getzilla/AGBP_SYNC.json', '.getzilla/getzilla/__init__.py')
# Files that only a full Getzilla checkout has: a lean project cannot be the source of components.
SOURCE_MARKERS = ('scripts/install_into.py', 'factory/pyproject.toml')


@dataclass
class Added:
    component: str
    files: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {'component': self.component, 'files': len(self.files), 'kept_existing': self.kept}


def _installer(source: Path):
    spec = importlib.util.spec_from_file_location('getzilla_install_into_on_demand', source / 'scripts' / 'install_into.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def is_source_checkout(path: Path) -> bool:
    return all((path / marker).is_file() for marker in SOURCE_MARKERS)


def getzilla_home() -> Path:
    """The full checkout components come from: $GETZILLA_HOME, this checkout, then ~/Getzilla."""
    candidates = [Path(os.environ['GETZILLA_HOME'])] if os.environ.get('GETZILLA_HOME') else []
    candidates += [Path(__file__).resolve().parents[2], Path.home() / 'Getzilla']
    for candidate in candidates:
        if is_source_checkout(candidate):
            return candidate
    raise RuntimeError('no full Getzilla checkout found to add components from; set GETZILLA_HOME '
                       'to the folder the installer cloned (default ~/Getzilla)')


def is_installed_project(root: Path) -> bool:
    return any((root / marker).is_file() for marker in INSTALLED_MARKERS)


def load_manifest(root: Path) -> dict[str, Any]:
    try:
        data = json.loads((root / MANIFEST).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {'schema_version': 'getzilla-managed-components-v1', 'components': {}}
    return data if isinstance(data, dict) else {'schema_version': 'getzilla-managed-components-v1', 'components': {}}


def present(root: Path, component: str, source: Path | None = None) -> bool:
    installer = _installer(source or getzilla_home())
    paths = [entry.path for entry in installer.build_payload(source or getzilla_home()) if installer.component_of(entry.path) == component]
    return bool(paths) and all((root / path).exists() for path in paths)


def ensure_components(root: Path, needs: list[str], *, source: Path | None = None) -> list[Added]:
    """Copy missing components into an installed project; existing files are left as they are."""
    source = source or getzilla_home()
    installer = _installer(source)
    payload = installer.build_payload(source)
    valid = {'factory', *(f'agent:{name}' for name in installer.KNOWN_AGENTS),
             *(f'compliance:{name}' for name in getattr(installer, 'KNOWN_COMPLIANCE', ())),
             *(f'extra:{name}' for name in getattr(installer, 'KNOWN_EXTRAS', ()))}
    results = []
    manifest = load_manifest(root)
    for need in needs:
        if need not in valid:
            raise ValueError(f'unknown component {need!r}; expected one of {", ".join(sorted(valid))}')
        added = Added(need)
        agents = {name for name in installer.KNOWN_AGENTS if (root / installer.AGENT_COMPONENT_PATHS[name][0]).exists()}
        for entry in payload:
            if installer.component_of(entry.path) != need:
                continue
            owner = installer._agent_of(entry.path) if hasattr(installer, '_agent_of') else None
            if need.startswith('extra:') and owner is not None and owner not in agents:
                continue  # an extra adds its skill only for the agents the project uses
            target = root / entry.path
            if target.exists() or target.is_symlink():
                if target.is_file() and target.read_bytes() != entry.content:
                    added.kept.append(entry.path)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(entry.content)
            os.chmod(target, entry.mode)
            added.files.append(entry.path)
        if added.files:
            record = manifest['components'].setdefault(need, {'files': []})
            record['files'] = sorted(set(record['files']) | set(added.files))
            record['added_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            record['source_version'] = (source / 'VERSION').read_text(encoding='utf-8').strip() \
                if (source / 'VERSION').is_file() else None
        results.append(added)
    layers = sorted(need.split(':', 1)[1] for need in needs if need.startswith('compliance:'))
    if layers:
        # Adding a compliance layer is the opt-in itself; keep any layer enabled earlier.
        config = root / '.getzilla/config/compliance.json'
        try:
            current = json.loads(config.read_text(encoding='utf-8')).get('enabled') or []
        except (OSError, ValueError, AttributeError):
            current = []
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(json.dumps({'schema_version': 'getzilla-compliance-v1',
                                      'enabled': sorted(set(current) | set(layers))}, indent=2, sort_keys=True) + '\n',
                          encoding='utf-8', newline='\n')
    if any(item.files for item in results):
        path = root / MANIFEST
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    return results
