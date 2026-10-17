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
INSTALLED_MARKER = '.getzilla/AGBP_SYNC.json'


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


def getzilla_home() -> Path:
    return Path(os.environ.get('GETZILLA_HOME') or Path(__file__).resolve().parents[2])


def is_installed_project(root: Path) -> bool:
    return (root / INSTALLED_MARKER).is_file()


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
    valid = {'factory', *(f'agent:{name}' for name in installer.KNOWN_AGENTS)}
    results = []
    manifest = load_manifest(root)
    for need in needs:
        if need not in valid:
            raise ValueError(f'unknown component {need!r}; expected one of {", ".join(sorted(valid))}')
        added = Added(need)
        for entry in payload:
            if installer.component_of(entry.path) != need:
                continue
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
    if any(item.files for item in results):
        path = root / MANIFEST
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    return results
