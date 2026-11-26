"""End-to-end uninstall check for CI: snapshot the machine before install, verify it after uninstall.

  python .github/ci/uninstall_e2e.py snapshot STATE.json PROJECT
  python .github/ci/uninstall_e2e.py verify   STATE.json PROJECT GETZILLA_HOME
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

PROFILES = ('.bashrc', '.zshrc', '.bash_profile', '.profile')
VARIABLES = ('OPENROUTER_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'GEMINI_API_KEY', 'COPILOT_GITHUB_TOKEN', 'GETZILLA_OSV_DB')


def digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def project_state(project: Path) -> dict[str, str]:
    head = subprocess.run(['git', '-C', str(project), 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True)
    status = subprocess.run(['git', '-C', str(project), 'status', '--porcelain', '--ignored'],
                            capture_output=True, text=True, check=True)
    return {'head': head.stdout.strip(), 'status': status.stdout}


def windows_user(name: str) -> str | None:
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment') as key:
        try:
            return str(winreg.QueryValueEx(key, name)[0])
        except FileNotFoundError:
            return None


def snapshot(state: Path, project: Path) -> int:
    home = Path.home()
    data = {
        'profiles': {name: digest(home / name) for name in PROFILES},
        'project': project_state(project),
        'had_state': (home / '.getzilla').exists(),
    }
    if os.name == 'nt':
        data['path'] = windows_user('Path')
    state.write_text(json.dumps(data, indent=2), encoding='utf-8')
    print(json.dumps(data, indent=2))
    return 0


def verify(state: Path, project: Path, getzilla_home: Path) -> int:
    before = json.loads(state.read_text(encoding='utf-8'))
    home = Path.home()
    errors: list[str] = []
    for path in (getzilla_home, home / '.getzilla', home / '.local/bin/getzilla'):
        if path.exists() or path.is_symlink():
            errors.append(f'still present: {path}')
    for name, old in before['profiles'].items():
        new = digest(home / name)
        # A profile the installer created may stay as an empty file.
        if new != old and not (old is None and (home / name).read_bytes().strip() == b''):
            errors.append(f'profile changed: {home / name}: {(home / name).read_text(errors="replace")[-400:]!r}')
    if project_state(project) != before['project']:
        errors.append(f'project changed: {project_state(project)}')
    if os.name == 'nt':
        local = Path(os.environ['LOCALAPPDATA']) / 'Programs' / 'Getzilla'
        if local.exists():
            errors.append(f'still present: {local}')
        path = windows_user('Path') or ''
        for entry in path.split(';'):
            low = entry.lower()
            if entry and (str(getzilla_home).lower() in low or '.getzilla' in low or str(local).lower() in low):
                errors.append(f'user PATH entry left: {entry}')
        for name in VARIABLES:
            if windows_user(name) is not None:
                errors.append(f'user variable left: {name}')
    for error in errors:
        print(f'::error title=uninstall-e2e::{error}')
    print('uninstall e2e: clean' if not errors else f'uninstall e2e: {len(errors)} problems')
    return 1 if errors else 0


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == 'snapshot':
        return snapshot(Path(argv[1]), Path(argv[2]))
    if len(argv) >= 4 and argv[0] == 'verify':
        return verify(Path(argv[1]), Path(argv[2]), Path(argv[3]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
