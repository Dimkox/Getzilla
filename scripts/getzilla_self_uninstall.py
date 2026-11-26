"""Report machine installation paths for a self-uninstall preview."""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]


def preview() -> None:
    user = Path.home()
    state = Path(os.environ.get('GETZILLA_STATE_HOME') or user / '.getzilla').expanduser()
    paths = [('Getzilla checkout', ROOT), ('Managed state', state)]
    if tools := os.environ.get('GETZILLA_TOOLCHAINS'):
        paths.append(('Configured toolchain directory', Path(tools).expanduser()))
    if os.name == 'nt':
        local = Path(os.environ.get('LOCALAPPDATA') or user / 'AppData/Local')
        paths.append(('Portable runtimes', local / 'Programs/Getzilla'))
    else:
        command = user / '.local/bin/getzilla'
        if command.is_symlink() and Path(os.path.abspath(command.parent / command.readlink())) == ROOT / 'bin/getzilla':
            paths.append(('Getzilla command link', command))
    print('Machine uninstall preview (read-only)')
    for name, path in paths:
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            status = 'absent'
        else:
            status = 'link' if stat.S_ISLNK(mode) else 'present'
        print(f'{name} [{status}]: {path}')


def main() -> int:
    parser = argparse.ArgumentParser(prog='getzilla self-uninstall', description=__doc__)
    parser.add_argument('--dry-run', required=True, action='store_true', help='show installation paths')
    parser.parse_args()
    try:
        preview()
    except OSError as exc:
        parser.exit(2, f'Could not inspect the installation: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
