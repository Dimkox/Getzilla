"""Report machine installation paths for a self-uninstall preview."""
from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]


def local_commit_retention_reason(checkout: Path) -> str | None:
    """Check local refs (including stash) and reflogs against the last known origin tips."""
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_ALLOW_PROTOCOL='',
               GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
    try:
        result = subprocess.run(
            ['git', '--no-replace-objects', '--git-dir', str(checkout / '.git'),
             '--work-tree', str(checkout), 'rev-list', '--max-count=1', 'HEAD', '--all',
             '--reflog', '--not', '--remotes=origin', '--'],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 'cannot verify local commits'
    if result.returncode:
        return 'cannot verify local commits'
    return 'locally held commits' if result.stdout.strip() else None


def checkout_retention_reason(checkout: Path, user: Path) -> str | None:
    """Recognize shared Git storage and protected roots using metadata only."""
    if user.resolve().is_relative_to(checkout):
        return 'contains the user home'
    if checkout == Path(checkout.anchor):
        return 'filesystem root'
    git = checkout / '.git'
    try:
        metadata = git.lstat()
    except FileNotFoundError:
        return 'Git metadata unavailable'
    if (not stat.S_ISDIR(metadata.st_mode)
            or getattr(metadata, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        return 'external Git metadata'
    for path, reason in (('commondir', 'external Git metadata'), ('worktrees', 'registered worktrees')):
        try:
            (git / path).lstat()
        except FileNotFoundError:
            continue
        return reason
    return local_commit_retention_reason(checkout)


def preview(*, keep_checkout: bool, keep_state: bool) -> None:
    user = Path.home()
    state = Path(os.environ.get('GETZILLA_STATE_HOME') or user / '.getzilla').expanduser()
    paths = []
    print('Machine uninstall preview (read-only)')
    if not keep_checkout:
        reason = checkout_retention_reason(ROOT, user)
        if reason:
            print(f'Getzilla checkout [retain: {reason}]: {ROOT}')
        else:
            paths.append(('Getzilla checkout', ROOT))
    if not keep_state:
        paths.append(('Managed state', state))
        if tools := os.environ.get('GETZILLA_TOOLCHAINS'):
            paths.append(('Configured toolchain directory', Path(tools).expanduser()))
    if os.name == 'nt':
        local = Path(os.environ.get('LOCALAPPDATA') or user / 'AppData/Local')
        paths.append(('Portable runtimes', local / 'Programs/Getzilla'))
    else:
        command = user / '.local/bin/getzilla'
        if command.is_symlink() and Path(os.path.abspath(command.parent / command.readlink())) == ROOT / 'bin/getzilla':
            paths.append(('Getzilla command link', command))
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
    parser.add_argument('--keep-checkout', action='store_true', help='retain the Getzilla checkout')
    parser.add_argument('--keep-state', action='store_true', help='retain managed state and toolchains')
    args = parser.parse_args()
    try:
        preview(keep_checkout=args.keep_checkout, keep_state=args.keep_state)
    except OSError as exc:
        parser.exit(2, f'Could not inspect the installation: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
