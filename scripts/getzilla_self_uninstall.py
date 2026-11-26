"""Remove Getzilla from this machine: the reverse of scripts/install.sh and scripts/install.ps1.

What it removes (only what the installer wrote):
  - OpenRouter entries that `setup-agent` wrote to ~/.qwen, ~/.claude and ~/.codex settings;
  - model keys and GETZILLA_OSV_DB (~/.getzilla/openrouter.env and its profile lines,
    or the user environment variables on Windows);
  - the `~/.getzilla/bin` PATH lines in shell profiles, or Getzilla entries in the Windows user PATH;
  - the ~/.local/bin/getzilla link;
  - the state folder (~/.getzilla or GETZILLA_STATE_HOME: managed tools, agents, OSV data, caches);
  - Windows portable runtimes (%LOCALAPPDATA%\\Programs\\Getzilla);
  - the Getzilla checkout (~/Getzilla or GETZILLA_HOME).

What it keeps: your projects, Git/Python/Node.js from the system package manager,
agents installed by their vendors outside ~/.getzilla, agent sign-ins, and Zero-Git
adoption state (use --purge-adoption to remove it as well).

By default it shows the plan and asks. --dry-run only shows the plan, --yes skips the question.
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import os
import shutil
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import agent_setup  # noqa: E402

PATH_MARKER = '# Getzilla: tools in ~/.getzilla/bin'
ENV_NAMES = (agent_setup.KEY_ENV, agent_setup.CLAUDE_TOKEN_ENV, *agent_setup.AGENT_KEY_ENV.values(), 'GETZILLA_OSV_DB')
PROFILES = ('.bashrc', '.zshrc', '.bash_profile', '.profile')


def is_checkout(path: Path) -> bool:
    return (path / 'scripts' / 'getzilla_cli.py').is_file() and (path / '.getzilla' / 'getzilla').is_dir()


def unsafe_target(path: Path, user_home: Path) -> bool:
    """Never remove the user home, a filesystem root or a parent of the user home."""
    resolved = path.resolve()
    return resolved == user_home or resolved == Path(resolved.anchor) or user_home.is_relative_to(resolved)


def dirty_files(home: Path) -> list[str]:
    if not (home / '.git').exists():
        return []
    try:
        result = subprocess.run(['git', '-C', str(home), 'status', '--porcelain', '--untracked-files=no'],
                                capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def strip_path_block(profile: Path, *, apply: bool) -> bool:
    """Remove the PATH_MARKER line and the PATH line the updater wrote after it."""
    if not profile.is_file():
        return False
    lines = profile.read_text(encoding='utf-8').splitlines(keepends=True)
    kept: list[str] = []
    skip_next = False
    for line in lines:
        if line.strip() == PATH_MARKER:
            skip_next = True
            if kept and not kept[-1].strip():
                kept.pop()
            continue
        if skip_next and '.getzilla/bin' in line:
            skip_next = False
            continue
        skip_next = False
        kept.append(line)
    if kept == lines:
        return False
    if apply:
        agent_setup._write_private(profile, ''.join(kept))
    return True


def profile_has_key_block(profile: Path) -> bool:
    return profile.is_file() and agent_setup.PROFILE_MARKER in profile.read_text(encoding='utf-8')


def windows_user_path() -> tuple[list[str], int]:
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment') as key:
        try:
            value, kind = winreg.QueryValueEx(key, 'Path')
        except FileNotFoundError:
            return [], winreg.REG_EXPAND_SZ
    return [part for part in str(value).split(';') if part], kind


def ours(entry: str, roots: list[Path]) -> bool:
    text = os.path.normcase(os.path.normpath(os.path.expandvars(entry)))
    for root in roots:
        base = os.path.normcase(os.path.normpath(str(root)))
        if text == base or text.startswith(base + os.sep):
            return True
    return False


def set_windows_user_path(parts: list[str], kind: int) -> None:
    import ctypes
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, 'Path', 0, kind, ';'.join(parts))
    result = ctypes.c_ulong()
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, 'Environment', 0x0002, 5000, ctypes.byref(result))


def _writable(function, path, _info) -> None:
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    function(path)


def remove_tree(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path, onerror=_writable)  # read-only Git objects on Windows


def locked_by_this_process(path: Path) -> bool:
    """Windows cannot delete the running interpreter or its folder; the PowerShell wrapper does it later."""
    if os.name != 'nt':
        return False
    target = path.resolve()
    running = {sys.executable, getattr(sys, '_base_executable', sys.executable), sys.base_prefix, sys.prefix}
    return any(Path(item).resolve().is_relative_to(target) for item in running if item)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='getzilla self-uninstall',
        description='Remove Getzilla from this machine (the reverse of the one-command installer). '
                    'Your projects are not changed.')
    parser.add_argument('--home', help='Getzilla checkout (default: GETZILLA_HOME, else this checkout)')
    parser.add_argument('--dry-run', action='store_true', help='show the plan and change nothing')
    parser.add_argument('--yes', '-y', action='store_true', help='do not ask for confirmation')
    parser.add_argument('--force', action='store_true', help='remove the checkout even with uncommitted changes')
    parser.add_argument('--keep-checkout', action='store_true', help='keep the Getzilla checkout folder')
    parser.add_argument('--keep-state', action='store_true', help='keep ~/.getzilla (managed tools, agents, OSV data)')
    parser.add_argument('--keep-agent-config', action='store_true',
                        help='keep OpenRouter settings and model keys of the coding agents')
    parser.add_argument('--purge-adoption', action='store_true', help='also remove Zero-Git adoption state')
    parser.add_argument('--deferred-file', help=argparse.SUPPRESS)  # used by scripts/uninstall.ps1
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    user_home = Path.home().resolve()
    home = Path(args.home or os.environ.get('GETZILLA_HOME') or ROOT).expanduser()
    state = Path(os.environ.get('GETZILLA_STATE_HOME') or user_home / '.getzilla').expanduser()
    windows = os.name == 'nt'
    programs = Path(os.environ.get('LOCALAPPDATA') or user_home / 'AppData/Local') / 'Programs' / 'Getzilla'

    folders: list[Path] = []
    if not args.keep_state:
        folders.append(state)
        toolchains = os.environ.get('GETZILLA_TOOLCHAINS')
        if toolchains:
            folders.append(Path(toolchains).expanduser())
    if windows:
        folders.append(programs)
    if args.purge_adoption:
        from getzilla.adoption_state import default_state_root
        folders.append(default_state_root())
    if not args.keep_checkout:
        if not is_checkout(home):
            print(f'ERROR: {home} is not a Getzilla checkout. Pass --home or --keep-checkout.', file=sys.stderr)
            return 2
        dirty = dirty_files(home)
        if dirty and not args.force:
            print(f'ERROR: {home} has uncommitted changes; nothing was changed:', file=sys.stderr)
            for line in dirty[:20]:
                print(f'  {line}', file=sys.stderr)
            print('Commit or save them, or pass --force (or --keep-checkout).', file=sys.stderr)
            return 2
        folders.append(home)
    for folder in folders:
        if unsafe_target(folder, user_home):
            print(f'ERROR: refusing to remove {folder}: it is the home folder, a root or its parent.', file=sys.stderr)
            return 2
    folders = [folder for folder in dict.fromkeys(folders) if folder.exists() or folder.is_symlink()]

    link = user_home / '.local' / 'bin' / 'getzilla'
    remove_link = link.is_symlink() and Path(os.readlink(link)) == home / 'bin' / 'getzilla'

    profiles = [user_home / name for name in PROFILES] if not windows else []
    path_profiles = [p for p in profiles if strip_path_block(p, apply=False)]
    key_profiles = [p for p in profiles if profile_has_key_block(p)]
    env_file = user_home / agent_setup.ENV_FILE

    path_roots = [home, state, programs]
    user_path: list[str] = []
    path_kind = 0
    stale_path: list[str] = []
    if windows:
        user_path, path_kind = windows_user_path()
        stale_path = [entry for entry in user_path if ours(entry, path_roots)]

    agent_files = [user_home / rel for rel in ('.qwen/settings.json', '.claude/settings.json', '.codex/config.toml')]

    print('Getzilla uninstall plan (your projects are not changed):')
    if not args.keep_agent_config:
        print('  agent settings: remove Getzilla OpenRouter entries from existing files of')
        for path in agent_files:
            if path.is_file():
                print(f'    {path}')
        if windows:
            print(f'  user environment variables: {", ".join(ENV_NAMES)}')
        elif env_file.exists() or key_profiles:
            print(f'  model keys: {env_file} and its lines in {", ".join(map(str, key_profiles)) or "no profile"}')
    for profile in path_profiles:
        print(f'  PATH line: {profile}')
    for entry in stale_path:
        print(f'  user PATH entry: {entry}')
    if remove_link:
        print(f'  command link: {link}')
    for folder in folders:
        print(f'  folder: {folder}')
    if args.keep_agent_config and args.keep_state:
        print('  (agent settings, keys and ~/.getzilla are kept)')

    if args.dry_run:
        print('Dry run: nothing was changed.')
        return 0
    if not args.yes:
        if not sys.stdin.isatty():
            print('ERROR: no terminal to confirm; run again with --yes or --dry-run.', file=sys.stderr)
            return 2
        if input('Remove all of the above? [y/N]: ').strip().lower() not in ('y', 'yes', 'д', 'да'):
            print('Cancelled: nothing was changed.')
            return 1

    problems: list[str] = []
    if not args.keep_agent_config:
        for undo in (agent_setup._unconfigure_qwen, agent_setup._unconfigure_claude, agent_setup._unconfigure_codex):
            try:
                for item in undo(user_home):
                    print(f'removed: Getzilla settings in {item}')
            except (ValueError, OSError) as exc:
                problems.append(str(exc))
        try:
            for item in agent_setup._store_env(user_home, {}, remove=ENV_NAMES):
                print(f'removed: {item}')
        except OSError as exc:
            problems.append(str(exc))
    elif not windows and not args.keep_state:
        # The key file lives inside ~/.getzilla: keep it out of the folder removal.
        problems.append(f'{env_file} is removed with ~/.getzilla; copy it first if you need the keys')
    if not windows and not args.keep_state:
        for item in agent_setup._remove_profiles(user_home):
            print(f'removed: key lines in {item}')
    for profile in path_profiles:
        strip_path_block(profile, apply=True)
        print(f'removed: PATH line in {profile}')
    if stale_path:
        set_windows_user_path([entry for entry in user_path if entry not in stale_path], path_kind)
        print('removed: Getzilla entries in the user PATH')
    if remove_link:
        link.unlink()
        print(f'removed: {link}')

    deferred: list[Path] = []
    for folder in folders:
        if locked_by_this_process(folder):
            deferred.append(folder)
            continue
        try:
            remove_tree(folder)
            print(f'removed: {folder}')
        except OSError as exc:
            problems.append(f'{folder}: {exc}')
    if deferred:
        if args.deferred_file:
            Path(args.deferred_file).write_text(''.join(f'{p}\n' for p in deferred), encoding='utf-8')
        else:
            for folder in deferred:
                problems.append(f'{folder} is in use by this Python; close it and delete the folder, '
                                'or run scripts\\uninstall.ps1')

    for problem in problems:
        print(f'WARNING: {problem}', file=sys.stderr)
    print('Getzilla is removed.' if not problems else 'Getzilla is removed with warnings (see above).')
    print('Open a new terminal so the PATH and environment changes apply.')
    return 0 if not problems else 3


if __name__ == '__main__':
    raise SystemExit(main())
