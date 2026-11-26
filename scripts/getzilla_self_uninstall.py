"""Remove Getzilla from this machine: the reverse of the one-command installer.

It removes only what the installer wrote and keeps your projects, system packages and agent sign-ins.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import agent_setup  # noqa: E402
from getzilla import machine_uninstall as mu  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='getzilla self-uninstall', description='Remove Getzilla from this '
                                     'machine. Your projects are not changed. It shows the plan and asks first.')
    parser.add_argument('--home', help='Getzilla checkout (default: GETZILLA_HOME, else this checkout)')
    parser.add_argument('--dry-run', action='store_true', help='show the plan and change nothing')
    parser.add_argument('--yes', '-y', action='store_true', help='do not ask for confirmation')
    parser.add_argument('--force', action='store_true', help='remove the checkout even with uncommitted changes')
    parser.add_argument('--keep-checkout', action='store_true', help='keep the Getzilla checkout folder')
    parser.add_argument('--keep-state', action='store_true', help='keep ~/.getzilla (managed tools, agents, OSV data)')
    parser.add_argument('--keep-agent-config', action='store_true', help='keep agent OpenRouter settings and keys')
    parser.add_argument('--deferred-file', help=argparse.SUPPRESS)  # scripts/uninstall.ps1 removes these later
    return parser


def fail(message: str) -> int:
    print(f'ERROR: {message}', file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    user = Path.home()
    home = Path(args.home or os.environ.get('GETZILLA_HOME') or ROOT).expanduser()
    state = Path(os.environ.get('GETZILLA_STATE_HOME') or user / '.getzilla').expanduser()
    folders = [] if args.keep_state else [state]
    programs = Path(os.environ.get('LOCALAPPDATA') or user / 'AppData/Local') / 'Programs' / 'Getzilla'
    if os.name == 'nt':
        folders.append(programs)  # portable runtimes from install.ps1
    if not args.keep_checkout:
        if not mu.is_checkout(home):
            return fail(f'{home} is not a Getzilla checkout. Pass --home or --keep-checkout.')
        dirty = mu.dirty_files(home)
        if dirty and not args.force:
            print('\n'.join(f'  {line}' for line in dirty[:20]), file=sys.stderr)
            return fail(f'{home} has uncommitted changes. Save them, or pass --force or --keep-checkout.')
        folders.append(home)
    for folder in folders:
        if mu.unsafe_target(folder, user):
            return fail(f'refusing to remove {folder}: it is the home folder, a root or its parent.')
    link = user / '.local' / 'bin' / 'getzilla'
    folders = [folder for folder in folders if folder.exists()] + ([link] if mu.owned_link(link, home) else [])
    path_profiles = [user / name for name in mu.PROFILES if mu.strip_path_block(user / name, apply=False)]
    key_profiles = [user / name for name in mu.PROFILES if mu.has_key_block(user / name)]
    user_path, path_kind = mu.windows_user_path() if os.name == 'nt' else ([], 0)
    stale = [entry for entry in user_path if mu.inside(entry, [home, state, programs])]
    plan = [f'PATH line: {p}' for p in path_profiles] + [f'remove: {f}' for f in folders]
    plan += [f'user PATH entry: {entry}' for entry in stale]
    if not args.keep_agent_config:
        plan += [f'agent settings: Getzilla entries in {user / rel}' for rel in mu.AGENT_FILES if (user / rel).is_file()]
        plan += [f'model key lines: {p}' for p in key_profiles]
    print('Getzilla uninstall plan (your projects are not changed):')
    print('\n'.join(f'  {line}' for line in plan))
    if args.dry_run:
        print('Dry run: nothing was changed.')
        return 0
    if not args.yes:
        if not sys.stdin.isatty():
            return fail('no terminal to confirm; run again with --yes or --dry-run.')
        if input('Remove all of the above? [y/N]: ').strip().lower() not in ('y', 'yes', 'д', 'да'):
            print('Cancelled: nothing was changed.')
            return 1
    problems: list[str] = []
    if not args.keep_agent_config:
        for undo in (agent_setup._unconfigure_qwen, agent_setup._unconfigure_claude, agent_setup._unconfigure_codex):
            try:
                for item in undo(user):
                    print(f'removed: Getzilla settings in {item}')
            except (ValueError, OSError) as exc:
                problems.append(str(exc))
        agent_setup._store_env(user, {}, remove=mu.ENV_NAMES)
    if not args.keep_agent_config or not args.keep_state:
        for item in agent_setup._remove_profiles(user):
            print(f'removed: key lines in {item}')
    for profile in path_profiles:
        mu.strip_path_block(profile, apply=True)
        print(f'removed: PATH line in {profile}')
    if stale:
        mu.set_windows_user_path([entry for entry in user_path if entry not in stale], path_kind)
        print('removed: Getzilla entries in the user PATH')
    deferred = [folder for folder in folders if mu.used_by_this_python(folder)]
    if deferred and args.deferred_file:
        Path(args.deferred_file).write_text(''.join(f'{folder}\n' for folder in deferred), encoding='utf-8')
    elif deferred:
        problems.append(f'{deferred[0]} is in use by this Python; run scripts\\uninstall.ps1 instead')
    for folder in (folder for folder in folders if folder not in deferred):
        try:
            mu.remove_tree(folder)
            print(f'removed: {folder}')
        except OSError as exc:
            problems.append(f'{folder}: {exc}')
    for problem in problems:
        print(f'WARNING: {problem}', file=sys.stderr)
    print('Getzilla is removed. Open a new terminal so the PATH change applies.')
    return 3 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
