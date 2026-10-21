"""getzilla update: bring Getzilla, the current project and the third-party tools up to date.

1. Getzilla itself. A checkout on a branch fast-forwards; a detached checkout (what the installer
   makes) moves to the fetched ref. Local changes skip this step; they are never discarded.
2. The project around the current folder, or the path given. The managed files of the updated
   Getzilla (the same set `install_into.py --plan` lists) are written on a new branch
   `getzilla-update-<version>` and committed there. The project must be a clean Git work tree.
   Nothing is pushed, nothing is deleted, and an up-to-date project gets no branch. Paths the
   project keeps (`.getzilla/AGBP_SYNC.json`) are left alone; in AGENTS.md only the managed
   block is replaced.
3. Third-party tools: `getzilla_update.py`, as before.

The tool options (--only, --status, --if-due, --now, --quiet) keep their old meaning and run step 3 alone.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

HOME = Path(__file__).resolve().parents[1]
TOOL_OPTIONS = ('--only', '--status', '--if-due', '--now', '--quiet')
BRANCH_PREFIX = 'getzilla-update-'


class UpdateError(RuntimeError):
    pass


def git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(['git', '-C', str(cwd), *args], capture_output=True, text=True, encoding='utf-8',
                          errors='replace', check=False)


def _git_out(cwd: Path, *args: str) -> str:
    proc = git(cwd, *args)
    if proc.returncode != 0:
        raise UpdateError(f"git {' '.join(args)} failed in {cwd}: {(proc.stderr or proc.stdout).strip()}")
    return proc.stdout.strip()


def update_self(home: Path, ref: str | None) -> str:
    """Move the Getzilla checkout forward; returns a one-line result."""
    if not (home / '.git').exists():
        return f'skip Getzilla: {home} is not a Git checkout'
    if _git_out(home, 'status', '--porcelain'):
        return f'skip Getzilla: {home} has local changes'
    before = _git_out(home, 'rev-parse', 'HEAD')
    branch = git(home, 'symbolic-ref', '-q', '--short', 'HEAD').stdout.strip()
    if branch and ref is None:
        _git_out(home, 'pull', '--ff-only', '--quiet')
    else:
        _git_out(home, 'fetch', '--quiet', '--depth', '1', 'origin', ref or 'main')
        _git_out(home, 'checkout', '--quiet', '--detach', 'FETCH_HEAD')
    after = _git_out(home, 'rev-parse', 'HEAD')
    return 'Getzilla is up to date' if after == before else f'Getzilla updated: {before[:12]} -> {after[:12]}'


def find_project(start: Path, home: Path) -> Path | None:
    """The nearest folder at or above start that carries Getzilla, unless it is Getzilla itself."""
    start = start.resolve()
    for base in (start, *start.parents):
        if (base / '.getzilla').is_dir():
            return None if base == home.resolve() else base
    return None


def load_installer(home: Path):
    spec = importlib.util.spec_from_file_location('getzilla_install_into', home / 'scripts/install_into.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module while the class is built
    spec.loader.exec_module(module)
    return module


def merge_agents(installer, existing: bytes | None, block: bytes) -> bytes:
    """Replace only the managed block of the project's AGENTS.md; its own text stays."""
    if existing is None:
        return block
    text, managed = existing.decode('utf-8'), block.decode('utf-8')
    start, end = text.find(installer.MANAGED_START), text.find(installer.MANAGED_END)
    if start < 0 and end < 0:
        return (text.rstrip('\n') + '\n\n' + managed).encode('utf-8') if text.strip() else block
    if start < 0 or end < start:
        raise UpdateError('AGENTS.md has a broken Getzilla managed block: fix its markers first')
    end += len(installer.MANAGED_END)
    if text[end:end + 1] == '\n':
        end += 1
    return (text[:start] + managed + text[end:]).encode('utf-8')


def safe_destination(project: Path, relative: str) -> Path:
    destination = project.joinpath(*relative.split('/'))
    if destination.is_symlink():
        raise UpdateError(f'refusing to write through a link: {relative}')
    parent = Path(os.path.realpath(destination.parent))
    if parent != project and project not in parent.parents:
        raise UpdateError(f'refusing to write outside the project: {relative}')
    return destination


def planned_changes(installer, home: Path, project: Path) -> list[tuple[str, bytes, int]]:
    """(path, new bytes, mode) for every managed file whose bytes or executable bit differ."""
    selection = installer.PayloadSelection(
        installer.detect_agents(project),
        extras=installer.detect_extras(project),
        root_shims=installer.has_root_shims(project),
        engine_archive=installer.wants_engine_archive(project),
    )
    plan = installer._make_plan(home, project, include_dependencies=False, include_optional=False,
                                selection=selection)
    if plan['target_state'] != 'directory':
        raise UpdateError(f'{project} is not a plain directory')
    wanted = {entry['path'] for entry in plan['entries']}
    changes = []
    for entry in installer.build_payload(home, selection=selection):
        if entry.path not in wanted:
            continue
        existing = installer._read_target_relative(project, entry.path, limit=installer.MAX_SOURCE_FILE_BYTES)
        content = merge_agents(installer, existing, entry.content) if entry.path == 'AGENTS.md' else entry.content
        mode = entry.mode & 0o777
        same_mode = True
        if existing is not None and os.name != 'nt':
            same_mode = (os.stat(project / entry.path).st_mode & 0o111) == (mode & 0o111)
        if existing != content or not same_mode:
            changes.append((entry.path, content, mode))
    return changes


def version_of(home: Path) -> str:
    try:
        return (home / 'VERSION').read_text(encoding='utf-8').strip() or 'latest'
    except OSError:
        return 'latest'


def sync_project(home: Path, project: Path) -> str:
    """Write the managed files on a new branch and commit them; returns a one-line result."""
    project = project.resolve()
    top = git(project, 'rev-parse', '--show-toplevel')
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != project:
        raise UpdateError(f'{project} is not the root of a Git repository')
    if _git_out(project, 'status', '--porcelain', '--untracked-files=all'):
        raise UpdateError(f'{project} has uncommitted changes: commit or stash them first')
    installer = load_installer(home)
    try:
        changes = planned_changes(installer, home, project)
    except installer.UnsafeInstallTarget as exc:
        raise UpdateError(str(exc)) from exc
    if not changes:
        return f'{project.name} is up to date'
    branch = BRANCH_PREFIX + version_of(home)
    if git(project, 'rev-parse', '--verify', '--quiet', f'refs/heads/{branch}').returncode == 0:
        raise UpdateError(f'branch {branch} already exists in {project}: merge or delete it first')
    destinations = [(safe_destination(project, path), content, mode) for path, content, mode in changes]
    _git_out(project, 'switch', '--quiet', '-c', branch)
    for destination, content, mode in destinations:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        if os.name != 'nt':
            os.chmod(destination, mode)
    _git_out(project, 'add', '--', *(path for path, _, _ in changes))
    _git_out(project, 'commit', '--quiet', '-m', f'chore: update Getzilla to {version_of(home)}')
    return (f'{project.name}: {len(changes)} file(s) updated on branch {branch}; '
            'review it and open a pull request')


def run_tools(home: Path, args: list[str]) -> int:
    return subprocess.run([sys.executable, str(home / 'scripts/getzilla_update.py'), *args], check=False).returncode


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(arg.split('=')[0] in TOOL_OPTIONS for arg in argv):
        return run_tools(HOME, argv)
    parser = argparse.ArgumentParser(prog='getzilla update', description=__doc__.splitlines()[0])
    parser.add_argument('project', nargs='?', help='project to update (default: the one around this folder)')
    parser.add_argument('--ref', help='branch or tag for a detached Getzilla checkout (default: main)')
    parser.add_argument('--no-self', action='store_true', help='do not update Getzilla itself')
    parser.add_argument('--no-tools', action='store_true', help='do not update third-party tools')
    args = parser.parse_args(argv)
    try:
        if not args.no_self:
            print(update_self(HOME, args.ref), flush=True)
            # Steps 2 and 3 run on the code just fetched, not on this process's old copy.
            project = args.project or find_project(Path.cwd(), HOME)
            rest = [*([str(project)] if project else []), '--no-self', *(['--no-tools'] if args.no_tools else [])]
            return subprocess.run([sys.executable, str(HOME / 'scripts/getzilla_upgrade.py'), *rest],
                                  check=False).returncode
        project = Path(args.project) if args.project else find_project(Path.cwd(), HOME)
        if project is None:
            print('no project here: run `getzilla update` inside a project to update it too')
        else:
            print(sync_project(HOME, project), flush=True)
    except UpdateError as exc:
        print(f'getzilla update: {exc}', file=sys.stderr)
        return 1
    return 0 if args.no_tools else run_tools(HOME, [])


if __name__ == '__main__':
    raise SystemExit(main())
