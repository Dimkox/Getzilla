"""getzilla update: bring Getzilla, the current project and the third-party tools up to date.

1. core: Getzilla itself. A checkout on a branch fast-forwards; a detached checkout (what the
   installer makes) moves to the fetched ref. Local changes skip this step; they are never discarded.
2. project: the project around the current folder, or the path given. The managed files of the
   updated Getzilla (the same set `install_into.py --plan` lists) are committed on a new branch
   `getzilla-update-<version>`, which is then checked out. The commit is built in a private Git
   index, so a failure at any step leaves the project as it was. The project must be a clean Git
   work tree. Nothing is pushed or deleted, and an up-to-date project gets no branch. Paths the
   project keeps (`.getzilla/AGBP_SYNC.json`) are left alone; in AGENTS.md only the managed block
   is replaced.
3. tools: the third-party tools, through `getzilla_update.py` as before.

`getzilla update` runs all three; `getzilla update core|project|tools` runs one. The tool options
(--only, --status, --if-due, --now, --quiet) keep their old meaning and run step 3 alone.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HOME = Path(__file__).resolve().parents[1]
TOOL_OPTIONS = ('--only', '--status', '--if-due', '--now', '--quiet')
OWN_OPTIONS = ('--ref', '--no-self', '--no-tools', '--help')
BRANCH_PREFIX = 'getzilla-update-'
STEPS = {
    'core': 'update only Getzilla itself',
    'project': 'update only the project, on a new branch',
    'tools': 'update only the third-party tools (getzilla_update.py options apply)',
}


class UpdateError(RuntimeError):
    pass


def git(cwd: Path, *args: str, data: bytes | None = None,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run git in cwd; output stays bytes when data is given, else text."""
    return subprocess.run(['git', '-C', str(cwd), *args], input=data, capture_output=True,
                          text=data is None, encoding='utf-8' if data is None else None,
                          errors='replace' if data is None else None, env=env, check=False)


def _git_out(cwd: Path, *args: str, data: bytes | None = None, env: dict[str, str] | None = None) -> str:
    proc = git(cwd, *args, data=data, env=env)
    out, err = proc.stdout, proc.stderr
    if isinstance(out, bytes):
        out, err = out.decode('utf-8', 'replace'), err.decode('utf-8', 'replace')
    if proc.returncode != 0:
        raise UpdateError(f"git {args[0]} failed in {cwd}: {(err or out).strip()}")
    return out.strip()


def update_self(home: Path, ref: str | None) -> str:
    """Move the Getzilla checkout forward; returns a one-line result."""
    if not (home / '.git').exists():
        return f'skip core: {home} is not a Git checkout'
    if _git_out(home, 'status', '--porcelain'):
        return f'skip core: {home} has local changes'
    before = _git_out(home, 'rev-parse', 'HEAD')
    branch = git(home, 'symbolic-ref', '-q', '--short', 'HEAD').stdout.strip()
    if branch and ref is not None:
        raise UpdateError(f'{home} is on branch {branch}: --ref works only for a detached checkout')
    if branch:
        _git_out(home, 'pull', '--ff-only', '--quiet')
    else:
        # Keep a full clone full; only a shallow one (the installer's) fetches shallow.
        shallow = _git_out(home, 'rev-parse', '--is-shallow-repository') == 'true'
        _git_out(home, 'fetch', '--quiet', *(['--depth', '1'] if shallow else []), 'origin', ref or 'main')
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
    try:
        text, managed = existing.decode('utf-8'), block.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise UpdateError('AGENTS.md is not UTF-8: convert it first') from exc
    start, end = text.find(installer.MANAGED_START), text.find(installer.MANAGED_END)
    if start < 0 and end < 0:
        return (text.rstrip('\n') + '\n\n' + managed).encode('utf-8') if text.strip() else block
    if start < 0 or end < start:
        raise UpdateError('AGENTS.md has a broken Getzilla managed block: fix its markers first')
    end += len(installer.MANAGED_END)
    if text[end:end + 1] == '\n':
        end += 1
    return (text[:start] + managed + text[end:]).encode('utf-8')


def head_tree(project: Path) -> dict[str, tuple[str, str]]:
    """path -> (mode, object id) for every file and link committed at HEAD."""
    raw = git(project, 'ls-tree', '-r', '-z', '--full-tree', 'HEAD', data=b'')
    if raw.returncode != 0:
        raise UpdateError(f'{project} has no commit yet: commit once first')
    tree = {}
    for record in raw.stdout.split(b'\0'):
        if record:
            meta, path = record.split(b'\t', 1)
            mode, _kind, oid = meta.decode().split()
            tree[path.decode('utf-8', 'surrogateescape')] = (mode, oid)
    return tree


def blob_id(content: bytes, object_format: str) -> str:
    # A Git object id, not a security digest.
    digest = hashlib.sha256() if object_format == 'sha256' else hashlib.sha1(usedforsecurity=False)
    digest.update(b'blob %d\0' % len(content) + content)
    return digest.hexdigest()


def planned_changes(installer, home: Path, project: Path) -> list[tuple[str, bytes, str]]:
    """(path, new bytes, Git mode) for every managed file that differs from the project's HEAD."""
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
    tree = head_tree(project)
    object_format = git(project, 'rev-parse', '--show-object-format').stdout.strip() or 'sha1'
    changes = []
    for entry in installer.build_payload(home, selection=selection):
        if entry.path not in wanted:
            continue
        content = entry.content
        if entry.path == 'AGENTS.md':
            existing = git(project, 'cat-file', 'blob', 'HEAD:AGENTS.md', data=b'').stdout \
                if 'AGENTS.md' in tree else None
            content = merge_agents(installer, existing, content)
        mode = '100755' if entry.mode & 0o111 else '100644'
        if tree.get(entry.path) == (mode, blob_id(content, object_format)):
            continue
        parts = entry.path.split('/')
        for depth in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:depth])
            committed = tree.get(prefix)
            if committed and (committed[0] == '120000' or depth < len(parts)):
                raise UpdateError(f'refusing to write through a committed link or file: {prefix}')
        changes.append((entry.path, content, mode))
    return changes


def version_of(home: Path) -> str:
    try:
        return (home / 'VERSION').read_text(encoding='utf-8').strip() or 'latest'
    except OSError:
        return 'latest'


def commit_changes(project: Path, changes: list[tuple[str, bytes, str]], message: str) -> str:
    """Build the commit in a private index; the work tree and the project's index stay untouched."""
    with tempfile.TemporaryDirectory(prefix='getzilla-update-') as scratch:
        env = {**os.environ, 'GIT_INDEX_FILE': str(Path(scratch) / 'index')}
        _git_out(project, 'read-tree', 'HEAD', env=env)
        lines = []
        for path, content, mode in changes:
            oid = _git_out(project, 'hash-object', '-w', '--stdin', data=content)
            lines.append(f'{mode} {oid}\t{path}')
        _git_out(project, 'update-index', '--index-info', data=('\n'.join(lines) + '\n').encode('utf-8'), env=env)
        tree = _git_out(project, 'write-tree', env=env)
    return _git_out(project, 'commit-tree', tree, '-p', 'HEAD', '-m', message)


def sync_project(home: Path, project: Path) -> str:
    """Commit the managed files on a new branch and check it out; returns a one-line result."""
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
    version = version_of(home)
    branch = BRANCH_PREFIX + version
    if git(project, 'rev-parse', '--verify', '--quiet', f'refs/heads/{branch}').returncode == 0:
        raise UpdateError(f'branch {branch} already exists in {project}: merge or delete it first')
    # `git switch` overwrites ignored files without asking; an ignored local file on a managed path is work.
    ignored = _git_out(project, 'ls-files', '--others', '--ignored', '--exclude-standard', '--',
                       *(path for path, _, _ in changes))
    if ignored:
        raise UpdateError(f'ignored local files sit on managed paths; move them first: {", ".join(ignored.splitlines())}')
    commit = commit_changes(project, changes, f'chore: update Getzilla to {version}')
    _git_out(project, 'branch', branch, commit)
    switched = git(project, 'switch', '--quiet', branch)
    if switched.returncode != 0:
        raise UpdateError(f'commit is on branch {branch}, but checking it out failed: '
                          f'{switched.stderr.strip()}; run `git switch {branch}`')
    return (f'{project.name}: {len(changes)} file(s) updated on branch {branch}; '
            'review it and open a pull request')


def run_tools(home: Path, args: list[str]) -> int:
    return subprocess.run([sys.executable, str(home / 'scripts/getzilla_update.py'), *args], check=False).returncode


def is_tool_option(arg: str) -> bool:
    """A tool option, or an abbreviation argparse accepted before, that is not one of ours."""
    name = arg.split('=')[0]
    if not name.startswith('--') or len(name) < 3:
        return False
    return any(option.startswith(name) for option in TOOL_OPTIONS) and \
        not any(option.startswith(name) for option in OWN_OPTIONS)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    step, rest = (argv[0], argv[1:]) if argv and argv[0] in STEPS else (None, argv)
    if step == 'tools':
        return run_tools(HOME, rest)
    if step is None and any(is_tool_option(arg) for arg in rest):
        return run_tools(HOME, [arg for arg in rest if arg not in ('--no-self', '--no-tools')])
    parser = argparse.ArgumentParser(
        prog=f"getzilla update{' ' + step if step else ''}", description=__doc__.splitlines()[0],
        epilog='steps: ' + '; '.join(f'`getzilla update {name}` {summary}' for name, summary in STEPS.items()))
    if step != 'core':
        parser.add_argument('project', nargs='?', help='project to update (default: the one around this folder)')
    if step is None or step == 'core':
        parser.add_argument('--ref', help='branch or tag for a detached Getzilla checkout (default: main)')
    if step is None:
        parser.add_argument('--no-self', action='store_true', help='do not update Getzilla itself')
        parser.add_argument('--no-tools', action='store_true', help='do not update third-party tools')
    args = parser.parse_args(rest)
    try:
        if step == 'core':
            print(update_self(HOME, args.ref))
            return 0
        if step is None and not args.no_self:
            print(update_self(HOME, args.ref), flush=True)
            # Steps 2 and 3 run on the code just fetched, not on this process's old copy.
            project = args.project or find_project(Path.cwd(), HOME)
            again = [*([str(project)] if project else []), '--no-self', *(['--no-tools'] if args.no_tools else [])]
            return subprocess.run([sys.executable, str(HOME / 'scripts/getzilla_upgrade.py'), *again],
                                  check=False).returncode
        project = Path(args.project) if args.project else find_project(Path.cwd(), HOME)
        if project is None:
            print('no project here: run `getzilla update` inside a project to update it too')
        else:
            print(sync_project(HOME, project), flush=True)
    except UpdateError as exc:
        print(f'getzilla update: {exc}', file=sys.stderr)
        return 1
    return 0 if step == 'project' or args.no_tools else run_tools(HOME, [])


if __name__ == '__main__':
    raise SystemExit(main())
