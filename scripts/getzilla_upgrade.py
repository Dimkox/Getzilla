"""getzilla update: bring Getzilla, the current project and the third-party tools up to date.

1. core: Getzilla itself. A checkout on a branch fast-forwards; a detached checkout (what the
   installer makes) moves to the fetched ref. Local changes skip this step; they are never discarded.
2. project: the project around the current folder, or the path given. The managed files of the
   updated Getzilla (the same set `install_into.py --plan` lists) are committed on a new branch
   `getzilla-update-<version>`, which is then checked out. The commit is built in a private Git
   index, so a failure at any step leaves the project as it was. The project must be a clean Git
   work tree. Nothing is pushed, nothing is deleted without --retire-legacy, and an up-to-date
   project gets no branch. Paths the
   project keeps (`.getzilla/AGBP_SYNC.json`) are left alone; in AGENTS.md only the managed block
   is replaced. The project's own ruff.toml, bandit.yaml and .coveragerc stay; --retire-legacy also removes
   committed pre-rename files (.grok-stack, scripts/grok_*) once nothing imports the old engine.
3. tools: the third-party tools, through `getzilla_update.py` as before.

`getzilla update` runs all three; `getzilla update core|project|tools` runs one. The tool options
(--only, --status, --if-due, --now, --quiet) keep their old meaning and run step 3 alone.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HOME = Path(__file__).resolve().parents[1]
TOOL_OPTIONS = ('--only', '--status', '--if-due', '--now', '--quiet')
OWN_OPTIONS = ('--ref', '--no-self', '--no-tools', '--accept-local', '--retire-legacy', '--help')
BRANCH_PREFIX = 'getzilla-update-'
# Lint and coverage settings name the project's own paths and rules; Getzilla's copy is only a first default.
PROJECT_CONFIGS = frozenset({'ruff.toml', 'bandit.yaml', '.coveragerc'})
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
        if (base / '.getzilla').is_dir() or (base / '.grok-stack').is_dir():
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


def accept_local(installer, project: Path) -> tuple[dict[str, str], bytes | None, list[str]]:
    """Digests of the kept paths as committed now: (digests, new sync record or None, accepted paths).

    A kept path with a recorded digest stops the update once its bytes change. `--accept-local`
    records the committed bytes as the project's chosen version instead; it never changes them.
    """
    raw = git(project, 'cat-file', 'blob', f'HEAD:{installer.STACK_SYNC_RECORD}', data=b'')
    if raw.returncode != 0:
        return {}, None, []
    installer._kept_local(project)  # the same shape checks the plan applies
    record = json.loads(raw.stdout.decode('utf-8'))
    digests = dict(record.get('kept_local_sha256', {}))
    accepted = []
    for path, digest in sorted(digests.items()):
        blob = git(project, 'cat-file', 'blob', f'HEAD:{path}', data=b'')
        if blob.returncode != 0:
            continue  # an absent kept path is already allowed
        current = hashlib.sha256(blob.stdout).hexdigest()
        if current != digest:
            digests[path] = current
            accepted.append(path)
    if not accepted:
        return digests, None, []
    record['kept_local_sha256'] = digests
    return digests, (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8'), accepted


def legacy_report(installer, project: Path, tree: dict[str, tuple[str, str]],
                  incoming: set[str]) -> tuple[list[str], list[str], list[str]]:
    """(committed pre-rename paths, project files that import the old engine, old engine paths the sync record keeps).

    Only a pre-rename file whose Getzilla replacement is committed or arrives with this update is
    retired; one without a replacement (a vendored factory the update does not install) stays.
    """
    present = set(tree) | incoming

    def replaced(path: str) -> bool:
        current = installer.legacy_to_current_path(path)
        # The engine may ship as one archive instead of a folder of modules.
        return current in present or (current.startswith(installer.ENGINE_DIR) and installer.ENGINE_ARCHIVE in present)

    retire = sorted(item['path'] for item in installer._legacy_migration(project)
                    if item['path'] in tree and replaced(item['path']))
    retired = set(retire)
    found = git(project, 'grep', '-l', '-I', '-F', '-e', 'adaptive_grok', '-e', '.grok-stack/', 'HEAD', '--', '*.py')
    importers = sorted({line.split(':', 1)[1] for line in found.stdout.splitlines() if ':' in line} - retired) \
        if found.returncode == 0 else []
    record = git(project, 'cat-file', 'blob', f'HEAD:{installer.LEGACY_STACK_SYNC_RECORD}')
    kept = []
    if record.returncode == 0:
        try:
            kept = sorted(path for path in json.loads(record.stdout).get('kept_local', [])
                          if isinstance(path, str) and path.startswith(installer.LEGACY_STACK_DIR + '/'))
        except (ValueError, AttributeError):
            kept = []
    return retire, importers, kept


def sync_record(installer, project: Path, tree: dict[str, tuple[str, str]]) -> bytes | None:
    """The sync record to add when the project has none: the pre-rename one with its paths renamed, or a fresh one."""
    if installer.STACK_SYNC_RECORD in tree:
        return None
    if installer.LEGACY_STACK_SYNC_RECORD not in tree:
        return installer.FRESH_SYNC_RECORD
    record = json.loads(git(project, 'cat-file', 'blob', f'HEAD:{installer.LEGACY_STACK_SYNC_RECORD}').stdout)
    rename = installer.legacy_to_current_path
    record['kept_local'] = [rename(path) for path in record.get('kept_local', [])]
    record['kept_local_sha256'] = {rename(path): digest for path, digest in record.get('kept_local_sha256', {}).items()}
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8')


def planned_changes(installer, home: Path, project: Path,
                    digests: dict[str, str] | None = None,
                    kept_configs: list[str] | None = None) -> list[tuple[str, bytes, str]]:
    """(path, new bytes, Git mode) for every managed file that differs from the project's HEAD.

    A lint or coverage configuration the project already commits is its own and stays; its path
    goes to kept_configs.
    """
    if digests is not None:
        # This installer module was loaded for this run only, so the override stays local to it.
        installer._kept_local_digests = lambda _target: digests
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
        if entry.path in PROJECT_CONFIGS and entry.path in tree:
            if kept_configs is not None:
                kept_configs.append(entry.path)
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


def commit_changes(project: Path, changes: list[tuple[str, bytes | None, str]], message: str) -> str:
    """Build the commit in a private index; the work tree and the project's index stay untouched.

    A change with content None removes that path.
    """
    zero = '0' * len(_git_out(project, 'rev-parse', 'HEAD'))
    with tempfile.TemporaryDirectory(prefix='getzilla-update-') as scratch:
        env = {**os.environ, 'GIT_INDEX_FILE': str(Path(scratch) / 'index')}
        _git_out(project, 'read-tree', 'HEAD', env=env)
        lines = []
        for path, content, mode in changes:
            if content is None:
                lines.append(f'0 {zero}\t{path}')
                continue
            oid = _git_out(project, 'hash-object', '-w', '--stdin', data=content)
            lines.append(f'{mode} {oid}\t{path}')
        _git_out(project, 'update-index', '--index-info', data=('\n'.join(lines) + '\n').encode('utf-8'), env=env)
        tree = _git_out(project, 'write-tree', env=env)
    return _git_out(project, 'commit-tree', tree, '-p', 'HEAD', '-m', message)


def sync_project(home: Path, project: Path, *, accept: bool = False, retire: bool = False) -> str:
    """Commit the managed files on a new branch and check it out; returns the result and its notes."""
    project = project.resolve()
    top = git(project, 'rev-parse', '--show-toplevel')
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != project:
        raise UpdateError(f'{project} is not the root of a Git repository')
    if _git_out(project, 'status', '--porcelain', '--untracked-files=all'):
        raise UpdateError(f'{project} has uncommitted changes: commit or stash them first')
    installer = load_installer(home)
    kept_configs: list[str] = []
    try:
        digests, record, accepted = accept_local(installer, project) if accept else ({}, None, [])
        changes = planned_changes(installer, home, project, digests if accepted else None, kept_configs)
        tree = head_tree(project)
        fresh_record = sync_record(installer, project, tree) if record is None else None
        if fresh_record is not None:
            changes.append((installer.STACK_SYNC_RECORD, fresh_record, '100644'))
        # The sync history log moves with the record, so the old stack folder can go.
        old_log = installer.LEGACY_STACK_DIR + '/AGBP_SYNC.log.jsonl'
        if old_log in tree and installer.legacy_to_current_path(old_log) not in tree:
            changes.append((installer.legacy_to_current_path(old_log),
                            git(project, 'cat-file', 'blob', f'HEAD:{old_log}', data=b'').stdout, tree[old_log][0]))
        legacy, importers, legacy_kept = legacy_report(installer, project, tree, {path for path, _, _ in changes})
    except installer.UnsafeInstallTarget as exc:
        hint = ('; if the current version is the one you want, run `getzilla update --accept-local`'
                if 'no longer matches its declared divergence' in str(exc) else '')
        raise UpdateError(f'{exc}{hint}') from exc
    except json.JSONDecodeError as exc:
        raise UpdateError(f'the pre-rename sync record is not valid JSON: {exc}') from exc
    if record is not None:
        changes.append((installer.STACK_SYNC_RECORD, record, '100644'))
    if retire and legacy and (importers or legacy_kept):
        raise UpdateError('the project still depends on the old engine; port these first, then retire it: '
                          + ', '.join(importers + legacy_kept))
    notes = []
    if kept_configs:
        notes.append(f'kept your own {", ".join(sorted(kept_configs))}; Getzilla does not replace them')
    if legacy_kept:
        notes.append('your sync record keeps changed old-engine files, which the new engine does not carry: '
                     + ', '.join(legacy_kept))
    if importers:
        notes.append('these files import the old engine and need porting: ' + ', '.join(importers))
    unreplaced = [item['path'] for item in installer._legacy_migration(project)
                  if item['path'] in tree and item['path'] not in legacy]
    if unreplaced:
        notes.append(f'{len(unreplaced)} pre-rename file(s) have no Getzilla replacement here and stay, '
                     f'for example {unreplaced[0]}')
    if legacy and retire:
        changes.extend((path, None, '') for path in legacy)
        notes.append(f'removed {len(legacy)} pre-rename file(s)')
    elif legacy:
        notes.append(f'{len(legacy)} pre-rename file(s) remain, for example {legacy[0]}; '
                     'run `getzilla update --retire-legacy` to remove them')
    arriving = sorted(path for path, content, mode in changes
                      if content is not None and path not in tree and (mode == '100755' or path.endswith('.py')))
    if arriving:
        notes.append(f'{len(arriving)} new executable file(s) arrive (hooks and scripts); '
                     'approve or exclude them in your own checks')
    if not changes:
        return '\n'.join([f'{project.name} is up to date', *notes])
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
    kept = f'; kept your current {", ".join(accepted)}' if accepted else ''
    return '\n'.join([f'{project.name}: {len(changes)} file(s) updated on branch {branch}{kept}; '
                      'review it and open a pull request', *notes])


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
    if step != 'core':
        parser.add_argument('--accept-local', action='store_true',
                            help='keep the committed version of kept files that changed since their digest was recorded')
        parser.add_argument('--retire-legacy', action='store_true',
                            help='also remove the committed pre-rename files (.grok-stack, scripts/grok_*) in the same commit')
    args = parser.parse_args(rest)
    try:
        if step == 'core':
            print(update_self(HOME, args.ref))
            return 0
        if step is None and not args.no_self:
            print(update_self(HOME, args.ref), flush=True)
            # Steps 2 and 3 run on the code just fetched, not on this process's old copy.
            project = args.project or find_project(Path.cwd(), HOME)
            again = [*([str(project)] if project else []), '--no-self', *(['--no-tools'] if args.no_tools else []),
                     *(['--accept-local'] if args.accept_local else []),
                     *(['--retire-legacy'] if args.retire_legacy else [])]
            return subprocess.run([sys.executable, str(HOME / 'scripts/getzilla_upgrade.py'), *again],
                                  check=False).returncode
        project = Path(args.project) if args.project else find_project(Path.cwd(), HOME)
        if project is None:
            print('no project here: run `getzilla update` inside a project to update it too')
        else:
            print(sync_project(HOME, project, accept=args.accept_local, retire=args.retire_legacy), flush=True)
    except UpdateError as exc:
        print(f'getzilla update: {exc}', file=sys.stderr)
        return 1
    return 0 if step == 'project' or args.no_tools else run_tools(HOME, [])


if __name__ == '__main__':
    raise SystemExit(main())
