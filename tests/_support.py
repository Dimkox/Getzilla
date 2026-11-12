from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from typing import Iterator

PROJECT = Path(__file__).resolve().parents[1]
CLEANUP_ATTEMPTS = 4


@contextlib.contextmanager
def windows_command_parser() -> Iterator[None]:
    """Exercise Windows syntax while retaining the host's actual lock backend."""
    from types import SimpleNamespace
    from unittest.mock import patch
    from getzilla import _policy_legacy, policy
    parser_platform = SimpleNamespace(WINDOWS=True)
    with patch.object(_policy_legacy, 'fsx', parser_platform), patch.object(policy, 'fsx', parser_platform):
        yield


def missing_history(what: str) -> None:
    """A test reads a commit or tag this clone lacks (#202): skip with the reason, but fail in CI,
    which checks out with fetch-depth: 0 and must not lose the check."""
    message = f'{what} is not in this clone; fetch the full history and tags (CI uses fetch-depth: 0)'
    if os.environ.get('CI') or os.environ.get('GITHUB_ACTIONS'):
        raise AssertionError(message)
    raise unittest.SkipTest(message)


@contextlib.contextmanager
def _test_directory() -> Iterator[str]:
    """A temporary directory whose cleanup retries briefly: a late git child still added a file under
    .git while it was removed, and that failed a passing test on CI (#196). The last failure is raised."""
    directory = tempfile.TemporaryDirectory(prefix='getzilla-test-')
    try:
        yield directory.name
    finally:
        for attempt in range(1, CLEANUP_ATTEMPTS + 1):
            try:
                directory.cleanup()
                break
            except OSError:
                if attempt == CLEANUP_ATTEMPTS:
                    raise
                time.sleep(0.25 * attempt)


@contextlib.contextmanager
def _scanner_environment(minimal_runtime: bool) -> Iterator[None]:
    """Synthetic verifier projects own their OSV inputs; the outer gate keeps its real configuration."""
    keys = ('GETZILLA_OSV_DB', 'GETZILLA_OSV_ONLINE')
    previous = {key: os.environ.pop(key, None) for key in keys}
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextlib.contextmanager
def _session_environment() -> Iterator[None]:
    """Every fixture owns its explicit caller; never inherit the author's task authority."""
    if str(PROJECT / '.getzilla') not in sys.path:
        sys.path.insert(0, str(PROJECT / '.getzilla'))
    from getzilla import state
    token = state._SESSION.set(None)
    keys = ('GETZILLA_SESSION_ID', 'CLAUDE_CODE_SESSION_ID')
    previous = {key: os.environ.pop(key, None) for key in keys}
    try:
        yield
    finally:
        state._SESSION.reset(token)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def activate_owned_route(root: Path, route: dict) -> None:
    """Select the fixture's named owner through real APIs; negative unbound tests bypass this helper."""
    from getzilla import state
    from getzilla.continuity import has_task_context
    owner = route.get('session_id')
    modern = has_task_context(route)
    if not isinstance(owner, str) or owner == 'manual' or not state._SESSION_ID.fullmatch(owner):
        owner = 'fixture-owner'
        if modern:
            route['session_id'] = owner
            route['origin_session_id'] = owner
    if not modern:
        route.setdefault('task', 'Synthetic legacy fixture task.')
        route.setdefault('created_at', '2026-01-01T00:00:00+00:00')
    state.bind_session(owner)
    os.environ['GETZILLA_SESSION_ID'] = owner
    existing = state.get_active_route(root)
    if existing and existing.get('route_id') == route.get('route_id') and has_task_context(existing):
        immutable = {'route_id', 'task', 'logical_task_id', 'origin_session_id', 'session_id', 'workspace',
                     'task_context_version', 'authority_epoch', 'state_revision', 'context', 'handoff', 'change_id'}
        for name in immutable - {'state_revision', 'context'}:
            if name in route and route[name] != existing.get(name):
                raise ValueError('fixture task authority changes require an explicit transition')
        route.update(state.update_route(root, **{key: value for key, value in route.items() if key not in immutable}))
        return
    state.set_active_route(root, route)


def _public_modes(source: Path) -> dict[str, int]:
    """Read logical checkout modes, not index blobs, for current working bytes."""
    top = subprocess.check_output(
        ['git', '--no-optional-locks', '-C', str(source), 'rev-parse', '--show-toplevel'])
    if Path(os.fsdecode(top).strip()).resolve() != source.resolve():
        raise ValueError('test source must be the Git worktree root')
    raw = subprocess.check_output(
        ['git', '--no-optional-locks', '-C', str(source), 'ls-files', '--stage', '-z'])
    modes = {}
    for row in raw.split(b'\0'):
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, _oid, stage = metadata.split()
        relative = os.fsdecode(name)
        if stage != b'0' or relative in modes:
            raise ValueError('test source has an unresolved index')
        modes[relative] = {b'100644': 0o644, b'100755': 0o755}.get(mode, 0)
    return modes


def _copy_public_file(source: str | Path, destination: str | Path,
                      root: Path, modes: dict[str, int]) -> str:
    source, destination = Path(source), Path(destination)
    relative = source.relative_to(root).as_posix()
    mode = modes.get(relative)
    if mode == 0:
        raise ValueError('test source is not a regular tracked file')
    if mode is None:
        # Existing project_copy also carries newly written untracked test inputs.
        # Preserve their current mode; an absent Git mode cannot confer one.
        return shutil.copy2(source, destination)
    descriptor = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as incoming:
        before = os.fstat(incoming.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('test source is not a regular working file')
        with destination.open('xb') as outgoing:
            shutil.copyfileobj(incoming, outgoing)
            if hasattr(os, 'fchmod'):
                os.fchmod(outgoing.fileno(), mode)
            else:
                os.chmod(destination, mode)
        after = os.fstat(incoming.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('test source changed during copying')
    return str(destination)


def copy_public_source(source: Path, destination: Path) -> None:
    """Create a new test-only source from tracked WORKING bytes and Git modes.

    No Git identity is invented. Real repository history stays at the caller's
    original root. Private/untracked inputs are not part of this source fixture.
    Existing targets and later custom modes are never normalized.
    """
    modes = _public_modes(source)
    destination.mkdir(mode=0o700)
    for relative in modes:
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts or '.git' in path.parts:
            raise ValueError('invalid test source path')
        if not os.path.lexists(source / path):
            continue  # A working-tree deletion is part of current TDD state.
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        _copy_public_file(source / path, target, source, modes)


@contextlib.contextmanager
def public_source_copy(source: Path | None = None) -> Iterator[Path]:
    """An owned public source fixture; it is not a Git checkout or authority."""
    with _test_directory() as temporary:
        root = Path(temporary).resolve() / 'source'
        copy_public_source(PROJECT if source is None else source, root)
        yield root


@contextlib.contextmanager
def project_copy(*, git: bool = False, minimal_runtime: bool = False,
                 verification_fixture: bool = False) -> Iterator[Path]:
    """Copy a full or minimal synthetic project with isolated scanner inputs."""
    with _test_directory() as tmp, _scanner_environment(minimal_runtime), _session_environment():
        # Tests can explicitly substitute a Gitless synthetic PROJECT. Keep its
        # original generic copy contract; never turn a real Git error into a fallback.
        if PROJECT == Path(__file__).resolve().parents[1] or os.path.lexists(PROJECT / '.git'):
            modes = _public_modes(PROJECT)
            def copy_file(source, destination):
                return _copy_public_file(source, destination, PROJECT, modes)
        else:
            copy_file = shutil.copy2
        root = Path(tmp).resolve() / 'project'  # macOS spells TMPDIR through /var -> /private/var
        root.mkdir()
        for rel in ('.grok', '.agents', '.getzilla', '.superpowers'):
            src = PROJECT / rel
            if not src.is_dir():
                continue
            def ignore(directory: str, names: list[str]) -> set[str]:
                omitted = set(shutil.ignore_patterns('__pycache__', '*.pyc')(directory, names))
                if verification_fixture and Path(directory) == PROJECT / '.getzilla':
                    # This opted-in project declares metadata contracts, not optional
                    # payload/template dependencies. Filter before its initial commit.
                    omitted.update({'vendor', 'optional-modules', 'tools'})
                if verification_fixture and Path(directory) == PROJECT / '.getzilla/templates':
                    omitted.update(name for name in names if name != 'change')
                if verification_fixture and Path(directory) == PROJECT / '.getzilla/config':
                    # The named closed providers below replace these fixture-only
                    # host tool installations. Default project copies retain both.
                    omitted.update({'python-quality-requirements.txt', 'python-test-requirements.txt'})
                    # This opted-in metadata fixture owns an empty security world;
                    # optional CI payload images must not enter its initial commit.
                    omitted.add('ci-images.json')
                if Path(directory) == PROJECT / '.getzilla/runtime':
                    # Runtime can contain the fixture destination or a changing review snapshot.
                    # Exclude it before descending; deleting copied state afterward is too late.
                    omitted.update(name for name in names if name not in {'.gitkeep', '.gitignore'})
                if minimal_runtime and not verification_fixture and Path(directory) == PROJECT / '.getzilla/getzilla':
                    omitted.update(name for name in names if name != '__init__.py')
                if (minimal_runtime or verification_fixture) and Path(directory) == PROJECT / '.getzilla/sast':
                    # Dedicated native scanner tests and full-source copies retain these rules.
                    omitted.add('rules')
                return omitted
            shutil.copytree(src, root / rel, ignore=ignore, copy_function=copy_file)
        runtime = root / '.getzilla/runtime'
        if runtime.exists():
            for child in runtime.iterdir():
                if child.name in {'.gitkeep', '.gitignore'}:  # shipped files: runtime state stays out of Git
                    continue
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        for rel in ('AGENTS.md', 'VERSION', 'ruff.toml', 'bandit.yaml', '.coveragerc'):
            src = PROJECT / rel
            if src.is_file():
                copy_file(src, root / rel)
        for rel in ('engineering/changes', 'engineering/adr', 'engineering/runbooks', 'engineering/reviews'):
            (root / rel).mkdir(parents=True, exist_ok=True)
        if verification_fixture:
            (root / '.getzilla/owned-verification-fixture.json').write_text(json.dumps({
                'schema_version': 1, 'kind': 'owned-verification-fixture',
                'providers': ['ruff', 'bandit'],
            }) + '\n')
            shutil.copytree(PROJECT / 'schemas', root / 'schemas', copy_function=copy_file)
            (root / 'owned_fixture.py').write_text('def value():\n    return "owned"\n')
            tests = root / 'tests'
            tests.mkdir()
            (tests / '__init__.py').write_text('')
            (tests / 'test_owned_fixture.py').write_text(
                'import unittest\nfrom owned_fixture import value\n'
                'class OwnedFixtureTests(unittest.TestCase):\n'
                '    def test_value(self):\n        self.assertEqual(value(), "owned")\n')
            (root / '.coveragerc').write_text(
                '[run]\nbranch = True\nsource = owned_fixture\n'
                '[report]\nfail_under = 100\nshow_missing = True\n')
        if git:
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=root, check=True)
            # Newer git starts auto maintenance detached after a commit; it can still write under .git
            # while the fixture is removed (#196).
            subprocess.run(['git', 'config', 'maintenance.auto', 'false'], cwd=root, check=True)
            subprocess.run(['git', 'config', 'gc.auto', '0'], cwd=root, check=True)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'initial'], cwd=root, check=True)
        with owned_verification_providers(root) if verification_fixture else contextlib.nullcontext():
            yield root


def _owned_verification_marker(root: Path) -> None:
    root = Path(root).resolve()
    if root == PROJECT.resolve():
        raise ValueError('the real project cannot be an owned verification fixture')
    marker = root / '.getzilla/owned-verification-fixture.json'
    expected = {'schema_version': 1, 'kind': 'owned-verification-fixture', 'providers': ['ruff', 'bandit']}
    if marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 4096:
        raise ValueError('owned fixture marker is unavailable')
    if json.loads(marker.read_text()) != expected:
        raise ValueError('owned fixture declaration differs')


@contextlib.contextmanager
def owned_verification_providers(root: Path, *, captured: str = '') -> Iterator[None]:
    """Own only unrelated linter callbacks; native plans, dispatch and validators run.

    These syntax providers qualify their closed fixture assertions. They make no
    Ruff/Bandit vendor, real-project, dependency-feed or independent-authority claim.
    """
    import ast
    from unittest.mock import patch
    from getzilla import verification
    _owned_verification_marker(root)
    if type(captured) is not str or len(captured) > 12000:
        raise ValueError('owned fixture capture exceeds the existing bound')

    def check(selected: Path, name: str):
        _owned_verification_marker(selected)
        paths = sorted(selected.glob('*.py'))
        if len(paths) > 64:
            raise ValueError('owned syntax source count exceeds its fixture bound')
        for path in paths:
            if path.is_symlink() or path.stat().st_size > 65536:
                raise ValueError('owned syntax source is not bounded')
            try:
                ast.parse(path.read_text(encoding='utf-8'), filename=path.name)
            except SyntaxError:
                return verification.CheckResult(name, 'fail', 'owned syntax provider refused source')
        return verification.CheckResult(name, 'pass', 'owned syntax provider; no external linter qualification',
            stdout=captured, details=[{'kind': 'owned-fixture-provider', 'source_count': len(paths)}])

    owned = root / '.getzilla/runtime'
    selectors = {'GETZILLA_SECURITY_DB': str(owned / 'owned-security-data'),
                 'GETZILLA_OSV_DB': str(owned / 'owned-security-data'), 'GETZILLA_OSV_ONLINE': '0',
                 'GETZILLA_SECURITY_TOOLS': str(owned / 'owned-security-tools'),
                 'GETZILLA_SECURITY_ARTIFACTS': str(owned / 'owned-security-artifacts'),
                 'GETZILLA_TEST_WORKERS': '1'}
    with patch.dict(os.environ, selectors), \
         patch.object(verification, '_ruff', side_effect=lambda selected: check(selected, 'ruff')), \
         patch.object(verification, '_bandit', side_effect=lambda selected: check(selected, 'bandit')):
        yield


def owned_verification_report(root: Path, *, mode: str = 'pr', captured: str = '', **options) -> dict:
    """Execute the actual verifier over the explicitly declared owned project."""
    from getzilla.verification import verify
    _owned_verification_marker(root)
    with owned_verification_providers(root, captured=captured):
        return verify(root, mode=mode, record=False, **options)


def run_hook(root: Path, name: str, payload: dict) -> tuple[int, dict, str]:
    script = root / '.getzilla/hooks' / name
    # Use the fixture even when the parent runner exposes the intact source package.
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join((str(root), str(root / '.getzilla')))
    # Bytes in both directions, as agents exchange them: UTF-8 JSON, never the console code page.
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=root,
        env=env,
        input=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
        capture_output=True,
        check=False,
    )
    stdout = proc.stdout.decode('utf-8', errors='replace')
    try:
        data = json.loads(stdout.strip() or '{}')
    except json.JSONDecodeError:
        data = {}
    return proc.returncode, data, proc.stderr.decode('utf-8', errors='replace')


def synchronize_fixture_scope(root: Path) -> None:
    """Declare and acknowledge actual fixture scope once; never repair a stale acknowledgment."""
    from getzilla import state
    from getzilla.continuity import ack_scope, context_binding, legacy_evidence_allowed
    from getzilla.change import start_change
    from getzilla.spec import load_spec, dump_canonical_spec
    route = state.get_active_route(root)
    if not route or legacy_evidence_allowed(route) or route['context']['last_ack'] is not None:
        return
    if not route.get('change_id'):
        if route.get('risk') == 'low' and (route.get('delivery_lane') == 'light' or route.get('complexity') == 'micro'):
            return
        start_change(root)
    route = state.get_active_route(root)
    active = state.get_active_change(root)
    path = root / active['path']
    spec = load_spec(path / 'change-spec.yaml')
    generated = (spec['objective'].get('success_metric') == 'UNKNOWN' and
                 spec['objective'].get('target') == 'UNKNOWN' and not spec['acceptance_criteria'])
    if generated:
        spec['objective'].update(success_metric='fixture boundary verification', target='all checks preserve their fences')
        spec['acceptance_criteria'] = [{'id': 'AC-001', 'statement': route['task'][:4096],
                                       'evidence': [{'receipt': 'verification'}]}]
        if spec['risk']['tier'] == 'red':
            spec['forbidden_outcomes'] = [{'id': 'FORBID-001', 'statement': 'No stale evidence admitted.',
                                           'evidence': [{'receipt': 'verification'}]}]
            spec['approvals']['required_scopes'] = ['scope_and_design_approval']
        (path / 'change-spec.yaml').write_text(dump_canonical_spec(spec), encoding='utf-8')
        (path / 'requirements.md').write_text(route['task'] + '\n' +
            '\n'.join(item['text'] for item in route['context']['pending']) + '\n', encoding='utf-8')
    binding = context_binding(root)
    target = spec['acceptance_criteria'][0]['id']
    ack_scope(root, {'version': 1, 'operation_id': 'fixture-scope-' + str(route['context']['revision']),
                    'route_id': route['route_id'], 'logical_task_id': route['logical_task_id'],
                    'authority_epoch': route['authority_epoch'], 'revision': route['context']['revision'],
                    'spec_digest': binding['spec_digest'], 'requirements_digest': binding['requirements_digest'],
                    'items': {'original': [spec['objective']['id']],
                              **{item['id']: [target] for item in route['context']['pending']}}})


def observed_context(root: Path):
    from getzilla.state import get_active_route
    from getzilla.continuity import context_binding, legacy_evidence_allowed
    route = get_active_route(root)
    return None if legacy_evidence_allowed(route) else context_binding(root, route)


def prepare_review_source(root: Path) -> dict[str, str]:
    """Freeze a real Git candidate and return explicit independent-review inputs."""
    from getzilla.state import get_active_change, get_active_route, set_active_change
    from getzilla.continuity import legacy_evidence_allowed
    synchronize_fixture_scope(root)
    route = get_active_route(root)
    active = get_active_change(root)
    if not active and legacy_evidence_allowed(route):
        active = {'path': 'engineering/changes/test-review', 'change_id': 'test-review'}
        set_active_change(root, active)
    report = (str(active['path']) + '/evidence/code-review.md' if active else
              f".getzilla/runtime/reviews/{route['route_id']}/code-review.md")
    path = root / report
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('Fixture independent review of the committed candidate.\n', encoding='utf-8')
    ignored = root / '.gitignore'
    text = ignored.read_text(encoding='utf-8') if ignored.exists() else ''
    if '.getzilla/runtime/' not in text:
        ignored.write_text(text + '\n.getzilla/runtime/\n__pycache__/\n*.pyc\n', encoding='utf-8')
    # Copies may already track .gitkeep; preserve it, ignore only machine-local files.
    subprocess.run(['git', 'add', '.'], cwd=root, check=True)
    subprocess.run(['git', 'commit', '--allow-empty', '-qm', 'freeze reviewed fixture'], cwd=root, check=True)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    route = get_active_route(root)
    if route and 'risk_assessment' in route:
        from getzilla.review_plan import reconcile_route
        reconcile_route(root)
    binding = observed_context(root)
    if binding:
        path.write_text('Fixture independent review of the committed candidate.\nreviewed-context-digest: ' +
                        binding['digest'] + '\n', encoding='utf-8')
    return {'report': report, 'reviewed_commit': head, **({'reviewed_context': binding['digest']} if binding else {})}


def offline_mirror(base: Path) -> Path:
    """A small stand-in for every download host of getzilla_update.py (``GETZILLA_UPDATE_MIRROR``).

    Each OSV archive is a valid zip with one record, each OpenGrep asset is a short script and each
    pinned workflow source is a one-commit repository with its upstream tag. getzilla-mirror.json
    pins these stand-ins, so the updater's zip, SHA-256 and commit checks run as they do for real.
    """
    if str(PROJECT / '.getzilla') not in sys.path:
        sys.path.insert(0, str(PROJECT / '.getzilla'))
    from getzilla import baseline, updater

    mirror = base / 'update-mirror'
    for ecosystem in updater.OSV_ECOSYSTEMS:
        archive = mirror / 'osv' / ecosystem / 'all.zip'
        archive.parent.mkdir(parents=True)
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('GZ-FIXTURE-1.json', json.dumps({'id': 'GZ-FIXTURE-1', 'affected': []}))
    opengrep = {}
    for asset, _ in updater.OPENGREP_ASSETS.values():
        data = f'#!/bin/sh\necho "opengrep {updater.OPENGREP_VERSION} fixture ({asset})"\n'.encode()
        path = mirror / 'opengrep' / f'v{updater.OPENGREP_VERSION}' / asset
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        opengrep[asset] = hashlib.sha256(data).hexdigest()
    # The developer's own Git config (signing, hooks, default branch) must not reach the fixture.
    env = {**os.environ, 'GIT_CONFIG_GLOBAL': str(base / 'no-gitconfig'), 'GIT_CONFIG_NOSYSTEM': '1'}

    def git(*args: str) -> str:
        return subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com', *args],
                              cwd=base, env=env, capture_output=True, text=True, check=True).stdout.strip()

    source = base / 'baseline-source'
    git('init', '-q', str(source))
    (source / 'README.md').write_text('Stand-in for a pinned workflow source.\n', encoding='utf-8')
    git('-C', str(source), 'add', 'README.md')
    git('-C', str(source), 'commit', '-qm', 'fixture')
    commit = git('-C', str(source), 'rev-parse', 'HEAD')
    components = baseline.components()
    for item in components.values():
        git('-C', str(source), 'tag', '-f', item['upstream_tag'])
    for item in components.values():
        git('clone', '-q', '--bare', str(source), str(mirror / 'git' / f"{item['repository']}.git"))
    manifest = {'opengrep': opengrep, 'baseline': {component_id: commit for component_id in components}}
    (mirror / updater.MIRROR_MANIFEST).write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return mirror
