from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Iterator

PROJECT = Path(__file__).resolve().parents[1]
CLEANUP_ATTEMPTS = 4


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
def project_copy(*, git: bool = False, minimal_runtime: bool = False) -> Iterator[Path]:
    with _test_directory() as tmp:
        root = Path(tmp).resolve() / 'project'  # macOS spells TMPDIR through /var -> /private/var
        root.mkdir()
        for rel in ('.grok', '.agents', '.getzilla', '.superpowers'):
            src = PROJECT / rel
            if not src.is_dir():
                continue
            def ignore(directory: str, names: list[str]) -> set[str]:
                omitted = set(shutil.ignore_patterns('__pycache__', '*.pyc')(directory, names))
                if minimal_runtime and Path(directory) == PROJECT / '.getzilla/getzilla':
                    omitted.update(name for name in names if name != '__init__.py')
                return omitted
            shutil.copytree(src, root / rel, ignore=ignore)
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
                shutil.copy2(src, root / rel)
        for rel in ('engineering/changes', 'engineering/adr', 'engineering/runbooks', 'engineering/reviews'):
            (root / rel).mkdir(parents=True, exist_ok=True)
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
        yield root


def run_hook(root: Path, name: str, payload: dict) -> tuple[int, dict, str]:
    script = root / '.grok/hooks' / name
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


def prepare_review_source(root: Path) -> dict[str, str]:
    """Freeze a real Git candidate and return explicit independent-review inputs."""
    from getzilla.state import get_active_change, set_active_change
    active = get_active_change(root)
    if not active:
        active = {'path': 'engineering/changes/test-review', 'change_id': 'test-review'}
        set_active_change(root, active)
    report = str(active['path']) + '/evidence/code-review.md'
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
    from getzilla.state import get_active_route
    route = get_active_route(root)
    if route and 'risk_assessment' in route:
        from getzilla.review_plan import reconcile_route
        reconcile_route(root)
    return {'report': report, 'reviewed_commit': head}


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
