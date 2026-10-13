"""Check frozen pip profiles using stdlib; regenerate only with the pinned uv tool."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

PROFILES = {'runtime': (False, False), 'test': (True, False), 'runner': (True, True)}
BINDING = 'lock-profiles.json'


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _closure(lock: dict, profile: str) -> set[tuple[str, str]]:
    root = next(package for package in lock['package'] if package['source'].get('editable') == '.')
    include_test, include_runner = PROFILES[profile]
    queue = list(root.get('dependencies', [])) + root['dev-dependencies']['build']
    if include_test:
        queue += root['optional-dependencies']['test']
    if include_runner:
        queue += root['dev-dependencies']['runner']
    packages = {}
    for package in lock['package']:
        packages.setdefault(package['name'], []).append(package)
    selected = set()
    visited = set()
    while queue:
        edge = queue.pop()
        matches = packages.get(edge['name'], [])
        if 'version' in edge:
            matches = [package for package in matches if package['version'] == edge['version']]
        if not matches:
            raise ValueError(f"missing locked dependency {edge['name']}")
        for package in matches:
            key = package['name'], package['version']
            extras = tuple(sorted(edge.get('extra', [])))
            if (key, extras) in visited:
                continue
            visited.add((key, extras))
            selected.add(key)
            queue += package.get('dependencies', [])
            for extra in extras:
                queue += package.get('optional-dependencies', {}).get(extra, [])
    return selected


def _rows(path: Path) -> dict[tuple[str, str], set[str]]:
    rows = {}
    pending = ''
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        pending += ' ' + line.rstrip('\\').strip()
        if line.endswith('\\'):
            continue
        match = re.match(r'^\s*([A-Za-z0-9_.-]+)==([^\s;]+)', pending)
        hashes = set(re.findall(r'--hash=sha256:([0-9a-f]{64})', pending))
        if not match or not hashes:
            raise ValueError(f'{path.name}: non-pinned or unhashed requirement')
        key = match[1].lower().replace('_', '-'), match[2]
        if key in rows:
            raise ValueError(f'{path.name}: duplicate requirement')
        rows[key] = hashes
        pending = ''
    if pending:
        raise ValueError(f'{path.name}: incomplete requirement')
    return rows


def _pins(requirements: list[str]) -> set[tuple[str, str]]:
    pins = set()
    for requirement in requirements:
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s;]+)', requirement)
        if not match:
            raise ValueError('project roots and groups must remain exact pins')
        pins.add((match[1].lower().replace('_', '-'), match[2]))
    return pins


def check(root: Path) -> list[str]:
    errors = []
    try:
        lock = tomllib.loads((root / 'uv.lock').read_text())
        project = tomllib.loads((root / 'pyproject.toml').read_text())
        binding = json.loads((root / BINDING).read_text())
        if set(binding['profiles']) != set(PROFILES) or binding['schema_version'] != 1:
            raise ValueError('unknown lock profile contract')
        locked_root = next(package for package in lock['package'] if package['source'].get('editable') == '.')
        root_specs = project['project']['dependencies'] + project['project']['optional-dependencies']['test']
        locked_specs = {(item['name'], item['specifier'].removeprefix('=='))
                        for item in locked_root['metadata']['requires-dist']}
        if _pins(root_specs) != locked_specs:
            errors.append('project requirements differ from locked roots')
        for group in ('build', 'runner'):
            declared = _pins(project['dependency-groups'][group])
            locked = {(item['name'], item['specifier'].removeprefix('=='))
                      for item in locked_root['metadata']['requires-dev'][group]}
            if declared != locked:
                errors.append(f'{group}: declared group differs from lock')
        if project['project']['requires-python'] != lock['requires-python']:
            errors.append('Python support differs from lock')
        if project['build-system']['requires'] != project['dependency-groups']['build']:
            errors.append('build profile differs from build-system requirements')
        for name in ('uv.lock', 'pyproject.toml'):
            if binding['inputs'][name] != digest(root / name):
                errors.append(f'{name}: stale binding')
        artifact_hashes = {}
        for package in lock['package']:
            artifacts = list(package.get('wheels', []))
            if package.get('sdist'):
                artifacts.append(package['sdist'])
            artifact_hashes[package['name'], package['version']] = {
                artifact['hash'].removeprefix('sha256:') for artifact in artifacts
            }
        for profile in PROFILES:
            path = root / f'requirements-{profile}.txt'
            if binding['profiles'][profile] != digest(path):
                errors.append(f'{profile}: stale exported profile')
            rows = _rows(path)
            if set(rows) != _closure(lock, profile):
                errors.append(f'{profile}: incomplete or expanded dependency graph')
            for key, hashes in rows.items():
                if hashes != artifact_hashes.get(key):
                    errors.append(f'{profile}: artifact hashes differ for {key[0]}')
    except (OSError, ValueError, KeyError, StopIteration, TypeError, AttributeError) as exc:
        errors.append(f'lock profile validation failed: {exc}')
    return errors


def refresh(root: Path) -> None:
    # Frozen export never resolves or updates uv.lock. uv's own version contract
    # comes from pyproject.toml. --locked check verifies the manifest first.
    subprocess.run(['uv', 'lock', '--project', str(root), '--check', '--offline', '--no-python-downloads'], check=True)
    for profile, (include_test, include_runner) in PROFILES.items():
        command = ['uv', 'export', '--project', str(root), '--frozen', '--offline',
                   '--no-default-groups', '--group', 'build', '--no-emit-project',
                   '--no-header', '--no-annotate', '-o', str(root / f'requirements-{profile}.txt')]
        if include_test:
            command += ['--extra', 'test']
        if include_runner:
            command += ['--group', 'runner']
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
    binding = {'schema_version': 1, 'inputs': {name: digest(root / name) for name in ('uv.lock', 'pyproject.toml')},
               'profiles': {name: digest(root / f'requirements-{name}.txt') for name in PROFILES}}
    (root / BINDING).write_text(json.dumps(binding, indent=2, sort_keys=True) + '\n')
    errors = check(root)
    if errors:
        raise ValueError('; '.join(errors))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    if args.refresh:
        refresh(directory)
    failures = check(directory)
    for failure in failures:
        print(failure, file=sys.stderr)
    raise SystemExit(bool(failures))
