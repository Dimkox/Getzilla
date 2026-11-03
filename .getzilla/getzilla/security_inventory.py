"""Derive bounded security objects from source; unresolved objects remain gaps.

This is source discovery, not proof of transitive resolution or artifact
licenses. The artifact evaluator must cover every discovered dependency/tool
and actual image. Fixture exclusions are reported explicitly.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

from .known_vulns import MAX_MANIFEST_BYTES, REQUIREMENTS_RE, _manifest_parser, _tracked_files, normalize_name

MAX_FILES = 100_000
_PIN = re.compile(r'([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[([A-Za-z0-9_,.-]+)\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)(?:\s*;[^\r\n]+)?\Z')
_UNSUPPORTED = frozenset({'pom.xml', 'build.gradle', 'build.gradle.kts', 'Pipfile', 'Gemfile',
                          'packages.config', 'packages.lock.json', 'Project.toml', 'Manifest.toml'})


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _safe_bytes(root: Path, relative: str) -> bytes:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or '..' in pure.parts or not pure.parts or '\\' in relative:
        raise ValueError('unsafe inventory path')
    path = root
    for part in pure.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('symlink inventory input')
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_MANIFEST_BYTES:
        raise ValueError('inventory input is not a bounded regular file')
    payload = path.read_bytes()
    after = path.stat()
    def identity(value):
        return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
    if identity(before) != identity(after) or len(payload) != before.st_size:
        raise ValueError('inventory input changed during read')
    return payload


def _logical_requirements(text: str):
    pending = ''
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        pending += line.removesuffix('\\').strip() + ' '
        if line.endswith('\\'):
            continue
        yield pending.strip()
        pending = ''
    if pending:
        raise ValueError('truncated requirements continuation')


def collect_inventory(root: Path, *, image_bindings: dict[str, str] | None = None) -> dict[str, Any]:
    root = Path(root).resolve()
    bindings = image_bindings or {}
    result: dict[str, Any] = {'schema_version': 1, 'files': [], 'manifests': [], 'dependencies': [],
                              'images': [], 'tools': [], 'gaps': [], 'excluded_fixture_paths': []}
    dependencies = {}
    texts = {}

    def gap(code: str, path: str, message: str):
        result['gaps'].append({'code': code, 'path': path, 'message': message})

    def add(ecosystem: str, name: str, version: str, path: str, usage: str, extras: str = ''):
        if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
            raise ValueError('dependency identity is missing')
        if re.search(r'[\s*<>=^~/$]', version):
            gap('unresolved-dependency', path, f'{name}: exact version unavailable')
            return
        item = {'ecosystem': ecosystem, 'name': normalize_name(ecosystem, name), 'version': version,
                'manifest': path, 'usage': usage, 'extras': sorted(filter(None, extras.split(',')))}
        dependencies[(ecosystem, item['name'], version, path, usage, extras)] = item

    def requirement(value: str, path: str, usage: str):
        match = _PIN.fullmatch(value.strip()) if isinstance(value, str) else None
        if match is None:
            gap('unresolved-dependency', path, 'dependency requires an exact resolved version')
        else:
            add('PyPI', match[1], match[3], path, usage, match[2] or '')

    files = _tracked_files(root)
    if len(files) > MAX_FILES:
        gap('inventory-limit', '.', 'source file inventory exceeds its bound')
        files = []
    for relative in files:
        pure = PurePosixPath(relative)
        if relative.startswith('.getzilla/runtime/') or any(part in {'.git', '.venv', 'node_modules'} for part in pure.parts):
            continue
        if 'fixtures' in pure.parts:
            result['excluded_fixture_paths'].append(relative)
            continue
        name = pure.name
        parser = _manifest_parser(name)
        relevant = (parser is not None or name in _UNSUPPORTED or name in {'package.json', 'composer.json', 'Cargo.toml'}
                    or name.endswith('.csproj') or name.lower().startswith('dockerfile')
                    or name.endswith('.Dockerfile') or name in {'compose.yaml', 'compose.yml', 'docker-compose.yml', 'docker-compose.yaml'}
                    or (name.startswith('compose.') and name.endswith(('.yaml', '.yml')))
                    or relative == '.getzilla/config/ci-images.json'
                    or relative.startswith('.github/workflows/'))
        result['files'].append(relative)
        if not relevant:
            continue
        try:
            payload = _safe_bytes(root, relative)
            text = payload.decode('utf-8')
            texts[relative] = text
            result['manifests'].append({'path': relative, 'sha256': hashlib.sha256(payload).hexdigest()})
            usage = 'build-ci' if relative.startswith(('.getzilla/config/', '.github/')) else 'runtime-and-development'
            if relative == '.getzilla/config/ci-images.json':
                data = json.loads(text)
                if data.get('schema_version') != 1 or data.get('platform') != 'linux/amd64':
                    raise ValueError('unsupported CI image binding schema or platform')
                for key, value in data.items():
                    if key in {'schema_version', 'platform'}:
                        continue
                    reference = value.get('reference', '') if isinstance(value, dict) else ''
                    image_id = value.get('image_id', '') if isinstance(value, dict) else ''
                    if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}', reference)
                            or not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id)):
                        gap('unresolved-image', relative, f'{key}: exact image reference and ID required')
                        continue
                    result['images'].append({'reference': reference, 'source_reference': reference,
                                             'manifest': relative, 'line': 0, 'image_id': image_id})
            elif name == 'pyproject.toml':
                data = tomllib.loads(text)
                project = data.get('project', {})
                if 'dependencies' in project.get('dynamic', []):
                    gap('unresolved-dependency', relative, 'dynamic project dependencies require a bound resolution')
                for value in project.get('dependencies', []):
                    requirement(value, relative, 'runtime')
                for values in project.get('optional-dependencies', {}).values():
                    for value in values:
                        requirement(value, relative, 'optional')
                for value in data.get('build-system', {}).get('requires', []):
                    requirement(value, relative, 'build')
                for values in data.get('dependency-groups', {}).values():
                    for value in values:
                        if isinstance(value, str):
                            requirement(value, relative, 'development')
                        else:
                            gap('unresolved-dependency', relative, 'dependency group inclusion needs resolution')
            elif REQUIREMENTS_RE.fullmatch(name):
                for line in _logical_requirements(text):
                    clean = re.sub(r'\s+--hash=sha256:[a-fA-F0-9]{64}', '', line).strip()
                    requirement(clean, relative, usage)
            elif name == 'uv.lock':
                for package in tomllib.loads(text).get('package', []):
                    source = package.get('source', {})
                    if 'editable' in source or 'virtual' in source:
                        continue  # project source is included in source checks, not a third-party artifact
                    if set(source) != {'registry'}:
                        gap('unresolved-dependency', relative, 'non-registry lock source needs an artifact adapter')
                    else:
                        add('PyPI', package.get('name'), package.get('version'), relative, usage)
            elif parser is not None:
                ecosystem, parse = parser
                for package, version in parse(text):
                    add(ecosystem, package, version, relative, usage)
            elif name in _UNSUPPORTED or name.endswith('.csproj'):
                gap('unsupported-manifest', relative, 'manifest needs a qualified resolution adapter')
            elif name == 'Cargo.toml' and not (root / pure.parent / 'Cargo.lock').is_file():
                gap('unresolved-dependency', relative, 'Cargo manifest has no resolved lock')
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, AttributeError) as exc:
            gap('unreadable-manifest', relative, str(exc)[:300])

    # Direct npm/Composer declarations must be covered by the corresponding lock.
    for relative, text in texts.items():
        pure = PurePosixPath(relative)
        if pure.name not in {'package.json', 'composer.json'}:
            continue
        try:
            data = json.loads(text)
            ecosystem = 'npm' if pure.name == 'package.json' else 'Packagist'
            groups = ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies') if ecosystem == 'npm' else ('require', 'require-dev')
            lock_names = {'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'} if ecosystem == 'npm' else {'composer.lock'}
            resolved = {item['name'] for item in dependencies.values()
                        if item['ecosystem'] == ecosystem and PurePosixPath(item['manifest']).parent == pure.parent
                        and PurePosixPath(item['manifest']).name in lock_names}
            for group in groups:
                for name in data.get(group, {}):
                    if ecosystem == 'Packagist' and (name == 'php' or name.startswith(('ext-', 'lib-'))):
                        continue
                    if normalize_name(ecosystem, name) not in resolved:
                        gap('unresolved-dependency', relative, f'{name}: no exact lock entry')
        except (ValueError, AttributeError, TypeError) as exc:
            gap('unreadable-manifest', relative, str(exc)[:300])

    for relative, text in texts.items():
        pure = PurePosixPath(relative)
        name = pure.name
        is_docker = name.lower().startswith('dockerfile') or name.endswith('.Dockerfile')
        stages = set()
        for line_number, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            image = None
            if is_docker and re.match(r'FROM\s', line, re.IGNORECASE):
                parts = line.split()
                parts = [part for part in parts[1:] if not part.startswith('--platform=')]
                image = parts[0] if parts else ''
                internal_stage = image.lower() == 'scratch' or image.lower() in stages
                if len(parts) >= 3 and parts[1].upper() == 'AS':
                    stages.add(parts[2].lower())
                if internal_stage:
                    continue
            elif 'compose' in name and re.match(r'image\s*:', line):
                image = line.split(':', 1)[1].strip().split(' #', 1)[0].strip('"\'')
            if image is not None:
                original = image
                variable = re.fullmatch(r'\$\{([A-Z][A-Z0-9_]*)(?::[?+-][^}]*)?\}', image)
                if variable:
                    image = bindings.get(variable[1], '')
                    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}', image):
                        gap('unresolved-image', relative, f'{variable[1]} needs an observed immutable image binding')
                elif '$' in image or not image:
                    gap('unresolved-image', relative, 'dynamic image expression needs an observed immutable binding')
                result['images'].append({'reference': image or original, 'source_reference': original,
                                         'manifest': relative, 'line': line_number})
            if relative.startswith('.github/workflows/'):
                action = re.match(r'(?:-\s*)?uses:\s*["\']?([^"\'\s#]+)', line)
                if action:
                    reference = action[1]
                    result['tools'].append({'kind': 'github-action', 'reference': reference,
                                            'manifest': relative, 'line': line_number})
                    if not reference.startswith('./') and not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[a-f0-9]{40}', reference):
                        gap('unresolved-ci-tool', relative, 'external action is not bound to a full commit')
                if re.search(r'\b(?:curl|wget|Invoke-WebRequest)\b', line):
                    result['tools'].append({'kind': 'script-download', 'reference': line[:500],
                                            'manifest': relative, 'line': line_number})
                    gap('unresolved-ci-tool', relative, 'downloaded executable needs digest-bound artifact evidence')
    result['dependencies'] = sorted(dependencies.values(), key=lambda item: (item['ecosystem'], item['name'], item['version'], item['manifest'], item['usage']))
    result['complete'] = not result['gaps']
    result['artifact_coverage'] = 'not_evaluated'
    result['digest'] = canonical_digest(result)
    return result
