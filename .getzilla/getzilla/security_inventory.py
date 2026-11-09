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
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .security_osv_snapshot import _cargo_manifest, _cargo_lock_pairs, MAX_MANIFEST_BYTES, REQUIREMENTS_RE, VulnerabilityError, _manifest_parser, _tracked_files, normalize_name

MAX_FILES = 100_000
MAX_YAML_BYTES = 1024 * 1024
MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 20_000
MAX_YAML_SCALAR_BYTES = 65_536
_IMAGE_DIGEST = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}\Z')
_ACTION_COMMIT = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[a-f0-9]{40}\Z')
_NONSTRING_SCALAR = re.compile(r'(?:null|Null|NULL|~|true|True|TRUE|false|False|FALSE|[-+]?(?:[0-9][0-9_.]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?)\Z')
_PIN = re.compile(r'([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[([A-Za-z0-9_,.-]+)\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)(?:\s*;[^\r\n]+)?\Z')
_UNSUPPORTED = frozenset({'pom.xml', 'build.gradle', 'build.gradle.kts', 'Pipfile', 'Gemfile',
                          'packages.config', 'packages.lock.json', 'Project.toml', 'Manifest.toml'})


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _safe_bytes(root: Path, relative: str, *, maximum: int = MAX_MANIFEST_BYTES) -> bytes:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or '..' in pure.parts or not pure.parts or '\\' in relative:
        raise ValueError('unsafe inventory path')
    path = root
    for part in pure.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('symlink inventory input')
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError('inventory input is not a bounded regular file')
    with path.open('rb') as stream:
        payload = stream.read(maximum + 1)
    after = path.stat()
    def identity(value):
        return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
    if len(payload) > maximum:
        raise ValueError('inventory input exceeded its byte bound during read')
    if identity(before) != identity(after) or len(payload) != before.st_size:
        raise ValueError('inventory input changed during read')
    return payload


class _YamlError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _YamlNode:
    kind: str
    value: Any
    line: int
    style: str | None = None


def _parse_inventory_yaml(text: str) -> _YamlNode:
    """Bound syntax events; never invoke YAML constructors or expand aliases.

    PyYAML is a lazy checker capability, not an implicitly shipped dependency.
    Rejecting unsupported syntax is an inventory gap, never proof of absence.
    """
    if len(text.encode('utf-8')) > MAX_YAML_BYTES:
        raise _YamlError('yaml-limit', 'YAML byte limit exceeded')
    try:
        import yaml
    except ImportError as exc:
        raise _YamlError('yaml-parser-unavailable', 'structural YAML inventory needs PyYAML in the qualified checker runtime') from exc
    event_names = ('StreamStartEvent', 'StreamEndEvent', 'DocumentStartEvent', 'DocumentEndEvent',
                   'AliasEvent', 'ScalarEvent', 'MappingStartEvent', 'MappingEndEvent',
                   'SequenceStartEvent', 'SequenceEndEvent')
    if (not callable(getattr(yaml, 'parse', None)) or not callable(getattr(yaml, 'BaseLoader', None))
            or not isinstance(getattr(yaml, 'YAMLError', None), type)
            or not issubclass(yaml.YAMLError, Exception)
            or not all(isinstance(getattr(getattr(yaml, 'events', None), name, None), type) for name in event_names)):
        raise _YamlError('yaml-parser-unavailable', 'checker YAML parser lacks the required event interface')
    count = 0

    def node(event, stream, depth=0):
        nonlocal count
        count += 1
        if count > MAX_YAML_NODES or depth > MAX_YAML_DEPTH:
            raise _YamlError('yaml-limit', 'YAML node or depth limit exceeded')
        if isinstance(event, yaml.events.AliasEvent) or getattr(event, 'anchor', None) is not None:
            raise _YamlError('unsupported-yaml', 'YAML anchors and aliases require a qualified composition adapter (alias limit zero)')
        if getattr(event, 'tag', None) is not None:
            raise _YamlError('unsupported-yaml', 'explicit YAML tags are unsupported; no object construction is permitted')
        line = event.start_mark.line + 1
        if isinstance(event, yaml.events.ScalarEvent):
            if len(event.value.encode('utf-8')) > MAX_YAML_SCALAR_BYTES:
                raise _YamlError('yaml-limit', 'YAML scalar limit exceeded')
            return _YamlNode('scalar', event.value, line, event.style)
        if isinstance(event, yaml.events.MappingStartEvent):
            value = {}
            while not isinstance(child := next(stream), yaml.events.MappingEndEvent):
                key = node(child, stream, depth + 1)
                if key.kind != 'scalar' or not key.value or key.value == '<<':
                    raise _YamlError('unsupported-yaml', 'YAML mapping needs nonempty scalar keys and cannot contain merges')
                if key.value in value:
                    raise _YamlError('unsupported-yaml', f'duplicate decoded YAML mapping key at line {key.line}')
                value[key.value] = node(next(stream), stream, depth + 1)
            return _YamlNode('mapping', value, line)
        if isinstance(event, yaml.events.SequenceStartEvent):
            value = []
            while not isinstance(child := next(stream), yaml.events.SequenceEndEvent):
                value.append(node(child, stream, depth + 1))
            return _YamlNode('sequence', value, line)
        raise _YamlError('unsupported-yaml', 'unexpected YAML node event')

    try:
        with closing(yaml.parse(text, Loader=yaml.BaseLoader)) as stream:
            if not isinstance(next(stream), yaml.events.StreamStartEvent):
                raise _YamlError('unsupported-yaml', 'YAML stream start is missing')
            start = next(stream)
            if not isinstance(start, yaml.events.DocumentStartEvent) or start.version or start.tags:
                raise _YamlError('unsupported-yaml', 'one YAML document without schema/tag directives is required')
            document = node(next(stream), stream)
            if (not isinstance(next(stream), yaml.events.DocumentEndEvent) or
                    not isinstance(next(stream), yaml.events.StreamEndEvent)):
                raise _YamlError('unsupported-yaml', 'multiple YAML documents are unsupported')
            return document
    except _YamlError:
        raise
    except (yaml.YAMLError, StopIteration, RecursionError) as exc:
        mark = getattr(exc, 'problem_mark', None)
        suffix = f' near line {mark.line + 1}' if mark is not None else ''
        raise _YamlError('unsupported-yaml', 'malformed or unsupported YAML' + suffix) from exc


def _yaml_map(node: _YamlNode | None, label: str) -> dict[str, _YamlNode]:
    if node is None or node.kind != 'mapping':
        raise _YamlError('unsupported-yaml', label + ' must be a static mapping')
    return node.value


def _yaml_text(node: _YamlNode | None, label: str) -> str:
    if (node is None or node.kind != 'scalar' or not node.value or
            (node.style is None and _NONSTRING_SCALAR.fullmatch(node.value))):
        raise _YamlError('unsupported-yaml', label + ' must be a nonempty string')
    return node.value


def _is_compose(name: str) -> bool:
    return (name in {'compose.yaml', 'compose.yml', 'docker-compose.yml', 'docker-compose.yaml'}
            or (name.startswith(('compose.', 'docker-compose.')) and name.endswith(('.yaml', '.yml'))))


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


def workflow_downloads(command: str, manifest: str, line: int, source: bytes, read_declared,
                       *, platform: str | None = None) -> tuple[list[dict], list[dict]]:
    """Return source declarations only; artifact evidence never changes this set."""
    tools, gaps = [], []
    lines = [text.strip() for text in command.splitlines() if text.strip()]
    downloads = [i for i, text in enumerate(lines) if re.search(r'\b(?:curl|wget|Invoke-WebRequest)\b', text)]
    for offset in downloads:
        text = lines[offset]
        try:
            # A deliberately closed straight-line shell subset. Unclassified
            # shell is still an obligation, never inferred harmless.
            if len(downloads) != 1 or not lines or lines[0] != 'set -euo pipefail' or offset + 1 >= len(lines):
                raise ValueError('unproved shell control flow')
            values, pins = {}, []
            for prefix in lines[1:offset]:
                assignment = re.fullmatch(r"([a-z][a-z0-9_]*)=\$\(sed -n 's/\^ARG ([A-Z][A-Z0-9_]*)=//p' ([A-Za-z0-9_./-]+)\)", prefix)
                if assignment:
                    variable, arg, path = assignment.groups()
                    if variable in values or PurePosixPath(path).is_absolute() or '..' in path.split('/'):
                        raise ValueError('ambiguous source variable')
                    payload = read_declared(path)
                    if not isinstance(payload, bytes) or len(payload) > MAX_MANIFEST_BYTES:
                        raise ValueError('unbounded source pin')
                    matches = re.findall(r'^ARG ' + re.escape(arg) + r'=([A-Za-z0-9_.-]+)$', payload.decode('utf-8'), re.M)
                    if len(matches) != 1:
                        raise ValueError('missing or duplicate exact source pin')
                    values[variable] = matches[0]
                    pins.append({'path': path, 'sha256': hashlib.sha256(payload).hexdigest(), 'arg': arg, 'value': matches[0]})
                elif not re.fullmatch(r'mkdir -p "\$RUNNER_TEMP/[A-Za-z0-9_/-]+"', prefix):
                    raise ValueError('unclassified pre-download operation')
            download = re.fullmatch(r'curl -fsSL -o "(\$RUNNER_TEMP/[A-Za-z0-9_/-]+)" "(https://github.com/[^"\s]+)"', text)
            if not download or any(part == '..' for part in download[1].split('/')):
                raise ValueError('unsupported download grammar')
            target, url = download.groups()
            check = re.fullmatch(r'echo "\$\{([a-z][a-z0-9_]*)\}  ' + re.escape(target) + r'" \| sha256sum -c -', lines[offset + 1])
            if not check or not re.fullmatch('[0-9a-f]{64}', values.get(check[1], '')):
                raise ValueError('exact download must be checked before any next operation')
            for variable in re.findall(r'\$\{([a-z][a-z0-9_]*)\}', url):
                if variable not in values or not re.fullmatch('[A-Za-z0-9_.-]+', values[variable]):
                    raise ValueError('unbound release URL')
                url = url.replace('${' + variable + '}', values[variable])
            if not re.fullmatch(r'https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', url):
                raise ValueError('unresolved release URL')
            tools.append({'kind': 'release-tool', 'reference': url, 'manifest': manifest, 'line': line,
                          'source_sha256': hashlib.sha256(source).hexdigest(), 'usage': 'build-ci',
                          'artifact_sha256': values[check[1]], 'platform': platform or 'unknown', 'pin_sources': pins})
            continue
        except (OSError, ValueError, UnicodeError):
            pass
        if re.search(r'\b(?:curl|wget|Invoke-WebRequest)\b', text):
            tools.append({'kind': 'script-download', 'reference': text[:500], 'manifest': manifest, 'line': line})
            gaps.append({'code': 'unresolved-ci-tool', 'path': manifest,
                         'message': 'downloaded executable needs digest-bound artifact evidence'})
    return tools, gaps


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

    def image(reference: str, path: str, line: int, *, require_digest=False, source_reference=None):
        original = reference
        variable = re.fullmatch(r'\$\{([A-Z][A-Z0-9_]*)(?::[?+-][^}]*)?\}', reference)
        if variable:
            observed = bindings.get(variable[1], '') if isinstance(bindings, dict) else ''
            reference = observed if isinstance(observed, str) else ''
            if not _IMAGE_DIGEST.fullmatch(reference):
                gap('unresolved-image', path, f'{variable[1]} needs an observed immutable image binding')
        elif '$' in reference or not reference:
            gap('unresolved-image', path, 'dynamic image expression needs an observed immutable binding')
        elif require_digest and not _IMAGE_DIGEST.fullmatch(reference):
            gap('unresolved-image', path, 'image requires an immutable sha256 reference')
        result['images'].append({'reference': reference or original,
                                 'source_reference': original if source_reference is None else source_reference,
                                 'manifest': path, 'line': line, 'kind': 'oci-image', 'platform': 'unknown',
                                 'usage': 'build-ci' if path.startswith('.github/') else 'runtime-and-development',
                                 'source_sha256': hashlib.sha256(texts[path].encode()).hexdigest()})

    def yaml_image(value: _YamlNode | None, path: str, label: str, *, container=False):
        if container and value is not None and value.kind == 'mapping':
            value = value.value.get('image')
        reference = _yaml_text(value, label)
        image(reference, path, value.line, require_digest=True)

    def action(value: _YamlNode, path: str, *, reusable=False):
        reference = _yaml_text(value, 'Actions uses')
        if reference.startswith('docker://') and not reusable:
            image(reference.removeprefix('docker://'), path, value.line, require_digest=True, source_reference=reference)
            return
        result['tools'].append({'kind': 'github-action', 'reference': reference, 'manifest': path, 'line': value.line,
                                'usage': 'build-ci', 'source_sha256': hashlib.sha256(texts[path].encode()).hexdigest()})
        local = reference.startswith(('./', '$/'))
        if reusable or local or '/.github/workflows/' in reference:
            gap('unsupported-ci-composition', path, 'local or reusable workflow/action needs qualified referenced-source coverage')
        if not local and not _ACTION_COMMIT.fullmatch(reference):
            gap('unresolved-ci-tool', path, 'external action is not bound to a full commit')

    def yaml_objects(relative: str, text: str, *, compose: bool):
        document = _yaml_map(_parse_inventory_yaml(text), 'YAML document')
        if compose:
            known = {'version', 'name', 'services', 'networks', 'volumes', 'secrets', 'configs', 'include'}
            if any(key not in known and not key.startswith('x-') for key in document):
                gap('unsupported-compose-composition', relative, 'unrecognized top-level Compose model field')
            if 'include' in document:
                gap('unsupported-compose-composition', relative, 'Compose include needs qualified referenced-source coverage')
            services = _yaml_map(document.get('services'), 'Compose services')
            for service in services.values():
                fields = _yaml_map(service, 'Compose service')
                for indirect in ('build', 'extends', 'provider'):
                    if indirect in fields:
                        gap('unsupported-compose-composition', relative, f'Compose {indirect} needs qualified build/composition coverage')
                if 'image' in fields:
                    yaml_image(fields['image'], relative, 'Compose image')
                elif not set(fields) & {'build', 'extends', 'provider'}:
                    gap('unresolved-image', relative, 'Compose service has no resolved image; override/composition needs evidence')
            return
        known = {'name', 'run-name', 'on', 'permissions', 'env', 'defaults', 'concurrency', 'cache-mode', 'jobs'}
        if set(document) - known:
            gap('unsupported-ci-composition', relative, 'unrecognized top-level Actions workflow field')
        jobs = _yaml_map(document.get('jobs'), 'Actions jobs')
        for job in jobs.values():
            fields = _yaml_map(job, 'Actions job')
            if 'uses' in fields:
                action(fields['uses'], relative, reusable=True)
            if 'container' in fields:
                yaml_image(fields['container'], relative, 'Actions job container image', container=True)
            if 'services' in fields:
                for service in _yaml_map(fields['services'], 'Actions services').values():
                    definition = _yaml_map(service, 'Actions service')
                    yaml_image(definition.get('image'), relative, 'Actions service image')
            if 'steps' not in fields:
                if 'uses' not in fields:
                    gap('unsupported-yaml', relative, 'Actions job needs steps or a reusable workflow reference')
                continue
            steps = fields['steps']
            if steps.kind != 'sequence':
                raise _YamlError('unsupported-yaml', 'Actions steps must be a static sequence')
            for step in steps.value:
                definition = _yaml_map(step, 'Actions step')
                if 'parallel' in definition:
                    gap('unsupported-ci-composition', relative, 'parallel/nested Actions steps need qualified composition coverage')
                if 'uses' in definition:
                    action(definition['uses'], relative)
                if 'run' in definition:
                    command = _yaml_text(definition['run'], 'Actions run')
                    tools, gaps = workflow_downloads(command, relative, definition['run'].line, text.encode(),
                        lambda path: _safe_bytes(root, path) if path in files else b'',
                        platform='linux/amd64' if fields.get('runs-on') is not None
                        and isinstance(fields['runs-on'].value, str)
                        and fields['runs-on'].value in {'ubuntu-22.04', 'ubuntu-24.04', 'ubuntu-latest'} else None)
                    result['tools'].extend(tools)
                    result['gaps'].extend(gaps)
                if not set(definition) & {'uses', 'run'}:
                    gap('unsupported-ci-composition', relative, 'Actions step has no covered run/uses operation')

    try:
        files = _tracked_files(root)
    except (VulnerabilityError, OSError, ValueError):
        gap('source-root-unverified', '.', 'cannot establish complete inventory for the exact selected Git worktree root')
        files = []
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
        is_yaml = _is_compose(name) or (relative.startswith('.github/workflows/') and pure.suffix in {'.yaml', '.yml'})
        relevant = (parser is not None or name in _UNSUPPORTED or name in {'package.json', 'composer.json', 'Cargo.toml'}
                    or name.endswith('.csproj') or name.lower().startswith('dockerfile')
                    or name.endswith('.Dockerfile') or is_yaml
                    or relative == '.getzilla/config/ci-images.json'
                    )
        result['files'].append(relative)
        if not relevant:
            continue
        try:
            payload = _safe_bytes(root, relative, maximum=MAX_YAML_BYTES if is_yaml else MAX_MANIFEST_BYTES)
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
                        'manifest': relative, 'line': text[:text.index(key)].count('\n') + 1 if key in text else 1,
                        'image_id': image_id, 'kind': 'oci-image', 'platform': data['platform'], 'usage': 'build-ci',
                        'source_sha256': hashlib.sha256(payload).hexdigest()})
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
            elif name == 'Cargo.lock':
                manifest = str(pure.with_name('Cargo.toml'))
                manifest_text = (_safe_bytes(root, manifest).decode('utf-8')
                                 if (root / manifest).exists() else None)
                for package, version in _cargo_lock_pairs(text, manifest_text):
                    add('crates.io', package, version, relative, usage)
            elif name == 'Cargo.toml':
                _cargo_manifest(text)
                if not (root / pure.parent / 'Cargo.lock').is_file():
                    gap('unresolved-dependency', relative, 'Cargo manifest has no resolved lock')
            elif parser is not None:
                ecosystem, parse = parser
                for package, version in parse(text):
                    add(ecosystem, package, version, relative, usage)
            elif name in _UNSUPPORTED or name.endswith('.csproj'):
                gap('unsupported-manifest', relative, 'manifest needs a qualified resolution adapter')
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
        is_yaml = _is_compose(name) or (relative.startswith('.github/workflows/') and pure.suffix in {'.yaml', '.yml'})
        if is_yaml:
            try:
                yaml_objects(relative, text, compose=_is_compose(name))
            except _YamlError as exc:
                gap(exc.code, relative, str(exc)[:300])
            continue
        is_docker = name.lower().startswith('dockerfile') or name.endswith('.Dockerfile')
        stages = set()
        for line_number, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            reference = None
            if is_docker and re.match(r'FROM\s', line, re.IGNORECASE):
                parts = line.split()
                parts = [part for part in parts[1:] if not part.startswith('--platform=')]
                reference = parts[0] if parts else ''
                internal_stage = reference.lower() == 'scratch' or reference.lower() in stages
                if len(parts) >= 3 and parts[1].upper() == 'AS':
                    stages.add(parts[2].lower())
                if internal_stage:
                    continue
            if reference is not None:
                image(reference, relative, line_number)
    result['dependencies'] = sorted(dependencies.values(), key=lambda item: (item['ecosystem'], item['name'], item['version'], item['manifest'], item['usage']))
    result['complete'] = not result['gaps']
    result['artifact_coverage'] = 'not_evaluated'
    result['digest'] = canonical_digest(result)
    return result
