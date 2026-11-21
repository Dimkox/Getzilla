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
# One proved historical documentation copy, not a deployed Compose source.
# Both unchanged source bytes and the tracked documentation of its role must
# match. No directory-wide history exclusion or YAML grammar exception follows.
_ARCHIVAL_DOCUMENTS = {
    'engineering/changes/20260824-the-user-sent-a-message-while-you-were-working-u-3e6166/evidence/compose.host-socket.yaml': {
        'bytes': 2134,
        'sha256': '798b9d4e150796f66ed9ffdd1ab088b605d0801100307259468117eb187abe6b',
        'provenance_path': 'engineering/changes/20260824-m0-2-sha-change-invalidation-on-draft-pr-5-beee95/evidence/analysis-architect.md',
        'provenance_bytes': 15550,
        'provenance_sha256': '3f1e515e53f3ccce679524137c9418da83b4ec18bec09836a5e5da76b6b5096a',
    },
}


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


def _archival_document(root: Path, relative: str, files: list[str]) -> dict | None:
    record = _ARCHIVAL_DOCUMENTS.get(relative)
    if record is None:
        return None
    if record['provenance_path'] not in files:
        raise ValueError('archival provenance is absent from tracked source')
    payload = _safe_bytes(root, relative, maximum=record['bytes'])
    provenance = _safe_bytes(root, record['provenance_path'], maximum=record['provenance_bytes'])
    if (len(payload) != record['bytes'] or hashlib.sha256(payload).hexdigest() != record['sha256']
            or len(provenance) != record['provenance_bytes']
            or hashlib.sha256(provenance).hexdigest() != record['provenance_sha256']):
        raise ValueError('archival documentation or provenance differs')
    return {'path': relative, 'bytes': len(payload), 'sha256': record['sha256'],
            'classification': 'historical-documentation-copy-not-active-manifest',
            'provenance': {'path': record['provenance_path'], 'bytes': len(provenance),
                           'sha256': record['provenance_sha256']}}


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


def _closed_download_tail(lines: list[str], target: str) -> bool:
    """Only these complete endings preserve the proved checked artifact state.

    Unknown subsequent statements remain unresolved, even after a valid digest
    prefix. This is a closed declaration grammar, not a shell interpreter.
    """
    return not lines or lines == [f'chmod 0755 "{target}"']


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
            if not _closed_download_tail(lines[offset + 2:], target):
                raise ValueError('post-check flow is unclassified; artifact replacement/use remains unknown')
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


def selected_image_use(uses: list[dict], *, path: str, line: int, source_sha256: str,
                       expression: str, platform: str | None = None) -> dict:
    """Select declared local inputs for one exact source use; not scan evidence."""
    if not isinstance(uses, list) or not 1 <= len(uses) <= 512:
        raise ValueError('image selection requires a bounded nonempty source-use list')
    keys = set()
    found = None
    for row in uses:
        if (not isinstance(row, dict) or set(row) != {'path', 'line', 'source_sha256', 'expression', 'reference', 'platform'}
                or not isinstance(row['path'], str) or not 0 < len(row['path']) <= 256
                or re.fullmatch(r'[A-Za-z0-9_./-]+', row['path']) is None
                or PurePosixPath(row['path']).is_absolute() or any(p in {'', '.', '..'} for p in row['path'].split('/'))
                or type(row['line']) is not int or row['line'] <= 0
                or not isinstance(row['source_sha256'], str) or re.fullmatch('[0-9a-f]{64}', row['source_sha256']) is None
                or not isinstance(row['expression'], str) or not 0 < len(row['expression']) <= 8192
                or not isinstance(row['reference'], str) or len(row['reference']) > 2048
                or _IMAGE_DIGEST.fullmatch(row['reference']) is None
                or not isinstance(row['platform'], str) or row['platform'] not in {'linux/amd64', 'linux/arm64'}):
            raise ValueError('image selection has an invalid closed source-use schema')
        key = (row['path'], row['line'], row['source_sha256'], row['expression'])
        if key in keys:
            raise ValueError('duplicate image source-use selection')
        keys.add(key)
        if key == (path, line, source_sha256, expression):
            found = row
    if found is None:
        raise ValueError('current source image use has no exact selection')
    original = expression.removeprefix('docker://')
    if (_IMAGE_DIGEST.fullmatch(original) and original != found['reference']) or (platform and platform != found['platform']):
        raise ValueError('image selection conflicts with immutable source identity or literal platform')
    return dict(found)


def read_image_selection(path: Path | None) -> dict | None:
    """Read at most64KiB of explicit declarations, never image evidence.

    The closed document has schema_version1, exact source/run objects matching
    input_profile, a timezone-aware created_at, and1..512 uses. Each use names
    path/line/source_sha256/expression/reference/platform. All uses must still
    exist in current bytes. The caller must obtain genuine immutable image and
    platform provenance separately; no transport or scanner authority is added.
    """
    if path is None:
        return None
    from .security_artifacts import read_file
    from .security_data import _json
    path = Path(path).absolute()
    document = _json(read_file(path.parent, path.name, 65536))
    if (set(document) != {'schema_version', 'source', 'run', 'created_at', 'uses'}
            or type(document['schema_version']) is not int or document['schema_version'] != 1
            or not isinstance(document['source'], dict) or not isinstance(document['run'], dict)
            or not isinstance(document['created_at'], str) or not 0 < len(document['created_at']) <= 128
            or not isinstance(document['uses'], list) or not 1 <= len(document['uses']) <= 512):
        raise ValueError('image selection document is malformed')
    return document


def declared_inventory(root: Path, selection: dict | None) -> dict[str, Any]:
    """Bind the complete declaration identity, without granting currentness.

    Callers must separately validate it against independent current authority.
    Image rows remain declaration-only-unverified and cannot start a scanner.
    """
    result = collect_inventory(root, image_bindings=selection['uses'] if selection else None)
    if selection is not None:
        result.pop('digest')
        result['image_selection_sha256'] = canonical_digest(selection)
        for image in result['images']:
            image['selection_assurance'] = 'declaration-only-unverified'
        result['digest'] = canonical_digest(result)
    return result


def compose_image_platform(fields: dict) -> str | None:
    value = fields.get('platform')
    if value is None:
        return None
    platform = _yaml_text(value, 'Compose platform')
    if platform not in {'linux/amd64', 'linux/arm64'}:
        raise ValueError('Compose image needs a supported explicit platform')
    return platform


def qualify_image_use(reference: str, path: str, line: int, source_sha256: str, *,
                      bindings=None, require_digest=False, source_reference=None, platform=None):
    """Bind a current source use to an explicit input choice, not a deployment claim.

    OCI graph/config validation must subsequently establish the actual selected
    bytes/platform. A selection never proves what a mutable tag resolved to on
    a registry or what a deployed service runs.
    """
    original = reference if source_reference is None else source_reference
    gaps = []
    used = None
    if platform not in (None, 'linux/amd64', 'linux/arm64'):
        raise ValueError('Unsupported image platform')
    if isinstance(bindings, list):
        if len(bindings) > 512:
            raise ValueError('Image source selection exceeds its finite bound')
        keys = set()
        selected = None
        for row in bindings:
            if (not isinstance(row, dict) or set(row) != {'manifest', 'line', 'source_sha256',
                    'source_reference', 'reference', 'platform'}
                    or not isinstance(row['manifest'], str) or not 0 < len(row['manifest']) <= 2048
                    or PurePosixPath(row['manifest']).is_absolute() or '..' in PurePosixPath(row['manifest']).parts
                    or '\\' in row['manifest'] or type(row['line']) is not int or row['line'] < 1
                    or not isinstance(row['source_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['source_sha256'])
                    or not isinstance(row['source_reference'], str) or not 0 < len(row['source_reference']) <= 8192
                    or not isinstance(row['reference'], str) or len(row['reference']) > 8192 or not _IMAGE_DIGEST.fullmatch(row['reference'])
                    or row['platform'] not in {'linux/amd64', 'linux/arm64'}):
                raise ValueError('Malformed current image source selection')
            key = (row['manifest'], row['line'], row['source_sha256'], row['source_reference'])
            if key in keys:
                raise ValueError('Duplicate image source selection')
            keys.add(key)
            if key == (path, line, source_sha256, original):
                selected = row
        if selected is None:
            gaps.append({'code': 'missing-image-source-selection', 'path': path,
                         'message': 'current image use requires its own exact selection'})
        else:
            if platform is not None and platform != selected['platform']:
                gaps.append({'code': 'image-selection-platform-mismatch', 'path': path,
                             'message': 'selected platform differs from current source platform'})
            elif _IMAGE_DIGEST.fullmatch(reference) and reference != selected['reference']:
                gaps.append({'code': 'image-selection-reference-mismatch', 'path': path,
                             'message': 'immutable source reference differs from selected artifact'})
            else:
                reference, platform = selected['reference'], selected['platform']
                used = canonical_digest(selected)
    variable = re.fullmatch(r'\$\{([A-Z][A-Z0-9_]*)(?::[?+-][^}]*)?\}', reference)
    if variable:
        observed = bindings.get(variable[1], '') if isinstance(bindings, dict) else ''
        reference = observed if isinstance(observed, str) else ''
        if not _IMAGE_DIGEST.fullmatch(reference):
            gaps.append({'code': 'unresolved-image', 'path': path,
                         'message': f'{variable[1]} needs an observed immutable image binding'})
    elif '$' in reference or not reference:
        gaps.append({'code': 'unresolved-image', 'path': path,
                     'message': 'dynamic image expression needs an observed immutable binding'})
    elif require_digest and not _IMAGE_DIGEST.fullmatch(reference):
        gaps.append({'code': 'unresolved-image', 'path': path,
                     'message': 'image requires an immutable sha256 reference'})
    item = {'reference': reference or original, 'source_reference': original,
            'manifest': path, 'line': line, 'kind': 'oci-image', 'platform': platform or 'unknown',
            'usage': 'build-ci' if path.startswith('.github/') else 'runtime-and-development',
            'source_sha256': source_sha256}
    if used is not None:
        item['source_selection_sha256'] = used
        # Preserve393's declaration fields alongside the OCI source-use key.
        item['selection_sha256'] = used
        item['selection_assurance'] = 'declaration-only-unverified'
    return item, gaps, used


def collect_inventory(root: Path, *, image_bindings: dict[str, str] | list[dict] | None = None) -> dict[str, Any]:
    root = Path(root).resolve()
    bindings = {} if image_bindings is None else image_bindings
    # Preserve393's complete declaration schema while using the existing OCI
    # source-use matcher. This conversion grants no image/platform evidence.
    if isinstance(bindings, list) and bindings and all(isinstance(row, dict) and 'path' in row for row in bindings):
        for row in bindings:
            selected_image_use(bindings, path=row.get('path',''), line=row.get('line',0), source_sha256=row.get('source_sha256',''),
                               expression=row.get('expression',''), platform=row.get('platform'))
        bindings = [{'manifest': row['path'], 'line': row['line'], 'source_sha256': row['source_sha256'],
                     'source_reference': row['expression'], 'reference': row['reference'], 'platform': row['platform']}
                    for row in bindings]
    used_image_bindings = set()
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

    def image(reference: str, path: str, line: int, *, require_digest=False, source_reference=None, platform=None):
        item, failures, used = qualify_image_use(reference, path, line,
            hashlib.sha256(texts[path].encode()).hexdigest(), bindings=bindings,
            require_digest=require_digest, source_reference=source_reference, platform=platform)
        result['images'].append(item)
        result['gaps'].extend(failures)
        if used is not None:
            used_image_bindings.add(used)

    def yaml_image(value: _YamlNode | None, path: str, label: str, *, container=False, platform=None):
        if container and value is not None and value.kind == 'mapping':
            value = value.value.get('image')
        reference = _yaml_text(value, label)
        image(reference, path, value.line, require_digest=True, platform=platform)

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
            for service_name, service in services.items():
                fields = _yaml_map(service, 'Compose service')
                for indirect in ('extends', 'provider'):
                    if indirect in fields:
                        gap('unsupported-compose-composition', relative, f'Compose {indirect} needs qualified build/composition coverage')
                if 'build' in fields:
                    from .security_build_inputs import describe_build
                    try:
                        build = describe_build(root, relative, service_name, fields, files, bindings)
                    except (OSError, ValueError, UnicodeError, TypeError, KeyError) as exc:
                        gap('unsupported-compose-composition', relative, str(exc)[:300])
                    else:
                        result.setdefault('builds', []).append(build)
                        for item in build['context_files']:
                            if item['path'] not in result['files']:
                                result['files'].append(item['path'])
                        image(build['source_reference'], relative, build['line'], require_digest=True,
                              platform=build['platform'])
                if 'image' in fields:
                    yaml_image(fields['image'], relative, 'Compose image', platform=compose_image_platform(fields))
                elif not set(fields) & {'build', 'extends', 'provider'}:
                    gap('unresolved-image', relative, 'Compose service has no resolved image; override/composition needs evidence')
                # This named input selects the image used by the runner. Read
                # only its source declaration, never the process environment.
                # Both Compose environment forms retain the scalar's real line
                # and the exact value expression for the current-use join.
                environment = fields.get('environment')
                runner = None
                if environment is not None and environment.kind == 'mapping':
                    runner = environment.value.get('TRUST_CI_RUNNER_IMAGE')
                    if runner is not None:
                        yaml_image(runner, relative, 'Compose runner image', platform=compose_image_platform(fields))
                elif environment is not None and environment.kind == 'sequence':
                    for entry in environment.value:
                        if entry.kind != 'scalar':
                            raise _YamlError('unsupported-yaml', 'Compose environment entries must be static strings')
                        key, separator, expression = entry.value.partition('=')
                        if key != 'TRUST_CI_RUNNER_IMAGE':
                            continue
                        if runner is not None:
                            raise _YamlError('unsupported-yaml', 'duplicate Compose runner image input')
                        runner = entry
                        if not separator or not expression:
                            gap('unresolved-image', relative, 'Compose runner image needs an explicit source value')
                            continue
                        image(expression, relative, entry.line, require_digest=True, platform=compose_image_platform(fields))
                elif environment is not None:
                    raise _YamlError('unsupported-yaml', 'Compose environment must be a static mapping or sequence')
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
    from .security_corresponding_source import classify
    try:
        corresponding = classify(root, files)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        corresponding = []
        gap('corresponding-source-unverified', '<corresponding-source>', str(exc)[:300])
    if corresponding:
        result['corresponding_sources'] = corresponding
    retained_manifests = {row['manifest'] for row in corresponding}
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
        try:
            archival = _archival_document(root, relative, files)
        except (OSError, ValueError):
            gap('archival-evidence-unverified', relative, 'exact historical documentation/provenance binding is unavailable')
        else:
            if archival is not None:
                result.setdefault('excluded_archival_evidence', []).append(archival)
                continue  # Retained in files for source/secret coverage above.
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
                    image(reference, relative, text[:text.index(key)].count('\n') + 1 if key in text else 1,
                          require_digest=True, platform=data['platform'])
                    result['images'][-1].update(image_id=image_id, usage='build-ci')
            elif name == 'pyproject.toml':
                if relative in retained_manifests:
                    continue  # Exact constraints remain typed in corresponding_sources.
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
            platform = None
            if is_docker and re.match(r'FROM\s', line, re.IGNORECASE):
                parts = line.split()
                flags = [part for part in parts[1:] if part.startswith('--platform=')]
                if flags:
                    if len(flags) != 1 or flags[0] not in {'--platform=linux/amd64', '--platform=linux/arm64'}:
                        gap('unresolved-image-platform', relative,
                            'Dockerfile FROM requires one supported literal platform')
                        continue
                    platform = flags[0].split('=', 1)[1]
                parts = [part for part in parts[1:] if not part.startswith('--platform=')]
                reference = parts[0] if parts else ''
                internal_stage = reference.lower() == 'scratch' or reference.lower() in stages
                if len(parts) >= 3 and parts[1].upper() == 'AS':
                    stages.add(parts[2].lower())
                if internal_stage:
                    continue
            if reference is not None:
                image(reference, relative, line_number, platform=platform)
    result['files'] = sorted(set(result['files']))
    result['dependencies'] = sorted(dependencies.values(), key=lambda item: (item['ecosystem'], item['name'], item['version'], item['manifest'], item['usage']))
    if isinstance(bindings, list) and used_image_bindings != {canonical_digest(row) for row in bindings}:
        gap('unused-image-source-selection', '<image-selection>', 'selected image use is absent or differs from current source')
    result['complete'] = not result['gaps']
    result['artifact_coverage'] = 'not_evaluated'
    result['digest'] = canonical_digest(result)
    return result
