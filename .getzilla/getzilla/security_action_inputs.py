"""Finite GitHub Action source data adapter; never execute upstream programs.

A complete retained source tree is diagnostic evidence. Only an independently
supplied, byte-bound bundle/component map plus complete terms can emit a family.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import hashlib
import io
import re
import stat
import zipfile
from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .security_artifacts import (ArtifactError, MAX_INDEX_BYTES, MAX_METADATA_BYTES, MAX_MEMBERS,
                                 _git_tree, _saved_proof, artifact_context, family_identity,
                                 read_file, safe_parts)

ZIP_LIMIT = 32 * 1024 * 1024
EXPANDED_LIMIT = 128 * 1024 * 1024
BATCH_LIMIT = 128 * 1024 * 1024
REFERENCE = re.compile(r'([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})')
# These two pinned repository test fixtures are retained as opaque Git blobs.
# They are never resolved, extracted, or eligible as entrypoints/term containers.
OPAQUE_LINKS = {
    ('actions/setup-python', '5fda3b95a4ea91299a34e894583c3862153e4b97'):
        {'__tests__/data/inner/poetry.lock': b'../poetry.lock',
         '__tests__/data/inner/pyproject.toml': b'../pyproject.toml'},
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _fail(code, message):
    raise ArtifactError(code, message)


def _json(raw):
    from .security_data import _json as parse
    value = parse(raw)
    if not isinstance(value, dict):
        _fail('artifact-action-data', 'source data must be an object')
    return value


def _plain(node):
    if node.kind == 'mapping':
        return {key: _plain(value) for key, value in node.value.items()}
    if node.kind == 'sequence':
        return [_plain(value) for value in node.value]
    return node.value


def _yaml(raw):
    from .security_inventory import _parse_inventory_yaml
    if len(raw) > MAX_METADATA_BYTES:
        _fail('artifact-action-data', 'Action YAML exceeds the existing metadata bound')
    try:
        return _plain(_parse_inventory_yaml(raw.decode('utf-8')))
    except (ValueError, UnicodeError) as exc:
        _fail('artifact-action-data', f'bounded Action YAML is unsupported: {exc}')


def licensed_text(raw, selector):
    """Decode one closed Licensed YAML selector, retaining its original container."""
    if not isinstance(selector, str) or not re.fullmatch(r'licenses/(0|[1-9][0-9]{0,3})/text', selector):
        _fail('artifact-action-selector', 'unsupported Licensed text selector')
    value = _yaml(raw)
    index = int(selector.split('/')[1])
    licenses = value.get('licenses') if isinstance(value, dict) else None
    if not isinstance(licenses, list) or index >= len(licenses) or not isinstance(licenses[index], dict):
        _fail('artifact-action-selector', 'Licensed selector is absent')
    text = licenses[index].get('text')
    if not isinstance(text, str) or not text.strip():
        _fail('artifact-action-selector', 'Licensed selector is not complete text')
    return text


def node_metadata(raw, files):
    """Read Node main/pre/post or a bounded local composite graph as data only."""
    value = _yaml(raw)
    if not isinstance(value, dict) or not isinstance(value.get('runs'), dict):
        _fail('artifact-action-metadata', 'Action runs mapping is missing')
    runs = value['runs']
    using = runs.get('using')
    if using not in {'node20', 'node24', 'composite'}:
        _fail('artifact-action-metadata', 'unsupported Action runtime')
    if using == 'composite':
        # Composite dependencies require a separate map rather than shell analysis.
        steps = runs.get('steps')
        if set(runs) != {'using', 'steps'} or not isinstance(steps, list) or not 0 < len(steps) <= 512:
            _fail('artifact-action-metadata', 'unsupported composite steps')
        for step in steps:
            if not isinstance(step, dict) or 'uses' in step or not isinstance(step.get('run'), str):
                _fail('artifact-action-metadata', 'composite dependency needs qualified source mapping')
        return {}
    if not set(runs) <= {'using', 'main', 'pre', 'post', 'pre-if', 'post-if'} or not isinstance(runs.get('main'), str):
        _fail('artifact-action-metadata', 'unsupported Node entrypoint schema')
    result = {}
    for key in ('main', 'pre', 'post'):
        if key in runs:
            name = runs[key]
            safe_parts(name)
            row = files.get(name)
            if row is None or (isinstance(row, dict) and row.get('mode') == '120000'):
                _fail('artifact-action-metadata', 'Node entrypoint is missing or is a link')
            result[name] = _sha(row) if isinstance(row, bytes) else row.get('sha256')
    return result


def source_url(url, repository, pin, kind, tree=None):
    expected = {'commit': f'https://api.github.com/repos/{repository}/git/commits/{pin}',
                'tree': f'https://api.github.com/repos/{repository}/git/trees/{tree}?recursive=1',
                'zip': f'https://codeload.github.com/{repository}/zip/{pin}'}
    return kind in expected and url == expected[kind]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _fail('artifact-action-origin', 'Action source redirect is not admitted')


def _fetch(url, *, maximum):
    # Caller constructs only exact official API/codeload URLs. No credentials,
    # redirects, retries, API fallback, package transport changes, or execution.
    try:
        with build_opener(_NoRedirect()).open(Request(url, headers={'User-Agent': 'Getzilla-source-data/1'}), timeout=30) as response:
            if response.geturl() != url:
                _fail('artifact-action-origin', 'Action source URL changed')
            raw = response.read(maximum + 1)
    except ArtifactError:
        raise
    except (OSError, ValueError) as exc:
        _fail('artifact-action-transport', str(exc))
    if len(raw) > maximum:
        _fail('artifact-size', 'Action source response exceeds its finite bound')
    return raw


def _source(payload, commit_raw, tree_raw, repository, pin, archive_root=None):
    commit, tree = _json(commit_raw), _json(tree_raw)
    if (commit.get('sha') != pin or not isinstance(commit.get('tree'), dict)
            or commit['tree'].get('sha') != tree.get('sha') or tree.get('truncated') is not False
            or not isinstance(tree.get('tree'), list) or not 0 < len(tree['tree']) <= MAX_MEMBERS):
        _fail('artifact-action-origin', 'complete pinned Git commit/tree evidence is required')
    rows = {}
    for row in tree['tree']:
        if not isinstance(row, dict):
            _fail('artifact-action-origin', 'malformed Git tree entry')
        name = row.get('path')
        safe_parts(name)
        if row.get('type') == 'tree' and row.get('mode') == '040000':
            continue
        if (name in rows or row.get('type') != 'blob' or row.get('mode') not in {'100644', '100755', '120000'}
                or not re.fullmatch('[0-9a-f]{40}', str(row.get('sha')))
                or type(row.get('size')) is not int or not 0 <= row['size'] <= EXPANDED_LIMIT):
            _fail('artifact-action-origin', 'Git tree has ambiguous blobs or unsupported submodules')
        if row['mode'] == '120000' and name not in OPAQUE_LINKS.get((repository, pin), {}):
            _fail('artifact-action-link', 'unreviewed source link is unsupported')
        rows[name] = row
    if _git_tree(rows) != tree.get('sha'):
        _fail('artifact-action-origin', 'Git tree identity differs')
    files, members, prefix, total = {}, {}, archive_root, 0
    if len(payload) > ZIP_LIMIT:
        _fail('artifact-size', 'Action ZIP exceeds its local source bound')
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            if len(archive.infolist()) > MAX_MEMBERS + 1000:
                _fail('artifact-size', 'too many Action ZIP entries')
            seen = set()
            for item in archive.infolist():
                if item.orig_filename != item.filename:
                    _fail('artifact-action-origin', 'ZIP name differs from original name')
                name = item.filename.rstrip('/')
                safe_parts(name)
                if name in seen:
                    _fail('artifact-action-origin', 'duplicate ZIP path')
                seen.add(name)
                parts = name.split('/')
                if prefix is None:
                    prefix = parts[0]
                if parts[0] != prefix or '/' in prefix:
                    _fail('artifact-action-origin', 'ZIP has more than one source root')
                if item.is_dir():
                    continue
                relative = '/'.join(parts[1:])
                row = rows.get(relative)
                if row is None or row['size'] != item.file_size or item.flag_bits & 1:
                    _fail('artifact-action-origin', 'ZIP differs from Git blob inventory')
                mode = item.external_attr >> 16
                # GitHub omits Unix mode for ordinary 100644 files; Git remains
                # authoritative. Executables and the two opaque links stay exact.
                valid_mode = (mode == int(row['mode'], 8) or (row['mode'] == '100644' and mode == 0)
                              or (row['mode'] == '120000' and mode == stat.S_IFLNK | 0o777))
                if not valid_mode:
                    _fail('artifact-action-origin', 'ZIP mode differs from pinned Git mode')
                total += item.file_size
                if total > EXPANDED_LIMIT:
                    _fail('artifact-size', 'Action expanded source exceeds bound')
                raw = archive.read(item)
                if hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw, usedforsecurity=False).hexdigest() != row['sha']:
                    _fail('artifact-action-origin', 'ZIP blob differs from pinned Git tree')
                if row['mode'] == '120000' and raw != OPAQUE_LINKS[(repository, pin)][relative]:
                    _fail('artifact-action-link', 'opaque fixture link target differs')
                files[relative] = raw
                members[prefix + '/' + relative] = {'sha256': _sha(raw), 'size': len(raw)}
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        _fail('artifact-action-origin', f'invalid source ZIP: {exc}')
    if set(files) != set(rows):
        _fail('artifact-action-origin', 'ZIP does not retain the complete Git tree')
    metadata = [name for name in ('action.yml', 'action.yaml') if name in files]
    if len(metadata) != 1:
        _fail('artifact-action-metadata', 'select exactly one root Action metadata file')
    regular = {name: raw for name, raw in files.items() if rows[name]['mode'] != '120000'}
    entries = node_metadata(files[metadata[0]], regular)
    return files, members, prefix, metadata[0], entries, rows


def verify_family(root, record, *, now=None):
    """Verify the source-data proof variant, without root-license inheritance."""
    identity = family_identity(record)
    match = REFERENCE.fullmatch(record['subject'].get('reference', ''))
    if record['kind'] != 'action' or record['subject'].get('kind') != 'github-action' or not match:
        _fail('artifact-action-origin', 'exact root repository Action pin is required')
    repository, pin = match.groups()
    origin = record['origin']
    keys = {'kind', 'index_url', 'index_path', 'index_sha256', 'artifact_url', 'tree_path', 'tree_sha256', 'archive_root'}
    if (set(origin) != keys or origin['kind'] != 'github-action-source/v1'
            or not source_url(origin['index_url'], repository, pin, 'commit')
            or not source_url(origin['artifact_url'], repository, pin, 'zip')):
        _fail('artifact-action-origin', 'source must name its exact official commit and codeload URL')
    try:
        acquired = datetime.fromisoformat(record['acquired_at'].replace('Z', '+00:00'))
        # The existing evaluator/catalog owns its supplied clock. Production
        # passes that clock explicitly; byte-only family_evidence must not
        # substitute the host clock for an evaluator's frozen observation.
        if acquired.tzinfo is None or (now is not None and not timedelta(0) <= now - acquired <= timedelta(hours=72)):
            raise ValueError('outside 72h window')
    except (ValueError, TypeError, AttributeError) as exc:
        _fail('artifact-action-stale', f'invalid source acquisition time: {exc}')
    payload = read_file(Path(root), record['path'], ZIP_LIMIT)
    if len(payload) != record['bytes'] or _sha(payload) != record['sha256']:
        _fail('artifact-hash', 'Action source payload changed')
    commit_raw, _ = _saved_proof(Path(root), origin['index_path'], origin['index_sha256'])
    tree_raw, _ = _saved_proof(Path(root), origin['tree_path'], origin['tree_sha256'])
    files, members, prefix, metadata, entries, rows = _source(payload, commit_raw, tree_raw, repository, pin, origin['archive_root'])
    raw, proof = _saved_proof(Path(root), record['components']['path'], record['components']['sha256'])
    required = {'schema_version', 'kind', 'artifact_sha256', 'metadata_sha256', 'entrypoints', 'bundles', 'components'}
    if (set(proof) != required or type(proof['schema_version']) is not int or proof['schema_version'] != 1
            or proof['kind'] != 'action-source-components/v1' or proof['artifact_sha256'] != _sha(payload)
            or proof['metadata_sha256'] != _sha(files[metadata]) or proof['entrypoints'] != entries
            or not isinstance(proof['components'], list) or not 0 < len(proof['components']) <= MAX_MEMBERS
            or not isinstance(proof['bundles'], list) or len(proof['bundles']) != len(entries) or not entries):
        _fail('license-transitive-coverage', 'exact Node bundles and closed component map are required')
    package = _json(files.get('package.json', b'{}'))
    lock = _json(files.get('package-lock.json', b'{}'))
    packages = lock.get('packages')
    if lock.get('lockfileVersion') not in {2, 3} or not isinstance(packages, dict):
        _fail('license-transitive-coverage', 'bounded npm package lock is required')
    expected = {(package.get('name'), package.get('version'))}
    for name, value in packages.items():
        if not isinstance(value, dict):
            _fail('license-transitive-coverage', 'malformed locked component')
        if not name or value.get('dev') is True:
            continue
        if value.get('link') or 'node_modules/' not in name:
            _fail('license-transitive-coverage', 'unsupported npm workspace or linked component')
        expected.add((value.get('name') or name.rsplit('node_modules/', 1)[1], value.get('version')))
    ids, pairs = set(), set()
    for component in proof['components']:
        if (not isinstance(component, dict) or set(component) != {'id', 'name', 'version', 'expression', 'requires', 'terms', 'notices'}
                or not isinstance(component['id'], str) or not component['id'] or component['id'] in ids
                or not all(isinstance(component[key], list) for key in ('requires', 'terms', 'notices'))
                or not component['terms'] or not all(isinstance(component[key], str) and component[key] for key in ('name', 'version', 'expression'))):
            _fail('license-transitive-coverage', 'component declaration is malformed')
        pair = (component['name'], component['version'])
        if pair in pairs:
            _fail('license-transitive-coverage', 'duplicate locked component identity')
        ids.add(component['id'])
        pairs.add(pair)
        if pair == (package.get('name'), package.get('version')) and component['expression'] != package.get('license'):
            _fail('license-conflict', 'root package expression differs from retained metadata')
    if pairs != expected or any(not isinstance(dep, str) or dep not in ids for c in proof['components'] for dep in c['requires']):
        _fail('license-transitive-coverage', 'bundle map does not cover exact production lock components')
    seen, mapped = set(), set()
    for bundle in proof['bundles']:
        if (not isinstance(bundle, dict) or set(bundle) != {'path', 'sha256', 'components'}
                or bundle['path'] in seen or entries.get(bundle['path']) != bundle['sha256']
                or not isinstance(bundle['components'], list) or not bundle['components']
                or len(set(bundle['components'])) != len(bundle['components']) or not set(bundle['components']) <= ids):
            _fail('license-transitive-coverage', 'bundle membership is incomplete or differs from exact entrypoints')
        seen.add(bundle['path'])
        mapped.update(bundle['components'])
    if seen != set(entries) or mapped != ids:
        _fail('license-transitive-coverage', 'bundle membership omits components')
    from .security_licenses import ALLOWED, _license_evidence, _select_expression
    evidence = [{'path': origin['index_path'], 'sha256': origin['index_sha256'], 'bytes': len(commit_raw)},
                {'path': origin['tree_path'], 'sha256': origin['tree_sha256'], 'bytes': len(tree_raw)},
                {'path': record['components']['path'], 'sha256': record['components']['sha256'], 'bytes': len(raw)}]
    normalized, retained = [], {}
    for component in proof['components']:
        paths, notices, owned, containers = [], [], [], {}
        is_root = (component['name'], component['version']) == (package.get('name'), package.get('version'))
        for kind in ('terms', 'notices'):
            for index, item in enumerate(component[kind]):
                if not isinstance(item, dict) or set(item) != {'path', 'sha256', 'selector', 'text_sha256'}:
                    _fail('artifact-action-selector', 'term/notice needs exact container and decoded-text binding')
                name = item['path']
                safe_parts(name)
                body = files.get(name)
                if body is None or rows[name]['mode'] == '120000' or _sha(body) != item['sha256']:
                    _fail('artifact-action-selector', 'term container is missing or changed')
                if not is_root and item['selector'] is None and kind == 'terms':
                    _fail('license-transitive-coverage', 'non-root terms need component-bound Licensed source metadata')
                if item['selector'] is not None:
                    if kind != 'terms':
                        _fail('artifact-action-selector', 'embedded notices need a separately qualified selector schema')
                    cached = _yaml(body)
                    if (not isinstance(cached, dict) or cached.get('type') != 'npm'
                            or (cached.get('name'), cached.get('version')) != (component['name'], component['version'])
                            or str(cached.get('license')).lower() != component['expression'].lower()):
                        _fail('license-conflict', 'embedded term component identity/expression differs')
                    containers.setdefault(name, set()).add(item['selector'])
                text = body if item['selector'] is None else licensed_text(body, item['selector']).encode('utf-8')
                if _sha(text) != item['text_sha256']:
                    _fail('artifact-action-selector', 'decoded term bytes changed')
                # Explicit virtual evidence path; never pretend decoded terms were
                # a separate source archive member. Original container stays bound.
                path = f'derived/{_sha(component["id"].encode())}/{kind}/{index}/' + ('LICENSE' if kind == 'terms' else 'NOTICE')
                retained[path] = text
                owned.append({'path': path, 'sha256': _sha(text), 'bytes': len(text)})
                (paths if kind == 'terms' else notices).append(path)
                evidence.append({'path': prefix + '/' + name, 'sha256': _sha(body), 'bytes': len(body),
                                 'selector': item['selector'], 'text_sha256': _sha(text), 'derived_path': path,
                                 'container_kind': 'archive-member', 'artifact_path': record['path'],
                                 'artifact_sha256': record['sha256']})
        for name, selectors in containers.items():
            cached = _yaml(files[name])
            if (not isinstance(cached.get('licenses'), list) or cached.get('notices') != []
                    or selectors != {f'licenses/{i}/text' for i in range(len(cached['licenses']))}):
                _fail('license-obligation-missing', 'all embedded terms/notices must be independently retained and checked')
        if is_root:
            declared = {item['path'] for key in ('terms', 'notices') for item in component[key]}
            required_root = {name for name in files if '/' not in name
                             and name.lower().startswith(('license', 'licence', 'copying', 'notice'))}
            if not required_root <= declared:
                _fail('license-obligation-missing', 'root source license/notice file was omitted')
        chosen, identifiers = _select_expression(component['expression'], list(ALLOWED))
        _license_evidence({p: retained[p] for p in paths + notices},
                          {'expression': component['expression'], 'license_paths': paths}, identifiers, chosen)
        normalized.append({'id': component['id'], 'expression': component['expression'], 'requires': component['requires'],
                           'files': owned, 'license_paths': paths, 'notice_paths': notices})
    return {'artifact_id': identity, 'members': members, 'files': retained, 'components': normalized,
            'binding': {'artifact_id': identity, 'artifact_sha256': record['sha256'], 'artifact_size': len(payload),
                        'subject': record['subject'], 'context': record['context'], 'proofs': evidence},
            'bound_bytes': len(payload) + sum(item['bytes'] for item in evidence)}



def _component_inputs(files):
    """Unqualified lock/cache facts, including every observed term/policy gap."""
    from .security_license_texts import recognized_license
    from .security_licenses import ALLOWED
    candidates, gaps, cached = [], [], set()
    try:
        lock = _json(files.get('package-lock.json', b'{}'))
        packages = lock.get('packages')
        if not isinstance(packages, dict):
            _fail('action-lock-missing', 'production component lock data is absent')
        expected = {(row.get('name') or name.rsplit('node_modules/', 1)[-1], row.get('version'))
                    for name, row in packages.items() if name and isinstance(row, dict) and row.get('dev') is not True}
    except (ArtifactError, ValueError, TypeError) as exc:
        expected = set()
        gaps.append({'code': getattr(exc, 'code', 'action-lock-data'), 'message': str(exc)})
    for name, body in sorted(files.items()):
        if not name.startswith('.licenses/') or not name.endswith(('.yml', '.yaml')):
            continue
        item = {'path': name, 'sha256': _sha(body), 'bytes': len(body), 'qualification': False}
        try:
            value = _yaml(body)
            if not isinstance(value, dict) or not isinstance(value.get('licenses'), list):
                _fail('artifact-action-data', 'Licensed component declaration is missing')
            pair = (value.get('name'), value.get('version'))
            cached.add(pair)
            item.update(name=pair[0], version=pair[1], expression=value.get('license'), terms=[], notices=value.get('notices'))
            for index, part in enumerate(value['licenses']):
                text = licensed_text(body, f'licenses/{index}/text').encode('utf-8')
                identifier = recognized_license(text.decode('utf-8'))
                item['terms'].append({'selector': f'licenses/{index}/text', 'text_sha256': _sha(text),
                                      'bytes': len(text), 'recognized_license': identifier})
                if identifier not in ALLOWED:
                    gaps.append({'code': 'action-component-term-review', 'path': name, 'selector': f'licenses/{index}/text'})
            if str(value.get('license')).lower() not in {identifier.lower() for identifier in ALLOWED}:
                gaps.append({'code': 'action-component-policy-review', 'path': name, 'expression': value.get('license')})
            if value.get('notices') != []:
                gaps.append({'code': 'action-component-notice-mapping', 'path': name})
        except (ArtifactError, ValueError, TypeError, KeyError, UnicodeError) as exc:
            item['gap'] = {'code': getattr(exc, 'code', 'artifact-action-data'), 'message': str(exc)}
            gaps.append(dict(item['gap'], path=name))
        candidates.append(item)
    for name, version in sorted(expected - cached, key=str):
        gaps.append({'code': 'action-component-term-container-missing', 'name': name, 'version': version})
    for name, version in sorted(cached - expected, key=str):
        gaps.append({'code': 'action-cache-component-not-in-lock', 'name': name, 'version': version})
    return {'qualification': False, 'production_lock_components': [{'name': name, 'version': version}
            for name, version in sorted(expected, key=str)], 'licensed_candidates': candidates, 'gaps': gaps}


def prepare_actions(inventory, artifacts, *, fetch=None, now=None, component_maps=None, byte_budget=None):
    """Retain deduplicated source facts; emit only proved per-use family records."""
    from . import manifest
    from .security_license_acquisition import _write
    fetch, now = fetch or _fetch, now or datetime.now(timezone.utc)
    maps = component_maps or {}
    report = {'schema_version': 1, 'inventory_sha256': inventory.get('digest'), 'records': [], 'gaps': [],
              'source_facts': [], 'bound_bytes': 0, 'record_bytes': 0}
    groups = {}
    for subject in inventory.get('tools', []):
        if subject.get('kind') == 'github-action':
            groups.setdefault(subject.get('reference'), []).append(subject)
    if len(groups) > 6:
        report['gaps'] = [{'subject': subject, 'code': 'artifact-action-source-count',
                           'message': 'finite Action adapter admits at most six distinct source pins'}
                          for subjects in groups.values() for subject in subjects]
        return report
    budget = BATCH_LIMIT if byte_budget is None else min(BATCH_LIMIT, byte_budget)
    _, descriptor = manifest._open_root(Path(artifacts))
    try:
        for reference, subjects in groups.items():
            try:
                match = REFERENCE.fullmatch(reference or '')
                if not match:
                    _fail('artifact-action-origin', 'Action source needs a full root-repository commit pin')
                repository, pin = match.groups()
                base = 'actions/' + _sha(reference.encode())
                paths = {'commit': base + '/commit.json', 'tree': base + '/tree.json', 'zip': base + '/source.zip'}
                facts = {'reference': reference, 'acquired_at': now.isoformat(), 'bound_bytes': 0,
                         'qualification': False, 'responses': [],
                         'required_inputs': ['qualified-bundle-component-map', 'complete-component-terms', 'component-policy-decisions']}
                report['source_facts'].append(facts)

                def receive(url, key, maximum):
                    nonlocal budget
                    maximum = min(maximum, max(0, budget))
                    if maximum <= 0:
                        _fail('artifact-size', 'shared Action byte budget is exhausted')
                    raw = fetch(url, maximum=maximum)
                    if not isinstance(raw, bytes) or len(raw) > maximum:
                        _fail('artifact-size', 'Action response exceeds bounded request')
                    _write(descriptor, paths[key], raw)
                    facts['responses'].append({'url': url, 'path': paths[key], 'sha256': _sha(raw), 'bytes': len(raw)})
                    facts['bound_bytes'] += len(raw)
                    logical = len(raw) * len(subjects)
                    report['bound_bytes'] += logical
                    budget -= logical
                    return raw

                commit_url = f'https://api.github.com/repos/{repository}/git/commits/{pin}'
                commit_raw = receive(commit_url, 'commit', MAX_INDEX_BYTES)
                commit = _json(commit_raw)
                tree_id = commit.get('tree', {}).get('sha')
                if not isinstance(tree_id, str) or not re.fullmatch('[0-9a-f]{40}', tree_id):
                    _fail('artifact-action-origin', 'commit tree identity is absent')
                tree_raw = receive(f'https://api.github.com/repos/{repository}/git/trees/{tree_id}?recursive=1', 'tree', MAX_INDEX_BYTES)
                zip_url = f'https://codeload.github.com/{repository}/zip/{pin}'
                payload = receive(zip_url, 'zip', ZIP_LIMIT)
                physical = len(commit_raw) + len(tree_raw) + len(payload)
                facts.update(commit={'url': commit_url, 'path': paths['commit'], 'sha256': _sha(commit_raw)},
                             tree={'path': paths['tree'], 'sha256': _sha(tree_raw), 'git_sha': tree_id},
                             archive={'url': zip_url, 'path': paths['zip'], 'sha256': _sha(payload), 'bytes': len(payload)})
                files, members, prefix, metadata, entries, rows = _source(payload, commit_raw, tree_raw, repository, pin)
                facts.update(metadata={'path': metadata, 'sha256': _sha(files[metadata])}, entrypoints=entries, members=members,
                             component_inputs=_component_inputs(files))
                if budget < 0:
                    _fail('artifact-size', 'logical Action uses exceed shared byte budget')
                if reference not in maps:
                    _fail('action-bundle-map-missing', 'qualified exact bundle/component/term map is absent; root license is insufficient')
                pending, pending_bytes = [], 0
                for subject in subjects:
                    record = {'schema_version': 1, 'kind': 'action', 'subject': subject, 'filename': 'source.zip',
                              'path': paths['zip'], 'sha256': _sha(payload), 'bytes': len(payload),
                              'context': artifact_context(subject), 'acquired_at': now.isoformat(),
                              'components': maps[reference], 'origin': {'kind': 'github-action-source/v1',
                                  'index_url': commit_url, 'index_path': paths['commit'], 'index_sha256': _sha(commit_raw),
                                  'tree_path': paths['tree'], 'tree_sha256': _sha(tree_raw), 'artifact_url': zip_url, 'archive_root': prefix}}
                    checked = verify_family(Path(artifacts), record, now=now)
                    extra = checked['bound_bytes'] - physical
                    if extra > budget:
                        _fail('artifact-size', 'component proof exceeds shared byte budget')
                    budget -= extra
                    report['bound_bytes'] += extra
                    pending_bytes += checked['bound_bytes']
                    pending.append(record)
                report['record_bytes'] += pending_bytes
                report['records'].extend(pending)
            except (ArtifactError, ValueError, TypeError, KeyError, UnicodeError, OSError) as exc:
                if report['source_facts'] and report['source_facts'][-1]['reference'] == reference:
                    report['source_facts'][-1]['gap'] = {'code': getattr(exc, 'code', 'artifact-action-data'), 'message': str(exc)}
                report['gaps'].extend({'subject': subject, 'code': getattr(exc, 'code', 'artifact-action-data'),
                                       'message': str(exc)} for subject in subjects)
                # No partial qualification of one deduplicated source group.
                report['records'] = [row for row in report['records'] if row['subject'] not in subjects]
        return report
    finally:
        import os
        os.close(descriptor)
