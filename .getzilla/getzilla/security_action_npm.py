"""Bounded original npm source objects for conservative Action composition.

This is a data reader. It never installs packages, follows archive links,
executes lifecycle scripts, or treats a root license label as vendor coverage.
"""
from __future__ import annotations

import base64
import hashlib
import io
from pathlib import Path, PurePosixPath
from datetime import datetime, timedelta
import re
import tarfile
from urllib.parse import quote, unquote, urlsplit

from .security_artifacts import ArtifactError, MAX_ARCHIVE_BYTES, MAX_MEMBERS, read_file, safe_parts

MAX_NPM_BYTES = 16 * 1024 * 1024
# Original known registry objects contain one identical dot-segment alias.
# Retain it as opaque data, never extract/select it, and check both full bytes.
_OPAQUE_ALIASES = {
    '7dd4a61668a9a4e8d4e903f1a254f94d53dafd3f316f2b9b597c5ad8c79cb57e',
    '785f73faa92bfba8d61da20bf59325ab2b3dca1bbc0bbac523406f404d8a6f02',
    '960f89e8e5240882f64249d04a538421dd39d62ffacc138544647cc3251bc0e0',
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _fail(code, message):
    raise ArtifactError(code, message)


def _json(raw):
    from .security_data import _json as parse
    value = parse(raw)
    if not isinstance(value, dict):
        _fail('artifact-npm-metadata', 'npm metadata must be an object')
    return value


def registry_url(url):
    if not isinstance(url, str) or len(url) > 4096:
        return False
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.netloc != 'registry.npmjs.org'
            or parsed.query or parsed.fragment or '\\' in unquote(parsed.path)):
        return False
    return not any(part in {'.', '..'} for part in unquote(parsed.path).split('/'))


def _integrity(raw, integrity, algorithms):
    if not isinstance(integrity, str) or not re.fullmatch(r'(sha1|sha512)-[A-Za-z0-9+/]+={0,2}', integrity):
        _fail('artifact-npm-integrity', 'one exact supported lock SRI is required')
    algorithm, encoded = integrity.split('-', 1)
    if algorithm not in algorithms or base64.b64encode(hashlib.new(algorithm, raw).digest()).decode() != encoded:
        _fail('artifact-npm-integrity', 'original npm source does not match its exact SRI')


def source_members(payload):
    """Read all original regular member bytes in memory; never host-extract."""
    if len(payload) > MAX_NPM_BYTES:
        _fail('artifact-size', 'npm object exceeds its source-specific bound')
    files, aliases, seen, total, prefix = {}, {}, set(), 0, None
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
            for member in archive:
                if len(seen) >= MAX_MEMBERS or member.name in seen:
                    _fail('artifact-archive', 'npm archive repeats paths or exceeds member bound')
                seen.add(member.name)
                if member.isdir():
                    safe_parts(member.name.rstrip('/'))
                    continue
                if not member.isfile() or member.issym() or member.islnk() or getattr(member, 'sparse', None):
                    _fail('artifact-archive', 'npm links/special/sparse members are unsupported')
                name = member.name
                if '/./' in name:
                    if _sha(payload) not in _OPAQUE_ALIASES or name != 'package/./dist/index.js':
                        _fail('artifact-path', 'unreviewed npm dot-segment member')
                    aliases[name] = 'package/dist/index.js'
                else:
                    safe_parts(name)
                parts = name.split('/')
                if prefix is None:
                    prefix = parts[0]
                if parts[0] != prefix or len(parts) < 2 or member.size < 0:
                    _fail('artifact-path', 'npm source member lies outside its single package root')
                total += member.size
                if total > MAX_ARCHIVE_BYTES:
                    _fail('artifact-size', 'expanded npm source exceeds existing archive bound')
                stream = archive.extractfile(member)
                if stream is None:
                    _fail('artifact-archive', 'npm regular member cannot be read')
                body = stream.read(member.size + 1)
                if len(body) != member.size:
                    _fail('artifact-archive', 'npm source member is truncated')
                files[name] = body
    except (tarfile.TarError, OSError, EOFError) as exc:
        _fail('artifact-archive', f'invalid original npm source: {exc}')
    for alias, canonical in aliases.items():
        if canonical not in files or files[alias] != files[canonical]:
            _fail('artifact-archive', 'opaque npm alias differs from its canonical regular member')
    regular = set(files) - set(aliases)
    for name in regular:
        parts = safe_parts(name)
        if any('/'.join(parts[:depth]) in regular for depth in range(1, len(parts))):
            _fail('artifact-path', 'npm regular file is also a directory ancestor')
    return files, {name: {'sha256': _sha(raw), 'size': len(raw)} for name, raw in files.items()}, aliases


def source_custody(root, source, expected, *, now=None):
    """Verify original bytes/lock/strong metadata; does not qualify any license."""
    if (not isinstance(source, dict) or set(source) not in ({'url', 'path', 'sha256', 'bytes', 'strong_metadata', 'acquired_at'},
            {'url', 'path', 'sha256', 'bytes', 'strong_metadata', 'acquired_at', 'term_supplement'})
            or not registry_url(source['url']) or type(source['bytes']) is not int or not 0 < source['bytes'] <= MAX_NPM_BYTES
            or not isinstance(expected, list) or not expected
            or any(row.get('resolved') != source['url'] for row in expected)):
        _fail('artifact-npm-origin', 'npm source must match each exact official lock URL')
    try:
        acquired = datetime.fromisoformat(source['acquired_at'].replace('Z', '+00:00'))
        if acquired.tzinfo is None or (now is not None and not timedelta(0) <= now - acquired <= timedelta(hours=72)):
            raise ValueError('outside original 72h acquisition window')
    except (ValueError, TypeError, AttributeError) as exc:
        _fail('artifact-npm-stale', f'original npm acquisition clock is invalid: {exc}')
    payload = read_file(Path(root), source['path'], MAX_NPM_BYTES)
    if len(payload) != source['bytes'] or _sha(payload) != source['sha256']:
        _fail('artifact-hash', 'original npm source bytes changed')
    files, members, aliases = source_members(payload)
    roots = {name.split('/', 1)[0] for name in files}
    if len(roots) != 1:
        _fail('artifact-npm-metadata', 'npm source needs one exact package root')
    archive_root = next(iter(roots))
    package = _json(files.get(archive_root + '/package.json', b'{}'))
    if not isinstance(package.get('name'), str) or not isinstance(package.get('version'), str):
        _fail('artifact-npm-metadata', 'original npm package identity is incomplete')
    # The current finite lock contour has no npm aliases. Do not silently equate
    # a future lock alias with its registry package identity.
    if any((row.get('name'), row.get('version')) != (package['name'], package['version']) for row in expected):
        _fail('artifact-npm-metadata', 'registry package identity differs from exact source lock')
    legacy = False
    for row in expected:
        _integrity(payload, row.get('integrity'), {'sha1', 'sha512'})
        legacy |= row['integrity'].startswith('sha1-')
    proofs = [{'path': source['path'], 'sha256': source['sha256'], 'bytes': len(payload),
               'url': source['url'], 'integrities': sorted({row['integrity'] for row in expected})}]
    bound = len(payload)
    if legacy:
        metadata = source.get('strong_metadata')
        if (not isinstance(metadata, dict) or set(metadata) != {'url', 'path', 'sha256', 'bytes'}
                or type(metadata['bytes']) is not int or not 0 < metadata['bytes'] <= MAX_NPM_BYTES):
            _fail('artifact-npm-integrity', 'legacy SHA1 lock needs independent exact-version official SHA512 metadata')
        expected_url = 'https://registry.npmjs.org/' + quote(package['name'], safe='@') + '/' + quote(package['version'], safe='')
        if metadata['url'] != expected_url:
            _fail('artifact-npm-origin', 'strong integrity metadata is not the exact official package version')
        raw = read_file(Path(root), metadata['path'], MAX_NPM_BYTES)
        if len(raw) != metadata['bytes'] or _sha(raw) != metadata['sha256']:
            _fail('artifact-hash', 'official npm integrity metadata changed')
        value = _json(raw)
        dist = value.get('dist')
        if (value.get('name'), value.get('version')) != (package['name'], package['version']) or not isinstance(dist, dict) or dist.get('tarball') != source['url']:
            _fail('artifact-npm-origin', 'strong integrity metadata belongs to other source bytes')
        _integrity(payload, dist.get('integrity'), {'sha512'})
        proofs.append(dict(metadata))
        bound += len(raw)
    elif source['strong_metadata'] is not None:
        _fail('artifact-npm-origin', 'unneeded extra metadata is outside this closed source proof')
    supplemental = None
    if 'term_supplement' in source:
        from .security_action_supplements import verify
        extra = verify(root, source, payload, files, now=now)
        supplemental = extra['terms']
        proofs.extend(extra['proofs'])
        bound += extra['bound_bytes']
    return {'payload': payload, 'files': files, 'members': members, 'aliases': aliases,
            'package': package, 'archive_root': archive_root, 'proofs': proofs, 'bound_bytes': bound,
            'supplemental_terms': supplemental}


def verify_source(root, source, expected, *, now=None):
    """Qualify every included component's actual complete terms and notices."""
    result = source_custody(root, source, expected, now=now)
    return _qualify_source(result, source, supplemental=result['supplemental_terms'])


def _qualify_source(result, source, *, supplemental=None):
    from .security_license_texts import recognized_license, reviewed_ancillary
    from .security_licenses import ALLOWED, _license_evidence, _select_expression
    files = {name: body for name, body in result['files'].items() if name not in result['aliases']}
    archive_root = result['archive_root']
    metadata = {archive_root: result['package']}
    for name, body in files.items():
        if not name.endswith('/package.json') or name == archive_root + '/package.json':
            continue
        value = _json(body)
        if set(value) <= {'type'} and value.get('type') in {'module', 'commonjs'}:
            continue  # Exact role declaration, retained in the original source object.
        if not all(isinstance(value.get(key), str) and value[key] for key in ('name', 'version', 'license')):
            _fail('license-transitive-coverage', 'nested npm metadata needs an explicit complete component identity/license')
        metadata[str(PurePosixPath(name).parent)] = value
    owned = {name: {} for name in metadata}
    for name, body in files.items():
        owner = max((path for path in metadata if name.startswith(path + '/')), key=len)
        owned[owner][name] = body
    from .security_action_npm_comments import project
    projection = project(source, files)
    result = dict(result, proofs=[*result['proofs'], *projection['proofs']])
    normalized, retained = [], {}
    prefix = 'npm/' + source['sha256'] + '/'
    for parent, package in metadata.items():
        expression = package.get('license')
        interpretation = None
        if parent == archive_root:
            from .security_action_supplier_terms import effective_metadata
            interpretation = effective_metadata(source, package, supplemental, result['proofs'])
            if interpretation is not None:
                expression = interpretation['expression']
        if not isinstance(expression, str) or not expression:
            _fail('license-metadata-missing', 'npm component has no exact SPDX expression')
        evidence_ids = [*ALLOWED, 'X11'] if interpretation is not None else list(ALLOWED)
        chosen, identifiers = _select_expression(expression, evidence_ids)
        for name, body in owned[parent].items():
            for declared in re.findall(rb'(?m)^\s*(?://|/\*+|\*|#)?\s*SPDX-License-Identifier:\s*([^\r\n*]+)', body):
                _, inline_ids = _select_expression(declared.decode('utf-8').strip(), list(ALLOWED))
                if not inline_ids <= identifiers:
                    _fail('license-conflict', 'included source SPDX declaration conflicts with its component metadata')
        terms, notices = [], []
        for name, body in owned[parent].items():
            base = PurePosixPath(name).name.lower()
            is_term = base.startswith(('license', 'licence', 'copying')) or any(x.lower() in {'licenses', 'licences'} for x in PurePosixPath(name).parts)
            is_notice = base.startswith(('notice', 'copyright', 'authors', 'third-party', 'third_party', 'thirdparty'))
            # A README can grant credit only as an independently recognized whole
            # file (closed reviewed hash), never by substring or filename alone.
            if base.startswith('readme') and recognized_license(body.decode('utf-8')) is not None:
                is_term = True
            if not is_term and not is_notice:
                continue
            path = prefix + name
            retained[path] = body
            (terms if is_term else notices).append(path)
            if is_notice and recognized_license(body.decode('utf-8')) is None and reviewed_ancillary(body.decode('utf-8')) is None:
                _fail('license-text-review', 'included npm notice/attribution needs closed complete-file review')
        if supplemental is not None and parent == archive_root:
            if terms or notices:
                _fail('license-obligation-missing', 'cache fallback cannot replace or hide original npm terms/notices')
            for path, body in supplemental:
                retained[path] = body
                terms.append(path)
        for (path, body), proof in zip(projection['terms'], projection['proofs']):
            if proof['path'] in owned[parent]:
                retained[path] = body
                terms.append(path)
        component = {'id': prefix + parent, 'name': package['name'], 'version': package['version'],
                     'source_artifact_sha256': source['sha256'], 'source_url': source['url'],
                     'metadata_path': parent + '/package.json', 'expression': expression, 'requires': [],
                     'files': [{'path': name, 'sha256': _sha(retained[name]), 'bytes': len(retained[name])} for name in terms + notices],
                     'license_paths': terms, 'notice_paths': notices}
        if interpretation is not None:
            component['source_metadata_interpretation'] = dict(interpretation,
                original_metadata_sha256=_sha(files[parent + '/package.json']))
        _license_evidence({name: retained[name] for name in terms + notices}, component, identifiers, chosen)
        if not terms:
            _fail('license-obligation-missing', 'npm component cannot inherit another component root license')
        normalized.append(component)
    return {**result, 'files': retained, 'components': normalized}
