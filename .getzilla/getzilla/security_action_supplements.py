"""Exact original publisher source terms for immutable published npm objects.

The research packet is not runtime authority. Cold preparation fetches these
fixed official objects; every use rechecks their bytes, source identity and all
published package members. No newer branch, generic MIT text or inferred holder.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
from pathlib import Path

from .security_artifacts import ArtifactError, read_file
from .security_action_supplier_terms import PROFILES as SUPPLIER_PROFILES

PROFILES = {
    '19347cbcba429e9f240427ce4e5998efe30a47cb9131b5673fc2f0441f7f4f57': {
        'id': 'xml-naming-0.1.0-source-mit-v1', 'name': 'xml-naming', 'version': '0.1.0',
        'npm_url': 'https://registry.npmjs.org/xml-naming/-/xml-naming-0.1.0.tgz',
        'registry_url': 'https://registry.npmjs.org/xml-naming/0.1.0', 'git_head': None,
        'source_identity_basis': 'all-published-members-at-fixed-source-commit',
        'source_commit': 'c0afc395948730bed124859d7fc7cccabe0aac8a',
        'source_url': 'https://codeload.github.com/NaturalIntelligence/xml-naming/tar.gz/c0afc395948730bed124859d7fc7cccabe0aac8a',
        'source_sha256': '1c845fcee71fd7d19f6c8af4b1df18db5441fe36c9fa702255c1202056d57d47',
        'package_prefix': '', 'published_members': 4, 'term_path': 'LICENSE',
        'term_sha256': '8e75fc0e776c62ccadb8178ece8d3daa9ba7601fb0a49b2dfb0ea9a7a5c0aa07', 'term_bytes': 1077,
    },
    '9c864305f59a18ece5505610859e3308bd0c2250562f1d1f9ce9a8ea3be3518d': {
        'id': 'nodable-entities-2.1.0-source-mit-v1', 'name': '@nodable/entities', 'version': '2.1.0',
        'npm_url': 'https://registry.npmjs.org/@nodable/entities/-/entities-2.1.0.tgz',
        'registry_url': 'https://registry.npmjs.org/@nodable%2Fentities/2.1.0',
        'git_head': 'f1c61a65e7b967c17b13822ef71e91bd25f17ce2',
        'source_url': 'https://codeload.github.com/nodable/val-parsers/tar.gz/f1c61a65e7b967c17b13822ef71e91bd25f17ce2',
        'source_sha256': 'bf8a0fc0f6a48c6ff403118347c2a334a62e7b1c497cf789dd962f3fd579468b',
        'package_prefix': 'Entity', 'published_members': 8, 'term_path': 'LICENSE',
        'term_sha256': '750cb3fb6362804957ef52caaf9b5c824015be44d494637330d7cd8834d31d40', 'term_bytes': 1064,
    },
    'aa86ce17d23103e701f3c21cda5bbf8a931d4ca316cefa918ae893bb5b63dcab': {
        'id': 'nodable-entities-2.2.0-source-mit-v1', 'name': '@nodable/entities', 'version': '2.2.0',
        'npm_url': 'https://registry.npmjs.org/@nodable/entities/-/entities-2.2.0.tgz',
        'registry_url': 'https://registry.npmjs.org/@nodable%2Fentities/2.2.0',
        'git_head': '1a2c08a483b5b6428f1b3d01974875c97f3b3953',
        'source_url': 'https://codeload.github.com/nodable/val-parsers/tar.gz/1a2c08a483b5b6428f1b3d01974875c97f3b3953',
        'source_sha256': '56cd32a67b83f8b44ab50ad03c91a79c422ac2900bff0c220760c39e0470350b',
        'package_prefix': 'Entity', 'published_members': 8, 'term_path': 'LICENSE',
        'term_sha256': '750cb3fb6362804957ef52caaf9b5c824015be44d494637330d7cd8834d31d40', 'term_bytes': 1064,
    },
}

PROFILES.update(SUPPLIER_PROFILES)


def profile_for(source):
    return PROFILES.get(source.get('sha256')) if isinstance(source, dict) else None


def admitted_urls(expected):
    """Only extra origins tied to exact expected npm names/version/URLs."""
    result = set()
    for profile in PROFILES.values():
        rows = expected.get(profile['npm_url'], [])
        if rows and all((row['name'], row['version']) == (profile['name'], profile['version']) for row in rows):
            result.update(profile_urls(profile))
    return result


def profile_urls(profile):
    return [profile['registry_url'], profile['source_url']] + ([profile['copyright_url']] if 'copyright_url' in profile else [])


def response_descriptors(source):
    supplement = source.get('term_supplement')
    return ([supplement['registry'], supplement['archive']] + ([supplement['copyright']] if 'copyright' in supplement else [])) if isinstance(supplement, dict) else []


def _fail(code, message):
    raise ArtifactError(code, message)


def verify(root, source, payload, npm_files, *, now=None):
    from .security_action_npm import _json, _integrity, source_members, MAX_NPM_BYTES
    from .security_license_texts import recognized_license
    profile = profile_for(source)
    value = source.get('term_supplement')
    if (profile is None or not isinstance(value, dict) or set(value) != ({'profile', 'registry', 'archive', 'copyright'} if profile and 'copyright_url' in profile else {'profile', 'registry', 'archive'})
            or value['profile'] != profile['id'] or source['url'] != profile['npm_url']):
        _fail('license-obligation-missing', 'no closed exact publisher source term profile')
    raw, proofs = {}, []
    for kind, url in [('registry', profile['registry_url']), ('archive', profile['source_url'])] + ([('copyright', profile['copyright_url'])] if 'copyright_url' in profile else []):
        descriptor = value[kind]
        if (not isinstance(descriptor, dict) or set(descriptor) != {'url', 'path', 'sha256', 'bytes', 'acquired_at'}
                or descriptor['url'] != url or type(descriptor['bytes']) is not int or not 0 < descriptor['bytes'] <= MAX_NPM_BYTES):
            _fail('artifact-npm-origin', 'supplement is not its fixed exact official source')
        body = read_file(Path(root), descriptor['path'], MAX_NPM_BYTES)
        if len(body) != descriptor['bytes'] or hashlib.sha256(body).hexdigest() != descriptor['sha256']:
            _fail('artifact-hash', 'original supplemental source bytes changed')
        try:
            acquired = datetime.fromisoformat(descriptor['acquired_at'].replace('Z', '+00:00'))
            original = datetime.fromisoformat(source['acquired_at'].replace('Z', '+00:00'))
            if acquired.tzinfo is None or original > acquired or (now is not None and not timedelta(0) <= now - acquired <= timedelta(hours=72)):
                raise ValueError('outside original source acquisition window')
        except (ValueError, TypeError, AttributeError) as exc:
            _fail('artifact-npm-stale', f'supplemental source clock is invalid: {exc}')
        raw[kind] = body
        proofs.append(dict(descriptor))
    metadata = _json(raw['registry'])
    dist = metadata.get('dist')
    if ((metadata.get('name'), metadata.get('version')) != (profile['name'], profile['version'])
            or (profile['git_head'] is not None and metadata.get('gitHead') != profile['git_head']) or not isinstance(dist, dict)
            or dist.get('tarball') != source['url']):
        _fail('artifact-npm-origin', 'supplemental registry identity/gitHead differs')
    _integrity(payload, dist.get('integrity'), {'sha512'})
    if hashlib.sha256(raw['archive']).hexdigest() != profile['source_sha256']:
        _fail('artifact-hash', 'immutable supplemental archive identity differs')
    upstream, _, aliases = source_members(raw['archive'])
    if aliases:
        _fail('artifact-path', 'supplemental source aliases are unsupported')
    roots = {name.split('/', 1)[0] for name in upstream}
    if len(roots) != 1 or len(npm_files) != profile['published_members']:
        _fail('license-transitive-coverage', 'published/source member inventory differs')
    prefix = next(iter(roots))
    matches = {}
    for name, body in npm_files.items():
        relative = name.split('/', 1)[1]
        source_path = prefix + '/' + (profile['package_prefix'] + '/' if profile['package_prefix'] else '') + relative
        if upstream.get(source_path) != body:
            _fail('license-transitive-coverage', 'published npm member differs from exact supplemental source')
        matches[name] = {'source_path': source_path, 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}
    if 'copyright_url' in profile:
        from .security_action_supplier_terms import project_dep5
        term = project_dep5(raw['copyright'], profile)
        term_path = 'debian/copyright#upstream-Files-star-and-complete-MIT-paragraph'
    else:
        term_path = prefix + '/' + profile['term_path']
        term = upstream.get(term_path)
        if (term is None or len(term) != profile['term_bytes'] or hashlib.sha256(term).hexdigest() != profile['term_sha256']
                or recognized_license(term.decode('utf-8')) != 'MIT'):
            _fail('license-text-review', 'complete original publisher MIT term is missing or modified')
    derived = 'derived/npm/' + source['sha256'] + ('/supplier/LICENSE' if 'copyright_url' in profile else '/publisher/LICENSE')
    proofs.append({'path': term_path, 'sha256': profile['term_sha256'], 'bytes': len(term),
        'container_kind': 'supplier-dep5-upstream-grant' if 'copyright_url' in profile else 'supplemental-source-archive-member', 'artifact_path': value.get('copyright', value['archive'])['path'],
        'artifact_sha256': value.get('copyright', value['archive'])['sha256'], 'derived_path': derived,
        'published_member_matches': matches, 'source_assurance': 'exact-published-member-source-match',
        'source_identity_basis': profile.get('source_identity_basis', 'registry-gitHead-and-all-published-members'),
        'registry_gitHead': profile['git_head'], 'source_commit': profile.get('source_commit', profile['git_head']),
        'physical_bytes': 0,
        **({'supplier_version': profile['supplier_version'], 'source_archive': dict(value['archive']),
            'grant_scope': 'upstream-Files:*; Debian packaging excluded'} if 'copyright_url' in profile else {})})
    return {'terms': [(derived, term)], 'proofs': proofs,
            'bound_bytes': sum(len(body) for body in raw.values())}


def source_receipts(source):
    """All original HTTP objects for source accounting, with identical reuse once."""
    rows = [{key: source[key] for key in ('url', 'path', 'sha256', 'bytes', 'acquired_at')}]
    if source['strong_metadata'] is not None:
        rows.append(dict(source['strong_metadata'], acquired_at=source['acquired_at']))
    rows.extend(response_descriptors(source))
    result, seen = [], {}
    for row in rows:
        identity = (row['path'], row['sha256'], row['bytes'])
        if row['url'] in seen:
            if seen[row['url']] != identity:
                _fail('artifact-npm-origin', 'one source URL has conflicting original cached responses')
            continue
        seen[row['url']] = identity
        result.append(row)
    return result
