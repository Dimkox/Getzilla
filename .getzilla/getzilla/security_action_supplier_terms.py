"""Two exact Debian upstream archives and complete upstream DEP5 projections.

Both archives are byte-identical to their npm objects, including every published
metadata, prose and executable member. Debian packaging changes are not used.
The original complete copyright container remains independent custody evidence.
Recognition and use permission remain duties of the ordinary license evaluator.
"""
from __future__ import annotations

import hashlib

from .security_artifacts import ArtifactError

PROFILES = {}
for _name, _version, _debian, _digest, _members, _copyright, _term, _size in (
    ('buffers', '0.1.1', '0.1.1-2', 'f8de49c60e467005182d9687b5d87775bbcec6385ac63220b7741327441deb6d', 6,
     '97423a03bc4476a98de2bf3fa7efff55b3f338da76a7b3cbf747b4dc6f52a056',
     '3325702108f9d65db464595854e509f2a1be9ffdc1ae82a7e99fa63c92c404c9', 1096),
    ('chainsaw', '0.1.0', '0.1.0-1', '01586a6aa1d1174ae07aff69822d01e0704fe30f23ac22221c9b804bab976cfb', 7,
     '50052e6460b658e38cb910e62ea03580f60627b6b4909142eedff10ad7132987',
     '8b7975e73de4ffd999102c9d599070b02e8b3146f14184ab66588fb27c660bd8', 1312),
):
    PROFILES[_digest] = {
        'id': f'{_name}-{_version}-debian-upstream-terms-v1', 'name': _name, 'version': _version,
        'npm_url': f'https://registry.npmjs.org/{_name}/-/{_name}-{_version}.tgz',
        'registry_url': f'https://registry.npmjs.org/{_name}/{_version}', 'git_head': None,
        'source_url': f'https://archive.debian.org/debian/pool/main/n/node-{_name}/node-{_name}_{_version}.orig.tar.gz',
        'source_sha256': _digest, 'package_prefix': '', 'published_members': _members,
        'copyright_url': f'https://sources.debian.org/data/main/n/node-{_name}/{_debian}/debian/copyright',
        'copyright_sha256': _copyright, 'supplier_version': _debian,
        'term_sha256': _term, 'term_bytes': _size,
        'source_identity_basis': 'supplier-upstream-grant+all-published-members-at-fixed-version',
    }


def project_dep5(raw, profile):
    """Decode a pinned complete DEP5; retain upstream notice and every condition."""
    if hashlib.sha256(raw).hexdigest() != profile['copyright_sha256']:
        raise ArtifactError('artifact-hash', 'original fixed supplier copyright differs')
    try:
        text = raw.decode('utf-8')
        if text.count('Files: *\n') != 1 or text.count('\nLicense: MIT\n ') != 1:
            raise ValueError('ambiguous upstream scope or complete grant')
        upstream = text.split('Files: *\n', 1)[1].split('\n\n', 1)[0]
        if upstream.count('Copyright: ') != 1 or '\nLicense: MIT' not in upstream:
            raise ValueError('upstream copyright/grant association is missing')
        notice = upstream.split('Copyright: ', 1)[1].split('\n', 1)[0]
        body = text.rsplit('\nLicense: MIT\n', 1)[1]
        lines = body.splitlines()
        if not lines or any(not line.startswith(' ') for line in lines):
            raise ValueError('invalid DEP5 continuation')
        decoded = '\n'.join('' if line == ' .' else line[1:] for line in lines) + '\n'
        term = ('Copyright ' + notice + '\n\n' + decoded).encode('utf-8')
        if len(term) != profile['term_bytes'] or hashlib.sha256(term).hexdigest() != profile['term_sha256']:
            raise ValueError('complete upstream grant or attribution differs')
        return term
    except (UnicodeError, ValueError, IndexError, KeyError) as exc:
        raise ArtifactError('license-text-review', f'fixed supplier DEP5 projection refused: {exc}') from exc


def effective_metadata(source, package, terms, proofs):
    """Interpret only two original legacy declarations after supplier custody.

This establishes evidence identity, not permission to use X11 or any other ID.
The original package object and every archive byte remain unchanged.
    """
    profile = PROFILES.get(source.get('sha256'))
    if profile is None:
        return None
    value = source.get('term_supplement')
    expected = 'MIT' if profile['name'] == 'buffers' else 'X11'
    declared = None if profile['name'] == 'buffers' else 'MIT/X11'
    path = 'derived/npm/' + source['sha256'] + '/supplier/LICENSE'
    if (not isinstance(value, dict) or value.get('profile') != profile['id']
            or source.get('url') != profile['npm_url']
            or (package.get('name'), package.get('version')) != (profile['name'], profile['version'])
            or ('license' in package if declared is None else package.get('license') != declared)
            or not isinstance(terms, list) or len(terms) != 1 or terms[0][0] != path
            or hashlib.sha256(terms[0][1]).hexdigest() != profile['term_sha256']):
        raise ArtifactError('license-metadata-missing', 'fixed supplier legacy metadata interpretation differs')
    for key, url, digest in (('archive', profile['source_url'], profile['source_sha256']),
                             ('copyright', profile['copyright_url'], profile['copyright_sha256'])):
        descriptor = value.get(key)
        if not isinstance(descriptor, dict) or descriptor.get('url') != url or descriptor.get('sha256') != digest:
            raise ArtifactError('license-obligation-missing', 'legacy metadata lacks exact original supplier custody')
    matching = [row for row in proofs if row.get('container_kind') == 'supplier-dep5-upstream-grant'
                and row.get('sha256') == profile['term_sha256'] and row.get('derived_path') == path
                and row.get('artifact_sha256') == profile['copyright_sha256']
                and row.get('source_identity_basis') == profile['source_identity_basis']
                and row.get('supplier_version') == profile['supplier_version']
                and len(row.get('published_member_matches', {})) == profile['published_members']]
    if len(matching) != 1:
        raise ArtifactError('license-obligation-missing', 'legacy metadata requires independently checked full supplier proof')
    return {'expression': expected, 'declared_license_present': 'license' in package,
            'declared_expression': package.get('license'), 'profile': profile['id'],
            'source_identity_basis': profile['source_identity_basis'], 'complete_term_sha256': profile['term_sha256']}
