"""Closed Packagist/GitHub source-archive consistency; no resolver or execution.

Version identity comes from saved official release metadata when composer.json
omits it. ZIP comments and hashes are consistency, never publisher authority.
"""
import hashlib
import io
import re
import zipfile

_NAME = re.compile(r'[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?/[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?\Z')
_VERSION = re.compile(r'v?([0-9]+(?:\.[0-9]+){0,3})\Z')
_GIT = r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'
_ARCHIVE = re.compile(r'https://api\.github\.com/repos/(' + _GIT + r')/zipball/([0-9a-f]{40})\Z')
_CODELOAD = re.compile(r'https://codeload\.github\.com/(' + _GIT + r')/legacy\.zip/([0-9a-f]{40})\Z')


def error(code, message):
    from .security_artifacts import ArtifactError
    return ArtifactError(code, message)


def version(value):
    if type(value) is not str or len(value) > 128 or not _VERSION.fullmatch(value):
        raise error('artifact-identity', 'Packagist requires an exact stable numeric version')
    parts = tuple(int(p) for p in _VERSION.fullmatch(value)[1].split('.'))
    return parts + (0,) * (4 - len(parts))


def key(name, value):
    if type(name) is not str or len(name) > 200 or not _NAME.fullmatch(name):
        raise error('artifact-identity', 'Packagist requires a canonical vendor/package name')
    return 'Packagist', name, version(value)


def index_url(name, value):
    key(name, value)
    return 'https://packagist.org/packages/' + name + '.json'


def allowed_url(url):
    return (type(url) is str and len(url) <= 4096 and not any(p in {'.', '..'} for p in url.split('/')[3:]) and (
        re.fullmatch(r'https://packagist\.org/packages/(' + _NAME.pattern[:-2] + r')\.json', url) is not None
        or _ARCHIVE.fullmatch(url) is not None or _CODELOAD.fullmatch(url) is not None))


def redirect_allowed(old, new):
    a, b = _ARCHIVE.fullmatch(old) or _CODELOAD.fullmatch(old), _CODELOAD.fullmatch(new)
    return bool(old == new and allowed_url(new) or a and b and a.groups() == b.groups())


def select_release(index, dep):
    from .security_artifacts import ArtifactError
    wanted = key(dep.get('name'), dep.get('version'))
    package = index.get('package')
    if type(package) is not dict or package.get('name') != dep['name'] or type(package.get('versions')) is not dict:
        raise error('artifact-origin', 'official Packagist package identity is missing')
    matches = []
    for label, row in package['versions'].items():
        if type(row) is not dict or type(label) is not str or not _VERSION.fullmatch(label):
            continue
        try:
            same = key(row.get('name'), row.get('version')) == wanted
        except ArtifactError:
            same = False
        if same:
            if version(label) != wanted[2]:
                raise error('artifact-origin', 'Packagist version key and release disagree')
            matches.append(row)
    if len(matches) != 1:
        raise error('artifact-origin', 'Packagist release is absent or ambiguous')
    row = matches[0]
    source, dist = row.get('source'), row.get('dist')
    if type(source) is not dict or type(dist) is not dict:
        raise error('artifact-origin', 'Packagist requires source and distribution metadata')
    match = _ARCHIVE.fullmatch(dist.get('url', '')) if type(dist.get('url')) is str else None
    if (not match or not allowed_url(dist['url']) or dist.get('type') != 'zip' or source.get('type') != 'git'
            or source.get('url') != 'https://github.com/' + match[1] + '.git'
            or source.get('reference') != match[2] or dist.get('reference') != match[2]
            or type(dist.get('shasum', '')) is not str
            or dist.get('shasum', '') and not re.fullmatch('[0-9a-f]{40}', dist['shasum'])):
        raise error('artifact-origin', 'Packagist source/dist need one fixed GitHub full commit')
    return row


def filename(row):
    return row['name'].replace('/', '-') + '-' + row['dist']['reference'] + '.zip'


def verify(record, payload, index):
    from .security_artifacts import archive_files
    row = select_release(index, record)
    if (record['origin'].get('index_url') != index_url(record['name'], record['version'])
            or record['origin'].get('artifact_url') != row['dist']['url']
            or record.get('filename') != filename(row)):
        raise error('artifact-origin', 'saved Packagist URLs or filename differ from selected release')
    archive_files(payload, record['filename'])  # Enforce original full ZIP/member/byte guards before opening metadata.
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        roots = {member.filename.split('/')[0] for member in archive.infolist()}
        if len(roots) != 1:
            raise error('artifact-origin', 'GitHub source archive requires one root directory')
        if archive.comment != row['source']['reference'].encode('ascii'):
            raise error('artifact-origin', 'GitHub archive comment differs from registry source commit')
    if row['dist'].get('shasum') and hashlib.sha1(payload, usedforsecurity=False).hexdigest() != row['dist']['shasum']:
        raise error('artifact-origin', 'archive differs from supplied Packagist distribution SHA1')
    return {'version_source': 'packagist-registry', 'name': row['name'], 'version': row['version'],
            'source_commit': row['source']['reference'], 'composer_metadata_sha256': metadata_digest(row)}


def expression(value):
    if type(value) is str and value and len(value) <= 1024:
        return value
    if type(value) is list and 1 <= len(value) <= 32 and all(type(v) is str and v and len(v) <= 128 for v in value):
        return ' OR '.join('(' + v + ')' for v in value)
    raise error('license-conflict', 'Composer requires explicit SPDX license metadata')


def metadata_digest(value):
    import json
    license_value = value.get('license')
    license_value = [license_value] if type(license_value) is str else license_value
    body = {'license': license_value, **{k: value.get(k, {}) for k in ('require', 'conflict', 'provide', 'replace')}}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def metadata(files, origin):
    from .security_data import _json
    if type(origin) is not dict or origin.get('version_source') != 'packagist-registry':
        raise error('artifact-origin', 'Composer metadata requires verified saved registry origin')
    paths = [p for p in files if p.endswith('/composer.json') and len(p.split('/')) == 2]
    if len(paths) != 1:
        raise error('artifact-metadata', 'archive requires exactly one root composer.json')
    path = paths[0]
    data = _json(files[path])
    if key(data.get('name'), data.get('version', origin['version'])) != key(origin['name'], origin['version']):
        raise error('artifact-identity', 'Composer name/version differs from verified registry release')
    license_value = data.get('license')
    if metadata_digest(data) != origin.get('composer_metadata_sha256'):
        raise error('license-conflict', 'Composer and registry license metadata disagree')
    requirements = data.get('require', {})
    if (type(requirements) is not dict or len(requirements) > 512
            or any(type(k) is not str or type(v) is not str or len(v) > 1024 for k, v in requirements.items())
            ):
        raise error('artifact-metadata', 'Composer and registry dependency metadata disagree')
    conflicts = data.get('conflict', {})
    if (type(conflicts) is not dict or len(conflicts) > 512
            or any(type(k) is not str or type(v) is not str or len(v) > 1024 for k, v in conflicts.items())):
        raise error('artifact-metadata', 'Composer conflict metadata is malformed')
    return {'name': data['name'], 'version': data.get('version', origin['version']),
            'version_source': 'composer.json' if 'version' in data else 'packagist-registry',
            'expression': expression(license_value), 'license_paths': [], 'requires': list(requirements.items()),
            'metadata_path': path, 'root': path.rsplit('/', 1)[0], 'conflicts': conflicts,
            'requires_external': bool(data.get('provide') or data.get('replace'))}


def license_members(files, metadata):
    """License.php classes are program source, not license text obligations."""
    root = metadata['root'] + '/'
    return {p: b for p, b in files.items() if p.startswith(root)
            and re.match(r'(?:licen[cs]e|copying|notice)', p.rsplit('/', 1)[-1], re.I)
            and not (p.lower().endswith('.php') and b.lstrip().startswith(b'<?php'))}


def satisfies(value, constraint):
    """Conservative stable Composer subset; unsupported resolution never succeeds."""
    target = version(value)
    if type(constraint) is not str or len(constraint) > 1024:
        raise error('license-transitive-coverage', 'Composer constraint is not bounded text')
    alternatives = constraint.split('||')
    if len(alternatives) > 32:
        raise error('license-transitive-coverage', 'Composer alternatives exceed bound')
    answers = []
    for branch in alternatives:
        tokens = branch.replace(',', ' ').split()
        if not tokens or len(tokens) > 32:
            raise error('license-transitive-coverage', 'Composer constraint needs a supported resolver')
        comparisons = []
        for token in tokens:
            if token == '*':
                comparisons.append(True)
                continue
            match = re.fullmatch(r'(\^|~|>=|<=|!=|==|=|>|<)?(v?[0-9]+(?:\.[0-9]+){0,3})', token)
            if not match:
                raise error('license-transitive-coverage', 'Composer constraint needs a supported resolver')
            op, text = match.groups()
            lower = version(text)
            if op in {'^', '~'}:
                precision = len(text.removeprefix('v').split('.'))
                position = (next((i for i in range(precision) if lower[i]), precision - 1)
                            if op == '^' else 1 if precision >= 3 else 0)
                upper = lower[:position] + (lower[position] + 1,) + (0,) * (3 - position)
                comparisons.append(lower <= target < upper)
            else:
                comparisons.append({'==': target == lower, '=': target == lower, None: target == lower,
                                    '!=': target != lower, '>=': target >= lower, '<=': target <= lower,
                                    '>': target > lower, '<': target < lower}[op])
        answers.append(all(comparisons))
    return any(answers)


def closure(metadata, dep, dependencies, environment):
    if metadata.get('requires_external'):
        raise error('license-transitive-coverage', 'Composer virtual providers/replacements need qualified coverage')
    for name, constraints in metadata['requires']:
        if name in {'php', 'composer', 'composer-plugin-api', 'composer-runtime-api'} or re.fullmatch(r'(?:ext|lib)-[a-z0-9][a-z0-9_-]*', name):
            platform = environment.get('composer_platform', {})
            observed = platform.get(name) if type(platform) is dict else None
            if observed is True and constraints == '*':
                continue
            if type(observed) is not str or not satisfies(observed, constraints):
                raise error('license-transitive-coverage', 'Composer target platform requirement remains unproved')
            continue
        key(name, '1.0.0')
        matches = [d for d in dependencies if d.get('ecosystem') == 'Packagist' and d.get('name') == name
                   and d.get('delivery_context') == dep.get('delivery_context')
                   and d.get('manifest') == dep.get('manifest')]
        versions = {d.get('version') for d in matches}
        if len(versions) != 1 or not satisfies(next(iter(versions)), constraints):
            raise error('license-transitive-coverage', 'Composer requires one exact covered transitive version')

    for name, constraints in metadata.get('conflicts', {}).items():
        if '/' not in name:
            raise error('license-transitive-coverage', 'Composer platform conflicts need qualified target coverage')
        key(name, '1.0.0')
        matches = [d for d in dependencies if d.get('ecosystem') == 'Packagist' and d.get('name') == name
                   and d.get('delivery_context') == dep.get('delivery_context')
                   and d.get('manifest') == dep.get('manifest')]
        if any(satisfies(d.get('version'), constraints) for d in matches):
            raise error('license-transitive-coverage', 'Covered Composer version conflicts with artifact requirements')
