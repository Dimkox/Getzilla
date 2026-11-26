"""Exact upstream release metadata for lockfile OSV fixes. No installation or execution."""
import re
from urllib.error import HTTPError
from urllib.parse import unquote, urlsplit

from . import security_packagist as composer
from .security_artifacts import (ArtifactError, MAX_INDEX_BYTES, _digest, allowed_download_url,
                                 package_key, pypi_index_url)
from .security_data import _json
from .security_license_acquisition import bounded_default
from .security_python_target import _filename


def _wheels(index, name, version):
    wanted = package_key('PyPI', name, version)
    info = index['info']
    if package_key('PyPI', info['name'], info['version']) != wanted or not isinstance(index['urls'], list):
        raise ArtifactError('artifact-identity', 'PyPI release identity or file list is invalid')
    urls = []
    for row in index['urls']:
        if type(row['yanked']) is not bool or row['packagetype'] not in {'bdist_wheel', 'sdist'}:
            raise ArtifactError('artifact-origin', 'invalid PyPI file type or withdrawal status')
        if row['yanked'] or row['packagetype'] == 'sdist':
            continue
        filename, url = row['filename'], row['url']
        wheel_name, wheel_version, _ = _filename(filename)
        if package_key('PyPI', wheel_name, wheel_version) != wanted:
            raise ArtifactError('artifact-identity', 'wheel filename differs from requested package or version')
        _digest(row['digests']['sha256'], 'wheel')
        if (not allowed_download_url(url) or urlsplit(url).netloc != 'files.pythonhosted.org'
                or unquote(urlsplit(url).path.rsplit('/', 1)[-1]) != filename):
            raise ArtifactError('artifact-origin', 'wheel location differs from the registry filename')
        urls.append(url)
    return tuple(sorted(urls))


def _composer_dist(index, name, version):
    package = index['package']
    if package['name'] != name or not isinstance(package['versions'], dict):
        raise ArtifactError('artifact-identity', 'invalid Packagist package or release index')
    wanted = composer.key(name, version)
    matches = []
    for label, row in package['versions'].items():
        try:
            numeric = composer.version(label)
        except ArtifactError:
            continue  # Development branches and prereleases cannot match this exact stable numeric version.
        if numeric == wanted[2]:
            if composer.key(row['name'], row['version']) != wanted:
                raise ArtifactError('artifact-identity', 'Packagist release key and metadata disagree')
            matches.append(row)
    if not matches:
        return ()
    if len(matches) != 1:
        raise ArtifactError('artifact-identity', 'ambiguous Packagist release')
    row = matches[0]
    if row.get('dist') is None:
        source = row['source']
        if (source['type'] == 'git' and re.fullmatch(r'[0-9a-f]{40}', source['reference'])
                and urlsplit(source['url']).scheme == 'https' and urlsplit(source['url']).hostname):
            return ()
        raise ArtifactError('artifact-origin', 'unqualified source-only Packagist release')
    selected = composer.select_release(index, {'name': name, 'version': version})
    return (selected['dist']['url'],)


def published_artifacts(ecosystem: str, name: str, version: str) -> tuple[str, ...]:
    """Return published distribution URLs. An unqualified response raises ArtifactError."""
    if ecosystem in {'npm', 'crates.io'}:
        from .osv_registry_releases import registry_artifacts
        return registry_artifacts(ecosystem, name, version)
    if ecosystem == 'PyPI':
        url, select = pypi_index_url(name, version), _wheels
    elif ecosystem == 'Packagist':
        url, select = composer.index_url(name, version), _composer_dist
    else:
        raise ArtifactError('artifact-origin', f'published artifact coverage unavailable for {ecosystem}')
    try:
        return select(_json(bounded_default(url, maximum=MAX_INDEX_BYTES)), name, version)
    except ArtifactError as exc:
        cause = exc.__cause__
        if ecosystem == 'PyPI' and isinstance(cause, HTTPError) and cause.code == 404 and cause.url == url:
            return ()
        raise
    except (KeyError, ValueError, TypeError) as exc:
        raise ArtifactError('artifact-origin', f'invalid {ecosystem} release metadata') from exc
