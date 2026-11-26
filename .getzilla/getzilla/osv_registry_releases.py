"""Queries to official package registries used for OSV fix publication evidence."""
import re
import time
from http.client import HTTPException
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener

from .latest_releases import MAX_METADATA_BYTES, npm_release
from .security_action_npm_fetch import _NoRedirect
from .security_artifacts import ArtifactError, _digest, _semver_key, package_key
from .security_artifacts import VulnerabilityError as VersionError
from .security_data import _json


class _NotPublished(Exception):
    """An exact metadata URL returned 404."""


def _metadata(url):
    if urlsplit(url).netloc not in {'registry.npmjs.org', 'crates.io'} or urlsplit(url).scheme != 'https':
        raise ArtifactError('artifact-origin', 'unexpected registry origin')
    request = Request(url, headers={'User-Agent': 'Getzilla release lookup', 'Accept-Encoding': 'identity'})
    deadline = time.monotonic() + 30
    try:
        with build_opener(_NoRedirect()).open(request, timeout=10) as response:
            if (response.status != 200 or response.geturl() != url
                    or response.headers.get('Content-Encoding', 'identity') != 'identity'):
                raise ArtifactError('artifact-origin', 'unexpected registry response')
            body = bytearray()
            while len(body) <= MAX_METADATA_BYTES and time.monotonic() < deadline:
                chunk = response.read1(min(65536, MAX_METADATA_BYTES - len(body) + 1))
                if not chunk:
                    return bytes(body)
                body.extend(chunk)
            raise ArtifactError('artifact-fetch', 'registry response exceeded its time or byte limit')
    except HTTPError as error:
        error.close()
        if error.code == 404 and error.url == url:
            raise _NotPublished from error
        raise ArtifactError('artifact-fetch', f'registry returned HTTP {error.code}') from error
    except (OSError, HTTPException) as error:
        raise ArtifactError('artifact-fetch', 'registry request failed') from error


def registry_artifacts(ecosystem, name, version):
    try:
        if ecosystem == 'npm':
            package_key('npm', name, version)
            if any(segment in {'.', '..', ''} for segment in name.split('/')):
                raise ArtifactError('artifact-identity', 'invalid npm name')
            release = npm_release(name, _metadata, version=version)
            basename = name.rsplit('/', 1)[-1]
            if release.url != f'https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz':
                raise ArtifactError('artifact-origin', 'npm tarball differs from expected release URL')
            return (release.url,)
        if ecosystem != 'crates.io' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', name):
            raise ArtifactError('artifact-identity', 'invalid crates.io lookup')
        _semver_key(version)
        path = f'/api/v1/crates/{name}/{quote(version, safe="")}'
        row = _json(_metadata('https://crates.io' + path))['version']
        if row['crate'] != name or row['num'] != version or type(row['yanked']) is not bool:
            raise ArtifactError('artifact-identity', 'crates.io returned an unqualified release')
        if row['yanked']:
            return ()
        if row['dl_path'] != f'/api/v1/crates/{name}/{version}/download':
            raise ArtifactError('artifact-origin', 'crate download path differs from requested release')
        _digest(row['checksum'], 'crate')
        return ('https://crates.io' + row['dl_path'],)
    except _NotPublished:
        return ()
    except ArtifactError:
        raise
    except (ValueError, VersionError, TypeError, KeyError, AttributeError) as error:
        raise ArtifactError('artifact-origin', 'invalid registry release metadata') from error
