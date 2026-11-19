"""Bounded official release transport and pinned executable contract.

Updater operations and verification share these exact objects. No installation
or orchestration runs here; host, redirect, byte and deadline rules are unchanged.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
import tempfile
import hashlib
import os
import platform
from pathlib import Path
import re
import sys
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError
import zlib


OPENGREP_VERSION = '1.30.1'


OPENGREP_DOWNLOAD = 'https://github.com/opengrep/opengrep/releases/download/v{version}/{asset}'


OPENGREP_ASSETS = {
    ('linux', 'x86_64'): ('opengrep_manylinux_x86', 'd3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4'),
    ('linux', 'aarch64'): ('opengrep_manylinux_aarch64', 'a730f6fdce1e978ea29e610a2e0503bfe1ec31fce08979a9a84e3699f03e16ee'),
    ('darwin', 'arm64'): ('opengrep_osx_arm64', '7b788794e111ce3fb83f0aa52c100a3b85d37d8b59482262109031f50d4a8d91'),
    ('darwin', 'x86_64'): ('opengrep_osx_x86', 'a8c6d5f51bb38253b48e9a80fca63684aa2a0f9abfeacea27b8d8b5778476bae'),
    ('windows', 'amd64'): ('opengrep_windows_x86.exe', 'd3a45326ff63cabe90d94ebc679fcd4302440178a0e5bf0248a6f7b610db3b53'),
}


def home_dir() -> Path:
    return Path(os.environ.get('GETZILLA_STATE_HOME') or Path.home() / '.getzilla')


_RELEASE_HOSTS = {'api.github.com', 'github.com', 'nodejs.org', 'www.python.org', 'getcomposer.org',
                  'pypi.org', 'files.pythonhosted.org', 'registry.npmjs.org', 'www.php.net', 'downloads.php.net',
                  'git-scm.com', 'www.kernel.org', 'release-assets.githubusercontent.com', 'downloads.claude.ai'}


def _release_origin(url):
    origin = urllib.parse.urlsplit(url)
    if origin.scheme != 'https' or origin.netloc not in _RELEASE_HOSTS or origin.fragment:
        raise ValueError('release redirect leaves official public origins')
    return origin


class _ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Check before the stdlib can send the redirected request.
        _release_origin(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_RELEASE_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _ReleaseRedirect())


def _release_refusal(error, origin):
    values = {}
    get_all = getattr(error.headers, 'get_all', None)
    for header, field in (('X-RateLimit-Remaining', 'remaining'), ('X-RateLimit-Reset', 'reset'),
                          ('Retry-After', 'retry_after')):
        rows = get_all(header) if callable(get_all) else None
        if (type(rows) is list and len(rows) == 1 and type(rows[0]) is str
                and re.fullmatch(r'[0-9]{1,19}', rows[0]) and int(rows[0]) < 2**63):
            values[field] = int(rows[0])
    source = 'github-api' if origin.netloc == 'api.github.com' else 'official-release'
    repository = r'/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'
    kinds = (('latest-release', repository + r'/releases/latest'),
             ('tag-refs', repository + r'/git/(?:matching-refs/tags/|ref/tags/[^/]+|tags/[a-f0-9]{40})'),
             ('tagged-release', repository + r'/releases/tags/[^/]+'))
    endpoint = next((kind for kind, pattern in kinds
                     if source == 'github-api' and re.fullmatch(pattern, origin.path)), 'other')
    if (origin.netloc == 'github.com' and re.fullmatch(
            r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[^/]+/[^/]+', origin.path)):
        endpoint = 'release-asset'
    reason = ('quota-exhausted' if values.get('remaining') == 0 else
              'rate-limited' if error.code == 429 else 'forbidden')
    detail = f'official release request refused: source={source} status={error.code} reason={reason} endpoint={endpoint}'
    return detail + ''.join(f' {name}={value}' for name, value in values.items())


def _release_fetch(url: str) -> bytes:
    """Bounded public release transport, owned by the existing updater boundary."""
    origin = urllib.parse.urlsplit(url)
    _release_origin(url)
    catalog = origin.netloc == 'pypi.org' and re.fullmatch(r'/pypi/[A-Za-z0-9_.-]+/json', origin.path)
    archive = origin.path.endswith(('.tgz', '.tar.gz', '.tar.xz'))
    metadata_host = origin.netloc in {'api.github.com', 'pypi.org', 'git-scm.com'} or origin.netloc in {'registry.npmjs.org', 'www.php.net'} and not archive
    limit = 2*1024*1024 if metadata_host or origin.path.endswith(('.json', '.txt', '.sha256sum', '.asc', '/latest')) else 512*1024*1024
    decoded_limit = 64*1024*1024 if catalog else limit
    headers = {'User-Agent': 'Getzilla-release-resolver/1', 'Accept-Encoding': 'gzip' if catalog else 'identity'}
    request = urllib.request.Request(url, headers=headers)  # nosec B310
    started = time.monotonic()
    try:
        response = _RELEASE_OPENER.open(request, timeout=20)  # nosec B310
    except HTTPError as exc:
        if exc.code not in {403, 429}:
            raise
        try:
            detail = _release_refusal(exc, origin)
        finally:
            exc.close()
        raise ValueError(detail) from None
    with response:
        _release_origin(response.geturl())
        encoding = response.headers.get('Content-Encoding', 'identity')
        if encoding not in ({'identity', 'gzip'} if catalog else {'identity'}):
            raise ValueError('unsupported upstream release content encoding')
        decoder = zlib.decompressobj(16+zlib.MAX_WBITS) if encoding == 'gzip' else None
        wire_limit = limit if decoder else decoded_limit
        chunks, wire, decoded = [], 0, 0
        while True:
            if time.monotonic()-started > 60:
                raise ValueError('upstream release response exceeded total deadline')
            block = response.read1(min(65536, wire_limit-wire+1))
            if not block:
                break
            wire += len(block)
            if wire > wire_limit:
                raise ValueError('upstream release wire byte bound exceeded')
            try:
                body = decoder.decompress(block, decoded_limit-decoded+1) if decoder else block
            except zlib.error as exc:
                raise ValueError('invalid compressed release metadata') from exc
            decoded += len(body)
            if decoded > decoded_limit or decoder and decoder.unconsumed_tail:
                raise ValueError('upstream release decoded byte bound exceeded')
            chunks.append(body)
        if decoder and (not decoder.eof or decoder.unused_data):
            raise ValueError('truncated/trailing compressed release metadata')
    return b''.join(chunks)


def _platform_key() -> tuple[str, str]:
    system = 'windows' if os.name == 'nt' else sys.platform
    if system.startswith('linux'):
        system = 'linux'
    return system, platform.machine().lower()


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open('rb') as handle:
            for block in iter(lambda: handle.read(1 << 20), b''):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None



@dataclass(frozen=True)
class Result:
    component: str
    status: str
    detail: str


def _replace_bytes(path: Path, data: bytes, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data)
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise

