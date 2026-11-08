"""Explicit bounded acquisition from fixed security origins and pinned tool assets."""
from __future__ import annotations

import hashlib
import http.client
import io
import os
import platform
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .security_data import SOURCE_URLS, SecurityDataError, osv_coverage, publish_snapshot
from .security_intelligence import validate_epss, validate_kev
from .updater import OPENGREP_ASSETS, OPENGREP_DOWNLOAD, OPENGREP_VERSION

TRIVY_VERSION = '0.74.0'
TRIVY_ARCHIVE_SHA256 = '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a'
TRIVY_URL = f'https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz'
MAX_DOWNLOAD = 1024 * 1024 * 1024


@dataclass(frozen=True)
class FetchResult:
    body: bytes
    requested_url: str
    final_url: str
    status: int


class _HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    max_repeats = 2

    def __init__(self, source_url):
        super().__init__()
        self.source_url = source_url

    def redirect_request(self, request, response, code, message, headers, url):
        if not _allowed_response(url, self.source_url):
            raise SecurityDataError('security download redirect left its fixed public HTTPS origins')
        return super().redirect_request(request, response, code, message, headers, url)


def _allowed_response(url: str, source_url: str) -> bool:
    try:
        parsed, source = urllib.parse.urlsplit(url), urllib.parse.urlsplit(source_url)
        hosts = {source.hostname}
        if source.hostname == 'github.com':
            hosts.update({'release-assets.githubusercontent.com', 'objects.githubusercontent.com'})
        if source.hostname == 'www.cisa.gov':
            hosts.add('cisa.gov')
        return (parsed.scheme == 'https' and parsed.hostname in hosts and parsed.port in {None, 443}
                and parsed.username is None and parsed.password is None)
    except (ValueError, AttributeError):
        return False


def fetch_public(url: str) -> FetchResult:
    parsed = urllib.parse.urlsplit(url)
    allowed = {'github.com', 'www.cisa.gov', 'epss.empiricalsecurity.com', 'osv-vulnerabilities.storage.googleapis.com'}
    if parsed.hostname not in allowed or not _allowed_response(url, url):
        raise SecurityDataError('security download requires a registered public HTTPS origin')
    request = urllib.request.Request(url, headers={'User-Agent': 'getzilla-security-acquisition/1', 'Accept-Encoding': 'identity'})
    opener = urllib.request.build_opener(_HTTPSRedirects(url))
    started = time.monotonic()
    try:
        with opener.open(request, timeout=10) as response:
            declared = response.headers.get('Content-Length')
            if response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise SecurityDataError('unexpected transport encoding for exact security bytes')
            if declared is not None and (not declared.isdecimal() or int(declared) > MAX_DOWNLOAD):
                raise SecurityDataError('security download length is invalid or exceeds the bound')
            remaining, chunks = MAX_DOWNLOAD + 1, []
            while remaining:
                if time.monotonic() - started > 80:
                    raise SecurityDataError('security download exceeded its total 90-second budget')
                chunk = response.read1(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                chunks.append(chunk)
            body = b''.join(chunks)
            if len(body) > MAX_DOWNLOAD or (declared is not None and len(body) != int(declared)):
                raise SecurityDataError('security download is incomplete or exceeds the bound')
            return FetchResult(body, url, response.geturl(), response.status)
    except http.client.HTTPException as exc:
        raise SecurityDataError('security HTTP body is incomplete or malformed') from exc


def _body(response: FetchResult, expected_url: str) -> bytes:
    if (not isinstance(response, FetchResult) or response.requested_url != expected_url or response.status != 200
            or not _allowed_response(response.final_url, expected_url)
            or not isinstance(response.body, bytes) or not response.body or len(response.body) > MAX_DOWNLOAD):
        raise SecurityDataError('download lacks the expected origin, complete body or successful response')
    return response.body


def refresh_feeds(database: Path, ecosystems: list[str], *, fetch: Callable[[str], FetchResult] = fetch_public,
                  now: datetime | None = None) -> list[dict]:
    results = []
    for source_id in [*(f'osv:{item}' for item in sorted(set(ecosystems))), 'kev', 'epss']:
        try:
            if source_id not in SOURCE_URLS:
                raise SecurityDataError('unsupported mandatory security source')
            response = fetch(SOURCE_URLS[source_id])
            payload = _body(response, SOURCE_URLS[source_id])
            current = datetime.now(timezone.utc) if now is None else now
            if source_id.startswith('osv:'):
                coverage = osv_coverage(payload, source_id.removeprefix('osv:'))
                published = None
            else:
                parsed = (validate_kev if source_id == 'kev' else validate_epss)(payload, now=current)
                coverage, published = parsed['coverage'], parsed['source_published_at']
            acquisition = {'last_verified_sync_utc': current.isoformat(), 'retrieval_kind': 'download',
                           'producer': 'getzilla-security-acquisition-v1'}
            if published is not None:
                acquisition['source_published_at'] = published
            proof = publish_snapshot(database, source_id, payload, acquisition=acquisition, coverage=coverage, now=current)
            results.append({'source_id': source_id, 'status': 'pass', 'snapshot': proof,
                            'http': {'requested_url': response.requested_url, 'final_url': response.final_url,
                                     'status': response.status}})
        except (OSError, ValueError, RuntimeError) as exc:
            results.append({'source_id': source_id, 'status': 'fail', 'reason': str(exc)})
    return results


def _atomic(path: Path, payload: bytes, *, executable: bool = False) -> None:
    for entry in (path, *path.parents):
        if entry.is_symlink():
            raise SecurityDataError('security output path must not traverse links')
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix='.security-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o755 if executable else 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def trivy_binary(archive: bytes) -> bytes:
    if hashlib.sha256(archive).hexdigest() != TRIVY_ARCHIVE_SHA256:
        raise SecurityDataError('Trivy release archive differs from the reviewed pin')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as bundle:
        members = []
        for member in bundle:
            if len(members) >= 1000:
                raise SecurityDataError('Trivy archive member inventory exceeds the bound')
            members.append(member)
        matches = [item for item in members if item.name == 'trivy']
        if len(members) > 1000 or len(matches) != 1 or not matches[0].isreg() or not 0 < matches[0].size <= MAX_DOWNLOAD:
            raise SecurityDataError('Trivy archive executable is missing, ambiguous or oversized')
        stream = bundle.extractfile(matches[0])
        if stream is None:
            raise SecurityDataError('Trivy executable is unreadable')
        with stream:
            payload = stream.read(MAX_DOWNLOAD + 1)
        if len(payload) != matches[0].size:
            raise SecurityDataError('Trivy executable is incomplete')
        return payload


def provision_tools(destination: Path, *, fetch: Callable[[str], FetchResult] = fetch_public) -> list[dict]:
    """Only pinned binaries are placed in the isolated tools directory; no install scripts."""
    key = (platform.system().lower(), platform.machine().lower())
    if key != ('linux', 'x86_64'):
        raise SecurityDataError('expanded tool provisioning currently requires isolated Linux x86_64')
    asset, digest = OPENGREP_ASSETS[key]
    opengrep_url = OPENGREP_DOWNLOAD.format(version=OPENGREP_VERSION, asset=asset)
    output = []
    for name, url, pin in [('opengrep', opengrep_url, digest), ('trivy', TRIVY_URL, TRIVY_ARCHIVE_SHA256)]:
        try:
            cached = destination / 'archives' / pin
            if cached.exists():
                from .security_artifacts import read_file
                payload = read_file(destination, f'archives/{pin}', MAX_DOWNLOAD)
            else:
                payload = _body(fetch(url), url)
            if hashlib.sha256(payload).hexdigest() != pin:
                raise SecurityDataError(f'{name} asset SHA-256 differs from the reviewed pin')
            executable = trivy_binary(payload) if name == 'trivy' else payload
            _atomic(cached, payload)
            _atomic(destination / 'bin' / name, executable, executable=True)
            output.append({'tool': name, 'status': 'pass', 'origin': url, 'archive_sha256': pin,
                           'executable_sha256': hashlib.sha256(executable).hexdigest()})
        except (OSError, ValueError, RuntimeError, tarfile.TarError) as exc:
            output.append({'tool': name, 'status': 'fail', 'reason': str(exc)})
    return output
