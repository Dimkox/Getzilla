"""Explicit network producer for saved PyPI artifacts; never installs or executes them.

Run this adapter from the independently qualified runner. Its saved hashes and
manifest give the pure evaluator byte-level evidence, not independent authority.
Direct pins do not imply that transitive dependencies have been resolved.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import stat
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

from .manifest import ManifestError, _open_root
from .security_artifacts import (ArtifactError, MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES,
                                 allowed_download_url, archive_files, package_key,
                                 package_metadata, pypi_index_url, read_file, safe_parts,
                                 verify_origin)
from .security_data import SecurityDataError, _clock, _json

MAX_BATCH_BYTES = 512 * 1024 * 1024
MAX_PACKAGES = 512


class _FixedOriginRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    max_repeats = 2

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_download_url(newurl):
            raise ArtifactError('artifact-origin', 'registry redirect leaves the fixed PyPI origins')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def bounded_default(url: str, *, maximum: int) -> bytes:
    """Fetch a fixed-origin HTTPS response with byte, redirect and time budgets."""
    if not allowed_download_url(url) or type(maximum) is not int or maximum < 1 or maximum > MAX_ARTIFACT_BYTES:
        raise ArtifactError('artifact-origin', 'fetch requires a fixed PyPI URL and bounded byte budget')
    started = time.monotonic()
    try:
        opener = urllib.request.build_opener(_FixedOriginRedirect())
        request = urllib.request.Request(url, headers={'User-Agent': 'Getzilla-artifact-evidence/1',
                                                       'Accept-Encoding': 'identity'})
        with opener.open(request, timeout=10) as response:
            if response.status != 200 or not allowed_download_url(response.geturl()):
                raise ArtifactError('artifact-origin', 'artifact response did not come from a successful fixed origin')
            if response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise ArtifactError('artifact-size', 'encoded HTTP response is outside the acquisition contract')
            declared = response.headers.get('Content-Length')
            if declared is not None and (not re.fullmatch(r'[0-9]+', declared) or int(declared) > maximum):
                raise ArtifactError('artifact-size', 'HTTP response exceeds its declared byte budget')
            remaining, chunks = maximum + 1, []
            while remaining:
                if time.monotonic() - started > 30:
                    raise ArtifactError('artifact-fetch-timeout', 'artifact fetch exceeded its wall-time budget')
                # read1 returns available transport data, allowing the total deadline
                # to be checked even when a server sends a slowly trickling body.
                chunk = response.read1(min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b''.join(chunks)
            if not body or not remaining or declared is not None and len(body) != int(declared):
                raise ArtifactError('artifact-size', 'HTTP body is empty, truncated or exceeds the byte budget')
            return body
    except (OSError, urllib.error.URLError, ValueError, http.client.HTTPException) as exc:
        if isinstance(exc, ArtifactError):
            raise
        raise ArtifactError('artifact-fetch', f'fixed-origin artifact fetch failed: {exc}') from exc


def _fetch(fetch, url: str, maximum: int) -> bytes:
    if not allowed_download_url(url):
        raise ArtifactError('artifact-origin', 'artifact URL is outside the fixed PyPI registry origins')
    body = fetch(url, maximum=maximum)
    if not isinstance(body, bytes) or not body or len(body) > maximum:
        raise ArtifactError('artifact-size', 'producer fetch did not return bounded nonempty bytes')
    return body


def _write(root_descriptor: int, relative: str, payload: bytes, *, immutable=False) -> None:
    """Atomically publish below an already bound directory, never through a link."""
    parts = safe_parts(relative)
    descriptor = os.dup(root_descriptor)
    temporary = None
    file_descriptor = None
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        try:
            existing = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISREG(existing.st_mode):
                raise ArtifactError('artifact-path', 'existing producer evidence is not a regular file')
            if immutable:
                old_descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=descriptor)
                with os.fdopen(old_descriptor, 'rb') as stream:
                    if stream.read(len(payload) + 1) != payload:
                        raise ArtifactError('artifact-hash', 'existing immutable object has different bytes')
                return
        temporary = '.tmp-' + uuid.uuid4().hex
        file_descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  0o600, dir_fd=descriptor)
        with os.fdopen(file_descriptor, 'wb') as stream:
            file_descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, parts[-1], src_dir_fd=descriptor, dst_dir_fd=descriptor)
        temporary = None
        os.fsync(descriptor)
    except OSError as exc:
        raise ArtifactError('artifact-path', 'cannot publish artifact evidence without following links') from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=descriptor)
            except FileNotFoundError:
                pass
        os.close(descriptor)


def _select(index: dict, dep: dict) -> dict:
    info, urls = index.get('info'), index.get('urls')
    if not isinstance(info, dict) or package_key('PyPI', info.get('name'), info.get('version')) != package_key('PyPI', dep.get('name'), dep.get('version')):
        raise ArtifactError('artifact-identity', 'registry release differs from the exact requested package')
    if not isinstance(urls, list) or not all(isinstance(item, dict) for item in urls):
        raise ArtifactError('artifact-origin', 'registry release file list is missing or malformed')
    filename, digest = dep.get('artifact_filename'), dep.get('artifact_sha256')
    if filename is not None and (not isinstance(filename, str) or len(safe_parts(filename)) != 1):
        raise ArtifactError('artifact-target-unknown', 'observed artifact filename is invalid')
    if digest is not None and (not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None):
        raise ArtifactError('artifact-target-unknown', 'observed artifact hash is invalid')
    selected = []
    for item in urls:
        candidate = item.get('filename')
        hashes = item.get('digests')
        if not isinstance(candidate, str) or not isinstance(hashes, dict):
            raise ArtifactError('artifact-origin', 'registry filename or digests are malformed')
        if filename is not None and filename != candidate or digest is not None and digest != hashes.get('sha256'):
            continue
        if filename is None and digest is None and re.search(r'-(?:py3|py2\.py3)-none-any\.whl$', candidate) is None:
            continue
        if item.get('yanked') is not False:
            continue
        if len(safe_parts(candidate)) != 1 or not isinstance(hashes.get('sha256'), str) or re.fullmatch(r'[0-9a-f]{64}', hashes['sha256']) is None:
            raise ArtifactError('artifact-origin', 'registry artifact lacks one safe filename and SHA-256')
        if item.get('packagetype') not in {'bdist_wheel', 'sdist'} or not allowed_download_url(item.get('url')) or not item['url'].startswith('https://files.pythonhosted.org/packages/'):
            raise ArtifactError('artifact-origin', 'registry artifact URL/type is outside the fixed file origin')
        selected.append(item)
    if len(selected) != 1:
        raise ArtifactError('artifact-target-unknown', 'select exactly one observed artifact or one unambiguous universal Python wheel')
    return selected[0]


def acquire_pypi(dependencies: list[dict], destination: Path, *, inventory_digest: str,
                 fetch=bounded_default, now: datetime | None = None) -> dict:
    """Save fixed-origin artifacts and commit manifest last; no dependency resolution.

    A network or verification failure leaves an existing manifest unchanged.
    Unsupported ecosystems appear as explicit gaps. Only the selected inventory
    identity is bound here; independent runner qualification binds its authority.
    The producer requires POSIX directory-descriptor writes; pure readers also
    support the repository's hardened Windows file-reading adapter.
    """
    if not isinstance(inventory_digest, str) or re.fullmatch(r'[0-9a-f]{64}', inventory_digest) is None:
        raise ArtifactError('artifact-inventory-binding', 'producer needs the exact full inventory digest')
    if not isinstance(dependencies, list) or len(dependencies) > MAX_PACKAGES or not all(isinstance(dep, dict) for dep in dependencies):
        raise ArtifactError('artifact-inventory-binding', 'producer dependencies must be a bounded list')
    current = _clock(now)
    descriptor = None
    try:
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination, descriptor = _open_root(destination)
        if not isinstance(descriptor, int):
            raise ArtifactError('artifact-platform', 'qualified POSIX producer required; this platform remains an acquisition gap')
        records, gaps, seen = [], [], set()
        total = 0
        for dep in dependencies:
            if dep.get('ecosystem') != 'PyPI':
                gaps.append({'code': 'artifact-acquisition-ecosystem', 'ecosystem': dep.get('ecosystem'),
                             'package': dep.get('name'), 'message': 'no qualified acquisition adapter for this ecosystem'})
                continue
            key = package_key('PyPI', dep.get('name'), dep.get('version'))
            observed = (key, dep.get('artifact_filename'), dep.get('artifact_sha256'))
            if observed in seen:
                continue
            if any(old[0] == key for old in seen):
                raise ArtifactError('artifact-target-unknown', 'one package/version has conflicting observed artifact targets')
            seen.add(observed)
            index_url = pypi_index_url(dep['name'], dep['version'])
            index_bytes = _fetch(fetch, index_url, MAX_INDEX_BYTES)
            selected = _select(_json(index_bytes), dep)
            payload = _fetch(fetch, selected['url'], MAX_ARTIFACT_BYTES)
            total += len(index_bytes) + len(payload)
            if total > MAX_BATCH_BYTES:
                raise ArtifactError('artifact-size', 'acquisition batch exceeds its total byte budget')
            digest = hashlib.sha256(payload).hexdigest()
            if digest != selected['digests']['sha256']:
                raise ArtifactError('artifact-hash', 'downloaded artifact differs from registry SHA-256')
            filename = selected['filename']
            metadata = package_metadata(archive_files(payload, filename), 'PyPI', filename)
            if package_key('PyPI', metadata['name'], metadata['version']) != key:
                raise ArtifactError('artifact-identity', 'artifact Name/Version differs from exact inventory')
            index_digest = hashlib.sha256(index_bytes).hexdigest()
            record = {'ecosystem': 'PyPI', 'name': dep['name'], 'version': dep['version'], 'filename': filename,
                      'path': f'objects/{digest}', 'sha256': digest,
                      'origin': {'index_url': index_url, 'index_path': f'indexes/{index_digest}.json',
                                 'index_sha256': index_digest, 'artifact_url': selected['url']}}
            _write(descriptor, record['origin']['index_path'], index_bytes, immutable=True)
            verify_origin(destination, record, payload)
            _write(descriptor, record['path'], payload, immutable=True)
            records.append(record)
        bundle = {'schema_version': 1, 'inventory_digest': inventory_digest,
                  'last_verified_sync_utc': (current if now is not None else _clock(None)).isoformat(),
                  'producer': 'getzilla-security-license-acquisition-v1', 'records': records, 'gaps': gaps,
                  'assurance': 'artifact-integrity-only'}
        body = json.dumps(bundle, sort_keys=True, separators=(',', ':')).encode()
        if len(body) > MAX_INDEX_BYTES:
            raise ArtifactError('artifact-size', 'artifact manifest exceeds its byte budget')
        _write(descriptor, 'manifest.json', body)
        return bundle
    except (OSError, ValueError, TypeError, ManifestError, SecurityDataError) as exc:
        if isinstance(exc, ArtifactError):
            raise
        raise ArtifactError('artifact-acquisition', str(exc)) from exc
    finally:
        if isinstance(descriptor, int):
            os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Acquire exact PyPI artifact evidence without installing packages')
    parser.add_argument('inventory', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args(argv)
    try:
        inventory = _json(read_file(args.inventory.parent, args.inventory.name, MAX_INDEX_BYTES))
        if inventory.get('complete') is not True or inventory.get('gaps'):
            raise ArtifactError('artifact-inventory-binding', 'acquisition requires a complete source inventory')
        result = acquire_pypi(inventory.get('dependencies'), args.destination, inventory_digest=inventory.get('digest'))
        print(json.dumps(result, sort_keys=True))
        return 1 if result['gaps'] else 0
    except (ArtifactError, SecurityDataError) as exc:
        print(json.dumps({'status': 'fail', 'code': getattr(exc, 'code', 'artifact-acquisition'), 'error': str(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
