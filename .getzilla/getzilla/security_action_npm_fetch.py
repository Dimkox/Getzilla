"""Finite official npm source-data acquisition for hosted Action preparation.

No npm program, lifecycle hook, compiler, credential, redirect or retry runs.
Original acquisition times survive cache reuse; cache bytes are never authority.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .security_action_npm import MAX_NPM_BYTES, _json, registry_url, source_custody
from .security_artifacts import ArtifactError, MAX_INDEX_BYTES, read_file

COMPRESSED_LIMIT = 192 * 1024 * 1024
REQUEST_LIMIT = 272


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ArtifactError('artifact-npm-origin', 'npm source redirects are not admitted')


def fetch_state():
    lock = threading.Lock()
    return {'lock': lock, 'condition': threading.Condition(lock), 'reserved': 0, 'requests': 0, 'bytes': 0,
            'deadline': time.monotonic() + 300, 'failures': {}, 'failed_responses': {}}


def _fetch(url, *, maximum):
    try:
        with build_opener(_NoRedirect()).open(Request(url, headers={'User-Agent': 'Getzilla-source-data/1'}), timeout=30) as response:
            if response.geturl() != url:
                raise ArtifactError('artifact-npm-origin', 'official npm source URL changed')
            return response.read(maximum + 1), response.status
    except HTTPError as exc:
        return exc.read(min(maximum + 1, 65536)), exc.code


def acquire_sources(expected, artifacts, *, fetch=None, now=None, state=None, byte_budget=None):
    """Fetch or revalidate exact lock sources; return all retained response costs."""
    from . import manifest
    from .security_license_acquisition import _write
    root = Path(artifacts)
    now = now or datetime.now(timezone.utc)
    state = state if state is not None else fetch_state()
    fetch = fetch or _fetch
    cache_path = 'actions/npm/source-manifest.json'
    result = {'sources': {}, 'responses': [], 'gaps': []}
    try:
        cache = _json(read_file(root, cache_path, MAX_INDEX_BYTES))
        if set(cache) != {'schema_version', 'sources'} or (type(cache['schema_version']) is not int or cache['schema_version'] != 1) or not isinstance(cache['sources'], dict):
            raise ArtifactError('artifact-npm-cache', 'unsupported source cache schema')
        cached = cache['sources']
    except FileNotFoundError:
        cached = {}
    except (ArtifactError, ValueError, OSError):
        # No invalid cached claim gets credit. Reacquisition still verifies the
        # original lock and exact official source; it does not renew old bytes.
        cached = {}
    _, descriptor = manifest._open_root(root)
    local = {'bytes': 0, 'reserved': 0}
    budget = COMPRESSED_LIMIT if byte_budget is None else min(COMPRESSED_LIMIT, byte_budget)

    def receive(url):
        if not registry_url(url):
            raise ArtifactError('artifact-npm-origin', 'only exact official registry sources are admitted')
        with state['condition']:
            if url in state['failures']:
                raise ArtifactError('artifact-npm-transport', state['failures'][url])
            while True:
                if time.monotonic() >= state['deadline'] or state['requests'] >= REQUEST_LIMIT:
                    raise ArtifactError('artifact-npm-budget', 'finite npm request/deadline budget exhausted')
                maximum = min(MAX_NPM_BYTES, max(0, COMPRESSED_LIMIT - state['bytes'] - state['reserved']),
                              max(0, budget - local['bytes'] - local['reserved']))
                if maximum > 0:
                    break
                if not state['reserved']:
                    raise ArtifactError('artifact-size', 'npm source byte budget exhausted')
                state['condition'].wait(timeout=min(0.1, max(0, state['deadline'] - time.monotonic())))
            state['requests'] += 1
            state['reserved'] += maximum
            local['reserved'] += maximum
        raw = None
        try:
            fetched = fetch(url, maximum=maximum)
            raw, status = fetched if isinstance(fetched, tuple) else (fetched, 200)
            if not isinstance(raw, bytes):
                raise ArtifactError('artifact-npm-transport', 'npm fetch did not return original bytes')
        finally:
            with state['condition']:
                state['reserved'] -= maximum
                local['reserved'] -= maximum
                if isinstance(raw, bytes):
                    state['bytes'] += len(raw)
                    local['bytes'] += len(raw)
                state['condition'].notify_all()
        digest = hashlib.sha256(raw).hexdigest()
        path = 'actions/npm/objects/' + digest
        _write(descriptor, path, raw, immutable=True)
        response = {'url': url, 'path': path, 'sha256': digest, 'bytes': len(raw), 'acquired_at': now.isoformat()}
        with state['lock']:
            result['responses'].append(response)
            if len(raw) > maximum or state['bytes'] > COMPRESSED_LIMIT or local['bytes'] > budget:
                raise ArtifactError('artifact-size', 'actual npm response exceeds source/shared byte budget')
        if status != 200:
            raise ArtifactError('artifact-npm-transport', f'official npm source returned HTTP{status}')
        return response, raw

    def one(item):
        url, rows = item
        try:
            with state['lock']:
                if url in state['failures']:
                    result['responses'].extend(state['failed_responses'].get(url, []))
                    raise ArtifactError('artifact-npm-transport', state['failures'][url])
            if not registry_url(url) or not url.endswith('.tgz'):
                raise ArtifactError('artifact-npm-origin', 'lock source must be an exact official registry tarball')
            if url in cached:
                source = cached[url]
                try:
                    source_custody(root, source, rows, now=now)
                    receipts = [{key: source[key] for key in ('url', 'path', 'sha256', 'bytes', 'acquired_at')}]
                    if source['strong_metadata'] is not None:
                        receipts.append(dict(source['strong_metadata'], acquired_at=source['acquired_at']))
                    with state['lock']:
                        result['responses'].extend(receipts)
                    return url, source
                except FileNotFoundError:
                    pass
                except ArtifactError as exc:
                    if exc.code != 'artifact-npm-stale':
                        raise
            response, payload = receive(url)
            source = dict(response, strong_metadata=None)
            if any(row['integrity'].startswith('sha1-') for row in rows):
                name, version = rows[0]['name'], rows[0]['version']
                metadata_url = 'https://registry.npmjs.org/' + quote(name, safe='@') + '/' + quote(version, safe='')
                metadata_response, _ = receive(metadata_url)
                source['strong_metadata'] = {key: metadata_response[key] for key in ('url', 'path', 'sha256', 'bytes')}
            source_custody(root, source, rows, now=now)
            return url, source
        except (ArtifactError, ValueError, TypeError, KeyError, OSError) as exc:
            with state['lock']:
                state['failures'][url] = str(exc)
                metadata_urls = {'https://registry.npmjs.org/' + quote(row['name'], safe='@') + '/' + quote(row['version'], safe='')
                                 for row in rows if str(row.get('integrity')).startswith('sha1-')}
                state['failed_responses'][url] = [row for row in result['responses'] if row['url'] == url or row['url'] in metadata_urls]
                result['gaps'].append({'url': url, 'code': getattr(exc, 'code', 'artifact-npm-transport'), 'message': str(exc)})
            return url, None

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for url, source in pool.map(one, sorted(expected.items())):
                if source is not None:
                    result['sources'][url] = source
                    cached[url] = source
        _write(descriptor, cache_path, json.dumps({'schema_version': 1, 'sources': cached}, sort_keys=True,
               separators=(',', ':'), allow_nan=False).encode())
        result['requests'] = state['requests']
        result['received_bytes'] = state['bytes']
        result['responses'].sort(key=lambda row: row['url'])
        return result
    finally:
        os.close(descriptor)
