"""Bounded public source data for the two checker tools; no execution or LIVE authority."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import unquote, urlsplit

from . import security_go_tool_inputs as reader
from .security_artifacts import ArtifactError, MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES, MAX_METADATA_BYTES, read_file
from .security_data import MAX_AGE_SECONDS, _clock, _json
from .security_license_acquisition import MAX_BATCH_BYTES, _write
from .manifest import _open_root

SOURCE_TRANSFER_BYTES = 1024 ** 3
DEADLINE_SECONDS = 600
ROOT_NAME = 'checker-tools'


def fail(code, message):
    raise ArtifactError(code, message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def descriptor(body, prefix='objects'):
    sha = hashlib.sha256(body).hexdigest()
    return dict(path=prefix + '/' + sha, sha256=sha)


def _allowed(url, *, redirect_from=None):
    if type(url) is not str or len(url) > 8192 or any(ord(char) < 32 for char in url):
        return False
    value = urlsplit(url)
    if (value.scheme != 'https' or value.username is not None or value.password is not None
            or value.port not in (None, 443) or value.fragment
            or any(part in {'.', '..'} for part in unquote(value.path).split('/'))):
        return False
    if redirect_from is not None:
        original = urlsplit(redirect_from)
        if (original.hostname == 'proxy.golang.org' and value.hostname == 'storage.googleapis.com'
                and value.path.startswith('/proxy-golang-org-prod/')):
            return True
        if (original.hostname == 'github.com' and value.hostname == 'release-assets.githubusercontent.com'
                and value.path.startswith('/github-production-release-asset-')):
            return True
    if value.query:
        return False
    if value.hostname == 'github.com':
        return url in {spec['url'] for spec in reader.PIN_SPECS.values()}
    if value.hostname == 'api.github.com':
        return bool(re.fullmatch(r'/repos/(?:aquasecurity/trivy|moby/buildkit|opencontainers/runc)/(?:releases/tags/v[0-9]+\.[0-9]+\.[0-9]+|git/(?:commits|trees|blobs)/[0-9a-f]{40})', value.path))
    if value.hostname == 'raw.githubusercontent.com':
        return bool(re.fullmatch(r'/golang/go/go[0-9]+\.[0-9]+\.[0-9]+/(?:LICENSE|PATENTS)', value.path))
    if value.hostname == 'proxy.golang.org':
        return bool(re.fullmatch(r'/[A-Za-z0-9_.!~+/-]+/@v/v[A-Za-z0-9_.!+~-]+\.zip', value.path))
    return False


def fetch_public(url, maximum, *, deadline=None):
    """Fixed anonymous origins; environment proxies, credentials and raw redirects are not persisted."""
    if type(maximum) is not int or not 0 < maximum <= MAX_ARTIFACT_BYTES or not _allowed(url):
        fail('go-source-origin', 'unsupported public source origin or byte bound')
    deadline = time.monotonic() + DEADLINE_SECONDS if deadline is None else deadline
    current = url
    for redirect in range(4):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail('go-source-timeout', 'public source deadline expired')
        parsed = urlsplit(current)
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=min(15, remaining))
        try:
            target = parsed.path + ('?' + parsed.query if parsed.query else '')
            connection.request('GET', target, headers={'User-Agent': 'Getzilla-Go-Source/1', 'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader('Location')
                if redirect == 3 or not _allowed(location, redirect_from=url):
                    fail('go-source-origin', 'public source redirect is outside its fixed origin')
                current = location
                continue
            if response.status != 200:
                error = ArtifactError('go-source-http', 'public source returned a non-success status')
                error.http_status = response.status
                raise error
            length = response.getheader('Content-Length')
            if length is not None and (not length.isdecimal() or not 0 < int(length) <= maximum):
                fail('artifact-size', 'public source length exceeds its bound')
            if response.getheader('Content-Encoding') not in (None, 'identity'):
                fail('go-source-transport', 'public source content encoding is unsupported')
            chunks, size = [], 0
            while True:
                if time.monotonic() >= deadline:
                    fail('go-source-timeout', 'public source deadline expired')
                block = response.read1(min(65536, maximum + 1 - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
                if size > maximum:
                    fail('artifact-size', 'public source body exceeds its bound')
            if not size or length is not None and size != int(length):
                fail('artifact-size', 'public source body is empty or truncated')
            return b''.join(chunks), dict(requested_url=url, fetched_at=time.time(), status=200)
        except (OSError, http.client.HTTPException) as original:
            error = ArtifactError('go-source-transport', 'public source transport unavailable')
            error.errno = getattr(original, 'errno', None)
            raise error from None
        finally:
            connection.close()
    fail('go-source-origin', 'public source redirect count exceeded')


class Store:
    """Owned immutable source objects and original-clock receipts below one namespace."""
    def __init__(self, root, *, now=None, fetch=None, byte_budget=None, cache_only=False):
        self.root = Path(root)
        self.now = _clock(now)
        self.deadline = time.monotonic() + DEADLINE_SECONDS
        self.fetch = fetch or (lambda url, maximum: fetch_public(url, maximum, deadline=self.deadline))
        self.budget = MAX_BATCH_BYTES if byte_budget is None else byte_budget
        if type(self.budget) is not int or not 0 < self.budget <= MAX_BATCH_BYTES:
            fail('artifact-size', 'invalid shared retained-source budget')
        self.cache_only = cache_only
        self.fd = None
        self.facts = []
        self.transferred = 0

    def __enter__(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root, self.fd = _open_root(self.root)
        if type(self.fd) is not int:
            fail('artifact-platform', 'qualified POSIX source store required')
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)

    def save(self, body, *, prefix='objects'):
        if not isinstance(body, bytes) or not body or len(body) > MAX_ARTIFACT_BYTES:
            fail('artifact-size', 'source object is empty or unbounded')
        desc = descriptor(body, prefix)
        _write(self.fd, desc['path'], body, immutable=True)
        return desc

    def _fresh(self, timestamp):
        return type(timestamp) in (int, float) and 0 <= self.now.timestamp() - timestamp <= MAX_AGE_SECONDS

    def _fact(self, url, body, receipt, data, *, stage, roles):
        saved = _json(read_file(self.root, receipt['path'], MAX_METADATA_BYTES))
        fact = dict(url=url, body=body, receipt=receipt, bytes=len(data), fetched_at=saved['fetched_at'],
                    stage=stage, roles=sorted(set(roles)))
        previous = next((row for row in self.facts if row['url'] == url and row['stage'] == stage), None)
        if previous:
            if any(previous[key] != fact[key] for key in ('body', 'receipt', 'bytes', 'fetched_at')):
                fail('go-source-cache', 'one source URL changed during preparation')
            previous['roles'] = sorted(set(previous['roles']) | set(roles))
            fact = previous
        else:
            self.facts.append(fact)
        retained = sum((row['bytes'] + len(read_file(self.root, row['receipt']['path'], MAX_METADATA_BYTES)))
                       * len(row['roles']) for row in self.facts)
        if retained > self.budget:
            fail('artifact-size', 'retained checker sources exceed the shared byte budget')
        return fact

    def get(self, url, maximum, *, stage, roles):
        if not _allowed(url):
            fail('go-source-origin', 'unsupported public source origin')
        key = 'cache/' + hashlib.sha256(url.encode()).hexdigest()
        try:
            os.stat(key, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            cached = None
        else:
            cached = _json(read_file(self.root, key, MAX_METADATA_BYTES))
        if cached is not None:
            receipt_raw = read_file(self.root, cached['path'], MAX_METADATA_BYTES)
            if hashlib.sha256(receipt_raw).hexdigest() != cached['sha256']:
                fail('artifact-hash', 'source cache receipt changed')
            saved = _json(receipt_raw)
            if (set(saved) != {'schema_version', 'url', 'body', 'fetched_at', 'status'}
                    or type(saved['schema_version']) is not int or saved['schema_version'] != 1
                    or saved['url'] != url or saved['status'] != 200):
                fail('go-source-cache', 'source cache belongs to another origin')
            data = read_file(self.root, saved['body']['path'], maximum)
            if hashlib.sha256(data).hexdigest() != saved['body']['sha256']:
                fail('artifact-hash', 'source cache bytes changed')
            if self._fresh(saved['fetched_at']):
                return data, self._fact(url, dict(saved['body']), cached, data, stage=stage, roles=roles)
            if self.cache_only:
                fail('go-source-stale', 'source cache is stale or future-dated')
        if self.cache_only:
            fail('go-source-missing', 'required source is not retained')
        data, observation = self.fetch(url, maximum)
        if (not isinstance(data, bytes) or not 0 < len(data) <= maximum or type(observation) is not dict
                or observation.get('requested_url') != url or observation.get('status') != 200
                or not self._fresh(observation.get('fetched_at'))):
            fail('go-source-clock', 'source response bytes, origin or original clock are invalid')
        self.transferred += len(data)
        if self.transferred > SOURCE_TRANSFER_BYTES:
            fail('go-source-budget', 'Go raw-source transfer exceeds its finite one-GiB calibration')
        body = self.save(data)
        receipt = self.save(canonical(dict(schema_version=1, url=url, body=body,
            fetched_at=observation['fetched_at'], status=200)), prefix='receipts')
        _write(self.fd, key, canonical(receipt))
        return data, self._fact(url, dict(body), receipt, data, stage=stage, roles=roles)


def _gap(error, *, role, stage, module=None):
    code = getattr(error, 'code', 'go-source-unavailable')
    return dict(role=role, stage=stage, code=code, **({'module': module} if module else {}),
        errno=getattr(error, 'errno', None), http_status=getattr(error, 'http_status', None))


def prepare_tools(checker, artifacts, tools=None, *, inventory_digest, now=None, fetch=None, byte_budget=None):
    """Retain data for both source-owned uses; no namespace or policy authority is created."""
    if type(inventory_digest) is not str or not re.fullmatch('[0-9a-f]{64}', inventory_digest):
        fail('artifact-inventory-binding', 'parent source inventory digest is required')
    inventory = reader.checker_inventory(checker)
    result = dict(schema_version=1, kind='go-checker-tools-preparation/v1', status='incomplete-source-inputs',
        parent_inventory_sha256=inventory_digest, inventory=inventory, records=[], gaps=[], source_facts=[])
    with Store(Path(artifacts) / ROOT_NAME, now=now, fetch=fetch, byte_budget=byte_budget) as store:
        for declaration in reader.checker_declarations(checker):
            role = declaration['role']
            repository = 'aquasecurity/trivy' if role == 'trivy' else 'moby/buildkit'
            sources = [('archive', declaration['reference'], MAX_ARTIFACT_BYTES),
                ('release', 'https://api.github.com/repos/' + repository + '/releases/tags/v' + declaration['version'], MAX_INDEX_BYTES)]
            for stage, url, maximum in sources:
                try:
                    store.get(url, maximum, stage=stage, roles=[role])
                except (ArtifactError, OSError, ValueError, KeyError, TypeError) as error:
                    result['gaps'].append(_gap(error, role=role, stage=stage))
        result['source_facts'] = store.facts
    return result
