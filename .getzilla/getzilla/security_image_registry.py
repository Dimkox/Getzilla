"""Bounded Docker Hub OCI acquisition. No daemon, push, credentials or tag cache.

Each HTTP exchange runs in a fixed isolated child under the existing bounded
process reader, including DNS/headers. Local graph validation remains mandatory.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from .security_oci import INDEX_MEDIA, MANIFEST_MEDIA, LIMITS, active_limits, _descriptor, _index_children, OPAQUE_ATTESTATION, canonical, document

DOCKER_CATALOG = 'https://raw.githubusercontent.com/docker-library/official-images/master/library/docker'
_ORIGINS = {'registry-1.docker.io', 'auth.docker.io', 'github.com'}
# Docker's published pull CDN, not arbitrary redirects or authentication realms.
_BLOB_CDN = {'production.cloudfront.docker.com'}
_BOOTSTRAP = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
              'from getzilla.security_image_registry import _worker;raise SystemExit(_worker())')


class RegistryError(ValueError):
    def __init__(self, message, *, detail=None, category='protocol'):
        super().__init__(message)
        self.detail = dict(detail or {})
        self.category = category


_FAULT_KEYS = {'version', 'category', 'phase', 'request_kind', 'origin', 'errno', 'http_status', 'command_id'}
_FAULT_HOSTS = _ORIGINS | _BLOB_CDN | {'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'unknown'}
_FAULT_CATEGORIES = {'request', 'dns', 'tls', 'http', 'timeout', 'os', 'protocol', 'bound', 'worker'}
_FAULT_PHASES = {'registry-request', 'registry-connect', 'registry-headers', 'registry-body', 'registry-worker', 'registry-reply'}


def _request_fault(url, category, phase, *, errno=None, status=None):
    category = category if isinstance(category, str) and category in _FAULT_CATEGORIES else 'protocol'
    phase = phase if isinstance(phase, str) and phase in _FAULT_PHASES else 'registry-request'
    try:
        parsed = urllib.parse.urlsplit(url)
        origin = parsed.hostname if parsed.hostname in _FAULT_HOSTS else 'unknown'
        kind = ('auth' if origin == 'auth.docker.io' else 'tool' if origin == 'github.com' else
                'manifest' if '/manifests/' in parsed.path else 'blob' if '/blobs/' in parsed.path else 'unknown')
    except (ValueError, TypeError, AttributeError):
        origin, kind = 'unknown', 'unknown'
    return dict(version=1, category=category, phase=phase, request_kind=kind, origin=origin,
                errno=errno if type(errno) is int and abs(errno) <= 65535 else None,
                http_status=status if type(status) is int and 100 <= status <= 599 else None,
                command_id='registry-http')


def _closed_fault(value):
    if (not isinstance(value, dict) or set(value) != _FAULT_KEYS or type(value['version']) is not int
            or value['version'] != 1 or value['category'] not in _FAULT_CATEGORIES
            or value['phase'] not in _FAULT_PHASES
            or value['request_kind'] not in {'auth', 'manifest', 'blob', 'tool', 'unknown'}
            or value['origin'] not in _FAULT_HOSTS or value['command_id'] != 'registry-http'
            or value['errno'] is not None and (type(value['errno']) is not int or abs(value['errno']) > 65535)
            or value['http_status'] is not None and (type(value['http_status']) is not int or not 100 <= value['http_status'] <= 599)):
        raise ValueError('unqualified registry fault protocol')
    return value


def _exception_fault(request, error, phase):
    if isinstance(error, RegistryError) and error.detail:
        try:
            return _closed_fault(error.detail)
        except (ValueError, TypeError):
            pass
    status = error.code if isinstance(error, urllib.error.HTTPError) else None
    cause = error.reason if isinstance(error, urllib.error.URLError) and not isinstance(error, urllib.error.HTTPError) else error
    category = ('http' if status is not None else 'dns' if isinstance(cause, socket.gaierror) else
                'tls' if isinstance(cause, ssl.SSLError) else 'timeout' if isinstance(cause, TimeoutError) else
                'os' if isinstance(cause, OSError) else error.category if isinstance(error, RegistryError) else 'protocol')
    if status is not None:
        phase = 'registry-headers'
    return _request_fault(request.get('url') if isinstance(request, dict) else None, category, phase,
                          errno=getattr(cause, 'errno', None), status=status)


def _url(url, hosts):
    try:
        value = urllib.parse.urlsplit(url)
        return (value.scheme == 'https' and value.hostname in hosts and value.port in {None, 443}
                and value.username is None and value.password is None and not value.fragment)
    except (ValueError, AttributeError):
        return False


class _Redirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    max_repeats = 1

    def __init__(self, source):
        self.source = source

    def redirect_request(self, request, response, code, message, headers, url):
        if self.source == DOCKER_CATALOG:
            raise RegistryError('official DinD catalog redirect refused')
        source = urllib.parse.urlsplit(self.source)
        hosts = {source.hostname}
        if source.hostname == 'registry-1.docker.io' and '/blobs/sha256:' in source.path:
            hosts |= _BLOB_CDN
        if source.hostname == 'github.com':
            hosts |= {'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
        if not _url(url, hosts):
            raise RegistryError('registry redirect leaves registered origins')
        result = super().redirect_request(request, response, code, message, headers, url)
        if urllib.parse.urlsplit(url).hostname != source.hostname:
            result.remove_header('Authorization')
        return result


def _http(request, *, opener=None, clock=time.monotonic):
    """Worker stream reader: no whole-body read and no response decompression."""
    if (set(request) != {'url', 'headers', 'maximum', 'seconds'}
            or not (_url(request['url'], _ORIGINS) or (request['url'] == DOCKER_CATALOG and request['headers'] == {} and request['maximum'] == 131072))
            or type(request['maximum']) is not int
            or not 0 < request['maximum'] <= LIMITS['max_storage_bytes']
            or not isinstance(request['seconds'], (int, float)) or not 0 < request['seconds'] <= 30):
        raise RegistryError('invalid bounded registry request', category='request')
    deadline = clock() + request['seconds']
    selected = urllib.request.Request(request['url'], headers={**request['headers'], 'Accept-Encoding': 'identity'})
    port = opener or urllib.request.build_opener(_Redirect(request['url'])).open
    phase = 'registry-connect'
    try:
        with port(selected, timeout=min(10, request['seconds'])) as response:
            phase = 'registry-headers'
            if response.status != 200:
                raise RegistryError('registry response status refused', detail=_request_fault(request['url'], 'http', phase, status=response.status))
            if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                raise RegistryError('registry response encoding refused')
            length = response.headers.get('Content-Length')
            if length is not None and (not re.fullmatch('[0-9]+', length) or int(length) > request['maximum']):
                raise RegistryError('registry declared response exceeds byte budget', category='bound')
            header = {'type': response.headers.get('Content-Type', '').split(';')[0],
                      'digest': response.headers.get('Docker-Content-Digest', '')}
            if any(not isinstance(v, str) or len(v) > 256 for v in header.values()):
                raise RegistryError('registry response metadata exceeds bound', category='bound')
            yield canonical(header) + b'\n'
            phase = 'registry-body'
            total = 0
            while True:
                if clock() >= deadline:
                    raise RegistryError('registry response deadline exceeded', category='timeout')
                requested = min(65536, request['maximum'] + 1 - total)
                part = response.read1(requested)
                if clock() >= deadline:
                    raise RegistryError('registry response deadline exceeded', category='timeout')
                if not isinstance(part, bytes):
                    raise RegistryError('registry response type refused')
                if len(part) > requested:
                    raise RegistryError('registry response chunk exceeds bound', category='bound')
                total += len(part)
                if total > request['maximum']:
                    raise RegistryError('registry response exceeds byte budget', category='bound')
                if not part:
                    break
                yield part
            if length is not None and total != int(length):
                raise RegistryError('registry body is truncated')
    except Exception as error:
        raise RegistryError('bounded registry exchange refused', detail=_exception_fault(request, error, phase)) from None


def _worker():
    request = None
    try:
        request = document(sys.stdin.buffer.read(65537))
        for part in _http(request):
            sys.stdout.buffer.write(part)
        return 0
    except Exception as error:
        # Only closed observations survive. Never serialize exception text,
        # request headers, response bodies, or signed redirect queries.
        detail = _exception_fault(request, error, 'registry-request')
        sys.stderr.write(canonical(detail).decode() + '\n')
        return 1


class BoundedHTTP:
    def __init__(self, *, deadline):
        self.deadline = deadline

    def bootstrap(self):
        """Exercise the exact isolated worker/import path without any egress."""
        try:
            self.get('invalid://bootstrap', {}, 1)
        except RegistryError as error:
            detail = error.detail
            if (detail.get('category') == 'request' and detail.get('phase') == 'registry-request'
                    and detail.get('origin') == 'unknown' and detail.get('exit_code') == 1):
                return
            raise
        raise RegistryError('registry bootstrap protocol refused')

    def get(self, url, headers, maximum):
        from .architecture_diff import _run_capped, ArchitectureError
        remaining = min(30, self.deadline - time.monotonic())
        if remaining <= 0:
            raise RegistryError('registry aggregate deadline exceeded')
        payload = canonical(dict(url=url, headers=headers, maximum=maximum, seconds=remaining))
        if len(payload) > 65536:
            raise RegistryError('registry request metadata exceeds bound')
        try:
            code, raw, stderr = _run_capped(
                [sys.executable, '-I', '-S', '-B', '-c', _BOOTSTRAP, str(Path(__file__).resolve().parents[1])],
                cwd=Path(__file__).resolve().parents[2], env={'PATH': os.defpath, 'LANG': 'C.UTF-8'},
                stdin_data=payload, stdout_limit=maximum + 1024, stderr_limit=2048, timeout=remaining)
        except (OSError, ArchitectureError) as error:
            detail = _request_fault(url, 'worker', 'registry-worker', errno=getattr(error, 'errno', None))
            detail.update(exit_code=None, command_id='registry-worker')
            raise RegistryError('bounded registry worker incomplete', detail=detail) from None
        header, separator, body = raw.partition(b'\n')
        if code != 0 or not separator or len(header) > 1024 or len(body) > maximum:
            try:
                if len(stderr) > 2048:
                    raise ValueError('fault exceeds bound')
                detail = dict(_closed_fault(document(stderr)))
            except (ValueError, TypeError):
                detail = _request_fault(url, 'worker', 'registry-worker')
                detail['command_id'] = 'registry-worker'
            detail.update(exit_code=code, stderr_bytes=len(stderr), stderr_sha256=hashlib.sha256(stderr).hexdigest())
            raise RegistryError('registry bounded reply refused', detail=detail)
        try:
            return document(header), body
        except ValueError:
            detail = _request_fault(url, 'protocol', 'registry-reply')
            detail.update(exit_code=code, command_id='registry-worker')
            raise RegistryError('registry bounded reply metadata refused', detail=detail) from None


def split_reference(reference):
    if not isinstance(reference, str) or len(reference) > 2048 or '$' in reference:
        raise RegistryError('image reference is unresolved')
    name, pinned, digest = reference.partition('@')
    if pinned and not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise RegistryError('invalid immutable image digest')
    # Only a colon after the last slash introduces an image tag.
    tag = 'latest'
    if ':' in name.rsplit('/', 1)[-1]:
        name, tag = name.rsplit(':', 1)
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', tag):
            raise RegistryError('invalid source image tag')
    selector = digest if pinned else tag
    for prefix in ('docker.io/', 'registry-1.docker.io/'):
        name = name.removeprefix(prefix)
    if '.' in name.split('/')[0] or ':' in name or not re.fullmatch(r'[a-z0-9][a-z0-9_/-]{0,199}', name):
        raise RegistryError('image registry/repository is outside current Docker Hub adapter')
    return name if '/' in name else 'library/' + name, selector


class Registry:
    """Actual descriptor/hash-addressed graph collector; injected ports are fixture-only models."""
    def __init__(self, *, transport=None, deadline=None):
        self.limits = active_limits()
        self.deadline = deadline or time.monotonic() + LIMITS['deadline_seconds']
        self.http = transport or BoundedHTTP(deadline=self.deadline)
        self.tokens, self.blobs, self.descriptors, self.roles = {}, {}, {}, {}
        self.downloaded = 0

    def _get(self, repository, kind, selector, maximum):
        if active_limits() != self.limits:
            raise RegistryError('registry live aggregate profile changed')
        if time.monotonic() >= self.deadline:
            raise RegistryError('registry aggregate deadline exceeded')
        if repository not in self.tokens:
            token_url = ('https://auth.docker.io/token?service=registry.docker.io&scope=repository:'
                         + urllib.parse.quote(repository, safe='/') + ':pull')
            _, raw = self.http.get(token_url, {}, 65536)
            token = document(raw).get('token')
            if not isinstance(token, str) or not 0 < len(token) < 32768 or '\n' in token or '\r' in token:
                raise RegistryError('anonymous registry token unavailable')
            self.tokens[repository] = token
        maximum = min(maximum, LIMITS['max_storage_bytes'], self.limits['max_storage_bytes'] - self.downloaded)
        if maximum <= 0:
            raise RegistryError('registry aggregate byte budget exceeded')
        header, body = self.http.get(f'https://registry-1.docker.io/v2/{repository}/{kind}/{selector}',
            {'Authorization': 'Bearer ' + self.tokens[repository], 'Accept': ', '.join(sorted(INDEX_MEDIA | MANIFEST_MEDIA))}, maximum)
        if not isinstance(body, bytes) or not body or len(body) > maximum:
            raise RegistryError('registry returned invalid bounded bytes')
        self.downloaded += len(body)
        digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        if selector.startswith('sha256:') and selector != digest or header.get('digest') not in {'', digest}:
            raise RegistryError('registry content digest mismatch')
        return header, body, digest

    def resolve(self, reference, platform):
        repository, selector = split_reference(reference)
        header, raw, digest = self._get(repository, 'manifests', selector, LIMITS['max_manifest_bytes'])
        value = document(raw)
        media = value.get('mediaType')
        if media not in INDEX_MEDIA | MANIFEST_MEDIA or header.get('type') != media:
            raise RegistryError('registry root is not supported OCI media')
        # Resolve the actual tag root. Keep its complete graph, including sibling
        # platforms; never flatten an index to evade the shared byte limits.
        root = {'mediaType': media, 'digest': digest, 'size': len(raw)}
        self._graph(repository, root, raw, 0)
        display = reference.split('@', 1)[0]
        if not selector.startswith('sha256:'):
            display = display.rsplit(':', 1)[0] if ':' in display else display
        return display + '@' + digest, root

    def _graph(self, repository, descriptor, raw=None, depth=0, *, attestation=False, opaque=False):
        if time.monotonic() >= self.deadline:
            raise RegistryError('registry aggregate deadline exceeded')
        media, digest, size = _descriptor(descriptor, opaque_attestation=opaque)
        if opaque and size > LIMITS['max_manifest_bytes']:
            raise RegistryError('opaque registry metadata exceeds existing bound')
        if depth > 64 or len(self.descriptors) >= 100000:
            raise RegistryError('registry graph exceeds traversal bound')
        role = ('opaque', None) if opaque else ('attestation', attestation) if attestation else ('ordinary', None)
        if digest in self.roles and self.roles[digest] != role:
            raise RegistryError('conflicting registry graph roles')
        self.roles[digest] = role
        if digest in self.descriptors:
            if (media, size) != self.descriptors[digest]:
                raise RegistryError('conflicting registry descriptors')
            return
        if raw is None:
            _, raw, _ = self._get(repository, 'manifests' if media in INDEX_MEDIA | MANIFEST_MEDIA else 'blobs', digest,
                                  min(size, self.limits['max_storage_bytes']))
        if len(raw) != size or 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
            raise RegistryError('registry graph bytes differ from descriptor')
        self.descriptors[digest], self.blobs[digest] = (media, size), raw
        if sum(len(value) for value in self.blobs.values()) > self.limits['max_storage_bytes']:
            raise RegistryError('registry graph storage bound exceeded')
        if media in INDEX_MEDIA | MANIFEST_MEDIA:
            node = document(raw)
            children = node.get('manifests') if media in INDEX_MEDIA else [node.get('config'), *node.get('layers', [])]
            if not isinstance(children, list) or len(children) > LIMITS['max_layers'] + 1:
                raise RegistryError('registry graph children exceed bound')
            if media in INDEX_MEDIA:
                for child, child_attestation in _index_children(children):
                    self._graph(repository, child, depth=depth + 1, attestation=child['annotations']['vnd.docker.reference.digest'] if child_attestation else False)
            else:
                for child in children:
                    child_opaque = attestation and type(child) is dict and child.get('mediaType') == OPAQUE_ATTESTATION
                    self._graph(repository, child, depth=depth + 1, opaque=child_opaque)
