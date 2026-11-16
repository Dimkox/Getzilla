"""Fixed, bounded host HTTP worker; never import or execute candidate code."""
from __future__ import annotations

import io
import math
import os
import stat
from pathlib import Path
import re
import struct
import sys
import time
import urllib.request
from urllib.parse import urlsplit, unquote

if __name__ == '__main__' and not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = 'adaptive_trust_ci'

from .github import GitHubClient
from .github_observer import _NoRedirect, _run_owned
from .models import parse_datetime, require_repository
from .security_bundle import bounded_json, canonical_json

_WORKER = str(Path(__file__).resolve())
_MAXIMUM = 1048576


def _time(clock, deadline):
    current = clock()
    if not math.isfinite(deadline) or not math.isfinite(current) or current >= deadline:
        raise ValueError('public-http-deadline')
    return current


def _read_http(opener, method, url, headers, body, deadline, clock, maximum):
    """Bound the raw response body before JSON and preserve every wire byte."""
    started = _time(clock, deadline)
    request = urllib.request.Request(url, data=body, headers={**headers, 'Accept-Encoding': 'identity'}, method=method)
    with opener.open(request, timeout=min(5, deadline - started)) as response:
        _time(clock, deadline)
        if (response.url != url or type(response.status) is not int or not 200 <= response.status < 300
                or response.headers.get('Content-Encoding', 'identity') != 'identity'):
            raise ValueError('public-http-response-scope')
        length = response.headers.get('Content-Length')
        if length is not None and (not length.isdecimal() or int(length) > maximum):
            raise ValueError('public-http-response-size')
        chunks, total = [], 0
        while True:
            remaining = deadline - _time(clock, deadline)
            sock = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(min(5, remaining))
            requested = min(65536, maximum - total + 1)
            part = response.read(requested)
            _time(clock, deadline)
            if type(part) is not bytes or len(part) > requested or total + len(part) > maximum:
                raise ValueError('public-http-response-size')
            total += len(part)
            if not part:
                break
            chunks.append(part)
        return response.status, b''.join(chunks)


def _exchange(request, deadline):
    # Bound structural/string material before encoding. Even worst-case JSON
    # escaping stays below the original1MiB response allocation ceiling.
    stack, nodes, material = [(request, 0)], 0, 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > 4096 or depth > 32:
            raise ValueError('public-http-worker-input-bound')
        if type(value) is str:
            material += len(value)
        elif type(value) is dict:
            if len(value) > 4096 or any(type(key) is not str for key in value):
                raise ValueError('public-http-worker-input-shape')
            stack.extend((item, depth + 1) for pair in value.items() for item in pair)
        elif type(value) in (list, tuple):
            if len(value) > 4096:
                raise ValueError('public-http-worker-input-bound')
            stack.extend((item, depth + 1) for item in value)
        elif type(value) is int:
            if value.bit_length() > 256:
                raise ValueError('public-http-worker-input-bound')
            material += 80
        elif value is not None and type(value) is not bool:
            raise ValueError('public-http-worker-input-shape')
        if material + nodes * 2 > 65536:
            raise ValueError('public-http-worker-input-bound')
    payload = canonical_json(request)
    if len(payload) > 65536:
        raise ValueError('public-http-worker-input-bound')
    return _run_owned([sys.executable, '-I', '-B', _WORKER, '--public-http-worker'], payload, deadline)


class _Response(io.BytesIO):
    def __init__(self, raw, url, status, clock, deadline):
        super().__init__(raw)
        self.url, self.status, self.encoding = url, status, 'identity'
        self.clock, self.deadline = clock, deadline

    def read(self, maximum=-1):
        _time(self.clock, self.deadline)
        if type(maximum) is not int or not 0 <= maximum <= 1048576:
            raise ValueError('public-http-read-bound')
        return super().read(maximum)


def _request_scope(repository, method, path, body):
    if not isinstance(path, str) or len(path) > 2048 or any(c in path for c in '\r\n\\ #'):
        return False
    parsed = urlsplit(path)
    decoded = unquote(parsed.path)
    if (parsed.scheme or parsed.netloc or parsed.fragment or re.search(r'%0[ad]', path, re.I)
            or any(part in ('.', '..') for part in decoded.split('/')) or '\\' in decoded):
        return False
    root = '/repos/' + repository
    return (method == 'GET' and body is None and (parsed.path == root or parsed.path.startswith(root + '/')
              or path == '/installation/repositories?per_page=100')
            or method == 'POST' and path == root + '/check-runs'
            or method == 'PATCH' and re.fullmatch(re.escape(root) + r'/check-runs/[1-9][0-9]*', path) is not None)


class BoundedHTTPPort:
    """Concrete PublicationPort; token callbacks and ordinary transports cannot run."""
    def __init__(self, repository, *, clock=time.monotonic):
        self.repository = require_repository(repository)
        self.clock = clock

    def open(self, client, method, path, body, *, deadline, maximum):
        started = _time(self.clock, deadline)
        if (type(client) is not GitHubClient or type(client.api_url) is not str
                or client.api_url != 'https://api.github.com' or client.token_provider is not None
                or type(client.token) is not str or not 0 < len(client.token) <= 4096
                or any(c.isspace() for c in client.token)
                or type(client.api_version) is not str or not 0 < len(client.api_version) <= 64
                or '\r' in client.api_version or '\n' in client.api_version
                or type(maximum) is not int or not 0 < maximum <= _MAXIMUM
                or not _request_scope(self.repository, method, path, body)):
            raise ValueError('public-http-request-scope')
        # Read only bounded plain fields; never invoke an overridable client callback.
        headers = {'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                   'Authorization': 'Bearer ' + client.token, 'User-Agent': 'adaptive-trust-ci/2.1.0',
                   'X-GitHub-Api-Version': client.api_version}
        end = min(deadline, started + 5)
        request = dict(action='http', repository=self.repository, url=client.api_url + path, method=method, headers=headers, body=body,
                       maximum=maximum, remaining_ns=int((end - self.clock()) * 1000000000))
        output = _exchange(request, end)
        _time(self.clock, end)
        if len(output) < 8:
            raise ValueError('public-http-worker-framing')
        status, count = struct.unpack('!II', output[:8])
        raw = output[8:]
        if not 200 <= status < 300 or count != len(raw) or count > maximum:
            raise ValueError('public-http-worker-framing')
        return _Response(raw, request['url'], status, self.clock, end)


def issue_scoped_token(config, key_path, budget, *, now, purpose='publisher'):
    """One owned5s broker operation; both requests share the publication allocation."""
    end = min(budget.deadline, budget.clock() + 5)
    _time(budget.clock, end)
    allocations = [budget.reserve(524288, publication=True) for _ in range(2)]
    if purpose not in ('observer', 'publisher'):
        raise ValueError('public-token-purpose')
    token_request = config.token_request()
    if purpose == 'observer':
        token_request['permissions']['checks'] = 'read'
    request = dict(action='token', purpose=purpose, app_id=config.app_id, installation_id=config.installation_id,
                   key_path=str(key_path), token_request=token_request, maximums=allocations,
                   remaining_ns=int((end - budget.clock()) * 1000000000))
    output = _exchange(request, end)
    _time(budget.clock, end)
    if len(output) < 12:
        raise ValueError('public-token-worker-framing')
    status, first, second = struct.unpack('!III', output[:12])
    if status != 201 or first > allocations[0] or second > allocations[1] or len(output) - 12 > second:
        raise ValueError('public-token-worker-framing')
    value = bounded_json(output[12:], maximum=allocations[1])
    token = value.get('token') if isinstance(value, dict) else None
    if (not isinstance(token, str) or not 0 < len(token) <= 4096 or any(c.isspace() for c in token)
            or parse_datetime(value.get('expires_at', '')) <= now):
        raise ValueError('public-token-unavailable')
    budget.finish(allocations[0], first)
    budget.finish(allocations[1], second)
    return token


def _read_app_key(path):
    """The actual secret stays inside the owned child and one private descriptor."""
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
        raise ValueError('public-key-reader-unavailable')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                or before.st_mode & 0o077 or not 0 < before.st_size <= 65536):
            raise ValueError('public-app-key-shape')
        chunks, total = [], 0
        while True:
            part = os.read(descriptor, min(65536, 65536 - total + 1))
            if total + len(part) > 65536:
                raise ValueError('public-app-key-size')
            if not part:
                break
            chunks.append(part)
            total += len(part)
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if total != before.st_size or any(getattr(before, name) != getattr(after, name) for name in fields):
            raise ValueError('public-app-key-changed')
        return b''.join(chunks)
    finally:
        os.close(descriptor)


def _worker_main():
    try:
        request = bounded_json(sys.stdin.buffer.read(65537), maximum=65536)
        if type(request) is not dict or request.get('action') not in ('http', 'token'):
            raise ValueError('public-http-worker-input')
        remaining = request.get('remaining_ns')
        if type(remaining) is not int or not 0 < remaining <= 5000000000:
            raise ValueError('public-http-worker-deadline')
        def deny_children(event, args):
            if event in {'subprocess.Popen', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.posix_spawnp', 'os.system'}:
                raise ValueError('public-http-worker-descendant')
        sys.addaudithook(deny_children)
        # This fixed child owns HTTP parsing too. Headers are additionally bounded
        # to64 lines of1024 bytes; these stricter limits affect no other process.
        import http.client
        http.client._MAXLINE = 1024
        http.client._MAXHEADERS = 64
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        deadline = time.monotonic() + remaining / 1000000000
        if request['action'] == 'http':
            if set(request) != {'action', 'repository', 'url', 'method', 'headers', 'body', 'maximum', 'remaining_ns'}:
                raise ValueError('public-http-worker-input')
            url, headers, maximum = request['url'], request['headers'], request['maximum']
            if (not isinstance(url, str) or not url.startswith('https://api.github.com/') or len(url) > 2048
                    or type(headers) is not dict or len(headers) > 64
                    or any(type(k) is not str or type(v) is not str or len(k) > 128 or len(v) > 4096
                           or '\r' in k + v or '\n' in k + v for k, v in headers.items())
                    or request['method'] not in ('GET', 'POST', 'PATCH')
                    or type(maximum) is not int or not 0 < maximum <= _MAXIMUM):
                raise ValueError('public-http-worker-scope')
            repository = require_repository(request['repository'])
            if not _request_scope(repository, request['method'], url.removeprefix('https://api.github.com'), request['body']):
                raise ValueError('public-http-worker-scope')
            raw = canonical_json(request['body']) if request['body'] is not None else None
            status, body = _read_http(opener, request['method'], url, headers, raw, deadline, time.monotonic, maximum)
            result = struct.pack('!II', status, len(body)) + body
        else:
            if set(request) != {'action', 'purpose', 'app_id', 'installation_id', 'key_path', 'token_request', 'maximums', 'remaining_ns'}:
                raise ValueError('public-token-worker-input')
            from .github_app import generate_app_jwt
            from .models import utc_now
            ids = request['token_request'].get('repository_ids')
            checks = 'read' if request['purpose'] == 'observer' else 'write'
            if (request['purpose'] not in ('observer', 'publisher') or type(request['app_id']) is not int or request['app_id'] <= 0
                    or type(request['installation_id']) is not int or request['installation_id'] <= 0
                    or not isinstance(ids, list) or len(ids) != 1 or type(ids[0]) is not int or ids[0] <= 0
                    or request['token_request'] != {'repository_ids': ids, 'permissions': {
                        'checks': checks, 'actions': 'read', 'contents': 'read', 'pull_requests': 'read'}}
                    or type(request['maximums']) is not list or len(request['maximums']) != 2
                    or any(type(n) is not int or not 0 < n <= 524288 for n in request['maximums'])):
                raise ValueError('public-token-worker-scope')
            key = _read_app_key(Path(request['key_path']))
            jwt = generate_app_jwt(request['app_id'], key, now=utc_now())
            headers = {'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                       'Authorization': 'Bearer ' + jwt, 'X-GitHub-Api-Version': '2026-03-10'}
            installation = request['installation_id']
            _, raw = _read_http(opener, 'GET', f'https://api.github.com/app/installations/{installation}',
                                headers, None, deadline, time.monotonic, request['maximums'][0])
            observed = bounded_json(raw, maximum=request['maximums'][0])
            if (type(observed.get('id')) is not int or type(observed.get('app_id')) is not int
                    or observed['id'] != installation or observed['app_id'] != request['app_id']):
                raise ValueError('public-token-installation-mismatch')
            status, token = _read_http(opener, 'POST', f'https://api.github.com/app/installations/{installation}/access_tokens',
                                      headers, canonical_json(request['token_request']), deadline,
                                      time.monotonic, request['maximums'][1])
            result = struct.pack('!III', status, len(raw), len(token)) + token
        _time(time.monotonic, deadline)
        sys.stdout.buffer.write(result)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        sys.stderr.write('public-http-worker-refused\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(_worker_main() if sys.argv[1:] == ['--public-http-worker'] else 2)
