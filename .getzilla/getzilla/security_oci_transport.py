"""Explicit public OCI pull into owned logical-byte storage; no daemon or credentials."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import stat
import threading
import time
from urllib.parse import urlencode, urlsplit

from .security_oci_layout import (ARTIFACT_BYTES, INDEX_BYTES, Budget, OCIError,
                                  CONFIG_MEDIA, LAYER_MEDIA, MANIFEST_MEDIA, digest,
                                  identity, json_object, open_directory, pack_layout, safe_name,
                                  validate_layout, read_directory, read_owned_file)

REGISTRIES = {'docker.io': ('registry-1.docker.io', 'auth.docker.io', 'registry.docker.io'),
              'ghcr.io': ('ghcr.io', 'ghcr.io', 'ghcr.io')}


class _CountedReader:
    def __init__(self, stream, budget):
        self.stream, self.budget = stream, budget
        self.line_bytes = 0

    def _read(self, method, count=-1):
        self.budget.check()
        remaining = self.budget.profile['max_compressed_bytes'] - self.budget.wire
        size = min(65536 if count < 0 else count, remaining + 1)
        line_remaining = min(65536, self.budget.profile['max_manifest_bytes']) - self.line_bytes
        if method == 'readline':
            size = min(size, line_remaining + 1)
        raw = getattr(self.stream, method)(size)
        if method == 'readline':
            if len(raw) > line_remaining:
                raise OCIError('OCI HTTP headers/framing exceed bound')
            self.line_bytes += len(raw)
        self.budget.charge('wire', len(raw))
        return raw

    def read(self, count=-1):
        return self._read('read', count)

    def read1(self, count=-1):
        return self._read('read1', count)

    def readline(self, count=-1):
        return self._read('readline', count)

    def close(self):
        self.stream.close()

    def __getattr__(self, name):
        return getattr(self.stream, name)


def _https(url, *, headers, timeout, budget):
    """No proxy/environment/credential lookup; account response headers/framing too."""
    parsed = urlsplit(url)
    defaults = ssl.get_default_verify_paths()
    context = ssl.create_default_context(cafile=defaults.openssl_cafile, capath=defaults.openssl_capath)
    connection = http.client.HTTPSConnection(parsed.hostname, timeout=timeout, context=context)
    def abort():
        if connection.sock is not None:
            try:
                connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()
    timer = threading.Timer(max(0, budget.deadline - budget.clock()), abort)
    timer.daemon = True
    class Response(http.client.HTTPResponse):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.fp = _CountedReader(self.fp, budget)
    connection.response_class = Response
    timer.start()
    try:
        target = parsed.path + (('?' + parsed.query) if parsed.query else '')
        request_headers = {'Host': parsed.hostname, 'Accept-Encoding': 'identity', **headers}
        request_bytes = ('GET ' + target + ' HTTP/1.1\r\n' + ''.join(key + ': ' + value + '\r\n' for key, value in request_headers.items()) + '\r\n').encode('ascii')
        budget.charge('wire', len(request_bytes))
        connection.request('GET', target, headers=request_headers)
        response = connection.getresponse()
        response.accounted = True
        old_close = response.close
        def close():
            old_close()
            timer.cancel()
            if threading.current_thread() is not timer:
                timer.join()
            connection.close()
        response.close = close
        return response
    except BaseException:
        timer.cancel()
        timer.join()
        connection.close()
        raise


def _selection(subjects, profile, storage_mode, clock, deadline):
    budget = Budget(profile, clock=clock, deadline=deadline)
    if storage_mode != 'logical-files':
        raise OCIError('physical quota enforcement is not qualified')
    if not isinstance(subjects, list) or not subjects or len(subjects) > 512:
        raise OCIError('complete bounded OCI source occurrences required')
    refs = []
    for subject in subjects:
        if not isinstance(subject, dict):
            raise OCIError('invalid OCI subject')
        allowed = {'reference', 'source_reference', 'manifest', 'line', 'kind', 'platform', 'usage',
                   'source_sha256', 'image_id', 'distribution', 'delivery_kind', 'delivery_context', 'target_environment'}
        if set(subject) - allowed or subject.get('kind', 'oci-image') != 'oci-image':
            raise OCIError('unknown OCI source role or context field')
        reference = subject.get('reference', '')
        if not isinstance(reference, str) or len(reference) > 1024:
            raise OCIError('invalid bounded OCI reference')
        match = re.fullmatch(r'(docker\.io|ghcr\.io)/([a-z0-9][a-z0-9._/-]*)@(sha256:[0-9a-f]{64})', reference)
        if (not match or any(not re.fullmatch(r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*', part) for part in match[2].split('/'))
                or subject.get('platform') != profile['platform']
                or not re.fullmatch('[0-9a-f]{64}', str(subject.get('source_sha256', '')))
                or type(subject.get('line')) is not int or not 1 <= subject['line'] <= 1000000):
            raise OCIError('unqualified public OCI source identity/platform')
        safe_name(subject.get('manifest'))
        try:
            if len(json.dumps(subject, allow_nan=False).encode()) > min(INDEX_BYTES, profile['max_manifest_bytes']):
                raise OCIError('OCI source context exceeds metadata bound')
        except (TypeError, ValueError) as exc:
            raise OCIError('OCI source context is not bounded JSON') from exc
        refs.append(reference)
    if sorted(set(refs)) != profile['images'] or len(set(refs)) > profile['max_images']:
        raise OCIError('OCI profile differs from selected subjects')
    return budget


def _binding(value):
    if value is None:
        return  # Standalone acquisition is UNVERIFIED and cannot enter a scan consumer.
    source_keys = {'head_sha', 'tree_sha', 'checker_sha', 'checker_tree_sha', 'candidate_clean', 'checker_clean', 'same_project'}
    run_keys = {'provider', 'repository', 'run_id', 'run_attempt', 'head_sha'}
    if (not isinstance(value, dict) or set(value) != {'source', 'inventory_sha256', 'policy_sha256', 'run'}
            or not isinstance(value['source'], dict) or set(value['source']) != source_keys
            or not isinstance(value['run'], dict) or set(value['run']) != run_keys
            or any(not re.fullmatch('[0-9a-f]{64}', str(value[key])) for key in ('inventory_sha256', 'policy_sha256'))
            or any(not re.fullmatch('[0-9a-f]{40}', str(value['source'][key])) for key in ('head_sha', 'tree_sha', 'checker_sha', 'checker_tree_sha'))
            or value['source']['candidate_clean'] is not True or value['source']['checker_clean'] is not True
            or type(value['source']['same_project']) is not bool
            or value['run']['provider'] != 'github-actions' or value['run']['head_sha'] != value['source']['head_sha']
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', str(value['run']['repository']))
            or any(not isinstance(value['run'][key], str) or not re.fullmatch(r'[0-9]{1,32}', value['run'][key]) for key in ('run_id', 'run_attempt'))):
        raise OCIError('OCI source/policy/run envelope is incomplete or malformed')


def _fetch(url, budget, opener, *, headers=None, maximum=ARTIFACT_BYTES):
    budget.check()
    parsed = urlsplit(url)
    allowed = {'registry-1.docker.io', 'auth.docker.io', 'ghcr.io'}
    if (parsed.scheme != 'https' or parsed.hostname not in allowed or parsed.port not in {None, 443}
            or parsed.username is not None or parsed.password is not None or parsed.fragment):
        raise OCIError('unqualified OCI HTTPS origin')
    response = None
    try:
        kwargs = {'headers': {'Accept-Encoding': 'identity', **(headers or {})},
                  'timeout': min(5, max(0.001, budget.deadline - budget.clock()))}
        response = opener(url, **kwargs) if opener is not None else _https(url, budget=budget, **kwargs)
        response_headers = response.headers
        rows = list(response_headers.items())
        header_size = sum(len(str(key).encode()) + len(str(value).encode()) + 4 for key, value in rows)
        if header_size > min(65536, budget.profile['max_manifest_bytes']):
            raise OCIError('OCI response headers exceed bound')
        accounted = getattr(response, 'accounted', False) is True
        if not accounted:
            budget.charge('wire', header_size)
        if response_headers.get('Content-Encoding', 'identity').lower() != 'identity':
            raise OCIError('unexpected OCI HTTP encoding')
        if hasattr(response_headers, 'get_all') and len(response_headers.get_all('Content-Length', [])) > 1:
            raise OCIError('ambiguous OCI content length')
        if hasattr(response_headers, 'get_all') and len(response_headers.get_all('WWW-Authenticate', [])) > 1:
            raise OCIError('ambiguous OCI anonymous challenge')
        length = response_headers.get('Content-Length')
        if length is not None and (not length.isdecimal() or int(length) > maximum):
            raise OCIError('OCI declared response exceeds selected bound')
        if length is not None and response_headers.get('Transfer-Encoding'):
            raise OCIError('ambiguous OCI transfer length')
        chunks, count = [], 0
        while True:
            budget.check()
            remaining = min(maximum - count, budget.profile['max_compressed_bytes'] - budget.wire)
            raw = response.read1(min(65536, remaining + 1))
            if not isinstance(raw, bytes) or len(raw) > remaining:
                raise OCIError('OCI streamed response exceeds selected bound')
            if not accounted:
                budget.charge('wire', len(raw))
            if not raw:
                break
            chunks.append(raw)
            count += len(raw)
        if length is not None and count != int(length):
            raise OCIError('OCI response length differs')
        # Only fixed protocol fields survive; never retain Authorization/token/Location.
        return response.status, {'challenge': response_headers.get('WWW-Authenticate', '')}, b''.join(chunks)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        if isinstance(exc, OCIError):
            raise
        raise OCIError('bounded OCI HTTPS request failed') from exc
    finally:
        if response is not None:
            response.close()


def _registry_get(host, repository, suffix, budget, opener, token, maximum):
    registry, auth, service = REGISTRIES[host]
    url = 'https://' + registry + '/v2/' + repository + '/' + suffix
    headers = {'Accept': ', '.join(sorted(MANIFEST_MEDIA))}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    status, fields, raw = _fetch(url, budget, opener, headers=headers, maximum=maximum)
    if status == 401 and token is None:
        expected_realm = 'https://' + auth + ('/token' if host == 'docker.io' else '/token')
        challenge = fields['challenge']
        match = re.fullmatch(r'Bearer realm="([^"\r\n]+)",service="([^"\r\n]+)",scope="([^"\r\n]+)"', challenge)
        scope = 'repository:' + repository + ':pull'
        if not match or match.groups() != (expected_realm, service, scope):
            raise OCIError('unqualified OCI anonymous challenge')
        token_url = expected_realm + '?' + urlencode({'service': service, 'scope': scope})
        status, _, body = _fetch(token_url, budget, opener, maximum=min(65536, budget.profile['max_manifest_bytes']))
        if status != 200:
            raise OCIError('OCI anonymous token unavailable')
        try:
            document = json_object(body, budget)
        except OCIError:
            raise OCIError('invalid OCI anonymous token response') from None
        token = document.get('token') or document.get('access_token')
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9._~-]{1,16384}', token):
            raise OCIError('invalid OCI anonymous token')
        status, _, raw = _fetch(url, budget, opener, headers={**headers, 'Authorization': 'Bearer ' + token}, maximum=maximum)
    if status != 200:
        raise OCIError('OCI status/redirect is not qualified')
    return raw, token


def _storage_usage(descriptor, budget, depth=0):
    if depth > 8:
        raise OCIError('unexpected OCI storage tree')
    for name in os.listdir(descriptor):
        budget.check()
        budget.charge('members', 1)
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                _storage_usage(child, budget, depth + 1)
            finally:
                os.close(child)
        elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
            budget.charge('storage', before.st_size)
        else:
            raise OCIError('OCI storage has unowned/link objects')


def acquire_images(subjects, profile, destination, *, open_url=None, clock=time.monotonic,
                   deadline=None, now=None, storage_mode='logical-files', binding=None):
    """Acquire exact child manifests only. Output is UNVERIFIED, never a scan/catalog."""
    budget = _selection(subjects, profile, storage_mode, clock, deadline)
    _binding(binding)
    root = Path(destination).absolute()
    descriptor = lock = None
    run = 'run-' + secrets.token_hex(12)
    published = False
    try:
        descriptor = open_directory(root)
        root_stat = os.fstat(descriptor)
        if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
            raise OCIError('OCI output root must be exclusively owned0700')
        lock = os.open('.writer.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        _storage_usage(descriptor, budget)
        os.mkdir(run, 0o700, dir_fd=descriptor)
        directories = {run}
        def write(relative, raw):
            safe_name(relative)
            budget.charge('storage', len(raw))
            budget.charge('members', 1)
            parent = os.dup(descriptor)
            try:
                parts = relative.split('/')
                for index, part in enumerate(parts[:-1], 1):
                    try:
                        os.mkdir(part, 0o700, dir_fd=parent)
                        directories.add('/'.join(parts[:index]))
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    os.close(parent)
                    parent = child
                fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                try:
                    view = memoryview(raw)
                    while view:
                        budget.check()
                        size = os.write(fd, view[:65536])
                        if size <= 0:
                            raise OCIError('OCI write did not progress')
                        view = view[size:]
                    os.fsync(fd)
                    if os.fstat(fd).st_size != len(raw) or os.fstat(fd).st_nlink != 1:
                        raise OCIError('OCI stored object differs')
                finally:
                    os.close(fd)
                os.fsync(parent)
            finally:
                os.close(parent)
        records, retained = [], {}
        current = now or datetime.now(timezone.utc)
        if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
            raise OCIError('OCI acquisition clock must be aware')
        for subject in subjects:
            budget.check()
            reference = subject['reference']
            if reference not in retained:
                host, tail = reference.split('/', 1)
                repository, selected = tail.rsplit('@', 1)
                manifest_raw, token = _registry_get(host, repository, 'manifests/' + selected,
                    budget, open_url, None, min(INDEX_BYTES, profile['max_manifest_bytes']))
                if digest(manifest_raw) != selected:
                    raise OCIError('downloaded OCI manifest digest differs')
                manifest = json_object(manifest_raw, budget)
                if manifest.get('mediaType') not in MANIFEST_MEDIA or manifest.get('schemaVersion') != 2:
                    raise OCIError('OCI index/manifest selection is not qualified')
                descriptors = [manifest.get('config'), *(manifest.get('layers') or [])]
                if not isinstance(manifest.get('layers'), list) or not manifest['layers'] or len(manifest['layers']) > profile['max_layers']:
                    raise OCIError('OCI layer selection exceeds bound')
                objects = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}',
                    'index.json': json.dumps({'schemaVersion': 2, 'manifests': [{
                        'mediaType': manifest['mediaType'], 'digest': selected, 'size': len(manifest_raw),
                        'platform': dict(zip(('os', 'architecture'), profile['platform'].split('/')))}]}, sort_keys=True, separators=(',', ':')).encode(),
                    'blobs/sha256/' + selected[7:]: manifest_raw}
                for index, item in enumerate(descriptors):
                    media = CONFIG_MEDIA if index == 0 else LAYER_MEDIA
                    if (not isinstance(item, dict) or set(item) - {'mediaType', 'digest', 'size', 'annotations'}
                            or item.get('mediaType') not in media or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(item.get('digest', '')))
                            or type(item.get('size')) is not int or not 0 < item['size'] <= ARTIFACT_BYTES):
                        raise OCIError('unsupported OCI acquisition descriptor')
                    if sum(map(len, objects.values())) + item['size'] > ARTIFACT_BYTES:
                        raise OCIError('OCI acquired object set exceeds artifact bound')
                    raw, token = _registry_get(host, repository, 'blobs/' + item['digest'], budget, open_url, token, item['size'])
                    if len(raw) != item['size'] or digest(raw) != item['digest']:
                        raise OCIError('downloaded OCI blob digest differs')
                    objects['blobs/sha256/' + item['digest'][7:]] = raw
                validated = validate_layout(objects, reference, profile['platform'], budget=budget)
                layout_name = run + '/image-' + str(len(retained)) + '/layout'
                for name, raw in objects.items():
                    write(layout_name + '/' + name, raw)
                archive = pack_layout(objects)
                archive_name = run + '/image-' + str(len(retained)) + '/image.tar'
                write(archive_name, archive)
                # Reacquire the actual published file namespace, not the in-memory proof.
                physical = read_directory(root / layout_name, reference, profile['platform'], budget=budget)
                archive_bytes, _ = read_owned_file(root, archive_name, budget=budget)
                if (physical['objects'] != objects or hashlib.sha256(archive_bytes).digest() != hashlib.sha256(archive).digest()):
                    raise OCIError('OCI stored bytes changed before publication')
                retained[reference] = {'layout': layout_name, 'archive': archive_name,
                    'archive_sha256': hashlib.sha256(archive).hexdigest(), 'archive_bytes': len(archive),
                    'manifest_digest': validated['manifest_digest'], 'config_digest': validated['config_digest'],
                    'diff_ids': validated['diff_ids'], 'platform': profile['platform'],
                    'objects': {name: {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)} for name, raw in objects.items()}}
            if subject.get('image_id') is not None and subject['image_id'] != retained[reference]['config_digest']:
                raise OCIError('declared OCI ImageID differs from actual config')
            records.append({**retained[reference], 'subject': dict(subject), 'acquired_at': current.astimezone(timezone.utc).isoformat()})
        body = {'schema_version': 1, 'kind': 'bounded-oci-acquisition', 'status': 'acquired',
                'qualification': 'UNVERIFIED', 'storage_mode': storage_mode, 'profile': profile,
                'records': records, 'binding': binding, 'counters': {'wire_bytes': budget.wire, 'expanded_bytes': budget.expanded,
                'storage_high_water_bytes': budget.storage, 'layers': budget.layers}}
        for _ in range(8):
            raw = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
            high_water = budget.storage + len(raw)
            if body['counters']['storage_high_water_bytes'] == high_water:
                break
            body['counters']['storage_high_water_bytes'] = high_water
        else:
            raise OCIError('OCI publication accounting did not converge')
        if len(raw) > min(INDEX_BYTES, profile['max_manifest_bytes']):
            raise OCIError('OCI publication metadata exceeds bound')
        pointer = run + '/pointer.json'
        write(pointer, raw)
        budget.check()
        for name in sorted(directories, key=lambda value: value.count('/'), reverse=True):
            budget.check()
            child = open_directory(root / name)
            try:
                os.fsync(child)
            finally:
                os.close(child)
        os.fsync(descriptor)
        if identity(os.stat(root, follow_symlinks=False))[:2] != identity(root_stat)[:2]:
            raise OCIError('OCI selected root was replaced')
        # Durable immutable files precede the only mutable pointer publication.
        os.replace(pointer, 'manifest.json', src_dir_fd=descriptor, dst_dir_fd=descriptor)
        published = True
        source_parent = open_directory(root / run)
        try:
            os.fsync(source_parent)
        finally:
            os.close(source_parent)
        os.fsync(descriptor)
        return body
    except (OSError, ValueError, TypeError, KeyError) as exc:
        if published:
            raise OCIError('OCI post-publication durability uncertain; do not retry blindly') from exc
        if isinstance(exc, OCIError):
            raise
        raise OCIError('OCI acquisition refused before publication') from exc
    finally:
        if descriptor is not None:
            if not published:
                try:
                    shutil.rmtree(run, dir_fd=descriptor)
                except FileNotFoundError:
                    pass
            if lock is not None:
                try:
                    if identity(os.stat('.writer.lock', dir_fd=descriptor, follow_symlinks=False))[:2] == identity(os.fstat(lock))[:2]:
                        os.unlink('.writer.lock', dir_fd=descriptor)
                finally:
                    os.close(lock)
            os.close(descriptor)


def retained_acquisition(root, subjects, *, binding, now=None):
    """Reacquire the exact current source/run envelope; never renew saved age."""
    _binding(binding)
    raw, physical = read_owned_file(root, 'manifest.json', INDEX_BYTES)
    body = json_object(raw, Budget())
    if (body.get('schema_version') != 1 or body.get('kind') != 'bounded-oci-acquisition'
            or body.get('qualification') != 'UNVERIFIED' or body.get('status') != 'acquired'
            or binding is None or body.get('binding') != binding):
        raise OCIError('OCI retained source/policy/run binding differs')
    selected = _selection(subjects, body.get('profile'), body.get('storage_mode'), time.monotonic, None)
    selected.manifest(raw)
    records = body.get('records')
    if not isinstance(records, list) or len(records) != len(subjects):
        raise OCIError('OCI retained use coverage differs')
    current = now or datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise OCIError('OCI consumer clock must be aware')
    for record, subject in zip(records, subjects):
        if not isinstance(record, dict) or record.get('subject') != subject:
            raise OCIError('OCI retained subject differs')
        try:
            instant = datetime.fromisoformat(record['acquired_at'].replace('Z', '+00:00'))
            if instant.tzinfo is None or not 0 <= (current - instant).total_seconds() <= 259200:
                raise OCIError('OCI retained acquisition is stale/future')
            if not re.fullmatch(r'run-[0-9a-f]{24}/image-[0-9]+/layout', record['layout']):
                raise OCIError('OCI retained layout namespace differs')
            if record['archive'] != record['layout'].removesuffix('/layout') + '/image.tar':
                raise OCIError('OCI retained archive namespace differs')
        except (ValueError, KeyError, TypeError) as exc:
            raise OCIError('OCI retained metadata is invalid') from exc
    body['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
    body['manifest_identity'] = physical
    return body
