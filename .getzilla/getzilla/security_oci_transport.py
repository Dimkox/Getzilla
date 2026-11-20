"""Explicit public OCI pull into owned logical-byte storage; no daemon or credentials."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import stat
import sys
import threading
import time
from urllib.parse import urlencode, urlsplit

from .security_oci_layout import (ARTIFACT_BYTES, INDEX_BYTES, Budget, OCIError,
                                  CONFIG_MEDIA, LAYER_MEDIA, MANIFEST_MEDIA, digest,
                                  identity, json_object, open_directory, pack_layout, safe_name,
                                  validate_layout, read_directory, read_owned_file,
                                  open_directory_chain, verify_directory_chain)

REGISTRIES = {'docker.io': ('registry-1.docker.io', 'auth.docker.io', 'registry.docker.io'),
              'ghcr.io': ('ghcr.io', 'ghcr.io', 'ghcr.io')}


def validate_network_selection(selection, *, required=()):
    """Literal public peers only. TLS still authenticates the original hostname."""
    allowed = {'registry-1.docker.io', 'auth.docker.io', 'ghcr.io'}
    if (not isinstance(selection, dict) or not selection or set(selection) - allowed
            or not set(required) <= set(selection)):
        raise OCIError('explicit fixed-host numeric network selection required before I/O')
    result = {}
    for host, addresses in selection.items():
        if not isinstance(addresses, list) or not 1 <= len(addresses) <= 4:
            raise OCIError('OCI numeric address count exceeds selected subset')
        observed = set()
        for text in addresses:
            if not isinstance(text, str) or len(text) > 64 or '%' in text:
                raise OCIError('OCI peer must be an unscoped numeric global address')
            try:
                address = ipaddress.ip_address(text)
            except ValueError as exc:
                raise OCIError('OCI automatic DNS is unqualified; select literal addresses') from exc
            if (not address.is_global or address.is_private or address.is_loopback or address.is_link_local
                    or address.is_reserved or address.is_multicast or address.is_unspecified
                    or (getattr(address, 'ipv4_mapped', None) is not None and not address.ipv4_mapped.is_global)):
                raise OCIError('OCI peer is not an admitted global unicast address')
            if str(address) in observed:
                raise OCIError('duplicate OCI numeric peer')
            observed.add(str(address))
        result[host] = list(addresses)
    return result


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


def _https(url, *, headers, timeout, budget, network_selection):
    """Direct numeric connect; no resolver/proxy/credentials. Hold both socket owners."""
    parsed = urlsplit(url)
    selected = validate_network_selection(network_selection, required={parsed.hostname})
    defaults = ssl.get_default_verify_paths()
    context = ssl.create_default_context(cafile=defaults.openssl_cafile, capath=defaults.openssl_capath)
    if context.minimum_version < ssl.TLSVersion.TLSv1_2:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    budget.check()
    connection = http.client.HTTPSConnection(parsed.hostname, timeout=timeout, context=context)
    connection.auto_open = 0  # HTTPConnection must never perform its DNS-based connect.
    held_sockets = []
    def abort():
        # HTTPResponse may detach connection.sock; these original owners remain live.
        for peer in tuple(reversed(held_sockets)):
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                peer.close()
            except OSError:
                pass
    timer = threading.Timer(max(0, budget.deadline - budget.clock()), abort)
    timer.daemon = True
    class Response(http.client.HTTPResponse):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.fp = _CountedReader(self.fp, budget)
    connection.response_class = Response
    timer.start()
    try:
        connected = False
        for text in selected[parsed.hostname]:
            budget.check()
            address = ipaddress.ip_address(text)
            raw = socket.socket(socket.AF_INET if address.version == 4 else socket.AF_INET6, socket.SOCK_STREAM)
            held_sockets.append(raw)
            raw.settimeout(min(timeout, max(0.001, budget.deadline - budget.clock())))
            try:
                # socket.create_connection would invoke getaddrinfo even for literals.
                raw.connect((str(address), 443))
                budget.check()
                secured = context.wrap_socket(raw, server_hostname=parsed.hostname, do_handshake_on_connect=False)
                held_sockets.append(secured)
                secured.settimeout(min(timeout, max(0.001, budget.deadline - budget.clock())))
                secured.do_handshake()
                budget.check()
                connection.sock = secured
                connected = True
                break
            except OSError:
                raw.close()
                budget.check()
        if not connected:
            raise OCIError('selected OCI numeric peers unavailable')
        target = parsed.path + (('?' + parsed.query) if parsed.query else '')
        request_headers = {'Host': parsed.hostname, 'Accept-Encoding': 'identity', **headers}
        request_bytes = ('GET ' + target + ' HTTP/1.1\r\n' + ''.join(key + ': ' + value + '\r\n' for key, value in request_headers.items()) + '\r\n').encode('ascii')
        budget.charge('wire', len(request_bytes))
        connection.request('GET', target, headers=request_headers)
        response = connection.getresponse()
        budget.check()
        response.accounted = True
        old_close = response.close
        def close():
            try:
                old_close()
            finally:
                timer.cancel()
                if threading.current_thread() is not timer:
                    timer.join()
                abort()
                connection.close()
        response.close = close
        return response
    except BaseException:
        timer.cancel()
        if threading.current_thread() is not timer:
            timer.join()
        abort()
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


def _fetch(url, budget, opener, *, headers=None, maximum=ARTIFACT_BYTES, network_selection=None):
    budget.check()
    parsed = urlsplit(url)
    allowed = {'registry-1.docker.io', 'auth.docker.io', 'ghcr.io'}
    if (parsed.scheme != 'https' or parsed.hostname not in allowed or parsed.port not in {None, 443}
            or parsed.username is not None or parsed.password is not None or parsed.fragment):
        raise OCIError('unqualified OCI HTTPS origin')
    selected = validate_network_selection(network_selection, required={parsed.hostname})
    response = None
    try:
        kwargs = {'headers': {'Accept-Encoding': 'identity', **(headers or {})},
                  'timeout': min(5, max(0.001, budget.deadline - budget.clock()))}
        response = opener(url, **kwargs) if opener is not None else _https(url, budget=budget, network_selection=selected, **kwargs)
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


def _registry_get(host, repository, suffix, budget, opener, token, maximum, network_selection):
    registry, auth, service = REGISTRIES[host]
    url = 'https://' + registry + '/v2/' + repository + '/' + suffix
    headers = {'Accept': ', '.join(sorted(MANIFEST_MEDIA))}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    status, fields, raw = _fetch(url, budget, opener, headers=headers, maximum=maximum, network_selection=network_selection)
    if status == 401 and token is None:
        expected_realm = 'https://' + auth + ('/token' if host == 'docker.io' else '/token')
        challenge = fields['challenge']
        match = re.fullmatch(r'Bearer realm="([^"\r\n]+)",service="([^"\r\n]+)",scope="([^"\r\n]+)"', challenge)
        scope = 'repository:' + repository + ':pull'
        if not match or match.groups() != (expected_realm, service, scope):
            raise OCIError('unqualified OCI anonymous challenge')
        token_url = expected_realm + '?' + urlencode({'service': service, 'scope': scope})
        status, _, body = _fetch(token_url, budget, opener, maximum=min(65536, budget.profile['max_manifest_bytes']), network_selection=network_selection)
        if status != 200:
            raise OCIError('OCI anonymous token unavailable')
        try:
            document = json_object(body, budget)
        except OCIError:
            raise OCIError('invalid OCI anonymous token response') from None
        token = document.get('token') or document.get('access_token')
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9._~-]{1,16384}', token):
            raise OCIError('invalid OCI anonymous token')
        status, _, raw = _fetch(url, budget, opener, headers={**headers, 'Authorization': 'Bearer ' + token}, maximum=maximum, network_selection=network_selection)
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
                   deadline=None, now=None, storage_mode='logical-files', binding=None, network_selection=None):
    """Acquire exact child manifests only. Output is UNVERIFIED, never a scan/catalog."""
    budget = _selection(subjects, profile, storage_mode, clock, deadline)
    _binding(binding)
    required_hosts = set()
    for subject in subjects:
        host = subject['reference'].split('/', 1)[0]
        required_hosts.update(REGISTRIES[host][:2])
    selected_network = validate_network_selection(network_selection, required=required_hosts)
    root = Path(destination).absolute()
    descriptor = lock = None
    root_handles = []
    written, directory_handles = {}, {}
    run = 'run-' + secrets.token_hex(12)
    published = False
    try:
        root_handles = open_directory_chain(root)
        descriptor = root_handles[-1]
        root_stat = os.fstat(descriptor)
        if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
            raise OCIError('OCI output root must be exclusively owned0700')
        lock = os.open('.writer.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        _storage_usage(descriptor, budget)
        os.mkdir(run, 0o700, dir_fd=descriptor)
        directories = {run}
        directory_handles[run] = os.open(run, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
        def write(relative, raw):
            safe_name(relative)
            budget.charge('storage', len(raw))
            budget.charge('members', 1)
            parent = os.dup(descriptor)
            try:
                parts = relative.split('/')
                for index, part in enumerate(parts[:-1], 1):
                    created = False
                    try:
                        os.mkdir(part, 0o700, dir_fd=parent)
                        directories.add('/'.join(parts[:index]))
                        created = True
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    selected_name = '/'.join(parts[:index])
                    if selected_name in directory_handles:
                        if identity(os.fstat(directory_handles[selected_name]))[:2] != identity(os.fstat(child))[:2]:
                            os.close(child)
                            raise OCIError('OCI writer directory was replaced')
                    elif created:
                        directory_handles[selected_name] = os.dup(child)
                    else:
                        os.close(child)
                        raise OCIError('OCI writer refuses an unowned directory')
                    os.close(parent)
                    parent = child
                fd = os.open(parts[-1], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
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
                    written[relative] = {'fd': fd, 'identity': identity(os.fstat(fd)),
                                         'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
                except BaseException:
                    os.close(fd)
                    raise
                os.fsync(parent)
            finally:
                os.close(parent)
        def verify_written(*, published_pointer=None):
            """Pin the original FDs and rebind every name, including the rename target."""
            verify_directory_chain(root, root_handles)
            expected_children = {name: set() for name in directory_handles}
            for name in [*directory_handles, *written]:
                if name == published_pointer:
                    continue
                parent_name, _, child_name = name.rpartition('/')
                if parent_name in expected_children:
                    expected_children[parent_name].add(child_name)
            for name, fd in directory_handles.items():
                budget.check()
                current_fd = open_directory(root / name)
                try:
                    if identity(os.fstat(fd))[:2] != identity(os.fstat(current_fd))[:2]:
                        raise OCIError('OCI original directory identity changed')
                    if set(os.listdir(current_fd)) != expected_children[name]:
                        raise OCIError('OCI writer namespace gained or lost an object')
                finally:
                    os.close(current_fd)
            for name, saved in written.items():
                budget.check()
                fd = saved['fd']
                before = os.fstat(fd)
                expected = saved['identity'][:4] if name == published_pointer else saved['identity']
                observed = identity(before)[:4] if name == published_pointer else identity(before)
                if observed != expected or before.st_nlink != 1:
                    raise OCIError('OCI original written inode was changed/replaced')
                os.lseek(fd, 0, os.SEEK_SET)
                total, checksum = 0, hashlib.sha256()
                while True:
                    budget.check()
                    block = os.read(fd, min(65536, saved['bytes'] - total + 1))
                    if not block:
                        break
                    total += len(block)
                    if total > saved['bytes']:
                        raise OCIError('OCI original FD grew')
                    checksum.update(block)
                current_name = 'manifest.json' if name == published_pointer else name
                body, named_identity = read_owned_file(root, current_name, saved['bytes'], budget=budget)
                if (identity(os.fstat(fd)) != identity(before) or named_identity != identity(before)
                        or total != saved['bytes'] or checksum.hexdigest() != saved['sha256']
                        or hashlib.sha256(body).hexdigest() != saved['sha256']):
                    raise OCIError('OCI original FD/content/name binding differs')
            verify_directory_chain(root, root_handles)
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
                    budget, open_url, None, min(INDEX_BYTES, profile['max_manifest_bytes']), selected_network)
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
                    raw, token = _registry_get(host, repository, 'blobs/' + item['digest'], budget, open_url, token, item['size'], selected_network)
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
                physical = read_directory(root / layout_name, reference, profile['platform'], budget=budget, validate=False)
                archive_bytes, _ = read_owned_file(root, archive_name, budget=budget)
                if (physical['objects'] != objects or hashlib.sha256(archive_bytes).digest() != hashlib.sha256(archive).digest()):
                    raise OCIError('OCI stored bytes changed before publication')
                verify_written()
                retained[reference] = {'layout': layout_name, 'archive': archive_name,
                    'archive_sha256': hashlib.sha256(archive).hexdigest(), 'archive_bytes': len(archive),
                    'manifest_digest': validated['manifest_digest'], 'config_digest': validated['config_digest'],
                    'diff_ids': validated['diff_ids'], 'platform': profile['platform'],
                    'objects': {name: {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)} for name, raw in objects.items()},
                    'object_identities': {name: list(written[layout_name + '/' + name]['identity']) for name in objects},
                    'archive_identity': list(written[archive_name]['identity'])}
            if subject.get('image_id') is not None and subject['image_id'] != retained[reference]['config_digest']:
                raise OCIError('declared OCI ImageID differs from actual config')
            records.append({**retained[reference], 'subject': dict(subject), 'acquired_at': current.astimezone(timezone.utc).isoformat()})
        body = {'schema_version': 1, 'kind': 'bounded-oci-acquisition', 'status': 'acquired',
                'qualification': 'UNVERIFIED', 'storage_mode': storage_mode, 'profile': profile,
                'network_selection': selected_network,
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
        verify_written()
        # Durable immutable files precede the only mutable pointer publication.
        os.replace(pointer, 'manifest.json', src_dir_fd=descriptor, dst_dir_fd=descriptor)
        published = True
        verify_written(published_pointer=pointer)
        source_parent = open_directory(root / run)
        try:
            os.fsync(source_parent)
        finally:
            os.close(source_parent)
        os.fsync(descriptor)
        verify_written(published_pointer=pointer)
        return body
    except (OSError, ValueError, TypeError, KeyError) as exc:
        if published:
            raise OCIError('OCI post-publication durability uncertain; do not retry blindly') from exc
        if isinstance(exc, OCIError):
            raise
        raise OCIError('OCI acquisition refused before publication') from exc
    finally:
        original_error = sys.exc_info()[1]
        cleanup_errors = []
        def cleanup(operation):
            try:
                operation()
            except FileNotFoundError:
                pass
            except OSError as error:
                cleanup_errors.append(type(error).__name__)
        if descriptor is not None:
            if not published:
                def remove_run():
                    owned_run = directory_handles.get(run)
                    if owned_run is not None and identity(os.stat(run, dir_fd=descriptor, follow_symlinks=False))[:2] == identity(os.fstat(owned_run))[:2]:
                        shutil.rmtree(run, dir_fd=descriptor)
                cleanup(remove_run)
            if lock is not None:
                def remove_lock():
                    if identity(os.stat('.writer.lock', dir_fd=descriptor, follow_symlinks=False))[:2] == identity(os.fstat(lock))[:2]:
                        os.unlink('.writer.lock', dir_fd=descriptor)
                cleanup(remove_lock)
                cleanup(lambda: os.close(lock))
            for saved in written.values():
                cleanup(lambda: os.close(saved['fd']))
            for fd in directory_handles.values():
                cleanup(lambda: os.close(fd))
        for fd in reversed(root_handles):
            cleanup(lambda: os.close(fd))
        if cleanup_errors:
            message = 'OCI cleanup incomplete; owned resources may remain; do not retry blindly'
            if original_error is not None:
                original_error.add_note(message)
            else:
                raise OCIError('OCI post-publication durability uncertain; ' + message)


def retained_acquisition(root, subjects, *, binding, now=None, profile=None, network_selection=None):
    """Reacquire the exact current source/run envelope; never renew saved age."""
    _binding(binding)
    selected_network = validate_network_selection(network_selection)
    raw, physical = read_owned_file(root, 'manifest.json', INDEX_BYTES)
    body = json_object(raw, Budget())
    if (body.get('schema_version') != 1 or body.get('kind') != 'bounded-oci-acquisition'
            or body.get('qualification') != 'UNVERIFIED' or body.get('status') != 'acquired'
            or binding is None or body.get('binding') != binding or body.get('profile') != profile
            or body.get('network_selection') != selected_network):
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
            snapshot = read_directory(Path(root) / record['layout'], subject['reference'], record['platform'], budget=selected, validate=False)
            if ({name: list(snapshot['identities'][name]) for name in snapshot['objects']} != record['object_identities']
                    or {name: {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)} for name, raw in snapshot['objects'].items()} != record['objects']):
                raise OCIError('OCI originally acquired object identity/content differs')
            archive, archive_identity = read_owned_file(root, record['archive'], budget=selected)
            if (list(archive_identity) != record['archive_identity'] or len(archive) != record['archive_bytes']
                    or hashlib.sha256(archive).hexdigest() != record['archive_sha256']):
                raise OCIError('OCI originally acquired archive identity/content differs')
        except (ValueError, KeyError, TypeError) as exc:
            raise OCIError('OCI retained metadata is invalid') from exc
    body['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
    body['manifest_identity'] = physical
    return body
