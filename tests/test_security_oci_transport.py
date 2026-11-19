"""NEW controlled public-OCI ports; no registry, daemon or scanner executes."""
import io
import json
from unittest import mock

from tests.test_security_oci_layout import OwnedOciCase, digest, owned_image, selected_profile, owned_binding, owned_network


class Response(io.BytesIO):
    def __init__(self, body, *, status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = {'Content-Length': str(len(body)), **(headers or {})}

    def read1(self, size=-1):
        return self.read(size)


def port_for(objects, reference, calls):
    manifest = reference.rsplit('@', 1)[1]
    def open_url(url, *, headers, timeout):
        calls.append({'url': url, 'headers': dict(headers), 'timeout': timeout})
        identifier = url.rsplit('/', 1)[1]
        raw = objects['blobs/sha256/' + identifier[7:]]
        if '/manifests/' in url:
            assert identifier == manifest
        return Response(raw)
    return open_url


class OciTransportContracts(OwnedOciCase):
    def test_cleanup_failures_release_all_fds_and_never_delete_foreign_lock(self):
        import os
        transport = self.module('security_oci_transport')
        _, reference = owned_image()
        subject = {'reference': reference, 'manifest': 'owned/source', 'line': 1,
                   'source_sha256': 'a' * 64, 'platform': 'linux/amd64'}
        for variant in ['rmtree', 'lock-stat', 'lock-unlink', 'foreign-lock']:
            destination = self.root / variant
            destination.mkdir(mode=0o700)
            opened, leaked = {}, []
            refusing = False
            actual_open, actual_stat, actual_unlink = os.open, os.stat, os.unlink
            def opening(*args, **kwargs):
                fd = actual_open(*args, **kwargs)
                observed = os.fstat(fd)
                opened[fd] = (observed.st_dev, observed.st_ino)
                return fd
            def statting(path, *args, **kwargs):
                if refusing and variant == 'lock-stat' and path == '.writer.lock':
                    raise PermissionError('NEW owned lock stat cut')
                return actual_stat(path, *args, **kwargs)
            def unlinking(path, *args, **kwargs):
                if refusing and variant == 'lock-unlink' and path == '.writer.lock':
                    raise PermissionError('NEW owned lock unlink cut')
                return actual_unlink(path, *args, **kwargs)
            def refuse(*args, **kwargs):
                nonlocal refusing
                refusing = True
                if variant == 'foreign-lock':
                    (destination / '.writer.lock').unlink()
                    (destination / '.writer.lock').write_bytes(b'foreign-owned lock')
                raise transport.OCIError('NEW original prepublication refusal')
            caught = None
            with (self.subTest(variant=variant), mock.patch.object(transport.os, 'open', side_effect=opening),
                  mock.patch.object(transport.os, 'stat', side_effect=statting),
                  mock.patch.object(transport.os, 'unlink', side_effect=unlinking),
                  mock.patch.object(transport.shutil, 'rmtree', side_effect=PermissionError('NEW owned run cleanup cut')) if variant == 'rmtree' else mock.patch.object(transport, 'REGISTRIES', transport.REGISTRIES)):
                try:
                    transport.acquire_images([subject], selected_profile(reference), destination,
                                             network_selection=owned_network(), open_url=refuse)
                except Exception as exc:
                    caught = exc
            for fd, inode in opened.items():
                try:
                    value = os.fstat(fd)
                    if (value.st_dev, value.st_ino) == inode:
                        leaked.append(fd)
                except OSError:
                    pass
            for fd in leaked:  # Always reap baseline leaked descriptors before asserting.
                os.close(fd)
            self.assertIsInstance(caught, transport.OCIError, variant)
            self.assertIn('NEW original prepublication refusal', str(caught), variant)
            self.assertEqual(leaked, [], variant)
            if variant == 'rmtree':
                self.assertFalse((destination / '.writer.lock').exists())
            if variant == 'foreign-lock':
                self.assertEqual((destination / '.writer.lock').read_bytes(), b'foreign-owned lock')

    def test_selected_root_swap_after_publication_is_uncertain(self):
        transport = self.module('security_oci_transport')
        objects, reference = owned_image()
        subject = {'reference': reference, 'manifest': 'owned/source', 'line': 1,
                   'source_sha256': 'a' * 64, 'platform': 'linux/amd64'}
        destination = self.root / 'selected'
        destination.mkdir(mode=0o700)
        actual_replace = transport.os.replace
        def publish(source, target, **kwargs):
            actual_replace(source, target, **kwargs)
            moved = self.root / 'original'
            destination.rename(moved)
            destination.mkdir(mode=0o700)
            for child in moved.iterdir():
                if child.name != '.writer.lock':
                    child.rename(destination / child.name)
        with mock.patch.object(transport.os, 'replace', side_effect=publish), self.assertRaisesRegex(transport.OCIError, 'uncertain'):
            transport.acquire_images([subject], selected_profile(reference), destination,
                                     network_selection=owned_network(), open_url=port_for(objects, reference, []))

    def test_last_retained_archive_read_refuses_ancestor_symlink_swap(self):
        transport = self.module('security_oci_transport')
        objects, reference = owned_image()
        subject = {'reference': reference, 'manifest': 'owned/source', 'line': 1,
                   'source_sha256': 'a' * 64, 'platform': 'linux/amd64'}
        parent = self.root / 'selected-parent'
        parent.mkdir(mode=0o700)
        destination = parent / 'oci'
        destination.mkdir(mode=0o700)
        binding = owned_binding()
        transport.acquire_images([subject], selected_profile(reference), destination, binding=binding,
                                 network_selection=owned_network(), open_url=port_for(objects, reference, []))
        transport.retained_acquisition(destination, [subject], binding=binding,
                                       profile=selected_profile(reference), network_selection=owned_network())
        actual_read = transport.os.read
        swapped = False
        def read(fd, count):
            nonlocal swapped
            body = actual_read(fd, count)
            if not swapped and body.startswith(b'blobs/sha256/'):
                swapped = True
                moved = self.root / 'moved-parent'
                parent.rename(moved)
                parent.symlink_to(moved, target_is_directory=True)
            return body
        with mock.patch.object(transport.os, 'read', side_effect=read), self.assertRaises(transport.OCIError):
            transport.retained_acquisition(destination, [subject], binding=binding,
                                           profile=selected_profile(reference), network_selection=owned_network())
        self.assertTrue(swapped, 'fixture must reach the final retained TAR read')

    def test_original_inode_and_pointer_are_pinned_through_publication(self):
        transport = self.module('security_oci_transport')
        layout = self.module('security_oci_layout')
        objects, reference = owned_image()
        subject = {'reference': reference, 'manifest': 'owned/source', 'line': 1,
                   'source_sha256': 'a' * 64, 'platform': 'linux/amd64'}
        for variant in ['object-before-read', 'object-at-publication', 'pointer-at-publication']:
            destination = self.root / variant
            destination.mkdir(mode=0o700)
            actual_read, actual_replace = layout.read_directory, transport.os.replace
            def swap(target):
                raw = target.read_bytes()
                target.unlink()
                target.write_bytes(raw)
            def read(path, *args, **kwargs):
                if variant == 'object-before-read':
                    swap(path / 'index.json')
                return actual_read(path, *args, **kwargs)
            def publish(source, target, **kwargs):
                if variant == 'object-at-publication':
                    swap(next(destination.glob('run-*/image-0/layout/index.json')))
                if variant == 'pointer-at-publication':
                    swap(destination / source)
                return actual_replace(source, target, **kwargs)
            with (self.subTest(variant=variant), mock.patch.object(transport, 'read_directory', side_effect=read),
                  mock.patch.object(transport.os, 'replace', side_effect=publish), self.assertRaises(transport.OCIError)):
                transport.acquire_images([subject], selected_profile(reference), destination, network_selection=owned_network(),
                                         open_url=port_for(objects, reference, []))

    def test_detached_response_socket_is_interrupted_by_absolute_deadline(self):
        import threading
        import time
        from types import SimpleNamespace
        transport = self.module('security_oci_transport')
        layout = self.module('security_oci_layout')
        _, reference = owned_image()
        for phase in ['connect', 'handshake', 'headers', 'body']:
            release, done, entered = threading.Event(), threading.Event(), threading.Event()
            observations, errors = [], []
            def block(selected):
                if phase == selected:
                    entered.set()
                    release.wait(1)
            class Peer:
                def settimeout(self, value):
                    pass
                def connect(self, address):
                    observations.append(('connect', address))
                    block('connect')
                def do_handshake(self):
                    block('handshake')
                def shutdown(self, how):
                    release.set()
                def close(self):
                    pass
            class Context:
                def wrap_socket(self, raw, *, server_hostname, do_handshake_on_connect):
                    observations.append(('sni', server_hostname, do_handshake_on_connect))
                    return Peer()
            class Body(Response):
                def read1(self, size=-1):
                    block('body')
                    return b''
            class Connection:
                def __init__(self, *args, **kwargs):
                    self.sock = None
                def request(self, *args, **kwargs):
                    pass
                def getresponse(self):
                    block('headers')
                    self.sock = None  # HTTPResponse can own the remaining socket.
                    return Body(b'')
                def close(self):
                    pass
            def consume():
                try:
                    budget = layout.Budget(selected_profile(reference), deadline=time.monotonic() + 0.04)
                    response = transport._https('https://registry-1.docker.io/v2/owned', headers={}, timeout=1,
                                                budget=budget, network_selection=owned_network())
                    try:
                        response.read1(1)
                    finally:
                        response.close()
                except transport.OCIError:
                    pass  # Expected when the deadline expires before response construction.
                except Exception as exc:
                    errors.append(type(exc).__name__)
                finally:
                    done.set()
            with (self.subTest(phase=phase), mock.patch.object(transport.socket, 'socket', side_effect=lambda *args: Peer()),
                  mock.patch.object(transport.http.client, 'HTTPSConnection', Connection),
                  mock.patch.object(transport.ssl, 'create_default_context', return_value=Context()),
                  mock.patch.object(transport.ssl, 'get_default_verify_paths', return_value=SimpleNamespace(openssl_cafile=None, openssl_capath=None))):
                worker = threading.Thread(target=consume)
                worker.start()
                try:
                    self.assertTrue(entered.wait(0.2), 'fixture never reached its blocking phase')
                    self.assertTrue(done.wait(0.2), 'selected phase exceeded the absolute deadline')
                finally:
                    release.set()
                    worker.join(1)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(observations[0], ('connect', ('93.184.216.34', 443)))
                if phase != 'connect':
                    self.assertIn(('sni', 'registry-1.docker.io', False), observations)

    def test_closed_numeric_selection_is_required_and_global_before_io(self):
        transport = self.module('security_oci_transport')
        method = getattr(transport, 'validate_network_selection', None)
        self.assertIsNotNone(method, 'missing admitted finite numeric selection')
        for selected in [None, {}, {'registry-1.docker.io': ['127.0.0.1']},
                         {'registry-1.docker.io': ['100.64.0.1']},
                         {'registry-1.docker.io': ['169.254.1.1']},
                         {'registry-1.docker.io': ['::ffff:127.0.0.1']},
                         {'registry-1.docker.io': ['2001:db8::1']},
                         {'registry-1.docker.io': ['fe80::1%eth0']},
                         {'private.invalid': ['93.184.216.34']},
                         {'registry-1.docker.io': ['93.184.216.34'] * 5}]:
            with self.subTest(selected=selected), self.assertRaises(transport.OCIError):
                method(selected, required={'registry-1.docker.io'})
        objects, reference = owned_image()
        subject = {'reference': reference, 'manifest': 'owned/source', 'line': 1,
                   'source_sha256': 'a' * 64, 'platform': 'linux/amd64'}
        for selected in [None, {}, {'ghcr.io': ['93.184.216.34']}]:
            absent = self.root / 'must-remain-absent'
            port = mock.Mock(side_effect=AssertionError('network selection must precede I/O'))
            with self.subTest(selected=selected), self.assertRaises(transport.OCIError):
                transport.acquire_images([subject], selected_profile(reference), absent,
                                         network_selection=selected, open_url=port)
            self.assertFalse(absent.exists())
            self.assertEqual(port.call_count, 0)

    def test_request_origin_guard_precedes_the_injected_port(self):
        transport = self.module('security_oci_transport')
        layout = self.module('security_oci_layout')
        _, reference = owned_image()
        calls = []
        def port(url, **kwargs):
            calls.append(url)
            return Response(b'new-owned')
        with self.assertRaises(transport.OCIError):
            transport._fetch('https://private.invalid/blob', layout.Budget(selected_profile(reference)), port, network_selection=owned_network())
        self.assertEqual(calls, [])

    def test_postpublication_flush_failure_is_uncertain_and_never_rolled_back(self):
        import os
        transport = self.module('security_oci_transport')
        objects, reference = owned_image()
        subject = {'reference': reference, 'manifest': 'owned/source', 'line': 1,
                   'source_sha256': 'a' * 64, 'platform': 'linux/amd64'}
        actual = os.fsync
        inode = self.root.stat().st_ino
        def fail_final(descriptor):
            if os.fstat(descriptor).st_ino == inode and (self.root / 'manifest.json').exists():
                raise OSError('NEW owned postpublication durability cut')
            return actual(descriptor)
        with mock.patch.object(transport.os, 'fsync', side_effect=fail_final), self.assertRaisesRegex(transport.OCIError, 'uncertain'):
            transport.acquire_images([subject], selected_profile(reference), self.root, network_selection=owned_network(),
                                     open_url=port_for(objects, reference, []))
        pointer = json.loads((self.root / 'manifest.json').read_text())
        self.assertEqual(pointer['qualification'], 'UNVERIFIED')
        self.assertTrue((self.root / pointer['records'][0]['layout']).is_dir())

    def test_final_physical_bytes_are_reacquired_before_publication(self):
        transport = self.module('security_oci_transport')
        layout = self.module('security_oci_layout')
        objects, reference = owned_image()
        subject = {'reference': reference, 'manifest': 'owned/Dockerfile', 'line': 1,
                   'source_sha256': 'd' * 64, 'platform': 'linux/amd64'}
        original = layout.read_directory
        def replace(path, *args, **kwargs):
            target = path / 'index.json'
            target.write_bytes(target.read_bytes() + b' ')
            return original(path, *args, **kwargs)
        with mock.patch.object(transport, 'read_directory', side_effect=replace), self.assertRaises(transport.OCIError):
            transport.acquire_images([subject], selected_profile(reference), self.root, network_selection=owned_network(),
                                     open_url=port_for(objects, reference, []))
        self.assertFalse((self.root / 'manifest.json').exists())

    def test_public_anonymous_challenge_is_scoped_and_token_never_persisted(self):
        transport = self.module('security_oci_transport')
        objects, reference = owned_image()
        subject = {'reference': reference, 'manifest': 'owned/Dockerfile', 'line': 1,
                   'source_sha256': 'd' * 64, 'platform': 'linux/amd64'}
        token = 'NEW-only-public-token-canary'
        calls = []
        plain = port_for(objects, reference, calls)
        challenged = False
        def port(url, *, headers, timeout):
            nonlocal challenged
            if url.startswith('https://auth.docker.io/token?'):
                self.assertIn('scope=repository%3Alibrary%2Fowned%3Apull', url)
                self.assertNotIn('Authorization', headers)
                return Response(json.dumps({'token': token}).encode())
            if not challenged:
                challenged = True
                return Response(b'', status=401, headers={'WWW-Authenticate':
                    'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/owned:pull"'})
            self.assertEqual(headers.get('Authorization'), 'Bearer ' + token)
            return plain(url, headers=headers, timeout=timeout)
        result = transport.acquire_images([subject], selected_profile(reference), self.root, network_selection=owned_network(), open_url=port)
        self.assertNotIn(token, json.dumps(result))
        for path in self.root.rglob('*'):
            if path.is_file():
                self.assertNotIn(token.encode(), path.read_bytes())

    def test_retained_binding_and_inclusive_freshness_revalidate_without_renewal(self):
        from datetime import datetime, timedelta, timezone
        transport = self.module('security_oci_transport')
        objects, reference = owned_image()
        subject = {'reference': reference, 'manifest': 'owned/source', 'line': 1,
                   'source_sha256': 'a' * 64, 'platform': 'linux/amd64'}
        binding = owned_binding()
        instant = datetime(2026, 1, 1, tzinfo=timezone.utc)
        transport.acquire_images([subject], selected_profile(reference), self.root, network_selection=owned_network(), binding=binding,
                                 open_url=port_for(objects, reference, []), now=instant)
        raw = (self.root / 'manifest.json').read_bytes()
        for age in [0, 259200]:
            result = transport.retained_acquisition(self.root, [subject], network_selection=owned_network(), binding=binding, profile=selected_profile(reference),
                                                     now=instant + timedelta(seconds=age))
            self.assertEqual(result['records'][0]['acquired_at'], instant.isoformat())
        for age in [-1, 259201]:
            with self.subTest(age=age), self.assertRaises(transport.OCIError):
                transport.retained_acquisition(self.root, [subject], network_selection=owned_network(), binding=binding, profile=selected_profile(reference),
                                               now=instant + timedelta(seconds=age))
        with self.assertRaises(transport.OCIError):
            transport.retained_acquisition(self.root, [subject], network_selection=owned_network(), binding={**binding, 'policy_sha256': 'c' * 64}, profile=selected_profile(reference), now=instant)
        for profile, selected in [(selected_profile(reference, max_layers=3), owned_network()),
                                   (selected_profile(reference), {**owned_network(), 'ghcr.io': ['93.184.216.34']})]:
            with self.subTest(profile=profile, selected=selected), self.assertRaises(transport.OCIError):
                transport.retained_acquisition(self.root, [subject], network_selection=selected,
                                               binding=binding, profile=profile, now=instant)
        self.assertEqual(raw, (self.root / 'manifest.json').read_bytes())

    def test_bounded_acquisition_publishes_exact_layout_and_retains_repeated_uses(self):
        transport = self.module('security_oci_transport')
        layout = self.module('security_oci_layout')
        objects, reference = owned_image()
        calls = []
        subjects = [{'reference': reference, 'manifest': 'owned/compose.yaml', 'line': i,
                     'source_sha256': 'a' * 64, 'platform': 'linux/amd64', 'usage': 'runtime'} for i in [2, 4]]
        result = transport.acquire_images(subjects, selected_profile(reference), self.root, network_selection=owned_network(),
                                           open_url=port_for(objects, reference, calls))
        self.assertEqual(result['status'], 'acquired')
        self.assertEqual(len(result['records']), 2)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result['qualification'], 'UNVERIFIED')
        record = result['records'][0]
        proved = layout.read_directory(self.root / record['layout'], reference, 'linux/amd64')
        self.assertEqual(record['config_digest'], proved['config_digest'])
        self.assertEqual(record['manifest_digest'], digest(objects['blobs/sha256/' + reference.rsplit(':', 1)[1]]))
        self.assertEqual(json.loads((self.root / 'manifest.json').read_text())['records'], result['records'])
        self.assertGreaterEqual(result['counters']['storage_high_water_bytes'],
            sum(path.stat().st_size for path in self.root.rglob('*') if path.is_file()))
        prior = (self.root / 'manifest.json').read_bytes()
        mismatched = [subjects[0], {**subjects[1], 'image_id': 'sha256:' + '0' * 64}]
        with self.assertRaises(transport.OCIError):
            transport.acquire_images(mismatched, selected_profile(reference), self.root, network_selection=owned_network(),
                                     open_url=port_for(objects, reference, []))
        self.assertEqual((self.root / 'manifest.json').read_bytes(), prior)

    def test_invalid_profile_origin_and_physical_quota_refuse_before_io(self):
        transport = self.module('security_oci_transport')
        objects, reference = owned_image()
        for subjects, profile, extra in [([{'reference': reference}], selected_profile(reference, max_storage_bytes=0), {}),
                ([{'reference': reference.replace('docker.io', '127.0.0.1')}], selected_profile(reference), {}),
                ([{'reference': reference}], selected_profile(reference), {'storage_mode': 'physical'})]:
            with self.subTest(extra=extra), self.assertRaises(transport.OCIError):
                transport.acquire_images(subjects, profile, self.root, network_selection=owned_network(),
                    open_url=mock.Mock(side_effect=AssertionError('no IO before admission')), **extra)

    def test_streamed_overshoot_hash_and_deadline_failure_preserve_pointer(self):
        transport = self.module('security_oci_transport')
        objects, reference = owned_image(compressed=True)
        subjects = [{'reference': reference, 'manifest': 'owned/Dockerfile', 'line': 1,
                     'source_sha256': 'b' * 64, 'platform': 'linux/amd64'}]
        (self.root / 'manifest.json').write_bytes(b'prior pointer retained\n')
        prior = (self.root / 'manifest.json').read_bytes()
        def corrupt(url, **kwargs):
            return Response(b'wrong bytes', headers={'Content-Length': '1'})
        for opener, profile in [(corrupt, selected_profile(reference)),
                                (port_for(objects, reference, []), selected_profile(reference, max_compressed_bytes=5)),
                                (port_for(objects, reference, []), selected_profile(reference, max_storage_bytes=1))]:
            with self.subTest(profile=profile), self.assertRaises(transport.OCIError):
                transport.acquire_images(subjects, profile, self.root, network_selection=owned_network(), open_url=opener)
            self.assertEqual((self.root / 'manifest.json').read_bytes(), prior)
        ticks = iter(range(100000))
        with self.assertRaises(transport.OCIError):
            transport.acquire_images(subjects, selected_profile(reference, deadline_seconds=1), self.root, network_selection=owned_network(),
                open_url=port_for(objects, reference, []), clock=lambda: next(ticks))
        self.assertEqual((self.root / 'manifest.json').read_bytes(), prior)

    def test_redirect_and_foreign_challenge_never_reach_another_origin(self):
        transport = self.module('security_oci_transport')
        _, reference = owned_image()
        subject = {'reference': reference, 'manifest': 'new/source', 'line': 1,
                   'source_sha256': 'c' * 64, 'platform': 'linux/amd64'}
        for response in [Response(b'', status=302, headers={'Location': 'https://private.invalid/blob'}),
                         Response(b'', status=401, headers={'WWW-Authenticate': 'Bearer realm="https://private.invalid/token"'})]:
            calls = []
            def port(url, **kwargs):
                calls.append(url)
                return response
            with self.assertRaises(transport.OCIError):
                transport.acquire_images([subject], selected_profile(reference), self.root, network_selection=owned_network(), open_url=port)
            self.assertEqual(len(calls), 1)
