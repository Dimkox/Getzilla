"""NEW controlled public-OCI ports; no registry, daemon or scanner executes."""
import io
import json
from unittest import mock

from tests.test_security_oci_layout import OwnedOciCase, digest, owned_image, selected_profile, owned_binding


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
    def test_request_origin_guard_precedes_the_injected_port(self):
        transport = self.module('security_oci_transport')
        layout = self.module('security_oci_layout')
        _, reference = owned_image()
        calls = []
        def port(url, **kwargs):
            calls.append(url)
            return Response(b'new-owned')
        with self.assertRaises(transport.OCIError):
            transport._fetch('https://private.invalid/blob', layout.Budget(selected_profile(reference)), port)
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
            transport.acquire_images([subject], selected_profile(reference), self.root,
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
            transport.acquire_images([subject], selected_profile(reference), self.root,
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
        result = transport.acquire_images([subject], selected_profile(reference), self.root, open_url=port)
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
        transport.acquire_images([subject], selected_profile(reference), self.root, binding=binding,
                                 open_url=port_for(objects, reference, []), now=instant)
        raw = (self.root / 'manifest.json').read_bytes()
        for age in [0, 259200]:
            result = transport.retained_acquisition(self.root, [subject], binding=binding,
                                                     now=instant + timedelta(seconds=age))
            self.assertEqual(result['records'][0]['acquired_at'], instant.isoformat())
        for age in [-1, 259201]:
            with self.subTest(age=age), self.assertRaises(transport.OCIError):
                transport.retained_acquisition(self.root, [subject], binding=binding,
                                               now=instant + timedelta(seconds=age))
        with self.assertRaises(transport.OCIError):
            transport.retained_acquisition(self.root, [subject], binding={**binding, 'policy_sha256': 'c' * 64}, now=instant)
        self.assertEqual(raw, (self.root / 'manifest.json').read_bytes())

    def test_bounded_acquisition_publishes_exact_layout_and_retains_repeated_uses(self):
        transport = self.module('security_oci_transport')
        layout = self.module('security_oci_layout')
        objects, reference = owned_image()
        calls = []
        subjects = [{'reference': reference, 'manifest': 'owned/compose.yaml', 'line': i,
                     'source_sha256': 'a' * 64, 'platform': 'linux/amd64', 'usage': 'runtime'} for i in [2, 4]]
        result = transport.acquire_images(subjects, selected_profile(reference), self.root,
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
            transport.acquire_images(mismatched, selected_profile(reference), self.root,
                                     open_url=port_for(objects, reference, []))
        self.assertEqual((self.root / 'manifest.json').read_bytes(), prior)

    def test_invalid_profile_origin_and_physical_quota_refuse_before_io(self):
        transport = self.module('security_oci_transport')
        objects, reference = owned_image()
        for subjects, profile, extra in [([{'reference': reference}], selected_profile(reference, max_storage_bytes=0), {}),
                ([{'reference': reference.replace('docker.io', '127.0.0.1')}], selected_profile(reference), {}),
                ([{'reference': reference}], selected_profile(reference), {'storage_mode': 'physical'})]:
            with self.subTest(extra=extra), self.assertRaises(transport.OCIError):
                transport.acquire_images(subjects, profile, self.root,
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
                transport.acquire_images(subjects, profile, self.root, open_url=opener)
            self.assertEqual((self.root / 'manifest.json').read_bytes(), prior)
        ticks = iter(range(100000))
        with self.assertRaises(transport.OCIError):
            transport.acquire_images(subjects, selected_profile(reference, deadline_seconds=1), self.root,
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
                transport.acquire_images([subject], selected_profile(reference), self.root, open_url=port)
            self.assertEqual(len(calls), 1)
