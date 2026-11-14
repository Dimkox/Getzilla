"""NEW handwritten OCI contracts; never load a repository image or run a tool."""
from __future__ import annotations

import copy
import gzip
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def tiny_tar(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, body in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(body)
            item.mode = 0o644
            archive.addfile(item, io.BytesIO(body))
    return stream.getvalue()


def owned_image(*, platform='linux/amd64', compressed=False, diff_id_override=None):
    layer = tiny_tar({'LICENSE': b'NEW owned fixture license bytes\n', 'app.txt': b'new app\n'})
    blob = gzip.compress(layer, mtime=0) if compressed else layer
    config = encoded({'os': platform.split('/')[0], 'architecture': platform.split('/')[1],
                      'rootfs': {'type': 'layers', 'diff_ids': [diff_id_override or digest(layer)]}})
    def descriptor(raw, media):
        return {'mediaType': media, 'digest': digest(raw), 'size': len(raw)}
    manifest = encoded({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'config': descriptor(config, 'application/vnd.oci.image.config.v1+json'),
        'layers': [descriptor(blob, 'application/vnd.oci.image.layer.v1.tar' + ('+gzip' if compressed else ''))]})
    selected = descriptor(manifest, 'application/vnd.oci.image.manifest.v1+json')
    selected['platform'] = dict(zip(('os', 'architecture'), platform.split('/')))
    objects = {'oci-layout': encoded({'imageLayoutVersion': '1.0.0'}),
               'index.json': encoded({'schemaVersion': 2, 'manifests': [selected]})}
    objects.update({'blobs/sha256/' + digest(raw)[7:]: raw for raw in [manifest, config, blob]})
    return objects, 'docker.io/library/owned@' + digest(manifest)


def selected_profile(reference, **updates):
    return {'images': [reference], 'max_images': 1, 'max_compressed_bytes': 131072,
            'max_unpacked_bytes': 131072, 'max_storage_bytes': 524288,
            'max_manifest_bytes': 16384, 'max_layers': 4,
            'deadline_seconds': 10, 'platform': 'linux/amd64', **updates}


def owned_binding():
    return {'source': {'head_sha': '1' * 40, 'tree_sha': '2' * 40, 'checker_sha': '3' * 40,
                       'checker_tree_sha': '4' * 40, 'candidate_clean': True, 'checker_clean': True, 'same_project': False},
            'inventory_sha256': 'a' * 64, 'policy_sha256': 'b' * 64,
            'run': {'provider': 'github-actions', 'repository': 'owned/fixture', 'run_id': '1', 'run_attempt': '1', 'head_sha': '1' * 40}}


def owned_network():
    # Explicit fixture metadata; no connection to these literals is made.
    return {host: ['93.184.216.34'] for host in ['registry-1.docker.io', 'auth.docker.io']}


class OwnedOciCase(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ.get('GETZILLA_OCI_TEST_ROOT', str(Path(__file__).resolve().parents[1] / '.getzilla/runtime')))
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='new-oci-', dir=base)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        for target in ['socket.socket', 'socket.getaddrinfo', 'subprocess.Popen', 'subprocess.run']:
            patch = mock.patch(target, side_effect=AssertionError('uncontrolled network/process forbidden'))
            patch.start()
            self.addCleanup(patch.stop)

    def module(self, name):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.' + name), 'missing admitted OCI capability')
        return importlib.import_module('getzilla.' + name)


class OciLayoutContracts(OwnedOciCase):
    def test_uncompressed_tar_padding_is_charged_to_selected_expansion(self):
        layout = self.module('security_oci_layout')
        objects, reference = owned_image()
        budget = layout.Budget(selected_profile(reference, max_unpacked_bytes=100))
        with self.assertRaises(layout.OCIError):
            layout.validate_layout(objects, reference, 'linux/amd64', budget=budget)

    def test_new_real_tar_and_legacy_zip_share_exact_identity_and_members(self):
        layout = self.module('security_oci_layout')
        objects, reference = owned_image(compressed=True)
        tar = tiny_tar(objects)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            for name, raw in objects.items():
                archive.writestr(name, raw)
        direct = layout.validate_layout(objects, reference, 'linux/amd64')
        for payload, name in [(tar, 'owned.tar'), (buffer.getvalue(), 'owned.zip')]:
            result = layout.read_archive(payload, name, reference, 'linux/amd64')
            self.assertEqual(result['manifest_digest'], reference.rsplit('@', 1)[1])
            self.assertEqual(result['config_digest'], direct['config_digest'])
            self.assertEqual(result['members'], direct['members'])
            self.assertTrue(result['files'])

    def test_bad_object_digest_platform_and_unreferenced_bytes_refuse(self):
        layout = self.module('security_oci_layout')
        original, reference = owned_image()
        variants = []
        wrong = copy.deepcopy(original)
        blob = next(name for name in wrong if name.startswith('blobs/'))
        wrong[blob] += b'changed'
        variants.append((wrong, reference, 'linux/amd64'))
        extra = {**original, 'blobs/sha256/' + 'f' * 64: b'extra'}
        variants += [(extra, reference, 'linux/amd64'), (original, reference, 'linux/arm64'),
                     (original, reference.replace(reference.rsplit(':', 1)[1], '0' * 64), 'linux/amd64')]
        for objects, subject, platform in variants:
            with self.subTest(subject=subject, platform=platform), self.assertRaises(layout.OCIError):
                layout.validate_layout(objects, subject, platform)

    def test_diff_id_duplicate_json_and_layer_semantics_refuse(self):
        layout = self.module('security_oci_layout')
        objects, reference = owned_image()
        for bad_index in [b'{"schemaVersion":2,"schemaVersion":2}',
                          encoded({'schemaVersion': 2, 'manifests': []})]:
            with self.assertRaises(layout.OCIError):
                layout.validate_layout({**objects, 'index.json': bad_index}, reference, 'linux/amd64')
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            member = tarfile.TarInfo('link')
            member.type = tarfile.SYMTYPE
            member.linkname = '/outside'
            archive.addfile(member)
        with self.assertRaises(layout.OCIError):
            layout.archive_members(layer.getvalue(), 'layer.tar')
        with self.assertRaises(layout.OCIError):
            layout.archive_members(tiny_tar({'../outside': b'bad'}), 'layer.tar')
        wrong, subject = owned_image(diff_id_override='sha256:' + '0' * 64)
        with self.assertRaises(layout.OCIError):
            layout.validate_layout(wrong, subject, 'linux/amd64')

    def test_manifest_digest_and_selected_platform_guards_are_independent(self):
        layout = self.module('security_oci_layout')
        original, reference = owned_image()
        name = 'blobs/sha256/' + reference.rsplit(':', 1)[1]
        index = json.loads(original['index.json'])
        index['manifests'][0]['size'] += 1
        whitespace = {**original, name: original[name] + b' ', 'index.json': encoded(index)}
        with self.assertRaises(layout.OCIError):
            layout.validate_layout(whitespace, reference, 'linux/amd64')
        index = json.loads(original['index.json'])
        index['manifests'][0]['platform']['architecture'] = 'arm64'
        with self.assertRaises(layout.OCIError):
            layout.validate_layout({**original, 'index.json': encoded(index)}, reference, 'linux/amd64')

    def test_expansion_padding_and_layer_limit_are_actual_bytes(self):
        layout = self.module('security_oci_layout')
        objects, reference = owned_image(compressed=True)
        for updates in [{'max_unpacked_bytes': 100}, {'max_layers': 0}, {'deadline_seconds': 0}]:
            with self.subTest(updates=updates), self.assertRaises(layout.OCIError):
                budget = layout.Budget(selected_profile(reference, **updates))
                layout.validate_layout(objects, reference, 'linux/amd64', budget=budget)

    def test_directory_reads_bind_regular_object_identity_and_reject_links(self):
        layout = self.module('security_oci_layout')
        objects, reference = owned_image()
        for name, raw in objects.items():
            target = self.root / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
        before = layout.read_directory(self.root, reference, 'linux/amd64')
        target = self.root / 'index.json'
        raw = target.read_bytes()
        target.unlink()
        target.write_bytes(raw)
        after = layout.read_directory(self.root, reference, 'linux/amd64')
        self.assertNotEqual(before['identities'], after['identities'])
        target.unlink()
        target.symlink_to(self.root / 'oci-layout')
        with self.assertRaises(layout.OCIError):
            layout.read_directory(self.root, reference, 'linux/amd64')
