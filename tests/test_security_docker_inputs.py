"""Owned Docker2/OCI graph bytes, not daemon, network or image execution."""
import gzip
import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_oci as oci

DM = 'application/vnd.docker.distribution.manifest.v2+json'
DI = 'application/vnd.docker.distribution.manifest.list.v2+json'
DC = 'application/vnd.docker.container.image.v1+json'
DG = 'application/vnd.docker.image.rootfs.diff.tar.gzip'


def owned_layout(root, kind, *, foreign=False, layer_media=None, schema=2):
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode='w') as archive:
        entry = tarfile.TarInfo('owned-marker')
        entry.size = 13
        archive.addfile(entry, io.BytesIO(b'owned fixture'))
    unpacked = layer.getvalue()
    compressed = gzip.compress(unpacked, mtime=0)
    blobs = root / 'blobs/sha256'
    blobs.mkdir(parents=True)
    def blob(media, raw):
        digest = hashlib.sha256(raw).hexdigest()
        (blobs / digest).write_bytes(raw)
        return dict(mediaType=media, size=len(raw), digest='sha256:' + digest)
    docker = kind != 'oci'
    layer_desc = blob(layer_media or (DG if docker else oci.GZIP), compressed)
    if foreign:
        layer_desc['urls'] = ['https://outside.invalid/never-opened']
    entries, config_hash = [], None
    for architecture in (('amd64', 'arm64') if kind == 'list' else ('amd64',)):
        config = blob(DC if docker else oci.CONFIG, oci.canonical(dict(architecture=architecture,
            os='linux', rootfs=dict(type='layers', diff_ids=['sha256:' + hashlib.sha256(unpacked).hexdigest()]))))
        if architecture == 'amd64':
            config_hash = config['digest']
        manifest = blob(DM if docker else oci.MANIFEST, oci.canonical(dict(schemaVersion=schema,
            mediaType=DM if docker else oci.MANIFEST, config=config, layers=[layer_desc])))
        manifest['platform'] = dict(os='linux', architecture=architecture)
        entries.append(manifest)
    selected = blob(DI, oci.canonical(dict(schemaVersion=2, mediaType=DI, manifests=entries))) if kind == 'list' else entries[0]
    (root / 'oci-layout').write_bytes(oci.canonical({'imageLayoutVersion': '1.0.0'}))
    (root / 'index.json').write_bytes(oci.canonical(dict(schemaVersion=2, mediaType=oci.INDEX, manifests=[selected])))
    reference = 'owned.local/fixture@' + selected['digest']
    inventory = dict(complete=True, gaps=[], images=[dict(reference=reference, platform='linux/amd64')])
    inventory['digest'] = hashlib.sha256(oci.canonical(inventory)).hexdigest()
    catalog = dict(schema_version=1, inventory_sha256=inventory['digest'],
                   records=[dict(reference=reference, platform='linux/amd64', layout=str(root))])
    return catalog, inventory, dict(oci.LIMITS, images=[reference], platform='linux/amd64'), config_hash, blobs / layer_desc['digest'][7:]


class DockerInputControls(unittest.TestCase):
    def setUp(self):
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        for name in ('socket.socket', 'socket.getaddrinfo', 'subprocess.Popen'):
            port = mock.patch(name, side_effect=AssertionError('outside fixture effect denied'))
            port.start()
            self.addCleanup(port.stop)

    def test_original_oci_and_docker_manifest_and_complete_list(self):
        for kind in ('oci', 'manifest', 'list'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
                root = Path(directory)
                catalog, inventory, profile, config, _ = owned_layout(root / 'layout', kind)
                with oci.import_layouts(catalog, inventory, profile, root) as images:
                    self.assertEqual(len(images), 1)
                    self.assertEqual(images[0].config_digest, config)
                    self.assertEqual(oci.document((images[0].layout / 'index.json').read_bytes())['manifests'][0]['mediaType'],
                                     oci.MANIFEST if kind == 'oci' else DM)

    def test_foreign_url_and_corrupt_layer_remain_refusals(self):
        for failure in ('foreign-url', 'corrupt', 'unknown-media', 'schema1'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
                root = Path(directory)
                catalog, inventory, profile, _, layer = owned_layout(root / 'layout', 'manifest',
                    foreign=failure == 'foreign-url', layer_media='application/vnd.docker.image.rootfs.foreign.diff.tar.gzip'
                    if failure == 'unknown-media' else None, schema=1 if failure == 'schema1' else 2)
                if failure == 'corrupt':
                    layer.write_bytes(b'corrupt actual layer')
                with self.assertRaises(oci.OCIError):
                    with oci.import_layouts(catalog, inventory, profile, root):
                        self.fail('unqualified graph must not yield an image')
