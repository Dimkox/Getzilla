import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from adaptive_trust_ci import runner_archive as archive


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


class RunnerArchiveTests(unittest.TestCase):
    def setUp(self):
        self.blobs = {}
        self.layer = self.add(b'layer', 'application/vnd.oci.image.layer.v1.tar')
        self.config = self.add(json.dumps({'os': 'linux', 'architecture': 'amd64'}).encode(),
                               'application/vnd.oci.image.config.v1+json')
        self.manifest = self.add(json.dumps(dict(schemaVersion=2, mediaType=archive.OCI_MANIFEST,
                        config=self.config, layers=[self.layer])).encode(), archive.OCI_MANIFEST)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'runner.tar'
        archive.fetch_archive(self.open, self.manifest['digest'], self.config['digest'], self.path)

    def add(self, data, media):
        key = digest(data)
        self.blobs[key] = data
        return dict(mediaType=media, digest=key, size=len(data))

    def open(self, kind, key):
        return io.BytesIO(self.blobs[key])

    def test_config_mismatch_before_load(self):
        docker = Mock()
        with self.assertRaises(ValueError):
            archive.load_archive(self.path, self.manifest['digest'], digest(b'other'), docker)
        docker.assert_not_called()

    def test_tampered_layer_refused_before_docker(self):
        data = self.path.read_bytes()
        self.path.chmod(0o600)
        self.path.write_bytes(data.replace(b'layer\0', b'wrong\0', 1))
        docker = Mock()
        with self.assertRaises(ValueError):
            archive.load_archive(self.path, self.manifest['digest'], self.config['digest'], docker)
        docker.assert_not_called()

    def test_post_load_id_must_match(self):
        for inspected, success in ((self.config['digest'], True), (digest(b'wrong'), False)):
            docker = Mock(return_value=Mock(stdout=inspected + '\n'))
            if success:
                archive.load_archive(self.path, self.manifest['digest'], self.config['digest'], docker)
            else:
                with self.assertRaises(ValueError):
                    archive.load_archive(self.path, self.manifest['digest'], self.config['digest'], docker)
            self.assertEqual([c.args[0][1] for c in docker.call_args_list], ['load', 'image'])
