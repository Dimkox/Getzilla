"""Owned local build/OCI producer fixtures. No real registry, builder or daemon."""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from urllib.parse import urlsplit
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_inventory as inventory
from getzilla import security_image_registry as registry
from getzilla import security_image_backend as backend
from getzilla import security_image_producer as producer
from getzilla.security_oci import CONFIG, MANIFEST, canonical


class GuardedFixture(unittest.TestCase):
    def setUp(self):
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        for name in ('socket.socket', 'socket.getaddrinfo',
                     'getzilla.security_image_registry.BoundedHTTP.get',
                     'getzilla.security_image_backend._fixed'):
            port = mock.patch(name, side_effect=AssertionError('outside fixture effect denied'))
            port.start()
            self.addCleanup(port.stop)


class BuildInputTests(GuardedFixture):
    def test_local_compose_build_is_parsed_without_execution_credit(self):
        runtime = ROOT / '.getzilla/runtime'
        runtime.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=runtime) as directory:
            root = Path(directory)
            compose = ('services:\n  api:\n    platform: linux/amd64\n    build:\n'
                       '      context: .\n      dockerfile: Dockerfile\n      args:\n'
                       '        PYTHON_BASE_IMAGE: python@sha256:' + '1' * 64 + '\n')
            dockerfile = 'ARG PYTHON_BASE_IMAGE\nFROM ${PYTHON_BASE_IMAGE}\nCOPY app.txt /app.txt\n'
            (root / 'compose.yaml').write_text(compose)
            (root / 'Dockerfile').write_text(dockerfile)
            (root / 'app.txt').write_text('owned current context')
            uses = [dict(manifest='Dockerfile', line=2,
                         source_sha256=hashlib.sha256(dockerfile.encode()).hexdigest(),
                         source_reference='${PYTHON_BASE_IMAGE}', reference='python@sha256:' + '1' * 64,
                         platform='linux/amd64')]
            with mock.patch.object(inventory, '_tracked_files', return_value=['compose.yaml', 'Dockerfile', 'app.txt']):
                result = inventory.collect_inventory(root, image_bindings=uses)
            unsupported = [gap for gap in result['gaps'] if gap['code'] == 'unsupported-compose-composition']
            self.assertEqual(unsupported, [], 'local build mapping needs a closed input adapter')
            self.assertEqual(len(result['builds']), 1)
            self.assertIn('app.txt', {row['path'] for row in result['builds'][0]['context_files']})
            self.assertTrue(result['gaps'], 'unproduced output must remain unresolved')
            (root / 'Dockerfile').write_text(dockerfile + 'RUN \\\n  --mount=type=bind,target=/uncovered true\n')
            with mock.patch.object(inventory, '_tracked_files', return_value=['compose.yaml', 'Dockerfile', 'app.txt']):
                changed = inventory.collect_inventory(root, image_bindings=uses)
            self.assertTrue(any(row['code'] == 'unsupported-compose-composition' for row in changed['gaps']),
                            'continued Dockerfile flags must not bypass the closed build grammar')


class RegistryReaderTests(GuardedFixture):
    def test_oversized_single_chunk_is_refused_before_delivery(self):
        class Response:
            status, headers = 200, {}
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            def read1(self, size):
                self.requested = size
                return b'x' * (size + 1)
        response = Response()
        request = dict(url='https://registry-1.docker.io/v2/library/owned/blobs/sha256:' + '1' * 64,
                       headers={}, maximum=100000, seconds=1)
        stream = registry._http(request, opener=lambda *_args, **_kwargs: response)
        next(stream)  # fixed bounded metadata only
        with self.assertRaises(registry.RegistryError):
            next(stream)

    def test_graph_uses_actual_hashed_bytes_and_refuses_corruption(self):
        config = canonical(dict(architecture='amd64', os='linux', rootfs=dict(type='layers', diff_ids=[])))
        descriptor = dict(mediaType=CONFIG, digest='sha256:' + hashlib.sha256(config).hexdigest(), size=len(config))
        body = canonical(dict(schemaVersion=2, mediaType=MANIFEST, config=descriptor, layers=[]))
        digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        class Port:
            corrupt = False
            def get(self, url, _headers, _maximum):
                if urlsplit(url).hostname == 'auth.docker.io':
                    return {}, b'{"token":"owned-anonymous-fixture"}'
                if '/blobs/' in url:
                    return {'digest': ''}, config + (b'x' if self.corrupt else b'')
                return {'type': MANIFEST, 'digest': digest}, body
        port = Port()
        resolved = registry.Registry(transport=port)
        reference, root = resolved.resolve('owned:fixture', 'linux/amd64')
        self.assertEqual(reference, 'owned@' + digest)
        self.assertEqual(root['digest'], digest)
        self.assertEqual(set(resolved.blobs), {digest, descriptor['digest']})
        port.corrupt = True
        with self.assertRaises(registry.RegistryError):
            registry.Registry(transport=port).resolve('owned:fixture', 'linux/amd64')


class ProducerBoundaryTests(GuardedFixture):
    def test_local_compose_output_is_bound_after_build_only(self):
        local = dict(manifest="trust-ci/compose.build.yaml", line=12, source_sha256="a"*64,
                     source_reference="compose-build:docker-engine")
        upstream = dict(local, source_reference="docker:29.10.1-dind-rootless@sha256:" + "b"*64)
        self.assertEqual(list(producer.registry_inputs(dict(images=[local, upstream], builds=[local]))), [upstream])
        with self.assertRaises(backend.BackendUnavailable):
            list(producer.registry_inputs(dict(images=[dict(local, line=13)], builds=[local])))

    def test_json_build_claim_cannot_restore_actual_completion(self):
        claimed = dict(builds=[dict(build_sha256='0' * 64)], images=[])
        with self.assertRaises(backend.BackendUnavailable):
            producer.require_builds(claimed, {'head': 'owned'}, {'run': 'owned'})

    def test_export_rejects_escape_without_writing_outside_owned_layout(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            root = Path(directory)
            archive, layout = root / 'export.tar', root / 'layout'
            layout.mkdir()
            with tarfile.open(archive, 'w') as stream:
                member = tarfile.TarInfo('../escape')
                member.size = 4
                stream.addfile(member, io.BytesIO(b'nope'))
            with self.assertRaises(backend.BackendUnavailable):
                producer._unpack_export(archive, layout)
            self.assertFalse((root / 'escape').exists())
            self.assertEqual(list(layout.iterdir()), [])

    def test_owned_child_stage_protocol_and_opening_deadline(self):
        body = '\n'.join(json.dumps(value) for value in
            [{'stage': 'declare'}, {'stage': 'prepare'}, {'stage': 'evaluate'}, {'result': {'owned': True}}]) + '\n'
        for expired in (False, True):
            with self.subTest(expired=expired):
                child = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', 'print(' + repr(body) + ',end="")'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={'PATH': os.defpath, 'LANG': 'C'}, start_new_session=True)
                try:
                    if expired:
                        with self.assertRaises(backend.BackendUnavailable):
                            backend._collect_pipeline(child, started=time.monotonic() - 901)
                    else:
                        self.assertEqual(backend._collect_pipeline(child), {'owned': True})
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)
                    child.stdout.close()
                    child.stderr.close()


if __name__ == '__main__':
    unittest.main()
