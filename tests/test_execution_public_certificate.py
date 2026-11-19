"""Only the exact shipped public CA bundle may cross the PEM source fence."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from getzilla import execution, package_status, state
from tests.execution_contract_support import owned_route

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_CA = '.getzilla/config/license-exception-inputs/factory-source-delivery-v1/vendor/certifi-2026.10.19/certifi/cacert.pem'
SIZE = 238856
SHA256 = '50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785'


@unittest.skipIf(os.name == 'nt', 'public source ACL custody is not qualified on Windows')
class PublicCertificateSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.enterContext(patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'certificate-fixture'}))
        self.addCleanup(state.bind_session, None)
        self.route = owned_route(self.root, session='certificate-fixture')
        self.raw = (ROOT / PUBLIC_CA).read_bytes()

    def install(self, raw=None, relative=PUBLIC_CA):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        # Source custody requires non-writable public directory ancestry.
        for directory in (target.parent, *target.parent.parents):
            if directory == self.root.parent:
                break
            directory.chmod(0o700)
        target.write_bytes(self.raw if raw is None else raw)
        target.chmod(0o644)
        return target

    def assert_refused(self):
        with self.assertRaises(execution.ExecutionError) as caught:
            execution._source(self.root, self.route)
        self.assertEqual(caught.exception.code, 'source_inventory_unavailable')

    def test_exact_shipped_certificate_size_hash_and_source_are_available(self):
        self.assertEqual(len(self.raw), SIZE)
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), SHA256)
        self.assertIn(b'-----BEGIN CERTIFICATE-----', self.raw)
        self.assertNotIn(b'PRIVATE KEY', self.raw)
        self.install()
        self.assertRegex(execution._source(self.root, self.route)['fingerprint'], r'^[a-f0-9]{64}$')

    def test_one_byte_changed_and_truncated_certificates_refuse(self):
        for raw in (bytes([self.raw[0] ^ 1]) + self.raw[1:], self.raw[:-1]):
            with self.subTest(size=len(raw)):
                self.install(raw)
                self.assert_refused()

    def test_private_key_marker_at_pinned_path_refuses_without_publication(self):
        marker = b'-----BEGIN PRIVATE KEY-----'
        self.install(marker + self.raw[len(marker):])
        self.assert_refused()

    def test_same_public_certificate_at_another_path_refuses_before_read(self):
        self.install(relative='other/cacert.pem')
        with patch.object(execution, 'read_package_file', wraps=execution.read_package_file) as reader:
            self.assert_refused()
        self.assertNotIn('other/cacert.pem', [call.args[1] for call in reader.call_args_list])

    def test_pinned_symlink_and_hardlink_refuse(self):
        target = self.install()
        other = self.root / 'public.txt'
        other.write_bytes(self.raw)
        other.chmod(0o644)
        target.unlink()
        target.symlink_to(other)
        self.assert_refused()
        target.unlink()
        target.hardlink_to(other)
        self.assert_refused()

    def test_pinned_directory_and_oversized_file_refuse(self):
        target = self.install(self.raw + b'\n')
        self.assert_refused()
        target.unlink()
        target.mkdir()
        self.assert_refused()

    def test_pinned_file_swapped_after_open_refuses(self):
        target = self.install()
        original = package_status.fsx.open_at
        def swap(directory, name, flags):
            descriptor = original(directory, name, flags)
            if name == 'cacert.pem':
                target.unlink()
                target.write_bytes(self.raw)
                target.chmod(0o644)
            return descriptor
        with patch.object(package_status.fsx, 'open_at', side_effect=swap):
            self.assert_refused()

    def test_other_sensitive_source_paths_still_refuse(self):
        for relative in ('.env', 'other/id_rsa', 'other/key.key', 'other/public.pem'):
            with self.subTest(relative=relative):
                target = self.install(b'fixture public bytes', relative)
                self.assert_refused()
                target.unlink()
