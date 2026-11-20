import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from getzilla.retrieval.contracts import sha


class StudyArtifactTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_artifacts')
        except ModuleNotFoundError:
            self.fail('held study artifact custody owner missing')

    def test_exact_tiny_bytes_are_held_and_replacement_refuses(self):
        owner = self.owner()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'model.onnx'
            path.write_bytes(b'inert')
            path.chmod(0o400)
            with owner.HeldArtifacts(root, (('model.onnx', 5, sha(b'inert')),)) as held:
                held.check()
                path.unlink()
                path.write_bytes(b'inert')
                path.chmod(0o400)
                with self.assertRaises(ValueError):
                    held.check()

    def test_symlink_extra_file_wrong_hash_and_writeable_mode_refuse(self):
        owner = self.owner()
        for changed in ('symlink', 'extra', 'hash', 'mode'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                file = root / 'data'
                file.write_bytes(b'inert')
                file.chmod(0o400)
                if changed == 'symlink':
                    file.unlink()
                    file.symlink_to('/dev/null')
                if changed == 'extra':
                    (root / 'unexpected.so').write_bytes(b'inert')
                if changed == 'mode':
                    file.chmod(0o664)
                digest = sha(b'other') if changed == 'hash' else sha(b'inert')
                with self.assertRaises(ValueError):
                    with owner.HeldArtifacts(root, (('data', 5, digest),)):
                        pass

    def test_deadline_and_hardlinks_refuse_without_retry(self):
        owner = self.owner()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'data').write_bytes(b'inert')
            os.link(root / 'data', root / 'alias')
            with self.assertRaises(ValueError):
                with owner.HeldArtifacts(root, (('data', 5, sha(b'inert')),)):
                    pass
            (root / 'alias').unlink()
            with self.assertRaisesRegex(ValueError, 'artifact_deadline'):
                with owner.HeldArtifacts(root, (('data', 5, sha(b'inert')),), deadline=0):
                    pass

    def test_unrelated_sibling_changes_do_not_retag_or_expand_held_inventory(self):
        owner = self.owner()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / 'models'
            root.mkdir(mode=0o700)
            (root / 'data').write_bytes(b'inert')
            with owner.HeldArtifacts(root, (('data', 5, sha(b'inert')),)) as held:
                (parent / 'unrelated').write_bytes(b'outside inventory')
                held.check()
                (root / 'extra').write_bytes(b'inside inventory')
                with self.assertRaises(ValueError):
                    held.check()

    def test_export_snapshot_is_metadata_only_with_exact_separate_dac(self):
        owner = self.owner()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            export = base / 'export'
            export.mkdir(mode=0o755)
            file = export / 'data'
            file.write_bytes(b'inert')
            file.chmod(0o444)
            expected = (('data', 5, sha(b'inert')),)
            with self.assertRaises(ValueError):
                owner.snapshot_study_export(base, 'export', expected)
            export.chmod(0o555)
            snapshot = owner.snapshot_study_export(base, 'export', expected)
            try:
                self.assertFalse(snapshot.hashes_verified)
                self.assertEqual(len(snapshot.binding_digest), 64)
                self.assertIsNone(owner.check_study_export(snapshot))
                file.chmod(0o644)
                with self.assertRaises(ValueError):
                    owner.check_study_export(snapshot)
            finally:
                snapshot.close()

    def test_insufficient_actual_fd_headroom_refuses_without_raising_limits(self):
        owner = self.owner()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'data').write_bytes(b'inert')
            with patch('resource.getrlimit', return_value=(8, 8)), \
                    patch('resource.setrlimit') as change_limit:
                with self.assertRaisesRegex(ValueError, 'artifact_file_descriptor_budget'):
                    with owner.HeldArtifacts(root, (('data', 5, sha(b'inert')),)):
                        pass
            change_limit.assert_not_called()
