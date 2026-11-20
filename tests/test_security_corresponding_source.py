"""Finite real-source classification and hostile-source controls."""
from pathlib import Path
import os
import unittest

from getzilla.security_inventory import collect_inventory

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY'), 'requires no-follow source custody')
class CorrespondingSourceTests(unittest.TestCase):
    def test_real_retained_sources_are_typed_without_losing_accounting(self):
        inventory = collect_inventory(ROOT)
        retained = inventory['corresponding_sources']
        self.assertEqual({'certifi', 'psycopg'}, {row['package'] for row in retained})
        self.assertEqual(115, sum(len(row['members']) for row in retained))
        self.assertEqual(0, len([g for g in inventory['gaps'] if g['code'] == 'unresolved-dependency']))
        for row in retained:
            self.assertEqual('declared-target-only', row['artifact_observation'])
            self.assertIn(row['manifest'], {m['path'] for m in inventory['manifests']})
            self.assertTrue(set(row['members']).issubset(inventory['files']))
        # Compare independently generated membership against the actual fixed builder.
        # Product classification never executes this candidate builder.
        import importlib.util
        import sys
        runtime = ROOT / 'factory/runtime'
        saved_path = sys.path[:]
        try:
            sys.path.insert(0, str(runtime))
            spec = importlib.util.spec_from_file_location('source_composition_control_builder', runtime / 'build_offline_release.py')
            builder = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(builder)
            for row in retained:
                payload, delivery = builder._repack_source(ROOT, row['package'])
                self.assertEqual(row['repack']['sha256'], delivery['sha256'])
                self.assertEqual(len(payload), row['repack']['bytes'])
        finally:
            sys.path[:] = saved_path
        constraints = [c for row in retained for c in row['constraints']]
        self.assertTrue({'runtime', 'build', 'test', 'docs'}.issubset({c['role'] for c in constraints}))


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY'), 'requires no-follow source custody')
class CorrespondingSourceTamperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import shutil
        import subprocess
        import tempfile
        from getzilla.security_osv_snapshot import _tracked_files
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix='corresponding-source-tests-', dir=scratch)
        cls.copy = Path(cls.temporary.name)
        cls.copy.chmod(0o700)
        for name in _tracked_files(ROOT):
            target = cls.copy / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        subprocess.run(['git', 'init', '-q', str(cls.copy)], check=True)
        subprocess.run(['git', '-C', str(cls.copy), 'add', '-f', '.'], check=True)
        subprocess.run(['git', '-C', str(cls.copy), '-c', 'user.name=Local control', '-c', 'user.email=control@example.invalid', 'commit', '-qm', 'Exact local source control'], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def assert_refused(self):
        result = collect_inventory(self.copy)
        self.assertNotIn('corresponding_sources', result)
        self.assertTrue(any(g['code'] == 'corresponding-source-unverified' for g in result['gaps']))
        self.assertTrue(any(g['code'] == 'unresolved-dependency' for g in result['gaps']))
        return result

    def test_changed_and_missing_fixed_inputs_refuse(self):
        from getzilla.security_corresponding_source import LEGAL
        paths = [LEGAL + 'certifi-2026.10.19-source-map.json',
                 LEGAL + 'certifi-2026.10.19-snapshot.json',
                 LEGAL + 'certifi-2026.10.19-index.json',
                 LEGAL + 'vendor/certifi-2026.10.19/pyproject.toml',
                 LEGAL + 'vendor/psycopg-3.3.4/pyproject.toml',
                 'factory/uv.lock', 'factory/pyproject.toml',
                 'factory/runtime/runtime-wheels-linux-x86_64-cpython312.json',
                 'factory/runtime/build_offline_release.py',
                 '.github/workflows/getzilla.yml',
                 '.getzilla/getzilla/security_corresponding_source.py']
        for name in paths:
            target = self.copy / name
            original = target.read_bytes()
            original_mode = target.stat().st_mode & 0o777
            for action in ('change', 'remove'):
                with self.subTest(path=name, action=action):
                    try:
                        if action == 'remove':
                            target.unlink()
                        else:
                            target.write_bytes(original + b'\n# changed source composition\n')
                        self.assert_refused()
                    finally:
                        target.write_bytes(original)
                        target.chmod(original_mode)

    def test_membership_modes_links_and_unrelated_inputs_refuse(self):
        import os
        from getzilla.security_corresponding_source import LEGAL
        target = self.copy / (LEGAL + 'vendor/certifi-2026.10.19/pyproject.toml')
        original = target.read_bytes()
        for action in ('mode', 'symlink', 'hardlink', 'extra-file', 'empty-directory', 'unrelated-manifest', 'new-launcher'):
            extra = None
            with self.subTest(action=action):
                try:
                    if action == 'mode':
                        target.chmod(0o755)
                    elif action == 'symlink':
                        target.unlink()
                        target.symlink_to('README.rst')
                    elif action == 'hardlink':
                        extra = target.with_name('unexpected-hardlink')
                        os.link(target, extra)
                    elif action == 'extra-file':
                        extra = target.with_name('unexpected')
                        extra.write_bytes(b'data')
                    elif action == 'empty-directory':
                        extra = target.with_name('unexpected-directory')
                        extra.mkdir()
                    elif action == 'unrelated-manifest':
                        extra = self.copy / 'unrelated/pyproject.toml'
                        extra.parent.mkdir()
                        extra.write_bytes(original)
                    else:
                        extra = self.copy / 'factory/runtime/new-launcher.py'
                        extra.write_text("exec(open('.getzilla/config/license-exception-inputs/factory-source-delivery-v1/vendor/certifi-2026.10.19/setup.py').read())\n")
                    result = self.assert_refused()
                    if action == 'unrelated-manifest':
                        self.assertIn('unrelated/pyproject.toml', {g['path'] for g in result['gaps'] if g['code'] == 'unresolved-dependency'})
                finally:
                    if extra is not None:
                        if extra.is_dir():
                            extra.rmdir()
                        else:
                            extra.unlink()
                        if action == 'unrelated-manifest':
                            extra.parent.rmdir()
                    if target.is_symlink():
                        target.unlink()
                    target.write_bytes(original)
                    target.chmod(0o644)

    def test_source_replacement_during_validation_refuses(self):
        from unittest.mock import patch
        from getzilla import security_corresponding_source as adapter
        name = adapter.LEGAL + 'vendor/certifi-2026.10.19/pyproject.toml'
        target = self.copy / name
        original = target.read_bytes()
        actual_read = adapter._read
        self.assertIn('corresponding_sources', collect_inventory(self.copy))
        changed = False
        def replace_after_read(root, relative, **kwargs):
            nonlocal changed
            result = actual_read(root, relative, **kwargs)
            if relative == name and not changed:
                target.write_bytes(original + b'\n# changed during validation\n')
                changed = True
            return result
        try:
            with patch.object(adapter, '_read', side_effect=replace_after_read):
                self.assert_refused()
            self.assertTrue(changed)
        finally:
            target.write_bytes(original)

    def test_removing_both_complete_source_trees_refuses(self):
        import shutil
        import subprocess
        import tempfile
        from getzilla.security_corresponding_source import ROOTS
        with tempfile.TemporaryDirectory(prefix='held-source-', dir=self.copy.parent) as saved:
            try:
                for index, prefix in enumerate(ROOTS):
                    shutil.move(str(self.copy / prefix), str(Path(saved) / str(index)))
                    subprocess.run(['git', '-C', str(self.copy), 'rm', '-qr', '--cached', '--', prefix], check=True)
                result = collect_inventory(self.copy)
                self.assertNotIn('corresponding_sources', result)
                self.assertTrue(any(g['code'] == 'corresponding-source-unverified' for g in result['gaps']))
            finally:
                for index, prefix in enumerate(ROOTS):
                    shutil.move(str(Path(saved) / str(index)), str(self.copy / prefix))
                    subprocess.run(['git', '-C', str(self.copy), 'add', '-f', '--', prefix], check=True)

    def test_original_budget_is_not_reset_between_reads(self):
        from unittest.mock import patch
        from getzilla import security_corresponding_source as adapter
        with patch.object(adapter, 'monotonic', side_effect=[0, adapter.MAX_SECONDS + 1]):
            self.assert_refused()
