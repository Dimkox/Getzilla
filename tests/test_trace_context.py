"""A trace context cut cannot fall back to pathname package/schema reads."""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from tests._support import PROJECT
from tests._native_public_fixture import project_copy
from tests import test_task_continuity as continuity_fixtures
from getzilla import state
from getzilla.continuity import context_binding
from getzilla.observation_privacy import initialize_private
from getzilla.trace_storage import native_root


class AnchoredContextTests(unittest.TestCase):
    def setUp(self):
        saved = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, saved)
        self.root = self.enterContext(project_copy(minimal_runtime=True))
        self.addCleanup(os.fchdir, saved)
        self.root.chmod(0o755)
        (self.root / '.getzilla').chmod(0o755)
        os.chdir(self.root)
        (self.root / 'schemas').mkdir(mode=0o755)
        shutil.copy2(PROJECT / 'schemas/change-spec.schema.json', self.root / 'schemas/change-spec.schema.json')
        fixture = continuity_fixtures.ContinuityTests()
        fixture.route(self.root)
        fixture.package(self.root)
        (self.root / 'tests').chmod(0o755)
        (self.root / 'tests/test_task_continuity.py').chmod(0o644)
        self.route = state.get_active_route(self.root)
        initialize_private(self.root)
        # Explicit private setup of this test-owned native package. Existing
        # native package creation modes are a separate initialization case.
        package = self.root / state.get_active_change(self.root)['path']
        package.chmod(0o700)
        for name in ('state.json', 'change-spec.yaml', 'requirements.md'):
            (package / name).chmod(0o600)
        self.addCleanup(state.bind_session, None)

    def test_full_context_uses_anchored_schema_contract_and_package_reads(self):
        expected = context_binding(self.root, self.route)
        with native_root(self.root) as anchor:
            with patch('getzilla.package_status.read_package_file', side_effect=AssertionError('path read fallback')):
                actual = context_binding(self.root, self.route, anchor=anchor)
        self.assertEqual(actual, expected)

    def test_original_scope_gap_checks_use_the_same_anchored_context(self):
        from getzilla.continuity import scope_gaps
        expected = scope_gaps(self.root, self.route)
        with native_root(self.root) as anchor:
            with patch('getzilla.package_status.read_package_file', side_effect=AssertionError('path read fallback')):
                actual = scope_gaps(self.root, self.route, anchor=anchor)
        self.assertEqual(actual, expected)

    def test_original_spec_validation_uses_anchored_package_and_schema(self):
        from getzilla.spec import validate_spec
        path = self.root/state.get_active_change(self.root)['path']/'change-spec.yaml'
        expected = validate_spec(self.root,path,gate=False,route=self.route)
        with native_root(self.root) as anchor:
            with patch('getzilla.spec.load_spec',side_effect=AssertionError('path fallback')):
                actual = validate_spec(self.root,path,gate=False,route=self.route,anchor=anchor)
        self.assertEqual(actual,expected)

    def test_unqualified_private_spec_returns_original_validation_failure_shape(self):
        from getzilla.spec import validate_spec
        path = self.root/state.get_active_change(self.root)['path']/'change-spec.yaml'
        path.chmod(0o644)
        with native_root(self.root) as anchor:
            errors = validate_spec(self.root,path,gate=False,route=self.route,anchor=anchor)
        self.assertTrue(errors)
        self.assertTrue(all(isinstance(item,str) for item in errors))

    def test_original_receipt_spec_binding_uses_same_native_package(self):
        from getzilla import receipts
        subprocess.run(['git','init','-q'],cwd=self.root,check=True)
        subprocess.run(['git','-c','user.name=Test','-c','user.email=test@example.invalid',
                        '-c','maintenance.auto=false','commit','--allow-empty','-qm','fixture'],
                       cwd=self.root,check=True)
        expected = receipts._active_spec_binding(self.root,self.route,'verification')
        with native_root(self.root) as anchor:
            with patch.object(receipts,'load_spec',side_effect=AssertionError('path fallback')):
                actual = receipts._active_spec_binding(self.root,self.route,'verification',anchor=anchor)
        self.assertEqual(actual,expected)

    def test_receipt_spec_binding_keeps_original_source_during_actual_launch_switch(self):
        from getzilla import receipts
        subprocess.run(['git','init','-q'],cwd=self.root,check=True)
        subprocess.run(['git','-c','user.name=Test','-c','user.email=test@example.invalid',
                        '-c','maintenance.auto=false','commit','--allow-empty','-qm','fixture A'],
                       cwd=self.root,check=True)
        foreign = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='native-public-B-')))
        subprocess.run(['git','init','-q'],cwd=foreign,check=True)
        subprocess.run(['git','-c','user.name=Test','-c','user.email=test@example.invalid',
                        '-c','maintenance.auto=false','commit','--allow-empty','-qm','fixture B'],
                       cwd=foreign,check=True)
        expected = receipts._active_spec_binding(self.root,self.route,'verification')
        real_popen,calls = subprocess.Popen,[]
        def switched(command,**kwargs):
            os.chdir(foreign)
            try:
                child = real_popen(command,**kwargs)
                calls.append(True)
                return child
            finally:
                os.chdir(self.root)
        with native_root(self.root) as anchor,patch('subprocess.Popen',side_effect=switched):
            actual = receipts._active_spec_binding(self.root,self.route,'verification',anchor=anchor)
        self.assertGreaterEqual(len(calls),3)
        self.assertEqual(actual,expected)
        self.assertEqual(Path.cwd(),self.root)

    def test_original_receipt_spec_binding_refuses_unqualified_active_spec(self):
        from getzilla import receipts
        path = self.root/state.get_active_change(self.root)['path']/'change-spec.yaml'
        path.chmod(0o644)
        with native_root(self.root) as anchor:
            with self.assertRaises((ValueError,OSError)):
                receipts._active_spec_binding(self.root,self.route,'verification',anchor=anchor)

    def test_original_spec_fingerprint_keeps_native_contract_and_cwd_source(self):
        from getzilla import spec as module
        subprocess.run(['git','init','-q'],cwd=self.root,check=True)
        subprocess.run(['git','-c','user.name=Test','-c','user.email=test@example.invalid',
                        '-c','maintenance.auto=false','commit','--allow-empty','-qm','fixture'],
                       cwd=self.root,check=True)
        directory = self.root/'contracts'
        directory.mkdir(mode=0o755)
        contract = directory/'one.json'
        contract.write_text('{"synthetic":true}\n')
        contract.chmod(0o644)
        path = self.root/state.get_active_change(self.root)['path']/'change-spec.yaml'
        spec = module.load_spec(path,allow_legacy=False)
        spec['contracts']['json_schema'] = ['contracts/one.json']
        expected = module.spec_fingerprint(self.root,path,spec,self.route)
        with native_root(self.root) as anchor:
            self.assertEqual(module.spec_fingerprint(self.root,path,spec,self.route,anchor=anchor),expected)
            contract.chmod(0o600)
            with patch('os.read',side_effect=AssertionError('private source read')):
                with self.assertRaises(module.SpecError):
                    module._contract_digest(self.root,'contracts/one.json',anchor=anchor)

    def test_changed_context_package_is_refused(self):
        with native_root(self.root) as anchor:
            relative = state.get_active_change(self.root)['path'] + '/requirements.md'
            original = anchor.read(relative)
            calls = []
            real_read = anchor.read
            def changing(path, *args, **kwargs):
                raw = real_read(path, *args, **kwargs)
                if str(path) == relative and not calls:
                    calls.append(True)
                    anchor.write(relative, original + b'changed\n')
                return raw
            with patch.object(anchor, 'read', side_effect=changing):
                with self.assertRaises(ValueError):
                    context_binding(self.root, self.route, anchor=anchor)
            self.assertEqual(calls, [True], 'the controlled requirements change must actually occur')

    def test_explicit_selected_package_initialization_changes_modes_only(self):
        package = self.root / state.get_active_change(self.root)['path']
        package.chmod(0o755)
        original = {}
        for name in ('state.json', 'change-spec.yaml', 'requirements.md'):
            (package / name).chmod(0o644)
            original[name] = (package / name).read_bytes()
        initialize_private(self.root, selected_package=True)
        self.assertEqual(package.stat().st_mode & 0o777, 0o700)
        for name, raw in original.items():
            self.assertEqual((package / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual((package / name).read_bytes(), raw)

    def test_selected_package_hardlink_is_not_normalized(self):
        package = self.root / state.get_active_change(self.root)['path']
        path = package / 'requirements.md'
        path.chmod(0o644)
        os.link(path, self.root / 'foreign-linked-sentinel')
        with self.assertRaises(ValueError):
            initialize_private(self.root, selected_package=True)
        self.assertEqual((self.root / 'foreign-linked-sentinel').stat().st_mode & 0o777, 0o644)


if __name__ == '__main__':
    unittest.main()
