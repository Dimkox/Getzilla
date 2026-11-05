"""A trace context cut cannot fall back to pathname package/schema reads."""
import os
import shutil
import unittest
from unittest.mock import patch

from tests._support import PROJECT, project_copy
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
