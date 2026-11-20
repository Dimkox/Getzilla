"""Proven Git absence is data, while unsafe metadata remains unavailable."""
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from getzilla import execution, fsx, package_status, state
from tests.execution_contract_support import CountingBackend, owned_route

ROOT = Path(__file__).resolve().parents[1]


class GitlessObservationTests(unittest.TestCase):
    def setUp(self):
        folder = ROOT / '.getzilla/runtime/scratch/gitless-observations'
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = tempfile.TemporaryDirectory(dir=folder)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'owned_source.py').write_text('VALUE = "owned fixture"\n')
        (self.root / 'owned_source.py').chmod(0o644)
        self.addCleanup(state.bind_session, None)

    def test_exact_missing_registration_never_invokes_or_inherits_parent_git(self):
        self.assertFalse((self.root / '.git').exists())
        with patch.object(package_status, 'run_git_read', side_effect=AssertionError('Git must not run')):
            for arguments in (['rev-parse', '--show-toplevel'],
                              ['rev-parse', '--show-prefix', '--is-inside-work-tree']):
                code, output = package_status._git_read(self.root, arguments)
                self.assertNotEqual(code, 0)
                self.assertEqual(output, b'')

    @unittest.skipUnless(os.name == 'posix', 'public source custody requires the POSIX profile')
    def test_canonical_gitless_execution_keeps_real_inventory_and_context(self):
        route = owned_route(self.root)
        caller = execution.trusted_caller(self.root)
        backend = CountingBackend()
        result = execution.submit(self.root, caller, execution.SubmitRequest('owned-gitless', {}, 30), backend=backend)
        self.assertEqual(backend.calls, 1)
        self.assertIsNone(result['source']['git_head'])
        self.assertIsNone(result['source']['tree_fingerprint'])
        self.assertRegex(result['source']['fingerprint'], r'^[0-9a-f]{64}$')
        from getzilla.continuity import context_binding
        self.assertEqual(result['source']['context_digest'], context_binding(self.root, route)['digest'])
        self.assertFalse(result['evidence_authority'])

    def test_present_malformed_or_linked_registration_is_not_absence(self):
        registration = self.root / '.git'
        kinds = ['malformed-file', 'empty-directory']
        if os.name == 'posix':
            kinds += ['dangling-link', 'directory-link']
        for kind in kinds:
            with self.subTest(kind=kind):
                if kind == 'malformed-file':
                    registration.write_text('not a Git registration\n')
                elif kind == 'empty-directory':
                    registration.mkdir()
                else:
                    target = self.root / 'owned-target'
                    if kind == 'directory-link':
                        target.mkdir()
                    registration.symlink_to(target, target_is_directory=True)
                with self.assertRaises(package_status.InspectionError):
                    package_status._git_read(self.root, ['rev-parse', '--show-toplevel'])
                if registration.is_dir() and not registration.is_symlink():
                    registration.rmdir()
                else:
                    registration.unlink()

    def test_unavailable_leaf_observation_does_not_become_gitless(self):
        original = fsx.lstat_at
        def unavailable(parent, name):
            if name == '.git':
                raise PermissionError('synthetic unreadable registration')
            return original(parent, name)
        with patch.object(fsx, 'lstat_at', side_effect=unavailable):
            with self.assertRaises(package_status.InspectionError):
                package_status._git_read(self.root, ['rev-parse', '--show-toplevel'])

    def test_registration_appearing_during_absence_check_is_unavailable(self):
        original = fsx.lstat_at
        seen = []
        def appear(parent, name):
            if name == '.git' and not seen:
                seen.append(True)
                (self.root / '.git').write_text('not a Git registration\n')
                raise FileNotFoundError('synthetic first absent cut')
            return original(parent, name)
        with patch.object(fsx, 'lstat_at', side_effect=appear):
            with self.assertRaises(package_status.InspectionError):
                package_status._git_read(self.root, ['rev-parse', '--show-toplevel'])
