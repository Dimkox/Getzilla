"""Closed diagnostics for trusted interpreter tag tooling."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.public_security_context import _preparation_fault, _preparation_step
from getzilla.security_artifacts import ArtifactError


class PythonTagProviderTests(unittest.TestCase):
    def test_tag_provider_import_failure_is_distinct_from_unqualified_tags(self):
        from getzilla.security_python_target import observe_target

        tags = 'pip._vendor.packaging.tags'
        markers = 'pip._vendor.packaging.markers'
        for provider, code in ((None, 'artifact-tag-provider-unavailable'),
                               (SimpleNamespace(sys_tags=lambda: ()), 'artifact-target-unknown')):
            with self.subTest(code=code), mock.patch.dict(sys.modules, {
                    tags: provider, markers: SimpleNamespace(default_environment=dict)}):
                with self.assertRaises(ArtifactError) as caught, _preparation_step('package-target'):
                    observe_target()
                self.assertEqual(_preparation_fault(caught.exception), {
                    'stage': 'package-target', 'error_kind': 'artifact', 'error_code': code, 'errno': None})

    def test_malformed_tag_module_initialization_keeps_unknown_refusal(self):
        from getzilla.security_python_target import observe_target
        original = __import__

        def malformed(name, *args, **kwargs):
            if name == 'pip._vendor.packaging.tags':
                raise ValueError('PRIVATE_MARKER')
            return original(name, *args, **kwargs)

        with mock.patch('builtins.__import__', malformed):
            with self.assertRaises(ArtifactError) as caught, _preparation_step('package-target'):
                observe_target()
        self.assertEqual(_preparation_fault(caught.exception)['error_code'], 'artifact-target-unknown')
