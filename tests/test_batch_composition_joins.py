"""Owned source-composition joins; no real project producers or installations."""
from __future__ import annotations

import ast
import contextlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

import getzilla
from getzilla import verification_plan
# Preload before the pure boundary.
from getzilla import verification_tool_workspace  # noqa: F401
from tests import _support

_PURE = False


def _audit(event, args):
    if _PURE and (event == 'open' or event in {'os.listdir', 'os.scandir', 'os.system', 'os.fork', 'os.posix_spawn'}
                  or event.startswith(('socket.', 'subprocess.', 'ctypes.'))):
        raise AssertionError('pure source-binding fixture denied an external effect')


sys.addaudithook(_audit)


@contextlib.contextmanager
def pure():
    global _PURE
    _PURE = True
    try:
        yield
    finally:
        _PURE = False


class _Registry:
    def __truediv__(self, part):
        return self

    def is_file(self):
        return True

    def is_symlink(self):
        return False

    def stat(self):
        return SimpleNamespace(st_size=2)

    def read_bytes(self):
        return b'{}'


class PolicySourceJoinTests(unittest.TestCase):
    def test_packagist_helpers_change_actual_policy_binding(self):
        helpers = ('security_artifacts.py', 'security_license_acquisition.py', 'security_packagist.py')
        contents = {name: b'owned source version one' for name in helpers}
        loaded = []

        def imported(name, package):
            filename = name.removeprefix('.') + '.py'
            loaded.append(filename)
            return SimpleNamespace(filename=filename)

        with mock.patch.object(verification_plan, '_POLICY_PATHS', ()), \
                mock.patch.object(verification_plan.importlib, 'import_module', side_effect=imported), \
                mock.patch.object(verification_plan, '_module_source',
                                  side_effect=lambda module: contents.get(module.filename, module.filename.encode())), \
                mock.patch.object(getzilla, 'STACK_DIR', _Registry()), pure():
            baseline = verification_plan.policy_binding(Path('owned-source-only'))
            self.assertTrue(set(helpers) <= set(baseline['implementation']),
                            'Packagist interpretation must be in the actual loaded policy closure')
            for name in helpers:
                self.assertEqual(loaded.count(name), 1)
            for name in helpers:
                contents[name] = b'owned changed source'
                changed = verification_plan.policy_binding(Path('owned-source-only'))
                self.assertNotEqual(changed['digest'], baseline['digest'], name)
                self.assertNotEqual(changed['implementation'][name], baseline['implementation'][name])
                contents[name] = b'owned source version one'

    def test_both_original_provider_sets_remain_once(self):
        # Actual policy execution with inert module bytes; no default source or plan producer.
        loaded = []
        def imported(name, package):
            loaded.append(name.removeprefix('.') + '.py')
            return SimpleNamespace(filename=loaded[-1])
        providers = {'security_cli.py', 'public_security_context.py', 'security_oci.py', 'process_limits.py',
                     'architecture_diff.py', 'architecture_fitness.py', 'receipts.py', 'review_plan.py',
                     'queue_provenance.py', 'python_source_proof.py', 'git_binding_guard.py'}
        with mock.patch.object(verification_plan, '_POLICY_PATHS', ()), \
                mock.patch.object(verification_plan.importlib, 'import_module', side_effect=imported), \
                mock.patch.object(verification_plan, '_module_source', side_effect=lambda module: module.filename.encode()), \
                mock.patch.object(getzilla, 'STACK_DIR', _Registry()), pure():
            observed = verification_plan.policy_binding(Path('owned-source-only'))
            self.assertTrue(providers <= set(observed['implementation']))
            self.assertEqual(len(loaded), len(set(loaded)))


class FixtureSelectionJoinTests(unittest.TestCase):
    def test_source_only_and_full_copies_keep_distinct_image_and_runtime_contracts(self):
        private = Path(__file__).resolve().parents[1] / '.getzilla/runtime/scratch'
        private.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='batch-source-fixture-', dir=private) as directory:
            base = Path(directory)
            source = base / 'source'
            config = source / '.getzilla/config'
            config.mkdir(parents=True)
            (config / 'ci-images.json').write_bytes(b'owned image declaration')
            (config / 'python-quality-requirements.txt').write_bytes(b'owned quality requirements')
            implementation = source / '.getzilla/getzilla/fixture_runtime.py'
            implementation.parent.mkdir()
            implementation.write_bytes(b'owned runtime bytes')
            (source / '.getzilla/getzilla/__init__.py').write_bytes(b'')

            @contextlib.contextmanager
            def destination():
                with tempfile.TemporaryDirectory(prefix='destination-', dir=base) as target:
                    yield target

            with mock.patch.object(_support, 'PROJECT', source), \
                    mock.patch.object(_support, '_test_directory', destination), \
                    mock.patch('subprocess.Popen', side_effect=AssertionError('fixture forbids subprocesses')):
                with _support.project_copy(minimal_runtime=True, source_only_runtime=True) as target:
                    self.assertFalse((target / '.getzilla/config/ci-images.json').exists())
                    self.assertFalse((target / '.getzilla/config/python-quality-requirements.txt').exists())
                    self.assertEqual((target / '.getzilla/getzilla/fixture_runtime.py').read_bytes(), b'owned runtime bytes')
                with _support.project_copy(minimal_runtime=True) as target:
                    self.assertEqual((target / '.getzilla/config/ci-images.json').read_bytes(), b'owned image declaration')
                    self.assertFalse((target / '.getzilla/getzilla/fixture_runtime.py').exists())


class ManagedDeclarationJoinTests(unittest.TestCase):
    def test_installer_keeps_unique_live_and_search_declarations(self):
        source = (Path(__file__).resolve().parents[1] / 'scripts/install_into.py').read_bytes()
        with pure():
            tree = ast.parse(source)
            value = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                         and any(isinstance(t, ast.Name) and t.id == 'MANAGED_FILES' for t in node.targets))
            names = [node.value for node in value.elts if isinstance(node, ast.Constant) and isinstance(node.value, str)]
            for name in ('scripts/getzilla_live.py', 'scripts/getzilla_live_lifecycle.py',
                         'scripts/getzilla_search_gateway.py', 'docs/search-gateway.md', 'docs/isolated-ci-acceptance.md'):
                self.assertEqual(names.count(name), 1, name)
            self.assertEqual(len(names), len(set(names)))

    def test_shared_resource_owner_and_all_live_paths_remain_unambiguous(self):
        source = (Path(__file__).resolve().parents[1] / 'architecture/system.yaml').read_bytes()
        with pure():
            model = json.loads(source)
            owners = [node['id'] for node in model['nodes']
                      if '.getzilla/getzilla/disposable_resources.py' in node['repository_paths']]
            self.assertEqual(owners, ['NODE-ISOLATED-ACCEPTANCE'])
            observer = next(node for node in model['nodes'] if node['id'] == 'NODE-LIVE-COMPONENT-OBSERVER')
            self.assertTrue({'.getzilla/getzilla/live_acceptance.py', '.getzilla/getzilla/live_contracts.py',
                             '.getzilla/getzilla/live_lifecycle.py', 'scripts/getzilla_live.py',
                             'scripts/getzilla_live_lifecycle.py'} <= set(observer['repository_paths']))
            self.assertEqual(len(model['nodes']), len({node['id'] for node in model['nodes']}))
