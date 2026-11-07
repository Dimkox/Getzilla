"""Common optional-module lifecycle reuses component ownership and never runs addons."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]
from getzilla.component_state import (  # noqa: E402
    MANIFEST, V2, ComponentTransaction, component_of, encode_manifest, read_state, record_owned,
)
from getzilla.optional_modules import (  # noqa: E402
    ModuleError, REGISTRY, PENDING, admit_module, manage_modules,
    module_status, plan_modules, recover_modules, rollback_modules,
)


def installer():
    spec = importlib.util.spec_from_file_location('optional_module_installer', ROOT / 'scripts/install_into.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OptionalModuleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.source = self.workspace / 'source'
        self.root = self.workspace / 'project'
        self.source.mkdir()
        self.root.mkdir()
        self.registry = {'schema_version': 1, 'core_api': 1,
                         'publishers': {'getzilla': {'licenses': ['MIT', 'LicenseRef-Proprietary']}}, 'modules': {}}
        self.install_core(self.root)
        self.make_module('context', '1.0.0')
        self.make_module('context', '2.0.0', files={'context.json': (b'{"version":2}\n', False),
                                                'settings.json': (b'{"theme":"new"}\n', True)})
        self.client_settings = {'.mcp.json': b'{ "mcpServers": { "other": { "token": "fake-user-value" } } }\n',
                                '.codex/config.toml': b'# user config\n[mcp_servers.existing]\nurl="https://example.invalid"\n',
                                '.getzilla/browser.json': b'{"preview":"user-browser","enabled":true}\n'}
        for path, content in self.client_settings.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

    def install_core(self, root):
        path = root / '.getzilla/getzilla/__init__.py'
        path.parent.mkdir(parents=True)
        path.write_bytes(b'# existing core\n')
        manifest = {'schema_version': V2, 'agents': [], 'components': {}}
        record_owned(manifest, '.getzilla/getzilla/__init__.py', path.read_bytes(), 0o644)
        (root / MANIFEST).write_bytes(encode_manifest(manifest))

    def write_registry(self):
        path = self.source / REGISTRY
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.registry, sort_keys=True), encoding='utf-8')

    def make_module(self, name, version, *, dependencies=None, permissions=None, files=None,
                    entitlement=None, core_api=None, hooks=None):
        folder = self.source / '.getzilla/optional-modules' / name / version
        folder.mkdir(parents=True, exist_ok=True)
        payload = {'context.json': (b'{"version":1}\n', False), 'settings.json': (b'{"theme":"default"}\n', True)} if files is None else files
        payload = {'LICENSE': (b'MIT synthetic fixture license\n', False), **payload}
        entries = []
        for path, (content, mutable) in payload.items():
            target = folder / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            entries.append({'path': path, 'sha256': hashlib.sha256(content).hexdigest(), 'mode': 0o644, 'mutable': mutable})
        value = {'schema_version': 1, 'id': name, 'version': version, 'publisher': 'getzilla',
                 'core_api': core_api or {'min': 1, 'max': 1}, 'license': 'LicenseRef-Proprietary' if entitlement else 'MIT',
                 'entitlement': entitlement, 'dependencies': dependencies or {},
                 'permissions': permissions or ['context.read'], 'hooks': hooks or 'declarative-v1', 'files': entries}
        manifest = folder / 'module.json'
        manifest.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
        self.registry['modules'].setdefault(name, {'publisher': 'getzilla', 'versions': {}})['versions'][version] = {
            'manifest': manifest.relative_to(self.source).as_posix(), 'sha256': hashlib.sha256(manifest.read_bytes()).hexdigest()}
        self.write_registry()
        return manifest

    def run_module(self, operation, requests=None, **kwargs):
        return manage_modules(self.root, operation, requests or {}, source=self.source, **kwargs)

    def module_file(self, path='context.json', name='context'):
        return self.root / '.getzilla/modules' / name / path

    def assert_user_settings(self):
        for path, content in self.client_settings.items():
            self.assertEqual((self.root / path).read_bytes(), content, path)

    def test_lifecycle_installs_disabled_and_preserves_foreign_settings(self):
        initial_core = (self.root / '.getzilla/getzilla/__init__.py').read_bytes()
        report = self.run_module('install', {'context': '1.0.0'})
        self.assertEqual(report['status'], 'applied')
        self.assertFalse(module_status(self.root)['modules']['context']['enabled'])
        self.assertFalse(admit_module(self.root, 'context')['allowed'])
        self.run_module('enable', {'context': None}, grants=['context.read'])
        self.assertTrue(admit_module(self.root, 'context', permission='context.read')['allowed'])
        self.run_module('disable', {'context': None})
        self.assertFalse(admit_module(self.root, 'context')['allowed'])
        self.run_module('update', {'context': '2.0.0'})
        self.assertEqual(json.loads(self.module_file().read_bytes()), {'version': 2})
        self.assertFalse(module_status(self.root)['modules']['context']['enabled'])
        self.assertEqual(rollback_modules(self.root)['status'], 'rolled_back')
        self.assertEqual(json.loads(self.module_file().read_bytes()), {'version': 1})
        self.assertEqual(rollback_modules(self.root)['status'], 'already_rolled_back')
        self.run_module('uninstall', {'context': None})
        self.assertNotIn('context', module_status(self.root)['modules'])
        self.assertFalse(self.module_file().exists())
        self.assertEqual((self.root / '.getzilla/getzilla/__init__.py').read_bytes(), initial_core)
        self.assert_user_settings()

    def test_exact_dependency_resolution_and_installed_conflicts(self):
        self.make_module('reader', '1.0.0', dependencies={'context': '1.0.0'})
        report = plan_modules(self.root, 'install', {'reader': '1.0.0'}, source=self.source)
        self.assertEqual(report['dependency_order'], ['context', 'reader'])
        self.assertEqual(set(report['artifacts']), {'context', 'reader'})
        self.assertGreater(report['artifacts']['context']['bytes'], 0)
        print(json.dumps({'module_dependency_footprint': report['artifacts'], 'external_dependencies_installed': 0}, sort_keys=True))
        self.assertFalse((self.root / '.getzilla/runtime').exists())
        self.run_module('install', {'reader': '1.0.0'})
        self.assertFalse(module_status(self.root)['modules']['context']['enabled'])
        before = (self.root / MANIFEST).read_bytes()
        self.make_module('other', '1.0.0', dependencies={'context': '2.0.0'})
        with self.assertRaises(ModuleError):
            self.run_module('install', {'other': '1.0.0'})
        with self.assertRaises(ModuleError):
            self.run_module('uninstall', {'context': None})
        with self.assertRaises(ModuleError):
            self.run_module('update', {'context': '2.0.0'})
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)

    def test_cycles_and_batch_conflicts_refuse_before_guard_creation(self):
        self.make_module('first', '1.0.0', dependencies={'second': '1.0.0'})
        self.make_module('second', '1.0.0', dependencies={'first': '1.0.0'})
        for requests in ({'first': '1.0.0'}, {'context': '1.0.0', 'unknown': '1.0.0'}):
            with self.subTest(requests=requests):
                with self.assertRaises(ModuleError):
                    self.run_module('install', requests)
                self.assertFalse((self.root / '.getzilla/runtime').exists())
                self.assertFalse(self.module_file().exists())

    def test_enable_is_project_scoped_and_needs_exact_declared_permissions(self):
        self.run_module('install', {'context': '1.0.0'})
        second = self.workspace / 'second-project'
        second.mkdir()
        self.install_core(second)
        manage_modules(second, 'install', {'context': '1.0.0'}, source=self.source)
        for grants in ([], ['context.read', 'unknown.write']):
            with self.assertRaises(ModuleError):
                self.run_module('enable', {'context': None}, grants=grants)
        self.run_module('enable', {'context': None}, grants=['context.read'])
        self.assertTrue(admit_module(self.root, 'context')['allowed'])
        self.assertFalse(admit_module(second, 'context')['allowed'])
        self.assertFalse(admit_module(self.root, 'context', permission='unknown.write')['allowed'])

    def test_update_and_rollback_never_revive_grants(self):
        self.run_module('install', {'context': '1.0.0'})
        self.run_module('enable', {'context': None}, grants=['context.read'])
        self.run_module('update', {'context': '2.0.0'})
        self.assertFalse(admit_module(self.root, 'context')['allowed'])
        rollback_modules(self.root)
        state = module_status(self.root)['modules']['context']
        self.assertFalse(state['enabled'])
        self.assertEqual(state['grants'], [])
        self.run_module('enable', {'context': None}, grants=['context.read'])
        self.run_module('disable', {'context': None})
        rollback_modules(self.root)
        self.assertFalse(admit_module(self.root, 'context')['allowed'])

    def test_user_config_and_unknown_files_survive_update_and_uninstall(self):
        self.run_module('install', {'context': '1.0.0'})
        self.module_file('settings.json').write_bytes(b'{"secret":"fake-user-credential"}\n')
        self.module_file('notes.txt').write_bytes(b'user note\n')
        self.run_module('update', {'context': '2.0.0'})
        self.assertEqual(self.module_file('settings.json').read_bytes(), b'{"secret":"fake-user-credential"}\n')
        self.run_module('uninstall', {'context': None})
        self.assertEqual(self.module_file('settings.json').read_bytes(), b'{"secret":"fake-user-credential"}\n')
        self.assertEqual(self.module_file('notes.txt').read_bytes(), b'user note\n')
        self.assert_user_settings()

    def test_modified_immutable_file_refuses_update_and_is_kept_by_uninstall(self):
        self.run_module('install', {'context': '1.0.0'})
        self.module_file().write_bytes(b'user changes\n')
        before = (self.root / MANIFEST).read_bytes()
        with self.assertRaises(ModuleError):
            self.run_module('update', {'context': '2.0.0'})
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)
        report = self.run_module('uninstall', {'context': None})
        self.assertIn('.getzilla/modules/context/context.json', report['preserved'])
        self.assertEqual(self.module_file().read_bytes(), b'user changes\n')

    def test_manifest_keep_contract_blocks_before_any_payload_write(self):
        before = (self.root / MANIFEST).read_bytes()
        (self.root / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': [MANIFEST],
            'kept_local_sha256': {MANIFEST: hashlib.sha256(before).hexdigest()}}), encoding='utf-8')
        with self.assertRaises(ModuleError):
            self.run_module('install', {'context': '1.0.0'})
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)
        self.assertFalse(self.module_file().exists())
        self.assertFalse((self.root / '.getzilla/runtime').exists())

    def test_registry_and_artifact_negative_cases_are_read_only(self):
        original_registry = deepcopy(self.registry)
        for kind in ('registry-key', 'publisher', 'manifest-hash', 'api', 'hook', 'traversal', 'file-hash', 'case-alias'):
            with self.subTest(kind=kind):
                self.registry = deepcopy(original_registry)
                manifest = self.make_module('context', '1.0.0')
                data = json.loads(manifest.read_bytes())
                if kind == 'registry-key':
                    self.registry['surprise'] = True
                if kind == 'publisher':
                    data['publisher'] = 'untrusted'
                if kind == 'manifest-hash':
                    self.registry['modules']['context']['versions']['1.0.0']['sha256'] = '0' * 64
                if kind == 'api':
                    data['core_api'] = {'min': 2, 'max': 3}
                if kind == 'hook':
                    data['hooks'] = {'install': 'run arbitrary command'}
                if kind == 'traversal':
                    data['files'][0]['path'] = '../../outside'
                if kind == 'file-hash':
                    data['files'][0]['sha256'] = '0' * 64
                if kind == 'case-alias':
                    data['files'].append({**data['files'][0], 'path': 'license'})
                if kind not in ('registry-key', 'manifest-hash'):
                    manifest.write_text(json.dumps(data), encoding='utf-8')
                    self.registry['modules']['context']['versions']['1.0.0']['sha256'] = hashlib.sha256(manifest.read_bytes()).hexdigest()
                self.write_registry()
                with self.assertRaises(ModuleError):
                    self.run_module('install', {'context': '1.0.0'})
                self.assertFalse((self.root / '.getzilla/runtime').exists())
                self.assertFalse(self.module_file().exists())

    def test_artifact_link_is_rejected_before_product_writes(self):
        path = self.source / '.getzilla/optional-modules/context/1.0.0/context.json'
        target = self.source / 'outside.json'
        target.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(target)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaises(ModuleError):
            self.run_module('install', {'context': '1.0.0'})
        self.assertFalse(self.module_file().exists())
        self.assertFalse((self.root / '.getzilla/runtime').exists())

    def test_disabled_operations_never_launch_import_authenticate_or_connect(self):
        forbidden = AssertionError('generic lifecycle must stay local and passive')
        with patch('socket.socket', side_effect=forbidden), patch('subprocess.Popen', side_effect=forbidden), \
             patch('importlib.import_module', side_effect=forbidden):
            self.run_module('install', {'context': '1.0.0'})
            module_status(self.root)
            self.run_module('update', {'context': '2.0.0'})
            self.run_module('enable', {'context': None}, grants=['context.read'])
            self.run_module('disable', {'context': None})
            self.run_module('uninstall', {'context': None})
        self.assertEqual(module_status(self.root)['workers'], 0)

    def test_licensed_admission_does_not_trust_manifest_or_cli_boolean(self):
        self.make_module('licensed', '1.0.0', entitlement='enterprise.api')
        with self.assertRaises(ModuleError):
            self.run_module('install', {'licensed': '1.0.0'})
        with self.assertRaises(ModuleError):
            self.run_module('install', {'licensed': '1.0.0'}, entitlement=lambda *args: True)
        def verified(project, module, version, capability):
            return {'verified': True, 'project': str(project), 'module': module, 'version': version, 'capability': capability}
        self.run_module('install', {'licensed': '1.0.0'}, entitlement=verified)
        self.run_module('enable', {'licensed': None}, grants=['context.read'], entitlement=verified)
        self.assertFalse(admit_module(self.root, 'licensed')['allowed'])
        self.assertTrue(admit_module(self.root, 'licensed', entitlement=verified)['allowed'])
        self.run_module('disable', {'licensed': None})
        self.run_module('uninstall', {'licensed': None})

    def test_failure_after_publication_rolls_back_and_retry_is_safe(self):
        before = (self.root / MANIFEST).read_bytes()
        real_write = ComponentTransaction.write
        failed = False
        def write_then_fail(transaction, path, *args, **kwargs):
            nonlocal failed
            result = real_write(transaction, path, *args, **kwargs)
            if path.endswith('/context.json') and not failed:
                failed = True
                raise OSError('injected post-publication failure')
            return result
        with patch.object(ComponentTransaction, 'write', new=write_then_fail):
            with self.assertRaises(ModuleError):
                self.run_module('install', {'context': '1.0.0'})
        self.assertTrue(failed)
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)
        self.assertFalse(self.module_file().exists())
        self.assertFalse((self.root / PENDING).exists())
        self.run_module('install', {'context': '1.0.0'})
        self.assertIn('context', module_status(self.root)['modules'])

    def test_recovery_preserves_intervening_user_edit_and_blocks_admission(self):
        self.run_module('install', {'context': '1.0.0'})
        real_write = ComponentTransaction.write
        failed = False
        def edit_then_fail(transaction, path, *args, **kwargs):
            nonlocal failed
            result = real_write(transaction, path, *args, **kwargs)
            if path.endswith('/context.json') and not failed:
                failed = True
                self.module_file().write_bytes(b'intervening user change\n')
                raise OSError('injected conflict')
            return result
        with patch.object(ComponentTransaction, 'write', new=edit_then_fail):
            with self.assertRaises(ModuleError):
                self.run_module('update', {'context': '2.0.0'})
        self.assertTrue((self.root / PENDING).exists())
        self.assertFalse(admit_module(self.root, 'context')['allowed'])
        with self.assertRaises(ModuleError):
            recover_modules(self.root)
        self.assertEqual(self.module_file().read_bytes(), b'intervening user change\n')
        self.module_file().write_bytes(b'{"version":2}\n')
        self.assertEqual(recover_modules(self.root)['status'], 'recovered')
        self.assertEqual(json.loads(self.module_file().read_bytes()), {'version': 1})
        self.assertEqual(recover_modules(self.root)['status'], 'nothing_to_recover')

    def test_malformed_journal_cannot_write_core_or_outside_module(self):
        pending = self.root / PENDING
        pending.parent.mkdir(parents=True)
        pending.write_bytes(b'{"schema_version":1,"operations":[{"path":"README.md"}]}')
        core = (self.root / '.getzilla/getzilla/__init__.py').read_bytes()
        with self.assertRaises(ModuleError):
            recover_modules(self.root)
        self.assertEqual((self.root / '.getzilla/getzilla/__init__.py').read_bytes(), core)
        self.assertFalse((self.root / 'README.md').exists())

    def test_existing_ledger_roundtrip_and_module_namespace_are_strict(self):
        self.run_module('install', {'context': '1.0.0'})
        state = read_state(self.root)
        record = state.manifest['components']['module:context']
        self.assertEqual(record['module']['version'], '1.0.0')
        self.assertTrue(all(component_of(path) == 'module:context' for path in record['files']))
        forged = deepcopy(state.manifest)
        forged['components']['module:context']['files'].append('README.md')
        with self.assertRaises(ValueError):
            encode_manifest(forged)
        forged = deepcopy(state.manifest)
        forged['components']['module:context']['module']['surprise'] = True
        with self.assertRaises(ValueError):
            encode_manifest(forged)

    def test_cli_uses_existing_components_entrypoint_and_installs_disabled(self):
        command = [sys.executable, str(ROOT / 'scripts/getzilla_components.py'), 'module', 'install',
                   'context@1.0.0', '--project', str(self.root), '--source', str(self.source)]
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)['status'], 'applied')
        self.assertFalse(module_status(self.root)['modules']['context']['enabled'])
        process = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_components.py'), 'module', 'enable',
                                  'context', '--project', str(self.root), '--grant', 'context.read'],
                                 capture_output=True, text=True, check=False)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(admit_module(self.root, 'context')['allowed'])

    def test_malformed_module_state_returns_value_error(self):
        self.run_module('install', {'context': '1.0.0'})
        original = read_state(self.root).manifest
        for field in ('license', 'publisher', 'permissions', 'dependencies', 'version'):
            for replacement in (None, [], {}, True, 10 ** 400):
                with self.subTest(field=field, replacement=type(replacement).__name__):
                    if (field == 'permissions' and replacement == [] or field == 'dependencies' and replacement == {}):
                        continue
                    forged = deepcopy(original)
                    forged['components']['module:context']['module'][field] = replacement
                    with self.assertRaises(ValueError):
                        encode_manifest(forged)

    def test_rollback_refuses_changed_ledger_before_creating_pending_state(self):
        self.run_module('install', {'context': '1.0.0'})
        manifest = read_state(self.root).manifest
        manifest['components']['core']['source_version'] = 'user-reconciled'
        (self.root / MANIFEST).write_bytes(encode_manifest(manifest))
        before = (self.root / MANIFEST).read_bytes()
        with self.assertRaises(ModuleError):
            rollback_modules(self.root)
        self.assertFalse((self.root / PENDING).exists())
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)

    def test_rollback_obeys_a_new_keep_local_declaration(self):
        self.run_module('install', {'context': '1.0.0'})
        self.run_module('update', {'context': '2.0.0'})
        path = '.getzilla/modules/context/context.json'
        (self.root / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': [path],
            'kept_local_sha256': {path: hashlib.sha256(self.module_file().read_bytes()).hexdigest()}}), encoding='utf-8')
        with self.assertRaises(ModuleError):
            rollback_modules(self.root)
        self.assertEqual(json.loads(self.module_file().read_bytes()), {'version': 2})
        self.assertFalse((self.root / PENDING).exists())

    def test_wrong_requested_version_cannot_enable_another_version(self):
        self.run_module('install', {'context': '1.0.0'})
        with self.assertRaises(ModuleError):
            self.run_module('enable', {'context': '2.0.0'}, grants=['context.read'])
        self.assertFalse(admit_module(self.root, 'context')['allowed'])

    def test_failure_matrix_recovers_each_publication_boundary(self):
        original_root = self.root
        self.make_module('context', '2.0.0', files={
            'LICENSE': (b'MIT updated synthetic fixture license\n', False),
            'context.json': (b'{"version":2}\n', False), 'settings.json': (b'{"theme":"new"}\n', True)})
        phases = ('pending', 'LICENSE', 'context.json', 'module.json', 'settings.json', 'manifest', 'history', 'last')
        for n, phase in enumerate(phases):
            with self.subTest(phase=phase):
                self.root = self.workspace / f'failure-{n}'
                self.root.mkdir()
                self.install_core(self.root)
                self.run_module('install', {'context': '1.0.0'})
                real_write = ComponentTransaction.write
                fired = False
                def write_and_fail(transaction, path, *args, **kwargs):
                    nonlocal fired
                    result = real_write(transaction, path, *args, **kwargs)
                    selected = (path == PENDING if phase == 'pending' else path == MANIFEST if phase == 'manifest'
                                else '/history/' in path if phase == 'history' else path.endswith('/last.json') if phase == 'last'
                                else path.endswith('/' + phase))
                    if selected and not fired:
                        fired = True
                        raise OSError('injected after publication')
                    return result
                with patch.object(ComponentTransaction, 'write', new=write_and_fail):
                    with self.assertRaises(ModuleError):
                        self.run_module('update', {'context': '2.0.0'})
                self.assertTrue(fired)
                if (self.root / PENDING).exists():
                    recover_modules(self.root)
                self.assertEqual(module_status(self.root)['modules']['context']['version'], '1.0.0')
                self.assertEqual(json.loads(self.module_file().read_bytes()), {'version': 1})
                self.assertFalse((self.root / PENDING).exists())
        self.root = original_root

    def test_core_inventory_ignores_uninstalled_artifact_tree(self):
        install = installer()
        source = self.workspace / 'minimal-core-source'
        (source / '.getzilla/templates').mkdir(parents=True)
        for relative in (*install.MANAGED_FILES, install.CONSUMER_AGENTS_TEMPLATE,
                         install.CONSUMER_FACTORY_README_TEMPLATE, install.ROOT_HOOK_SHIM_TEMPLATE):
            if relative in install.ROOT_HOOK_SHIMS:
                continue
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        config = source / '.getzilla/config/toolchain.json'
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_bytes(b'{"tools":[],"workflow_sources":{"components":[]}}\n')
        (source / '.getzilla/modules').mkdir()
        (source / '.getzilla/modules/jira').mkdir()
        (source / '.getzilla/modules/jira/provider.py').write_bytes(b'raise RuntimeError("never import")\n')
        (source / '.getzilla/optional-modules').mkdir()
        (source / '.getzilla/optional-modules/unknown').mkdir()
        (source / '.getzilla/optional-modules/unknown/binary').write_bytes(b'large optional payload')
        for selection in (install.PayloadSelection(()), install.PayloadSelection.full_layout()):
            paths = {entry.path for entry in install.build_payload(source, selection=selection)}
            self.assertFalse([path for path in paths if path.startswith(('.getzilla/modules/', '.getzilla/optional-modules/'))])
        (source / '.getzilla/optional-modules/unknown/binary').unlink()
        (source / '.getzilla/optional-modules/unknown').rmdir()
        (source / '.getzilla/optional-modules').rmdir()
        try:
            (source / '.getzilla/optional-modules').symlink_to(self.source, target_is_directory=True)
        except OSError as exc:
            self.skipTest(str(exc))
        paths = {entry.path for entry in install.build_payload(source, selection=install.PayloadSelection(()))}
        self.assertIn('AGENTS.md', paths)

    def test_descriptor_and_ledger_security_fields_must_agree(self):
        self.run_module('install', {'context': '1.0.0'})
        baseline = read_state(self.root).manifest
        for field, value in (('permissions', ['context.read', 'jira.write']), ('version', '9.0.0'),
                             ('dependencies', {'missing': '1.0.0'}), ('publisher', 'other'), ('license', 'Apache-2.0')):
            with self.subTest(field=field):
                modified = deepcopy(baseline)
                modified['components']['module:context']['module'][field] = value
                (self.root / MANIFEST).write_bytes(encode_manifest(modified))
                grants = modified['components']['module:context']['module']['permissions']
                with self.assertRaises(ModuleError):
                    self.run_module('enable', {'context': None}, grants=grants)
                self.assertFalse(admit_module(self.root, 'context')['allowed'])
        (self.root / MANIFEST).write_bytes(encode_manifest(baseline))
        modified = deepcopy(baseline)
        path = '.getzilla/modules/context/context.json'
        modified['components']['module:context']['files'].remove(path)
        modified['components']['module:context']['owned'].pop(path)
        (self.root / MANIFEST).write_bytes(encode_manifest(modified))
        with self.assertRaises(ModuleError):
            self.run_module('enable', {'context': None}, grants=['context.read'])

    def test_history_capacity_never_blocks_disable(self):
        self.run_module('install', {'context': '1.0.0'})
        self.run_module('enable', {'context': None}, grants=['context.read'])
        before_history = list((self.root / '.getzilla/runtime/modules/history').iterdir())
        with patch('getzilla.optional_modules.MAX_HISTORY', len(before_history)):
            report = self.run_module('disable', {'context': None})
        self.assertEqual(report['status'], 'applied')
        self.assertFalse(report['rollback_available'])
        self.assertFalse(admit_module(self.root, 'context')['allowed'])
        self.assertEqual(list((self.root / '.getzilla/runtime/modules/history').iterdir()), before_history)

    def test_completed_pending_removal_is_reconciled_as_applied(self):
        real_remove = ComponentTransaction.remove
        fired = False
        def remove_then_fail(transaction, path, *args, **kwargs):
            nonlocal fired
            result = real_remove(transaction, path, *args, **kwargs)
            if path == PENDING and not fired:
                fired = True
                raise OSError('injected after pending removal')
            return result
        with patch.object(ComponentTransaction, 'remove', new=remove_then_fail):
            report = self.run_module('install', {'context': '1.0.0'})
        self.assertTrue(fired)
        self.assertEqual(report['status'], 'applied')
        self.assertFalse((self.root / PENDING).exists())
        self.assertEqual(module_status(self.root)['modules']['context']['version'], '1.0.0')

    def test_thirty_two_module_shared_dependency_graph_is_admitted(self):
        self.make_module('common', '1.0.0')
        dependencies = {'common': '1.0.0'}
        for n in range(30):
            name = f'leaf-{n:02d}'
            self.make_module(name, '1.0.0', dependencies={'common': '1.0.0'})
            dependencies[name] = '1.0.0'
        self.make_module('bundle', '1.0.0', dependencies=dependencies)
        # Keep the source catalog at the 32-module contract boundary.
        self.registry['modules'].pop('context')
        self.write_registry()
        self.run_module('install', {'bundle': '1.0.0'})
        self.run_module('enable', {'bundle': None}, grants=['context.read'])
        self.assertTrue(admit_module(self.root, 'bundle')['allowed'])

    def test_published_schemas_match_manifest_and_registry(self):
        from tests.json_schema_subset import SubsetValidator
        path = self.source / '.getzilla/optional-modules/context/1.0.0/module.json'
        for schema, value in (
            ('optional-module-v1.schema.json', json.loads(path.read_bytes())),
            ('optional-module-registry-v1.schema.json', self.registry)):
            validator = SubsetValidator(json.loads((ROOT / 'schemas' / schema).read_bytes()))
            validator.validate(value)
            with self.assertRaises(ValueError):
                validator.validate({**value, 'unknown': True})

    def test_incompatible_installed_version_can_update_to_compatible_version(self):
        self.run_module('install', {'context': '1.0.0'})
        self.make_module('context', '2.0.0', core_api={'min': 2, 'max': 2})
        self.registry['core_api'] = 2
        self.write_registry()
        with patch('getzilla.optional_modules.CORE_API', 2):
            self.assertFalse(admit_module(self.root, 'context')['allowed'])
            self.run_module('update', {'context': '2.0.0'})
            self.run_module('enable', {'context': None}, grants=['context.read'])
            self.assertTrue(admit_module(self.root, 'context')['allowed'])

    def test_core_api_change_and_broken_dependency_block_admission(self):
        self.make_module('reader', '1.0.0', dependencies={'context': '1.0.0'})
        self.run_module('install', {'reader': '1.0.0'})
        self.run_module('enable', {'reader': None}, grants=['context.read'])
        self.assertTrue(admit_module(self.root, 'reader')['allowed'])
        with patch('getzilla.optional_modules.CORE_API', 2):
            self.assertFalse(admit_module(self.root, 'reader')['allowed'])
        manifest = read_state(self.root).manifest
        manifest['components']['module:context']['module']['enabled'] = False
        manifest['components']['module:context']['module']['grants'] = []
        (self.root / MANIFEST).write_bytes(encode_manifest(manifest))
        self.assertFalse(admit_module(self.root, 'reader')['allowed'])

    def test_core_update_and_harness_regeneration_preserve_module_and_native_bytes(self):
        from getzilla.harnesses import write as regenerate
        install = installer()
        project = self.workspace / 'full-project'
        install._materialize_new(ROOT, project, include_dependencies=False, include_optional=False,
                                 selection=install.PayloadSelection(('qwen',)))
        self.root = project
        for relative, content in self.client_settings.items():
            path = project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.run_module('install', {'context': '1.0.0'})
        self.run_module('enable', {'context': None}, grants=['context.read'])
        module_record = deepcopy(read_state(project).manifest['components']['module:context'])
        module_bytes = {path: (project / path).read_bytes() for path in module_record['files']}
        regenerate(project)
        self.assertEqual(read_state(project).manifest['components']['module:context'], module_record)
        self.assert_user_settings()
        registry_path = project / REGISTRY
        project_registry = json.loads(registry_path.read_bytes())
        project_registry['publishers']['local'] = {'licenses': ['MIT']}
        registry_path.write_text(json.dumps(project_registry), encoding='utf-8')
        saved_registry = registry_path.read_bytes()
        environment = {**dict(__import__('os').environ), 'GIT_AUTHOR_NAME': 'fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                       'GIT_COMMITTER_NAME': 'fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
        for args in (('init', '-q'), ('add', '-A'), ('commit', '-qm', 'fixture')):
            subprocess.run(['git', '-C', str(project), *args], env=environment, check=True, capture_output=True)
        spec = importlib.util.spec_from_file_location('optional_module_upgrade', ROOT / 'scripts/getzilla_upgrade.py')
        upgrade = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = upgrade
        spec.loader.exec_module(upgrade)
        payload = install.build_payload(ROOT, selection=install.PayloadSelection(('qwen',)))
        changed_payload = tuple(install.InstallEntry(entry.path, entry.content + b'\n', entry.mode)
                                if entry.path == '.getzilla/config/policy.json' else entry for entry in payload)
        with patch.object(install, 'build_payload', return_value=changed_payload):
            changes = upgrade.planned_changes(install, ROOT, project, None)
        self.assertFalse([path for path, _content, _mode in changes if path.startswith('.getzilla/modules/')])
        new_ledger = next(content for path, content, _mode in changes if path == MANIFEST)
        self.assertEqual(json.loads(new_ledger)['components']['module:context'], module_record)
        from getzilla.component_state import component_transaction
        with component_transaction(project) as transaction:
            for path, content, mode in changes:
                transaction.write(path, content, int(mode, 8) & 0o777, expected=transaction.read(path))
        self.assertEqual(read_state(project).manifest['components']['module:context'], module_record)
        for path, content in module_bytes.items():
            self.assertEqual((project / path).read_bytes(), content)
        self.assert_user_settings()
        self.assertTrue(admit_module(project, 'context')['allowed'])
        self.assertEqual(registry_path.read_bytes(), saved_registry)

    def test_core_only_real_install_has_no_addon_payload_or_activation(self):
        install = installer()
        started = time.monotonic()
        project = self.workspace / 'clean-core'
        selection = install.PayloadSelection((), engine_archive=True)
        result = install._materialize_new(ROOT, project, include_dependencies=False, include_optional=False, selection=selection)
        files = [p for p in project.rglob('*') if p.is_file()]
        measurements = {'seconds': round(time.monotonic() - started, 4), 'files': len(files),
                        'bytes': sum(p.stat().st_size for p in files), 'external_dependencies_installed': 0}
        self.assertGreater(measurements['files'], 0)
        self.assertGreater(measurements['bytes'], 0)
        print(json.dumps({'core_only_install_measurement': measurements}, sort_keys=True))
        self.assertFalse((project / '.getzilla/modules').exists())
        self.assertFalse((project / '.getzilla/optional-modules').exists())
        self.assertEqual(module_status(project)['modules'], {})
        self.assertFalse([r for r in (project / '.getzilla/runtime').rglob('*') if 'module' in r.name])
        with zipfile.ZipFile(project / '.getzilla/getzilla.zip') as archive:
            self.assertFalse([name for name in archive.namelist() if '/integrations/getzilla_entire/' in name])
        self.assertEqual(result['target_state'], 'absent')


if __name__ == '__main__':
    unittest.main()
