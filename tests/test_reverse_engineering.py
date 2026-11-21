"""Bounded data-only reconstruction and actual owned public ELF qualification."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
ARTIFACT = ROOT / '.getzilla/optional-modules/reverse-engineering/0.1.0'


def provider():
    path = ARTIFACT / 'elf.py'
    if not path.exists():
        raise AssertionError('static ELF addon missing')
    module = types.ModuleType('reverse_provider_test')
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('cc'), 'real Linux C toolchain required')
class ElfTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(dir=scratch)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.target = Path(cls.temp.name) / 'public-probe.so'
        cls.command = [shutil.which('cc'), '-shared', '-fPIC', '-fvisibility=hidden',
                       '-Wl,--build-id=none', '-o', str(cls.target),
                       str(ROOT / 'tests/fixtures/reverse263/public-probe.c')]
        subprocess.run(cls.command, check=True, timeout=10, capture_output=True)
        cls.raw = cls.target.read_bytes()
        cls.expected = json.loads((ROOT / 'tests/fixtures/reverse263/expected.json').read_text())

    def setUp(self):
        self.m = provider()

    def analyze(self, **options):
        return self.m.analyze(self.raw, question='Which loader libraries and exported functions are declared?',
                              **options)

    def test_actual_compiled_probe_exports_dependencies_offsets_and_unknown_behavior(self):
        with patch('subprocess.Popen', side_effect=AssertionError('target execution forbidden')), \
                patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = self.analyze()
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(sorted(x['name'] for x in result['needed']), self.expected['needed'])
        self.assertEqual(sorted(x['name'] for x in result['exports']), self.expected['exports'])
        self.assertEqual(result['input_sha256'], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result['behavior'], 'unknown')
        self.assertFalse(result['target_executed'])
        for row in result['exports']:
            self.assertGreater(row['address'], 0)
            self.assertGreater(row['file_offset'], 0)
            self.assertLess(row['evidence_offset'], len(self.raw))

    def test_limits_timeout_cancel_and_unknown_provider_are_truthful(self):
        limited = self.analyze(max_functions=1)
        self.assertEqual((limited['status'], limited['reason']), ('partial', 'function_limit'))
        self.assertEqual(len(limited['exports']), 1)
        self.assertEqual(self.analyze(cancelled=lambda: True)['reason'], 'cancelled')
        self.assertEqual(self.analyze(deadline=time.monotonic() - 1)['reason'], 'deadline_exceeded')
        self.assertEqual(self.analyze(provider='ghidra')['reason'], 'provider_unavailable')
        self.assertEqual(self.analyze(max_sections=1)['reason'], 'section_limit')
        self.assertLessEqual(len(json.dumps(self.analyze()).encode()), 32768)

    def test_unsupported_and_malformed_bytes_never_become_complete(self):
        for raw in (b'MZ' + b'x' * 80, b'\x7fELF\x01\x01\x01' + b'\0' * 80,
                    self.raw[:63], self.raw[:512]):
            with self.subTest(size=len(raw)):
                self.assertNotEqual(self.m.analyze(raw, question='Public format probe')['status'], 'complete')
        broken = bytearray(self.raw)
        struct.pack_into('<Q', broken, 40, len(broken) + 99)
        self.assertEqual(self.m.analyze(bytes(broken), question='Bounded table probe')['reason'], 'malformed_elf')
        with self.assertRaisesRegex(ValueError, 'invalid_limits'):
            self.analyze(max_functions=True)


class NativeAddonTests(ElfTests):
    def setUp(self):
        super().setUp()
        script = ROOT / 'scripts/getzilla_reverse.py'
        self.assertTrue(script.is_file(), 'native reverse command missing')
        import importlib.util
        spec = importlib.util.spec_from_file_location('reverse_native_test', script)
        self.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cli)
        scratch = ROOT / '.getzilla/runtime/scratch'
        self.project_temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.project_temp.cleanup)
        self.root = Path(self.project_temp.name)
        self.root.chmod(0o700)
        self.enterContext(patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'reverse-test-owner'}))
        from tests.test_design_reference import create_public_task
        from tests.test_optional_modules import OptionalModuleTests
        OptionalModuleTests.install_core(self, self.root)
        self.route, self.package = create_public_task(self.root, 'reverse-test-owner')
        (self.root / 'artifacts').mkdir()
        self.path = 'artifacts/public-probe.so'
        (self.root / self.path).write_bytes(self.raw)
        (self.root / self.path).chmod(0o644)
        self.sha = hashlib.sha256(self.raw).hexdigest()

    def enable(self):
        from getzilla.optional_modules import manage_modules
        manage_modules(self.root, 'install', {'reverse-engineering':'0.1.0'}, source=ROOT)
        manage_modules(self.root, 'enable', {'reverse-engineering':None}, grants=['reverse.artifact.read'])

    def run_analysis(self, **kwargs):
        return self.cli.analyze_project(self.root, self.path, self.sha,
                                       'Which public interfaces and dependencies are declared?', **kwargs)

    def test_disabled_refuses_before_source_or_provider_loading(self):
        with patch.object(self.cli, '_load', side_effect=AssertionError('provider loaded')), \
                patch.object(self.cli, '_read_artifact', side_effect=AssertionError('source read')), \
                self.assertRaisesRegex(self.cli.ReverseError, 'module_disabled_or_missing'):
            self.run_analysis()

    def test_real_project_lifecycle_authorized_read_and_disable_preserve_user_files(self):
        from getzilla.optional_modules import manage_modules
        self.enable()
        result = self.run_analysis()
        self.assertEqual(result['analysis']['status'], 'complete')
        self.assertEqual(result['artifact']['sha256'], self.sha)
        self.assertEqual(result['task']['route_id'], self.route['route_id'])
        self.assertFalse(result['evidence_authority'])
        manage_modules(self.root, 'disable', {'reverse-engineering':None})
        with self.assertRaisesRegex(self.cli.ReverseError, 'module_disabled_or_missing'):
            self.run_analysis()
        installed = self.root / '.getzilla/modules/reverse-engineering'
        (installed / 'user-notes.txt').write_text('preserve')
        manage_modules(self.root, 'uninstall', {'reverse-engineering':None})
        self.assertEqual((installed/'user-notes.txt').read_text(), 'preserve')
        self.assertEqual((self.root/self.path).read_bytes(), self.raw)

    def test_digest_credentials_links_and_stale_authority_refuse(self):
        self.enable()
        for relative in ('../outside', '.env', '.getzilla/runtime/routes/x.json'):
            with self.assertRaises(self.cli.ReverseError):
                self.cli.analyze_project(self.root, relative, self.sha, 'Authorized path check')
        with self.assertRaisesRegex(self.cli.ReverseError, 'artifact_digest'):
            self.cli.analyze_project(self.root, self.path, '0'*64, 'Exact digest check')
        (self.root/'artifacts/link.so').symlink_to(self.root/self.path)
        with self.assertRaises(self.cli.ReverseError):
            self.cli.analyze_project(self.root, 'artifacts/link.so', self.sha, 'No link alias')
        from getzilla import state
        state.bind_session('foreign-session')
        with self.assertRaises(self.cli.ReverseError):
            self.run_analysis()

    def test_result_cap_returns_bound_partial_not_unavailable(self):
        self.enable()
        source = self.root / 'many.c'
        source.write_text('\n'.join(f'int exported_{i:04}(void) {{ return {i}; }}' for i in range(300)))
        subprocess.run([shutil.which('cc'),'-shared','-fPIC','-o',str(self.root/self.path),str(source)],
                       check=True,capture_output=True,timeout=10)
        (self.root/self.path).chmod(0o644)
        self.sha=hashlib.sha256((self.root/self.path).read_bytes()).hexdigest()
        result=self.run_analysis(max_functions=512)
        self.assertEqual(result['analysis']['reason'],'result_limit')
        self.assertEqual(result['analysis']['status'],'partial')
        self.assertLessEqual(len(json.dumps(result,separators=(',',':')).encode()),32768)
        self.assertGreater(len(result['analysis']['exports']),0)

    def test_secret_sentinel_and_disable_during_read_do_not_release_report(self):
        self.enable()
        secret=self.raw+b'-----BEGIN PRIVATE KEY-----'
        (self.root/self.path).write_bytes(secret)
        with self.assertRaisesRegex(self.cli.ReverseError,'artifact_sensitive_content'):
            self.cli.analyze_project(self.root,self.path,hashlib.sha256(secret).hexdigest(),'Secret rejection')
        (self.root/self.path).write_bytes(self.raw)
        from getzilla.optional_modules import manage_modules
        def revoke():
            manage_modules(self.root,'disable',{'reverse-engineering':None})
            return False
        with self.assertRaisesRegex(self.cli.ReverseError,'module_disabled_or_missing'):
            self.run_analysis(cancelled=revoke)

    def test_cli_json_text_missing_provider_and_core_payload_omits_addon(self):
        self.enable()
        command = [sys.executable,str(ROOT/'scripts/getzilla_reverse.py'),'analyze',self.path,
                   '--project',str(self.root),'--sha256',self.sha,'--question','Declared public ELF interfaces']
        env = dict(os.environ,GETZILLA_SESSION_ID='reverse-test-owner')
        result = subprocess.run(command+['--json'],check=True,capture_output=True,text=True,env=env,timeout=5)
        self.assertEqual(json.loads(result.stdout)['analysis']['status'],'complete')
        result = subprocess.run(command,check=True,capture_output=True,text=True,env=env,timeout=5)
        self.assertIn('behavior: unknown',result.stdout)
        result = subprocess.run(command+['--provider','ghidra','--json'],capture_output=True,text=True,env=env,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(result.stdout)['analysis']['reason'],'provider_unavailable')
        from tests.test_design_reference import load_file
        installer = load_file(ROOT/'scripts/install_into.py','reverse_installer_test')
        payload = installer.build_payload(ROOT,selection=installer.PayloadSelection((),engine_archive=True))
        self.assertFalse(any('optional-modules/reverse-engineering/' in row.path for row in payload))
        self.assertTrue(any(row.path=='scripts/getzilla_reverse.py' for row in payload))
        import io
        import zipfile
        archive = next(row for row in payload if row.path==installer.ENGINE_ARCHIVE)
        with zipfile.ZipFile(io.BytesIO(archive.content)) as zipped:
            self.assertFalse(any('reverse-engineering' in name or name.endswith('/elf.py') for name in zipped.namelist()))


if __name__ == '__main__':
    unittest.main()
