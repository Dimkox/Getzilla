"""Real source payload/compressed import and fixed generator custody controls."""
from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import harnesses  # noqa: E402


class PayloadPackagingTests(unittest.TestCase):
    def test_declared_keep_cannot_silently_leave_an_incompatible_factory_engine(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.source_fixture(root)
            harnesses.write(root, repository_all=True)
            mirror = root / harnesses.FACTORY_PAYLOAD_ENGINE
            original = mirror.read_bytes()
            (root / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
                'schema_version': 1, 'kept_local': [harnesses.FACTORY_PAYLOAD_ENGINE],
                'kept_local_sha256': {harnesses.FACTORY_PAYLOAD_ENGINE: hashlib.sha256(original).hexdigest()},
            }), encoding='utf-8', newline='\n')
            (root / harnesses.PAYLOAD_ENGINE).write_bytes(b'# new public canonical fixture\n')
            with self.assertRaisesRegex(ValueError, 'conflict.*kept'):
                harnesses.write(root, repository_all=True)
            self.assertEqual(mirror.read_bytes(), original)

    def source_fixture(self, root):
        for directory in ('.grok/agents', '.agents/skills', '.grok/cursor-rules',
                          '.getzilla/getzilla', 'scripts', 'factory/src/getzilla_factory'):
            (root / directory).mkdir(parents=True, exist_ok=True)
        for relative, data in (
            ('.grok/hooks.json', b'{"hooks":{}}'),
            ('.grok/cursor-rules/core.toml', b'description="public rule"\nalways_apply=true\ninstructions="public fixture"\n'),
            ('scripts/install_into.py', b'# source marker only\n'),
            ('factory/pyproject.toml', b'# source marker only\n'),
            (harnesses.PAYLOAD_ENGINE, b'# first public generated fixture\n'),
        ):
            (root / relative).write_bytes(data)

    def test_fixed_source_mirror_updates_only_owned_bytes_and_refuses_foreign_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.source_fixture(root)
            harnesses.write(root, repository_all=True)
            mirror = root / harnesses.FACTORY_PAYLOAD_ENGINE
            self.assertEqual(mirror.read_bytes(), b'# first public generated fixture\n')
            canonical = root / harnesses.PAYLOAD_ENGINE
            canonical.write_bytes(b'# second public generated fixture\n')
            self.assertIn('stale ' + harnesses.FACTORY_PAYLOAD_ENGINE,
                          harnesses.drift(root, repository_all=True))
            harnesses.write(root, repository_all=True)
            self.assertEqual(mirror.read_bytes(), b'# second public generated fixture\n')
            mirror.write_bytes(b'# foreign public replacement\n')
            canonical.write_bytes(b'# third public canonical fixture\n')
            with self.assertRaisesRegex(ValueError, 'conflict'):
                harnesses.write(root, repository_all=True)
            self.assertEqual(mirror.read_bytes(), b'# foreign public replacement\n')

    def test_installed_core_hook_generation_does_not_acquire_factory_output(self):
        from getzilla.component_state import MANIFEST, V2, encode_manifest
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.source_fixture(root)
            (root / 'scripts/install_into.py').unlink()
            (root / MANIFEST).write_bytes(encode_manifest({
                'schema_version': V2, 'agents': ['qwen'], 'components': {},
            }))
            output = harnesses.render(root)
            self.assertTrue(output)
            self.assertTrue(all(p.startswith('.qwen/') for p in output))
            harnesses.write(root)
            self.assertFalse((root / harnesses.FACTORY_PAYLOAD_ENGINE).exists())

    def test_actual_installer_payload_keeps_source_identity_in_compressed_import(self):
        spec = importlib.util.spec_from_file_location('payload_installer_fixture', ROOT / 'scripts/install_into.py')
        installer = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = installer
        spec.loader.exec_module(installer)
        entries = {entry.path: entry for entry in installer.build_payload(
            ROOT, selection=installer.PayloadSelection.full_layout())}
        canonical = entries[harnesses.PAYLOAD_ENGINE].content
        self.assertEqual(canonical, (ROOT / harnesses.PAYLOAD_ENGINE).read_bytes())
        self.assertEqual(entries[harnesses.FACTORY_PAYLOAD_ENGINE].content, canonical)
        self.assertIn('.getzilla/getzilla/payload_transform.py', entries)
        with tempfile.TemporaryDirectory() as temporary:
            archive, probe = Path(temporary) / 'public-payload.zip', Path(temporary) / 'probe.py'
            with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as output:
                for path, entry in entries.items():
                    if path.endswith('.py') and path.startswith(('.getzilla/getzilla/', 'factory/src/getzilla_factory/')):
                        output.writestr(path, entry.content)
            with zipfile.ZipFile(archive) as restored:
                self.assertEqual(restored.read(harnesses.PAYLOAD_ENGINE), canonical)
                self.assertEqual(restored.read(harnesses.FACTORY_PAYLOAD_ENGINE), canonical)
            probe.write_text(
                "import sys\n"
                "sys.path.insert(0,sys.argv[1]+'/factory/src')\n"
                "from getzilla_factory import _payload_engine as factory\n"
                "from getzilla_factory.result_broker import ResultBroker\n"
                "assert 'getzilla' not in sys.modules\n"
                "sys.path.insert(0,sys.argv[1]+'/.getzilla')\n"
                "from getzilla import _payload_engine as core\n"
                "for engine in (core,factory):\n"
                " assert engine.redact('password=public-fixture',100)=='[REDACTED]'\n"
                "value=ResultBroker(policy_version='public-fixture-v1').sanitize_candidate(\n"
                " channel='native_tool_result',content_type='text/plain',chunks=[b'public note'])\n"
                "assert value.sanitized_payload=='public note'\n"
                "print('compressed-source-and-factory-wrappers-ok')\n",
                encoding='utf-8', newline='\n',
            )
            result = subprocess.run([sys.executable, '-I', str(probe), str(archive)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8'))
            self.assertEqual(result.stdout, b'compressed-source-and-factory-wrappers-ok\n')


if __name__ == '__main__':
    unittest.main()
