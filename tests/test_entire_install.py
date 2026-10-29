"""Entire is opt-in even when the core engine is packaged as a zip archive."""
from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
sys.path.insert(0, str(ROOT / 'scripts'))
import install_into as installer
from getzilla.on_demand import ensure_components


class EntireInstallTests(unittest.TestCase):
    def test_module_is_excluded_from_lean_payload_and_engine_zip(self):
        payload = installer.build_payload(ROOT, selection=installer.PayloadSelection((), engine_archive=True))
        self.assertFalse(any('/getzilla_entire/' in entry.path for entry in payload))
        archive = next(entry for entry in payload if entry.path == installer.ENGINE_ARCHIVE)
        with zipfile.ZipFile(io.BytesIO(archive.content)) as packed:
            self.assertFalse(any('getzilla_entire' in name for name in packed.namelist()))
        self.assertIn('scripts/getzilla_entire.py', {entry.path for entry in payload})

    def test_explicit_extra_includes_only_the_adapter(self):
        selection = installer.PayloadSelection((), extras=('entire',), engine_archive=True)
        self.assertTrue(selection.includes('.getzilla/integrations/getzilla_entire/client.py'))
        self.assertFalse(selection.includes('.grok/skills/bitrix-development/SKILL.md'))
        self.assertEqual(installer.component_of('.getzilla/integrations/getzilla_entire/client.py'), 'extra:entire')

    def test_launcher_help_and_missing_component_are_actionable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / 'scripts' / 'getzilla_entire.py'
            script.parent.mkdir()
            script.write_bytes((ROOT / 'scripts/getzilla_entire.py').read_bytes())
            help_result = subprocess.run([sys.executable, str(script), '--help'], capture_output=True, text=True)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            missing = subprocess.run([sys.executable, str(script), 'status'], capture_output=True, text=True)
            self.assertEqual(missing.returncode, 2)
            self.assertIn('getzilla components add extra:entire', missing.stderr)

    def test_repeated_extra_install_preserves_hooks_checkpoints_and_local_edits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'repository'
            root.mkdir()
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            hook = root / '.git/hooks/pre-push'
            hook.write_text('# existing hook manager\n', encoding='utf-8')
            settings = root / '.entire/settings.json'
            settings.parent.mkdir()
            settings.write_text('{"strategy_options":{"push_sessions":false}}', encoding='utf-8')
            checkpoint = root / '.git/refs/entire/checkpoints/fixture'
            checkpoint.parent.mkdir(parents=True)
            checkpoint.write_text('a' * 40 + '\n', encoding='utf-8')
            local = root / 'unfinished.txt'
            local.write_text('local work\n', encoding='utf-8')
            before = {path: path.read_bytes() for path in [hook, settings, checkpoint, local]}
            first = ensure_components(root, ['extra:entire'], source=ROOT)
            self.assertTrue(first[0].files)
            custom = root / '.getzilla/integrations/getzilla_entire/__init__.py'
            custom.write_text('# user customization\n', encoding='utf-8')
            again = ensure_components(root, ['extra:entire'], source=ROOT)
            self.assertFalse(again[0].files)
            self.assertIn(custom.relative_to(root).as_posix(), again[0].kept)
            self.assertEqual(custom.read_text(), '# user customization\n')
            for path, content in before.items():
                self.assertEqual(path.read_bytes(), content)


if __name__ == '__main__':
    unittest.main()
