from __future__ import annotations

import tempfile
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import skill_sandbox as sandbox  # noqa: E402


class SandboxContracts(unittest.TestCase):
    def test_command_has_no_workspace_credentials_network_or_ambient_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('source', 'deps', 'work'):
                (root / name).mkdir()
            if sys.platform != 'linux':
                with self.assertRaisesRegex(ValueError, 'UNQUALIFIED_NATIVE_GENERATOR'):
                    sandbox.sandbox_command('bmad', root / 'source', root / 'deps', root / 'work', 'claude-code')
                return
            command = sandbox.sandbox_command('bmad', root / 'source', root / 'deps', root / 'work', 'claude-code')
            self.assertIn('--unshare-all', command)
            self.assertIn('--clearenv', command)
            self.assertIn('--cap-drop', command)
            self.assertIn('--ignore-agent-tools', sandbox.sandbox_command('spec-kit', root / 'source', root / 'deps', root / 'work', 'claude'))
            self.assertIn('/source/tools/installer/bmad-cli.js', command)
            self.assertNotIn('npx', command)
            self.assertNotIn('specify', command)
            self.assertNotIn(str(Path.home()), command)

    def test_unknown_tool_adapter_or_outside_stage_refuses_before_execution(self):
        for component, agent in (('unknown', 'claude'), ('bmad', '../../shell'), ('spec-kit', 'unknown')):
            with self.assertRaises(ValueError):
                sandbox.sandbox_command(component, Path('/source'), Path('/deps'), Path('/work'), agent)

    def test_stage_output_snapshot_rejects_link_escape_oversize_and_executable_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.specify').mkdir()
            (root / '.specify/config.md').write_bytes(b'pinned-output')
            result = sandbox.read_stage(root)
            self.assertEqual(dict(result)['.specify/config.md'], b'pinned-output')
            (root / '.specify/escape').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                sandbox.read_stage(root)
            (root / '.specify/escape').unlink()
            (root / '.env').write_text('credential-like output')
            with self.assertRaises(ValueError):
                sandbox.read_stage(root)

    def test_dependency_lock_requires_integrity_and_exact_official_origins(self):
        lock = {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/a': {
            'version': '1.0.0', 'resolved': 'https://registry.npmjs.org/a/-/a-1.0.0.tgz',
            'integrity': 'sha512-' + 'A' * 86 + '=='}}}
        sandbox.validate_npm_lock(lock)
        for key, value in (('integrity', ''), ('resolved', 'https://example.invalid/a.tgz'),
                           ('resolved', 'git+https://github.com/example/a')):
            changed = {**lock, 'packages': {'': {}, 'node_modules/a': {**lock['packages']['node_modules/a'], key: value}}}
            with self.assertRaises(ValueError):
                sandbox.validate_npm_lock(changed)
