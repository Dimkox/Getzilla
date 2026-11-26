"""Public software join with owned archive and explicit mocked native effects."""
import hashlib
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import managed_software
from getzilla.latest_releases import Target


class SoftwareJoinTests(unittest.TestCase):
    def test_public_install_uses_resolved_exact_bytes_not_existing_command(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            item = tarfile.TarInfo('node-current/bin/node')
            item.size, item.mode = 5, 0o755
            archive.addfile(item, io.BytesIO(b'inert'))
        raw = stream.getvalue()
        target = Target('node', '31.0.0', 'https://nodejs.org/fixture.tar.gz',
                        sha256=hashlib.sha256(raw).hexdigest(), filename='fixture.tar.gz')
        scratch = ROOT/'.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-software-join-', dir=scratch) as owned:
            calls = []
            def run(command, cwd=None, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, 'v31.0.0', '')
            with patch.object(managed_software, 'plan', return_value=({'node': target}, [])), \
                    patch.object(managed_software, 'verify_environment', return_value=dict(component='python-environment', status='complete')):
                result = managed_software.install_software(Path(owned)/'state', Path(owned), fetch=lambda _: raw,
                    run=run, which=lambda _: '/old/node', system='linux', architecture='x64')
            self.assertEqual(result['status'], 'complete', result)
            self.assertEqual(result['components'][0]['target'], '31.0.0')
            self.assertNotEqual(calls[0][0], '/old/node')
            self.assertEqual(result['components'][0]['path'], calls[0][0])

    def test_final_verify_rejects_path_shadow_even_matching_version(self):
        target = Target('node', '31.0.0', 'https://nodejs.org/unused', sha256='a'*64)
        with patch.object(managed_software, 'plan', return_value=({'node': target}, [])), \
                patch.object(managed_software, 'verify_environment', return_value=dict(component='python-environment', status='complete')):
            scratch = ROOT/'.getzilla/runtime/scratch'
            scratch.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='owned-shadow-', dir=scratch) as owned:
                result = managed_software.install_software(Path(owned)/'state', Path(owned), verify_only=True,
                    which=lambda _: '/old/node', run=lambda *args, **kwargs: self.fail('shadowed program must not run'))
            self.assertEqual(result['status'], 'incomplete')
            self.assertIn('PATH shadowing', result['components'][0]['error'])

    def test_update_notice_does_not_satisfy_installed_agent_version(self):
        target = Target('claude', '2.9.0', 'https://unused.invalid/claude', sha256='a'*64)
        cases = [
            ('2.8.0 (Claude Code)\nUpdate available: 2.9.0', 0, '2.8.0', 'incomplete'),
            ('2.9.0 (Claude Code)', 0, '2.9.0', 'complete'),
            ('2.9.0 (Claude Code)', 1, '2.9.0', 'incomplete'),
            ('dependency 2.9.0', 0, None, 'incomplete'),
            ('Claude Code 2.8.0\nClaude Code 2.9.0', 0, None, 'incomplete'),
        ]
        for output, code, actual, status in cases:
            with self.subTest(output=output, code=code), tempfile.TemporaryDirectory() as owned, \
                    patch.object(managed_software, 'plan', return_value=({'agent:claude': target}, [])), \
                    patch.object(managed_software, 'verify_environment', return_value={'status': 'complete'}):
                root = Path(owned)
                result = managed_software.install_software(root, root, agent='claude', verify_only=True,
                    system='linux', which=lambda _: str(root/'bin/claude'),
                    run=lambda *args: subprocess.CompletedProcess(args, code, output, ''))
                self.assertEqual(result['status'], status)
                self.assertEqual(result['components'][0]['actual'], actual)
