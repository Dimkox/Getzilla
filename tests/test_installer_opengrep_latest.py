"""New2.x scanner fixtures exercise public updater and verification trust join."""
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import updater
from getzilla import verification
from getzilla import opengrep_releases


class OpenGrepLatestTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        owned = tempfile.TemporaryDirectory(prefix='owned-opengrep2-', dir=scratch)
        self.addCleanup(owned.cleanup)
        self.root = Path(owned.name)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('opengrep.exe', b'owned inert EXE')
            archive.writestr('support.dll', b'owned inert DLL')
        self.payload = stream.getvalue()
        self.asset = 'opengrep_windows_x86.zip'
        self.url = 'https://github.com/opengrep/opengrep/releases/download/v2.1.0/' + self.asset
        self.metadata = [dict(tag_name='v2.1.0', draft=False, prerelease=False, assets=[dict(name=self.asset,
                        size=len(self.payload), digest='sha256:' + hashlib.sha256(self.payload).hexdigest(),
                        browser_download_url=self.url)])]
        self.urls = []

    def fetch(self, url):
        self.urls.append(url)
        if url.startswith('https://api.github.com/repos/opengrep/opengrep/releases?'):
            return json.dumps(self.metadata).encode()
        self.assertEqual(url, self.url)
        return self.payload

    def run_inert(self, command, cwd):
        self.assertEqual(command, [str(self.root / 'bin/opengrep.exe'), '--version'])
        return subprocess.CompletedProcess(command, 0, 'opengrep 2.1.0', '')

    def test_public_latest_update_keeps_windows_dlls_and_re_resolves_rerun(self):
        for _ in range(2):
            result = updater.update_opengrep(self.fetch, self.root, ('windows', 'amd64'), run=self.run_inert)
            self.assertEqual(result[0].status, 'ok', result)
            self.assertEqual((self.root / 'bin/support.dll').read_bytes(), b'owned inert DLL')
        self.assertEqual(sum('api.github.com' in url for url in self.urls), 2)

    def test_verifier_rederives_official_integrity_not_forged_manifest(self):
        binary = self.root / 'opengrep.exe'
        binary.write_bytes(b'forged')
        (self.root / 'opengrep-current.json').write_text(json.dumps({'sha256': hashlib.sha256(b'forged').hexdigest()}))
        with patch.object(updater, '_platform_key', return_value=('windows', 'amd64')), \
                patch.object(opengrep_releases, 'public_fetch', side_effect=self.fetch):
            self.assertIsNotNone(verification._unpinned_opengrep(binary))
            binary.write_bytes(b'owned inert EXE')
            (self.root / 'support.dll').write_bytes(b'owned inert DLL')
            self.assertIsNone(verification._unpinned_opengrep(binary))
            (self.root / 'support.dll').write_bytes(b'tampered')
            self.assertIsNotNone(verification._unpinned_opengrep(binary))

    def test_integrity_and_user_conflict_refuse_without_damaging_old_bytes(self):
        (self.root / 'bin').mkdir()
        binary = self.root / 'bin/opengrep.exe'
        binary.write_bytes(b'user data')
        result = updater.update_opengrep(self.fetch, self.root, ('windows', 'amd64'), run=self.run_inert)
        self.assertEqual(result[0].status, 'fail')
        self.assertEqual(binary.read_bytes(), b'user data')
        binary.unlink()
        self.metadata[0]['assets'][0]['digest'] = 'sha256:' + '0'*64
        result = updater.update_opengrep(self.fetch, self.root, ('windows', 'amd64'), run=self.run_inert)
        self.assertEqual(result[0].status, 'fail')
        self.assertFalse(binary.exists())
