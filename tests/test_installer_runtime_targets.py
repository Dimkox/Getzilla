"""Tiny official runtime catalog shapes; no installers or downloads execute."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import latest_releases as releases


class RuntimeTargetTests(unittest.TestCase):
    def test_python_latest_global_major_not_old_compatible_flavour(self):
        rows = [dict(id='pythoncore-3.14-64', **{'sort-version': '3.14.9'}),
                dict(id='pythoncore-4.0-64', **{'sort-version': '4.0.1'}, executable='.\\python.exe',
                     url='https://www.python.org/ftp/python/4.0.1/python-4.0.1-amd64.zip', hash={'sha256': 'a'*64}),
                dict(id='pythoncore-4.1-64', **{'sort-version': '4.1.0a1'})]
        target = releases.python_windows(lambda _: json.dumps({'versions': rows, 'next': None}).encode(), 'x64')
        self.assertEqual(target.version, '4.0.1')
        with self.assertRaises(ValueError):
            releases.python_windows(lambda _: json.dumps({'versions': rows, 'next': None}).encode(), 'arm64')

    def test_git_windows_preserves_vendor_build_and_official_asset(self):
        row = dict(tag_name='v3.0.1.windows.2', draft=False, prerelease=False, assets=[dict(
            name='MinGit-3.0.1-64-bit.zip', size=10, digest='sha256:'+'a'*64,
            browser_download_url='https://github.com/git-for-windows/git/releases/download/v3.0.1.windows.2/MinGit-3.0.1-64-bit.zip')])
        def fetch(url):
            return json.dumps([dict(ref='refs/tags/'+row['tag_name'])] if '/matching-refs/' in url else row).encode()
        target = releases.git_windows(fetch, 'x64')
        self.assertEqual(target.version, '3.0.1.windows.2')
        self.assertIn('/v3.0.1.windows.2/', target.url)

    def test_composer_global_stable_not_lts_and_versioned_hash(self):
        def fetch(url):
            if url == 'https://getcomposer.org/versions':
                return json.dumps({'stable': [dict(version='2.2.99', path='/download/2.2.99/composer.phar', **{'min-php': 50300}),
                                              dict(version='3.0.0', path='/download/3.0.0/composer.phar', **{'min-php': 80400})]}).encode()
            self.assertEqual(url, 'https://getcomposer.org/download/3.0.0/composer.phar.sha256sum')
            return ('a'*64+'  composer.phar\n').encode()
        target = releases.composer_release(fetch)
        self.assertEqual(target.version, '3.0.0')
        self.assertEqual(target.requirements['php'], 80400)

    def test_php_requires_newest_global_version_in_windows_catalog(self):
        def fetch(url):
            if url == 'https://www.php.net/releases/?json':
                return json.dumps({'8': {'version': '8.5.1'}, '9': {'version': '9.0.0'}}).encode()
            return json.dumps({'8.5': {'version': '8.5.1', 'nts-vs17-x64': {'zip': {'path': 'old.zip', 'sha256': 'a'*64}}}}).encode()
        with self.assertRaisesRegex(ValueError, '9.0.0'):
            releases.php_windows(fetch, 'x64')
