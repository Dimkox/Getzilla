"""Official source selection and owned archives with an unavailable XZ codec."""
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import latest_releases, managed_runtime, managed_software


# A fixed tar.xz containing source/configure=b'data'; no local XZ encoder needed.
XZ = bytes.fromhex(
    'fd377a585a000004e6d6b4460200210116000000742fe5a3e027ff00665d00399bcb11'
    'efec401d79a16c58e21cbf00d4f84b672037b90b0d8914059d44df68c95a9add90188'
    '35c13b74175c06cdae8c8303701bf15b40fd4d68da0571a01d7335cf13f28e16c4e3'
    '228d1f7e0589dafa9c2a0ad7bbea4c05366c9c3d27279729d7d411d1900000000a9'
    '7f3cb4d223e7a6000182018050000035d0a82cb1c467fb020000000004595a')


class LinuxArchiveTests(unittest.TestCase):
    def test_corrupt_archives_fail_with_bounded_identity_without_parser_text(self):
        for filename, raw in (('fixture.zip', b'not a zip'),
                              ('fixture.tar.gz', b'\x1f\x8b\x08\x00'+b'\x00'*6+b'\xff'*10)):
            with self.subTest(filename=filename):
                target = latest_releases.Target('git', '1.0.0', 'https://owned.invalid/?private=hidden',
                    sha256=hashlib.sha256(raw).hexdigest(), filename=filename)
                with self.assertRaisesRegex(ValueError, f'git {filename}: archive-decode') as error:
                    managed_runtime.entries(target, raw)
                self.assertNotIn('hidden', str(error.exception))
                self.assertLess(len(str(error.exception)), 400)

    def test_python_gzip_requires_same_current_official_row_and_sha(self):
        page = b'Python 3.13.18 Python 3.13.17'
        def row(filename, digest):
            return f'<tr><td><a href="https://www.python.org/ftp/python/3.13.18/{filename}">source</a></td><td><code>{digest}</code></td></tr>'
        detail = row('Python-3.13.18.tgz', 'a'*64)+row('Python-3.13.18.tar.xz', 'b'*64)
        def fetch(url):
            return page if url.endswith('/downloads/') else detail.encode()
        target = latest_releases.python_source(fetch)
        self.assertEqual(target.filename, 'Python-3.13.18.tgz')
        self.assertEqual(target.sha256, 'a'*64)
        for digest in ('', 'a'*63, 'a'*65, 'not-a-hash'):
            detail = row('Python-3.13.18.tgz', digest)+row('Python-3.13.18.tar.xz', 'b'*64)
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                latest_releases.python_source(fetch)

    def test_php_gzip_requires_current_official_asset_and_sha(self):
        catalog = {'8': {'version': '8.5.12', 'source': [
            {'filename': 'php-8.5.12.tar.gz', 'sha256': 'a'*64},
            {'filename': 'php-8.5.12.tar.xz', 'sha256': 'b'*64}]},
            '7': {'version': '7.4.33', 'source': [{'filename': 'php-7.4.33.tar.gz', 'sha256': 'c'*64}]}}
        def fetch(_):
            return json.dumps(catalog).encode()
        target = latest_releases.php_source(fetch)
        self.assertEqual(target.url, 'https://www.php.net/distributions/php-8.5.12.tar.gz')
        self.assertEqual(target.sha256, 'a'*64)
        for digest in ('', 'a'*63, 'not-a-hash'):
            catalog['8']['source'][0]['sha256'] = digest
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                latest_releases.php_source(fetch)
        catalog['8']['source'].pop(0)
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            latest_releases.php_source(fetch)

    def test_git_selects_exact_official_gzip_without_older_fallback(self):
        page = b'Latest version: 2.56.1'
        sums = (b'a'*64+b'  git-2.56.1.tar.gz\n'+b'b'*64+b'  git-2.56.1.tar.xz\n'
                +b'c'*64+b'  git-2.55.0.tar.gz\n')
        def fetch(url):
            return sums if url.endswith('sha256sums.asc') else page
        target = latest_releases.git_source(fetch)
        self.assertEqual(target.filename, 'git-2.56.1.tar.gz')
        self.assertEqual(target.sha256, 'a'*64)
        self.assertEqual(target.url, 'https://www.kernel.org/pub/software/scm/git/git-2.56.1.tar.gz')
        sums = b'b'*64+b'  git-2.56.1.tar.xz\n'+b'c'*64+b'  git-2.55.0.tar.gz\n'
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            latest_releases.git_source(fetch)
        sums = b'bad  git-2.56.1.tar.gz\n'
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            latest_releases.git_source(fetch)

    def test_missing_xz_codec_reports_component_file_stage_in_join(self):
        target = latest_releases.Target('git', '2.56.1', 'https://www.kernel.org/fixture.tar.xz',
            sha256=hashlib.sha256(XZ).hexdigest(), filename='git-2.56.1.tar.xz')
        scratch = ROOT/'.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-linux-archive-', dir=scratch) as owned, \
                patch.object(managed_software, 'plan', return_value=({'git': target}, [])), \
                patch.object(managed_software, 'verify_environment', return_value={'status': 'complete'}), \
                patch.dict(sys.modules, {'lzma': None, 'bz2': None}):
            result = managed_software.install_software(Path(owned)/'state', Path(owned),
                fetch=lambda _: XZ, system='linux', architecture='x64',
                run=lambda *a, **kw: self.fail('archive failure must precede native build'))
        self.assertEqual(result['status'], 'incomplete')
        error = result['components'][0]['error']
        self.assertIn('git', error)
        self.assertIn('git-2.56.1.tar.xz', error)
        self.assertIn('archive-decode', error)

    def test_verified_gzip_unpacks_without_optional_codecs_and_rejects_tamper(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            item = tarfile.TarInfo('source/configure')
            item.size = 4
            archive.addfile(item, io.BytesIO(b'data'))
        raw = stream.getvalue()
        with patch.dict(sys.modules, {'lzma': None, 'bz2': None}):
            for component, filename in (('git', 'git-2.56.1.tar.gz'), ('python', 'Python-3.13.18.tgz'),
                                        ('php', 'php-8.5.12.tar.gz')):
                with self.subTest(component=component):
                    target = latest_releases.Target(component, '1.0.0', 'https://owned.invalid/fixture',
                        sha256=hashlib.sha256(raw).hexdigest(), filename=filename)
                    self.assertEqual(managed_runtime.entries(target, raw)[0]['configure'][0], b'data')
                    with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
                        managed_runtime.entries(target, raw+b'tamper')
