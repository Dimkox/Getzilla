"""Owned public metadata fixtures; resolver fetch is explicit inert bytes."""
import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import latest_releases as releases


def encoded(value):
    return json.dumps(value).encode()


class LatestReleaseTests(unittest.TestCase):
    def test_github_new_major_selected_before_platform_compatibility(self):
        rows = [dict(tag_name='v1.9.0', draft=False, prerelease=False, assets=[]),
                dict(tag_name='v2.0.0', draft=False, prerelease=False, assets=[]),
                dict(tag_name='v3.0.0rc1', draft=False, prerelease=True, assets=[])]
        release = releases.github_release('owned/tool', lambda url: encoded(rows))
        self.assertEqual(release['version'], '2.0.0')
        with self.assertRaisesRegex(ValueError, 'asset'):
            releases.github_asset(release, 'missing.zip')

    def test_exact_asset_requires_upstream_digest_not_computed_download_hash(self):
        row = dict(tag_name='v2.0.0', draft=False, prerelease=False,
                   assets=[dict(name='tool.zip', size=7, digest='sha256:' + 'a'*64,
                                browser_download_url='https://github.com/owned/tool/releases/download/v2.0.0/tool.zip')])
        release = releases.github_release('owned/tool', lambda url: encoded([row]))
        self.assertEqual(releases.github_asset(release, 'tool.zip').sha256, 'a'*64)
        row['assets'][0]['digest'] = None
        release = releases.github_release('owned/tool', lambda url: encoded([row]))
        with self.assertRaisesRegex(ValueError, 'digest'):
            releases.github_asset(release, 'tool.zip')

    def test_npm_independent_latest_integrity_and_identity(self):
        data = dict(name='npm', version='12.0.0', engines={'node': '>=26'},
                    dist=dict(tarball='https://registry.npmjs.org/npm/-/npm-12.0.0.tgz',
                              integrity='sha512-' + base64.b64encode(hashlib.sha512(b'fixture').digest()).decode()))
        target = releases.npm_release('npm', lambda url: encoded(data))
        self.assertEqual(target.version, '12.0.0')
        self.assertEqual(target.requirements, {'node': '>=26'})
        data['name'] = 'foreign'
        with self.assertRaises(ValueError):
            releases.npm_release('npm', lambda url: encoded(data))

    def test_current_rerun_re_fetches_and_never_uses_cached_version(self):
        calls = []
        def fetch(url):
            calls.append(url)
            return encoded(dict(info={'name': 'pytest'}, releases={'9.0.0': [{}], '10.0.0': [{}], '11.0.0a1': [{}]}))
        self.assertEqual(releases.pypi_version('pytest', fetch), '10.0.0')
        self.assertEqual(releases.pypi_version('pytest', fetch), '10.0.0')
        self.assertEqual(len(calls), 2)

    def test_metadata_failure_and_exhaustion_never_use_old_release(self):
        for body in (b'html', encoded([]), encoded([dict(tag_name='v1.0.0', draft=False, prerelease=False)] * 100)):
            with self.assertRaises(ValueError):
                releases.github_release('owned/tool', lambda url: body)
