import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import osv_published_artifacts as lookup  # noqa: E402
from getzilla.security_artifacts import ArtifactError  # noqa: E402


class PublishedArtifactTests(unittest.TestCase):
    def lookup(self, ecosystem, name, version, data):
        with patch.object(lookup, 'bounded_default', return_value=json.dumps(data).encode()):
            return lookup.published_artifacts(ecosystem, name, version)

    def test_pypi_published_wheel_and_source_only_or_yanked_release(self):
        filename = 'demo-2-py3-none-any.whl'
        url = 'https://files.pythonhosted.org/packages/ab/' + filename
        wheel = dict(filename=filename, packagetype='bdist_wheel', yanked=False, url=url, digests={'sha256': 'a' * 64})
        data = dict(info={'name':'demo','version':'2'}, urls=[wheel])
        self.assertEqual(self.lookup('PyPI', 'demo', '2', data), (url,))
        for file in [dict(wheel, yanked=True), dict(wheel, packagetype='sdist', filename='demo-2.tar.gz')]:
            self.assertEqual(self.lookup('PyPI', 'demo', '2', dict(data, urls=[file])), ())
        for file in [dict(wheel, yanked=None), dict(wheel, filename='other-2-py3-none-any.whl'),
                     dict(wheel, url=url.replace('/ab/', '/else/wrong-')), dict(wheel, digests={})]:
            with self.subTest(file=file), self.assertRaises(ArtifactError):
                self.lookup('PyPI', 'demo', '2', dict(data, urls=[file]))
        with self.assertRaises(ArtifactError):
            self.lookup('PyPI', 'other', '2', data)

    def test_only_exact_pypi_release_404_is_absence(self):
        url = 'https://pypi.org/pypi/demo/2/json'
        for target, status in [(url, 404), (url, 503), (url + '/other', 404)]:
            error = ArtifactError('artifact-fetch', 'request failed')
            error.__cause__ = lookup.HTTPError(target, status, 'failed', {}, None)
            with patch.object(lookup, 'bounded_default', side_effect=error):
                if target == url and status == 404:
                    self.assertEqual(lookup.published_artifacts('PyPI', 'demo', '2'), ())
                else:
                    with self.assertRaises(ArtifactError):
                        lookup.published_artifacts('PyPI', 'demo', '2')

    def test_packagist_release_identity_and_distribution(self):
        ref = 'a' * 40
        name = 'vendor/demo'
        url = 'https://api.github.com/repos/vendor/demo/zipball/' + ref
        row = dict(name=name, version='v2.0', source=dict(type='git', reference=ref,
                   url='https://github.com/vendor/demo.git'), dist=dict(type='zip', reference=ref, url=url))
        data = {'package': {'name': name, 'versions': {'v2.0': row}}}
        self.assertEqual(self.lookup('Packagist', name, '2.0.0.0', data), (url,))
        self.assertEqual(self.lookup('Packagist', name, '3', data), ())
        row['dist']['reference'] = 'b' * 40
        with self.assertRaises(ArtifactError):
            self.lookup('Packagist', name, '2', data)
        del row['dist']
        self.assertEqual(self.lookup('Packagist', name, '2', data), ())
        row['name'] = 'other/project'
        with self.assertRaises(ArtifactError):
            self.lookup('Packagist', name, '2', data)


class RegistryReleaseTests(unittest.TestCase):
    def lookup(self, ecosystem, name, version, data):
        with patch('getzilla.osv_registry_releases._metadata', return_value=json.dumps(data).encode()):
            return lookup.published_artifacts(ecosystem, name, version)

    def test_crate_version_binds_download_and_yank_status(self):
        path = '/api/v1/crates/serde/1.0.219/download'
        row = dict(crate='serde', num='1.0.219', yanked=False, checksum='a' * 64, dl_path=path)
        def query(**overrides):
            return self.lookup('crates.io', 'serde', '1.0.219', {'version': dict(row, **overrides)})
        self.assertEqual(query(), ('https://crates.io' + path,))
        self.assertEqual(query(yanked=True), ())
        for override in [dict(yanked=None), dict(checksum=''), dict(num='2.0.0'), dict(dl_path='/other')]:
            with self.subTest(override=override), self.assertRaises(ArtifactError):
                query(**override)

    def test_invalid_crate_version_is_an_input_error_before_network(self):
        with patch('getzilla.osv_registry_releases._metadata', side_effect=AssertionError('unexpected fetch')):
            with self.assertRaises(ArtifactError):
                lookup.published_artifacts('crates.io', 'serde', 'latest')

    def test_scoped_npm_tarball_belongs_to_requested_release(self):
        import base64
        name = '@example/pkg'
        url = 'https://registry.npmjs.org/@example/pkg/-/pkg-1.2.3.tgz'
        dist = dict(tarball=url, integrity='sha512-' + base64.b64encode(b'x'*64).decode())
        row = dict(name=name, version='1.2.3', dist=dist)
        self.assertEqual(self.lookup('npm', name, '1.2.3', row), (url,))
        for override in [dict(name='pkg'), dict(dist=dict(dist, tarball=url.replace('1.2.3', '1.2.4'))),
                         dict(dist=dict(dist, integrity=''))]:
            with self.subTest(override=override), self.assertRaises(ArtifactError):
                self.lookup('npm', name, '1.2.3', dict(row, **override))

    def test_registry_404_is_absent_but_503_and_redirects_are_refusals(self):
        from getzilla import osv_registry_releases as registry
        url = 'https://crates.io/api/v1/crates/demo/1.2.3'
        for code, target in [(404, url), (503, url), (404, url + '/changed')]:
            error = registry.HTTPError(target, code, 'error', {}, None)
            with patch.object(registry, 'build_opener') as opener:
                opener.return_value.open.side_effect = error
                if (code, target) == (404, url):
                    self.assertEqual(lookup.published_artifacts('crates.io', 'demo', '1.2.3'), ())
                else:
                    with self.assertRaises(ArtifactError):
                        lookup.published_artifacts('crates.io', 'demo', '1.2.3')
