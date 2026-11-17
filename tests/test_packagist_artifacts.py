"""New owned Packagist controls; fetch is inert data, all effects are denied."""
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
from getzilla import security_artifacts as artifacts
from getzilla import security_license_acquisition as acquisition
from getzilla import security_licenses as licenses
try:
    from getzilla import security_packagist
except ImportError:
    security_packagist = None

b'x'.decode('cp437')  # Load the stdlib ZIP name codec before closing fixture I/O.
NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)
MIT = b'''MIT License

Copyright (c) 2026 Owned Fixture

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
_ACTIVE = None

def audit(event, args):
    if _ACTIVE is None:
        return
    if event == 'open':
        value = args[0]
        if isinstance(value, int):
            value = os.readlink('/proc/self/fd/' + str(value))
        p = Path(os.fsdecode(value))
        if p.is_absolute() and not p.is_relative_to(_ACTIVE):
            flags = args[2] if isinstance(args[2], int) else 0
            if not (flags & os.O_DIRECTORY and _ACTIVE.is_relative_to(p)):
                raise AssertionError('outside owned I/O denied')
        elif not p.is_absolute() and args[1] is not None:
            raise AssertionError('relative stream I/O denied')
    if event in ('os.listdir', 'os.scandir'):
        value = args[0]
        p = Path(os.readlink('/proc/self/fd/' + str(value))) if isinstance(value, int) else Path(value)
        if not p.is_absolute() or not p.is_relative_to(_ACTIVE):
            raise AssertionError('outside owned listing denied')
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('unmocked effect denied')
sys.addaudithook(audit)

@contextmanager
def guarded(root):
    global _ACTIVE
    opener = os.open
    def checked(path, flags, *a, **kw):
        p = Path(os.fsdecode(path))
        if not p.is_absolute():
            p = Path(os.readlink('/proc/self/fd/' + str(kw['dir_fd']))) / p
        if not p.is_relative_to(root) and not (flags & os.O_DIRECTORY and root.is_relative_to(p)):
            raise AssertionError('outside owned native I/O denied')
        return opener(path, flags, *a, **kw)
    _ACTIVE = root
    try:
        with patch.object(os, 'open', checked), patch.object(os, 'supports_dir_fd', os.supports_dir_fd | {checked}):
            yield
    finally:
        _ACTIVE = None


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class PackagistArtifactTests(unittest.TestCase):
    def setUp(self):
        runtime = Path(__file__).resolve().parents[1] / '.getzilla/runtime/scratch'
        runtime.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='owned-composer-', dir=runtime)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.destination = self.root / 'evidence'
        self.responses = {}
        self.dependencies = []
        self.policy = dict(schema_version=1, project_repository='github.com/owned/source',
                           auto_allow=['MIT'], usage_distribution={'runtime': 'internal'})
        self.child = self.add('owned/leaf', '1.3.0', 'b' * 40, {})
        self.parent = self.add('owned/root', 'v2.0.1', 'a' * 40,
                               {'owned/leaf': '^1.2', 'php': '>=8.1'})
        self.current = dict(complete=True, gaps=[], dependencies=self.dependencies, tools=[], images=[],
                            marker_environment={'composer_platform': {'php': '8.3.6'}}, digest='d' * 64)

    def add(self, name, version, commit, requires):
        metadata = dict(name=name, license='MIT', require=requires)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.comment = commit.encode()
            archive.writestr('source-' + commit[:7] + '/composer.json', encoded(metadata))
            archive.writestr('source-' + commit[:7] + '/LICENSE', MIT)
            archive.writestr('source-' + commit[:7] + '/NOTICE', b'Owned notice')
            archive.writestr('source-' + commit[:7] + '/src/License.php', b'<?php class License {}')
        url = 'https://api.github.com/repos/' + name + '/zipball/' + commit
        release = dict(name=name, version=version, license=['MIT'], require=requires,
                       source=dict(type='git', url='https://github.com/' + name + '.git', reference=commit),
                       dist=dict(type='zip', url=url, reference=commit, shasum=''))
        registry = 'https://packagist.org/packages/' + name + '.json'
        self.responses[registry] = encoded(dict(package=dict(name=name, versions={version: release})))
        self.responses[url] = stream.getvalue()
        dep = dict(ecosystem='Packagist', name=name, version=version, manifest='composer.lock', usage='runtime')
        self.dependencies.append(dep)
        return registry, url

    def fetch(self, url, *, maximum):
        self.assertIn(url, self.responses)
        value = self.responses[url]
        self.assertLessEqual(len(value), maximum)
        return value

    def acquire(self):
        value = acquisition.acquire_pypi(self.dependencies, self.destination,
                                        inventory_digest=self.current['digest'], fetch=self.fetch, now=NOW)
        self.assertEqual(value['gaps'], [], 'Packagist must enter the real package acquisition path')
        self.assertEqual(len(value['records']), 2)
        return value

    def test_registry_bound_absent_version_and_license_closure(self):
        with guarded(self.root):
            bundle = self.acquire()
            report = licenses.evaluate_artifacts(self.current, self.destination, self.policy, now=NOW)
            self.assertEqual(report['status'], 'pass', report)
            self.assertEqual(len(report['details']), 2)
            self.assertEqual({r['ecosystem'] for r in bundle['records']}, {'Packagist'})
            self.assertTrue(all(row['notice_files'] for row in report['details']))
            self.assertTrue(all(row['origin']['version_source'] == 'packagist-registry' for row in report['details']))

    def test_origin_and_metadata_negative_cases(self):
        with guarded(self.root):
            self.acquire()
            baseline = dict(self.responses)
            registry, url = self.parent
            for kind in ('commit', 'version', 'url', 'name', 'license', 'comment'):
                self.responses = dict(baseline)
                data = json.loads(self.responses[registry])
                release = data['package']['versions']['v2.0.1']
                if kind == 'commit':
                    release['source']['reference'] = 'f' * 40
                elif kind == 'version':
                    release['version'] = '3.0.0'
                elif kind == 'url':
                    release['dist']['url'] = 'https://foreign.invalid/x.zip'
                elif kind == 'name':
                    release['name'] = 'foreign/package'
                elif kind == 'license':
                    release['license'] = ['GPL-3.0-only']
                else:
                    stream = io.BytesIO(self.responses[url])
                    with zipfile.ZipFile(stream, 'a') as archive:
                        archive.comment = b'f' * 40
                    self.responses[url] = stream.getvalue()
                self.responses[registry] = encoded(data)
                with self.assertRaises(artifacts.ArtifactError, msg=kind):
                    acquisition.acquire_pypi(self.dependencies, self.destination,
                        inventory_digest=self.current['digest'], fetch=self.fetch, now=NOW)

    def test_transitive_platform_scope_and_age_refuse(self):
        with guarded(self.root):
            self.acquire()
            for change in ('missing-child', 'wrong-child', 'platform', 'scope', 'stale'):
                current = json.loads(json.dumps(self.current))
                when = NOW
                if change == 'missing-child':
                    current['dependencies'] = [current['dependencies'][1]]
                elif change == 'wrong-child':
                    current['dependencies'][0]['version'] = '3.0.0'
                elif change == 'platform':
                    current['marker_environment'] = {}
                elif change == 'scope':
                    current['dependencies'][1]['distribution'] = 'redistributed'
                else:
                    when += timedelta(hours=72, seconds=1)
                report = licenses.evaluate_artifacts(current, self.destination, self.policy, now=when)
                self.assertEqual(report['status'], 'fail', change)


    def test_license_text_notice_and_embedded_identity_remain_evidence(self):
        with guarded(self.root):
            self.acquire()
            baseline = dict(self.responses)
            registry, url = self.parent
            for change in ('no-license', 'damaged-license', 'empty-notice', 'embedded-version', 'require-mismatch'):
                self.responses = dict(baseline)
                archive = io.BytesIO(self.responses[url])
                with zipfile.ZipFile(archive) as source:
                    members = {n: source.read(n) for n in source.namelist()}
                    comment = source.comment
                primary = next(p for p in members if p.endswith('/composer.json'))
                if change == 'no-license':
                    del members[next(p for p in members if p.endswith('/LICENSE'))]
                elif change == 'damaged-license':
                    members[next(p for p in members if p.endswith('/LICENSE'))] = b'MIT'
                elif change == 'empty-notice':
                    members[next(p for p in members if p.endswith('/NOTICE'))] = b''
                else:
                    data = json.loads(members[primary])
                    if change == 'embedded-version':
                        data['version'] = '9.0.0'
                    else:
                        data['require']['owned/leaf'] = '^9.0'
                    members[primary] = encoded(data)
                result = io.BytesIO()
                with zipfile.ZipFile(result, 'w') as target:
                    target.comment = comment
                    for name, content in members.items():
                        target.writestr(name, content)
                self.responses[url] = result.getvalue()
                if change in ('embedded-version', 'require-mismatch'):
                    with self.assertRaises(artifacts.ArtifactError, msg=change):
                        acquisition.acquire_pypi(self.dependencies, self.destination,
                            inventory_digest=self.current['digest'], fetch=self.fetch, now=NOW)
                else:
                    self.acquire()
                    report = licenses.evaluate_artifacts(self.current, self.destination, self.policy, now=NOW)
                    self.assertEqual(report['status'], 'fail', change)

    def test_existing_pypi_dispatch_and_npm_gap_stay_compatible(self):
        stream = io.BytesIO()
        filename = 'owned_extra-1.0.0-py3-none-any.whl'
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('owned_extra-1.0.0.dist-info/METADATA', b'Metadata-Version: 2.4\nName: owned-extra\nVersion: 1.0.0\nLicense-Expression: MIT\nLicense-File: LICENSE\n')
            archive.writestr('owned_extra-1.0.0.dist-info/licenses/LICENSE', MIT)
        payload = stream.getvalue()
        self.responses['https://files.pythonhosted.org/packages/' + filename] = payload
        self.responses['https://pypi.org/pypi/owned-extra/1.0.0/json'] = encoded(dict(
            info=dict(name='owned-extra', version='1.0.0'), urls=[dict(filename=filename,
            digests={'sha256': hashlib.sha256(payload).hexdigest()}, yanked=False, packagetype='bdist_wheel',
            url='https://files.pythonhosted.org/packages/' + filename)]))
        self.dependencies.append(dict(ecosystem='PyPI', name='owned-extra', version='1.0.0', manifest='requirements.txt', usage='runtime'))
        with guarded(self.root):
            bundle = acquisition.acquire_pypi(self.dependencies, self.destination,
                inventory_digest=self.current['digest'], fetch=self.fetch, now=NOW)
            self.assertEqual(bundle['gaps'], [])
            report = licenses.evaluate_artifacts(self.current, self.destination, self.policy, now=NOW)
            self.assertEqual(report['status'], 'pass', report)
            unsupported = acquisition.acquire_pypi([dict(ecosystem='npm', name='fixture', version='1.0.0')],
                self.root / 'npm-observation', inventory_digest='e'*64, fetch=self.fetch, now=NOW)
            self.assertEqual([g['code'] for g in unsupported['gaps']], ['artifact-acquisition-ecosystem'])


    def test_conflicting_locked_package_refuses(self):
        with guarded(self.root):
            self.acquire()
            registry, url = self.parent
            data = json.loads(self.responses[registry])
            data['package']['versions']['v2.0.1']['conflict'] = {'owned/leaf': '^1.0'}
            self.responses[registry] = encoded(data)
            stream = io.BytesIO(self.responses[url])
            with zipfile.ZipFile(stream) as archive:
                comment = archive.comment
                members = {name: archive.read(name) for name in archive.namelist()}
            name = next(name for name in members if name.endswith('/composer.json'))
            metadata = json.loads(members[name])
            metadata['conflict'] = {'owned/leaf': '^1.0'}
            members[name] = encoded(metadata)
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as archive:
                archive.comment = comment
                for name, body in members.items():
                    archive.writestr(name, body)
            self.responses[url] = stream.getvalue()
            self.acquire()
            report = licenses.evaluate_artifacts(self.current, self.destination, self.policy, now=NOW)
            self.assertEqual(report['status'], 'fail', 'an installed version matches a Composer conflict')

    def test_cross_lock_cannot_supply_transitive_coverage(self):
        with guarded(self.root):
            self.acquire()
            current = json.loads(json.dumps(self.current))
            current['dependencies'][0]['manifest'] = 'different/composer.lock'
            report = licenses.evaluate_artifacts(current, self.destination, self.policy, now=NOW)
            self.assertIn('license-transitive-coverage', {g['code'] for g in report['gaps']})

    def test_origin_redirects_are_bound_to_same_commit(self):
        with guarded(self.root):
            self.acquire()
            target = 'https://codeload.github.com/owned/root/legacy.zip/' + 'a'*40
            self.assertTrue(security_packagist.redirect_allowed(self.parent[1], target))
            self.assertFalse(security_packagist.redirect_allowed(self.parent[1], target.replace('/root/', '/foreign/')))
            self.assertFalse(artifacts.allowed_download_url('https://api.github.com/repos/../root/zipball/' + 'a'*40))


    def test_catalog_revalidation_and_inclusive_age(self):
        with guarded(self.root):
            bundle = self.acquire()
            projected = licenses.artifact_catalog_source(self.current, self.destination, self.policy, now=NOW)
            self.assertTrue(projected['coverage']['complete'])
            report = licenses.evaluate_artifacts(self.current, self.destination, self.policy, now=NOW + timedelta(hours=72))
            self.assertEqual(report['status'], 'pass', report)
            path = self.destination / bundle['records'][0]['path']
            data = bytearray(path.read_bytes())
            data[0] ^= 1
            path.write_bytes(data)
            with self.assertRaises(artifacts.ArtifactError):
                licenses.artifact_catalog_source(self.current, self.destination, self.policy, now=NOW)

    def test_production_redirect_handler_refuses_cross_source(self):
        with guarded(self.root):
            self.acquire()
            handler = acquisition._FixedOriginRedirect()
            target = 'https://codeload.github.com/owned/root/legacy.zip/' + 'a'*40
            request = SimpleNamespace(full_url=self.parent[1])
            # Only the guard is under test; the stdlib delegate stays inert.
            with patch.object(type(handler).__mro__[1], 'redirect_request', autospec=True,
                              return_value=SimpleNamespace(full_url=target)) as delegate:
                redirected = handler.redirect_request(request, None, 302, '', {}, target)
                self.assertEqual(redirected.full_url, target)
                delegate.assert_called_once_with(handler, request, None, 302, '', {}, target)
                delegate.reset_mock()
                with self.assertRaises(artifacts.ArtifactError):
                    handler.redirect_request(request, None, 302, '', {}, target.replace('/root/', '/foreign/'))
                with self.assertRaises(artifacts.ArtifactError):
                    handler.redirect_request(SimpleNamespace(full_url='https://pypi.org/pypi/owned/1.0.0/json'),
                        None, 302, '', {}, self.parent[1])
                delegate.assert_not_called()

    def test_stable_composer_constraints_are_conservative(self):
        with guarded(self.root):
            self.acquire()
            for version, constraint in (('0.2.4', '^0.2.3'), ('8.3.6', '^7.4 || ^8.0'), ('1.2.9', '~1.2.3')):
                self.assertTrue(security_packagist.satisfies(version, constraint))
            for version, constraint in (('0.3.0', '^0.2.3'), ('2.0.0', '~1.2'), ('1.3.0', '~1.2.3')):
                self.assertFalse(security_packagist.satisfies(version, constraint))
            for constraint in ('dev-main', '1.0.*', '>=1.0 <3.0 @dev'):
                with self.assertRaises(artifacts.ArtifactError):
                    security_packagist.satisfies('1.2.3', constraint)


    def test_saved_registry_cannot_bind_traversal_archive_url(self):
        with guarded(self.root):
            bundle = self.acquire()
            record = json.loads(json.dumps(bundle['records'][1]))
            payload = (self.destination / record['path']).read_bytes()
            index = json.loads(self.responses[self.parent[0]])
            release = index['package']['versions']['v2.0.1']
            release['source']['url'] = 'https://github.com/../root.git'
            release['dist']['url'] = 'https://api.github.com/repos/../root/zipball/' + 'a'*40
            record['origin']['artifact_url'] = release['dist']['url']
            raw = encoded(index)
            record['origin']['index_sha256'] = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(artifacts.ArtifactError):
                artifacts.verify_origin(self.destination, record, payload, index_bytes=raw)

    def test_fixed_origins_and_effect_denial(self):
        with guarded(self.root):
            self.acquire()
            for url in ('https://packagist.org.evil/packages/a/b.json',
                        'https://api.github.com/repos/a/b/zipball/main',
                        'https://api.github.com/repos/a/b/zipball/' + 'a'*40 + '?token=x'):
                self.assertFalse(artifacts.allowed_download_url(url), url)
            for effect in (lambda: Path('/never-owned-file').read_bytes(), lambda: os.listdir('/never-owned-list'), lambda: socket.socket(),
                           lambda: subprocess.Popen(['/never-execute']), lambda: ctypes.CDLL(None)):
                with self.assertRaises(AssertionError):
                    effect()
