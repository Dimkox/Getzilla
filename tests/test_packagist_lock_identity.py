"""Fresh public acquisition/evaluation regressions for observed Composer lock scope."""
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
from datetime import datetime, timezone
from unittest.mock import patch
from tests._support import fixture_descriptor_path
from getzilla import security_family_inputs  # noqa: F401 preload before fixture I/O isolation
from getzilla import security_license_acquisition, security_licenses
# Preload the complete production closure before closing fixture I/O.
from getzilla import security_packagist as _packagist  # noqa: F401
from getzilla import security_release_tool_inputs  # noqa: F401
from getzilla.security_artifacts import ArtifactError

b'x'.decode('cp437')
NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)
MIT = b'''MIT License

Copyright (c) 2026 Explicit Lock Fixture

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
_BOUND = None

def _audit(event, args):
    if _BOUND is None:
        return
    if event == 'open':
        value = args[0]
        p = Path(fixture_descriptor_path(value)) if isinstance(value, int) else Path(os.fsdecode(value))
        flags = args[2] if isinstance(args[2], int) else 0
        if p.is_absolute():
            if not p.is_relative_to(_BOUND) and not (flags & os.O_DIRECTORY and _BOUND.is_relative_to(p)):
                raise AssertionError('foreign fixture I/O denied')
        elif args[1] is not None:
            raise AssertionError('relative stream denied')
    if event in ('os.listdir', 'os.scandir'):
        value = args[0]
        p = Path(fixture_descriptor_path(value)) if isinstance(value, int) else Path(value)
        if not p.is_absolute() or not p.is_relative_to(_BOUND):
            raise AssertionError('foreign fixture listing denied')
    if event.startswith(('socket.', 'subprocess.', 'ctypes.')) or event in ('os.system', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('unmocked effect denied')
sys.addaudithook(_audit)

@contextmanager
def _guard(root):
    global _BOUND
    original = os.open
    def opened(path, flags, *args, **kwargs):
        p = Path(os.fsdecode(path))
        if not p.is_absolute():
            p = Path(fixture_descriptor_path(kwargs['dir_fd'])) / p
        if not p.is_relative_to(root) and not (flags & os.O_DIRECTORY and root.is_relative_to(p)):
            raise AssertionError('foreign descriptor open denied')
        return original(path, flags, *args, **kwargs)
    _BOUND = root
    try:
        with patch.object(os, 'open', opened), patch.object(os, 'supports_dir_fd', os.supports_dir_fd | {opened}):
            yield
    finally:
        _BOUND = None


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class PackagistLockIdentityTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[1] / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        directory = tempfile.TemporaryDirectory(prefix='owned-lock-identity-', dir=scratch)
        self.addCleanup(directory.cleanup)
        self.owned = Path(directory.name)
        self.responses = {}
        self.deps = []
        for name, release, commit, requirements in (
                ('audit/leaf', '1.2.0', '1' * 40, {}),
                ('audit/application', '3.1.0', '2' * 40, {'audit/leaf': '>=1.0.0'})):
            body = _json(dict(name=name, license='MIT', require=requirements))
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as archive:
                archive.comment = commit.encode()
                archive.writestr('bound-source/composer.json', body)
                archive.writestr('bound-source/LICENSE', MIT)
            index_url = 'https://packagist.org/packages/' + name + '.json'
            dist_url = 'https://api.github.com/repos/' + name + '/zipball/' + commit
            entry = dict(name=name, version=release, license=['MIT'], require=requirements,
                         source=dict(type='git', url='https://github.com/' + name + '.git', reference=commit),
                         dist=dict(type='zip', url=dist_url, reference=commit, shasum=''))
            self.responses[index_url] = _json(dict(package=dict(name=name, versions={release: entry})))
            self.responses[dist_url] = buffer.getvalue()
            self.deps.append(dict(ecosystem='Packagist', name=name, version=release,
                                  manifest='explicit-target/composer.lock', usage='runtime'))
        self.policy = dict(schema_version=1, project_repository='github.com/audit/caller',
                           auto_allow=['MIT'], usage_distribution={'runtime': 'internal'})

    def fetch(self, url, *, maximum):
        self.assertIn(url, self.responses)
        result = self.responses[url]
        self.assertLessEqual(len(result), maximum)
        return result

    def consume(self, label, deps):
        current = dict(complete=True, gaps=[], dependencies=deps, tools=[], images=[])
        current['digest'] = hashlib.sha256(_json(current)).hexdigest()
        destination = self.owned / label
        bundle = security_license_acquisition.acquire_pypi(deps, destination,
                    inventory_digest=current['digest'], fetch=self.fetch, now=NOW)
        self.assertEqual(bundle['gaps'], [])
        self.assertEqual(len(bundle['records']), 2)
        return security_licenses.evaluate_artifacts(current, destination, self.policy, now=NOW)

    def assert_lock_refusal(self, result):
        self.assertEqual(result['status'], 'fail', 'unproved lock scope must not grant artifact PASS')
        self.assertIn('license-transitive-coverage', {g['code'] for g in result['gaps']})

    def test_explicit_shared_lock_remains_valid(self):
        with _guard(self.owned):
            result = self.consume('explicit', self.deps)
            self.assertEqual(result['status'], 'pass', result)
            self.assertEqual(len(result['details']), 2)

    def test_both_absent_lock_identities_refuse_public_closure(self):
        deps = [{k: v for k, v in dep.items() if k != 'manifest'} for dep in self.deps]
        with _guard(self.owned):
            self.assert_lock_refusal(self.consume('absent-both', deps))

    def test_parent_absent_lock_identity_refuses_public_closure(self):
        deps = [dict(dep) for dep in self.deps]
        deps[1].pop('manifest')
        with _guard(self.owned):
            self.assert_lock_refusal(self.consume('absent-parent', deps))

    def test_child_absent_lock_identity_refuses_public_closure(self):
        deps = [dict(dep) for dep in self.deps]
        deps[0].pop('manifest')
        with _guard(self.owned):
            self.assert_lock_refusal(self.consume('absent-child', deps))

    def test_nonempty_malformed_or_non_lock_identity_refuses(self):
        with _guard(self.owned):
            for number, scope in enumerate((' ', 'not-a-lock.json', '../composer.lock',
                                             '/absolute/composer.lock', './composer.lock',
                                             'target//composer.lock', 'C:/composer.lock')):
                deps = [dict(dep, manifest=scope) for dep in self.deps]
                self.assert_lock_refusal(self.consume('malformed-' + str(number), deps))

    def test_empty_and_non_string_manifest_keep_producer_refusal(self):
        with _guard(self.owned):
            for number, scope in enumerate(('', None, 7, True, {})):
                deps = [dict(dep, manifest=scope) for dep in self.deps]
                with self.assertRaises(ArtifactError):
                    self.consume('invalid-' + str(number), deps)

    def test_guard_denies_foreign_bytes_and_unmocked_effects(self):
        with _guard(self.owned):
            for effect in (lambda: Path('/outside-lock-fixture').read_bytes(),
                           lambda: os.listdir('/outside-lock-fixture'), lambda: socket.socket(),
                           lambda: subprocess.Popen(['/never-execute']), lambda: ctypes.CDLL(None)):
                with self.assertRaises(AssertionError):
                    effect()
