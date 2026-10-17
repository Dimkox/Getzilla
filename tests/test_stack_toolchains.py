"""S01: toolchains install per user, only after the checksum matches, without touching PATH or profiles."""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import stack_toolchains  # noqa: E402
from getzilla.stack_toolchains import Blocker, Toolchain, ensure_toolchain, platform_key, resolve_version  # noqa: E402

BASE = 'https://example.test/dist'


def _tar(files: dict[str, bytes], *, prefix: str = 'tool-1.2.3-linux-x64', links: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as bundle:
        for name, content in files.items():
            info = tarfile.TarInfo(f'{prefix}/{name}' if prefix else name)
            info.size, info.mode = len(content), 0o755
            bundle.addfile(info, io.BytesIO(content))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(f'{prefix}/{name}')
            info.type, info.linkname = tarfile.SYMTYPE, target
            bundle.addfile(info)
    return buffer.getvalue()


def _zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as bundle:
        for name, content in files.items():
            bundle.writestr(name, content)
    return buffer.getvalue()


def _spec(*, pinned: dict[str, str] | None = None, strip: int = 1) -> dict:
    return {
        'default_version': '1.2.3',
        'pin_files': [{'path': '.toolrc', 'kind': 'text'}],
        'source': {
            'kind': 'archive', 'algorithm': 'sha256', 'url': BASE + '/v{version}/{archive}',
            'archives': {key: name for key, name in (('linux-x64', 'tool-{version}-linux-x64.tar.gz'),
                                                     ('windows-x64', 'tool-{version}-win-x64.zip'))},
            'checksums': {'kind': 'sha256-list', 'url': BASE + '/v{version}/SHASUMS256.txt'},
            'strip_components': strip,
            'pinned': {'1.2.3': pinned} if pinned else {},
        },
        'bin': {'posix': ['bin'], 'windows': ['.']},
        'env': {'TOOL_HOME': '{home}', 'TOOL_CACHE': '{cache}/pkgs'},
    }


class FakeFetch:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files, self.calls = files, []

    def __call__(self, url: str, destination: Path) -> None:
        self.calls.append(url)
        if url not in self.files:
            raise urllib.error.URLError('unreachable')
        destination.write_bytes(self.files[url])


def _sums(entries: dict[str, bytes]) -> bytes:
    return ''.join(f'{hashlib.sha256(content).hexdigest()}  {name}\n' for name, content in entries.items()).encode()


class ToolchainTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name) / 'home'
        self.home.mkdir()
        self.root = self.home / '.getzilla' / 'toolchains'
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home), 'USERPROFILE': str(self.home),
                                             'GETZILLA_TOOLCHAIN_CACHE': str(self.home / '.getzilla' / 'cache')})
        patch.start()
        self.addCleanup(patch.stop)
        self.archive = _tar({'bin/tool': b'#!/bin/sh\necho tool 1.2.3\n'}, links={'bin/tool-alias': 'tool'})
        self.name = 'tool-1.2.3-linux-x64.tar.gz'

    def _fetch(self, archive: bytes | None = None, sums: bytes | None = None) -> FakeFetch:
        archive = self.archive if archive is None else archive
        return FakeFetch({f'{BASE}/v1.2.3/{self.name}': archive,
                          f'{BASE}/v1.2.3/SHASUMS256.txt': sums if sums is not None else _sums({self.name: self.archive})})

    def _ensure(self, spec: dict, fetch: FakeFetch, **kwargs) -> Toolchain | Blocker:
        return ensure_toolchain('tool', spec, '1.2.3', fetch=fetch, key=kwargs.pop('key', 'linux-x64'), root=self.root, **kwargs)

    def test_installs_after_checksum_and_reuses_the_pin(self) -> None:
        fetch = self._fetch()
        first = self._ensure(_spec(), fetch)
        self.assertIsInstance(first, Toolchain)
        assert isinstance(first, Toolchain)
        self.assertTrue(first.fetched)
        self.assertTrue((first.home / 'bin' / 'tool').is_file())
        self.assertTrue((first.home / 'bin' / 'tool-alias').is_symlink())
        self.assertEqual(first.home, self.root / 'tool' / '1.2.3')
        marker = json.loads((first.home / stack_toolchains.MARKER).read_text(encoding='utf-8'))
        self.assertEqual(marker['digest'], hashlib.sha256(self.archive).hexdigest())
        calls = len(fetch.calls)
        again = self._ensure(_spec(), fetch)
        assert isinstance(again, Toolchain)
        self.assertFalse(again.fetched)
        self.assertEqual(len(fetch.calls), calls, 'the same pin must not download again')

    def test_checksum_mismatch_unpacks_nothing(self) -> None:
        tampered = _tar({'bin/tool': b'#!/bin/sh\necho evil\n'})
        result = self._ensure(_spec(), self._fetch(archive=tampered))
        self.assertIsInstance(result, Blocker)
        assert isinstance(result, Blocker)
        self.assertEqual(result.code, 'TOOLCHAIN_CHECKSUM_MISMATCH')
        self.assertFalse((self.root / 'tool' / '1.2.3').exists())
        self.assertEqual(list((self.root / 'tool').glob('.staging-*')), [])
        self.assertEqual(list((self.home / '.getzilla' / 'cache' / 'tool' / 'downloads').glob('*')), [])

    def test_published_manifest_must_agree_with_the_pinned_digest(self) -> None:
        result = self._ensure(_spec(pinned={'linux-x64': '0' * 64}), self._fetch())
        assert isinstance(result, Blocker)
        self.assertEqual(result.code, 'TOOLCHAIN_CHECKSUM_MISMATCH')

    def test_pinned_digest_works_when_the_manifest_is_unreachable(self) -> None:
        fetch = FakeFetch({f'{BASE}/v1.2.3/{self.name}': self.archive})
        result = self._ensure(_spec(pinned={'linux-x64': hashlib.sha256(self.archive).hexdigest()}), fetch)
        self.assertIsInstance(result, Toolchain)

    def test_unreachable_source_is_a_failure_not_a_skip(self) -> None:
        result = self._ensure(_spec(), FakeFetch({}))
        assert isinstance(result, Blocker)
        self.assertEqual(result.code, 'TOOLCHAIN_UNAVAILABLE')

    def test_unsafe_archive_is_refused(self) -> None:
        evil = _tar({'../../escape': b'x'}, prefix='')
        name_sums = _sums({self.name: evil})
        result = self._ensure(_spec(strip=0), self._fetch(archive=evil, sums=name_sums))
        assert isinstance(result, Blocker)
        self.assertEqual(result.code, 'TOOLCHAIN_ARCHIVE_UNSAFE')
        self.assertFalse((self.home / 'escape').exists())
        link = _tar({}, links={'bin/x': '../../../../etc/passwd'})
        result = self._ensure(_spec(), self._fetch(archive=link, sums=_sums({self.name: link})))
        assert isinstance(result, Blocker)
        self.assertEqual(result.code, 'TOOLCHAIN_ARCHIVE_UNSAFE')

    def test_windows_zip_and_unsupported_platform(self) -> None:
        archive = _zip({'tool.exe': b'MZ'})
        zip_name = 'tool-1.2.3-win-x64.zip'
        fetch = FakeFetch({f'{BASE}/v1.2.3/{zip_name}': archive, f'{BASE}/v1.2.3/SHASUMS256.txt': _sums({zip_name: archive})})
        result = self._ensure(_spec(strip=0), fetch, key='windows-x64')
        assert isinstance(result, Toolchain)
        self.assertEqual(result.bin_dirs, (result.home / '.',))
        self.assertTrue((result.home / 'tool.exe').is_file())
        other = self._ensure(_spec(), self._fetch(), key='freebsd-x64')
        assert isinstance(other, Blocker)
        self.assertEqual(other.code, 'TOOLCHAIN_UNSUPPORTED_PLATFORM:freebsd-x64')

    def test_admin_prerequisite_is_reported_with_a_command_and_never_installed(self) -> None:
        spec = _spec()
        spec['requires'] = [{'id': 'msvc-build-tools', 'platforms': ['windows-x64'], 'unless_channel_suffix': '-gnu',
                             'probe': 'link.exe', 'message': 'needs MSVC', 'command': 'winget install X'}]
        fetch = self._fetch()
        result = ensure_toolchain('tool', spec, '1.2.3', fetch=fetch, key='windows-x64', root=self.root, which=lambda _name: None)
        assert isinstance(result, Blocker)
        self.assertEqual((result.code, result.command), ('TOOLCHAIN_NEEDS_ADMIN:msvc-build-tools', 'winget install X'))
        self.assertEqual(fetch.calls, [])
        gnu = ensure_toolchain('tool', spec, '1.2.3-gnu', fetch=fetch, key='windows-x64', root=self.root, which=lambda _name: None)
        self.assertNotEqual(getattr(gnu, 'code', ''), 'TOOLCHAIN_NEEDS_ADMIN:msvc-build-tools')

    def test_only_the_check_process_sees_the_toolchain(self) -> None:
        profiles = ('.profile', '.bashrc', '.zshrc', '.bash_profile')
        before_path = os.environ.get('PATH')
        result = self._ensure(_spec(), self._fetch())
        assert isinstance(result, Toolchain)
        environment = result.process_env({'PATH': '/usr/bin'})
        self.assertEqual(environment['PATH'].split(os.pathsep)[0], str(result.home / 'bin'))
        self.assertEqual(environment['TOOL_HOME'], str(result.home))
        self.assertTrue(environment['TOOL_CACHE'].startswith(str(self.home / '.getzilla' / 'cache' / 'tool')))
        self.assertEqual(os.environ.get('PATH'), before_path)
        self.assertEqual([name for name in profiles if (self.home / name).exists()], [])
        self.assertEqual(sorted(path.name for path in self.home.iterdir()), ['.getzilla'])
        source = Path(stack_toolchains.__file__).read_text(encoding='utf-8')
        for forbidden in ('winreg', 'setx', 'HKCU', 'os.environ[', 'os.putenv'):
            self.assertNotIn(forbidden, source)


class VersionTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def _write(self, name: str, text: str) -> None:
        (self.root / name).write_text(text, encoding='utf-8')

    def test_pin_files_win_over_the_registry_default(self) -> None:
        spec = {'default_version': '9.9.9', 'pin_files': [
            {'path': '.nvmrc', 'kind': 'text'}, {'path': 'global.json', 'kind': 'json', 'key': 'sdk.version'},
            {'path': 'rust-toolchain.toml', 'kind': 'toml', 'key': 'toolchain.channel'},
            {'path': 'go.mod', 'kind': 'regex', 'pattern': r'^toolchain go(\S+)'},
            {'path': '.java-version', 'kind': 'text'}]}
        self.assertEqual(resolve_version(self.root, spec), ('9.9.9', 'stacks.json'))
        self._write('.java-version', '21.0.4\n')
        self.assertEqual(resolve_version(self.root, spec), ('21.0.4', '.java-version'))
        self._write('go.mod', 'module x\n\ngo 1.22\ntoolchain go1.22.5\n')
        self.assertEqual(resolve_version(self.root, spec), ('1.22.5', 'go.mod'))
        self._write('rust-toolchain.toml', '[toolchain]\nchannel = "1.80.1"\ncomponents = ["clippy"]\n')
        self.assertEqual(resolve_version(self.root, spec), ('1.80.1', 'rust-toolchain.toml'))
        self._write('global.json', json.dumps({'sdk': {'version': '8.0.404', 'rollForward': 'latestFeature'}}))
        self.assertEqual(resolve_version(self.root, spec), ('8.0.404', 'global.json'))
        self._write('.nvmrc', 'v22.11.0\n')
        self.assertEqual(resolve_version(self.root, spec), ('22.11.0', '.nvmrc'))

    def test_platform_keys(self) -> None:
        self.assertEqual(platform_key('Linux', 'x86_64'), 'linux-x64')
        self.assertEqual(platform_key('Windows', 'AMD64'), 'windows-x64')
        self.assertEqual(platform_key('Darwin', 'arm64'), 'darwin-arm64')
        self.assertEqual(platform_key('Linux', 'aarch64'), 'linux-arm64')


if __name__ == '__main__':
    unittest.main()
