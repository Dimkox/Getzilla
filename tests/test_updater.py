"""Third-party tool updates a person starts: agent CLIs, workflow sources, OSV mirror, OpenGrep.

No network: git sources are local repositories, downloads are fakes, and agent
installers are recorded instead of run. Nothing starts updates on its own.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import baseline, updater

from tests._support import offline_mirror, project_copy, run_hook



def _zip_bytes(name: str, padding: int = 64) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_STORED) as archive:
        archive.writestr('osv-test.json', ('{"id": "%s", "padding": "%s"}' % (name, 'x' * padding)).encode())
    return buffer.getvalue()


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(['git', *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


class UpdaterTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / 'state'

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_due_respects_the_interval(self) -> None:
        now = 1_000_000.0
        self.assertTrue(updater.is_due(self.root, now, {}))
        updater.save_state(self.root, [], now)
        self.assertFalse(updater.is_due(self.root, now + 1800, {}))
        self.assertTrue(updater.is_due(self.root, now + 3600, {}))
        self.assertTrue(updater.is_due(self.root, now + 1, {'GETZILLA_UPDATE_INTERVAL_HOURS': '0'}))
        self.assertFalse(updater.is_due(self.root, now + 3600, {'GETZILLA_UPDATE_INTERVAL_HOURS': '24'}))
        self.assertEqual(updater.interval_hours({'GETZILLA_UPDATE_INTERVAL_HOURS': 'soon'}), 1.0)

    def test_only_one_update_runs_and_stale_locks_expire(self) -> None:
        now = time.time()
        with updater.update_lock(self.root, now) as first:
            self.assertTrue(first)
            with updater.update_lock(self.root, now) as second:
                self.assertFalse(second)
        self.assertFalse((self.root / updater.LOCK_FILE).exists())
        (self.root / updater.LOCK_FILE).write_text('1')
        old = now - updater.LOCK_STALE_SECONDS - 10
        os.utime(self.root / updater.LOCK_FILE, (old, old))
        with updater.update_lock(self.root, now) as acquired:
            self.assertTrue(acquired)

    def test_sources_follow_the_latest_upstream_commit(self) -> None:
        upstream = Path(self._tmp.name) / 'upstream'
        upstream.mkdir()
        _git('init', '-q', cwd=upstream)
        _git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'one', cwd=upstream)
        sources = {'superpowers': upstream.as_uri()}
        first = updater.update_sources(updater._default_runner, self.root, sources)
        self.assertEqual(first[0].status, 'ok')
        self.assertEqual(first[0].detail, _git('rev-parse', '--short=12', 'HEAD', cwd=upstream))
        _git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'two', cwd=upstream)
        second = updater.update_sources(updater._default_runner, self.root, sources)
        self.assertEqual(second[0].detail, _git('rev-parse', '--short=12', 'HEAD', cwd=upstream))
        broken = updater.update_sources(updater._default_runner, self.root, {'bmad': (upstream / 'missing').as_uri()})
        self.assertEqual(broken[0].status, 'fail')

    def test_osv_mirror_is_replaced_per_ecosystem(self) -> None:
        def fetch(url: str) -> bytes:
            if '/npm/' in url:
                raise OSError('offline')
            return _zip_bytes(url)
        results = {item.component: item for item in updater.update_osv(fetch, self.root)}
        self.assertEqual(results['osv:npm'].status, 'fail')
        self.assertEqual(results['osv:PyPI'].status, 'ok')
        self.assertTrue((self.root / 'osv/PyPI/all.zip').read_bytes().startswith(b'PK'))
        rejected = updater.update_osv(lambda url: b'<html>', self.root)
        self.assertTrue(all(item.status == 'fail' for item in rejected))
        self.assertTrue((self.root / 'osv/PyPI/all.zip').read_bytes().startswith(b'PK'))

    def test_osv_archive_with_bad_crc_is_rejected(self) -> None:
        good = _zip_bytes('x', padding=64 * 1024)
        updater.update_osv(lambda url: good, self.root)
        corrupt = bytearray(good)
        # ZIP_STORED keeps the payload verbatim. Flip one byte near the end of a member larger
        # than zipfile's read chunk: headers and filename stay intact, and a reader that stops
        # after the first chunk never sees it -- only a full CRC check (testzip) does.
        corrupt[good.rindex(b'x' * 64) + 32] ^= 0x01
        results = updater.update_osv(lambda url: bytes(corrupt), self.root)
        self.assertTrue(all(item.status == 'fail' for item in results), results)
        self.assertEqual((self.root / 'osv/PyPI/all.zip').read_bytes(), good)
        truncated = updater.update_osv(lambda url: b'PK\x03\x04' + b'x' * 32, self.root)
        self.assertTrue(all(item.status == 'fail' for item in truncated))

    def _pinned(self, payload: bytes) -> mock._patch:
        return mock.patch.dict(updater.OPENGREP_ASSETS, {
            ('linux', 'x86_64'): ('opengrep_manylinux_x86', hashlib.sha256(payload).hexdigest()),
        })

    def test_opengrep_pinned_release_is_verified_and_installed_executable(self) -> None:
        urls: list[str] = []
        def fetch(url: str) -> bytes:
            urls.append(url)
            return b'\x7fELF'
        with self._pinned(b'\x7fELF'):
            result = updater.update_opengrep(fetch, self.root, ('linux', 'x86_64'))
        self.assertEqual(result[0].status, 'ok', result)
        self.assertIn(f'v{updater.OPENGREP_VERSION}', result[0].detail)
        self.assertEqual(urls, [
            f'https://github.com/opengrep/opengrep/releases/download/v{updater.OPENGREP_VERSION}/opengrep_manylinux_x86',
        ])
        binary = self.root / 'bin/opengrep'
        self.assertEqual(binary.read_bytes(), b'\x7fELF')
        if os.name != 'nt':
            self.assertTrue(stat.S_IMODE(binary.stat().st_mode) & stat.S_IXUSR)
        self.assertEqual(updater.update_opengrep(fetch, self.root, ('sunos', 'sparc'))[0].status, 'skip')

    def test_opengrep_checksum_mismatch_is_not_installed(self) -> None:
        with self._pinned(b'\x7fELF'):
            result = updater.update_opengrep(lambda url: b'tampered', self.root, ('linux', 'x86_64'))
            self.assertEqual(result[0].status, 'fail')
            self.assertIn('sha256', result[0].detail)
            self.assertFalse((self.root / 'bin/opengrep').exists())

    def test_unverified_previous_opengrep_is_quarantined_not_kept(self) -> None:
        # A binary that does not match the pin (e.g. installed from `latest` by an older updater)
        # must not stay runnable when the pinned download fails or does not verify (#39).
        def offline(url: str) -> bytes:
            raise OSError('offline')
        for fetch in (lambda url: b'tampered', offline):
            with self.subTest(fetch=fetch), self._pinned(b'\x7fELF'):
                (self.root / 'bin').mkdir(parents=True, exist_ok=True)
                binary = self.root / 'bin/opengrep'
                binary.write_bytes(b'previous')
                binary.chmod(0o755)
                result = updater.update_opengrep(fetch, self.root, ('linux', 'x86_64'))
                self.assertEqual(result[0].status, 'fail')
                self.assertIn('quarantined', result[0].detail)
                self.assertFalse(binary.exists())
                quarantined = self.root / 'bin/opengrep.unverified'
                self.assertEqual(quarantined.read_bytes(), b'previous')
                if os.name != 'nt':
                    self.assertEqual(stat.S_IMODE(quarantined.stat().st_mode) & 0o111, 0)

    def test_opengrep_never_follows_the_latest_release(self) -> None:
        urls: list[str] = []
        def fetch(url: str) -> bytes:
            urls.append(url)
            raise OSError('offline')
        for key in updater.OPENGREP_ASSETS:
            updater.update_opengrep(fetch, self.root, key)
        self.assertTrue(urls)
        self.assertFalse([url for url in urls if 'latest' in url or 'api.github.com' in url], urls)

    def test_installed_opengrep_with_pinned_digest_is_not_downloaded_again(self) -> None:
        (self.root / 'bin').mkdir(parents=True)
        (self.root / 'bin/opengrep').write_bytes(b'\x7fELF')
        def fetch(url: str) -> bytes:
            raise AssertionError('must not download')
        with self._pinned(b'\x7fELF'):
            result = updater.update_opengrep(fetch, self.root, ('linux', 'x86_64'))
        self.assertEqual(result[0].status, 'ok', result)

    @unittest.skipIf(os.name == 'nt', 'POSIX execute bits')
    def test_installed_opengrep_without_execute_bits_is_made_executable(self) -> None:
        (self.root / 'bin').mkdir(parents=True)
        binary = self.root / 'bin/opengrep'
        binary.write_bytes(b'\x7fELF')
        binary.chmod(0o644)
        def fetch(url: str) -> bytes:
            raise AssertionError('must not download')
        with self._pinned(b'\x7fELF'):
            result = updater.update_opengrep(fetch, self.root, ('linux', 'x86_64'))
        self.assertEqual(result[0].status, 'ok', result)
        self.assertTrue(os.access(binary, os.X_OK))
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode) & 0o111, 0o111)

    def test_opengrep_pin_matches_the_ci_runner_pin(self) -> None:
        runner = (ROOT / 'trust-ci/runner.Dockerfile').read_text(encoding='utf-8')
        version = re.search(r'ARG OPENGREP_VERSION=(\S+)', runner).group(1)
        digest = re.search(r'ARG OPENGREP_SHA256=([0-9a-f]{64})', runner).group(1)
        self.assertEqual(updater.OPENGREP_VERSION, version)
        self.assertEqual(updater.OPENGREP_ASSETS[('linux', 'x86_64')], ('opengrep_manylinux_x86', digest))
        for asset, sha256 in updater.OPENGREP_ASSETS.values():
            self.assertRegex(sha256, r'^[0-9a-f]{64}$', asset)

    def test_only_installed_agents_are_updated(self) -> None:
        calls: list[list[str]] = []
        def run(command, cwd=None):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, 'ok', '')
        installed = {'npm': '/bin/npm', 'qwen': '/bin/qwen', 'copilot': '/bin/copilot', 'claude': '/bin/claude',
                     'specify': '/bin/specify', 'uv': '/bin/uv'}
        results = updater.update_agents(run, installed.get)
        self.assertIn(['/bin/npm', 'install', '-g', '@qwen-code/qwen-code@latest'], calls)
        self.assertIn(['/bin/npm', 'install', '-g', '@github/copilot@latest'], calls)
        self.assertIn(['/bin/claude', 'update'], calls)
        self.assertTrue(any(call[:4] == ['/bin/uv', 'tool', 'install', '--force'] for call in calls))
        self.assertFalse(any('@openai/codex@latest' in call for call in calls))
        self.assertEqual({item.component for item in results},
                         {'agent:qwen', 'agent:copilot', 'agent:claude', 'tool:specify'})
        no_npm = updater.update_agents(run, {'codex': '/bin/codex'}.get)
        self.assertEqual(no_npm[0].status, 'skip')

    def test_main_records_results_and_status(self) -> None:
        fake = [updater.Result('osv:PyPI', 'ok', '1 KiB'), updater.Result('source:bmad', 'fail', 'offline')]
        with mock.patch.dict(os.environ, {'GETZILLA_STATE_HOME': str(self.root)}), \
                mock.patch.object(updater, 'run_all', return_value=fake), \
                mock.patch.object(updater, 'export_environment', return_value=[]):
            self.assertEqual(updater.main(['--now', '--quiet']), 1)
            state = json.loads((self.root / updater.STATE_FILE).read_text())
            self.assertEqual(state['results']['source:bmad'], {'status': 'fail', 'detail': 'offline'})
            self.assertEqual(updater.main(['--if-due', '--quiet']), 0)

    def test_session_start_only_reminds_when_tools_are_stale(self) -> None:
        now = 2_000_000.0
        self.assertIn('have never been updated', updater.reminder(self.root, now))
        updater.save_state(self.root, [], now - 3 * 86400)
        note = updater.reminder(self.root, now)
        self.assertIn('3 day(s) ago', note)
        self.assertIn('do not run it yourself', note)
        updater.save_state(self.root, [], now - 3600)
        self.assertIsNone(updater.reminder(self.root, now))
        with project_copy() as root, mock.patch.dict(os.environ, {'GETZILLA_STATE_HOME': str(self.root / 'fresh')}):
            code, data, stderr = run_hook(root, 'session_start.py', {'cwd': str(root)})
        self.assertEqual(code, 0, stderr)
        self.assertIn('scripts/getzilla_update.py', data['hookSpecificOutput']['additionalContext'])
        self.assertFalse((self.root / 'fresh').exists())

    def test_no_hook_or_installer_runs_updates_without_a_person(self) -> None:
        for rel in ('.grok/hooks/session_start.py', '.grok/hooks/user_prompt_submit.py', '.grok/hooks/stop_gate.py'):
            text = (ROOT / rel).read_text(encoding='utf-8')
            self.assertNotIn('run_all', text, rel)
            self.assertNotIn('getzilla_update.py', text, rel)
        shell = (ROOT / 'scripts/install.sh').read_text(encoding='utf-8')
        powershell = (ROOT / 'scripts/install.ps1').read_text(encoding='utf-8')
        # Installers install only the pinned baseline (owner decision 2026-10-16); moving tools to their
        # latest versions is never run by an installer, only printed as a separate command.
        for text in (shell, powershell):
            for latest in ('--only agents', '--only sources', "'--only', 'agents'", "'--only', 'sources'"):
                for line in text.splitlines():
                    if latest in line and not line.lstrip().startswith('#'):
                        self.fail(f'installer runs a latest-version update: {line.strip()}')
        self.assertIn('--only baseline', shell)
        self.assertIn("'--only', 'baseline'", powershell)


class OfflineMirrorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / 'state'
        self.mirror_dir = offline_mirror(self.base)
        self.uv: list[list[str]] = []

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _mirror(self) -> updater.Mirror:
        return updater.Mirror.from_environ({updater.MIRROR_ENV: str(self.mirror_dir)})

    def _run(self, command: list[str], cwd: Path | None) -> subprocess.CompletedProcess:
        if command[0] == 'fake-uv':
            self.uv.append(command)
            return subprocess.CompletedProcess(command, 0, '', '')
        return baseline.default_runner(command, cwd)

    def _update(self, mirror: updater.Mirror) -> dict[str, updater.Result]:
        def network(*args, **kwargs):
            raise AssertionError('the offline mirror must not reach the network')
        with mock.patch.object(updater, '_default_fetch', network), \
                mock.patch.object(updater.urllib.request, 'urlopen', network):
            results = updater.run_all(self.root, run=self._run, which={'uv': 'fake-uv', 'npx': 'npx'}.get, mirror=mirror,
                                      components=('agents', 'osv', 'opengrep', 'baseline'))
        return {item.component: item for item in results}

    def test_every_download_comes_from_the_mirror_with_its_pins(self) -> None:
        results = self._update(self._mirror())
        self.assertEqual(results.pop('agents').status, 'skip')
        self.assertEqual({name: item.status for name, item in results.items() if item.status != 'ok'}, {})
        for name, item in results.items():
            self.assertIn(f'[offline mirror {self.mirror_dir}', item.detail, name)
        for name in ('tool:opengrep', 'baseline:superpowers', 'baseline:bmad', 'baseline:spec-kit'):
            self.assertIn(f'pin from {updater.MIRROR_MANIFEST}', results[name].detail, name)
        self.assertNotIn('pin from', results['osv:PyPI'].detail)
        self.assertEqual((self.root / 'osv/npm/all.zip').read_bytes(),
                         (self.mirror_dir / 'osv/npm/all.zip').read_bytes())
        asset, _ = updater.OPENGREP_ASSETS[updater._platform_key()]
        installed = next((self.root / 'bin').glob('opengrep*'))
        self.assertEqual(installed.read_bytes(),
                         (self.mirror_dir / 'opengrep' / f'v{updater.OPENGREP_VERSION}' / asset).read_bytes())
        spec_kit = baseline.components()['spec-kit']
        source = (self.mirror_dir / 'git' / f"{spec_kit['repository']}.git").as_uri()
        self.assertEqual(self.uv[0][-1], f"git+{source}@{spec_kit['upstream_tag']}")
        again = self._update(self._mirror())
        self.assertIn('already installed, sha256 verified', again['tool:opengrep'].detail)

    def test_a_mirror_without_its_own_pins_must_match_the_release_pins(self) -> None:
        (self.mirror_dir / updater.MIRROR_MANIFEST).unlink()
        results = self._update(self._mirror())
        self.assertEqual(results['osv:PyPI'].status, 'ok')
        self.assertEqual(results['tool:opengrep'].status, 'fail')
        self.assertIn('does not match pinned', results['tool:opengrep'].detail)
        self.assertFalse((self.root / 'bin').exists() and any((self.root / 'bin').glob('opengrep*')))
        for component_id in ('superpowers', 'bmad', 'spec-kit'):
            self.assertEqual(results[f'baseline:{component_id}'].status, 'fail')
            self.assertIn('PINNED_COMMIT_MISMATCH', results[f'baseline:{component_id}'].detail)
            self.assertNotIn('pin from', results[f'baseline:{component_id}'].detail)

    def test_mirror_refuses_foreign_urls_and_bad_settings(self) -> None:
        mirror = self._mirror()
        self.assertEqual(mirror.path(f'{updater.OSV_BUCKET}/Go/all.zip'), self.mirror_dir / 'osv/Go/all.zip')
        self.assertEqual(mirror.path('https://github.com/obra/superpowers.git'),
                         self.mirror_dir / 'git/obra/superpowers.git')
        for url in ('https://example.com/all.zip', f'{updater.OSV_BUCKET}/../../etc/passwd',
                    'https://github.com/a/..\\..\\b.git', f'{updater.OSV_BUCKET}/'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                mirror.path(url)
        self.assertIsNone(updater.Mirror.from_environ({}))
        for value in ('relative/mirror', str(self.base / 'missing')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                updater.Mirror.from_environ({updater.MIRROR_ENV: value})
        manifest = self.mirror_dir / updater.MIRROR_MANIFEST
        for text in ('[]', '{"opengrep": {"opengrep_manylinux_x86": "abc"}}', '{"baseline": []}', 'not json'):
            manifest.write_text(text, encoding='utf-8')
            with self.subTest(manifest=text), self.assertRaises(ValueError):
                self._mirror()
        with mock.patch.dict(os.environ, {'GETZILLA_STATE_HOME': str(self.root), updater.MIRROR_ENV: str(self.mirror_dir)}), \
                mock.patch.object(updater, 'run_all') as run_all, mock.patch('sys.stderr', new_callable=io.StringIO) as err:
            self.assertEqual(updater.main(['--only', 'osv']), 2)
        run_all.assert_not_called()
        self.assertIn(updater.MIRROR_MANIFEST, err.getvalue())


if __name__ == '__main__':
    unittest.main()
