"""Third-party tool updates a person starts: agent CLIs, workflow sources, OSV mirror, OpenGrep.

No network: git sources are local repositories, downloads are fakes, and agent
installers are recorded instead of run. Nothing starts updates on its own.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import updater

from tests._support import project_copy, run_hook



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
            return b'PK\x03\x04' + url.encode()
        results = {item.component: item for item in updater.update_osv(fetch, self.root)}
        self.assertEqual(results['osv:npm'].status, 'fail')
        self.assertEqual(results['osv:PyPI'].status, 'ok')
        self.assertTrue((self.root / 'osv/PyPI/all.zip').read_bytes().startswith(b'PK'))
        rejected = updater.update_osv(lambda url: b'<html>', self.root)
        self.assertTrue(all(item.status == 'fail' for item in rejected))
        self.assertTrue((self.root / 'osv/PyPI/all.zip').read_bytes().startswith(b'PK'))

    def test_opengrep_latest_release_is_installed_executable(self) -> None:
        release = {'tag_name': 'v9.9.9', 'assets': [
            {'name': 'opengrep_manylinux_x86', 'browser_download_url': 'https://example.invalid/bin'},
        ]}
        def fetch(url: str) -> bytes:
            return json.dumps(release).encode() if url == updater.OPENGREP_RELEASE else b'\x7fELF'
        result = updater.update_opengrep(fetch, self.root, ('linux', 'x86_64'))
        self.assertEqual(result[0].detail, 'v9.9.9')
        binary = self.root / 'bin/opengrep'
        self.assertEqual(binary.read_bytes(), b'\x7fELF')
        if os.name != 'nt':
            self.assertTrue(stat.S_IMODE(binary.stat().st_mode) & stat.S_IXUSR)
        self.assertEqual(updater.update_opengrep(fetch, self.root, ('linux', 'aarch64'))[0].status, 'fail')
        self.assertEqual(updater.update_opengrep(fetch, self.root, ('sunos', 'sparc'))[0].status, 'skip')

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
        self.assertIn('[y/N]', shell)
        self.assertIn('[y/N]', powershell)
        self.assertIn('can_ask', shell[shell.index('offer_tool_update() {'):])
        self.assertIn('Test-CanAsk', powershell[powershell.index('function Request-ToolUpdate'):])

if __name__ == '__main__':
    unittest.main()
