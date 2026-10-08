"""User-level agent configuration written by the installers.

Every case runs against a throwaway HOME. The OpenRouter key must land only in
private (0600) user files, existing user settings must survive, and a project
never receives the key.
"""

from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import agent_setup
from getzilla.agent_setup import configure

KEY = 'sk-or-v1-0123456789abcdef0123456789abcdef'


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _exported(home: Path) -> dict[str, str]:
    """What a new login shell exports, read the way an agent process inherits it."""
    key_file = home / '.getzilla/openrouter.env'
    if key_file.exists():
        assert _mode(key_file) == 0o600
    script = '. "$HOME/.bashrc" >/dev/null 2>&1; env'
    output = subprocess.run(['bash', '--norc', '-c', script], env={'HOME': str(home), 'PATH': os.environ['PATH']},
                            capture_output=True, text=True, check=True).stdout
    names = ('OPENROUTER_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'GEMINI_API_KEY', 'COPILOT_GITHUB_TOKEN')
    return {line.split('=', 1)[0]: line.split('=', 1)[1] for line in output.splitlines()
            if line.split('=', 1)[0] in names}


@unittest.skipIf(os.name == 'nt', 'POSIX file modes and shell profiles')
class AgentSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_qwen_gets_an_openrouter_provider_and_keeps_existing_settings(self) -> None:
        settings = self.home / '.qwen/settings.json'
        settings.parent.mkdir()
        settings.write_text(json.dumps({'ui': {'theme': 'dark'}, 'modelProviders': {'openai': [{'id': 'mine'}]}}))
        result = configure('qwen', 'openrouter', self.home, key=KEY)
        data = json.loads(settings.read_text())
        self.assertEqual(data['ui'], {'theme': 'dark'})
        self.assertEqual(data['model']['name'], 'qwen/qwen3-coder')
        self.assertEqual(data['security']['auth']['selectedType'], 'openai')
        first, mine = data['modelProviders']['openai']
        self.assertEqual(first['envKey'], 'OPENROUTER_API_KEY')
        self.assertEqual(first['baseUrl'], 'https://openrouter.ai/api/v1')
        self.assertEqual(mine, {'id': 'mine'})
        self.assertNotIn(KEY, settings.read_text())
        self.assertFalse((self.home / '.qwen/.env').exists())
        self.assertEqual(_exported(self.home), {'OPENROUTER_API_KEY': KEY})
        self.assertIn('open a new terminal so the agent sees OPENROUTER_API_KEY', result.next_steps)

    def test_running_twice_does_not_duplicate_the_provider(self) -> None:
        configure('qwen', 'openrouter', self.home, key=KEY)
        configure('qwen', 'openrouter', self.home, key=KEY)
        data = json.loads((self.home / '.qwen/settings.json').read_text())
        self.assertEqual(len(data['modelProviders']['openai']), 1)

    def test_claude_routes_through_openrouter_in_user_settings_only(self) -> None:
        settings = self.home / '.claude/settings.json'
        settings.parent.mkdir()
        settings.write_text(json.dumps({'env': {'KEEP': '1'}, 'theme': 'light'}))
        configure('claude', 'openrouter', self.home, key=KEY)
        data = json.loads(settings.read_text())
        self.assertEqual(data['theme'], 'light')
        self.assertEqual(data['env'], {
            'KEEP': '1',
            'ANTHROPIC_BASE_URL': 'https://openrouter.ai/api',
            'ANTHROPIC_API_KEY': '',
        })
        self.assertNotIn(KEY, settings.read_text())
        self.assertEqual(_exported(self.home), {'OPENROUTER_API_KEY': KEY, 'ANTHROPIC_AUTH_TOKEN': KEY})

    def test_codex_gets_a_valid_provider_and_a_private_key_file(self) -> None:
        (self.home / '.bashrc').write_text('alias ll="ls -l"\n')
        config = self.home / '.codex/config.toml'
        config.parent.mkdir()
        config.write_text('approval_policy = "on-request"\n\n[projects."/x"]\ntrust_level = "trusted"\n')
        configure('codex', 'openrouter', self.home, key=KEY)
        data = tomllib.loads(config.read_text())
        self.assertEqual(data['model_provider'], 'openrouter')
        self.assertEqual(data['model'], 'openai/gpt-5.5')
        self.assertEqual(data['approval_policy'], 'on-request')
        self.assertEqual(data['projects']['/x']['trust_level'], 'trusted')
        self.assertEqual(data['model_providers']['openrouter']['env_key'], 'OPENROUTER_API_KEY')
        self.assertNotIn(KEY, config.read_text())
        key_file = self.home / '.getzilla/openrouter.env'
        self.assertEqual(_mode(key_file), 0o600)
        loaded = subprocess.run(
            ['bash', '-c', f'. "{key_file}"; printf %s "$OPENROUTER_API_KEY"'],
            capture_output=True, text=True, check=True,
        ).stdout
        self.assertEqual(loaded, KEY)
        self.assertEqual(_exported(self.home), {'OPENROUTER_API_KEY': KEY})
        configure('codex', 'openrouter', self.home, key=KEY)
        bashrc = (self.home / '.bashrc').read_text()
        self.assertEqual(bashrc.count(agent_setup.PROFILE_MARKER), 1)
        self.assertTrue(bashrc.startswith('alias ll="ls -l"\n'))
        self.assertEqual(config.read_text().count('[model_providers.openrouter]'), 1)

    def test_codex_respects_an_existing_provider_choice(self) -> None:
        config = self.home / '.codex/config.toml'
        config.parent.mkdir()
        config.write_text('model_provider = "azure"\n')
        result = configure('codex', 'openrouter', self.home, key=KEY)
        data = tomllib.loads(config.read_text())
        self.assertEqual(data['model_provider'], 'azure')
        self.assertIn('openrouter', data['model_providers'])
        self.assertTrue(any('already uses model_provider = "azure"' in step for step in result.next_steps))

    def test_codex_replaces_an_existing_model_and_keeps_other_providers(self) -> None:
        config = self.home / '.codex/config.toml'
        config.parent.mkdir()
        original = (
            '# my settings\r\nmodel = "gpt-5"\r\nmodel_reasoning_effort = "high"\r\n\r\n'
            '[model_providers]\r\n\r\n[model_providers.azure]\r\nname = "Azure"\r\n'
        )
        config.write_bytes(original.encode())
        configure('codex', 'openrouter', self.home, key=KEY, model='qwen/qwen3-coder')
        data = tomllib.loads(config.read_text())
        self.assertEqual(data['model'], 'qwen/qwen3-coder')
        self.assertEqual(data['model_reasoning_effort'], 'high')
        self.assertEqual(set(data['model_providers']), {'azure', 'openrouter'})
        self.assertEqual((self.home / '.codex/config.toml.getzilla-backup').read_bytes(), original.encode())
        configure('codex', 'openrouter', self.home, key=KEY, model='openai/gpt-5.5')
        self.assertEqual(tomllib.loads(config.read_text())['model'], 'openai/gpt-5.5')
        self.assertEqual((self.home / '.codex/config.toml.getzilla-backup').read_bytes(), original.encode())

    def test_codex_refuses_files_it_cannot_edit_safely(self) -> None:
        config = self.home / '.codex/config.toml'
        config.parent.mkdir()
        for text in (
            'model_providers = { azure = { name = "Azure" } }\n',
            'model = \n',
            'note = \"\"\"\nmodel = "x"\n\"\"\"\n',
        ):
            config.write_text(text)
            with self.assertRaises(ValueError):
                configure('codex', 'openrouter', self.home, key=KEY)
            self.assertEqual(config.read_text(), text)
        self.assertFalse((self.home / '.getzilla').exists())

    def test_qwen_refuses_unexpected_shapes_before_writing_the_key(self) -> None:
        settings = self.home / '.qwen/settings.json'
        settings.parent.mkdir()
        for content in ('{"model": "x"}', '{"security": "x"}', '{"modelProviders": {"openai": {}}}',
                        '{// comment\n}'):
            settings.write_text(content)
            with self.assertRaises(ValueError):
                configure('qwen', 'openrouter', self.home, key=KEY)
            self.assertEqual(settings.read_text(), content)
            self.assertFalse((self.home / '.getzilla').exists())

    def test_switching_to_native_sign_in_removes_the_openrouter_routing(self) -> None:
        for agent in ('qwen', 'claude', 'codex'):
            configure(agent, 'openrouter', self.home, key=KEY)
            result = configure(agent, 'native', self.home, key=None)
            self.assertTrue(result.written, agent)
        claude = json.loads((self.home / '.claude/settings.json').read_text())
        self.assertEqual(claude['env'], {})
        qwen = json.loads((self.home / '.qwen/settings.json').read_text())
        self.assertEqual(qwen['modelProviders']['openai'], [])
        self.assertNotIn('name', qwen['model'])
        self.assertNotIn('selectedType', qwen['security']['auth'])
        codex = tomllib.loads((self.home / '.codex/config.toml').read_text())
        self.assertNotIn('model_provider', codex)
        self.assertNotIn('model', codex)
        self.assertEqual(_exported(self.home), {'OPENROUTER_API_KEY': KEY})
        result = agent_setup.forget_key(self.home)
        self.assertTrue(result.written)
        self.assertFalse((self.home / '.getzilla/openrouter.env').exists())
        self.assertNotIn('openrouter.env', (self.home / '.bashrc').read_text())

    def test_zsh_profiles_get_the_key_on_macos(self) -> None:
        with mock.patch.object(agent_setup.sys, 'platform', 'darwin'):
            result = configure('codex', 'openrouter', self.home, key=KEY)
        for profile in ('.zshrc', '.bashrc'):
            self.assertIn(agent_setup.PROFILE_MARKER, (self.home / profile).read_text(), profile)
        self.assertFalse((self.home / '.bash_profile').exists())
        self.assertIn('open a new terminal so the agent sees OPENROUTER_API_KEY', result.next_steps)

    def test_symlinked_settings_are_written_through(self) -> None:
        real = self.home / 'dotfiles/claude.json'
        real.parent.mkdir()
        real.write_text('{"theme": "dark"}')
        (self.home / '.claude').mkdir()
        (self.home / '.claude/settings.json').symlink_to(real)
        configure('claude', 'openrouter', self.home, key=KEY)
        self.assertTrue((self.home / '.claude/settings.json').is_symlink())
        self.assertEqual(json.loads(real.read_text())['theme'], 'dark')
        self.assertEqual([p.name for p in real.parent.iterdir()], ['claude.json'])

    def test_gemini_and_copilot_keys_become_environment_variables(self) -> None:
        result = configure('gemini', 'openrouter', self.home, key='AIzaSyA-0123456789abcdefghijklmnopqrstu')
        self.assertIn('open a new terminal so the agent sees GEMINI_API_KEY', result.next_steps)
        configure('copilot', 'native', self.home, key='github_pat_0123456789abcdefABCDEF')
        self.assertEqual(_exported(self.home), {
            'GEMINI_API_KEY': 'AIzaSyA-0123456789abcdefghijklmnopqrstu',
            'COPILOT_GITHUB_TOKEN': 'github_pat_0123456789abcdefABCDEF',
        })
        agent_setup.forget_key(self.home)
        self.assertEqual(_exported(self.home), {})
        for agent in ('gemini', 'copilot'):
            result = configure(agent, 'native', self.home, key=None)
            self.assertEqual(result.written, ())
            self.assertIn(agent, result.next_steps[0])

    def test_native_login_and_grok_write_nothing(self) -> None:
        for agent, provider in (('grok', 'openrouter'), ('codex', 'native'), ('claude', 'native')):
            result = configure(agent, provider, self.home, key=KEY)
            self.assertEqual(result.written, ())
            self.assertTrue(result.next_steps)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_missing_key_writes_nothing_and_explains(self) -> None:
        result = configure('qwen', 'openrouter', self.home, key=None)
        self.assertEqual(result.written, ())
        self.assertIn('openrouter.ai/keys', result.next_steps[0])
        self.assertEqual(list(self.home.iterdir()), [])

    def test_malformed_key_and_settings_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            configure('qwen', 'openrouter', self.home, key="bad key'; rm -rf ~")
        settings = self.home / '.claude/settings.json'
        settings.parent.mkdir()
        settings.write_text('[]')
        with self.assertRaises(ValueError):
            configure('claude', 'openrouter', self.home, key=KEY)
        self.assertEqual(settings.read_text(), '[]')

    def test_cli_reads_the_key_from_stdin_and_never_prints_it(self) -> None:
        env = {**os.environ, 'HOME': str(self.home)}
        env.pop('OPENROUTER_API_KEY', None)
        result = subprocess.run(
            [sys.executable, str(ROOT / 'scripts/getzilla_setup_agent.py'), '--agent', 'qwen', '--key-stdin'],
            input=KEY + '\n', capture_output=True, text=True, env=env, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(KEY, result.stdout + result.stderr)
        self.assertIn('configured:', result.stdout)
        self.assertEqual(agent_setup.read_key(io.StringIO('  \n')), None)

    def test_unknown_agent_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            configure('cursor', 'openrouter', self.home, key=KEY)
        with mock.patch.object(agent_setup, 'AGENTS', ('qwen',)):
            with self.assertRaises(ValueError):
                configure('codex', 'openrouter', self.home, key=KEY)


if __name__ == '__main__':
    unittest.main()
