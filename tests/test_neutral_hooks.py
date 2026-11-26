"""Shared hook sources and ordinary installs do not depend on a client directory."""
from __future__ import annotations

import base64
import json
import re
import os
import subprocess
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
sys.path.insert(0, str(ROOT / 'scripts'))
from getzilla.harnesses import render
from getzilla.component_state import V2, encode_manifest
import install_into


class NeutralHooksTests(unittest.TestCase):
    def test_v211_release_preview_apply_rollback(self):
        import hashlib
        from unittest.mock import patch
        import getzilla_upgrade as upgrade
        from tests._support import public_source_copy
        from tests.test_getzilla_upgrade import GIT_ENV, git

        self.enterContext(patch.dict(os.environ, GIT_ENV))
        home = self.enterContext(public_source_copy(ROOT))
        project = Path(self.enterContext(tempfile.TemporaryDirectory())) / 'consumer'
        install_into.materialize_new(home, project, selection=install_into.PayloadSelection(('claude',), engine_archive=True))
        git(project, 'init', '--quiet', '--initial-branch=main')
        git(project, 'config', 'core.autocrlf', 'false')
        old = project / '.grok-stack/adaptive_grok/__init__.py'  # predecessor-record
        old.parent.mkdir(parents=True)
        stock = b'"""Adaptive Grok Build Pro runtime."""\n\n__version__ = "2.1.1"\n'  # predecessor-record
        old.write_bytes(stock)
        git(project, 'add', '-A')
        git(project, 'commit', '--quiet', '-m', 'predecessor 2.1.1 runtime')
        before = git(project, 'rev-parse', 'HEAD')
        report = upgrade.sync_project(home, project, preview=True)
        self.assertIn('RETIRE .grok-stack/adaptive_grok/__init__.py', report)  # predecessor-record
        self.assertIn(hashlib.sha256(stock).hexdigest(), report)
        self.assertEqual(git(project, 'rev-parse', 'HEAD'), before)
        upgrade.sync_project(home, project, retire=True)
        self.assertFalse(old.exists())
        self.assertIn('up to date', upgrade.sync_project(home, project, retire=True))
        event = {'cwd': str(project), 'session_id': 'retire-legacy-fixture',
                 'tool_name': 'Bash', 'tool_input': {'command': 'cat .env'}}
        hook = subprocess.run([sys.executable, str(project / '.getzilla/hooks/pre_tool_use.py')],
                              input=json.dumps(event), cwd=project, text=True, capture_output=True, timeout=30)
        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assertIn('deny', json.dumps(json.loads(hook.stdout)).lower())
        git(project, 'switch', '--quiet', 'main')
        self.assertEqual(old.read_bytes(), stock)

    def test_archived_neutral_install_keeps_actual_counted_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'consumer'
            install_into.materialize_new(
                ROOT, root,
                selection=install_into.PayloadSelection(('codex',), engine_archive=True))
            self.assertFalse((root / '.grok').exists())
            runner = root / 'scripts/getzilla_unittest.py'
            self.assertTrue(runner.is_file(), 'neutral compressed install lost counted runner')
            with zipfile.ZipFile(root / '.getzilla/getzilla.zip') as archive:
                self.assertTrue(any(name.endswith('.py') for name in archive.namelist()))
                self.assertFalse(any(name.endswith('.pyc') for name in archive.namelist()))
            for label, body, expected_exit, expected_count in (
                ('one', 'import unittest\nclass One(unittest.TestCase):\n'
                 '    def test_actual(self):\n        self.assertEqual(2 + 2, 4)\n', 0, 1),
                ('zero', 'value = 1\n', 5, 0),
            ):
                with self.subTest(collection=label):
                    suite = root / ('suite-' + label)
                    suite.mkdir()
                    (suite / 'test_actual.py').write_text(body, encoding='utf-8')
                    result = root / (label + '-result.json')
                    process = subprocess.run(
                        [sys.executable, str(runner), '--result', str(result),
                         '--nonce', 'composition-fixture', 'discover', '-s', str(suite)],
                        cwd=root, text=True, capture_output=True, timeout=30)
                    self.assertEqual(process.returncode, expected_exit, process.stderr)
                    self.assertEqual(json.loads(result.read_bytes()), {
                        'schema_version': 1, 'nonce': 'composition-fixture',
                        'tests_run': expected_count, 'successful': True})

    def test_all_clients_render_without_grok_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / '.getzilla', root / '.getzilla', ignore=shutil.ignore_patterns('runtime', '__pycache__'))
            shutil.copytree(ROOT / '.agents', root / '.agents')
            agents = ['codex', 'claude', 'qwen', 'gemini', 'copilot', 'grok', 'cursor']
            (root / '.getzilla/managed-components.json').write_bytes(encode_manifest({
                'schema_version': V2, 'agents': agents, 'components': {}}))
            outputs = render(root)
            for rel in ('.codex/hooks.json', '.claude/settings.json', '.qwen/settings.json',
                        '.gemini/settings.json', '.github/hooks/getzilla.json', '.grok/hooks.json'):
                # Encoded native Windows launchers still carry the same actual
                # Python hook; decode data without executing either language.
                text = outputs[rel].decode()
                decoded = [text]
                for encoded in re.findall(r'-EncodedCommand ([A-Za-z0-9+/=]+)', text):
                    powershell = base64.b64decode(encoded, validate=True).decode('utf-16le')
                    decoded.append(powershell)
                    decoded.extend(base64.b64decode(value, validate=True).decode('utf-8')
                                   for value in re.findall(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", powershell))
                logical = '\n'.join(decoded)
                self.assertIn('.getzilla/hooks/pre_tool_use.py', logical)
                self.assertNotIn('.grok/hooks/', logical)
            self.assertIn('.grok/skills/getzilla-delivery/SKILL.md', outputs)

    def test_archived_engine_fresh_install_enforces_guards_from_a_subdirectory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'consumer'
            install_into.materialize_new(ROOT, root, selection=install_into.PayloadSelection(('codex',), engine_archive=True))
            self.assertFalse((root / '.grok').exists())
            self.assertTrue((root / '.getzilla/getzilla.zip').is_file())
            self.assertFalse((root / '.getzilla/getzilla/policy.py').exists())
            child = root / 'src'
            child.mkdir()
            hook = json.loads((root / '.codex/hooks.json').read_bytes())['hooks']['PreToolUse'][0]['hooks'][0]
            command = hook['commandWindows' if os.name == 'nt' else 'command']
            env = {key: value for key, value in os.environ.items()
                   if key not in {'CLAUDE_PROJECT_DIR', 'QWEN_PROJECT_DIR', 'GEMINI_PROJECT_DIR', 'PYTHONPATH'}}
            for action, expected in (('echo hello', 'allow'), ('cat .env', 'deny')):
                proc = subprocess.run(command, shell=True, cwd=child, env=env,
                                      input=json.dumps({'cwd': str(root), 'session_id': 'neutral-test',
                                                        'tool_name': 'Bash', 'tool_input': {'command': action}}),
                                      text=True, capture_output=True, timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                verdict = json.loads(proc.stdout)
                if expected == 'allow':
                    self.assertEqual(verdict, {})
                else:
                    self.assertIn(expected, json.dumps(verdict).lower())

    def test_archived_engine_missing_policy_still_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'consumer'
            install_into.materialize_new(
                ROOT, root, selection=install_into.PayloadSelection(('codex',), engine_archive=True))
            archive = root / '.getzilla/getzilla.zip'
            with zipfile.ZipFile(archive) as source:
                members = [(item, source.read(item)) for item in source.infolist()
                           if item.filename != 'getzilla/policy.py']
            with zipfile.ZipFile(archive, 'w') as target:
                for item, content in members:
                    target.writestr(item, content)
            child = root / 'src'
            child.mkdir()
            proc = subprocess.run(
                [sys.executable, str(root / '.getzilla/hooks/pre_tool_use.py'), '--harness', 'codex'],
                cwd=child, input=json.dumps({'cwd': str(root), 'session_id': 'neutral-test',
                    'tool_name': 'Bash', 'tool_input': {'command': 'echo hello'}}),
                text=True, capture_output=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_non_grok_install_has_no_grok_files_and_has_shared_sources(self):
        payload = {entry.path: entry for entry in install_into.build_payload(
            ROOT, selection=install_into.PayloadSelection(('codex',)))}
        self.assertFalse([path for path in payload if path.startswith('.grok/')])
        self.assertIn('.getzilla/hooks/pre_tool_use.py', payload)
        self.assertIn('.getzilla/config/hooks.json', payload)
        self.assertIn('.getzilla/agents/code_reviewer.toml', payload)
        self.assertIn('.getzilla/config/codex-hooks.json', payload)
        events = json.loads(payload['.codex/hooks.json'].content)['hooks']
        self.assertIn('PreToolUse', events)


if __name__ == '__main__':
    unittest.main()
