"""Shell launchers select Python separately from the hook's policy outcome."""
from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.harnesses import _command, _powershell_command, _source_hook_command, platform_hook_payload, render


class HookLauncherTests(unittest.TestCase):
    def fixture(self, root):
        (root / '.getzilla/getzilla').mkdir(parents=True)
        (root / '.getzilla/getzilla/__init__.py').touch()
        hooks = root / '.getzilla/hooks'
        hooks.mkdir()
        (hooks / 'probe.py').write_text(
            "import pathlib,sys\n"
            "p=pathlib.Path(__file__).parents[2]\n"
            "with (p/'calls').open('a') as f:f.write('1')\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n"
            "sys.stderr.write('policy denied')\n"
            "raise SystemExit(2)\n", encoding='utf-8')

    @unittest.skipUnless(os.name != 'nt' and shutil.which('bash'), 'POSIX Bash host required; native Windows contract below')
    def test_posix_deny_runs_once_and_preserves_json_bytes(self):
        with tempfile.TemporaryDirectory(prefix="hook ' Ю ") as directory:
            root = Path(directory)
            self.fixture(root)
            payload = json.dumps({'text': 'Юникод 😀'}, ensure_ascii=False).encode()
            result = subprocess.run(['bash', '-c', _command('probe.py', 'codex')],
                                    cwd=root, input=payload, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, payload)
            self.assertEqual((root/'calls').read_text(), '1')
            self.assertEqual(result.stderr, b'policy denied')

    def test_windows_command_is_ps51_encoded_and_has_no_pipeline_chain(self):
        command = _command('probe.py', 'copilot', windows=True)
        self.assertTrue(command.startswith('powershell.exe -NoProfile -NonInteractive -EncodedCommand '))
        code = base64.b64decode(command.rsplit(' ', 1)[1]).decode('utf-16le')
        self.assertNotIn('||', code)
        self.assertIn('ProcessStartInfo', code)
        self.assertIn('ExitCode', code)

    @unittest.skipUnless(os.name != 'nt' and shutil.which('pwsh'), 'Portable PowerShell host required')
    def test_optional_startup_progress_cannot_wrap_inherited_hook_streams(self):
        with tempfile.TemporaryDirectory(prefix="hook ' Ю ") as directory:
            root = Path(directory)
            self.fixture(root)
            binaries = root/'bin'
            binaries.mkdir()
            (binaries/'python3.exe').symlink_to(sys.executable)
            encoded = _command('probe.py', 'copilot', windows=True).rsplit(' ', 1)[1]
            code = base64.b64decode(encoded).decode('utf-16le')
            # Model optional first-use module progress at the actual constructor
            # boundary, without replacing the child launch or its byte handles.
            code = code.replace('$info=New-Object',
                                "Write-Progress -Activity 'owned startup' -Status 'owned progress';$info=New-Object")
            payload = '{"text":"Юникод 😀"}'.encode()
            result = subprocess.run([shutil.which('pwsh'), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                     base64.b64encode(code.encode('utf-16le')).decode('ascii')],
                                    cwd=root, env={**os.environ, 'PATH': str(binaries)+os.pathsep+os.environ['PATH']},
                                    input=payload, capture_output=True, timeout=15)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, payload, b'policy denied'))
            self.assertEqual((root/'calls').read_text(), '1')

    def test_equivalent_owned_windows_mode_is_idempotent_without_adopting_foreign_bytes(self):
        import getzilla.harnesses as harnesses
        from getzilla.component_state import BoundRoot, component_transaction, encode_manifest, read_state, MANIFEST
        import importlib.util
        spec = importlib.util.spec_from_file_location('hook_mode_installer', ROOT/'scripts/install_into.py')
        installer = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = installer
        spec.loader.exec_module(installer)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'consumer'
            installer._materialize_new(ROOT, target, include_dependencies=False, include_optional=False,
                                       selection=installer.PayloadSelection(('qwen',)))
            settings = target/'.qwen/settings.json'
            content = settings.read_bytes()
            state = read_state(target)
            state.manifest['components']['agent:qwen']['owned']['.qwen/settings.json']['mode'] = 0o666
            with component_transaction(target) as transaction:
                transaction.write(MANIFEST, encode_manifest(state.manifest), 0o644, expected=transaction.read(MANIFEST))
            before = (target/MANIFEST).read_bytes()
            # Exact portable Windows mode semantics, without changing the native
            # filesystem implementation or trusting a candidate container/value.
            def windows_mode(actual, expected):
                return bool(actual & stat.S_IWRITE) == bool(expected & stat.S_IWUSR)

            with mock.patch.object(harnesses, 'mode_matches', side_effect=windows_mode):
                self.assertEqual(harnesses.write(target), [])
                self.assertEqual((target/MANIFEST).read_bytes(), before)
                for field, value in (('sha256', '0'*64), ('mode', 0o400)):
                    with self.subTest(unmatched=field), BoundRoot(target) as binding:
                        proposal = copy.deepcopy(read_state(target, binding=binding))
                        proof = proposal.manifest['components']['agent:qwen']['owned']['.qwen/settings.json']
                        proof[field] = value
                        _problems, _changes, _retirements, manifest = harnesses._generation_plan(
                            binding, proposal, ('qwen',))
                        self.assertEqual(manifest['components']['agent:qwen']['owned']['.qwen/settings.json']['mode'],
                                         0o644, 'unmatched metadata cannot retain an old platform mode')
                    self.assertEqual((target/MANIFEST).read_bytes(), before, 'proposal must not publish')
                settings.write_bytes(b'{"foreign":true}\n')
                foreign = settings.read_bytes()
                with self.assertRaisesRegex(ValueError, 'conflict'):
                    harnesses.write(target)
                self.assertEqual(settings.read_bytes(), foreign)
                self.assertEqual((target/MANIFEST).read_bytes(), before)
                settings.write_bytes(content)
                settings.chmod(0o400)
                try:
                    with self.assertRaisesRegex(ValueError, 'conflict'):
                        harnesses.write(target)
                    self.assertEqual((target/MANIFEST).read_bytes(), before)
                finally:
                    settings.chmod(0o644)

    @unittest.skipUnless(shutil.which('bash') and os.name != 'nt', 'POSIX Bash required')
    def test_discovery_fallback_and_absence_do_not_run_hook_twice(self):
        bash = shutil.which('bash')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            binaries = root / 'bin'
            binaries.mkdir()
            # The first name exists but is not a usable Python interpreter.
            (binaries/'python3').write_text('#!/bin/sh\nexit 37\n')
            (binaries/'python3').chmod(0o755)
            (binaries/'python').symlink_to(sys.executable)
            env = {**os.environ, 'PATH': str(binaries)}
            result = subprocess.run([bash, '-c', _command('probe.py', 'codex')],
                                    cwd=root, input=b'{"one":1}', env=env, capture_output=True)
            self.assertEqual((result.returncode, result.stdout), (2, b'{"one":1}'))
            self.assertEqual((root/'calls').read_text(), '1')
            (binaries/'python').unlink()
            result = subprocess.run([bash, '-c', _command('probe.py', 'codex')],
                                    cwd=root, input=b'{}', env=env, capture_output=True)
            self.assertEqual(result.returncode, 127)
            self.assertEqual((root/'calls').read_text(), '1')

    def test_platform_conversion_preserves_settings_and_custom_hooks(self):
        data = {'context': {'fileName': ['AGENTS.md']}, 'hooks': {'BeforeTool': [
            {'hooks': [{'command': _command('probe.py', 'gemini')},
                       {'command': 'custom.exe'}]}]}}
        original = json.dumps(data).encode()
        converted = platform_hook_payload('.gemini/settings.json', original, windows=True)
        expected = json.loads(original)
        expected['hooks']['BeforeTool'][0]['hooks'][0]['command'] = _command('probe.py', 'gemini', windows=True)
        self.assertEqual(json.loads(converted), expected)
        self.assertEqual(platform_hook_payload('.gemini/settings.json', converted, windows=True), converted)
        self.assertEqual(json.loads(platform_hook_payload('.gemini/settings.json', converted, windows=False)), data)

    def test_installer_platform_transform_is_part_of_payload_before_publication(self):
        # Use the real descriptor reader and payload builder, with no install or
        # external effects. Overriding this pure boundary avoids faking os.name.
        import importlib.util
        spec = importlib.util.spec_from_file_location('hook_launcher_installer', ROOT/'scripts/install_into.py')
        installer = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = installer
        spec.loader.exec_module(installer)
        def windows_payload(path, content):
            return platform_hook_payload(path, content, windows=True)
        with mock.patch.object(installer, 'platform_hook_payload', side_effect=windows_payload):
            payload = {entry.path: entry.content for entry in installer._build_full_payload(ROOT)}
        for path, harness, event in (('.qwen/settings.json', 'qwen', 'PreToolUse'),
                                     ('.gemini/settings.json', 'gemini', 'BeforeTool'),
                                     ('.claude/settings.json', 'claude', 'PreToolUse'),
                                     ('.grok/hooks.json', 'grok', 'PreToolUse')):
            command = json.loads(payload[path])['hooks'][event][0]['hooks'][0]['command']
            self.assertEqual(command, _command('pre_tool_use.py', harness, windows=True))

    @unittest.skipUnless(os.name != 'nt', 'POSIX source launcher; Windows uses native control below')
    def test_source_path_launcher_preserves_stdin_outcome_and_root_priority(self):
        with tempfile.TemporaryDirectory(prefix="source ' Ю ") as directory:
            root = Path(directory)
            reported = root / 'reported'
            reported.mkdir()
            self.fixture(reported)
            nested = root / 'nested'
            (nested / '.getzilla/hooks').mkdir(parents=True)
            (nested / '.getzilla/hooks/probe.py').write_text("raise SystemExit(98)\n")
            env = {**os.environ, 'PATH': str(ROOT/'bin')+os.pathsep+os.environ['PATH'],
                   'QWEN_PROJECT_DIR': str(reported)}
            for key in ('CLAUDE_PROJECT_DIR', 'GEMINI_PROJECT_DIR'):
                env.pop(key, None)
            result = subprocess.run(['sh', '-c', _source_hook_command('probe.py', 'qwen')],
                                    cwd=nested, env=env, input=b'{"source":"\xce\xa9"}', capture_output=True)
            self.assertEqual((result.returncode, result.stdout), (2, b'{"source":"\xce\xa9"}'))
            self.assertEqual((reported/'calls').read_text(), '1')

    def test_source_render_is_platform_independent_and_never_rewrites_checkout(self):
        from types import SimpleNamespace
        import getzilla.harnesses as harnesses
        expected = render(ROOT, repository_all=True)
        with mock.patch.object(harnesses, 'os', SimpleNamespace(name='nt')):
            self.assertEqual(render(ROOT, repository_all=True), expected)
        command = json.loads(expected['.qwen/settings.json'])['hooks']['PreToolUse'][0]['hooks'][0]['command']
        self.assertEqual(command, _source_hook_command('pre_tool_use.py', 'qwen'))

    def test_windows_consumer_publication_rerender_and_local_edit_refusal(self):
        import hashlib
        import importlib.util
        from types import SimpleNamespace
        import getzilla.harnesses as harnesses
        from getzilla.component_state import read_state
        spec = importlib.util.spec_from_file_location('hook_publication_installer', ROOT/'scripts/install_into.py')
        installer = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = installer
        spec.loader.exec_module(installer)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'consumer'
            with mock.patch.object(installer, 'platform_hook_payload',
                                   side_effect=lambda path, content: platform_hook_payload(path, content, windows=True)):
                installer._materialize_new(ROOT, target, include_dependencies=False, include_optional=False,
                                           selection=installer.PayloadSelection(('qwen',)))
            settings = target/'.qwen/settings.json'
            content = settings.read_bytes()
            owned = read_state(target).manifest['components']['agent:qwen']['owned']['.qwen/settings.json']
            self.assertEqual(owned['sha256'], hashlib.sha256(content).hexdigest())
            with mock.patch.object(harnesses, 'os', SimpleNamespace(name='nt')):
                self.assertEqual(harnesses.drift(target), [])
                self.assertEqual(harnesses.write(target), [])
                events = target/'.getzilla/config/hooks.json'
                data = json.loads(events.read_bytes())
                data['hooks']['PreToolUse'][0]['hooks'][0]['timeout'] += 1
                events.write_text(json.dumps(data))
                self.assertIn('wrote .qwen/settings.json', harnesses.write(target))
                self.assertIn(_command('pre_tool_use.py', 'qwen', windows=True), settings.read_text())
                settings.write_text('{"custom":true}\n')
                before = settings.read_bytes()
                with self.assertRaisesRegex(ValueError, 'conflict'):
                    harnesses.write(target)
                self.assertEqual(settings.read_bytes(), before)

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'),
                         'Native Windows PowerShell 5.1 execution requires Windows')
    def test_windows_source_launcher_through_cmd_and_gemini_powershell_contract(self):
        with tempfile.TemporaryDirectory(prefix="source ' Ю ") as directory:
            root = Path(directory)
            self.fixture(root)
            payload = '{"text":"Юникод 😀"}'.encode()
            command = _source_hook_command('probe.py', 'qwen')
            env = {**os.environ, 'PATH': str(ROOT/'bin')+os.pathsep+os.environ['PATH']}
            for key in ('CLAUDE_PROJECT_DIR', 'QWEN_PROJECT_DIR', 'GEMINI_PROJECT_DIR'):
                env.pop(key, None)
            # Qwen's default Windows parent is cmd. Gemini's PowerShell hook
            # runner appends this explicit propagation expression upstream.
            for parent in ([os.environ['COMSPEC'], '/d', '/s', '/c', command],
                           [shutil.which('powershell.exe'), '-NoProfile', '-NonInteractive', '-Command',
                            command+'; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }']):
                with self.subTest(parent=parent[0]):
                    (root/'calls').unlink(missing_ok=True)
                    result = subprocess.run(parent, cwd=root, env=env, input=payload, capture_output=True)
                    self.assertEqual((result.returncode, result.stdout), (2, payload))
                    self.assertEqual((root/'calls').read_text(), '1')
            # A bare -Command is an unsupported manual Qwen override: the
            # native child still runs once with status2, but PS maps it to1.
            (root/'calls').unlink()
            bare = subprocess.run([shutil.which('powershell.exe'), '-NoProfile', '-NonInteractive',
                                   '-Command', command], cwd=root, env=env, input=payload, capture_output=True)
            self.assertEqual((bare.returncode, bare.stdout), (1, payload))
            self.assertEqual((root/'calls').read_text(), '1')

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'),
                         'Native Windows PowerShell 5.1 execution requires Windows')
    def test_windows_deny_runs_once_and_preserves_json_bytes(self):
        with tempfile.TemporaryDirectory(prefix="hook ' Ю ") as directory:
            root = Path(directory)
            self.fixture(root)
            payload = json.dumps({'text': 'Юникод 😀'}, ensure_ascii=False).encode()
            command = _command('probe.py', 'copilot', windows=True)
            for parent in ([os.environ['COMSPEC'], '/d', '/s', '/c', command],
                           [shutil.which('powershell.exe'), '-NoProfile', '-NonInteractive', '-Command',
                            _powershell_command('probe.py', 'copilot')]):
                with self.subTest(parent=parent[0]):
                    (root/'calls').unlink(missing_ok=True)
                    result = subprocess.run(parent, cwd=root, input=payload, capture_output=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, payload)
                    self.assertEqual((root/'calls').read_text(), '1')
                    self.assertEqual(result.stderr, b'policy denied')


if __name__ == '__main__':
    unittest.main()
