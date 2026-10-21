"""Scaffolding is a bounded exclusive write, not a registry mutation."""
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from tests.test_eu_ai_act import ROOT, Repo


class ScaffoldTests(unittest.TestCase):
    def module(self):
        from getzilla import compliance_scaffold
        return compliance_scaffold

    def test_both_languages_and_exclusive_retry(self):
        for lang, name, symbol in (('python', 'ai_transparency.py', 'mark_generated_content'),
                                   ('typescript', 'aiTransparency.ts', 'markGeneratedContent')):
            with self.subTest(lang=lang):
                repo = Repo(self)
                repo.registry({'id': 'bot', 'paths': ['src/bot/**']})
                before = (repo.root / '.getzilla/config/ai-systems.json').read_bytes()
                mod = self.module()
                if mod.fsx.WINDOWS:
                    with self.assertRaisesRegex(mod.ScaffoldError, 'descriptor-relative'):
                        mod.scaffold(repo.root, 'bot', lang)
                    self.assertFalse((repo.root / 'src').exists())
                    continue
                paths = mod.scaffold(repo.root, 'bot', lang)
                self.assertEqual(paths, [repo.root / 'src/bot' / name])
                content = paths[0].read_bytes()
                self.assertIn(symbol.encode(), content)
                with self.assertRaises(mod.ScaffoldError):
                    mod.scaffold(repo.root, 'bot', lang)
                self.assertEqual(paths[0].read_bytes(), content)
                self.assertEqual((repo.root / '.getzilla/config/ai-systems.json').read_bytes(), before)
                self.assertEqual(mod.registry_hints(lang)['marking_symbol'], symbol)

    def test_rejects_unknown_and_unsafe_or_unowned_targets(self):
        repo = Repo(self)
        mod = self.module()
        for paths in ([], ['../escape/*'], ['/tmp/escape/*'], ['src/bot.py'],
                      ['src/bot*/*.py'], ['*/bot.py'], ['src/bot/*.js'], ['src/../bot/*.py'],
                      ['src/bot/?.py'], ['src\\bot\\*.py']):
            with self.subTest(paths=paths):
                repo.registry({'id': 'bot', 'paths': paths})
                with self.assertRaises(mod.ScaffoldError):
                    mod.scaffold(repo.root, 'bot', 'python')
        repo.registry({'id': 'bot', 'paths': ['src/bot/*.py']})
        for system, lang in (('missing', 'python'), ('bot', 'ruby')):
            with self.assertRaises(mod.ScaffoldError):
                mod.scaffold(repo.root, system, lang)
        repo.registry({'id': 'bot', 'paths': ['src/bot/*.py']}, {'id': 'bot', 'paths': ['other/*']})
        with self.assertRaises(mod.ScaffoldError):
            mod.scaffold(repo.root, 'bot', 'python')

    def test_windows_refuses_before_any_creation_or_parent_swap(self):
        repo = Repo(self)
        mod = self.module()
        repo.registry({'id': 'bot', 'paths': ['src/bot/**']})
        with mock.patch.object(mod.fsx, 'WINDOWS', True), \
                mock.patch.object(mod.fsx, 'mkdir_at', wraps=mod.fsx.mkdir_at) as mkdir, \
                mock.patch.object(mod.fsx, 'open_at', wraps=mod.fsx.open_at) as create:
            with self.assertRaisesRegex(mod.ScaffoldError, 'descriptor-relative'):
                mod.scaffold(repo.root, 'bot', 'python')
            mkdir.assert_not_called()
            create.assert_not_called()
        self.assertFalse((repo.root / 'src').exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX emulation of the reviewed Windows parent swap')
    def test_windows_parent_swap_probe_cannot_reach_mutation(self):
        repo = Repo(self)
        outside = Repo(self)
        mod = self.module()
        repo.registry({'id': 'bot', 'paths': ['src/bot/**']})
        original = mod.fsx.open_dir_at

        def swap_after_open(parent, name, **kwargs):
            result = original(parent, name, **kwargs)
            if name == 'src':
                (repo.root / 'src').rename(repo.root / 'src-original')
                (repo.root / 'src').symlink_to(outside.root, target_is_directory=True)
            return result

        with mock.patch.object(mod.fsx, 'WINDOWS', True), \
                mock.patch.object(mod.fsx, 'open_dir_at', side_effect=swap_after_open) as swap:
            with self.assertRaisesRegex(mod.ScaffoldError, 'descriptor-relative'):
                mod.scaffold(repo.root, 'bot', 'python')
            swap.assert_not_called()
        self.assertFalse((outside.root / 'bot').exists())
        self.assertFalse((repo.root / 'src').exists())

    @unittest.skipIf(os.name == 'nt', 'symlink creation needs Windows privilege')
    def test_parent_and_target_links_are_refused(self):
        repo = Repo(self)
        mod = self.module()
        repo.registry({'id': 'bot', 'paths': ['src/bot/*.py']})
        (repo.root / 'outside').mkdir()
        (repo.root / 'src').symlink_to(repo.root / 'outside', target_is_directory=True)
        with self.assertRaises(mod.ScaffoldError):
            mod.scaffold(repo.root, 'bot', 'python')
        self.assertEqual(list((repo.root / 'outside').iterdir()), [])
        (repo.root / 'src').unlink()
        target = repo.root / 'src/bot/ai_transparency.py'
        target.parent.mkdir(parents=True)
        target.symlink_to(repo.root / 'outside/missing')
        with self.assertRaises(mod.ScaffoldError):
            mod.scaffold(repo.root, 'bot', 'python')

    @unittest.skipIf(os.name == 'nt', 'symlink creation needs Windows privilege')
    def test_template_links_are_refused(self):
        repo = Repo(self)
        mod = self.module()
        repo.registry({'id': 'bot', 'paths': ['src/bot/*.py']})
        template_root = repo.root / 'installed/.getzilla'
        template = template_root / 'templates/eu-ai-act/transparency/python/ai_transparency.py'
        template.parent.mkdir(parents=True)
        source = repo.root / 'source.txt'
        source.write_text('private fixture', encoding='utf-8')
        template.symlink_to(source)
        with mock.patch.object(mod, '__file__', str(template_root / 'getzilla/compliance_scaffold.py')):
            with self.assertRaises(mod.ScaffoldError):
                mod.scaffold(repo.root, 'bot', 'python')
        self.assertFalse((repo.root / 'src/bot/ai_transparency.py').exists())

    def test_dispatcher_returns_language_hints_and_leaves_registry_unchanged(self):
        repo = Repo(self)
        repo.registry({'id': 'bot', 'paths': ['src/bot/**']})
        proc = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_cli.py'), 'compliance',
                               'scaffold', '--root', str(repo.root), '--system', 'bot', '--lang', 'typescript'],
                              capture_output=True, text=True, check=False, timeout=30)
        if os.name == 'nt':
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('descriptor-relative', proc.stdout + proc.stderr)
            self.assertFalse((repo.root / 'src').exists())
            return
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertEqual(json.loads(proc.stdout)['registry_hints']['marking_symbol'], 'markGeneratedContent')
