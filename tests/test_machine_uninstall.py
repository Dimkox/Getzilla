"""Helpers for the machine uninstaller: .getzilla/getzilla/machine_uninstall.py."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import machine_uninstall as mu  # noqa: E402

PATH_LINES = '\n# Getzilla: tools in ~/.getzilla/bin\nexport PATH="$HOME/.getzilla/bin:$PATH"\n'


class MachineUninstallHelpersTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.temp, True)

    def checkout(self) -> Path:
        home = self.temp / 'Getzilla'
        (home / 'scripts').mkdir(parents=True)
        (home / 'scripts/getzilla_cli.py').write_text('', encoding='utf-8')
        (home / '.getzilla/getzilla').mkdir(parents=True)
        return home

    def test_checkout_detection(self) -> None:
        self.assertTrue(mu.is_checkout(self.checkout()))
        self.assertFalse(mu.is_checkout(self.temp))

    def test_unsafe_targets(self) -> None:
        user = self.temp / 'user'
        user.mkdir()
        self.assertTrue(mu.unsafe_target(user, user))
        self.assertTrue(mu.unsafe_target(self.temp, user))
        self.assertTrue(mu.unsafe_target(Path(user.anchor), user))
        self.assertFalse(mu.unsafe_target(user / '.getzilla', user))

    def test_path_block_is_removed_and_other_lines_stay(self) -> None:
        profile = self.temp / '.bashrc'
        profile.write_text('alias ll="ls -l"\n' + PATH_LINES + 'export EDITOR=vi\n', encoding='utf-8')
        self.assertTrue(mu.strip_path_block(profile, apply=False))
        self.assertIn(mu.PATH_MARKER, profile.read_text(encoding='utf-8'))
        self.assertTrue(mu.strip_path_block(profile, apply=True))
        self.assertEqual(profile.read_text(encoding='utf-8'), 'alias ll="ls -l"\nexport EDITOR=vi\n')
        self.assertFalse(mu.strip_path_block(profile, apply=True))
        self.assertFalse(mu.strip_path_block(self.temp / 'missing', apply=True))

    def test_only_the_link_into_this_checkout_is_owned(self) -> None:
        home = self.checkout()
        link = self.temp / 'getzilla'
        link.symlink_to(home / 'bin' / 'getzilla')
        self.assertTrue(mu.owned_link(link, home))
        self.assertFalse(mu.owned_link(link, self.temp / 'other'))
        self.assertFalse(mu.owned_link(self.temp / 'missing', home))

    def test_path_entries_inside_roots(self) -> None:
        root = self.temp / 'Getzilla'
        self.assertTrue(mu.inside(str(root / 'bin'), [root]))
        self.assertTrue(mu.inside(str(root), [root]))
        self.assertFalse(mu.inside(str(self.temp / 'Getzilla2'), [root]))

    def test_dirty_files(self) -> None:
        home = self.checkout()
        self.assertEqual(mu.dirty_files(home), [])
        if not shutil.which('git'):
            self.skipTest('git is missing')
        git = ['git', '-C', str(home), '-c', 'user.name=t', '-c', 'user.email=t@t']
        subprocess.run([*git, 'init', '-q'], check=True)
        subprocess.run([*git, 'add', '-A'], check=True)
        subprocess.run([*git, 'commit', '-qm', 'x'], check=True)
        self.assertEqual(mu.dirty_files(home), [])
        (home / 'scripts/getzilla_cli.py').write_text('edit\n', encoding='utf-8')
        self.assertEqual(len(mu.dirty_files(home)), 1)

    def test_remove_tree_handles_read_only_files(self) -> None:
        folder = self.temp / 'tree'
        (folder / 'sub').mkdir(parents=True)
        (folder / 'sub/file').write_text('x', encoding='utf-8')
        os.chmod(folder / 'sub/file', 0o444)
        mu.remove_tree(folder)
        self.assertFalse(folder.exists())


if __name__ == '__main__':
    unittest.main()
