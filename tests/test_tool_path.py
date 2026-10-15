"""Tools installed into per-user directories must be found without a login PATH (bare install)."""
from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import util


def _tool(directory: Path, name: str, output: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == 'nt':
        path = directory / f'{name}.cmd'
        path.write_text(f'@echo {output}\r\n', encoding='utf-8')
    else:
        path = directory / name
        path.write_text(f'#!/bin/sh\necho {output}\n', encoding='utf-8')
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class ToolPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.home = base / 'home'
        self.system = base / 'system-bin'
        self.system.mkdir(parents=True)
        system_path = os.pathsep.join([str(self.system), os.path.dirname(sys.executable)])
        patches = [mock.patch.dict(os.environ, {'PATH': system_path, 'HOME': str(self.home),
                                                'USERPROFILE': str(self.home)}),
                   mock.patch.object(util.Path, 'home', return_value=self.home)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_user_tool_is_found_and_runs_without_login_path(self) -> None:
        _tool(self.home / '.local' / 'bin', 'gz-fake-ruff', 'user-ruff')
        self.assertTrue(util.command_exists('gz-fake-ruff'))
        proc = util.run(['gz-fake-ruff'], cwd=Path(self.tmp.name), timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), 'user-ruff')

    def test_getzilla_bin_is_searched(self) -> None:
        _tool(self.home / '.getzilla' / 'bin', 'gz-fake-opengrep', 'og')
        self.assertIsNotNone(util.find_tool('gz-fake-opengrep'))

    def test_path_entries_keep_priority_over_user_dirs(self) -> None:
        system_tool = _tool(self.system, 'gz-fake-tool', 'system')
        _tool(self.home / '.local' / 'bin', 'gz-fake-tool', 'user')
        self.assertEqual(Path(util.find_tool('gz-fake-tool')).parent, system_tool.parent)

    def test_missing_dirs_are_not_added_and_entries_are_not_duplicated(self) -> None:
        (self.home / '.local' / 'bin').mkdir(parents=True)
        path = util.tool_search_path()
        entries = path.split(os.pathsep)
        self.assertNotIn(str(self.home / '.getzilla' / 'bin'), entries)
        self.assertEqual(entries.count(str(self.home / '.local' / 'bin')), 1)
        self.assertEqual(util.tool_search_path(path), path)

    def test_explicit_path_in_env_stays_isolated(self) -> None:
        _tool(self.home / '.local' / 'bin', 'gz-fake-ruff', 'user-ruff')
        proc = util.run(['gz-fake-ruff'], cwd=Path(self.tmp.name), timeout=30,
                        env={'PATH': str(self.system)})
        self.assertNotEqual(proc.returncode, 0)


if __name__ == '__main__':
    unittest.main()
