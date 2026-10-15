"""Getzilla's own environment: resolution order and the verify re-exec guard."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import interpreter


def make_venv(home: Path) -> Path:
    python = home / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    python.parent.mkdir(parents=True)
    python.write_text('', encoding='utf-8')
    return python


class InterpreterTests(unittest.TestCase):
    def test_checkout_venv_wins_then_getzilla_home_then_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            checkout, home, user = base / 'checkout', base / 'home', base / 'user'
            for path in (checkout, home, user / 'Getzilla'):
                path.mkdir(parents=True)
            with mock.patch.dict(os.environ, {'GETZILLA_HOME': str(home)}), \
                    mock.patch.object(interpreter.Path, 'home', return_value=user):
                self.assertEqual(interpreter.project_python(checkout), sys.executable)
                default = make_venv(user / 'Getzilla')
                self.assertEqual(interpreter.project_python(checkout), str(default))
                configured = make_venv(home)
                self.assertEqual(interpreter.project_python(checkout), str(configured))
                own = make_venv(checkout)
                self.assertEqual(interpreter.project_python(checkout), str(own))

    def test_reexec_is_skipped_without_venv_when_opted_out_or_already_inside(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(interpreter.subprocess, 'run') as run:
            checkout = Path(tmp)
            with mock.patch.dict(os.environ, {'GETZILLA_HOME': tmp}), \
                    mock.patch.object(interpreter.Path, 'home', return_value=checkout / 'nobody'):
                interpreter.reexec_in_project_venv(checkout)
                make_venv(checkout)
                with mock.patch.dict(os.environ, {interpreter.OPT_OUT: '1'}):
                    interpreter.reexec_in_project_venv(checkout)
                with mock.patch.object(interpreter, 'running_in', return_value=True):
                    interpreter.reexec_in_project_venv(checkout)
            run.assert_not_called()

    def test_reexec_runs_the_same_script_under_the_venv_and_exits_with_its_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp)
            python = make_venv(checkout)
            completed = mock.Mock(returncode=7)
            with mock.patch.object(interpreter.subprocess, 'run', return_value=completed) as run, \
                    mock.patch.object(interpreter.sys, 'argv', ['scripts/getzilla_verify.py', '--mode', 'pr']), \
                    mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop(interpreter.OPT_OUT, None)
                with self.assertRaises(SystemExit) as stop:
                    interpreter.reexec_in_project_venv(checkout)
            self.assertEqual(stop.exception.code, 7)
            argv = run.call_args.args[0]
            self.assertEqual(argv[0], str(python))
            self.assertEqual(argv[2:], ['--mode', 'pr'])
            self.assertEqual(run.call_args.kwargs['env'][interpreter.OPT_OUT], '1')


if __name__ == '__main__':
    unittest.main()
