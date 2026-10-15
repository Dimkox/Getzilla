"""Getzilla's own Python environment (.venv) holding the pinned test and quality tools.

The installers create <GETZILLA_HOME>/.venv. Tools that need coverage, pytest-xdist, ruff or
bandit "with this Python" run under that interpreter when it exists.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

VENV = '.venv'
OPT_OUT = 'GETZILLA_NO_VENV'


def venv_python(home: Path) -> Path | None:
    candidate = home / VENV / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    return candidate if candidate.is_file() else None


def candidate_homes(script_root: Path) -> list[Path]:
    """Where to look for the environment: this checkout, $GETZILLA_HOME, then the default home."""
    homes = [script_root]
    if os.environ.get('GETZILLA_HOME'):
        homes.append(Path(os.environ['GETZILLA_HOME']))
    homes.append(Path.home() / 'Getzilla')
    return homes


def project_python(script_root: Path) -> str:
    for home in candidate_homes(script_root):
        found = venv_python(home)
        if found is not None:
            return str(found)
    return sys.executable


def running_in(python: str) -> bool:
    # Compare environment directories: a venv's python is a symlink to the base interpreter.
    try:
        return Path(sys.prefix).resolve() == Path(python).parent.parent.resolve()
    except OSError:
        return False


def reexec_in_project_venv(script_root: Path) -> None:
    """Run this script again under Getzilla's environment when it exists and is not this one."""
    if os.environ.get(OPT_OUT) == '1':
        return
    python = project_python(script_root)
    if python == sys.executable or running_in(python):
        return
    environment = {**os.environ, OPT_OUT: '1'}
    proc = subprocess.run([python, os.path.abspath(sys.argv[0]), *sys.argv[1:]], env=environment, check=False)
    sys.exit(proc.returncode)
