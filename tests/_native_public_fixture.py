"""Opt-in ordinary public Git fixtures for the strict native read graph.

No production graph or admission rule is changed. Maintenance settings stay
command-scoped; the stored configuration contains only admitted public keys.
"""
import os
import subprocess
from pathlib import Path
from contextlib import contextmanager

from tests._support import project_copy as ordinary_project_copy


@contextmanager
def project_copy(*,git=False,minimal_runtime=False):
    previous = os.umask(0o022)
    try:
        with ordinary_project_copy(git=False,minimal_runtime=minimal_runtime) as root:
            # The owned public fixture must not inherit a developer worktree's
            # group-writable directory modes from copytree.
            for directory, _, _ in os.walk(root):
                path = Path(directory)
                path.chmod(path.stat().st_mode & ~0o022)
            if git:
                commands = (['init','-q'],['config','user.name','Test'],
                            ['config','user.email','test@example.invalid'],['add','.'],
                            ['-c','maintenance.auto=false','-c','gc.auto=0','commit','-qm','initial'])
                for arguments in commands:
                    subprocess.run(['git',*arguments],cwd=root,check=True,capture_output=True)
            yield root
    finally:
        os.umask(previous)
