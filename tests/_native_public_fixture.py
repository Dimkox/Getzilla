"""Opt-in ordinary public Git fixtures for the strict native read graph.

No production graph or admission rule is changed. Maintenance settings stay
command-scoped; the stored configuration contains only admitted public keys.
"""
import os
import subprocess
from contextlib import contextmanager

from tests._support import project_copy as ordinary_project_copy


@contextmanager
def project_copy(*,git=False,minimal_runtime=False):
    previous = os.umask(0o022)
    try:
        with ordinary_project_copy(git=False,minimal_runtime=minimal_runtime) as root:
            if git:
                commands = (['init','-q'],['config','user.name','Test'],
                            ['config','user.email','test@example.invalid'],['add','.'],
                            ['-c','maintenance.auto=false','-c','gc.auto=0','commit','-qm','initial'])
                for arguments in commands:
                    subprocess.run(['git',*arguments],cwd=root,check=True,capture_output=True)
            yield root
    finally:
        os.umask(previous)
