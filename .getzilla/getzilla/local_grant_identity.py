"""Physical local Git identity for delegated grants, never remote authority."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

PREFIX = 'local-git-v1:'


def repository_identity(root: Path) -> str:
    # Lazy existing Git registration proof avoids a state/architecture import cycle.
    from .architecture import ArchitectureError
    from .architecture_diff import _git_binding, _git_command, _git_environment, _run_capped
    from .fsx import _identity

    try:
        binding = _git_binding(root)
        code, output, _error = _run_capped(
            _git_command(['config', '--get-all', 'remote.origin.url'],
                         safe_directory=binding.root, git_directory=binding.git_directory),
            cwd=binding.root, env=_git_environment(), stdout_limit=16_384,
            stderr_limit=4096, timeout=30)
        # Git config exit1 and no output means absent. Empty/multiple values and
        # command errors must not become a local grant identity.
        if code != 1 or output:
            raise RuntimeError('local grants require a genuinely absent origin')
        directories = []
        for path in (binding.root, binding.git_directory, binding.common_directory):
            if path is None:
                raise RuntimeError('local Git physical identity unavailable')
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or not info.st_ino:
                raise RuntimeError('local Git physical identity unavailable')
            directories.append([os.path.normcase(str(path)), list(_identity(info))])
        binding.verify()
        body = json.dumps({'version': 1, 'directories': directories},
                          sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        return PREFIX+hashlib.sha256(body).hexdigest()
    except (ArchitectureError, OSError, ValueError) as exc:
        raise RuntimeError('local Git physical identity unavailable') from exc
