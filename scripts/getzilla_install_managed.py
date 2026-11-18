#!/usr/bin/env python3
"""Installer-owned current software activation; no project dependency mutation."""
from __future__ import annotations

import argparse
import json
import os
import sys
import subprocess
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))

from getzilla.managed_environment import failure_details, install_environment
from getzilla.updater import _release_fetch, home_dir


def main(argv=None):
    original_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--environment-only', action='store_true')
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--home', type=Path, default=ROOT)
    parser.add_argument('--agent', choices=('qwen', 'codex', 'claude', 'gemini', 'copilot', 'grok'))
    parser.add_argument('--tool', action='append', default=[])
    parser.add_argument('--result', type=Path)
    args = parser.parse_args(original_argv)
    try:
        if args.environment_only:
            from getzilla.managed_software import ensure_python
            python = ensure_python(home_dir(), fetch=_release_fetch)
            if sys.version_info < (3, 11):
                # The supported 3.10 bootstrap must leave before importing the
                # selected runtime's tomllib-dependent pure-build helper.
                selected = Path(python)
                if not selected.is_absolute() or not selected.is_file():
                    raise ValueError('fresh selected Python handoff path is unavailable')
                selected = selected.resolve(strict=True)
                if selected.samefile(sys.executable):
                    raise ValueError('fresh selected Python still has the old bootstrap identity')
                os.execv(str(selected), [str(selected), '-I', '-B', str(Path(__file__).resolve()), *original_argv])
                raise ValueError('selected Python process replacement did not complete')
            executable = install_environment(args.home, str(python), fetch=_release_fetch)
            result = dict(status='complete', python=str(executable), detail='exact current quality wheel closure verified')
        else:
            from getzilla.managed_software import install_software
            result = install_software(home_dir(), args.home, agent=args.agent, tools=args.tool, verify_only=args.verify_only)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        result = dict(status='incomplete', error=str(exc))
        diagnostic = failure_details(exc)
        if diagnostic is not None:
            result['diagnostic'] = diagnostic
    if args.result:
        from getzilla.updater import _replace_bytes
        _replace_bytes(args.result, (json.dumps(result, indent=2)+'\n').encode(), mode=0o600)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
