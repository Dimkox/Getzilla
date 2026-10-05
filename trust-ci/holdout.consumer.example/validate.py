#!/usr/bin/env python3
"""External holdout for any repository with Getzilla installed.

Used by a Trust CI owner profile, so it checks only what every Getzilla
consumer installation carries: the change-spec contract, the local approval
disclaimer, delegated-grant binding and the GitHub Actions ban. Repository
specific holdouts (for example Getzilla's own) belong in exact profiles.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

from change_spec_validate import validate as validate_change_specs


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def text(root: Path, rel: str) -> str:
    path = root / rel
    require(path.is_file() and not path.is_symlink(), f'missing required Getzilla file: {rel}')
    return path.read_text(encoding='utf-8')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('workspace', type=Path)
    args = parser.parse_args()
    root = args.workspace.resolve()
    require(root.is_dir(), 'workspace is not a directory')
    require((root / '.getzilla/getzilla').is_dir(), 'Getzilla is not installed in this repository')
    validate_change_specs(root)

    require(not (root / '.github' / 'workflows').exists(), 'GitHub Actions workflows are forbidden')

    approve = text(root, 'scripts/getzilla_approve.py')
    require('external_trust_ci_authority' in approve, 'local approval CLI must disclaim Trust CI authority')
    state = text(root, '.getzilla/getzilla/state.py')
    require("'git_head'" in state, 'delegated grant must bind git_head')
    require("'tree_fingerprint'" in state, 'delegated grant must bind tree fingerprint')
    policy_source = text(root, '.getzilla/getzilla/policy.py')
    require('workflow-dispatch' in policy_source and 'forbidden' in policy_source.lower(), 'workflow dispatch must be forbidden')
    text(root, 'scripts/getzilla_verify.py')

    for rel in ('.getzilla/getzilla/state.py', '.getzilla/getzilla/policy.py', 'scripts/getzilla_verify.py'):
        try:
            ast.parse(text(root, rel), filename=rel)
        except SyntaxError as exc:
            raise SystemExit(f'invalid Python in {rel}: {exc}') from exc

    print('external consumer holdout validation: PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
