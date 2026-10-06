#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

from change_spec_validate import validate as validate_change_specs


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def text(root: Path, rel: str) -> str:
    path = root / rel
    require(path.is_file(), f'missing required file: {rel}')
    return path.read_text(encoding='utf-8')


def parse(root: Path, rel: str) -> ast.AST:
    try:
        return ast.parse(text(root, rel), filename=rel)
    except SyntaxError as exc:
        raise SystemExit(f'invalid Python in {rel}: {exc}') from exc


USES = re.compile(r'^\s*(?:-\s*)?uses:\s*(\S+)', re.MULTILINE)
PINNED = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$')
FORBIDDEN_WORKFLOW_TEXT = (
    'pull_request_target',
    'workflow_dispatch',
    'repository_dispatch',
    'secrets.',
    'write-all',
    ': write',
)


def validate_workflows(root: Path) -> None:
    workflows = root / '.github' / 'workflows'
    if not workflows.exists():
        return
    require(workflows.is_dir() and not workflows.is_symlink(), '.github/workflows must be a real directory')
    files = sorted(workflows.iterdir())
    require(bool(files), '.github/workflows is empty')
    for path in files:
        rel = path.relative_to(root).as_posix()
        require(path.is_file() and not path.is_symlink(), f'{rel} must be a regular file')
        require(path.suffix in {'.yml', '.yaml'}, f'{rel} is not a workflow file')
        source = path.read_text(encoding='utf-8')
        require(re.search(r'^permissions:\s*\n\s+contents:\s*read\s*$', source, re.MULTILINE) is not None,
                f'{rel} must declare top-level permissions contents: read')
        for needle in FORBIDDEN_WORKFLOW_TEXT:
            require(needle not in source, f'{rel} must not use {needle!r}')
        references = USES.findall(source)
        require(bool(references), f'{rel} has no pinned actions')
        for reference in references:
            require(PINNED.match(reference) is not None, f'{rel} must pin {reference} to a full commit SHA')
        require('persist-credentials: false' in source, f'{rel} must check out without persisted credentials')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('workspace', type=Path)
    args = parser.parse_args()
    root = args.workspace.resolve()
    require(root.is_dir(), 'workspace is not a directory')
    validate_change_specs(root)

    validate_workflows(root)

    approve = text(root, 'scripts/getzilla_approve.py')
    require('external_trust_ci_authority' in approve, 'local approval CLI must disclaim Trust CI authority')
    state = text(root, '.getzilla/getzilla/state.py')
    require("'git_head'" in state, 'delegated grant must bind git_head')
    require("'tree_fingerprint'" in state, 'delegated grant must bind tree fingerprint')

    api_source = text(root, 'trust-ci/src/adaptive_trust_ci/api.py')
    require('GitHubClient' not in api_source, 'webhook API must not hold GitHub publishing authority')
    require('GitHubAppAuth' not in api_source, 'webhook API must not hold the GitHub App key')

    worker_source = text(root, 'trust-ci/src/adaptive_trust_ci/worker.py')
    require('GitHubAppAuth' in worker_source, 'worker must use GitHub App authentication')
    github_source = text(root, 'trust-ci/src/adaptive_trust_ci/github.py')
    require("'checks': [{'context': status_context, 'app_id': app_id}]" in github_source, 'branch protection must bind context to app_id')

    policy_source = text(root, '.getzilla/getzilla/policy.py')
    require('workflow-dispatch' in policy_source and 'forbidden' in policy_source.lower(), 'workflow dispatch must be forbidden')

    for rel in (
        '.getzilla/getzilla/state.py',
        '.getzilla/getzilla/policy.py',
        'trust-ci/src/adaptive_trust_ci/api.py',
        'trust-ci/src/adaptive_trust_ci/worker.py',
        'trust-ci/src/adaptive_trust_ci/runner.py',
    ):
        parse(root, rel)

    print('external holdout validation: PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
