"""Delegated grants name exact resources; wildcard patterns are refused (issue #38)."""
from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.policy import evaluate_pre_tool
from getzilla.router import build_route
from getzilla.state import add_approval, approvals_path, has_valid_approval, set_active_route
from tests._support import project_copy

PATTERNS = ('*', '**', '.grok/**', '.getzilla/*', 'AGENTS.m?', '[A]GENTS.md', 'trust-ci/**/api.py')
CONTROL_PLANE_TARGETS = (
    'AGENTS.md',
    '.grok/hooks/pre_tool_use.py',
    '.getzilla/config/policy.json',
    'trust-ci/src/adaptive_trust_ci/api.py',
)


@contextlib.contextmanager
def github_project() -> Iterator[Path]:
    with project_copy(git=True) as root:
        subprocess.run(
            ['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'],
            cwd=root,
            check=True,
        )
        set_active_route(root, build_route(root, 'Исправить PHP баг', 's1').to_dict())
        yield root


class ApprovalResourceTests(unittest.TestCase):
    def test_protected_path_grant_refuses_patterns(self) -> None:
        with github_project() as root:
            for pattern in PATTERNS:
                with self.subTest(pattern=pattern):
                    with self.assertRaisesRegex(ValueError, 'exact'):
                        add_approval(
                            root, 'protected-path', 'blanket', 5,
                            actions=['protected-path-write'], resources=[pattern],
                        )
            self.assertFalse(approvals_path(root).exists() and json.loads(approvals_path(root).read_text()))

    def test_protected_path_grant_refuses_paths_outside_the_repository(self) -> None:
        with github_project() as root:
            for resource in ('/etc/passwd', '../outside.txt', '.grok/../AGENTS.md'):
                with self.subTest(resource=resource):
                    with self.assertRaisesRegex(ValueError, 'repository-relative'):
                        add_approval(
                            root, 'protected-path', 'edit', 5,
                            actions=['protected-path-write'], resources=[resource],
                        )

    def test_external_write_grant_refuses_patterns_without_route_gate(self) -> None:
        with github_project() as root:
            with self.assertRaisesRegex(ValueError, 'exact'):
                add_approval(
                    root, 'external-write', 'issues', 5,
                    actions=['external-write'], resources=['https://api.github.com/repos/Dimkox/Getzilla/*'],
                )

    def test_stored_pattern_grant_does_not_authorize_control_plane_writes(self) -> None:
        with github_project() as root:
            approval = add_approval(
                root, 'protected-path', 'one file', 5,
                actions=['protected-path-write'], resources=['AGENTS.md'],
            )
            approval['resources'] = ['*']
            approvals_path(root).write_text(json.dumps([approval]), encoding='utf-8')
            for target in CONTROL_PLANE_TARGETS:
                with self.subTest(target=target):
                    self.assertFalse(
                        has_valid_approval(root, 'protected-path', action='protected-path-write', resource=target)
                    )
                    allowed, _ = evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'path': target}})
                    self.assertFalse(allowed, target)

    def test_exact_grant_authorizes_only_its_path(self) -> None:
        with github_project() as root:
            add_approval(
                root, 'protected-path', 'one file', 5,
                actions=['protected-path-write'], resources=['./AGENTS.md'],
            )
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'path': 'AGENTS.md'}})
            self.assertTrue(allowed, reason)
            allowed, _ = evaluate_pre_tool(
                root, {'tool_name': 'Edit', 'tool_input': {'path': '.grok/hooks/pre_tool_use.py'}},
            )
            self.assertFalse(allowed)

    def test_cli_refuses_wildcard_resource_without_traceback(self) -> None:
        with github_project() as root:
            proc = subprocess.run(
                [
                    sys.executable, str(ROOT / 'scripts/getzilla_approve.py'), 'protected-path',
                    '--action', 'protected-path-write', '--resource', '*', '--reason', 'blanket',
                ],
                cwd=root, text=True, capture_output=True, check=False,
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn('exact', proc.stderr)
            self.assertNotIn('Traceback', proc.stderr)
            self.assertFalse(approvals_path(root).exists() and json.loads(approvals_path(root).read_text()))


if __name__ == '__main__':
    unittest.main()
