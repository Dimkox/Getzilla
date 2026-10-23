"""A protected-path grant must survive edits to its own file and nothing else."""
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

from getzilla.router import build_route
from getzilla.state import add_approval, approvals_path, has_valid_approval, set_active_route
from tests._support import project_copy

TARGET = 'tests/test_cpu_capacity.py'


@contextlib.contextmanager
def github_project() -> Iterator[Path]:
    with project_copy(git=True) as root:
        subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'],
                       cwd=root, check=True)
        set_active_route(root, build_route(root, 'Fix startup CPU regression test', 's1').to_dict())
        yield root


def valid(root: Path, scope: str = 'protected-path', resource: str | None = TARGET) -> bool:
    action = 'protected-path-write' if scope == 'protected-path' else 'git-push-branch'
    return has_valid_approval(root, scope, action=action, resource=resource)


class GrantLifecycleTests(unittest.TestCase):
    def test_grant_survives_repeated_writes_to_its_own_file(self) -> None:
        with github_project() as root:
            add_approval(root, 'protected-path', 'TDD on one test', 15,
                         actions=['protected-path-write'], resources=[TARGET])
            target = root / TARGET
            target.parent.mkdir(parents=True, exist_ok=True)
            for content in ('# red\n', '# red plus assertion\n', '# green\n'):
                target.write_text(content, encoding='utf-8')
                self.assertTrue(valid(root), content)

    def test_any_other_tree_change_still_invalidates(self) -> None:
        with github_project() as root:
            add_approval(root, 'protected-path', 'TDD on one test', 15,
                         actions=['protected-path-write'], resources=[TARGET])
            (root / 'AGENTS.md').write_text('changed\n', encoding='utf-8')
            self.assertFalse(valid(root))

    def test_commit_inside_granted_file_set_retains_approval(self) -> None:
        with github_project() as root:
            add_approval(root, 'protected-path', 'TDD on one test', 15,
                         actions=['protected-path-write'], resources=[TARGET])
            (root / TARGET).parent.mkdir(parents=True, exist_ok=True)
            (root / TARGET).write_text('# test\n', encoding='utf-8')
            subprocess.run(['git', 'add', TARGET], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'test'], cwd=root, check=True)
            self.assertTrue(valid(root))

    def test_other_scopes_keep_exact_tree_binding(self) -> None:
        with github_project() as root:
            approval = add_approval(root, 'production', 'push', 15, actions=['git-push-branch'])
            self.assertNotIn('binding', approval)
            self.assertTrue(valid(root, 'production', None))
            (root / TARGET).parent.mkdir(parents=True, exist_ok=True)
            (root / TARGET).write_text('# any change\n', encoding='utf-8')
            self.assertFalse(valid(root, 'production', None))

    def test_relaxed_binding_cannot_be_forged_onto_another_scope(self) -> None:
        with github_project() as root:
            approval = add_approval(root, 'production', 'push', 15, actions=['git-push-branch'])
            approval['binding'] = 'tree-except-granted-resources'
            approval['resources'] = [TARGET]
            approvals_path(root).write_text(json.dumps([approval]), encoding='utf-8')
            self.assertFalse(valid(root, 'production', None))

    def test_legacy_grant_without_binding_keeps_exact_tree(self) -> None:
        with github_project() as root:
            approval = add_approval(root, 'protected-path', 'one file', 15,
                                    actions=['protected-path-write'], resources=[TARGET])
            approval.pop('binding')
            approvals_path(root).write_text(json.dumps([approval]), encoding='utf-8')
            self.assertTrue(valid(root))
            (root / TARGET).parent.mkdir(parents=True, exist_ok=True)
            (root / TARGET).write_text('# write\n', encoding='utf-8')
            self.assertFalse(valid(root))


if __name__ == '__main__':
    unittest.main()
