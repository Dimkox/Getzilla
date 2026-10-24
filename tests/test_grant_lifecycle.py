"""A protected-path grant must survive edits to its own file and nothing else."""
from __future__ import annotations

import contextlib
import json
import os
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

    def test_initial_dirty_bytes_cannot_mask_a_new_outside_scope_commit(self) -> None:
        from tests.branch_support import git
        with github_project() as root:
            outside = root / 'outside.py'
            outside.write_text('base\n')
            git(root, 'add', 'outside.py')
            git(root, 'commit', '-qm', 'outside baseline')
            outside.write_text('initial dirty bytes\n')
            add_approval(root, 'protected-path', 'one file', 15,
                         actions=['protected-path-write'], resources=[TARGET])
            self.assertTrue(valid(root))
            outside.write_text('unapproved committed bytes\n')
            git(root, 'add', 'outside.py')
            git(root, 'commit', '-qm', 'outside change')
            outside.write_text('initial dirty bytes\n')
            self.assertFalse(valid(root), 'worktree must not mask different HEAD bytes')

    def test_initial_dirty_bytes_cannot_mask_a_new_outside_scope_index_blob(self) -> None:
        from tests.branch_support import git
        with github_project() as root:
            outside = root / 'outside.py'
            outside.write_text('base\n')
            git(root, 'add', 'outside.py')
            git(root, 'commit', '-qm', 'outside baseline')
            outside.write_text('initial staged bytes\n')
            git(root, 'add', 'outside.py')
            outside.write_text('initial dirty bytes\n')
            add_approval(root, 'protected-path', 'one file', 15,
                         actions=['protected-path-write'], resources=[TARGET])
            self.assertTrue(valid(root))
            # Unchanged pre-existing index and worktree dirt survives approved commits.
            target = root / TARGET
            target.parent.mkdir(parents=True, exist_ok=True)
            for number in range(2):
                target.write_text(f'# approved {number}\n')
                git(root, 'add', TARGET)
                git(root, 'commit', '-qm', 'approved change', '--only', TARGET)
                self.assertTrue(valid(root))
            outside.write_text('unapproved staged bytes\n')
            git(root, 'add', 'outside.py')
            outside.write_text('initial dirty bytes\n')
            self.assertFalse(valid(root), 'worktree must not mask different index bytes')

    @unittest.skipIf(os.name == 'nt', 'Windows treats backslashes as path separators')
    def test_literal_git_backslash_names_are_outside_exact_resources_in_every_layer(self) -> None:
        from tests.branch_support import git
        for layer in ('untracked', 'index', 'committed'):
            with self.subTest(layer=layer), github_project() as root:
                literal = TARGET.replace('/', '\\')
                outside = root / literal
                if layer != 'untracked':
                    outside.write_text('initial dirty bytes\n')
                anchor = git(root, 'rev-parse', 'HEAD')
                add_approval(root, 'protected-path', 'one exact file', 15,
                             actions=['protected-path-write'], resources=[TARGET])
                target = root / TARGET
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('# approved file\n')
                self.assertTrue(valid(root))
                git(root, 'add', '--', TARGET)
                git(root, 'commit', '-qm', 'approved file')
                self.assertTrue(valid(root))
                outside.write_text('outside exact resource\n')
                if layer != 'untracked':
                    git(root, 'add', '--', literal)
                if layer == 'committed':
                    git(root, 'commit', '-qm', 'outside literal filename')
                    # Isolate HEAD identity from the index and worktree layers.
                    git(root, 'restore', '--source', anchor, '--staged', '--', literal)
                if layer != 'untracked':
                    outside.write_text('initial dirty bytes\n')
                self.assertFalse(valid(root), f'{layer} Git names must retain literal backslashes')

    def test_a_new_route_keeps_a_branch_bound_grant_but_not_a_production_grant(self) -> None:
        with github_project() as root:
            add_approval(root, 'protected-path', 'one file', 15,
                         actions=['protected-path-write'], resources=[TARGET])
            add_approval(root, 'production', 'push', 15, actions=['git-push-branch'])
            set_active_route(root, build_route(root, 'Next prompt about something else', 's1').to_dict())
            self.assertTrue(valid(root))
            self.assertFalse(valid(root, 'production', None))

    def test_a_route_of_another_session_voids_the_grant(self) -> None:
        with github_project() as root:
            add_approval(root, 'protected-path', 'one file', 15,
                         actions=['protected-path-write'], resources=[TARGET])
            set_active_route(root, build_route(root, 'Another session prompt', 's2').to_dict())
            self.assertFalse(valid(root))

    def test_without_a_known_session_the_exact_route_is_still_required(self) -> None:
        with github_project() as root:
            approval = add_approval(root, 'protected-path', 'one file', 15,
                                    actions=['protected-path-write'], resources=[TARGET])
            approval.pop('session_id')
            approvals_path(root).write_text(json.dumps([approval]), encoding='utf-8')
            self.assertTrue(valid(root))
            set_active_route(root, build_route(root, 'Next prompt', 's1').to_dict())
            self.assertFalse(valid(root))

    def test_a_new_change_package_still_voids_a_branch_bound_grant(self) -> None:
        from getzilla.state import set_active_change
        with github_project() as root:
            add_approval(root, 'protected-path', 'one file', 15,
                         actions=['protected-path-write'], resources=[TARGET])
            self.assertTrue(valid(root))
            set_active_change(root, {'change_id': 'another-change'})
            self.assertFalse(valid(root))

    def test_a_forged_branch_binding_on_a_production_grant_keeps_the_route_check(self) -> None:
        with github_project() as root:
            # A complete branch-bound record relabelled as production, from another route.
            approval = add_approval(root, 'protected-path', 'one file', 15,
                                    actions=['protected-path-write'], resources=[TARGET])
            approval.update(scope='production', actions=['git-push-branch'], route_id='some-other-route')
            approvals_path(root).write_text(json.dumps([approval]), encoding='utf-8')
            self.assertFalse(valid(root, 'production', None))

    def test_a_branch_change_still_voids_the_grant_after_a_new_route(self) -> None:
        from tests.branch_support import git
        with github_project() as root:
            add_approval(root, 'protected-path', 'one file', 15,
                         actions=['protected-path-write'], resources=[TARGET])
            set_active_route(root, build_route(root, 'Next prompt', 's1').to_dict())
            git(root, 'checkout', '-q', '-b', 'other-branch')
            self.assertFalse(valid(root))

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
            approval.pop('git_branch')
            approval.pop('anchor_commit')
            from getzilla.util import tree_fingerprint
            approval['grant_binding_digest'] = tree_fingerprint(root)
            approvals_path(root).write_text(json.dumps([approval]), encoding='utf-8')
            self.assertTrue(valid(root))
            (root / TARGET).parent.mkdir(parents=True, exist_ok=True)
            (root / TARGET).write_text('# write\n', encoding='utf-8')
            self.assertFalse(valid(root))


if __name__ == '__main__':
    unittest.main()
