"""#75: planning a migration from the earlier factory preserves requirements, evidence and consumer policy."""
from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_into_migration', ROOT / 'scripts/install_into.py')
install_into = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = install_into
spec.loader.exec_module(install_into)

CONSUMER = {
    'AGENTS.md': '# Consumer rules\nKeep the CI policy below.\n',
    '.github/workflows/ci.yml': 'name: consumer-ci\non: [pull_request]\n',
    'src/app.py': 'print(1)\n',
}
UNTRACKED = {
    'factory/src/adaptive_factory.egg-info/PKG-INFO': ('generated-metadata', 'Name: adaptive-factory\n'),
    'client-consent.factory.json': ('requirements', '{"requirements": []}\n'),
    '_bmad-output/client-consent.factory.json': ('requirements', '{"requirements": []}\n'),
    'docs/test-evidence/claw/af2554/summary.json': ('evidence', '{"ok": true}\n'),
    '.qwen/drafts/pr.md': ('agent-scratch', 'draft\n'),
    '.grok-stack/AGBP_SYNC.json': ('legacy-installation', '{}\n'),
    'notes/todo.md': ('user-change', 'mine\n'),
}


def digest_tree(root: Path) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob('*')) if path.is_file() and '.git' not in path.relative_to(root).parts}


class MigrationPlanTests(unittest.TestCase):
    def test_plan_classifies_and_preserves_every_untracked_path_and_changes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'consumer'
            for rel, content in CONSUMER.items():
                (target / rel).parent.mkdir(parents=True, exist_ok=True)
                (target / rel).write_text(content, encoding='utf-8')
            subprocess.run(['git', 'init', '-q'], cwd=target, check=True)
            subprocess.run(['git', 'add', '-A'], cwd=target, check=True)
            subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'consumer'], cwd=target, check=True)
            for rel, (_kind, content) in UNTRACKED.items():
                (target / rel).parent.mkdir(parents=True, exist_ok=True)
                (target / rel).write_text(content, encoding='utf-8')
            before = digest_tree(target)
            plan = install_into._make_plan(ROOT, target, include_dependencies=False, include_optional=False)
            self.assertEqual(digest_tree(target), before, 'planning is read-only, even on a dirty tree')
            report = {item['path']: item for item in plan['existing_untracked']}
            self.assertFalse(plan['existing_untracked_truncated'])
            for rel, (kind, _content) in UNTRACKED.items():
                with self.subTest(path=rel):
                    self.assertEqual(report[rel]['class'], kind)
                    self.assertEqual(report[rel]['action'], 'PRESERVE')
            # Tracked consumer policy is not untracked work, and the plan never offers to delete anything.
            self.assertNotIn('AGENTS.md', report)
            self.assertNotIn('.github/workflows/ci.yml', report)
            self.assertFalse({item['action'] for item in plan['existing_untracked']} - {'PRESERVE', 'CONFLICT'})
            self.assertIn('.grok-stack/AGBP_SYNC.json', {item['path'] for item in plan['legacy_migration']})

    def test_an_untracked_file_at_an_installation_path_is_a_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'consumer'
            target.mkdir()
            subprocess.run(['git', 'init', '-q'], cwd=target, check=True)
            owned = install_into.build_payload(ROOT)[0].path
            (target / owned).parent.mkdir(parents=True, exist_ok=True)
            (target / owned).write_text('local\n', encoding='utf-8')
            report, _ = install_into._existing_untracked(target, frozenset({owned}))
            self.assertEqual(report, [{'action': 'CONFLICT', 'path': owned, 'class': report[0]['class'],
                                       'reason': 'untracked target file at a path the installation would write'}])

    def test_a_target_without_git_reports_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(install_into._existing_untracked(Path(tmp), frozenset()), ([], False))


if __name__ == '__main__':
    unittest.main()
