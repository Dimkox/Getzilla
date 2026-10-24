from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.resource_inventory import (  # noqa: E402
    EPHEMERAL, PROTECTED, classify, disposable, inventory, measure, repository_copies,
)


def snapshot(base: Path) -> dict[str, bytes]:
    return {str(path.relative_to(base)): path.read_bytes() for path in sorted(base.rglob('*'))
            if path.is_file() and not path.is_symlink()}


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.root = self.base / 'project'
        self.runtime = self.root / '.getzilla' / 'runtime'
        for name in ('receipts', 'routes', 'worktrees/task', 'par/run-1', 'scratch', 'mystery'):
            (self.runtime / name).mkdir(parents=True)
        (self.runtime / 'approvals.json').write_text('{}')
        (self.runtime / 'receipts' / 'r.json').write_text('{"status": "pass"}')
        (self.runtime / 'par' / 'run-1' / 'log.txt').write_text('x' * 100)
        self.temp = self.base / 'tmp'
        self.temp.mkdir()
        (self.temp / 'grok-core-parallel-abc').mkdir()
        (self.temp / 'grok-core-parallel-abc' / 'out').write_text('y' * 10)
        (self.temp / 'someone-else').mkdir()

    def link(self, link: Path, target: Path) -> None:
        try:
            link.symlink_to(target, target_is_directory=target.is_dir())
        except OSError:
            self.skipTest('symlinks unavailable')

    def test_persistent_state_is_protected_and_only_runner_logs_are_disposable(self) -> None:
        self.assertEqual(classify(self.root, self.runtime / 'approvals.json'), 'protected')
        self.assertEqual(classify(self.root, self.runtime / 'receipts' / 'r.json'), 'protected')
        self.assertEqual(classify(self.root, self.runtime / 'worktrees' / 'task'), 'protected')
        self.assertEqual(classify(self.root, self.runtime), 'protected')
        self.assertTrue(disposable(self.root, self.runtime / 'par' / 'run-1'))
        for name in ('scratch', 'mystery', 'never-seen.json'):
            self.assertEqual(classify(self.root, self.runtime / name), 'unknown', name)
            self.assertFalse(disposable(self.root, self.runtime / name))
        self.assertFalse(PROTECTED & {'par', 'scratch'})

    def test_every_protected_name_stays_protected_and_only_par_is_ephemeral(self) -> None:
        self.assertEqual(EPHEMERAL, frozenset({'par'}))
        self.assertFalse(PROTECTED & EPHEMERAL)
        for name in [*PROTECTED, '.state.lock', '.approvals.lock']:
            self.assertEqual(classify(self.root, self.runtime / name), 'protected', name)

    def test_traversal_and_outside_paths_are_unknown(self) -> None:
        self.assertEqual(classify(self.root, self.runtime / 'par' / '..' / 'receipts'), 'unknown')
        self.assertFalse(disposable(self.root, self.runtime / 'par' / 'run-1' / '..' / 'run-1'))
        self.assertFalse(disposable(self.root, self.runtime / 'par' / '..' / '..' / '..' / 'src'))
        self.assertFalse(disposable(self.root, self.root / 'src'))
        self.assertFalse(disposable(self.root, self.base / 'tmp' / 'grok-core-parallel-abc'))
        self.assertFalse(disposable(self.root, Path(str(self.runtime) + '-par')))

    def test_a_symlink_anywhere_on_the_path_is_never_disposable(self) -> None:
        outside = self.base / 'precious'
        outside.mkdir()
        (outside / 'work.txt').write_text('unique')
        self.link(self.runtime / 'par' / 'escape', outside)
        self.assertEqual(classify(self.root, self.runtime / 'par' / 'escape'), 'unknown')
        self.assertFalse(disposable(self.root, self.runtime / 'par' / 'escape' / 'work.txt'))
        (outside / 'deep').mkdir()
        self.assertFalse(disposable(self.root, self.runtime / 'par' / 'escape' / 'deep' / '..' / 'work.txt'))
        (self.runtime / 'par').rename(self.base / 'real-par')
        self.link(self.runtime / 'par', self.base / 'real-par')
        self.assertFalse(disposable(self.root, self.runtime / 'par' / 'run-1'))

    def test_a_linked_runtime_folder_is_never_disposable(self) -> None:
        other = self.base / 'other'
        (other / '.getzilla').mkdir(parents=True)
        self.link(other / '.getzilla' / 'runtime', self.runtime)
        self.assertEqual(classify(other, other / '.getzilla' / 'runtime' / 'par' / 'run-1'), 'unknown')
        linked = self.base / 'linked'
        linked.mkdir()
        self.link(linked / '.getzilla', self.root / '.getzilla')
        self.assertFalse(disposable(linked, linked / '.getzilla' / 'runtime' / 'par' / 'run-1'))

    def test_unreadable_path_parts_fail_closed(self) -> None:
        (self.runtime / 'par' / 'file').write_text('not a directory')
        self.assertEqual(classify(self.root, self.runtime / 'par' / 'file' / 'child'), 'unknown')

    def test_a_missing_runtime_folder_fails_closed(self) -> None:
        fresh = self.base / 'fresh'
        fresh.mkdir()
        self.assertEqual(classify(fresh, fresh / '.getzilla' / 'runtime' / 'par' / 'run-1'), 'unknown')
        (fresh / '.getzilla').mkdir()
        self.assertEqual(classify(fresh, fresh / '.getzilla' / 'runtime' / 'par' / 'run-1'), 'unknown')

    def test_a_dot_dot_part_alone_is_unknown(self) -> None:
        self.assertEqual(classify(self.root, self.runtime / 'par' / '..' / 'par' / 'run-1'), 'unknown')

    def test_measure_does_not_follow_links_and_discloses_the_budget(self) -> None:
        big = self.base / 'big'
        big.mkdir()
        (big / 'blob').write_bytes(b'z' * 1_048_576)
        self.link(self.runtime / 'par' / 'run-1' / 'to-big', big)
        measured = measure(self.runtime / 'par')
        self.assertTrue(measured['complete'])
        self.assertLess(measured['bytes'], 1_048_576)
        limited = measure(self.runtime, budget=3)
        self.assertEqual((limited['entries'], limited['complete']), (3, False))
        self.assertEqual(measure(self.base / 'missing'), {'bytes': 0, 'entries': 0, 'complete': False})

    def test_inventory_lists_runtime_and_owned_temp_dirs_and_deletes_nothing(self) -> None:
        before = snapshot(self.base)
        report = inventory(self.root, self.temp)
        self.assertEqual(snapshot(self.base), before)
        self.assertEqual(report['deleted'], 0)
        by_name = {(item['location'], item['name']): item for item in report['resources']}
        self.assertEqual(by_name[('runtime', 'approvals.json')]['class'], 'protected')
        self.assertEqual(by_name[('runtime', 'par')]['class'], 'ephemeral')
        self.assertEqual(by_name[('temp', 'grok-core-parallel-abc')]['class'], 'unknown')
        self.assertNotIn(('temp', 'someone-else'), by_name)
        self.assertEqual(report['totals']['ephemeral']['resources'], 1)
        self.assertTrue(report['complete'])
        self.assertIn('free', report['disk']['temp'])

    def make_copy(self, folder: Path) -> Path:
        (folder / 'scripts').mkdir(parents=True)
        (folder / 'engineering').mkdir()
        (folder / 'AGENTS.md').write_text('# copy\n' * 100)
        return folder

    def test_repository_copies_are_found_counted_once_and_never_followed_through_links(self) -> None:
        self.make_copy(self.runtime / 'scratch' / 'review-1' / 'candidate')
        nested = self.make_copy(self.runtime / 'mystery-root' / 'unrelated')  # not a snapshot folder
        outer = self.make_copy(self.runtime / 'scratch' / 'review-2')
        self.make_copy(outer / 'tests' / 'fixture')  # a copy inside a copy is part of it
        (self.runtime / 'reviews').mkdir()
        self.make_copy(self.runtime / 'reviews' / 'route' / 'code' / 'repo')
        self.make_copy(self.runtime / 'scratch' / 'a' / 'b' / 'c' / 'd' / 'too-deep')
        outside = self.make_copy(self.base / 'outside-copy')
        self.link(self.runtime / 'scratch' / 'link', outside)
        before = snapshot(self.base)
        report = inventory(self.root, self.temp)
        self.assertEqual(snapshot(self.base), before)
        paths = [item['path'] for item in report['repository_copies']]
        self.assertEqual(paths, ['.getzilla/runtime/reviews/route/code/repo',
                                 '.getzilla/runtime/scratch/review-1/candidate',
                                 '.getzilla/runtime/scratch/review-2'])
        self.assertNotIn(str(nested), paths)
        self.assertTrue(all(item['bytes'] > 0 for item in report['repository_copies']))
        self.assertFalse(any(disposable(self.root, self.root / path) for path in paths))

    def test_a_linked_getzilla_runtime_or_copy_folder_is_not_read_and_is_incomplete(self) -> None:
        self.make_copy(self.runtime / 'scratch' / 'review-1')
        linked = self.base / 'linked'
        linked.mkdir()
        self.link(linked / '.getzilla', self.root / '.getzilla')
        report = inventory(linked, self.temp)
        runtime_entries = [item for item in report['resources'] if item['location'] == 'runtime']
        self.assertEqual((runtime_entries, report['repository_copies'], report['complete']), ([], [], False))
        runtime_link = self.base / 'runtime-link'
        (runtime_link / '.getzilla').mkdir(parents=True)
        self.link(runtime_link / '.getzilla' / 'runtime', self.runtime)
        self.assertEqual(repository_copies(runtime_link), ([], False))
        outside = self.make_copy(self.base / 'outside-scratch' / 'copy')
        self.link(self.runtime / 'archive', outside.parent)
        copies, complete = repository_copies(self.root)
        self.assertEqual([item['path'] for item in copies], ['.getzilla/runtime/scratch/review-1'])
        self.assertFalse(complete)
        self.assertFalse(inventory(self.root, self.temp)['complete'])

    def test_one_entry_budget_covers_the_search_and_every_copy_size(self) -> None:
        self.make_copy(self.runtime / 'scratch' / 'review-1')
        self.make_copy(self.runtime / 'scratch' / 'review-2')
        copies, complete = repository_copies(self.root)
        self.assertEqual((len(copies), complete), (2, True))
        copies, complete = repository_copies(self.root, budget=8)
        self.assertFalse(complete)
        self.assertTrue(all(item['entries'] <= 8 for item in copies))
        self.assertFalse(repository_copies(self.root, budget=1)[1])

    def test_a_search_that_uses_exactly_the_budget_is_complete(self) -> None:
        (self.runtime / 'scratch' / 'empty').mkdir()
        self.assertEqual(repository_copies(self.root, budget=1), ([], True))
        self.assertEqual(repository_copies(self.root, budget=0), ([], False))

    def test_the_budget_left_after_the_search_bounds_the_copy_size(self) -> None:
        big = self.make_copy(self.runtime / 'scratch' / 'big')
        for index in range(10):
            (big / 'scripts' / f'file-{index}.py').write_text('x\n')
        copies, complete = repository_copies(self.root, budget=100)
        self.assertTrue(complete)
        # The scratch listing has 1 entry; the copy counts its own 14 entries once, through its size.
        self.assertEqual(copies[0]['entries'], 14)
        self.assertTrue(repository_copies(self.root, budget=15)[1], 'the exact budget is enough')
        copies, complete = repository_copies(self.root, budget=14)
        self.assertEqual(([item['path'] for item in copies], complete), (['.getzilla/runtime/scratch/big'], False))
        self.assertFalse(copies[0]['complete'])

    def test_an_unreadable_copy_folder_marks_the_report_incomplete(self) -> None:
        (self.runtime / 'scratch' / 'locked').mkdir()
        real_scandir = os.scandir

        def denied(path):
            if Path(path).name == 'locked':
                raise PermissionError('denied')
            return real_scandir(path)

        with patch('getzilla.resource_inventory.os.scandir', side_effect=denied):
            self.assertEqual(repository_copies(self.root), ([], False))

    def test_cli_lists_repository_copies(self) -> None:
        (self.root / '.git').mkdir()
        self.make_copy(self.runtime / 'scratch' / 'review-9')
        cli = [sys.executable, str(ROOT / 'scripts' / 'getzilla_cleanup.py'), 'inventory', '--temp', str(self.temp)]
        text = subprocess.run(cli, cwd=self.root, capture_output=True, text=True, check=True).stdout
        self.assertIn('Repository copies (review snapshots and the like, kept until you decide): 1,', text)
        self.assertIn('.getzilla/runtime/scratch/review-9', text)

    def test_inventory_of_a_fresh_clone_without_runtime_is_empty(self) -> None:
        report = inventory(self.base / 'fresh', self.base / 'no-temp')
        self.assertEqual((report['resources'], report['totals'], report['complete'], report['repository_copies']),
                         ([], {}, True, []))

    def test_cli_prints_classes_and_json_without_deleting(self) -> None:
        (self.root / '.git').mkdir()
        before = snapshot(self.base)
        cli = [sys.executable, str(ROOT / 'scripts' / 'getzilla_cleanup.py'), 'inventory', '--temp', str(self.temp)]
        env = {**os.environ, 'PYTHONIOENCODING': 'utf-8'}
        text = subprocess.run(cli, cwd=self.root, capture_output=True, text=True, check=True, env=env).stdout
        self.assertIn('nothing deleted', text)
        self.assertIn('ephemeral  runtime  par', text)
        data = json.loads(subprocess.run([*cli, '--json'], cwd=self.root, capture_output=True, text=True,
                                         check=True, env=env).stdout)
        self.assertEqual(data['schema_version'], 'getzilla-resource-inventory-v1')
        self.assertEqual(snapshot(self.base), before)


if __name__ == '__main__':
    unittest.main()
