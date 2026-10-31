"""Read before edit: a patch may not change an existing file this session never read (#218)."""
from __future__ import annotations

import subprocess
import sys
import threading
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

import getzilla.read_ledger as ledger  # noqa: E402
from getzilla.read_ledger import command_files, output_files, patch_targets, record, seen  # noqa: E402
from getzilla.router import build_route  # noqa: E402
from getzilla.state import add_approval, set_active_route  # noqa: E402
from tests._support import project_copy, run_hook  # noqa: E402


def _patch(kind: str, path: str) -> str:
    body = '@@\n-a\n+b\n' if kind == 'Update' else '+b\n'
    return f'*** Begin Patch\n*** {kind} File: {path}\n{body}*** End Patch\n'


class ReadLedgerHookTests(unittest.TestCase):
    def _shell(self, root: Path, command: str, session: str = 'ledger-session') -> None:
        payload = {'cwd': str(root), 'session_id': session, 'hook_event_name': 'PostToolUse',
                   'tool_name': 'exec_command', 'tool_input': {'cmd': command, 'workdir': str(root)},
                   'tool_response': {'output': ''}}
        code, _, stderr = run_hook(root, 'post_tool_use.py', payload)
        self.assertEqual(code, 0, stderr)

    def _patch(self, root: Path, patch: str, session: str = 'ledger-session') -> dict:
        payload = {'cwd': str(root), 'session_id': session, 'hook_event_name': 'PreToolUse',
                   'tool_name': 'apply_patch', 'tool_input': {'input': patch}}
        code, data, stderr = run_hook(root, 'pre_tool_use.py', payload)
        self.assertEqual(code, 0, stderr)
        return data

    def _project(self, root: Path) -> None:
        (root / 'app').mkdir()
        for name in ('read.py', 'unread.py'):
            (root / 'app' / name).write_text('a\n', encoding='utf-8')
        subprocess.run(['git', 'add', 'app'], cwd=root, check=True)

    def test_linked_worktree_read_is_known_to_canonical_session_ledger(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                            'commit', '-qm', 'fixture'], cwd=root, check=True)
            target = root / '.getzilla/runtime/worktrees/ledger-child'
            subprocess.run(['git', 'worktree', 'add', '-qb', 'ledger-child', str(target)], cwd=root, check=True)
            self._shell(root, 'cat app/read.py')
            self._shell(target, 'cat app/unread.py')
            read_patch = _patch('Update', str(target / 'app/unread.py'))
            unseen_patch = _patch('Update', str(target / 'app/read.py'))
            self.assertEqual(ledger.unread(root, 'ledger-session', read_patch, root), [])
            self.assertEqual(ledger.unread(root, 'ledger-session', unseen_patch, root),
                             ['.getzilla/runtime/worktrees/ledger-child/app/read.py'])
            self.assertEqual(ledger.unread(target, 'ledger-session', _patch('Update', 'app/unread.py'), target), [])
            self._shell(root, 'cat app/read.py', 'other-session')
            self.assertTrue(ledger.unread(root, 'other-session', read_patch, root))
            subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Example/project.git'],
                           cwd=root, check=True)
            set_active_route(root, build_route(root, 'fix read ledger regression', 'ledger-session').to_dict())
            add_approval(root, 'protected-path', 'fixture', 5, actions=['protected-path-write'],
                         resources=['.getzilla/runtime/worktrees/ledger-child/app/unread.py'])
            self.assertEqual(self._patch(root, read_patch)['decision'], 'allow')

    def test_unregistered_nested_git_pointer_does_not_share_a_ledger(self) -> None:
        with project_copy(git=True) as root:
            target = root / '.getzilla/runtime/worktrees/unregistered'
            target.mkdir(parents=True)
            (target / '.git').write_text('gitdir: not-a-worktree\n', encoding='utf-8')
            self.assertEqual(ledger._ledger_root(target), target.resolve())

    def test_a_patch_to_an_unread_file_is_refused_and_a_read_one_passes(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            self._shell(root, "nl -ba app/read.py | sed -n '1,40p'")
            data = self._patch(root, _patch('Update', 'app/unread.py'))
            self.assertEqual(data['decision'], 'deny', data)
            self.assertIn('`app/unread.py`', data['reason'])
            self.assertIn('read before you change it', data['reason'])
            self.assertEqual(self._patch(root, _patch('Update', 'app/read.py'))['decision'], 'allow')
            self.assertEqual(self._patch(root, _patch('Add', 'app/new.py'))['decision'], 'allow')
            self._shell(root, 'cat app/unread.py')
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'))['decision'], 'allow')

    def test_a_session_without_a_ledger_is_never_blocked(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'), 'fresh-session')['decision'], 'allow')
            self._shell(root, 'cat app/read.py', 'manual')
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'), 'manual')['decision'], 'allow')

    def test_a_file_the_session_patched_counts_as_seen(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            self._shell(root, 'cat app/read.py')
            payload = {'cwd': str(root), 'session_id': 'ledger-session', 'hook_event_name': 'PostToolUse',
                       'tool_name': 'apply_patch', 'tool_input': {'input': _patch('Add', 'app/new.py')},
                       'tool_response': {'output': ''}}
            (root / 'app/new.py').write_text('b\n', encoding='utf-8')
            run_hook(root, 'post_tool_use.py', payload)
            self.assertEqual(self._patch(root, _patch('Update', 'app/new.py'))['decision'], 'allow')


    def test_files_a_search_printed_and_a_claude_read_count_as_seen(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            payload = {'cwd': str(root), 'session_id': 'ledger-session', 'hook_event_name': 'PostToolUse',
                       'tool_name': 'exec_command', 'tool_input': {'cmd': 'rg -n a app', 'workdir': str(root)},
                       'tool_response': {'output': 'app/unread.py:1:a\n'}}
            run_hook(root, 'post_tool_use.py', payload)
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'))['decision'], 'allow')
        with project_copy(git=True) as root:
            self._project(root)
            self._shell(root, 'cat app/read.py', 'claude-session')
            payload = {'cwd': str(root), 'session_id': 'claude-session', 'hook_event_name': 'PostToolUse',
                       'tool_name': 'Read', 'tool_input': {'file_path': str(root / 'app/unread.py')}, 'tool_response': {}}
            run_hook(root, 'post_tool_use.py', payload)
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'), 'claude-session')['decision'], 'allow')

    def test_a_corrupt_ledger_lets_the_patch_run(self) -> None:
        with project_copy(git=True) as root:
            self._project(root)
            self._shell(root, 'cat app/read.py')
            for item in (root / '.getzilla/runtime/reads').glob('*.json'):
                item.write_text('{not json', encoding='utf-8')
            self.assertEqual(self._patch(root, _patch('Update', 'app/unread.py'))['decision'], 'allow')


class ReadLedgerUnitTests(unittest.TestCase):
    def test_parallel_writers_keep_every_entry_and_a_full_ledger_drops_the_oldest(self) -> None:
        with project_copy(git=True) as root:
            threads = [threading.Thread(target=record, args=(root, 's', {f'f{index}.py'})) for index in range(40)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(seen(root, 's')), 40)
            with mock.patch.object(ledger, 'MAX_ENTRIES', 3):
                for name in ('z.py', 'y.py', 'a.py', 'b.py'):
                    record(root, 'cap', {name})
            self.assertEqual(seen(root, 'cap'), {'y.py', 'a.py', 'b.py'})

    def test_cd_globs_and_printed_paths(self) -> None:
        with project_copy(git=True) as root:
            (root / 'app').mkdir()
            for name in ('b.py', 'c.py'):
                (root / 'app' / name).write_text('x\n', encoding='utf-8')
            self.assertEqual(command_files(root, 'cd app && cat b.py', root), {'app/b.py'})
            self.assertEqual(command_files(root, 'cat app/*.py', root), {'app/b.py', 'app/c.py'})
            printed = 'diff --git a/app/b.py b/app/b.py\n+++ b/app/c.py\napp/b.py:3:x\n'
            self.assertEqual(output_files(root, printed, root), {'app/b.py', 'app/c.py'})

    def test_a_long_word_in_output_is_scanned_in_linear_time(self) -> None:
        # Codex review of #222 consumers: a long base64 value made the old pattern quadratic.
        import time
        with project_copy(git=True) as root:
            (root / 'app').mkdir()
            (root / 'app/b.py').write_text('x\n', encoding='utf-8')
            start = time.monotonic()
            found = output_files(root, 'A' * 150_000 + ' app/b.py:1:x\n', root)
            self.assertLess(time.monotonic() - start, 2.0)
            self.assertEqual(found, {'app/b.py'})

    def test_command_files_and_patch_targets(self) -> None:
        with project_copy(git=True) as root:
            (root / 'a.py').write_text('x\n', encoding='utf-8')
            self.assertEqual(command_files(root, "sed -n '1,20p' a.py missing.py --file=a.py", root), {'a.py'})
            self.assertEqual(command_files(root, 'cat /etc/hostname', root), set())
            changed, written = patch_targets(_patch('Update', 'a.py') + _patch('Delete', 'b.py') + _patch('Add', 'c.py'))
            self.assertEqual((changed, written), ({'a.py', 'b.py'}, {'c.py'}))


if __name__ == '__main__':
    unittest.main()
