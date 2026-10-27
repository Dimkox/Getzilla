"""Path hints: a read that names missing paths is answered with the real ones instead of a search spiral."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.path_hints import PROMPT_LOCATE, command_cwd, hint, inspect, prompt_paths, refusal, suggestions  # noqa: E402
from tests._support import project_copy, run_hook  # noqa: E402

MODULE = 'vendor/modules/acme.selector'
TREE = (f'{MODULE}/lib/SheetController.php', f'{MODULE}/lib/BitrixSheetRepository.php', f'{MODULE}/lib/CurvePointEvaluator.php',
        f'{MODULE}/install/index.php', 'vendor/components/acme/selector/templates/.default/template.php',
        'tests/php/test_sheet.php', 'README.md', '.getzilla/AGBP_SYNC.json')


def _repo(root: Path) -> Path:
    for name in TREE:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('x\n', encoding='utf-8')
    subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
    subprocess.run(['git', 'add', '-A'], cwd=root, check=True)
    return root


class InspectTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = _repo(Path(tmp.name))

    def missing(self, command: str) -> list[str] | None:
        found = inspect(command, self.root)
        return None if found is None else found.missing

    def test_patterns_scripts_and_option_values_are_not_paths(self) -> None:
        self.assertEqual(self.missing("rg -n 'return|id' README.md nope.md"), ['nope.md'])
        self.assertEqual(self.missing("rg -e x -e y README.md"), [])
        self.assertEqual(self.missing("rg --files vendor -g '*.php' gone/"), ['gone/'])
        self.assertEqual(self.missing("grep -rn -m 3 needle tests gone"), ['gone'])
        self.assertEqual(self.missing("sed -n '1,20p' README.md"), [])
        self.assertEqual(self.missing("head -n 5 README.md missing.txt"), ['missing.txt'])
        self.assertEqual(self.missing("find vendor gone -name '*.php'"), ['gone'])
        self.assertEqual(self.missing("awk '{print $1}' README.md"), None)  # $ is shell expansion territory
        self.assertEqual(self.missing(f"ls {MODULE}/lib/Sheet*Builder*.php"), [f'{MODULE}/lib/Sheet*Builder*.php'])
        self.assertEqual(self.missing(f"cat {MODULE}/lib/Sheet*.php"), [])

    def test_redirections_cd_and_pipelines(self) -> None:
        self.assertEqual(self.missing('cat nope.md 2>/dev/null'), ['nope.md'])
        self.assertEqual(self.missing('cat README.md 2>&1 | head -n 3'), [])
        self.assertEqual(self.missing(f'cd {MODULE} && cat lib/SheetController.php'), [])
        self.assertEqual(self.missing(f'cd {MODULE} && cat lib/Sheet.php'), ['lib/Sheet.php'])

    def test_writes_expansion_and_unknown_programs_are_never_inspected(self) -> None:
        for command in ('cat README.md > out.txt', "sed -i 's/a/b/' gone.md", 'cat "$FILE"', 'cat `ls`', 'rm gone.md',
                        'python3 gone.py', 'cat <<EOF\nx\nEOF', 'cat gone.md &', 'cat <(ls)', '(cat gone.md)'):
            with self.subTest(command=command):
                self.assertIsNone(inspect(command, self.root))

    def test_refusal_only_when_nothing_could_be_read(self) -> None:
        self.assertTrue(inspect('cat gone.md other.md', self.root).nothing_readable)
        self.assertTrue(inspect("rg --files gone1 gone2 | rg 'x'", self.root).nothing_readable)
        self.assertFalse(inspect('cat gone.md README.md', self.root).nothing_readable)
        self.assertFalse(inspect('cat gone.md; ls', self.root).nothing_readable)
        self.assertFalse(inspect('cat gone.md || cat README.md', self.root).nothing_readable)
        self.assertFalse(inspect('rg needle', self.root).nothing_readable)


class SuggestionTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = _repo(Path(tmp.name))

    def test_guessed_names_point_to_the_real_files(self) -> None:
        cases = {
            f'{MODULE}/lib/Sheet.php': f'{MODULE}/lib/SheetController.php',
            f'{MODULE}/lib/Sheet*Builder*.php': f'{MODULE}/lib/SheetController.php',
            f'{MODULE}/lib/CurvePayloadValidator.php': f'{MODULE}/lib/CurvePointEvaluator.php',
            'acme.selector': MODULE,
            '.getzilla/AGBP_SYNC.log.jsonl': '.getzilla/AGBP_SYNC.json',
            'vendor/local/templates': 'vendor/components/acme/selector/templates',
        }
        for missing, expected in cases.items():
            with self.subTest(missing=missing):
                found = suggestions(self.root, missing, self.root)
                self.assertIn(expected, found[:3], found)
                self.assertLessEqual(len(found), 5)

    def test_untracked_neighbours_are_suggested_and_outside_paths_are_not(self) -> None:
        (self.root / MODULE / 'lib' / 'SheetPresenter.php').write_text('', encoding='utf-8')
        self.assertIn(f'{MODULE}/lib/SheetPresenter.php', suggestions(self.root, f'{MODULE}/lib/SheetPresenterX.php', self.root))
        self.assertEqual(suggestions(self.root, '/etc/nope.conf', self.root), [])

    def test_fast_on_a_large_repository(self) -> None:
        files = [f'pkg{index // 500}/module{index % 500}/File{index}.php' for index in range(50000)]
        started = time.perf_counter()
        inspect('cat pkg1/module1/Nope.php README.md', self.root)
        self.assertLess(time.perf_counter() - started, 0.05)
        started = time.perf_counter()
        found = suggestions(self.root, 'pkg3/module7/File1507.phpx', self.root, files)
        self.assertLess(time.perf_counter() - started, 1.0)
        self.assertIn('pkg3/module7/File1507.php', found)

    def test_messages_name_each_missing_path_and_count_what_they_saved(self) -> None:
        message = refusal(self.root, f'cat {MODULE}/lib/Sheet.php nope.md', self.root)
        self.assertIn(f'`{MODULE}/lib/SheetController.php`', message)
        self.assertIn('`nope.md`', message)
        self.assertIn('rg --files', message)
        self.assertIsNone(refusal(self.root, f'cat {MODULE}/lib/Sheet.php README.md', self.root))
        self.assertIn(f'{MODULE}/lib/SheetController.php', hint(self.root, f'cat {MODULE}/lib/Sheet.php README.md', self.root))
        self.assertIsNone(hint(self.root, 'cat README.md', self.root))
        stats = json.loads((self.root / '.getzilla/runtime/path-hints.json').read_text(encoding='utf-8'))
        self.assertEqual((stats['refused'], stats['hinted']), (1, 1))

    def test_a_read_that_works_in_a_linked_worktree_is_not_refused(self) -> None:
        # The agent ran `sed` inside a worker worktree but the hook only saw the main checkout.
        subprocess.run(['git', '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'base'], cwd=self.root, check=True)
        worker = self.root / '.getzilla/runtime/scratch/worker-1/worktree'
        subprocess.run(['git', 'worktree', 'add', '-q', '--detach', str(worker)], cwd=self.root, check=True)
        (worker / 'deploy').mkdir()
        (worker / 'deploy' / 'new_release.py').write_text('x\n', encoding='utf-8')
        self.assertIsNone(refusal(self.root, 'sed -n 1,260p deploy/new_release.py', self.root))
        message = refusal(self.root, 'sed -n 1,260p deploy/old_release.py', self.root)
        self.assertIn('none of these paths exist', message)

    def test_command_directory_comes_from_the_tool_input_first(self) -> None:
        self.assertEqual(command_cwd(self.root, {'cwd': '/elsewhere'}, {'workdir': MODULE}), self.root / MODULE)
        self.assertEqual(command_cwd(self.root, {'cwd': '/elsewhere'}, {}), Path('/elsewhere'))
        self.assertEqual(command_cwd(self.root, {}, {}), self.root)


class PromptPathTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = _repo(Path(tmp.name))

    def test_names_in_a_task_come_back_as_real_paths(self) -> None:
        text = prompt_paths(self.root, 'Fix SheetController, then lib/Service/CurvePointEvaluator.php and test_sheet')
        self.assertIn(f'- SheetController: `{MODULE}/lib/SheetController.php`', text)
        self.assertIn(f'`{MODULE}/lib/CurvePointEvaluator.php`', text)
        self.assertIn('`tests/php/test_sheet.php`', text)
        self.assertTrue(text.endswith(PROMPT_LOCATE))

    def test_files_that_use_a_named_class_and_its_tests_are_listed(self) -> None:
        (self.root / 'vendor/app.php').write_text('<?php new SheetController();\n', encoding='utf-8')
        (self.root / 'tests/php/test_controller.php').write_text('<?php SheetController::run();\n', encoding='utf-8')
        (self.root / 'vendor/other.php').write_text('<?php new SheetControllerFactory();\n', encoding='utf-8')
        subprocess.run(['git', 'add', '-A'], cwd=self.root, check=True)
        text = prompt_paths(self.root, 'Fix SheetController and lib/SheetController.php')
        self.assertIn('  used in: `vendor/app.php`', text)
        self.assertIn('  tests: `tests/php/test_controller.php`', text)
        self.assertNotIn('vendor/other.php', text, 'a longer name is not a use')
        self.assertEqual(text.count(f'`{MODULE}/lib/SheetController.php`'), 1, 'one file named twice is listed once')

    def test_a_task_without_known_names_gets_only_the_locate_rule(self) -> None:
        self.assertEqual(prompt_paths(self.root, 'Make the README clearer for UnknownWidget'), PROMPT_LOCATE)
        self.assertEqual(prompt_paths(self.root, ''), PROMPT_LOCATE)


def _notes(root: Path) -> None:
    (root / 'notes').mkdir()
    (root / 'notes' / 'install_guide.md').write_text('x\n', encoding='utf-8')
    subprocess.run(['git', 'add', 'notes'], cwd=root, check=True)


class HookTests(unittest.TestCase):
    def _payload(self, root: Path, event: str, command: str, **extra) -> dict:
        return {'cwd': str(root), 'session_id': 'path-hints', 'hook_event_name': event, 'tool_name': 'exec_command',
                'tool_input': {'cmd': command, 'workdir': str(root)}, **extra}

    def test_pre_tool_use_refuses_an_impossible_read_and_allows_the_rest(self) -> None:
        with project_copy(git=True) as root:
            _notes(root)
            code, data, stderr = run_hook(root, 'pre_tool_use.py', self._payload(root, 'PreToolUse', 'cat notes/install_guidee.md'))
            self.assertEqual(code, 0, stderr)
            self.assertEqual(data['decision'], 'deny', data)
            self.assertIn('notes/install_guide.md', data['reason'])
            code, data, _ = run_hook(root, 'pre_tool_use.py', self._payload(root, 'PreToolUse', 'cat notes/install_guide.md'))
            self.assertEqual(data['decision'], 'allow', data)
            code, data, _ = run_hook(root, 'pre_tool_use.py', self._payload(root, 'PreToolUse', 'cat notes/install_guidee.md notes/install_guide.md'))
            self.assertEqual(data['decision'], 'allow', data)

    def test_user_prompt_submit_names_the_real_paths(self) -> None:
        with project_copy(git=True) as root:
            _notes(root)
            payload = {'cwd': str(root), 'session_id': 'path-hints', 'hook_event_name': 'UserPromptSubmit',
                       'prompt': 'Update install_guide before the release'}
            code, data, stderr = run_hook(root, 'user_prompt_submit.py', payload)
            self.assertEqual(code, 0, stderr)
            self.assertIn('`notes/install_guide.md`', data['hookSpecificOutput']['additionalContext'])

    def test_post_tool_use_adds_the_hint_beside_the_output(self) -> None:
        with project_copy(git=True) as root:
            _notes(root)
            payload = self._payload(root, 'PostToolUse', 'cat notes/install_guidee.md notes/install_guide.md', tool_response={'output': ''})
            code, data, stderr = run_hook(root, 'post_tool_use.py', payload)
            self.assertEqual(code, 0, stderr)
            self.assertIn('notes/install_guide.md', data['hookSpecificOutput']['additionalContext'])
            payload = self._payload(root, 'PostToolUse', 'cat notes/install_guide.md', tool_response={'output': ''})
            self.assertEqual(run_hook(root, 'post_tool_use.py', payload)[1]['hookSpecificOutput']['additionalContext'], '')


if __name__ == '__main__':
    unittest.main()
