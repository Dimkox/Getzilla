"""Source-only duplicate scan and pinned updater contracts."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import updater


class DuplicateTests(unittest.TestCase):
    def _scan(self, mutate=None):
        from getzilla import duplicates
        def execute(argv, cwd, report=None, timeout=120):
            if '--version' in argv:
                return 0, '4.0.5\n'
            payload = {'duplicates': [{'firstFile': {'name': str(cwd / 'source/a.py'), 'start': 1, 'end': 2},
                                       'secondFile': {'name': str(cwd / 'source/b.py'), 'start': 1, 'end': 2},
                                       'tokens': 0}]}
            self.assertFalse((cwd / 'source/.jscpd.json').exists())
            self.assertFalse((cwd / 'source/docs').exists())
            if mutate:
                mutate(payload, cwd)
            report.parent.mkdir()
            report.write_text(json.dumps(payload))
            return 0, ''
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(duplicates, 'find_tool', return_value='/tools/jscpd'), \
                mock.patch.object(duplicates, '_execute', side_effect=execute):
            root = Path(temporary)
            for name in ('a.py', 'b.py'):
                (root / name).write_text('value = 1\nprint(value)\n')
            (root / '.jscpd.json').write_text('{"reporters": ["evil"]}')
            (root / 'docs').mkdir()
            (root / 'docs/large.py').write_text('invalid docs')
            return duplicates.scan(root)

    def test_valid_report_preserves_hashes_and_unavailable_tokens(self):
        result = self._scan()
        self.assertEqual(result['status'], 'complete', result)
        self.assertEqual(len(result['pairs']), 1)
        self.assertIsNone(result['pairs'][0]['tokens'])
        self.assertEqual(set(result['source_hashes']), {'a.py', 'b.py'})

    def test_bad_paths_and_spans_are_partial_not_clean(self):
        for bad in ({'name': '/escape.py', 'start': 1, 'end': 2},
                    {'name': 'source/a.py', 'start': 0, 'end': 2},
                    {'name': 'source/a.py', 'start': 2, 'end': 1},
                    {'name': 'source/a.py', 'start': 1, 'end': 100}):
            result = self._scan(lambda payload, cwd: payload['duplicates'][0].update(firstFile=bad))
            self.assertEqual(result['status'], 'partial', result)
            self.assertEqual(result['rejected_pairs'], 1)

    def test_source_change_during_scan_is_error(self):
        def mutate(payload, cwd):
            # The snapshot parent is under the original root's owned runtime.
            original = cwd.parents[3]
            (original / 'a.py').write_text('changed\n')
        self.assertEqual(self._scan(mutate)['status'], 'error')

    def test_malformed_report_and_tool_failure_are_not_clean(self):
        from getzilla import duplicates
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(duplicates, 'find_tool', return_value='/tools/jscpd'):
            for response in ((1, ''), (0, '5.0.0')):
                with mock.patch.object(duplicates, '_execute', return_value=response):
                    result = duplicates.scan(Path(temporary))
                    self.assertNotEqual(result['status'], 'complete')
                    self.assertIsNone(result['pairs'])
            with mock.patch.object(duplicates, '_execute', side_effect=ValueError('jscpd timeout')):
                self.assertEqual(duplicates.scan(Path(temporary))['status'], 'error')

    def test_core_sources_are_included_but_runtime_is_not(self):
        from getzilla import duplicates
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('.getzilla/getzilla/module.py', '.getzilla/runtime/data.py'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('value = 1\n')
            self.assertEqual(set(duplicates.inventory(root)), {'.getzilla/getzilla/module.py'})

    def test_nested_runtime_is_excluded_before_read(self):
        from getzilla import duplicates
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('nested/.getzilla/getzilla/module.py', 'nested/.getzilla/runtime/data.py'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('value = 1\n')
            self.assertEqual(set(duplicates.inventory(root)), {'nested/.getzilla/getzilla/module.py'})

    def test_linked_scratch_ancestor_cannot_receive_snapshot_writes(self):
        from getzilla import duplicates
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            project, outside = base / 'project', base / 'outside'
            project.mkdir()
            outside.mkdir()
            try:
                (project / '.getzilla').symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest('symlinks unavailable')
            with mock.patch.object(duplicates, 'find_tool', return_value='/tools/jscpd'), \
                    mock.patch.object(duplicates, '_execute', return_value=(0, '4.0.5')):
                result = duplicates.scan(project)
            self.assertEqual(result['status'], 'error')
            self.assertEqual(list(outside.iterdir()), [])
    def test_updater_installs_exact_pin_and_checks_version(self):
        calls = []
        def run(command, cwd):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, '4.0.5\n', '')
        update = getattr(updater, 'update_jscpd', None)
        self.assertIsNotNone(update, 'jscpd updater is missing')
        result = update(run, {'npm': '/tools/npm', 'jscpd': '/tools/jscpd'}.get)
        self.assertEqual(result[0].status, 'ok')
        self.assertIn('jscpd@4.0.5', calls[0])
        self.assertIn('--ignore-scripts', calls[0])
        self.assertEqual(calls[1], ['/tools/jscpd', '--version'])

    def test_scanner_exists(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('getzilla.duplicates'))

    def test_source_inventory_excludes_docs_generated_tests_and_symlinks(self):
        from getzilla import duplicates
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('src/a.py', 'docs/large.py', 'README.md', 'tests/a.py',
                         'node_modules/a.py', '.codex/a.py', 'engineering/a.py'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('value = 1\n')
            try:
                (root / 'src/link.py').symlink_to(root / 'src/a.py')
            except OSError:
                pass
            self.assertEqual(set(duplicates.inventory(root)), {'src/a.py'})

    def test_missing_tool_is_unavailable_not_clean(self):
        from getzilla import duplicates
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(duplicates, 'find_tool', return_value=None):
            result = duplicates.scan(Path(temporary))
        self.assertEqual(result['status'], 'unavailable')
        self.assertIsNone(result['pairs'])

    def test_updater_rejects_wrong_version_and_missing_npm(self):
        result = updater.update_jscpd(lambda argv, cwd: subprocess.CompletedProcess(argv, 0, '5.0.0', ''),
                                      {'npm': 'npm', 'jscpd': 'jscpd'}.get)
        self.assertEqual(result[0].status, 'fail')
        self.assertEqual(updater.update_jscpd(mock.Mock(), lambda name: None)[0].status, 'skip')

    def test_offline_selection_never_calls_npm(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = mock.Mock(side_effect=AssertionError('must stay offline'))
            result = updater.run_all(Path(temporary), run=run, components=('jscpd',),
                                     mirror=updater.Mirror(Path(temporary), {}, {}))
        self.assertEqual([(item.component, item.status) for item in result], [('tool:jscpd', 'skip')])

    def test_default_and_selective_updater_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(updater, 'update_agents', return_value=[]), \
                mock.patch.object(updater, 'update_sources', return_value=[]), \
                mock.patch.object(updater, 'update_osv', return_value=[]), \
                mock.patch.object(updater, 'update_opengrep', return_value=[]), \
                mock.patch.object(updater, 'update_jscpd', return_value=[]) as update:
            updater.run_all(Path(temporary))
            self.assertEqual(update.call_count, 1)
            updater.run_all(Path(temporary), components=('osv',))
            self.assertEqual(update.call_count, 1)
