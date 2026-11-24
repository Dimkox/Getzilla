from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

from getzilla.language_quality.core import PolicyError, load_policy, run_registry
from getzilla.language_quality.models import ToolOutput
from getzilla.language_quality.sandbox import ContainerExecutor, Execution, bounded_process, operator_images

IMAGE = 'lint@sha256:' + 'a' * 64
BASE = 'b' * 40


class PolicyRepairTests(unittest.TestCase):
    def test_invalid_driver_and_engine_types_report_policy_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / '.getzilla/config/policy.json'
            path.parent.mkdir(parents=True)
            for invalid in ([], {}, None, True, 1):
                for section in ({'tools': {'eslint': {'driver': invalid}}},
                                {'sandbox': {'image': IMAGE, 'engine': invalid}}):
                    with self.subTest(section=section):
                        path.write_text(json.dumps({'language_quality_gates': section}))
                        with self.assertRaises(PolicyError):
                            load_policy(root)
                        result = run_registry(root, BASE)
                        self.assertEqual(result[0]['execution_status'], 'ERROR')
                        self.assertEqual(result[0]['enforcement'], 'blocking')

    @unittest.skipUnless(os.name == 'posix', 'safe input snapshot requires POSIX')
    def test_custom_config_and_project_policy_changes_force_full_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / '.getzilla/config/policy.json'
            policy.parent.mkdir(parents=True)
            (root / 'web/config').mkdir(parents=True)
            for path, text in {'web/package.json': '{}', 'web/a.js': 'const a = 1;',
                               'web/b.js': 'const b = 2;', 'web/config/rules.json': '{}'}.items():
                (root / path).write_text(text)
            policy.write_text(json.dumps({'language_quality_gates': {'sandbox': {'image': IMAGE}, 'tools': {
                'eslint': {'launcher': ['/opt/eslint'], 'version': '9.0.0', 'config': 'config/rules.json', 'enforcement': 'blocking'}}}}))
            backend = Mock()
            payload = [{'filePath': '/workspace/web/' + name, 'messages': [], 'errorCount': 0,
                        'warningCount': 0, 'fatalErrorCount': 0} for name in ('a.js', 'b.js')]
            backend.execute.return_value = Execution('COMPLETED', ToolOutput(0, json.dumps(payload), ''), identity='fixture')
            for changed in ('web/config/rules.json', '.getzilla/config/policy.json'):
                with self.subTest(changed=changed), \
                     patch('getzilla.language_quality.core.inventory', return_value=('web/package.json', 'web/a.js', 'web/b.js', 'web/config/rules.json')), \
                     patch('getzilla.language_quality.core.git_head', return_value='c' * 40), \
                     patch('getzilla.language_quality.core.changed_file_statuses', return_value=[{'path': changed, 'status': 'M', 'source': 'range:' + BASE}]):
                    result = next(r for r in run_registry(root, BASE, executor=backend) if r['tool_id'] == 'eslint')
                    self.assertEqual(result['scope'], 'full', result)
                    self.assertEqual(result['fallback_reason'], 'configuration-change')
                    self.assertEqual(result['execution_status'], 'PASS', result)


class OperatorAdmissionTests(unittest.TestCase):
    def metadata(self, path, **changes):
        is_file = str(path).endswith('language-quality.json')
        return SimpleNamespace(st_mode=(stat.S_IFREG | 0o600) if is_file else (stat.S_IFDIR | 0o755),
                               st_uid=0, st_size=1024, **changes)

    def test_only_owned_safe_regular_registry_with_closed_schema_admits_image(self):
        good = json.dumps({'schema_version': 1, 'images': [IMAGE]})
        with patch.object(Path, 'lstat', autospec=True, side_effect=self.metadata), \
             patch.object(Path, 'read_text', return_value=good):
            self.assertEqual(operator_images(), frozenset({IMAGE}))
        for bad in ('{}', '{', '[]', '{"schema_version":true,"images":[]}',
                    '{"schema_version":1,"schema_version":1,"images":[]}',
                    json.dumps({'schema_version': 1, 'images': [IMAGE, IMAGE]}),
                    json.dumps({'schema_version': 1, 'images': [IMAGE], 'unknown': True}),
                    json.dumps({'schema_version': 1, 'images': [{}]}),
                    json.dumps({'schema_version': 1, 'images': ['node:latest']}),
                    json.dumps({'schema_version': 1, 'images': ['lint@sha256:' + format(n, '064x') for n in range(65)]})):
            with self.subTest(bad=bad), patch.object(Path, 'lstat', autospec=True, side_effect=self.metadata), \
                 patch.object(Path, 'read_text', return_value=bad):
                self.assertEqual(operator_images(), frozenset())

    def test_unsafe_metadata_rejects_without_reading_registry(self):
        for target in ('/etc', '/etc/getzilla', '/etc/getzilla/language-quality.json'):
            for field, value in (('st_uid', 1000), ('st_mode', stat.S_IFREG | 0o622),
                                 ('st_mode', stat.S_IFLNK | 0o777)):
                def metadata(path):
                    item = self.metadata(path)
                    if str(path) == target:
                        setattr(item, field, value)
                    return item
                with self.subTest(target=target, field=field, value=value), \
                     patch.object(Path, 'lstat', autospec=True, side_effect=metadata), \
                     patch.object(Path, 'read_text') as read:
                    self.assertEqual(operator_images(), frozenset())
                    read.assert_not_called()
        for failure in (FileNotFoundError(), PermissionError()):
            with patch.object(Path, 'lstat', side_effect=failure):
                self.assertEqual(operator_images(), frozenset())


@unittest.skipUnless(os.name == 'posix', 'POSIX bounded process and no-follow descriptors')
class SandboxRepairTests(unittest.TestCase):
    def test_fifo_input_fails_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / 'input.js')
            program = ('import sys; from pathlib import Path; '
                       'sys.path.insert(0, sys.argv[1]); '
                       'from getzilla.language_quality.core import read_input; '
                       'read_input(Path(sys.argv[2]), "input.js")')
            try:
                result = subprocess.run([sys.executable, '-c', program,
                                         str(Path(__file__).resolve().parents[1] / '.getzilla'), str(root)],
                                        capture_output=True, timeout=2, check=False)
            except subprocess.TimeoutExpired:
                self.fail('FIFO source blocked before regular-file validation')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'not a bounded regular file', result.stderr)

    def test_running_cancellation_kills_and_reaps_owned_process(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'started'
            command = [sys.executable, '-c',
                       'import os,sys,time; from pathlib import Path; Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)',
                       str(marker)]
            started = time.monotonic()
            result = bounded_process(command, {}, timeout=5, output_limit=1024, cancellation=marker.exists)
            self.assertEqual(result.status, 'CANCELLED')
            self.assertLess(time.monotonic() - started, 2)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)

    def test_cancellation_is_polled_after_process_closes_output_pipes(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'started'
            command = [sys.executable, '-c',
                       'import os,sys,time; from pathlib import Path; os.close(1); os.close(2); time.sleep(.1); Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)', str(marker)]
            started = time.monotonic()
            result = bounded_process(command, {}, timeout=1, output_limit=1024, cancellation=marker.exists)
            self.assertEqual(result.status, 'CANCELLED')
            self.assertLess(time.monotonic() - started, .8)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)

    def test_cleanup_failure_replaces_success_or_cancel_with_error(self):
        executor = ContainerExecutor({'image': IMAGE}, approved_images=frozenset({IMAGE}))
        inspect = Execution('COMPLETED', ToolOutput(0, 'sha256:' + 'd' * 64, ''))
        cleanup = Execution('COMPLETED', ToolOutput(1, '', 'daemon refused removal'))
        for status in ('COMPLETED', 'CANCELLED'):
            with tempfile.TemporaryDirectory() as directory, self.subTest(status=status), \
                 patch.object(executor, '_available', return_value=True), \
                 patch('getzilla.language_quality.sandbox.bounded_process', side_effect=[inspect, Execution(status, ToolOutput(0, '', '')), cleanup]) as process:
                root = Path(directory)
                result = executor.execute(root, '.', (), ('/opt/eslint',))
                self.assertEqual(result.status, 'ERROR')
                self.assertIn('cleanup', result.summary)
                self.assertEqual(process.call_args_list[-1].args[0][1:3], ['rm', '-f'])
                self.assertEqual(list((root / '.getzilla/runtime/lqg').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
