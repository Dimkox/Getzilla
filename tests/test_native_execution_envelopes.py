"""Native envelopes retain ordinary public reads and exact dispatch identity."""
import json
import subprocess
import unittest
import os
from pathlib import Path
import shutil
import tempfile


class NativeExecutionEnvelopeTests(unittest.TestCase):
    def setUp(self):
        project = Path(__file__).resolve().parents[1]
        scratch = Path(os.environ.get('GETZILLA_TEST_RUNTIME', project / '.getzilla/runtime/tests'))
        scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for component in ('hooks', 'getzilla', 'config'):
            shutil.copytree(project / '.getzilla' / component, self.root / '.getzilla' / component,
                            ignore=shutil.ignore_patterns('__pycache__'))

    def invoke(self, tool, inputs, **extra):
        payload = {'cwd': str(self.root), 'tool_name': tool, 'tool_input': inputs, **extra}
        result = subprocess.run(['python3', str(self.root / '.getzilla/hooks/pre_tool_use.py')],
                                cwd=self.root, input=json.dumps(payload), text=True,
                                capture_output=True, timeout=10)
        return result, json.loads(result.stdout)

    def test_namespaced_public_reads_keep_ordinary_policy(self):
        (self.root / 'README.md').write_text('Public fixture.\n')
        for command in ('pwd', 'cat README.md'):
            with self.subTest(command=command):
                result, data = self.invoke('functions.exec_command', {'cmd': command})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(data.get('decision'), 'allow', data)

    def test_same_tool_conflicting_argument_envelopes_refuse(self):
        _, data = self.invoke('functions.exec_command', {'cmd': 'pwd'},
                              toolArgs=json.dumps({'cmd': 'terraform destroy'}))
        self.assertEqual(data.get('decision'), 'deny', data)

    def test_native_spawn_without_route_does_not_infer_an_agent_role(self):
        _, data = self.invoke('collaboration.spawn_agent',
                              {'task_name': 'bounded_read', 'message': 'Read public sources'})
        self.assertEqual(data.get('decision'), 'deny', data)

    def test_unrecognized_namespace_does_not_inherit_leaf_shell_alias(self):
        _, data = self.invoke('functions.vendor.exec_command', {'cmd': 'pwd'})
        self.assertEqual(data.get('decision'), 'deny', data)
