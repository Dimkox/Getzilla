"""Real owned signals stop read-only queue work through the verifier's context."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix', 'owned POSIX SIGTERM control')
class QueueCancellationTests(unittest.TestCase):
    def run_signal_case(self, boundary):
        # Inject only signal timing. The original analysis/budget method still runs.
        program = '''
import ast
import os
import signal
from unittest.mock import patch
from getzilla import architecture_fitness as fit, queue_provenance as queue
from getzilla.python_test_runner import _cancellation
boundary = __import__('sys').argv[1]
owner, name = ((queue._Interpreter, '_statement') if boundary == 'statement'
               else (fit._QueueBudget, boundary))
original = getattr(owner, name)
def interrupted(self, *args, **kwargs):
    os.kill(os.getpid(), signal.SIGTERM)
    print('handler-returned', flush=True)
    return original(self, *args, **kwargs)
with _cancellation(), patch.object(owner, name, interrupted):
    if boundary == 'statement':
        queue.analyze_queue_tree(ast.parse('import celery\\nvalue = celery.Celery("owned")\\n'))
    elif boundary == 'step':
        fit._QueueBudget('head').step(request=True)
    else:
        fit._QueueBudget('head').source('owned.py', b'value = 1\\n')
print('analysis-completed', flush=True)
'''
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='queue-cancel-', dir=scratch) as directory:
            result = subprocess.run([sys.executable, '-B', '-c', program, boundary], cwd=directory,
                                    env={'PATH': os.defpath, 'PYTHONPATH': str(ROOT / '.getzilla')},
                                    capture_output=True, text=True, timeout=10, check=False)
        self.assertIn('handler-returned', result.stdout, result.stderr)
        self.assertNotIn('analysis-completed', result.stdout, result.stderr)
        self.assertEqual(result.returncode, 143, result.stderr)

    def test_sigterm_during_queue_interpreter_stops_without_completion(self):
        self.run_signal_case('statement')

    def test_sigterm_during_recursive_queue_work_stops_without_completion(self):
        self.run_signal_case('step')

    def test_sigterm_during_queue_source_admission_stops_without_completion(self):
        self.run_signal_case('source')


if __name__ == '__main__':
    unittest.main()
