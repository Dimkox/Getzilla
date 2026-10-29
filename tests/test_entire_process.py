"""Exercise real child processes, including a pipe-flood and an orphaned pipe."""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla' / 'integrations'))
from getzilla_entire.process import bounded_run


@unittest.skipUnless(os.name == 'posix', 'remote execution currently requires POSIX process groups')
class BoundedProcessTests(unittest.TestCase):
    def run_python(self, code, **kwargs):
        return bounded_run([sys.executable, '-c', code], cwd=ROOT, env=os.environ.copy(), **kwargs)

    def test_separate_output_and_stdin(self):
        result = self.run_python('import sys; print(sys.stdin.read()); print("diagnostic", file=sys.stderr)',
                                 input_data=b'hello', timeout=2, max_output=1024)
        self.assertEqual((result.status, result.returncode, result.stdout), ('completed', 0, b'hello\n'))
        self.assertEqual(result.stderr, b'diagnostic\n')

    def test_output_flood_is_bounded_before_decode(self):
        start = time.monotonic()
        result = self.run_python('import os\nwhile True: os.write(1, b"x"*65536)',
                                 timeout=2, max_output=4096)
        self.assertEqual(result.status, 'output_limit')
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 4096)
        self.assertLess(time.monotonic() - start, 3)

    def test_timeout_kills_child_group_even_if_parent_exits(self):
        code = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])'
        start = time.monotonic()
        result = self.run_python(code, timeout=0.2, max_output=1024)
        self.assertEqual(result.status, 'timeout')
        self.assertLess(time.monotonic() - start, 2)

    def test_cancellation_and_missing_program(self):
        cancel = threading.Event()
        cancel.set()
        result = self.run_python('raise SystemExit(99)', cancel=cancel, timeout=2, max_output=1024)
        self.assertEqual(result.status, 'cancelled')
        with tempfile.TemporaryDirectory() as temp:
            result = bounded_run([str(Path(temp) / 'missing')], cwd=ROOT, env={}, timeout=1, max_output=1024)
        self.assertEqual(result.status, 'missing_tool')

    def test_nonzero_exit_is_not_success(self):
        result = self.run_python('raise SystemExit(7)', timeout=1, max_output=1024)
        self.assertEqual((result.status, result.returncode), ('completed', 7))


if __name__ == '__main__':
    unittest.main()
