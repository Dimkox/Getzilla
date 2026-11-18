"""Owned child/kernel-command diagnostic models; no mounts or network."""
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_image_backend as backend


class FaultControls(unittest.TestCase):
    def test_fixed_kernel_failure_retains_command_and_closed_diagnostic(self):
        failure = (32, b'', b'mount: /owned/private/path: Permission denied\n')
        with mock.patch('getzilla.architecture_diff._run_capped', return_value=failure):
            with self.assertRaises(backend.BackendUnavailable) as result:
                backend._fixed(['/usr/bin/mount', '--make-rprivate', '/'])
        detail = result.exception.detail
        self.assertEqual(detail['command_id'], 'mount-propagation')
        self.assertEqual(detail['exit_code'], 32)
        self.assertIn('Permission denied', detail['stderr']['first'])
        self.assertNotIn('/owned/private/path', str(detail))

    def test_owned_child_failure_keeps_bounded_worker_diagnostic(self):
        child = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c',
            'import sys;sys.stderr.write("unshare: unshare failed: Operation not permitted\\n");sys.exit(1)'],
            env={'PATH': os.defpath, 'LANG': 'C'}, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            with self.assertRaises(backend.BackendUnavailable) as result:
                backend._collect_pipeline(child)
            self.assertIn('Operation not permitted', result.exception.detail['stderr']['first'])
            self.assertEqual(result.exception.detail['phase'], 'producer')
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()
