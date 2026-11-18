"""Owned child/kernel-command diagnostic models; no mounts or network."""
import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_image_backend as backend


class FaultControls(unittest.TestCase):
    def test_normal_build_failure_retains_redacted_actual_tail_and_complete_capture_identity(self):
        first = b'ordinary first error: input refused\n'
        final = b'\nACTUAL FINAL FAILURE: no space left on device\n'
        url = b'https://owned-user:owned-secret@internal.invalid/' + b'private-segment/' * 20
        path = b'/owned/private/context/secret-file'
        opaque = b'Q' * 96
        tail = url + b' ' + path + b' ' + opaque + final
        cases = [(first + b'x ' * 222 + url, tail), (first + b'x ' * 222 + opaque, tail),
                 (first + ('🙂\x00\t' * 150).encode(), url + b' ' + ('🙂\x00\t' * 150).encode() + final),
                 (first, path + b' ' + b'safe line\n' * 46 + final)]
        for index, (prefix, tail) in enumerate(cases):
            stderr = prefix + b'\n' + b'middle safe line\n' * 500 + tail
            with self.subTest(boundary_case=index):
                self.assertGreater(len(stderr), 4097)
                guard = object()
                builder = object.__new__(backend.BuildKit)
                builder.guard, builder.client, builder.address = guard, 'owned-buildctl', 'unix:///owned/private.sock'
                builder.deadline = time.monotonic() + 5
                builder.env = {'PATH': os.defpath, 'OWNED_SECRET': 'DO_NOT_EXPORT_ENV'}
                with mock.patch.object(backend, '_GUARD', guard), \
                     mock.patch.object(backend.BuildKit, '_daemon_alive', return_value=True), \
                     mock.patch('getzilla.architecture_diff._run_capped', return_value=(1, b'', stderr)) as command, \
                     mock.patch('subprocess.Popen', side_effect=AssertionError('actual process denied')):
                    with self.assertRaises(backend.BackendUnavailable) as result:
                        builder.build(dict(dockerfile='Dockerfile', context='.', platform='linux/amd64', arguments={}),
                                      Path('/owned/private/context'), Path('/owned/private/output'), offline_control=False)
                detail = result.exception.detail
                self.assertEqual(set(detail), {'phase', 'command_id', 'exit_code', 'errno', 'stderr_captured_sha256', 'stderr'})
                self.assertEqual((detail['phase'], detail['command_id'], detail['exit_code'], detail['errno']),
                                 ('build', 'buildctl-build', 1, None))
                diagnostic = detail['stderr']
                self.assertEqual(detail['stderr_captured_sha256'], hashlib.sha256(stderr).hexdigest())
                self.assertEqual(diagnostic['captured_sha256'], detail['stderr_captured_sha256'])
                self.assertEqual(diagnostic['captured_bytes'], len(stderr))
                self.assertIn('ordinary first error', diagnostic['first'])
                self.assertIn('ACTUAL FINAL FAILURE', diagnostic['last'])
                retained = diagnostic['first'] + diagnostic['last']
                for secret in ('owned-user', 'owned-secret', 'internal.invalid', '/owned/private', 't-file',
                               'Q' * 12, 'DO_NOT_EXPORT_ENV'):
                    self.assertNotIn(secret, retained)
                for key in ('first', 'last'):
                    self.assertLessEqual(len(json.dumps(diagnostic[key], ensure_ascii=True).encode()), 512)
                self.assertLess(len(json.dumps({'fault': detail}, ensure_ascii=True).encode()), 4096)
                self.assertEqual(command.call_args.kwargs['stderr_limit'], 1024 * 1024)

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
