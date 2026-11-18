"""Fixed independent job allocation models. No systemd or kernel execution."""
from contextlib import ExitStack
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_image_job as job
from getzilla.security_image_backend import BackendUnavailable


class JobControls(unittest.TestCase):
    def test_only_explicit_owned_scope_gets_fixed_budget(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory, ExitStack() as stack:
            observed = Path('/sys/fs/cgroup/user.slice/user-1000.slice/cgroup.subtree_control')
            def read_text(path, *_args, **_kwargs):
                if path != observed:
                    raise AssertionError('outside fixture read denied')
                return 'cpu memory pids'
            stack.enter_context(mock.patch.object(Path, 'read_text', read_text))
            stack.enter_context(mock.patch.object(Path, 'exists', return_value=False))
            stack.enter_context(mock.patch.object(os, 'geteuid', return_value=0))
            stack.enter_context(mock.patch.object(os, 'sched_getaffinity', return_value=set(range(6))))
            stack.enter_context(mock.patch.dict(os.environ, SUDO_UID='1000', SUDO_GID='1000'))
            stack.enter_context(mock.patch('getzilla.startup_cpu.cgroup_bounds', return_value={
                'membership': '/old-app.service', 'effective_cpuset': '0-5'}))
            native = stack.enter_context(mock.patch('getzilla.security_image_job.ctypes.CDLL'))
            native.return_value.prctl.return_value = 0
            stack.enter_context(mock.patch.object(job, '_reap_children'))
            port = stack.enter_context(mock.patch('getzilla.architecture_diff._run_capped',
                return_value=(0, b'{"result":{"kind":"owned-model","qualification":"UNVERIFIED"}}', b'')))
            result = job.run_job(b'{"kind":"kernel-self-test"}', Path(directory), slice_name='user-1000.slice')
            self.assertEqual(result['qualification'], 'UNVERIFIED')
            command = port.call_args.args[0]
            for required in ('--scope', '--slice=user-1000.slice', '--property=MemoryMax=2147483648',
                             '--property=MemorySwapMax=0', '--property=TasksMax=256', '--property=CPUQuota=600%'):
                self.assertIn(required, command)
            self.assertFalse(any('AllowedCPUs' in value for value in command), 'do not enable a global cpuset controller')
            self.assertTrue(next(value for value in command if value.startswith('--unit=')).endswith('.scope'))

            # Ordinary production requests must observe the existing reserve,
            # rather than accepting the caller's six-CPU claim as proof.
            observer = stack.enter_context(mock.patch('getzilla.startup_cpu.measure', return_value={
                'chosen_capacity': 2, 'verified_cpus': '0-5'}))
            stack.enter_context(mock.patch.object(os, 'fchown'))
            job.run_job(b'{"kind":"production","capacity":6}', Path(directory), slice_name='user-1000.slice')
            observer.assert_called_once_with(reserve=2, probe=False)
            self.assertIn('--property=CPUQuota=200%', port.call_args.args[0])
            records = list(Path(directory).glob('image-startup-*.json'))
            self.assertEqual(len(records), 1)
            self.assertIn(b'"chosen_capacity": 2', records[0].read_bytes())

    def test_other_user_slice_is_refused_before_any_command(self):
        with mock.patch.object(os, 'geteuid', return_value=0), mock.patch.dict(os.environ, SUDO_UID='1000'), \
                mock.patch.object(job, '_retain_fault'), mock.patch('subprocess.Popen', side_effect=AssertionError('process denied')):
            with self.assertRaises(BackendUnavailable):
                job.run_job(b'{"kind":"kernel-self-test"}', ROOT / '.getzilla/runtime', slice_name='user-9999.slice')
