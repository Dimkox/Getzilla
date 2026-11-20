import importlib
import pickle
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock


class StudySupervisorTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_supervisor')
        except ModuleNotFoundError:
            self.fail('owned study supervisor is missing')

    def test_caller_cannot_construct_or_serialize_a_live_resource(self):
        owner = self.owner()
        with self.assertRaises(TypeError):
            owner.LiveStudyResourceRef()
        forged = object.__new__(owner.LiveStudyResourceRef)
        with self.assertRaises(ValueError):
            owner.check_live_study_resource(forged, {})
        with self.assertRaises(TypeError):
            pickle.dumps(forged)

    def test_report_dict_or_forged_result_cannot_become_native_inspection(self):
        owner = self.owner()
        with self.assertRaises(TypeError):
            owner.StudyInspectionResultRef()
        for fake in ({'native_executed': True}, object.__new__(owner.StudyInspectionResultRef)):
            with self.subTest(kind=type(fake)), self.assertRaises(ValueError):
                owner.check_study_inspection_result(fake, object())

    def test_raw_data_cannot_start_a_container_when_operation_owner_unavailable(self):
        owner = self.owner()
        with patch('getzilla.retrieval.study_docker_process._spawn') as spawn:
            with self.assertRaises(ValueError):
                with owner.owned_study_runtime({'allow_execution': True}):
                    self.fail('raw request became a live resource')
            spawn.assert_not_called()

    def test_create_command_is_fixed_offline_and_never_pulls(self):
        owner = self.owner()
        projection = SimpleNamespace(image_id='sha256:' + 'a' * 64,
            model_root='/fixture/model', software_root='/fixture/software',
            worker_root='/fixture/worker', cpu_ids=(2, 3))
        args, command = owner._create_arguments(projection, 'b' * 32, 'c' * 64, 10000)
        self.assertIn('--pull=never', args)
        self.assertIn('--network=none', args)
        self.assertIn('--read-only', args)
        self.assertIn('--memory-swap=6442450944', args)
        self.assertIn('--pids-limit=128', args)
        self.assertEqual(command[:4], ('/usr/local/bin/python', '-I', '-S', '-B'))
        self.assertIn('--nonce', command)
        self.assertNotIn('--privileged', args)

    def test_waiting_worker_is_stdlib_only_until_owned_channel_release(self):
        owner = self.owner()
        self.assertEqual(owner.status()['execution_enabled'], False)

    def test_failed_owned_start_retains_failure_and_actual_cleanup_not_repeat(self):
        owner = self.owner()
        backend = owner._Backend(object(), object())
        admission = SimpleNamespace(consume=Mock())
        native = Mock()
        native.start.side_effect = ValueError('controlled unavailable')
        native.close.return_value = True
        with patch.object(owner, '_Owner', return_value=native):
            result = backend.dispatch(object(), admission, object())
        admission.consume.assert_called_once()
        native.start.assert_called_once()
        native.close.assert_called_once()
        self.assertEqual(result['execution_status'], 'failed')
        self.assertEqual(result['cleanup_status'], 'confirmed')

    def test_other_active_or_unconfirmed_model_owner_refuses(self):
        owner = self.owner()
        backend = owner._Backend(object(), object())
        for status, cleanup in (('running', 'not_required'), ('failed', 'unconfirmed')):
            with self.subTest(status=status), self.assertRaises(ValueError):
                backend.admit_resources({'records': {'x': {'backend': {'kind': backend.kind},
                    'execution_status': status, 'cleanup_status': cleanup}}}, object())

    def test_docker_pid_collision_never_opens_a_foreign_local_pidfd(self):
        owner = self.owner()
        resource = object.__new__(owner._Owner)
        resource.pid, resource.start_ticks, resource.command = 1234, '77', ('python', 'worker')
        resource.pidfd, resource.pid_scope = None, 'docker-daemon'
        with patch('os.readlink', return_value='pid:[unrelated]'), \
                patch('os.pidfd_open') as pidfd:
            resource._bind_direct_host_pid({'namespace_ids': {'pid': 'pid:[owned]'}})
        pidfd.assert_not_called()
        self.assertIsNone(resource.pidfd)
        self.assertEqual(resource.pid_scope, 'docker-daemon')

    def test_image_environment_values_are_cleared_before_controller_start(self):
        owner = self.owner()
        env = owner._container_environment(['HTTP_PROXY=http://inert.invalid', 'LD_PRELOAD=/inert.so',
                                            'AWS_ACCESS_KEY_ID=inert-fixture'])
        self.assertEqual(env['HTTP_PROXY'], '')
        self.assertEqual(env['LD_PRELOAD'], '')
        self.assertEqual(env['AWS_ACCESS_KEY_ID'], '')
        self.assertEqual(env['OMP_NUM_THREADS'], '1')
        with self.assertRaises(ValueError):
            owner._container_environment(['PATH=a', 'PATH=b'])

    def test_actual_environment_order_is_not_authority_and_duplicates_refuse(self):
        owner = self.owner()
        self.assertEqual(owner._observed_environment(['PATH=fixed', 'OMP_NUM_THREADS=1']),
                         owner._observed_environment(['OMP_NUM_THREADS=1', 'PATH=fixed']))
        with self.assertRaises(ValueError):
            owner._observed_environment(['PATH=fixed', 'PATH=other'])
