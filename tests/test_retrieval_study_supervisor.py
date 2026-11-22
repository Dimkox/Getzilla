import importlib
import pickle
import io
import time
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock


class StudySupervisorTests(unittest.TestCase):
    def test_bootstrap_storage_directory_is_actual_unique_empty_owned_context(self):
        owner = self.owner()
        from getzilla.retrieval.study_run_artifacts import RunArtifacts
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            operation = object()
            projection = SimpleNamespace(root=root)
            with RunArtifacts(root, byte_limit=4096) as output:
                actual = object.__new__(owner._Owner)
                actual.operation_ref, actual.execution_id, actual.projection = operation, 'fixture', projection
                actual.admission = SimpleNamespace(execution_generation='generation')
                actual.backend = SimpleNamespace(run_artifact_context=output)
                actual.current = Mock(return_value={'execution_generation': 'generation',
                    'execution_status': 'running', 'output': None})
                with patch.object(owner, '_operation', return_value=projection), \
                        patch.dict(owner._LIVE, {123: actual}, clear=True):
                    observed = owner.reserved_study_output_directory(operation, 'fixture')
                    self.assertEqual(root / observed.relative_path, output._folder)
                    self.assertEqual(observed.inode, output._folder.stat().st_ino)
                    actual.current.return_value['output'] = {'artifact': None}
                    self.assertEqual(owner.reserved_study_output_directory(operation, 'fixture'), observed)
                    with self.assertRaises(ValueError):
                        owner.reserved_study_output_directory(operation, 'other-execution')
                    output.write('not-empty.json', {})
                    with self.assertRaises(ValueError):
                        owner.reserved_study_output_directory(operation, 'fixture')

    def test_bootstrap_directory_refuses_a_replaced_named_inode(self):
        owner = self.owner()
        from getzilla.retrieval.study_run_artifacts import RunArtifacts
        with tempfile.TemporaryDirectory() as temporary:
            root, operation = Path(temporary), object()
            projection = SimpleNamespace(root=root)
            with RunArtifacts(root, byte_limit=4096) as output:
                actual = object.__new__(owner._Owner)
                actual.operation_ref, actual.execution_id, actual.projection = operation, 'fixture', projection
                actual.admission = SimpleNamespace(execution_generation='generation')
                actual.backend = SimpleNamespace(run_artifact_context=output)
                actual.current = Mock(return_value={'execution_generation': 'generation',
                    'execution_status': 'running', 'output': {'artifact': None}})
                output._folder.rename(output._folder.with_name('retained-original'))
                output._folder.mkdir(mode=0o700)
                with patch.object(owner, '_operation', return_value=projection), \
                        patch.dict(owner._LIVE, {123: actual}, clear=True), self.assertRaises(ValueError):
                    owner.reserved_study_output_directory(operation, 'fixture')

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

    def test_rank_deadline_cannot_restart_the_inspection_or_review_budget(self):
        owner = self.owner()
        now = time.monotonic()
        rank = SimpleNamespace(operation='rank_public_study', original_deadline=now + 5.)
        self.assertEqual(owner._bound_execution_deadline(rank, now + 100.), now + 5.)
        self.assertEqual(owner._bound_execution_deadline(rank, now + 2.), now + 2.)
        for value in (None, now - 1., float('inf'), 'caller timestamp'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                owner._bound_execution_deadline(SimpleNamespace(
                    operation='rank_public_study', original_deadline=value), now + 100.)

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
        self.assertIn('--interactive', args)
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
        backend = owner._Backend(object(), SimpleNamespace(operation='inspect_public_artifacts'))
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
        backend = owner._Backend(object(), SimpleNamespace(operation='inspect_public_artifacts'))
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
                patch.object(owner, '_start_ticks', return_value='77'), \
                patch('builtins.open', return_value=io.BytesIO(b'python\0worker\0')), \
                patch.object(owner.select, 'select', return_value=([], [], [])), \
                patch('os.pidfd_open', return_value=42, create=True) as pidfd:
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

    def test_create_side_stdin_and_non_tty_are_rechecked_from_actual_config(self):
        from tests.test_retrieval_study_resources import StudyResourceTests
        owner = self.owner()
        resource = object.__new__(owner._Owner)
        resource.projection = SimpleNamespace(image_id='sha256:' + 'a' * 64,
            cpu_ids=(2, 3), model_root='/fixture/model', software_root='/fixture/software',
            worker_root='/fixture/worker')
        resource.command, resource.expected_env = ('python', 'worker'), {}
        observed = StudyResourceTests().fixture()
        observed['Config'].update(Env=[], OpenStdin=True, Tty=False)
        observed['HostConfig']['RestartPolicy'] = {'Name': 'no'}
        resource.validate_container(observed)
        for key, value in (('OpenStdin', False), ('Tty', True)):
            broken = {**observed, 'Config': {**observed['Config'], key: value}}
            with self.subTest(key=key), self.assertRaises(ValueError):
                resource.validate_container(broken)
