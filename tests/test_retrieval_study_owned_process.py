"""Inert pipe/process doubles only; never execute Docker or model packages."""
from contextlib import ExitStack
import importlib
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class StudyOwnedProcessTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_docker_process')
        except ModuleNotFoundError:
            self.fail('owned Docker transport is missing')

    def fixture(self, owner, stack, raw):
        input_r, input_w = os.pipe()
        output_r, output_w = os.pipe()
        error_r, error_w = os.pipe()
        os.write(output_w, raw)
        os.close(output_w)
        os.close(error_w)
        stack.callback(os.close, input_r)
        process = SimpleNamespace(pid=123456789, returncode=None,
            stdin=os.fdopen(input_w, 'wb', buffering=0),
            stdout=os.fdopen(output_r, 'rb', buffering=0),
            stderr=os.fdopen(error_r, 'rb', buffering=0))
        for stream in (process.stdin, process.stdout, process.stderr):
            stack.callback(stream.close)
        def cleanup(actual):
            self.assertIs(actual, process)
            process.returncode = 0
            return True
        stack.enter_context(patch.object(owner, '_spawn', return_value=process))
        stack.enter_context(patch('os.pidfd_open', side_effect=lambda pid: os.dup(input_r), create=True))
        stack.enter_context(patch('os.P_PIDFD', 3, create=True))
        stack.enter_context(patch('os.waitid', return_value=SimpleNamespace(si_pid=process.pid)))
        stack.enter_context(patch('getzilla.managed_execution._cleanup', side_effect=cleanup))
        return process

    def test_owned_unreaped_handle_drains_then_reaps_only_its_process(self):
        owner = self.owner()
        with ExitStack() as stack:
            process = self.fixture(owner, stack, b'{"waiting":true}\n')
            command = owner.OwnedCommand(Path('.'), object(), ['inspect'])
            stack.callback(command.close)
            self.assertEqual(command.finish(float('inf')), b'{"waiting":true}\n')
            self.assertTrue(command.confirmed)
            self.assertEqual(process.returncode, 0)

    def test_fixed_capture_cap_refuses_without_retaining_excess(self):
        owner = self.owner()
        with ExitStack() as stack:
            self.fixture(owner, stack, b'x' * 128)
            stack.enter_context(patch.object(owner, 'MAX_STDOUT', 16))
            command = owner.OwnedCommand(Path('.'), object(), ['inspect'])
            stack.callback(command.close)
            with self.assertRaisesRegex(ValueError, 'study_worker_output_exceeded'):
                command.finish(float('inf'))
            self.assertLessEqual(len(command.stdout), 16)

    def test_deadline_refuses_and_cleanup_is_idempotent(self):
        owner = self.owner()
        with ExitStack() as stack:
            self.fixture(owner, stack, b'')
            command = owner.OwnedCommand(Path('.'), object(), ['inspect'])
            stack.callback(command.close)
            with self.assertRaisesRegex(ValueError, 'study_docker_deadline'):
                command.finish(0)
            self.assertTrue(command.close())
            self.assertTrue(command.close())

    def test_transport_uses_held_binary_and_fixed_local_daemon_without_shell(self):
        owner = self.owner()
        with patch('getzilla.fsx.owned_popen') as spawn:
            binary = SimpleNamespace(path='/usr/bin/docker', fd=42,
                                     config_directory='/owned/private/empty-client')
            owner._spawn(Path('.'), binary, ['image', 'inspect', 'sha256:' + 'a' * 64])
            arguments, keywords = spawn.call_args
            self.assertEqual(arguments[0][:5], ['/usr/bin/docker', '--config',
                '/owned/private/empty-client', '--host', 'unix:///var/run/docker.sock'])
            self.assertEqual(keywords['executable'], '/proc/self/fd/42')
            self.assertEqual(keywords['pass_fds'], (42,))
            self.assertNotIn('shell', keywords)
            self.assertNotIn('DOCKER_HOST', keywords['env'])
