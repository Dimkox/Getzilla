"""NEW registered-hook fixtures; no Core pipeline, journal, process or filesystem."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import pytest_progress as progress

_ACTIVE = False


def _deny_io(event, args):
    if _ACTIVE and (event == 'open' or event.startswith(('os.', 'socket.', 'subprocess.', 'ctypes.', 'shutil.'))):
        raise AssertionError('registered fixture denies outside/native/network I/O')


sys.addaudithook(_deny_io)


class OwnedHookError(Exception):
    pass


class RegisteredTerminalHooks(unittest.TestCase):
    def dispatch(self, hook, *, failure, worker):
        manager = pytest.PytestPluginManager()
        options = {'getzilla_progress_dir': '/UNREAD-owned-phase-root',
                   'getzilla_progress_nonce': 'a' * 32, 'getzilla_progress_workers': '1',
                   'getzilla_progress_phases': True}
        config = SimpleNamespace(pluginmanager=manager, getoption=lambda name: options[name])
        if worker:
            config.workerinput = {'workerid': 'gw0'}

        class Downstream:
            @pytest.hookimpl
            def pytest_sessionfinish(self, session, exitstatus):
                if failure:
                    raise OwnedHookError('owned fixed downstream error')

            @pytest.hookimpl
            def pytest_terminal_summary(self, terminalreporter, exitstatus, config):
                if failure:
                    raise OwnedHookError('owned fixed downstream error')

        rows = []
        global _ACTIVE
        with patch.object(progress, '_configure_journal', return_value=False), \
                patch.object(progress, '_private_directory', side_effect=OSError('owned phase storage unavailable')), \
                patch.object(progress.os, 'write', side_effect=lambda fd, raw: rows.append((fd, raw)) or len(raw)), \
                patch.object(progress.time, 'monotonic_ns', return_value=123456789):
            _ACTIVE = True
            try:
                progress.pytest_configure(config)  # Actual production registration.
                manager.register(Downstream(), 'owned-downstream')
                arguments = ({'session': None, 'exitstatus': 0} if hook == 'pytest_sessionfinish' else
                             {'terminalreporter': None, 'exitstatus': 0, 'config': config})
                if failure:
                    with self.assertRaises(OwnedHookError):
                        getattr(manager.hook, hook)(**arguments)
                else:
                    getattr(manager.hook, hook)(**arguments)
                self.assertEqual([json.loads(raw)['state'] for _, raw in rows],
                                 ['start', 'error' if failure else 'end'])
                self.assertTrue(all(fd == 2 for fd, _ in rows))
                self.assertLessEqual(sum(len(raw) for _, raw in rows), progress.MAX_PHASE_BYTES)
            finally:
                _ACTIVE = False

    def test_registered_success_reports_end_without_changing_outcome(self):
        for worker in (False, True):
            for hook in ('pytest_sessionfinish', 'pytest_terminal_summary'):
                with self.subTest(worker=worker, hook=hook):
                    self.dispatch(hook, failure=False, worker=worker)

    def test_registered_downstream_failure_reports_error_and_propagates(self):
        for worker in (False, True):
            for hook in ('pytest_sessionfinish', 'pytest_terminal_summary'):
                with self.subTest(worker=worker, hook=hook):
                    self.dispatch(hook, failure=True, worker=worker)


if __name__ == '__main__':
    unittest.main()
