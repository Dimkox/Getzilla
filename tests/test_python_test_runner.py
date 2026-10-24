from __future__ import annotations

import contextlib
import io
from importlib import metadata
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

from getzilla.verification import CheckResult, _python
from getzilla import fsx, python_test_runner, verification
from getzilla.python_test_runner import RunnerError, execute, parallel_engine_ready, selected_workers
from getzilla.verification_scope import FOCUSED_TEST_TARGETS, select_docs_state_scope


@contextlib.contextmanager
def fixture(*, workers: object = 2):
    with tempfile.TemporaryDirectory(prefix='grok-runner-test-') as directory:
        root = Path(directory)
        (root / 'tests').mkdir()
        (root / 'tests/__init__.py').write_text('')
        (root / '.getzilla-test-runner.json').write_text(
            json.dumps({'schema_version': 1, 'workers': workers})
        )
        (root / 'tests/test_sample.py').write_text(
            'import os\nfrom pathlib import Path\nimport unittest\n'
            'class Sample(unittest.TestCase):\n'
            + ''.join(
                f'    def test_{i}(self):\n'
                f'        with Path("result-{i}").open("x") as output:\n'
                f'            output.write(str(os.getpid()))\n'
                for i in range(4)
            )
        )
        environment = os.environ.copy()
        for key in ('GETZILLA_TEST_WORKERS', '_GETZILLA_TEST_CHILD'):
            environment.pop(key, None)
        with patch.dict(os.environ, environment, clear=True), patch(
            'getzilla.verification._ruff',
            return_value=CheckResult('ruff', 'skip', 'no python quality paths'),
        ), patch(
            'getzilla.verification._bandit',
            return_value=CheckResult('bandit', 'skip', 'no non-test python paths'),
        ):
            yield root


@contextlib.contextmanager
def capacity_files(root: Path, files: dict[str, object], *, cpus: int = 22):
    """Supply complete proc/cgroup inputs without consulting this test host."""
    reads: list[str] = []
    real_open = Path.open

    def open_input(path, *args, **kwargs):
        if path == root / python_test_runner.CONFIG:
            return real_open(path, *args, **kwargs)
        name = str(path)
        reads.append(name)
        value = files.get(name, FileNotFoundError(name))
        if isinstance(value, BaseException):
            raise value
        mode = args[0] if args else kwargs.get('mode', 'r')
        return io.BytesIO(value.encode('utf-8')) if 'b' in mode else io.StringIO(value)

    with patch.object(Path, 'open', open_input), \
         patch.object(sys, 'platform', 'linux'), \
         patch.object(os, 'sched_getaffinity', return_value=set(range(cpus)), create=True):
        yield reads


def v2_capacity(*, membership: str = '/team/job', mount_root: str = '/',
                mountpoint: str = '/sys/fs/cgroup') -> dict[str, object]:
    return {
        '/proc/self/cgroup': f'0::{membership}\n',
        '/proc/self/mountinfo': (
            f'32 24 0:28 {mount_root} {mountpoint} rw,nosuid shared:7 - cgroup2 cgroup rw\n'
        ),
    }


def windows_process_running(pid: int, recorded_ns: int) -> bool:
    """Whether the process that recorded ``pid`` at ``recorded_ns`` still runs; a reused pid does not count."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    try:
        if kernel32.WaitForSingleObject(handle, 1000) == 0:  # WAIT_OBJECT_0: exited
            return False
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel32.GetProcessTimes(handle, *(ctypes.byref(item) for item in times)):
            return True
        created = ((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime) * 100 - 11644473600 * 10**9
        return created <= recorded_ns
    finally:
        kernel32.CloseHandle(handle)


class NamedSmokeTests(unittest.TestCase):
    def test_temp_files_a_killed_child_leaves_are_removed_with_the_run(self):
        with fixture() as root, tempfile.TemporaryDirectory() as report_dir:
            report = Path(report_dir) / 'leaked.txt'
            (root / 'tests/test_leak.py').write_text(
                'import os, tempfile, unittest\n'
                'class Leak(unittest.TestCase):\n'
                '    def test_leak(self):\n'
                '        path = tempfile.mkdtemp(prefix="leak-")\n'
                '        open(os.path.join(path, "blob"), "w").write("x")\n'
                '        open(os.environ["LEAK_REPORT"], "w").write(path)\n'
                '        os._exit(0)  # no cleanup runs, as after SIGKILL\n'
            )
            with patch.dict(os.environ, {'LEAK_REPORT': str(report)}):
                python_test_runner.run_named_tests(root, ['tests.test_leak'], budget=30)
            leaked = Path(report.read_text())
            self.assertNotEqual(leaked.parent, Path(tempfile.gettempdir()))
            self.assertFalse(leaked.exists())

    def test_existing_cli_requires_explicit_observation_mode_and_no_record(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/getzilla_verify.py'
        for arguments in (
            ['--test', 'tests.test_named'], ['--mode', 'release', '--no-record', '--test', 'tests.test_named'],
            ['--mode', 'fast', '--test', 'tests.test_named'], ['--mode', 'fast', '--no-record', '--budget', '1'],
            ['--mode', 'fast', '--no-record', '--test', '', '--budget', '1'],
            ['--mode', 'fast', '--no-record', '--test', 'tests.test_named', '--budget', '181'],
        ):
            with self.subTest(arguments=arguments), self.committed_tree() as root:
                proc = subprocess.run([sys.executable, str(script), *arguments], cwd=root,
                                      text=True, capture_output=True, timeout=10)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertFalse((root / '.getzilla/runtime/receipts').exists())
        with self.committed_tree() as root:
            (root / '.git/info/exclude').write_text('.getzilla/runtime/\n')
            receipt = root / '.getzilla/runtime/receipts/verification.json'
            receipt.parent.mkdir(parents=True)
            receipt.write_text('prior evidence')
            proc = subprocess.run([sys.executable, str(script), '--mode', 'fast', '--no-record', '--json',
                                   '--test', 'tests.test_named', '--test', 'tests.test_named.Named.test_named', '--budget', '10'],
                                  cwd=root, text=True, capture_output=True, timeout=15)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(json.loads(proc.stdout)['evidence_status'], 'not_recorded')
            self.assertEqual(receipt.read_text(), 'prior evidence')
            (root / 'dirty.txt').write_text('dirty')
            refused = subprocess.run([sys.executable, str(script), '--mode', 'fast', '--no-record', '--test', 'tests.test_named'],
                                     cwd=root, text=True, capture_output=True, timeout=10)
            self.assertEqual(refused.returncode, 2)
            self.assertIn('clean committed HEAD', refused.stderr)
            self.assertEqual(receipt.read_text(), 'prior evidence')

    @unittest.skipUnless(os.name == 'posix', 'POSIX signal exit status (128 + signal)')
    def test_named_smoke_cancellation_retains_signal_and_identity_without_receipt(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/getzilla_verify.py'
        body = '__import__("os").kill(__import__("os").getppid(), 15); time.sleep(5)'
        with self.committed_tree(body) as root:
            proc = subprocess.run([sys.executable, str(script), '--mode', 'fast', '--no-record', '--json',
                                   '--test', 'tests.test_named', '--budget', '10'],
                                  cwd=root, text=True, capture_output=True, timeout=15)
            self.assertEqual(proc.returncode, 143, proc.stdout + proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report['terminal_state'], 'cancelled')
            self.assertEqual(report['head_before'], report['head_after'])
            self.assertEqual(report['checks'][0]['status'], 'cancelled')
            self.assertEqual(report['checks'][1]['status'], 'pass')
            self.assertFalse((root / '.getzilla/runtime/receipts').exists())

    @contextlib.contextmanager
    def committed_tree(self, body='self.assertEqual(core_marker.VALUE, 42)'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tests').mkdir()
            (root / '.getzilla').mkdir()
            (root / 'tests/__init__.py').write_text('')
            (root / '.getzilla/core_marker.py').write_text('VALUE = 42\n')
            (root / 'tests/test_named.py').write_text(
                'import unittest\nimport core_marker\nimport time\nfrom pathlib import Path\n'
                'class Named(unittest.TestCase):\n    def test_named(self):\n        ' + body + '\n')
            for args in (['init', '-q'], ['config', 'user.name', 'Test'],
                         ['config', 'user.email', 'test@example.com'], ['add', '.'], ['commit', '-qm', 'fixture']):
                subprocess.run(['git', *args], cwd=root, check=True)
            yield root

    def test_named_smoke_uses_core_imports_and_never_records_receipt(self):
        from getzilla.verification import verify_named_tests
        with self.committed_tree() as root:
            receipt = root / '.getzilla/runtime/receipts/verification.json'
            receipt.parent.mkdir(parents=True)
            receipt.write_text('prior evidence')
            # Runtime evidence is ignored as in a real repository.
            (root / '.git/info/exclude').write_text('.getzilla/runtime/\n')
            report = verify_named_tests(root, ['tests.test_named.Named.test_named'], budget=10)
            self.assertEqual(report['status'], 'pass')
            self.assertEqual(report['evidence_status'], 'not_recorded')
            self.assertEqual(report['head_before'], report['head_after'])
            self.assertEqual(report['fingerprint_before'], report['tree_fingerprint'])
            self.assertIn('Ran 1 test', report['checks'][0]['stderr'])
            self.assertEqual(receipt.read_text(), 'prior evidence')

    def test_named_smoke_timeout_failure_and_source_mutation_are_refused(self):
        from getzilla.verification import verify_named_tests
        for body, budget, diagnostic in (
            ('time.sleep(5)', 1, 'timeout'),
            ('self.fail("specific assertion")', 10, 'specific assertion'),
            ('Path("changed.txt").write_text("mutation")', 10, 'repository changed'),
            ('self.assertEqual(__import__("subprocess").call(["git", "commit", "--allow-empty", "-qm", "new head"]), 0)',
             10, 'repository changed'),
        ):
            with self.subTest(body=body), self.committed_tree(body) as root:
                started = time.monotonic()
                report = verify_named_tests(root, ['tests.test_named'], budget=budget)
                self.assertEqual(report['status'], 'fail')
                self.assertLess(time.monotonic() - started, budget + 4)
                self.assertIn(diagnostic, json.dumps(report))
                self.assertFalse((root / '.getzilla/runtime/receipts').exists())

    def test_named_smoke_rejects_dirty_tree_empty_invalid_targets_and_budget(self):
        from getzilla.verification import verify_named_tests
        with self.committed_tree() as root:
            for targets, budget in (([], 10), ([''], 10), (['../test_named'], 10),
                                    (['tests.test_missing'], 10), (['tests.test_named'], 0),
                                    (['tests.test_named'], 181)):
                with self.subTest(targets=targets, budget=budget), self.assertRaises(ValueError):
                    verify_named_tests(root, targets, budget=budget)
            (root / 'dirty.txt').write_text('dirty')
            with self.assertRaisesRegex(ValueError, 'clean committed HEAD'):
                verify_named_tests(root, ['tests.test_named'], budget=10)


@unittest.skipUnless(os.name == 'posix', 'cgroup capacity fixtures name POSIX paths; Windows auto is tested below')
class PythonTestCapacityTests(unittest.TestCase):
    def test_auto_applies_nested_v2_quota_and_tighter_visible_ancestors(self) -> None:
        for leaf, parent, expected in (
            ('200000 100000', 'max 100000', 2),
            ('800000 100000', '200000 100000', 2),
            ('max 100000', '300000 100000', 3),
            ('max 100000', 'max 100000', 22),
            ('50000 100000', 'max 100000', 1),
            ('150000 100000', 'max 100000', 1),
            ('250000 100000', 'max 100000', 2),
        ):
            files = v2_capacity()
            files.update({'/sys/fs/cgroup/team/job/cpu.max': leaf,
                          '/sys/fs/cgroup/team/cpu.max': parent})
            with self.subTest(leaf=leaf, parent=parent), fixture(workers='auto') as root, \
                 capacity_files(root, files) as reads:
                self.assertEqual(selected_workers(root), expected)
                self.assertEqual(set(reads), set(files) | {'/sys/fs/cgroup/cpu.max'})

    def test_auto_intersects_affinity_quota_and_existing_ceiling(self) -> None:
        for cpus, quota, expected in ((2, '800000 100000', 2), (96, 'max 100000', 28),
                                     (96, '250000 100000', 2)):
            files = v2_capacity(membership='/')
            files['/sys/fs/cgroup/cpu.max'] = quota
            with self.subTest(cpus=cpus, quota=quota), fixture(workers='auto') as root, \
                 capacity_files(root, files, cpus=cpus):
                self.assertEqual(selected_workers(root), expected)

    def test_auto_handles_absent_v2_controls_without_skipping_parent(self) -> None:
        for membership, extra, expected in (
            ('/team/job', {'/sys/fs/cgroup/team/cpu.max': '200000 100000'}, 2),
            ('/', {}, 22),
            ('/team/job', {}, 22),
        ):
            files = v2_capacity(membership=membership)
            files.update(extra)
            with self.subTest(membership=membership, extra=extra), fixture(workers='auto') as root, \
                 capacity_files(root, files):
                self.assertEqual(selected_workers(root), expected)

    def test_auto_maps_mount_roots_escapes_and_component_boundaries(self) -> None:
        for membership, mount_root, mountpoint, leaf, expected in (
            ('/slice/job', '/slice', '/cgroup', '/cgroup/job/cpu.max', 2),
            ('/slice/job', '/slice', '/cpu\\040space', '/cpu space/job/cpu.max', 2),
            ('/slice/job', '/slice', '/cpu\\134name', '/cpu\\name/job/cpu.max', 2),
            ('/teammate/job', '/team', '/cgroup', None, 1),
            ('/', '/host/slice', '/cgroup', None, 1),
            ('/../job', '/', '/cgroup', None, 1),
            ('/', '/..', '/cgroup', None, 1),
            ('/team/./job', '/', '/cgroup', None, 1),
        ):
            files = v2_capacity(membership=membership, mount_root=mount_root, mountpoint=mountpoint)
            if leaf:
                files[leaf] = '200000 100000'
            with self.subTest(membership=membership, mountpoint=mountpoint), \
                 fixture(workers='auto') as root, capacity_files(root, files) as reads:
                self.assertEqual(selected_workers(root), expected)
                if leaf:
                    self.assertEqual(set(reads), set(files) | {str(Path(leaf).parent.parent / 'cpu.max')})
                else:
                    self.assertEqual(set(reads), {'/proc/self/cgroup', '/proc/self/mountinfo'})

    def test_auto_checks_wider_mount_even_when_bind_subtree_appears_first(self) -> None:
        files = v2_capacity(membership='/team/job')
        files['/proc/self/mountinfo'] = (
            '40 24 0:28 /team/job /bind rw - cgroup2 cgroup rw\n'
            + files['/proc/self/mountinfo']
            + '41 24 0:28 /sibling /irrelevant rw - cgroup2 cgroup rw\n'
        )
        files.update({'/bind/cpu.max': 'max 100000',
                      '/sys/fs/cgroup/team/job/cpu.max': 'max 100000',
                      '/sys/fs/cgroup/team/cpu.max': '200000 100000',
                      '/irrelevant/cpu.max': '100000 100000'})
        with fixture(workers='auto') as root, capacity_files(root, files) as reads:
            self.assertEqual(selected_workers(root), 2)
            self.assertNotIn('/irrelevant/cpu.max', reads)
            self.assertNotIn('/cpu.max', reads)

    def test_auto_resolves_v1_cpu_controller_in_combined_and_hybrid_layouts(self) -> None:
        for hybrid in (False, True):
            files = {
                '/proc/self/cgroup': '7:cpu,cpuacct:/slice/job\n9:cpuset:/other\n',
                '/proc/self/mountinfo': (
                    '31 24 0:27 /slice /cpu-mount rw - cgroup cgroup rw,cpuacct,cpu\n'
                    '33 24 0:29 / /not-cpu rw - cgroup cgroup rw,cpuset\n'
                ),
                '/cpu-mount/job/cpu.cfs_quota_us': '-1\n',
                '/cpu-mount/job/cpu.cfs_period_us': '100000\n',
                '/cpu-mount/cpu.cfs_quota_us': '250000\n',
                '/cpu-mount/cpu.cfs_period_us': '100000\n',
            }
            if hybrid:
                files['/proc/self/cgroup'] += '0::/unified\n'
                files['/proc/self/mountinfo'] += '32 24 0:28 / /v2 rw - cgroup2 cgroup rw\n'
                files['/v2/unified/cpu.max'] = '100000 100000'
            with self.subTest(hybrid=hybrid), fixture(workers='auto') as root, \
                 capacity_files(root, files) as reads:
                self.assertEqual(selected_workers(root), 2)
                self.assertEqual(set(reads), {name for name in files if not name.startswith('/v2')})

    def test_auto_distinguishes_v1_unlimited_missing_and_invalid_pairs(self) -> None:
        for quota, period, expected in (
            ('-1', '100000', 22), ('250000', '100000', 2), ('50000', '100000', 1),
            ('-2', '100000', 1), ('0', '100000', 1), ('2', '0', 1),
            ('100000', None, 1), (None, '100000', 1), ('1 2', '100000', 1),
        ):
            files = {'/proc/self/cgroup': '7:cpu:/\n',
                     '/proc/self/mountinfo': '31 24 0:27 / /cpu rw - cgroup cgroup rw,cpu\n'}
            if quota is not None:
                files['/cpu/cpu.cfs_quota_us'] = quota
            if period is not None:
                files['/cpu/cpu.cfs_period_us'] = period
            with self.subTest(quota=quota, period=period), fixture(workers='auto') as root, \
                 capacity_files(root, files):
                self.assertEqual(selected_workers(root), expected)

    def test_auto_uses_one_worker_for_unknown_or_malformed_relevant_evidence(self) -> None:
        for value in ('', 'max', 'max 0', '0 100000', '-1 100000', '2 nope', '2 1 extra',
                      '１２ １００', '2.5 1', PermissionError('unreadable'), '9' * 8192):
            files = v2_capacity()
            files.update({'/sys/fs/cgroup/team/job/cpu.max': '800000 100000',
                          '/sys/fs/cgroup/team/cpu.max': value})
            with self.subTest(value=str(value)[:40]), fixture(workers='auto') as root, \
                 capacity_files(root, files):
                self.assertEqual(selected_workers(root), 1)
        for path, value in (
            ('/proc/self/cgroup', FileNotFoundError('missing')),
            ('/proc/self/mountinfo', PermissionError('unreadable')),
            ('/proc/self/cgroup', '0::/team/job\n0::/different\n'),
            ('/proc/self/cgroup', '0:cpu:/team/job\n'),
            ('/proc/self/cgroup', 'broken\n'),
            ('/proc/self/mountinfo', '32 24 0:28 / /cpu rw - cgroup2\n'),
            ('/proc/self/mountinfo', '32 24 invalid / /cpu rw - cgroup2 cgroup rw\n'),
            ('/proc/self/mountinfo', '32 24 0:28 / /cpu\\999 rw - cgroup2 cgroup rw\n'),
            ('/proc/self/mountinfo',
             '32 24 0:28 / /cpu rw - cgroup2 cgroup rw\n'
             '33 24 0:29 / /other rw - cgroup2 cgroup rw\n'),
            ('/proc/self/mountinfo', 'x' * (1024 * 1024 + 1)),
        ):
            files = v2_capacity()
            files[path] = value
            with self.subTest(path=path, value=str(value)[:40]), fixture(workers='auto') as root, \
                 capacity_files(root, files):
                self.assertEqual(selected_workers(root), 1)

    def test_auto_bounds_hierarchy_depth_and_mount_count(self) -> None:
        for kind in ('deep', 'mounts'):
            files = v2_capacity(membership='/' + '/'.join(['x'] * 2048) if kind == 'deep' else '/')
            if kind == 'mounts':
                files['/proc/self/mountinfo'] = ''.join(
                    f'{i + 32} 24 0:28 / /cpu-{i} rw - cgroup2 cgroup rw\n' for i in range(2048)
                )
            with self.subTest(kind=kind), fixture(workers='auto') as root, \
                 capacity_files(root, files) as reads:
                self.assertEqual(selected_workers(root), 1)
                self.assertLessEqual(len(reads), 1024)
        files = v2_capacity(membership='/' + '/'.join(['x'] * 64))
        files['/proc/self/mountinfo'] = ''.join(
            f'{i + 32} 24 0:28 / /cpu-{i} rw - cgroup2 cgroup rw\n' for i in range(17)
        )
        with fixture(workers='auto') as root, capacity_files(root, files) as reads:
            self.assertEqual(selected_workers(root), 1)
            self.assertLessEqual(len(reads), 1026)

    def test_explicit_default_child_and_other_platform_paths_avoid_capacity_reads(self) -> None:
        for configured, override, child, expected in (
            (0, None, False, 0), (64, None, False, 64), (2, '64', False, 64),
            ('auto', '0', False, 0), ('auto', None, True, 0),
        ):
            with self.subTest(configured=configured, override=override, child=child), \
                 fixture(workers=configured) as root, capacity_files(root, {}) as reads:
                env = {'_GETZILLA_TEST_CHILD': '1'} if child else {}
                if override is not None:
                    env['GETZILLA_TEST_WORKERS'] = override
                with patch.dict(os.environ, env):
                    self.assertEqual(selected_workers(root), expected)
                self.assertEqual(reads, [])
        with fixture() as root:
            (root / python_test_runner.CONFIG).unlink()
            with capacity_files(root, {}) as reads:
                self.assertIsNone(selected_workers(root))
                self.assertEqual(reads, [])
        with fixture(workers='auto') as root, capacity_files(root, {}) as reads, \
             patch.object(sys, 'platform', 'darwin'):
            self.assertEqual(selected_workers(root), 22)
            self.assertEqual(reads, [])
        with fixture(workers='auto') as root, capacity_files(root, {}) as reads, \
             patch.object(python_test_runner, '_parallel_process_cleanup_supported', return_value=False):
            self.assertEqual(selected_workers(root), 0)
            self.assertEqual(reads, [])

    def test_environment_auto_uses_quota_and_affinity_errors_use_cpu_count(self) -> None:
        files = v2_capacity(membership='/')
        files['/sys/fs/cgroup/cpu.max'] = '200000 100000'
        with fixture(workers=64) as root, capacity_files(root, files), \
             patch.dict(os.environ, {'GETZILLA_TEST_WORKERS': 'auto'}):
            self.assertEqual(selected_workers(root), 2)
        for cpus, expected in ((4, 4), (None, 1)):
            with self.subTest(cpus=cpus), fixture(workers='auto') as root, \
                 capacity_files(root, v2_capacity(membership='/')), \
                 patch.object(os, 'sched_getaffinity', side_effect=OSError('unavailable')), \
                 patch.object(os, 'cpu_count', return_value=cpus):
                self.assertEqual(selected_workers(root), expected)


class PythonTestRunnerTests(unittest.TestCase):
    def test_child_scope_does_not_inherit_controller_override(self) -> None:
        code = (
            'import json, os\nfrom pathlib import Path\n'
            'from getzilla.python_test_runner import selected_workers\n'
            'from getzilla.verification_scope import FOCUSED_TEST_TARGETS, select_docs_state_scope\n'
            'def scope():\n'
            '    return select_docs_state_scope("pr", ["README.md"], range_base_count=1,\n'
            '        file_statuses=[{"status": "M", "path": "README.md"}],\n'
            '        status_inventory_trusted=True, available_test_targets=FOCUSED_TEST_TARGETS)\n'
            'observed = {"override": os.environ.get("GETZILLA_VERIFY_FORCE_FULL"),\n'
            '    "scope": scope()["reason_code"], "workers": selected_workers(Path.cwd()),\n'
            '    "environment": {key: os.environ.get(key) for key in (\n'
            '        "RUNNER_MARKER", "GETZILLA_RUNNER_MARKER", "GETZILLA_VERIFY_CAPABILITY",\n'
            '        "GETZILLA_TEST_WORKERS", "_GETZILLA_TEST_CHILD", "PYTEST_ADDOPTS",\n'
            '        "PYTEST_PLUGINS", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "COVERAGE_PROCESS_START",\n'
            '        "COV_CORE_SOURCE", "COVERAGE_FILE", "PYTHONDONTWRITEBYTECODE", "PYTHONPATH")}}\n'
            'os.environ["GETZILLA_VERIFY_FORCE_FULL"] = "1"\n'
            'observed["test_owned_scope"] = scope()["reason_code"]\n'
            'print(json.dumps(observed))\n'
        )
        for override in ('1', None):
            with self.subTest(override=override), fixture() as root, patch.dict(os.environ, {
                'RUNNER_MARKER': 'ordinary', 'GETZILLA_RUNNER_MARKER': 'retained',
                'GETZILLA_VERIFY_CAPABILITY': 'required', 'GETZILLA_TEST_WORKERS': '2',
                '_GETZILLA_TEST_CHILD': '0', 'PYTEST_ADDOPTS': '--bad-option',
                'PYTEST_PLUGINS': 'unwanted_plugin', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '0',
                'COVERAGE_PROCESS_START': 'parent.rc', 'COV_CORE_SOURCE': 'parent-source',
                'COVERAGE_FILE': 'parent.coverage', 'PYTHONDONTWRITEBYTECODE': '0',
                'PYTHONPATH': str(Path(__file__).resolve().parents[1] / '.getzilla'),
            }):
                if override is None:
                    os.environ.pop('GETZILLA_VERIFY_FORCE_FULL', None)
                else:
                    os.environ['GETZILLA_VERIFY_FORCE_FULL'] = override
                parent = dict(os.environ)
                data_file = root / '.coverage-child'
                result = execute([sys.executable, '-c', code], root,
                                 python_test_runner._environment(root, data_file), timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(dict(os.environ), parent)
                parent_scope = select_docs_state_scope(
                    'pr', ['README.md'], range_base_count=1,
                    file_statuses=[{'status': 'M', 'path': 'README.md'}],
                    status_inventory_trusted=True, available_test_targets=FOCUSED_TEST_TARGETS,
                )
                self.assertEqual(parent_scope['reason_code'], 'operator-override' if override else 'eligible')
                self.assertEqual(parent_scope['profile'], 'full-pr-suite' if override else 'docs-state-focused')
                self.assertEqual(json.loads(result.stdout), {
                    'override': None, 'scope': 'eligible', 'workers': 0,
                    'test_owned_scope': 'operator-override',
                    'environment': {
                        'RUNNER_MARKER': 'ordinary', 'GETZILLA_RUNNER_MARKER': 'retained',
                        'GETZILLA_VERIFY_CAPABILITY': 'required', 'GETZILLA_TEST_WORKERS': None,
                        '_GETZILLA_TEST_CHILD': '1', 'PYTEST_ADDOPTS': None, 'PYTEST_PLUGINS': None,
                        'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1', 'COVERAGE_PROCESS_START': None,
                        'COV_CORE_SOURCE': None, 'COVERAGE_FILE': str(data_file),
                        'PYTHONDONTWRITEBYTECODE': '1',
                        'PYTHONPATH': os.pathsep.join((str(root), str(root / 'tests'),
                                                      str(root / '.getzilla'), parent['PYTHONPATH'])),
                    },
                })

    def assert_descendant_stopped(self, pid_file: Path) -> None:
        if os.name == 'nt':
            if windows_process_running(int(pid_file.read_text()), pid_file.stat().st_mtime_ns):
                self.fail('owned descendant continued after process cleanup')
            return
        if sys.platform != 'linux':
            self.skipTest('descendant verification reads /proc on Linux or process handles on Windows')
        status = Path('/proc') / pid_file.read_text() / 'status'
        for _ in range(100):
            try:
                if 'Z (zombie)' in status.read_text():
                    return
            except FileNotFoundError:
                return
            time.sleep(0.01)
        self.fail('owned descendant continued after process cleanup')

    def test_trust_cli_uses_own_imports_and_keeps_each_file_on_one_worker(self) -> None:
        for workers in (2, 0):
            with self.subTest(workers=workers), fixture(workers=workers) as root:
                trust = root / 'trust-ci'
                (trust / 'src').mkdir(parents=True)
                (trust / 'src/subject.py').write_text('value = 42\n')
                (trust / 'tests').mkdir()
                (trust / 'tests/__init__.py').write_text('')
                (trust / 'tests/_support.py').write_text('from subject import value\n')
                (trust / 'pytest.ini').write_text('[pytest]\naddopts = -k test_0\n')
                for name in ('alpha', 'beta'):
                    (trust / f'tests/test_{name}.py').write_text(
                        'import os, unittest\nfrom pathlib import Path\nfrom _support import value\n'
                        'class T(unittest.TestCase):\n'
                        + ''.join(
                            f' def test_{i}(self):\n'
                            f'  self.assertEqual(value, 42)\n'
                            f'  with Path("{name}-{i}.pid").open("x") as output:\n'
                            f'   output.write(str(os.getpid()))\n'
                            for i in range(3)
                        )
                    )
                command = [sys.executable, '-m', 'getzilla.python_test_runner', '--suite', 'trust-ci']
                environment = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / '.getzilla')}
                result = execute(command, root, environment)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual({p.name for p in trust.glob('*.pid')},
                                 {f'{name}-{i}.pid' for name in ('alpha', 'beta') for i in range(3)})
                for name in ('alpha', 'beta'):
                    self.assertEqual(len({p.read_text() for p in trust.glob(f'{name}-*.pid')}), 1)
                effective, engine = python_test_runner.select_engine(workers, measured=False)
                self.assertIn(f'requested_workers={workers}; workers={effective}; engine={engine}', result.stdout)
                self.assertFalse(list(root.glob('result-*')), 'Core tests must not be collected by Trust CI')
                (trust / 'tests/test_alpha.py').write_text('raise RuntimeError("expected collection failure")\n')
                failed = execute(command, root, environment)
                self.assertNotEqual(failed.returncode, 0)

    def test_unittest_filename_pattern_is_preserved(self) -> None:
        with fixture() as root:
            (root / 'tests/test_sample.py').rename(root / 'tests/testsample.py')
            result = next(check for check in _python(root) if check.name == 'python-unittest')
            self.assertEqual(result.status, 'pass', result.stdout + result.stderr)
            self.assertEqual(len(list(root.glob('result-*'))), 4)

    def test_absent_opt_in_and_private_child_flag_preserve_consumer(self) -> None:
        with fixture() as root:
            (root / '.getzilla-test-runner.json').unlink()
            with patch.dict(os.environ, {'_GETZILLA_TEST_CHILD': '1'}):
                self.assertIsNone(selected_workers(root))
                result = next(check for check in _python(root) if check.name == 'python-unittest')
            self.assertEqual(result.status, 'pass', result.stderr)
            self.assertEqual(len({p.read_text() for p in root.glob('result-*')}), 1)

    def test_serial_rollback_and_child_cap_do_not_start_a_pool(self) -> None:
        with fixture() as root:
            with patch.dict(os.environ, {'GETZILLA_TEST_WORKERS': '0'}):
                result = next(check for check in _python(root) if check.name == 'python-unittest')
            self.assertEqual(result.status, 'pass', result.stderr)
            self.assertEqual(len({p.read_text() for p in root.glob('result-*')}), 1)
            with patch.dict(os.environ, {'_GETZILLA_TEST_CHILD': '1', 'GETZILLA_TEST_WORKERS': '22'}):
                self.assertEqual(selected_workers(root), 0)

    def test_auto_runs_serially_without_owned_tree_cleanup(self) -> None:
        with fixture(workers='auto') as root, \
             patch.object(python_test_runner, '_parallel_process_cleanup_supported', return_value=False):
            self.assertEqual(selected_workers(root), 0)
            self.assertEqual(python_test_runner.select_engine(4, True), (0, 'unittest-degraded'))
            with self.assertRaisesRegex(RunnerError, 'requires POSIX sessions or Windows Job Objects'):
                python_test_runner._pytest_command(4, 'worksteal')

    def test_windows_auto_counts_logical_cpus_without_cgroup_reads(self) -> None:
        # Windows has no sched_getaffinity and no cgroups: auto is the bounded CPU count.
        for cpus, expected in ((8, 8), (96, 28), (None, 1)):
            with self.subTest(cpus=cpus), fixture(workers='auto') as root, \
                 capacity_files(root, {}) as reads, \
                 patch.object(sys, 'platform', 'win32'), \
                 patch.object(os, 'sched_getaffinity', side_effect=AttributeError, create=True), \
                 patch.object(os, 'cpu_count', return_value=cpus), \
                 patch.object(python_test_runner, '_parallel_process_cleanup_supported', return_value=True):
                self.assertEqual(selected_workers(root), expected)
                self.assertEqual(reads, [])

    @unittest.skipUnless(os.name == 'nt', 'Windows Job Object capability')
    def test_windows_job_objects_select_parallel_engine(self) -> None:
        self.assertTrue(fsx.process_jobs_supported())
        self.assertTrue(python_test_runner._parallel_process_cleanup_supported())
        with fixture(workers='auto') as root:
            self.assertEqual(selected_workers(root), min(28, os.cpu_count() or 1))
        expected = (4, 'pytest-xdist') if parallel_engine_ready(False) else (0, 'unittest-degraded')
        self.assertEqual(python_test_runner.select_engine(4, False), expected)
        command = python_test_runner._pytest_command(4, 'worksteal')
        self.assertEqual(command[command.index('-n') + 1], '4')

    @unittest.skipUnless(os.name == 'nt', 'Windows Job Object')
    def test_windows_job_holds_descendants_until_terminated(self) -> None:
        with tempfile.TemporaryDirectory(prefix='grok-runner-job-') as directory:
            pid_file = Path(directory) / 'grandchild.pid'
            grandchild = (f'import os, time; open({str(pid_file)!r} + ".tmp", "w").write(str(os.getpid())); '
                          f'os.replace({str(pid_file)!r} + ".tmp", {str(pid_file)!r}); time.sleep(60)')
            code = f'import subprocess, sys, time\nsubprocess.Popen([sys.executable, "-c", {grandchild!r}])\ntime.sleep(60)\n'
            process = fsx.owned_popen([sys.executable, '-c', code])
            job = fsx.owned_job(process)
            self.assertIsNotNone(job)
            try:
                deadline = time.monotonic() + 20
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pid_file.exists(), 'grandchild did not start')
                # A venv python.exe is a launcher with its own child, so count at least two.
                self.assertGreaterEqual(job.active_processes(), 2)
                self.assertTrue(job.terminate(5))
                self.assertEqual(job.active_processes(), 0)
                self.assertEqual(process.wait(timeout=5), 1)
            finally:
                job.close()
            self.assert_descendant_stopped(pid_file)
        job.close()
        self.assertTrue(job.terminate(1))
        self.assertEqual(job.active_processes(), 0)

    @unittest.skipUnless(os.name == 'nt', 'Windows Job Object')
    def test_windows_job_assignment_failure_kills_the_suspended_child(self) -> None:
        started: list[subprocess.Popen] = []
        real_popen = subprocess.Popen

        def popen(*args, **kwargs):
            started.append(real_popen(*args, **kwargs))
            return started[-1]

        with fixture() as root, patch.object(subprocess, 'Popen', side_effect=popen), \
             patch.object(fsx.ProcessJob, 'assign_suspended', side_effect=OSError(5, 'assignment refused')):
            result = execute([sys.executable, '-c', 'open("ran", "x").close()'], root, os.environ.copy())
            self.assertEqual(result.returncode, 127)
            self.assertIn('assignment refused', result.stderr)
            self.assertEqual(len(started), 1)
            self.assertIsNotNone(started[0].returncode)
            self.assertFalse((root / 'ran').exists(), 'a child outside its job must never run')

    @unittest.skipUnless(os.name == 'posix', 'cgroup capacity fixtures name POSIX paths; Windows auto is tested above')
    def test_auto_uses_available_logical_cpus_with_a_bound(self) -> None:
        with fixture(workers='auto') as root:
            with capacity_files(root, v2_capacity(membership='/'), cpus=22):
                self.assertEqual(selected_workers(root), 22)
            with capacity_files(root, v2_capacity(membership='/'), cpus=96):
                self.assertEqual(selected_workers(root), 28)

    def test_unimportable_parallel_engine_degrades_to_one_serial_pass(self) -> None:
        # Retake of defect 33: an interpreter that cannot import the xdist engine
        # (the Trust CI image case) must run one disclosed sequential pass, not fail.
        with fixture() as root:
            with patch('importlib.util.find_spec', return_value=None):
                result = next(check for check in _python(root) if check.name == 'python-unittest')
            self.assertEqual(result.status, 'pass', result.stderr + result.stdout)
            self.assertEqual(len(list(root.glob('result-*'))), 4)
            self.assertEqual(len({p.read_text() for p in root.glob('result-*')}), 1)
            self.assertIn('unittest-degraded', result.details[0]['versions'])

    # Retained PR135 regressions originate at 7a7851af5d11e8ce5c3af23ab46214ae7ae4cdc8.
    def test_non_posix_cleanup_capability_degrades_core_and_trust_before_launch(self) -> None:
        # Emulate Windows through the runner capability seam, without changing
        # os.name globally (which would alter pathlib and subprocess behavior).
        with fixture() as root, \
             patch.object(python_test_runner, '_parallel_process_cleanup_supported',
                          return_value=False, create=True), \
             patch.object(python_test_runner, 'parallel_engine_ready', return_value=True), \
             patch.object(python_test_runner.metadata, 'version',
                          side_effect=lambda name: python_test_runner.PINS[name]):
            self.assertEqual(python_test_runner.select_engine(2, measured=False),
                             (0, 'unittest-degraded'))
            core = python_test_runner.run_core_tests(root, 'fast', 2)
            self.assertEqual(core.tests.returncode, 0, core.tests.stdout + core.tests.stderr)
            self.assertEqual(core.workers, 0)
            self.assertEqual(core.versions['engine'], 'unittest-degraded')
            self.assertEqual(core.tests.command[1:4], ['-m', 'unittest', 'discover'])
            self.assertEqual({p.name for p in root.glob('result-*')}, {f'result-{i}' for i in range(4)})
            self.assertEqual(len({p.read_text() for p in root.glob('result-*')}), 1)

            trust = root / 'trust-ci'
            (trust / 'tests').mkdir(parents=True)
            (trust / 'tests/test_trust.py').write_text(
                'import unittest\nclass Trust(unittest.TestCase):\n'
                ' def test_pass(self): self.assertTrue(True)\n'
            )
            result = python_test_runner.run_trust_tests(root, 2)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.command[1:4], ['-m', 'unittest', 'discover'])
            self.assertEqual(python_test_runner.select_engine(0, measured=False), (0, 'unittest'))

            output = io.StringIO()
            with patch.object(Path, 'cwd', return_value=root), \
                 patch.object(sys, 'argv', ['python_test_runner', '--suite', 'trust-ci']), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(python_test_runner.main(), 0)
            self.assertIn('workers=0; engine=unittest-degraded', output.getvalue())

    def test_cleanup_capability_keeps_xdist_and_strict_pins(self) -> None:
        with patch.object(python_test_runner, '_parallel_process_cleanup_supported',
                          return_value=True, create=True), \
             patch.object(python_test_runner, 'parallel_engine_ready', return_value=True):
            self.assertEqual(python_test_runner.select_engine(2, measured=True), (2, 'pytest-xdist'))
        for distribution in ('worksteal', 'loadfile'):
            with self.subTest(distribution=distribution):
                command = python_test_runner._pytest_command(2, distribution)
                self.assertEqual(command[command.index('-n') + 1], '2')
                self.assertIn(f'--dist={distribution}', command)
                # Windows '-c nul' would leave collection unbounded above the project root.
                self.assertEqual('--confcutdir=.' in command, os.name == 'nt')

    def test_measured_core_uses_parallel_coverage_without_xdist_pins(self) -> None:
        with fixture() as root:
            (root / 'subject.py').write_text('value = 42\n')
            sample = root / 'tests/test_sample.py'
            sample.write_text('import subject\n' + sample.read_text())
            (root / '.coveragerc').write_text(
                '[run]\nbranch = True\nsource = subject\n[report]\nfail_under = 74\n'
            )
            real_version = metadata.version

            def coverage_only_version(name):
                if name != 'coverage':
                    raise AssertionError(f'unexpected dependency pin check: {name}')
                return real_version(name)

            def fake_parallel(_root, _config, data_file, workers, _environment):
                data_file.write_bytes(b'current-run-coverage')
                return python_test_runner.ProcessResult(['parallel-coverage'], 0, seconds=0.01)

            def fake_execute(command, _root, _environment, timeout=python_test_runner.TIMEOUT):
                if command[3] == 'json':
                    Path(command[command.index('-o') + 1]).write_text(json.dumps({
                        'meta': {'branch_coverage': True},
                        'files': {'subject.py': {}},
                        'totals': {'covered_lines': 1},
                    }))
                return python_test_runner.ProcessResult(list(command), 0, seconds=0.01)

            with patch.object(python_test_runner, '_parallel_process_cleanup_supported',
                              return_value=True, create=True), \
                 patch.object(python_test_runner, 'parallel_engine_ready', return_value=False), \
                 patch.object(python_test_runner.metadata, 'version', side_effect=coverage_only_version), \
                 patch.object(python_test_runner, '_parallel_coverage_unittest', side_effect=fake_parallel), \
                 patch.object(python_test_runner, 'execute', side_effect=fake_execute):
                core = python_test_runner.run_core_tests(root, 'pr', 2)
            self.assertEqual(core.tests.returncode, 0, core.tests.stdout + core.tests.stderr)
            self.assertEqual(core.tests.command, ['parallel-coverage'])
            self.assertEqual(core.workers, 2)
            self.assertEqual(core.versions, {'coverage': real_version('coverage'),
                                             'engine': 'coverage-unittest-parallel'})
            self.assertIsNotNone(core.coverage)
            self.assertEqual(core.coverage.returncode, 0, core.coverage.stdout + core.coverage.stderr)
            self.assertTrue(core.coverage_metadata['files'])

    def test_empty_serial_core_and_trust_collection_cannot_pass(self) -> None:
        for workers in (0, 2):
            for suite in ('core', 'trust'):
                with self.subTest(workers=workers, suite=suite), fixture() as root, \
                     patch.object(python_test_runner, 'parallel_engine_ready', return_value=False):
                    tests = root / 'tests' if suite == 'core' else root / 'trust-ci/tests'
                    tests.mkdir(parents=True, exist_ok=True)
                    (tests / 'test_sample.py').write_text('# deliberately empty collection\n')
                    result = (python_test_runner.run_core_tests(root, 'fast', workers).tests
                              if suite == 'core' else python_test_runner.run_trust_tests(root, workers))
                    self.assertIn('Ran 0 tests', result.stderr)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_empty_measured_serial_collection_cannot_qualify_import_coverage(self) -> None:
        for workers in (0, 2):
            with self.subTest(workers=workers), fixture() as root, \
                 patch.object(python_test_runner, 'parallel_engine_ready', return_value=False):
                (root / 'subject.py').write_text('value = 42\n')
                (root / 'tests/test_sample.py').write_text('import subject\n')
                (root / '.coveragerc').write_text(
                    '[run]\nbranch = True\nsource = subject\n[report]\nfail_under = 74\n'
                )
                core = python_test_runner.run_core_tests(root, 'pr', workers)
                self.assertIn('Ran 0 tests', core.tests.stderr)
                self.assertNotEqual(core.tests.returncode, 0, core.tests.stdout + core.tests.stderr)
                self.assertIsNotNone(core.coverage)
                self.assertNotEqual(core.coverage.returncode, 0, core.coverage.stdout + core.coverage.stderr)

    def test_degraded_serial_failures_propagate_without_retry(self) -> None:
        for source in (
            'import unittest\nclass T(unittest.TestCase):\n def test_bad(self): self.fail("expected")\n',
            'raise RuntimeError("collection failure")\n',
            'import os, unittest\nclass T(unittest.TestCase):\n def test_exit(self): os._exit(86)\n',
        ):
            for suite in ('core', 'trust'):
                with self.subTest(source=source, suite=suite), fixture() as root, \
                     patch.object(python_test_runner, 'parallel_engine_ready', return_value=False), \
                     patch.object(python_test_runner, 'execute', wraps=execute) as launched:
                    directory = root if suite == 'core' else root / 'trust-ci'
                    tests = directory / 'tests'
                    tests.mkdir(parents=True, exist_ok=True)
                    (tests / 'test_sample.py').write_text(
                        'from pathlib import Path\nPath("collection-attempt").touch(exist_ok=False)\n' + source
                    )
                    result = (python_test_runner.run_core_tests(root, 'fast', 2).tests
                              if suite == 'core' else python_test_runner.run_trust_tests(root, 2))
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue((directory / 'collection-attempt').is_file())
                    self.assertEqual(launched.call_count, 1)

    def test_degraded_serial_preserves_nested_pattern_and_single_collection(self) -> None:
        with fixture() as root, \
             patch.object(python_test_runner, 'parallel_engine_ready', return_value=False):
            sample = root / 'tests/test_sample.py'
            sample.write_text('from pathlib import Path\nPath("collected-once").touch(exist_ok=False)\n'
                              + sample.read_text())
            sample.rename(root / 'tests/testsample.py')
            nested = root / 'tests/nested'
            nested.mkdir()
            (nested / '__init__.py').write_text('')
            (nested / 'test_nested.py').write_text(
                'import unittest\nfrom pathlib import Path\nclass Nested(unittest.TestCase):\n'
                ' def test_nested(self): Path("result-nested").touch(exist_ok=False)\n'
            )
            result = python_test_runner.run_core_tests(root, 'fast', 2)
            self.assertEqual(result.tests.returncode, 0, result.tests.stdout + result.tests.stderr)
            self.assertEqual({p.name for p in root.glob('result-*')},
                             {f'result-{i}' for i in range(4)} | {'result-nested'})
            self.assertTrue((root / 'collected-once').is_file())

    def test_importable_but_wrong_versioned_parallel_dependency_still_fails(self) -> None:
        # Degradation is capability-only: with the engine importable, the declared
        # pinned contract stays strict — missing/mismatched versions fail, no serial retry.
        with fixture() as root:
            for label, version_effect in (
                ('missing', metadata.PackageNotFoundError),
                ('mismatched', lambda _name: '0.0.1'),
            ):
                with self.subTest(pinning=label), \
                     patch('getzilla.python_test_runner.parallel_engine_ready', return_value=True), \
                     patch('getzilla.python_test_runner._parallel_process_cleanup_supported', return_value=True), \
                     patch('getzilla.python_test_runner.metadata.version', side_effect=version_effect):
                    result = next(check for check in _python(root) if check.name == 'python-unittest')
                self.assertEqual(result.status, 'fail', label)
                self.assertIn('python-test-requirements.txt' if label == 'missing' else 'requires tested version',
                              result.summary)
                self.assertFalse(list(root.glob('result-*')))

    def test_repo_root_without_optin_uses_measured_parallel_coverage_fallback(self) -> None:
        # The Trust CI image lacks pytest/xdist, so measured PR verification must still
        # avoid the legacy serial coverage timeout without requiring a repo-local opt-in file.
        repo_root = Path(__file__).resolve().parents[1]
        self.assertFalse((repo_root / '.getzilla-test-runner.json').exists())
        # This assertion covers the default, not an inherited explicit opt-in.
        with patch.dict(os.environ):
            os.environ.pop('GETZILLA_TEST_WORKERS', None)
            os.environ.pop('_GETZILLA_TEST_CHILD', None)
            self.assertIsNone(selected_workers(repo_root))

        class Core:
            tests = python_test_runner.ProcessResult(['parallel'], 0)
            coverage = python_test_runner.ProcessResult(['coverage'], 0)
            workers = 2
            versions = {'coverage': python_test_runner.PINS['coverage'], 'engine': 'coverage-unittest-parallel'}
            coverage_metadata = {'files': ['.getzilla/getzilla/python_test_runner.py']}

        real_command_check = verification._command_check

        def without_pilot(root, name, *args, **kwargs):
            # The pilot suite is its own check (it does not pass on Windows yet); this test is about Core wiring.
            if name == 'pilot-unittest':
                return CheckResult(name, 'pass', 'fixture')
            return real_command_check(root, name, *args, **kwargs)

        with patch('getzilla.verification._command_check', side_effect=without_pilot), \
             patch('getzilla.verification._ruff', return_value=CheckResult('ruff', 'pass', 'fixture')), \
             patch('getzilla.verification._bandit', return_value=CheckResult('bandit', 'pass', 'fixture')), \
             patch('getzilla.verification._factory_unit', return_value=[]), \
             patch('getzilla.verification.run_core_tests', return_value=Core()) as runner, \
             patch.dict(os.environ, {'GETZILLA_VERIFY_CAPABILITY': 'repository-sandbox'}):
            results = {check.name: check for check in _python(repo_root, mode='pr')}
        self.assertIn('python-unittest', results)
        self.assertIsNotNone(runner.call_args, results)
        self.assertEqual(runner.call_args.args[2], 2)
        self.assertIn('coverage-unittest-parallel', results['python-unittest'].summary)

    def test_inherited_pytest_selection_cannot_omit_tests(self) -> None:
        with fixture() as root:
            (root / 'pytest.ini').write_text('[pytest]\naddopts = -k test_0\nnorecursedirs = nested\n')
            nested = root / 'tests/nested'
            nested.mkdir()
            (nested / '__init__.py').write_text('')
            (nested / 'test_nested.py').write_text(
                'import unittest\nfrom pathlib import Path\nclass Nested(unittest.TestCase):\n'
                ' def test_nested(self):\n  Path("result-nested").touch(exist_ok=False)\n'
            )
            with patch.dict(os.environ, {'PYTEST_ADDOPTS': '-k nonexistent', 'PYTEST_PLUGINS': 'nonexistent_plugin'}):
                result = next(check for check in _python(root) if check.name == 'python-unittest')
            self.assertEqual(result.status, 'pass', result.stderr)
            self.assertEqual(len(list(root.glob('result-*'))), 5)

    @unittest.skipUnless(sys.platform.startswith('linux') or os.name == 'nt',
                         'descendant verification reads /proc on Linux or process handles on Windows')
    def test_sigterm_cancels_owned_group_and_restores_previous_handler(self) -> None:
        # On Windows terminate() is TerminateProcess: no handler runs, and the
        # controller's kill-on-close Job Object ends the child it owned.
        with fixture() as root:
            pid_file = root / 'terminated-child.pid'
            child_code = f'import os,time; from pathlib import Path; Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(60)'
            code = (
                'import os,sys\nfrom pathlib import Path\n'
                'from getzilla.python_test_runner import execute\n'
                f'execute([sys.executable,"-c",{child_code!r}],Path.cwd(),os.environ.copy())\n'
            )
            environment = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / '.getzilla')}
            controller = subprocess.Popen([sys.executable, '-c', code], cwd=root, env=environment)
            try:
                for _ in range(500):
                    if pid_file.exists():
                        break
                    time.sleep(0.01)
                self.assertTrue(pid_file.exists(), 'controlled child did not start')
                controller.terminate()
                self.assertNotEqual(controller.wait(timeout=5), 0)
                self.assert_descendant_stopped(pid_file)
            finally:
                if controller.poll() is None:
                    controller.kill()
                    controller.wait(timeout=5)
                if os.name == 'posix' and pid_file.exists():
                    child_pid = int(pid_file.read_text())
                    try:
                        if os.getpgid(child_pid) == child_pid:
                            os.killpg(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            previous = signal.getsignal(signal.SIGTERM)
            self.assertEqual(execute([sys.executable, '-c', 'pass'], root, environment).returncode, 0)
            self.assertIs(signal.getsignal(signal.SIGTERM), previous)
            self.assertEqual(execute([str(root / 'missing-command')], root, environment).returncode, 127)
            self.assertIs(signal.getsignal(signal.SIGTERM), previous)

    def test_assertion_collection_and_worker_failures_propagate(self) -> None:
        for source in (
            'import unittest\nclass T(unittest.TestCase):\n def test_bad(self): self.fail("expected")\n',
            'raise RuntimeError("collection failure")\n',
            '# no tests collected\n',
            'import os, unittest\nclass T(unittest.TestCase):\n def test_exit(self): os._exit(86)\n',
        ):
            with self.subTest(source=source), fixture() as root:
                (root / 'tests/test_sample.py').write_text(source)
                result = next(check for check in _python(root) if check.name == 'python-unittest')
                self.assertEqual(result.status, 'fail', result.stdout)

    def test_output_limit_applies_even_when_process_exits_quickly(self) -> None:
        with fixture() as root, patch('getzilla.python_test_runner.OUTPUT_LIMIT', 16):
            result = execute([sys.executable, '-c', 'print("x" * 10000)'], root, os.environ.copy())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('output limit', result.stderr)

    def test_timeout_stops_owned_descendant_process(self) -> None:
        with fixture() as root:
            pid_file = root / 'child.pid'
            code = (
                'import subprocess, sys, time\nfrom pathlib import Path\n'
                'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])\n'
                f'Path({str(pid_file)!r}).write_text(str(child.pid))\n'
                'time.sleep(60)\n'
            )
            result = execute([sys.executable, '-c', code], root, os.environ.copy(), timeout=1)
            self.assertEqual(result.returncode, 124)
            self.assertIn('timeout', result.stderr)
            self.assert_descendant_stopped(pid_file)

    @unittest.skipUnless(sys.platform.startswith('linux') or os.name == 'nt',
                         'descendant verification reads /proc on Linux or process handles on Windows')
    def test_controller_exit_stops_owned_descendant_process(self) -> None:
        with fixture() as root:
            pid_file = root / 'orphan.pid'
            code = (
                'import subprocess, sys\nfrom pathlib import Path\n'
                'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])\n'
                f'Path({str(pid_file)!r}).write_text(str(child.pid))\n'
            )
            result = execute([sys.executable, '-c', code], root, os.environ.copy())
            self.assertEqual(result.returncode, 0)
            self.assert_descendant_stopped(pid_file)

    @unittest.skipUnless(sys.platform.startswith('linux') or os.name == 'nt',
                         'descendant verification reads /proc on Linux or process handles on Windows')
    def test_term_resistant_grandchild_is_killed_on_every_stop_path(self) -> None:
        # The grandchild ignores SIGTERM/SIGINT/SIGBREAK and, on Windows, first asks to
        # break away from the job. Its parent waits until it is ready, then exits,
        # floods output, sleeps into the timeout, or loses its controller. Only
        # owning the whole tree (SIGKILL after the grace, or the Job Object) ends it.
        grandchild = (
            'import os, signal, sys, time\n'
            'for name in ("SIGTERM", "SIGINT", "SIGBREAK"):\n'
            '    if hasattr(signal, name):\n'
            '        signal.signal(getattr(signal, name), signal.SIG_IGN)\n'
            'with open(sys.argv[1] + ".tmp", "w") as output:\n'
            '    output.write(str(os.getpid()))\n'
            'os.replace(sys.argv[1] + ".tmp", sys.argv[1])\n'
            'time.sleep(60)\n'
        )
        child = (
            'import os, subprocess, sys, time\n'
            'pid_file, then = sys.argv[1], sys.argv[2]\n'
            f'command = [sys.executable, "-c", {grandchild!r}, pid_file]\n'
            'try:\n'
            '    subprocess.Popen(command, creationflags=getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0))\n'
            'except OSError:\n'
            '    subprocess.Popen(command)\n'
            'while not os.path.exists(pid_file):\n'
            '    time.sleep(0.01)\n'
            'if then == "flood":\n'
            '    sys.stdout.write("x" * 65536)\n'
            '    sys.stdout.flush()\n'
            'if then != "exit":\n'
            '    time.sleep(60)\n'
        )
        for then in ('exit', 'flood', 'timeout', 'controller'):
            with self.subTest(then=then), fixture() as root:
                pid_file = root / 'grandchild.pid'
                command = [sys.executable, '-c', child, str(pid_file), 'sleep' if then == 'controller' else then]
                if then == 'controller':
                    code = (
                        'import os\nfrom pathlib import Path\n'
                        'from getzilla.python_test_runner import execute\n'
                        f'execute({command!r}, Path.cwd(), os.environ.copy())\n'
                    )
                    environment = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / '.getzilla')}
                    controller = subprocess.Popen([sys.executable, '-c', code], cwd=root, env=environment)
                    try:
                        deadline = time.monotonic() + 30
                        while not pid_file.exists() and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertTrue(pid_file.exists(), 'grandchild did not start')
                        controller.terminate()
                        self.assertNotEqual(controller.wait(timeout=10), 0)
                    finally:
                        if controller.poll() is None:
                            controller.kill()
                            controller.wait(timeout=5)
                else:
                    with patch.object(python_test_runner, 'OUTPUT_LIMIT', 1024):
                        result = execute(command, root, os.environ.copy(), timeout=5 if then == 'timeout' else 30)
                    self.assertTrue(pid_file.exists(), f'grandchild did not start: {result.stderr}')
                    self.assertEqual(result.returncode, 0 if then == 'exit' else 124, result.stderr)
                    self.assertEqual(result.cleanup_error, '')
                self.assert_descendant_stopped(pid_file)

    def test_coverage_below_threshold_and_worker_data_loss_fail(self) -> None:
        for scenario in ('below-threshold', 'missing-worker'):
            with self.subTest(scenario=scenario), fixture() as root:
                (root / 'subject.py').write_text(
                    'value = 1\n' + (
                        'def unused():\n' + ''.join(f'    value = {i}\n' for i in range(20))
                        if scenario == 'below-threshold' else ''
                    )
                )
                sample = root / 'tests/test_sample.py'
                sample.write_text('import subject\n' + sample.read_text())
                (root / '.coveragerc').write_text(
                    '[run]\nbranch = True\nsource = subject\n[report]\nfail_under = 74\n'
                )
                if scenario == 'missing-worker' and python_test_runner.select_engine(2, True)[1] != 'pytest-xdist':
                    self.skipTest('xdist worker data-loss is unobservable on a degraded serial engine')
                if scenario == 'missing-worker':
                    (root / 'conftest.py').write_text(
                        'import pytest\n@pytest.hookimpl(tryfirst=True, optionalhook=True)\n'
                        'def pytest_testnodedown(node, error):\n'
                        '    node.workeroutput.pop("cov_worker_node_id", None)\n'
                    )
                results = {check.name: check for check in _python(root, mode='pr')}
                self.assertEqual(results['coverage'].status, 'fail', results)

    def test_missing_and_corrupt_current_coverage_fail(self) -> None:
        if not parallel_engine_ready(measured=True):
            self.skipTest('pytest current coverage data-loss is unobservable on the coverage-unittest fallback')
        for scenario in ('missing', 'corrupt'):
            with self.subTest(scenario=scenario), fixture() as root:
                (root / 'subject.py').write_text('value = 1\n')
                sample = root / 'tests/test_sample.py'
                sample.write_text('import subject\n' + sample.read_text())
                (root / '.coveragerc').write_text(
                    '[run]\nbranch = True\nsource = subject\n[report]\nfail_under = 74\n'
                )

                def damage_current_data(command, cwd, environment, **kwargs):
                    result = execute(command, cwd, environment, **kwargs)
                    if command[1:3] == ['-m', 'pytest'] or command[1:4] == ['-m', 'coverage', 'run']:
                        data = Path(environment['COVERAGE_FILE'])
                        if scenario == 'missing':
                            data.unlink()
                        else:
                            data.write_bytes(b'broken coverage data')
                    return result

                with patch('getzilla.python_test_runner.execute', side_effect=damage_current_data):
                    results = {check.name: check for check in _python(root, mode='pr')}
                self.assertEqual(results['python-unittest'].status, 'pass', results)
                self.assertEqual(results['coverage'].status, 'fail', results)

    def test_nested_legacy_coverage_keeps_parent_data(self) -> None:
        with fixture() as root:
            (root / '.getzilla-test-runner.json').unlink()
            (root / 'subject.py').write_text('value = 1\n')
            sample = root / 'tests/test_sample.py'
            sample.write_text('import subject\n' + sample.read_text())
            (root / '.coveragerc').write_text(
                '[run]\nbranch = True\nsource = subject\n[report]\nfail_under = 74\n'
            )
            parent = root / 'parent.coverage'
            parent.write_bytes(b'parent-owned-evidence')
            with patch.dict(os.environ, {'COVERAGE_FILE': str(parent), '_GETZILLA_TEST_CHILD': '1'}):
                results = {check.name: check for check in _python(root, mode='pr')}
            self.assertEqual(results['coverage'].status, 'pass', results)
            self.assertEqual(parent.read_bytes(), b'parent-owned-evidence')

    def test_opted_in_verifier_shards_each_method_once(self) -> None:
        with fixture() as root:
            result = next(check for check in _python(root) if check.name == 'python-unittest')
            self.assertEqual(result.status, 'pass', result.stderr + result.stdout)
            outputs = list(root.glob('result-*'))
            self.assertEqual({p.name for p in outputs}, {f'result-{i}' for i in range(4)})
            workers, engine = python_test_runner.select_engine(2, measured=False)
            self.assertEqual(json.loads(result.details[0]['versions'])['engine'], engine)
            if workers:
                self.assertEqual(result.command[result.command.index('-n') + 1], '2')
                self.assertIn('--dist=worksteal', result.command)
            else:
                self.assertEqual(len({p.read_text() for p in outputs}), 1)

    def test_invalid_worker_setting_fails_before_running_tests(self) -> None:
        for bad in ('invalid', 65, -1, 1.5, True):
            with self.subTest(workers=bad), fixture(workers=bad) as root:
                result = next(check for check in _python(root) if check.name == 'python-unittest')
                self.assertEqual(result.status, 'fail')
                self.assertFalse(list(root.glob('result-*')))
        with fixture() as root:
            config = root / '.getzilla-test-runner.json'
            config.write_text(json.dumps({'schema_version': 2, 'workers': 2}))
            self.assertRaises(RunnerError, selected_workers, root)
            config.write_text(json.dumps({'schema_version': 1, 'workers': 2, 'extra': 1}))
            self.assertRaises(RunnerError, selected_workers, root)
        with fixture(workers=0) as root, patch.dict(os.environ, {'GETZILLA_TEST_WORKERS': '65'}):
            self.assertRaises(RunnerError, selected_workers, root)
        with fixture(workers=0) as root, patch.dict(os.environ, {'GETZILLA_TEST_WORKERS': 'invalid'}):
            self.assertRaises(RunnerError, selected_workers, root)
        if not hasattr(os, 'mkfifo'):
            return  # a FIFO configuration is a POSIX-only case
        with fixture() as root:
            config = root / '.getzilla-test-runner.json'
            config.unlink()
            os.mkfifo(config)
            result = execute(
                [sys.executable, '-c',
                 'from pathlib import Path; from getzilla.python_test_runner import selected_workers; selected_workers(Path.cwd())'],
                root, {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / '.getzilla')}, timeout=1,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotEqual(result.returncode, 124, 'nonregular configuration must fail without blocking')

    def test_parallel_coverage_preserves_parent_and_existing_data(self) -> None:
        with fixture() as root:
            (root / 'subject.py').write_text('value = 1\n')
            sample = root / 'tests/test_sample.py'
            sample.write_text('import subject\n' + sample.read_text())
            (root / '.coveragerc').write_text(
                '[run]\nbranch = True\nsource = subject\n'
                '[report]\nfail_under = 74\n'
            )
            parent = root / 'parent.coverage'
            prior = root / '.coverage'
            parent.write_bytes(b'parent-owned-evidence')
            prior.write_bytes(b'previous-run-evidence')
            with patch.dict(os.environ, {'COVERAGE_FILE': str(parent)}):
                results = {check.name: check for check in _python(root, mode='pr')}
            self.assertEqual(results['python-unittest'].status, 'pass', results)
            self.assertEqual(results['coverage'].status, 'pass', results)
            self.assertEqual(parent.read_bytes(), b'parent-owned-evidence')
            self.assertEqual(prior.read_bytes(), b'previous-run-evidence')


if __name__ == '__main__':
    unittest.main()
