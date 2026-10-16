from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import startup_cpu
from getzilla.startup_cpu import choose_capacity, format_cpu_list, parse_cpu_list, topology_from_lscpu
from getzilla.state import set_active_change
from getzilla.util import dump_json
from tests._support import project_copy

LSCPU_P = '''# The following is the parsable format
# CPU,Core,Socket,Online
0,0,0,Y
1,1,0,Y
2,0,0,Y
3,1,0,Y
4,2,0,N
'''


def fake_runner(calls: list[list[str]], allowed: str = '0-3'):
    def runner(argv: list[str]) -> dict:
        calls.append(argv)
        if argv[:2] == ['lscpu', '-p=CPU,CORE,SOCKET,ONLINE']:
            stdout = LSCPU_P
        elif argv[0] == 'taskset' and argv[1] == '-c':
            stdout = f'Name:\tcat\nCpus_allowed_list:\t{allowed}\n'
        else:
            stdout = 'ok\n'
        return {'argv': argv, 'code': 0, 'stdout': stdout, 'stderr': ''}
    return runner


class CpuListTests(unittest.TestCase):
    def test_round_trip_and_malformed_lists(self) -> None:
        self.assertEqual(parse_cpu_list('0,1,8-27\n'), {0, 1, *range(8, 28)})
        self.assertEqual(format_cpu_list({0, 1, *range(8, 28)}), '0,1,8-27')
        for bad in ('0-', 'a', '5-3', '1;2'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_cpu_list(bad)

    def test_topology_counts_online_logical_and_physical_cores(self) -> None:
        topology = topology_from_lscpu(LSCPU_P)
        self.assertEqual(topology['online_cpus'], {0, 1, 2, 3})
        self.assertEqual(topology['physical_cores'], 2)


class ChooseCapacityTests(unittest.TestCase):
    online = set(range(28))
    affinity = {0, 1, *range(8, 28)}

    def choose(self, **overrides) -> dict:
        values = {'online': self.online, 'affinity': self.affinity, 'cpuset': set(range(28)),
                  'quota': None, 'probe_allowed': None, 'reserve': 0, **overrides}
        return choose_capacity(**values)

    def test_capacity_is_not_host_count_without_probe(self) -> None:
        self.assertEqual(self.choose()['chosen_capacity'], 22)

    def test_successful_probe_widens_to_allowed_cpus(self) -> None:
        self.assertEqual(self.choose(probe_allowed=set(range(28)))['chosen_capacity'], 28)

    def test_finite_quota_and_owner_reserve_lower_capacity(self) -> None:
        self.assertEqual(self.choose(probe_allowed=set(range(28)), quota=4)['chosen_capacity'], 4)
        self.assertEqual(self.choose(probe_allowed=set(range(28)), reserve=2)['chosen_capacity'], 26)

    def test_cpuset_bounds_probe_result(self) -> None:
        result = self.choose(cpuset=set(range(16)), probe_allowed=set(range(28)))
        self.assertEqual(result['chosen_capacity'], 16)
        self.assertEqual(result['verified_cpus'], '0-15')


@unittest.skipUnless(hasattr(os, 'sched_getaffinity'), 'Linux affinity API required')
class MeasureTests(unittest.TestCase):
    def measure(self, *, affinity: set[int], reserve: int = 0, allowed: str = '0-3'):
        calls: list[list[str]] = []
        bounds = {'cgroup_version': 2, 'membership': '/x', 'levels': [], 'effective_cpuset': '0-3'}
        with mock.patch.object(startup_cpu.os, 'sched_getaffinity', return_value=affinity), \
                mock.patch.object(startup_cpu.os, 'sched_setaffinity', create=True) as setaffinity, \
                mock.patch.object(startup_cpu, 'cgroup_bounds', return_value=bounds), \
                mock.patch.object(startup_cpu._cpu_capacity, 'linux_quota_capacity', return_value=None):
            snapshot = startup_cpu.measure(reserve=reserve, runner=fake_runner(calls, allowed))
        setaffinity.assert_not_called()
        return snapshot, calls

    def test_narrow_affinity_runs_one_child_only_probe(self) -> None:
        snapshot, calls = self.measure(affinity={0, 1})
        probes = [argv for argv in calls if argv[:2] == ['taskset', '-c']]
        self.assertEqual(probes, [['taskset', '-c', '0-3', 'cat', '/proc/self/status']])
        self.assertEqual(snapshot['probe']['allowed'], '0-3')
        self.assertEqual(snapshot['chosen_capacity'], 4)
        self.assertEqual(snapshot['process'], {'nproc': 2, 'affinity': '0,1'})

    def test_full_affinity_needs_no_probe(self) -> None:
        snapshot, calls = self.measure(affinity={0, 1, 2, 3})
        self.assertFalse([argv for argv in calls if argv[:2] == ['taskset', '-c']])
        self.assertIsNone(snapshot['probe'])
        self.assertEqual(snapshot['chosen_capacity'], 4)

    def test_failed_probe_keeps_existing_affinity(self) -> None:
        snapshot, _ = self.measure(affinity={0, 1}, allowed='garbage')
        self.assertEqual(snapshot['chosen_capacity'], 2)
        self.assertTrue(any('probe' in item for item in snapshot['uncertainties']))

    def test_reserve_probes_only_the_owner_ceiling(self) -> None:
        snapshot, calls = self.measure(affinity={0}, reserve=2, allowed='0-1')
        self.assertIn(['taskset', '-c', '0,1', 'cat', '/proc/self/status'], calls)
        self.assertEqual(snapshot['chosen_capacity'], 2)


class WindowsMeasureTests(unittest.TestCase):
    def test_windows_counts_usable_cpus_with_reserve_and_physical_cores(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]) -> dict:
            calls.append(argv)
            return {'argv': argv, 'code': 0, 'stdout': '10\r\n', 'stderr': ''}

        with mock.patch.object(startup_cpu, 'has_linux_affinity', return_value=False), \
                mock.patch.object(startup_cpu.os, 'cpu_count', return_value=12), \
                mock.patch.object(startup_cpu.os, 'process_cpu_count', return_value=12, create=True):
            snapshot = startup_cpu.measure(reserve=2, runner=runner)
        self.assertEqual(snapshot['platform'], 'windows')
        self.assertEqual(snapshot['topology']['physical_cores'], 10)
        self.assertEqual(snapshot['topology']['online_logical_cpus'], 12)
        self.assertEqual(snapshot['chosen_capacity'], 10)
        self.assertIsNone(snapshot['probe'])
        self.assertEqual(len(calls), 1)

    def test_windows_unknown_cores_is_an_uncertainty_not_a_failure(self) -> None:
        def runner(argv: list[str]) -> dict:
            return {'argv': argv, 'code': None, 'stdout': '', 'stderr': 'FileNotFoundError'}

        with mock.patch.object(startup_cpu, 'has_linux_affinity', return_value=False), \
                mock.patch.object(startup_cpu.os, 'cpu_count', return_value=4), \
                mock.patch.object(startup_cpu.os, 'process_cpu_count', return_value=2, create=True):
            snapshot = startup_cpu.measure(reserve=0, runner=runner)
        self.assertIsNone(snapshot['topology']['physical_cores'])
        self.assertEqual(snapshot['chosen_capacity'], 2)
        self.assertTrue(any('physical core' in item for item in snapshot['uncertainties']))

@unittest.skipUnless(hasattr(os, 'sched_getaffinity'), 'Linux affinity API required')
class CliTests(unittest.TestCase):
    script = ROOT / 'scripts/getzilla_startup_cpu.py'

    def run_cli(self, root: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(self.script), '--no-probe', *args], cwd=root,
                              capture_output=True, text=True, check=False, timeout=60)

    def test_records_runtime_snapshot(self) -> None:
        with project_copy() as root:
            proc = self.run_cli(root, '--json')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            record = json.loads((root / '.getzilla/runtime/startup-capacity.json').read_text())
            self.assertEqual(record['kind'], 'startup-cpu-step-zero')
            self.assertGreaterEqual(record['chosen_capacity'], 1)
            self.assertEqual(json.loads(proc.stdout)['observed_at'], record['observed_at'])

    def test_attach_requires_active_change_and_writes_evidence(self) -> None:
        with project_copy() as root:
            proc = self.run_cli(root, '--attach')
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('No active change package', proc.stderr)
            package = root / 'engineering/changes/20261015-task-abcdef'
            dump_json(package / 'state.json', {'change_id': package.name, 'status': 'draft'})
            set_active_change(root, {'change_id': package.name, 'path': package.relative_to(root).as_posix()})
            proc = self.run_cli(root, '--attach')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            evidence = json.loads((package / 'evidence/startup-capacity.json').read_text())
            self.assertEqual(evidence['change_id'], package.name)


if __name__ == '__main__':
    unittest.main()
