"""Platform acceptance observations never replace independent security admission."""
from __future__ import annotations

import copy
import json
import tempfile
import time
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import platform_install as acceptance  # noqa: E402


class PlatformContractTests(unittest.TestCase):
    def test_supported_matrix_requires_five_native_pairs_and_explicit_windows_arm_gap(self):
        cells = acceptance.load_matrix(ROOT)
        self.assertEqual({c['id'] for c in cells if c['required']},
                         {'linux-x64', 'linux-arm64', 'macos-x64', 'macos-arm64', 'windows-x64'})
        arm = next(c for c in cells if c['id'] == 'windows-arm64')
        self.assertFalse(arm['supported'])
        self.assertFalse(arm['required'])
        self.assertIn('OpenGrep', arm['reason'])

    def test_architecture_must_be_observed_not_inferred_from_requested_runner(self):
        self.assertEqual(acceptance.native_platform('Darwin', 'arm64'), ('macos', 'arm64'))
        self.assertEqual(acceptance.native_platform('Windows', 'AMD64'), ('windows', 'x64'))
        with self.assertRaises(ValueError):
            acceptance.native_platform('Linux', 'mips64')

    def test_malformed_support_inventory_cannot_establish_required_platforms(self):
        original = json.loads((ROOT/acceptance.MATRIX_PATH).read_text())
        for field, value in [('schema_version', True), ('cells', [1]*6)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root/acceptance.MATRIX_PATH
                path.parent.mkdir(parents=True)
                broken = copy.deepcopy(original)
                broken[field] = value
                path.write_text(json.dumps(broken))
                with self.assertRaises(ValueError):
                    acceptance.load_matrix(root)

    def record(self):
        return {'schema': 'getzilla-platform-install-v1', 'cell': 'linux-x64',
                'os': 'linux', 'arch': 'x64', 'head': 'a' * 40, 'tree': 'b' * 40,
                'head_after': 'a' * 40, 'tree_after': 'b' * 40, 'source_clean': True,
                'run_id': '123', 'run_attempt': '2', 'authority': 'observations-only',
                'stable': {'tag': 'v2.3.0', 'commit': '2bb417431f1e4b9494e4af71ebf27adb1d04d898',
                           'tag_object': '815aeabc5d215d65e72651692a6457920de9fa71'},
                'scenarios': {name: {'status': 'pass', 'installed_head': 'a' * 40,
                                    'version': '2.3.1', 'cli_sha256': 'c' * 64,
                                    'managed_sha256': 'e' * 64,
                                    'from_head': '2bb417431f1e4b9494e4af71ebf27adb1d04d898', 'from_version': '2.3.0',
                                    'cli_exit': 0, 'doctor_exit': 0, 'installer_exit': 0,
                                    'user_preserved': True, 'settings_preserved': True,
                                    'agents': ['qwen'], 'update_exit': 0, 'logs_complete': True}
                              for name in ('clean', 'upgrade')}}

    def validate(self, records, job_result='success'):
        return acceptance.validate_results(records, matrix=acceptance.load_matrix(ROOT),
                 required=['linux-x64'], head='a' * 40, tree='b' * 40, run_id='123', run_attempt='2',
                 version='2.3.1', cli_sha256='c' * 64, managed_sha256='e' * 64,
                 stable=self.record()['stable'], job_result=job_result)

    def test_missing_failed_skipped_duplicate_or_substituted_evidence_blocks_aggregate(self):
        good = self.record()
        self.assertEqual(self.validate([good]), [])
        self.assertTrue(self.validate([]))
        self.assertTrue(self.validate([good, good]))
        for result in ('skipped', 'cancelled', 'failure', 'missing'):
            self.assertTrue(self.validate([good], result))
        for field, value in [('head', 'd' * 40), ('tree', 'd' * 40), ('run_attempt', '1'),
                             ('arch', 'arm64'), ('authority', 'security-approved'),
                             ('error', 'producer failed'), ('source_clean', False), ('head_after', 'd' * 40)]:
            bad = copy.deepcopy(good)
            bad[field] = value
            self.assertTrue(self.validate([bad]), field)
        for field, value in [('status', 'skipped'), ('installer_exit', 1), ('doctor_exit', 1),
                             ('logs_complete', False), ('user_preserved', False),
                             ('settings_preserved', False), ('agents', ['codex']),
                             ('installed_head', 'd' * 40), ('cli_sha256', 'd' * 64)]:
            bad = copy.deepcopy(good)
            bad['scenarios']['upgrade'][field] = value
            self.assertTrue(self.validate([bad]), field)

    def test_json_result_reader_refuses_duplicate_keys_and_oversized_input(self):
        with self.assertRaises(ValueError):
            acceptance.decode_result(b'{"cell":"linux-x64","cell":"windows-x64"}')
        with self.assertRaises(ValueError):
            acceptance.decode_result(b' ' * 65537)
        with self.assertRaises(ValueError):
            acceptance.decode_result(b'{"seconds":1e999}')
        self.assertEqual(acceptance.decode_result(json.dumps(self.record()).encode()), self.record())


class ActualCommandTests(unittest.TestCase):
    def test_real_producer_is_drained_past_report_quota_without_false_complete_evidence(self):
        from getzilla.platform_acceptance import run_command
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_command([sys.executable, '-c', "import os; os.write(1,b'x'*200000)"],
                                 cwd=root, log=root/'output.log', timeout=5, quota=1024)
            self.assertEqual(result['exit'], 0)
            self.assertEqual(result['observed_bytes'], 200000)
            self.assertEqual((root/'output.log').stat().st_size, 1024)
            self.assertFalse(result['logs_complete'])

    def test_total_deadline_still_applies_when_child_closes_its_output(self):
        from getzilla.platform_acceptance import run_command
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            started = time.monotonic()
            result = run_command([sys.executable, '-c', 'import os,time; os.close(1); os.close(2); time.sleep(2)'],
                                 cwd=root, log=root/'output.log', timeout=0.1)
            self.assertEqual(result['exit'], 124)
            self.assertLess(time.monotonic()-started, 1.5)
