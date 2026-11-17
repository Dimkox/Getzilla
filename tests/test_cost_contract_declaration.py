"""Declared budgets remain mandatory when an injected adapter escapes heuristics."""
from contextlib import ExitStack, contextmanager
import builtins
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import cost_guard as cost  # noqa: E402


ADAPTER = b'''def dispatch(transport, items, budget_limit):
    return [transport(item) for item in items[:budget_limit]]
'''
BOUND_TEST = b'''def test_budget_limit():
    seen = []
    assert dispatch(seen.append, [1, 2, 3], budget_limit=2) == [None, None]
    assert seen == [1, 2]
'''
CONTRACT = {'schema_version': 'cost-contract-v1', 'provider': 'owned injected transport',
            'max_calls': 2, 'max_spend_usd_cents': 10,
            'stop_condition': 'Stop before the third owned fixture item.',
            'alert': 'Report budget exhaustion to the caller.', 'limit_symbol': 'budget_limit'}
RULES = {'tests': ['tests/**'], 'trivial': {'allow': ['*.md']}}


@contextmanager
def effects_denied(fixture):
    """Only contract bytes from this owned fixture may be opened."""
    original_open, original_io = builtins.open, io.open
    def guarded(open_fn):
        def read(path, *args, **kwargs):
            if not isinstance(path, (str, bytes, os.PathLike)):
                raise AssertionError('outside owned fixture')
            target = Path(os.fsdecode(path)).absolute()
            if not target.is_relative_to(fixture):
                raise AssertionError('outside owned fixture')
            return open_fn(path, *args, **kwargs)
        return read
    def denied(*args, **kwargs):
        raise AssertionError('unmocked external effect')
    with ExitStack() as stack:
        stack.enter_context(patch('builtins.open', guarded(original_open)))
        stack.enter_context(patch('io.open', guarded(original_io)))
        for target in ('subprocess.Popen', 'os.system', 'os.fork', 'os.posix_spawn',
                       'socket.socket', 'socket.create_connection', 'ctypes.CDLL', 'ctypes.PyDLL'):
            stack.enter_context(patch(target, denied))
        yield


class DeclaredContractTests(unittest.TestCase):
    def setUp(self):
        runtime = ROOT / '.getzilla/runtime'
        runtime.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='declared-cost-', dir=runtime)
        self.addCleanup(temporary.cleanup)
        self.fixture = Path(temporary.name).absolute()
        self.package = self.fixture / 'package'
        self.package.mkdir()
        self.blobs = {'adapter.py': ADAPTER, 'tests/test_adapter.py': BOUND_TEST}
        self.providers = {'hosts': [], 'python_modules': [], 'python_scheduler_modules': []}

    def run_guard(self, raw=json.dumps(CONTRACT), *, mode='pr', route=None, findings=None):
        if raw is not None:
            (self.package / cost.CONTRACT_NAME).write_text(raw)
        def git(root, *args, **kwargs):
            if root != self.fixture:
                raise AssertionError('foreign source root')
            if args == ('ls-tree', '-r', '--name-only', '-z', 'owned-head'):
                return SimpleNamespace(returncode=0, stdout=b'\0'.join(p.encode() for p in self.blobs)+b'\0')
            if len(args) == 2 and args[0] == 'show' and args[1].startswith('owned-head:'):
                raw = self.blobs.get(args[1].split(':', 1)[1])
                return SimpleNamespace(returncode=int(raw is None), stdout=raw or b'')
            raise AssertionError('unexpected source read')
        detected = cost.python_findings('adapter.py', self.blobs['adapter.py'], self.providers)
        with ExitStack() as stack:
            stack.enter_context(patch('getzilla.diff_risk.load_rules', return_value=RULES))
            stack.enter_context(patch('getzilla.diff_risk.changed_paths', return_value=[
                SimpleNamespace(path=name, status='A') for name in self.blobs]))
            stack.enter_context(patch.object(cost, 'diff_cost_findings', return_value=detected if findings is None else findings))
            stack.enter_context(patch('getzilla.project_ingestion._git', side_effect=git))
            stack.enter_context(effects_denied(self.fixture))
            result = cost.evaluate(self.fixture, route, mode, ['owned-base'], 'owned-head', self.package)
        return result

    def test_declared_undetected_adapter_validates_a_real_bounded_fixture(self):
        namespace = {}
        with effects_denied(self.fixture):
            exec(ADAPTER + BOUND_TEST, namespace)
            namespace['test_budget_limit']()
        result = self.run_guard()
        self.assertEqual((result.status, result.findings, result.signal), ('pass', [], False))
        self.assertIn('budget contract', result.summary)

    def test_declared_invalid_limit_fails_without_a_heuristic_signal(self):
        result = self.run_guard(json.dumps({**CONTRACT, 'max_calls': 0}))
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(p.startswith('COST_CONTRACT_INVALID') for p in result.problems))

    def test_declared_malformed_json_fails_without_a_heuristic_signal(self):
        result = self.run_guard('{broken')
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(p.startswith('COST_CONTRACT_INVALID') for p in result.problems))

    def test_declared_null_fails_schema_validation(self):
        result = self.run_guard('null')
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(p.startswith('COST_CONTRACT_INVALID') for p in result.problems))

    def test_declared_json_array_fails_schema_validation(self):
        result = self.run_guard('[]')
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(p.startswith('COST_CONTRACT_INVALID') for p in result.problems))

    def test_declared_unreadable_contract_fails_without_a_signal(self):
        with patch.object(Path, 'read_text', side_effect=PermissionError('owned denied contract')):
            result = self.run_guard()
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(p.startswith('COST_CONTRACT_INVALID') for p in result.problems))

    def test_declared_bound_missing_from_source_fails(self):
        self.blobs['adapter.py'] = b'def dispatch(transport, items):\n    return [transport(x) for x in items]\n'
        result = self.run_guard()
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(p.startswith('COST_BOUND_UNTESTED') for p in result.problems))

    def test_declared_bound_missing_from_test_fails(self):
        self.blobs['tests/test_adapter.py'] = b'def test_unrelated():\n    assert 2 + 2 == 4\n'
        result = self.run_guard()
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(p.startswith('COST_BOUND_UNTESTED') for p in result.problems))

    def test_declared_bound_with_unreadable_test_blob_fails(self):
        self.blobs['tests/test_adapter.py'] = None
        result = self.run_guard()
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(p.startswith('COST_BOUND_UNTESTED') for p in result.problems))

    def test_no_contract_reports_non_detection_without_proving_absence(self):
        result = self.run_guard(None)
        self.assertEqual((result.status, result.problems), ('pass', []))
        self.assertIn('detected', result.summary)
        self.assertNotIn('no paid or unbounded operation in', result.summary)

    def test_detected_operation_without_contract_still_fails(self):
        result = self.run_guard(None, route={'human_gates': [cost.GATE]})
        self.assertEqual(result.status, 'fail')
        self.assertTrue(any(p.startswith('COST_CONTRACT_MISSING') for p in result.problems))

    def test_fast_mode_retains_warning_for_invalid_declared_contract(self):
        result = self.run_guard('null', mode='fast')
        self.assertEqual(result.status, 'pass')
        self.assertTrue(result.problems)
        self.assertTrue(result.summary.startswith('will fail pr/release:'))


if __name__ == '__main__':
    unittest.main()
