"""Actual public-study decision owners change the existing policy capture."""
import ast
import hashlib
import importlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.verification_plan import policy_binding

OWNERS = (
    'retrieval/public_study_operation.py', 'retrieval/public_study_inspection.py',
    'retrieval/public_study_graphs.py', 'retrieval/public_study_storage.py',
    'retrieval/study_artifacts.py', 'retrieval/study_resources.py',
    'retrieval/study_worker_inventory.py', 'retrieval/study_supervisor.py',
    'retrieval/study_kernel.py', 'retrieval/study_docker_process.py',
    'retrieval/study_waiter_process.py', 'retrieval/study_waiter_kernel.py',
    'retrieval/study_windows.py', 'retrieval/research.py',
    'retrieval/contracts.py', 'retrieval/budget.py',
    'retrieval/evaluation_inputs.py', 'retrieval/evaluation_inputs_io.py',
    'execution.py', 'execution_store.py', 'execution_output.py', 'optional_modules.py',
)


class PublicStudyPolicyBindingTests(unittest.TestCase):
    def test_actual_callee_body_mutations_change_warmed_policy_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = policy_binding(root)
            for name in OWNERS:
                with self.subTest(owner=name):
                    module = importlib.import_module('getzilla.' + name[:-3].replace('/', '.'))
                    raw = (ROOT / '.getzilla/getzilla' / name).read_bytes()
                    self.assertEqual(baseline['implementation'][name], hashlib.sha256(raw).hexdigest())
                    tree = ast.parse(raw)
                    function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef))
                    function.body.insert(0, ast.parse("raise RuntimeError('actual callee mutation')").body[0])
                    changed = (ast.unparse(ast.fix_missing_locations(tree)) + '\n').encode()
                    with patch.object(module.__loader__, 'get_data', return_value=changed):
                        observed = policy_binding(root)
                    self.assertEqual(observed['implementation'][name], hashlib.sha256(changed).hexdigest())
                    self.assertNotEqual(baseline['digest'], observed['digest'])
                    self.assertIs(module, importlib.import_module(module.__name__))
            self.assertEqual(baseline, policy_binding(root))

    def test_capture_preserves_actual_live_state_and_exact_class_identity(self):
        from getzilla.retrieval import public_study_operation as operations
        from getzilla.retrieval import public_study_inspection as inspections
        from getzilla.retrieval import public_study_storage as storage
        from getzilla.retrieval import study_supervisor as supervisor
        identities = (operations._ISSUER, operations._PRODUCTION, inspections._ISSUER,
                      operations.PublicStudyOperationProjection, storage.StudyStorageObservation,
                      supervisor._ISSUER, supervisor.LiveStudyResourceRef, supervisor._LIVE,
                      supervisor._RESULTS)
        before = (dict(supervisor._LIVE), dict(supervisor._RESULTS))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(operations, 'register_public_study_operation', side_effect=AssertionError('operation invoked')), \
                patch.object(inspections, 'witness_public_inspection', side_effect=AssertionError('observer invoked')), \
                patch.object(storage, 'study_storage_observation', side_effect=AssertionError('storage observer invoked')), \
                patch.object(supervisor, 'owned_study_runtime', side_effect=AssertionError('runtime invoked')):
            policy_binding(Path(directory))
        after = (operations._ISSUER, operations._PRODUCTION, inspections._ISSUER,
                 operations.PublicStudyOperationProjection, storage.StudyStorageObservation,
                 supervisor._ISSUER, supervisor.LiveStudyResourceRef, supervisor._LIVE,
                 supervisor._RESULTS)
        for original, current in zip(identities, after):
            self.assertIs(original, current)
        self.assertEqual(before, (dict(supervisor._LIVE), dict(supervisor._RESULTS)))
