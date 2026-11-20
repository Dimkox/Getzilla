import importlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class StudyWorkerInventoryTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_worker_inventory')
        except ModuleNotFoundError:
            self.fail('fixed reviewed worker source inventory owner missing')

    def test_relative_import_outside_fixed_closure_is_unavailable(self):
        owner = self.owner()
        with self.assertRaises(ValueError):
            owner._check_imports('getzilla/retrieval/study_worker_dispatch.py',
                                  b'from .unreviewed_plugin import execute\n')

    def test_fixed_manifest_is_read_as_current_source_not_caller_pins(self):
        owner = self.owner()
        self.assertIn('getzilla/retrieval/study_worker_entry.py', owner.WORKER_FILES)
        with patch('getzilla.fsx.ReadOnlyBoundRoot') as reader:
            anchor = reader.return_value.__enter__.return_value
            anchor.read.return_value = SimpleNamespace(content=b'"inert"\n', mode=0o644)
            rows = owner.worker_source_files(Path(__file__).resolve().parent)
        self.assertEqual(tuple(row[0] for row in rows), owner.WORKER_FILES)
        self.assertEqual(anchor.read.call_count, 2 * len(owner.WORKER_FILES))
        self.assertTrue(all(call.args[0].startswith('.getzilla/getzilla/')
                            for call in anchor.read.call_args_list))

    def test_actual_current_source_closure_is_complete_and_python_only(self):
        owner = self.owner()
        rows = owner.worker_source_files(Path(__file__).resolve().parents[1])
        self.assertEqual(tuple(row[0] for row in rows), owner.WORKER_FILES)
        self.assertTrue(all(path.endswith('.py') and '__pycache__' not in path
                            for path, _, _ in rows))
        self.assertLess(sum(size for _, size, _ in rows), 4 * 1024**2)
