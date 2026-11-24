"""Same-source observer imports retain immutable capture identity."""

import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import queue_refusal, queue_provenance


class QueueRefusalLeafTests(unittest.TestCase):
    def test_source_alias_and_compatibility_reexport_share_the_exact_capture_type(self):
        name = "owned_queue_refusal_alias"
        spec = importlib.util.spec_from_file_location(name, ROOT / ".getzilla/getzilla/queue_refusal.py")
        alias = importlib.util.module_from_spec(spec)
        sys.modules[name] = alias
        self.addCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(alias)
        self.assertIs(alias.QueueRefusalCapture, queue_refusal.QueueRefusalCapture)
        self.assertIs(queue_provenance.QueueRefusalCapture, queue_refusal.QueueRefusalCapture)
        self.assertNotIn("analyze_queue_tree", alias.__dict__)
