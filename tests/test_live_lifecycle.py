"""Admission rules for measured lifecycle cycles, not a Docker simulation."""
import importlib
import importlib.util
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))


class LifecycleEvidenceTests(unittest.TestCase):
    def test_worker_retains_failed_primary_when_cleanup_and_ack_storage_fail(self):
        from getzilla import live_lifecycle as module
        class Owner:
            def cleanup(self):
                raise RuntimeError("cleanup failure")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with patch.object(module, "OwnedDocker", return_value=Owner()), \
                    patch.object(module, "_allocate", side_effect=ValueError("primary failure")), \
                    patch.object(module, "_write", side_effect=OSError("ack storage failure")):
                self.assertEqual(module.worker(root, root, "gz-fixture", "failure"), 1)

    def test_incomplete_or_leaking_cycles_do_not_satisfy_100_cycle_gate(self):
        self.assertIsNotNone(importlib.util.find_spec("getzilla.live_lifecycle"))
        module = importlib.import_module("getzilla.live_lifecycle")
        rows = [{"cycle": n, "status": "pass", "disposable_remaining": 0,
                 "protected_unchanged": True, "payload_bytes": 1024,
                 "directory_payload_bytes": 1024,
                 "resources": [{"kind": kind, "name": f"gz-c{n}-{kind}", **({"id": f"{n:064x}"} if kind == "container" else {})}
                               for kind in ("container", "volume", "network", "directory")]}
                for n in range(1, 101)]
        self.assertTrue(module.cycles_accepted(rows))
        self.assertFalse(module.cycles_accepted(rows[:-1]))
        for field, value in (("disposable_remaining", 1), ("protected_unchanged", False), ("status", "unknown")):
            changed = [dict(item) for item in rows]
            changed[38][field] = value
            self.assertFalse(module.cycles_accepted(changed))
        duplicate = [dict(item) for item in rows]
        duplicate[-1]["cycle"] = 99
        self.assertFalse(module.cycles_accepted(duplicate))
        incomplete = [dict(item) for item in rows]
        del incomplete[22]["resources"]
        self.assertFalse(module.cycles_accepted(incomplete))


if __name__ == "__main__":
    unittest.main()
