"""Actual native child timing, never an invoice or human-acceptance fixture."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from tests import test_trace_observation as trace_fixtures
from tests._native_public_fixture import project_copy
from getzilla import state, task_budget
from getzilla.observation_privacy import load_local


class EconomicsNativeProducerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = trace_fixtures.TraceObservationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(state.bind_session, None)

    def test_actual_child_publishes_one_elapsed_fact_and_replay_does_not_duplicate(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            command = [sys.executable, "--version"]
            result = task_budget.execute_local(root, "economic-child-one", command, timeout=1)
            self.assertEqual(result["outcome"], "succeeded")
            first = load_local(root)
            economic = [row for row in first["events"] if row.get("kind") == "economics_observation"]
            self.assertEqual(len(economic), 1)
            row = economic[0]
            self.assertEqual(row["payload"]["candidate_kind"], "local_usage")
            self.assertEqual(row["observer"]["context"]["logical_task_id"], route["logical_task_id"])
            self.assertIsNone(row["payload"]["operation"]["attempt_id"])
            self.assertGreaterEqual(row["payload"]["elapsed"]["value"], 0)
            self.assertIsNone(row["payload"]["cpu"]["value"])
            self.assertIsNone(row["payload"]["gpu"]["value"])
            self.assertIsNone(row["payload"]["energy"]["value"])
            self.assertIsNone(row["payload"]["service_period"])
            self.assertIn(row["event_id"], first["delivery_proofs"])
            replay = task_budget.execute_local(root, "economic-child-one", command, timeout=1)
            self.assertTrue(replay["replayed"])
            second = load_local(root)
            self.assertEqual(economic, [r for r in second["events"] if r.get("kind") == "economics_observation"])
