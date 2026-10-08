"""The local updater's https egress is declared in the architecture model.

`.getzilla/getzilla/updater.py` imports `urllib.request` to fetch pinned
supply-chain artifacts (the OpenGrep release binary, the OSV database). The
architecture fitness rule FIT-DECLARED-NETWORK-ONLY requires its owner node to
declare that https boundary with an explicit edge. This test fails if the edge
is dropped or the rule is loosened to admit an undeclared client.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from tests import test_architecture_fitness as fixture

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ".getzilla/getzilla/updater.py"


class UpdaterNetworkBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = fixture.ARCHITECTURE.load_architecture(ROOT)

    def _owner(self, path: str) -> dict:
        prefix_owner = None
        for node in self.snapshot.system["nodes"]:
            for owned in node["repository_paths"]:
                if path == owned or path.startswith(owned.rstrip("/") + "/"):
                    if prefix_owner is None or len(owned) > len(prefix_owner[1]):
                        prefix_owner = (node, owned)
        self.assertIsNotNone(prefix_owner, f"no owner node for {path}")
        return prefix_owner[0]

    def test_updater_is_owned_by_the_local_preflight_node(self) -> None:
        owner = self._owner(UPDATER)
        self.assertEqual(owner["id"], "NODE-LOCAL-ROUTE-POLICY")
        self.assertEqual(owner["type"], "local_component")

    def test_owner_declares_an_https_egress_edge(self) -> None:
        owner = self._owner(UPDATER)
        https_edges = [
            edge for edge in self.snapshot.system["edges"]
            if edge["from"] == owner["id"] and edge["protocol"] == "https"
        ]
        self.assertTrue(
            https_edges,
            f"{owner['id']} fetches over https but declares no https egress edge",
        )
        # The declared boundary is an allowlisted egress, not an unbounded client.
        self.assertTrue(
            any(edge["network_policy"] == "allowlisted_egress" for edge in https_edges),
            "the declared https egress must be allowlisted",
        )

    def test_rule_requires_a_declared_edge_rather_than_admitting_any_client(self) -> None:
        rules = self.snapshot.rules["network_policies"]
        owner = self._owner(UPDATER)
        matching = [rule for rule in rules if owner["type"] in rule["node_types"]]
        self.assertTrue(matching, "no network policy governs the local preflight node")
        for rule in matching:
            self.assertIn("https", rule["allowed_protocols"])
            self.assertTrue(
                rule["require_declared_edge"],
                "the boundary must be declared, not loosened by dropping require_declared_edge",
            )


if __name__ == "__main__":
    unittest.main()
