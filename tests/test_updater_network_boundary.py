"""The local updater's https egress is declared on a dedicated architecture node.

`.getzilla/getzilla/updater.py` imports `urllib.request` to fetch pinned
supply-chain artifacts (the OpenGrep release binary, the OSV database). The
architecture fitness rule FIT-DECLARED-NETWORK-ONLY requires its owner node to
declare that https boundary with an explicit edge.

The egress is scoped to a dedicated node (`NODE-LOCAL-SUPPLY-CHAIN-UPDATER`)
rather than the broad `NODE-LOCAL-ROUTE-POLICY`, so the policy engine and the
harness hooks keep `network: none`: a network client introduced in
`pre_tool_use.py`, `_policy_legacy.py`, or `_lib.py` must still trip the rule.
This test fails if the edge is dropped, the rule is loosened, or the egress is
re-attached to the node that owns the hooks/policy.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from tests import test_architecture_fitness as fixture

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ".getzilla/getzilla/updater.py"
HOOK = ".grok/hooks/pre_tool_use.py"
POLICY_ENGINE = ".getzilla/getzilla/_policy_legacy.py"


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

    def _https_egress(self, node_id: str) -> list[dict]:
        return [
            edge for edge in self.snapshot.system["edges"]
            if edge["from"] == node_id and edge["protocol"] == "https"
        ]

    def test_updater_is_owned_by_a_dedicated_supply_chain_node(self) -> None:
        owner = self._owner(UPDATER)
        self.assertEqual(owner["id"], "NODE-LOCAL-SUPPLY-CHAIN-UPDATER")
        self.assertEqual(owner["type"], "local_component")

    def test_dedicated_node_declares_an_allowlisted_https_egress(self) -> None:
        owner = self._owner(UPDATER)
        https_edges = self._https_egress(owner["id"])
        self.assertTrue(
            https_edges,
            f"{owner['id']} fetches over https but declares no https egress edge",
        )
        self.assertTrue(
            any(edge["network_policy"] == "allowlisted_egress" for edge in https_edges),
            "the declared https egress must be allowlisted",
        )

    def test_hooks_and_policy_engine_keep_network_none_and_no_egress(self) -> None:
        # The egress must not be re-attached to the node that owns the hooks and
        # the policy engine, or a future network client there would go unnoticed.
        for path in (HOOK, POLICY_ENGINE):
            owner = self._owner(path)
            self.assertEqual(
                owner["id"], "NODE-LOCAL-ROUTE-POLICY",
                f"{path} must stay owned by the hooks/policy node",
            )
            self.assertEqual(
                owner["runtime"]["network"], "none",
                f"{owner['id']} must keep network: none so new clients are flagged",
            )
            self.assertEqual(
                self._https_egress(owner["id"]), [],
                f"{owner['id']} must declare no https egress of its own",
            )

    def test_rule_requires_a_declared_edge_rather_than_admitting_any_client(self) -> None:
        rules = self.snapshot.rules["network_policies"]
        owner = self._owner(UPDATER)
        matching = [rule for rule in rules if owner["type"] in rule["node_types"]]
        self.assertTrue(matching, "no network policy governs the updater node")
        for rule in matching:
            self.assertIn("https", rule["allowed_protocols"])
            self.assertTrue(
                rule["require_declared_edge"],
                "the boundary must be declared, not loosened by dropping require_declared_edge",
            )


if __name__ == "__main__":
    unittest.main()
