from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))

from getzilla.language_quality.models import AdapterCapabilities, AdapterRequest, AdapterResult, Diagnostic, ToolOutput


class AdapterContractTests(unittest.TestCase):
    def test_shared_contract_is_immutable_and_preserves_status(self):
        request = AdapterRequest("eslint", "cli", ("node", "eslint.js"), "changed", ("app.js",))
        self.assertEqual(request.files, ("app.js",))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.scope = "full"
        self.assertTrue(AdapterCapabilities(False).full)
        diagnostic = Diagnostic("error", "rule", "message")
        self.assertEqual(AdapterResult("FAIL", "findings", (diagnostic,)).diagnostics, (diagnostic,))
        self.assertEqual(ToolOutput(2, "", "bad config").returncode, 2)


if __name__ == "__main__":
    unittest.main()
