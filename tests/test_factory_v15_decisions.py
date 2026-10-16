"""Root-discovery bridge for the governed Factory decision contract suite."""

import unittest

try:
    from factory.tests.decision_contract_cases import DecisionContractTests
except ModuleNotFoundError as exc:  # a core-only install has no factory extras
    raise unittest.SkipTest(f"Factory decision contracts need the factory extras ({exc.name})") from exc

__all__ = ["DecisionContractTests"]
