"""Economic trace validation must not import the whole report/computation owner."""

from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))


class EconomicsContractLeafTests(unittest.TestCase):
    def test_payload_error_and_validator_keep_public_type_identity(self):
        from getzilla import economics_contracts, route_metrics

        self.assertIs(economics_contracts.EconomicsError, route_metrics.EconomicsError)
        self.assertIs(economics_contracts.validate_economics_payload, route_metrics.validate_economics_payload)

    def test_actual_v4_validation_does_not_load_route_metrics(self):
        script = (
            "import sys;sys.path[:0]=sys.argv[1:];"
            "from tests.economics_fixtures import observation,payloads;"
            "from getzilla.trace_contracts import validate_v4;"
            'validate_v4(observation(payloads()["local_usage"],"synthetic")["row"]);'
            'assert "getzilla.route_metrics" not in sys.modules'
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", script, str(ROOT / ".getzilla"), str(ROOT)], capture_output=True, timeout=5
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
