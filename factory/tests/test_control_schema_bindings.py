"""Critical paid authority contracts match persisted source dataclasses."""
import dataclasses
import json
from pathlib import Path
import unittest
from getzilla_factory.paid_admission import PaidAccountV1, PaidTaskV1, PaidPriceV1

class ControlSchemaBindingsTests(unittest.TestCase):
    def test_authority_schema_closes_actual_persisted_fields(self):
        path = Path(__file__).resolve().parents[1] / "contracts/jsonschema/paid-execution-authority.v1.schema.json"
        schema = json.loads(path.read_text())
        for cls in (PaidAccountV1, PaidTaskV1, PaidPriceV1):
            definition = schema["$defs"][cls.__name__]
            fields = {field.name for field in dataclasses.fields(cls)}
            self.assertEqual(set(definition["properties"]), fields)
            self.assertEqual(set(definition["required"]), fields)
            self.assertFalse(definition["additionalProperties"])
