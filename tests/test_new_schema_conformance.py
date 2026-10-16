"""Real records validate against their schemas with the repository's own validator (getzilla.spec)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.source_baseline import manifest_record  # noqa: E402
from getzilla.spec import SpecError, validate_schema  # noqa: E402
from tests.code_graph_support import FOLDER, fixture_scope  # noqa: E402
from tests.zero_git_support import clean_source, plan_and_adopt  # noqa: E402


def schema(name: str) -> dict:
    return json.loads((ROOT / 'schemas' / f'{name}.schema.json').read_text(encoding='utf-8'))


class SchemaConformanceTests(unittest.TestCase):
    def test_release_state_matches_schema(self) -> None:
        state = json.loads((ROOT / 'RELEASE_STATE.json').read_text(encoding='utf-8'))
        validate_schema(state, schema('release-state-v1'))
        validate_schema({**state, 'published': None}, schema('release-state-v1'))
        with self.assertRaises(SpecError):
            validate_schema({**state, 'source': {'version': '2.2.2', 'state': 'shipping'}}, schema('release-state-v1'))

    def test_code_graph_export_matches_schema(self) -> None:
        from getzilla.code_graph.builder import build_generation
        from getzilla.code_graph.models import GraphConfig, make_graph_input
        export = build_generation(make_graph_input(FOLDER, fixture_scope(), GraphConfig())).export()
        validate_schema(export, schema('code-index-state-v1'))
        export['calls'].append({**export['calls'][0], 'resolution': 'proven'})
        with self.assertRaises(SpecError):
            validate_schema(export, schema('code-index-state-v1'))

    def test_zero_git_records_match_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plan, receipt = plan_and_adopt(clean_source(base / 'src'), base / 'target', base / 'state')
            validate_schema(plan.to_dict(), schema('admission-plan-v1'))
            validate_schema(receipt, schema('adoption-receipt-v1'))
            validate_schema(manifest_record(plan.entries, plan.path_profile, plan.executable_mode),
                            schema('source-baseline-v1'))


if __name__ == '__main__':
    unittest.main()
