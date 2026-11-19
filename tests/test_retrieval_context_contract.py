"""Tagged provenance serialization is not source authorization."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'factory/src'))
from getzilla_factory.contracts import ContractError
from getzilla_factory.context_contracts import ContextManifestV1
from tests.test_factory_v15_context_schema import context_facts


class RetrievalContextTests(unittest.TestCase):
    def test_tagged_context_source_has_precise_existing_factory_owner(self):
        from getzilla.architecture import load_architecture, validate_repository_drift
        snapshot = load_architecture(ROOT)
        path = 'factory/src/getzilla_factory/retrieval_context_contracts.py'
        owners = [node['id'] for node in snapshot.system['nodes']
            if path in node['repository_paths']]
        self.assertEqual(owners, ['NODE-FACTORY-CONTROL'])
        self.assertEqual(validate_repository_drift(ROOT, snapshot), ())

    def test_removing_tagged_context_owner_still_reports_undeclared_source(self):
        from dataclasses import replace
        from getzilla.architecture import load_architecture, validate_repository_drift
        snapshot = load_architecture(ROOT)
        system = deepcopy(snapshot.system)
        path = 'factory/src/getzilla_factory/retrieval_context_contracts.py'
        owner = next(node for node in system['nodes'] if node['id'] == 'NODE-FACTORY-CONTROL')
        self.assertIn(path, owner['repository_paths'])
        owner['repository_paths'].remove(path)
        findings = validate_repository_drift(ROOT, replace(snapshot, system=system))
        self.assertEqual([(item.code, item.path) for item in findings],
            [('undeclared_source', path)])

    def contract(self):
        from getzilla_factory.retrieval_context_contracts import ContextManifestV2
        return ContextManifestV2

    def test_gitless_snapshot_has_real_tagged_digest_without_manufactured_git_sha(self):
        facts = context_facts()
        facts['schema_version'] = 2
        facts['source_snapshot'] = {'kind': 'gitless', 'snapshot_digest': 'a' * 64}
        result = self.contract().from_dict(facts, expected_tenant='tenant-1', expected_repository='owner/project')
        self.assertEqual(result.to_dict()['source_snapshot'], facts['source_snapshot'])
        self.assertNotIn('head_sha', result.to_dict()['source_snapshot'])
        with self.assertRaises(ContractError):
            ContextManifestV1.from_dict(facts)

    def test_v1_wire_and_semantic_validation_stay_unchanged(self):
        facts = context_facts()
        old = ContextManifestV1.from_dict(facts)
        tagged = deepcopy(facts)
        tagged['schema_version'] = 2
        tagged['source_snapshot']['kind'] = 'git'
        result = self.contract().from_dict(tagged)
        self.assertEqual(result.to_dict()['mandatory_sources'], old.to_dict()['mandatory_sources'])
        tagged['mandatory_sources'][0]['sha256'] = '0' * 64
        with self.assertRaises(ContractError):
            self.contract().from_dict(tagged)

    def test_tagged_identity_is_closed_and_cannot_smuggle_role_or_gitless_commit(self):
        facts = context_facts()
        facts['schema_version'] = 2
        facts['source_snapshot'] = {'kind': 'gitless', 'snapshot_digest': 'a' * 64}
        for extra in ({'head_sha': '1' * 40}, {'role': 'owner'}, {'snapshot_digest': 'not-a-hash'}):
            candidate = deepcopy(facts)
            candidate['source_snapshot'].update(extra)
            with self.assertRaises(ContractError):
                self.contract().from_dict(candidate)
        with self.assertRaises(ContractError):
            self.contract().from_dict(facts, expected_tenant='other')

    def test_structural_schema_agrees_for_both_source_tags(self):
        import json
        from tests.json_schema_subset import SubsetValidator
        schema = json.loads((ROOT / 'factory/contracts/jsonschema/context-manifest.v2.schema.json').read_text())
        validator = SubsetValidator(schema)
        for source in ({'kind': 'gitless', 'snapshot_digest': 'a' * 64},
                {'kind': 'git', 'base_sha': '1' * 40, 'head_sha': '2' * 40, 'dirty_fingerprint': None}):
            facts = context_facts()
            facts['schema_version'] = 2
            facts['source_snapshot'] = source
            validator.validate(facts)
            self.contract().from_dict(facts)

    def test_v2_supports_both_git_hash_formats_without_changing_v1(self):
        import json
        from tests.json_schema_subset import SubsetValidator
        validator = SubsetValidator(json.loads(
            (ROOT / 'factory/contracts/jsonschema/context-manifest.v2.schema.json').read_text()))
        for width in (40, 64):
            facts = context_facts()
            facts['schema_version'] = 2
            facts['source_snapshot'] = {'kind': 'git', 'base_sha': '1' * width,
                'head_sha': '2' * width, 'dirty_fingerprint': None}
            validator.validate(facts)
            self.contract().from_dict(facts)
        legacy = context_facts()
        legacy['source_snapshot']['base_sha'] = '1' * 64
        legacy['source_snapshot']['head_sha'] = '2' * 64
        with self.assertRaises(ContractError):
            ContextManifestV1.from_dict(legacy)
        for bad in ('A' * 64, '1' * 63, 'main', True):
            facts = context_facts()
            facts['schema_version'] = 2
            facts['source_snapshot']['kind'] = 'git'
            facts['source_snapshot']['head_sha'] = bad
            with self.assertRaises(ContractError):
                self.contract().from_dict(facts)


if __name__ == '__main__':
    unittest.main()
