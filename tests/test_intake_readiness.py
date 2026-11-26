import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla.spec import SpecError, validate_spec, load_schema, validate_schema
from getzilla.intake_readiness import assess_readiness
from getzilla.requirements_intake import project_requirements
from tests.test_requirements_intake import snapshot


class ReadinessTests(unittest.TestCase):
    def assess(self, data, **state):
        return assess_readiness(data['spec'], project_requirements(data), {**data['policy'], **state})

    def test_complete_ordinary_task_ready_without_another_permission_question(self):
        result = self.assess(snapshot())
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(result['questions'], [])
        self.assertFalse(result['required_decision'])
        self.assertFalse(result['authority'])

    def test_vague_objective_scope_and_missing_evidence_produce_targeted_reasons(self):
        data = snapshot()
        data['spec']['objective']['target'] = 'UNKNOWN'
        data['spec']['acceptance_criteria'][0]['evidence'] = []
        data['scope'] = []
        result = self.assess(data)
        self.assertEqual(result['status'], 'missing')
        self.assertEqual({row['field'] for row in result['missing']}, {'objective.target', 'scope', 'acceptance_criteria.AC-001.evidence'})
        self.assertEqual(len(result['questions']), 3)
        for rows in (result['missing'], result['questions']):
            evidence = next(row for row in rows if row['field'] == 'acceptance_criteria.AC-001.evidence')
            self.assertEqual(evidence['locator'], data['sources'][0]['locator'])

    def test_whole_placeholders_and_evidence_agree_with_strict_spec(self):
        data = snapshot()
        spec = data['spec']
        valid = {'statement': 'Reject the UNKNOWN status', 'evidence': [{'test': 'tests/test_intake_readiness.py'}]}
        for collection, ident in [('acceptance_criteria', 'AC-001'), ('invariants', 'INV-001'),
                                  ('forbidden_outcomes', 'FORBID-001')]:
            spec[collection] = [dict(valid, id=ident)]
            item = spec[collection][0]
            for key, value in [('statement', '  '), ('statement', ' tBd '), ('evidence', [])]:
                with self.subTest(collection=collection, key=key, value=value):
                    item[key] = value
                    self.assertTrue(validate_spec(spec, gate=False)['ok'])
                    result = self.assess(data)
                    self.assertEqual([row['field'] for row in result['missing']], [f'{collection}.{ident}.{key}'])
                    with self.assertRaises(SpecError):
                        validate_spec(spec)
                    item[key] = valid[key]
        for field, value in zip(('statement', 'success_metric', 'target'), (' todo ', 'NEEDS CLARIFICATION', '...')):
            with self.subTest(field=field):
                spec['objective'][field] = value
                self.assertEqual([row['field'] for row in self.assess(data)['missing']], [f'objective.{field}'])
                with self.assertRaises(SpecError):
                    validate_spec(spec)
                spec['objective'][field] = 'Reject the UNKNOWN status'
        self.assertTrue(validate_spec(spec)['ok'])
        self.assertEqual(self.assess(data)['status'], 'ready')

    def test_orphan_finding_names_source_and_clears_on_remap(self):
        data = snapshot()
        data['sources'].append(dict(data['sources'][0], id='support', uri='native:notes.md'))
        self.assertEqual(self.assess(data)['status'], 'ready')
        orphan = dict(data['requirements'][0], id='REQ-002', action_key='second', criterion_ids=[])
        data['requirements'].append(orphan)
        result = self.assess(data)
        finding = {'field': 'requirements.REQ-002.criterion_ids', 'reason': 'requirement_unmapped',
                   'locator': data['sources'][0]['locator']}
        self.assertEqual(result['missing'], [finding])
        self.assertEqual(result['questions'], [dict(finding, id=result['questions'][0]['id'])])
        schema = load_schema(Path(__file__).resolve().parents[1] / 'schemas/intake-readiness-v1.schema.json')
        validate_schema(result, schema, schema)
        orphan['criterion_ids'] = ['AC-001']
        corrected = self.assess(data)
        self.assertEqual(corrected['status'], 'ready')
        self.assertNotEqual(result['draft_digest'], corrected['draft_digest'])
        validate_schema(corrected, schema, schema)

    def test_conflict_and_unassessed_semantics_cannot_be_ready(self):
        data = snapshot()
        other = copy.deepcopy(data['requirements'][0])
        other['id'] = 'REQ-002'
        other['facts'][0]['value'] = 30
        data['requirements'].append(other)
        self.assertEqual(self.assess(data)['status'], 'conflicted')
        data['requirements'] = data['requirements'][:1]
        data['requirements'][0]['facts'] = []
        self.assertEqual(self.assess(data)['status'], 'missing')

    def test_unknown_dependencies_permissions_and_sources_stay_unresolved(self):
        data = snapshot()
        data['dependencies'] = [{'id': 'schema', 'status': 'unknown'}]
        data['permissions'][0]['status'] = 'unknown'
        data['sources'] = []
        data['requirements'] = []
        result = self.assess(data)
        self.assertEqual(result['status'], 'missing')
        self.assertEqual({row['reason'] for row in result['missing']}, {'dependency_unresolved', 'permission_unresolved', 'source_missing', 'criterion_unmapped'})

    def test_questions_stable_and_budget_exhaustion_retains_missing_facts(self):
        data = snapshot()
        data['dependencies'] = [{'id': f'dep-{i}', 'status': 'unknown'} for i in range(8)]
        first = self.assess(data, rounds=0)
        second = self.assess(data, rounds=0)
        self.assertEqual(first['questions'], second['questions'])
        self.assertEqual(len(first['questions']), 5)
        exhausted = self.assess(data, rounds=3)
        self.assertEqual(exhausted['questions'], [])
        self.assertEqual(len(exhausted['missing']), 8)
        self.assertTrue(exhausted['question_budget_exhausted'])

    def test_material_decision_is_unsupported_even_with_imported_yes(self):
        data = snapshot()
        data['policy']['decision_required'] = True
        provenance = project_requirements(data)
        provenance['decisions'] = [{'approved': True, 'principal': 'owner', 'draft_digest': provenance['draft_digest']}]
        result = assess_readiness(data['spec'], provenance, data['policy'])
        self.assertEqual(result['status'], 'needs_decision')
        self.assertEqual(result['required_decision'], 'unsupported_decision_ingress')

    def test_mutable_bookkeeping_cannot_change_draft_and_current_policy_must_match(self):
        data = snapshot()
        first = self.assess(data)
        self.assertEqual(self.assess(data, rounds=2)['draft_digest'], first['draft_digest'])
        stale = assess_readiness(data['spec'], project_requirements(data), {**data['policy'], 'digest': 'c' * 64})
        self.assertEqual(stale['status'], 'stale')

    def test_forged_projection_ready_and_changed_spec_cannot_admit(self):
        data = snapshot()
        provenance = project_requirements(data)
        changed = copy.deepcopy(data['spec'])
        changed['objective']['target'] = '30'
        provenance['status'] = 'ready'
        self.assertEqual(assess_readiness(changed, provenance, data['policy'])['status'], 'stale')


class ConfiguredQuestionBudgetTests(unittest.TestCase):
    def test_current_explicit_limits_control_question_count_and_exhaustion(self):
        data = snapshot()
        data["policy"]["question_limits"] = {"max_questions_per_round": 2, "max_question_rounds": 1}
        data["dependencies"] = [{"id": f"dep-{i}", "status": "unknown"} for i in range(7)]
        projection = project_requirements(data)
        first = assess_readiness(data["spec"], projection, {**data["policy"], "rounds": 0})
        self.assertEqual(len(first["questions"]), 2)
        final = assess_readiness(data["spec"], projection, {**data["policy"], "rounds": 1})
        self.assertEqual(final["questions"], [])
        self.assertTrue(final["question_budget_exhausted"])
        self.assertEqual(len(final["missing"]), 7)

    def test_unconfigured_or_invalid_limits_cannot_start_a_clarification_loop(self):
        data = snapshot()
        data["dependencies"] = [{"id": "unknown", "status": "unknown"}]
        for limits in (
            None,
            {"max_questions_per_round": True, "max_question_rounds": 3},
            {"max_questions_per_round": 2, "max_question_rounds": 0},
        ):
            data["policy"].pop("question_limits", None)
            projection = project_requirements(data)
            result = assess_readiness(data["spec"], projection, {**data["policy"], "question_limits": limits})
            self.assertEqual(result["questions"], [])
            self.assertIn("question_limits_unconfigured", [x["reason"] for x in result["missing"]])
