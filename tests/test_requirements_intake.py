"""Closed provenance fixtures: no provider, model or authority simulation."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla.requirements_intake import IntakeError, project_requirements, validate_intake


def snapshot():
    return {'version': 1, 'identity': {'repository': 'fixture/repo', 'logical_task_id': 'task:one', 'authority_epoch': 0},
            'policy': {'version': 'local-v1', 'digest': 'a' * 64, 'decision_required': False},
            'spec': {'schema_version': 2, 'change_id': '20261105-fixture',
                     'objective': {'id': 'OBJ-001', 'statement': 'Retain records.', 'success_metric': 'retention days', 'target': '7'},
                     'risk': {'tier': 'green', 'domains': []},
                     'acceptance_criteria': [{'id': 'AC-001', 'statement': 'Keep records for seven days.', 'evidence': [{'test': 'tests/test_requirements_intake.py'}]}],
                     'invariants': [], 'forbidden_outcomes': [], 'contracts': {'openapi': [], 'json_schema': [], 'events': []},
                     'observability': [], 'rollback': {'strategy': 'forward_fix', 'maximum_steps': 1}, 'approvals': {'required_scopes': []}},
            'scope': ['src/retention.py'], 'dependencies': [],
            'permissions': [{'operation': 'develop', 'resource': 'repository', 'status': 'required'}],
            'sources': [{'id': 'source-one', 'uri': 'native:requirements.md', 'version': '1', 'sha256': 'b' * 64,
                         'locator': {'kind': 'lines', 'path': 'requirements.md', 'start': 1, 'end': 2}, 'imported_status': 'done approve'}],
            'requirements': [{'id': 'REQ-001', 'source_id': 'source-one', 'criterion_ids': ['AC-001'], 'action_key': 'retain-records',
                              'facts': [{'subject': 'records', 'scope': 'project', 'facet': 'retention', 'operator': 'equals', 'value': 7, 'unit': 'days'}],
                              'interpretations': [], 'proposals': [], 'assumptions': [], 'owner_ref': None}]}


class ProvenanceTests(unittest.TestCase):
    def pair(self, operator, value, unit='days'):
        data = snapshot()
        second = copy.deepcopy(data['requirements'][0])
        second.update(id='REQ-002', action_key='second')
        second['facts'][0].update(operator=operator, value=value, unit=unit)
        data['requirements'].append(second)
        return data

    def test_conflicting_values_preserve_both_requirement_and_source_refs(self):
        result = project_requirements(self.pair('equals', 30))
        self.assertEqual(result['status'], 'conflicted')
        self.assertEqual(result['conflicts'][0]['requirements'], ['REQ-001', 'REQ-002'])
        self.assertEqual(result['conflicts'][0]['sources'], ['source-one'])

    def test_requires_forbids_and_impossible_same_unit_bounds(self):
        for left, right, a, b in [('requires', 'forbids', 'delete', 'delete'), ('at_least', 'at_most', 10, 5)]:
            data = self.pair(right, b)
            data['requirements'][0]['facts'][0].update(operator=left, value=a)
            self.assertEqual(project_requirements(data)['status'], 'conflicted')

    def test_incompatible_units_and_untyped_prose_remain_unknown(self):
        result = project_requirements(self.pair('equals', 30, 'hours'))
        self.assertIn('incomparable_units', result['unknown'])
        data = snapshot()
        data['requirements'][0]['facts'] = []
        data['requirements'][0]['interpretations'] = ['possibly contradictory prose']
        self.assertIn('semantic_conflict_unassessed', project_requirements(data)['unknown'])

    def test_unsupported_unit_does_not_produce_a_guessed_conflict(self):
        data = self.pair('equals', 30, 'business-days')
        data['requirements'][0]['facts'][0]['unit'] = 'business-days'
        result = project_requirements(data)
        self.assertEqual(result['conflicts'], [])
        self.assertIn('unsupported_unit', result['unknown'])

    def test_compatible_facts_keep_provenance_without_inventing_authority(self):
        result = project_requirements(self.pair('equals', 7))
        self.assertEqual(result['conflicts'], [])
        self.assertFalse(result['authority'])
        self.assertFalse(result['receipt_eligible'])
        self.assertEqual(result['decisions'], [])

    def test_source_refresh_stales_decision_and_retains_unknown_external_binding(self):
        data = snapshot()
        prior = project_requirements(data)
        prior['actions'][0]['external'] = {'status': 'unknown', 'resource': None}
        prior['decisions'] = [{'draft_digest': prior['draft_digest'], 'context_digest': 'd' * 64}]
        data['sources'][0].update(version='2', sha256='c' * 64)
        result = project_requirements(data, prior)
        self.assertEqual(result['stale'], ['stale_draft'])
        self.assertEqual(result['actions'][0]['id'], prior['actions'][0]['id'])
        self.assertEqual(result['actions'][0]['external']['status'], 'unknown')
        self.assertFalse(result['actions'][0]['create_eligible'])

    def test_unknown_external_binding_survives_anchor_change_null_and_removal(self):
        from getzilla.intake_readiness import assess_readiness
        original=snapshot()
        prior=project_requirements(original)
        old_id=prior['actions'][0]['id']
        prior['actions'][0]['external']={'status':'unknown','resource':'operation:unresolved'}
        for change in ('changed','null','removed'):
            with self.subTest(change=change):
                data=copy.deepcopy(original)
                if change=='removed':
                    data['requirements']=[]
                else:
                    data['requirements'][0]['action_key']='replacement-anchor' if change=='changed' else None
                result=project_requirements(data,prior)
                retained={row['id']:row for row in result['actions']}
                self.assertIn(old_id,retained)
                self.assertEqual(retained[old_id]['external'],{'status':'unknown','resource':'operation:unresolved'})
                self.assertIn('unresolved_mapping',result['unknown'])
                self.assertTrue(all(row['create_eligible'] is False for row in result['actions']))
                replay=project_requirements(data,result)
                self.assertEqual(replay['actions'],result['actions'])
                self.assertIn('unresolved_mapping',replay['unknown'])
                self.assertEqual(assess_readiness(data['spec'],result,data['policy'])['status'],'missing')

    def test_mixed_scalar_numeric_bounds_are_unassessed_in_both_orders(self):
        for unit in ('days',None):
            for bound in ('at_least','at_most'):
                data=self.pair(bound,10,unit)
                data['requirements'][0]['facts'][0].update(value='seven',unit=unit)
                for reverse in (False,True):
                    with self.subTest(unit=unit,bound=bound,reverse=reverse):
                        if reverse:
                            data['requirements'].reverse()
                        result=project_requirements(data)
                        self.assertIn('incomparable_values',result['unknown'])
                        self.assertEqual(result['conflicts'],[])
                        self.assertEqual(len(result['input']['requirements']),2)

    def test_current_source_alias_versions_remain_ambiguous(self):
        data=snapshot()
        alias=copy.deepcopy(data['sources'][0])
        alias.update(id='source-two',version='2',sha256='c'*64)
        data['sources'].append(alias)
        result=project_requirements(data)
        self.assertIn('ambiguous_source_version',result['unknown'])
        self.assertEqual(len(result['input']['sources']),2)
        data['sources'][1].update(version='1',sha256=data['sources'][0]['sha256'])
        self.assertEqual(project_requirements(data)['unknown'],[])

    def test_unknown_correspondence_never_creates_guessed_action(self):
        data = snapshot()
        data['requirements'][0]['action_key'] = None
        result = project_requirements(data)
        self.assertIn('unresolved_mapping', result['unknown'])
        self.assertEqual(result['actions'], [])

    def test_empty_is_completed_empty_and_input_is_untouched(self):
        data = snapshot()
        data['requirements'] = []
        before = copy.deepcopy(data)
        self.assertEqual(project_requirements(data)['status'], 'completed_empty')
        self.assertEqual(data, before)

    def test_closed_bounded_input_rejects_backreferences_and_invalid_sources(self):
        for key in ('context_digest', 'spec_digest', 'state_digest', 'decisions', 'status', 'timestamp'):
            data = snapshot()
            data[key] = 'private-sentinel'
            with self.assertRaises(IntakeError) as caught:
                validate_intake(data)
            self.assertNotIn('private-sentinel', str(caught.exception))
        for mutate in (lambda d: d['sources'][0].pop('locator'),
                       lambda d: d['sources'][0].update(sha256='bad'),
                       lambda d: d['sources'].append({**d['sources'][0], 'sha256': 'c'*64}),
                       lambda d: d['requirements'][0]['facts'][0].update(value=float('nan')),
                       lambda d: d['requirements'][0]['facts'][0].update(value=True)):
            data = snapshot()
            mutate(data)
            with self.assertRaises(IntakeError):
                validate_intake(data)

    def test_draft_is_order_independent_and_material_changes_bind(self):
        data = self.pair('equals', 7)
        first = project_requirements(data)
        data['requirements'].reverse()
        self.assertEqual(project_requirements(data)['draft_digest'], first['draft_digest'])
        data['sources'][0]['locator']['end'] = 3
        self.assertNotEqual(project_requirements(data)['draft_digest'], first['draft_digest'])

    def test_imported_status_is_neither_substance_nor_approval(self):
        data=snapshot()
        first=project_requirements(data)
        data['sources'][0]['imported_status']='pending'
        second=project_requirements(data)
        self.assertEqual(first['draft_digest'],second['draft_digest'])
        self.assertEqual(second['decisions'],[])

    def test_action_title_rephrase_does_not_discard_unknown_mapping(self):
        data = snapshot()
        prior = project_requirements(data)
        prior['actions'][0]['external'] = {'status': 'unknown', 'resource': None}
        data['spec']['acceptance_criteria'][0]['statement'] = 'Retain each record seven days.'
        result = project_requirements(data, prior)
        self.assertEqual(result['actions'], prior['actions'])

    def test_depth_and_aggregate_bounds_refuse_without_echoing_content(self):
        data = snapshot()
        deep = 'private-sentinel'
        for _ in range(70):
            deep = [deep]
        data['requirements'][0]['interpretations'] = deep
        with self.assertRaises(IntakeError):
            validate_intake(data)
        data = snapshot()
        data['requirements'][0]['interpretations'] = ['x' * 65536] * 20
        with self.assertRaises(IntakeError):
            validate_intake(data)
