"""Closed v4 syntax is not a source/coverage/access authority claim."""
import copy
import unittest

from tests._support import PROJECT
import sys
sys.path.insert(0,str(PROJECT/'.getzilla'))
from getzilla import trace_contracts, metrics_journal


def coverage(kind='native_coverage_open'):
    """Synthetic syntax fixture; no native cut, proof or source authority."""
    row = {'schema_version':4,'event':'observation','event_id':'a'*64,'kind':kind,
           'at':'2026-11-05T00:00:00Z','captured_at':'2026-11-05T00:00:00Z','producer_version':1,
           'repository_digest':'b'*64,'workspace_digest':'c'*64,
           'observer':{'profile':'core_native','operation_id':'coverage-open:synthetic-fixture',
                       'context':{'route_id':'0123456789ab','logical_task_id':'task:'+'d'*32,
                                  'session_id':'00000000-0000-4000-8000-000000000001',
                                  'authority_epoch':0,'state_revision':1,'context_revision':0,
                                  'scope_digest':'e'*64,'spec_digest':None,'evidence_digest':None,
                                  'head':'f'*40,'tree':'1'*40,'base':'2'*40}},
           'payload':{'definition_version':1,'policy':'prospective_original_roster_v1',
                      'window_start':'2026-11-06T00:00:00Z','window_end':'2026-11-20T00:00:00Z',
                      'roster_digest':'3'*64,'roster_count':0,'source_inventory_digest':'4'*64,
                      'journal_prefix_digest':'5'*64,'journal_prefix_rows':0}}
    if kind == 'native_coverage_close':
        row['at'] = row['captured_at'] = '2026-11-20T00:00:00Z'
        row['payload'].update(open_event_id='6'*64,outcomes_digest='7'*64,outcome_count=0)
    return row


class V4ContractTests(unittest.TestCase):
    def validate(self,row):
        function = getattr(trace_contracts,'validate_v4',None)
        self.assertIsNotNone(function,'closed v4 validator is missing')
        return function(row)

    def refused(self,row):
        with self.assertRaisesRegex(ValueError,'^invalid_observation$'):
            self.validate(row)

    def test_open_and_zero_count_close_have_exact_closed_shapes(self):
        for kind in ('native_coverage_open','native_coverage_close'):
            with self.subTest(kind=kind):
                self.assertIsNone(self.validate(coverage(kind)))

    def test_existing_journal_dispatches_v4_without_legacy_expansion(self):
        metrics_journal.validate(coverage())
        self.assertNotIn('observation',metrics_journal.EVENTS)
        with self.assertRaises(ValueError):
            metrics_journal.validate({'event':'observation','at':'2026-11-05T00:00:00Z'})

    def test_unknown_fields_and_caller_authority_are_refused(self):
        for target in ('envelope','observer','context','payload'):
            row = coverage()
            value = {'envelope':row,'observer':row['observer'],'context':row['observer']['context'],
                     'payload':row['payload']}[target]
            value['caller_approved'] = 'PRIVATE_SENTINEL'
            self.refused(row)

    def test_boolean_counts_and_invalid_horizon_or_time_are_refused(self):
        for field,value in (('roster_count',True),('roster_count',65),('journal_prefix_rows',4097),
                            ('definition_version',False),('window_end','2026-11-21T00:00:00Z')):
            row = coverage()
            row['payload'][field] = value
            self.refused(row)
        row = coverage()
        row['captured_at'] = row['payload']['window_start']
        self.refused(row)
        row = coverage('native_coverage_close')
        row['payload']['outcome_count'] = 1
        self.refused(row)

    def test_registered_host_cannot_declare_native_coverage(self):
        row = coverage()
        row['observer'] = {'profile':'registered_host','operation_digest':'1'*64,
                           'binding_digest':'2'*64,'scope_digest':'3'*64}
        self.refused(row)

    def test_economics_has_no_generic_payload_or_missing_validator_fallback(self):
        row = coverage()
        row['kind'] = 'economics_observation'
        row['payload'] = {'candidate_kind':'generic','attrs':{'raw':'PRIVATE_SENTINEL'}}
        self.refused(row)
        original = copy.deepcopy(row)
        with self.assertRaises(ValueError):
            metrics_journal.validate(row)
        self.assertEqual(row,original)
