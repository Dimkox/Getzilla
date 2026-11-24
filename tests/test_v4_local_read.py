"""Synthetic closed rows test the real owner-FD reader; they prove no operation."""
import copy
import json
import unittest
import time

from tests import test_observation_privacy as fixtures
from tests.test_v4_contracts import coverage
from getzilla import observation_privacy
from getzilla.metrics_journal import digest
from getzilla.trace_storage import native_root


class V4LocalReadTests(unittest.TestCase):
    setUp = fixtures.PrivacyTests.setUp

    def row(self):
        row = coverage()
        with native_root(self.root) as anchor:
            row.update(anchor.binding)
        row['event_id'] = digest(row)
        return row

    def publish_fixture(self,row,*,proof=True,frozen=None):
        self.path.write_text(json.dumps(row)+'\n')
        directory = self.path.parent/'routes'
        directory.mkdir(mode=0o700,exist_ok=True)
        context = row['observer']['context']
        binding = {'proof_version':2,'clock_domain':'native_local_utc','row_digest':digest(row),
                   'delivered_by':'2026-11-05T00:00:01.000001Z'}
        route = {'route_id':context['route_id'],'logical_task_id':context['logical_task_id'],
                 'workspace':str(self.root),'authority_epoch':context['authority_epoch'],
                 'state_revision':context['state_revision'],'context':{'revision':context['context_revision']},
                 'observation_publication':{'events':[frozen or row],
                    'delivery':{row['event_id']:binding} if proof else {},'dropped':0}}
        path = directory/(context['route_id']+'.json')
        path.write_text(json.dumps(route))
        path.chmod(0o600)
        return path

    def test_v4_same_root_row_requires_exact_canonical_bytes_and_delivery(self):
        row = self.row()
        self.publish_fixture(row)
        result = observation_privacy.load_local(self.root)
        self.assertEqual(result['events'],[row])
        self.assertIn(row['event_id'],result['delivery_proofs'])
        self.assertTrue(observation_privacy.revalidate_local(self.root,result))

    def test_missing_proof_and_mutated_frozen_row_do_not_admit_v4(self):
        row = self.row()
        changed = copy.deepcopy(row)
        changed['payload']['roster_digest'] = 'f'*64
        for options in ({'proof':False},{'frozen':changed}):
            with self.subTest(options=options):
                self.publish_fixture(row,**options)
                result = observation_privacy.load_local(self.root)
                self.assertEqual(result['events'],[])
                self.assertIn('native_delivery_proof_missing',result['gaps'])

    def test_project_mismatch_and_conflicting_duplicate_are_quarantined(self):
        row = self.row()
        self.publish_fixture(row)
        changed = copy.deepcopy(row)
        changed['repository_digest'] = 'f'*64
        self.path.write_text(json.dumps(changed)+'\n')
        result = observation_privacy.load_local(self.root)
        self.assertEqual(result['events'],[])
        self.assertIn('project_binding_mismatch',result['gaps'])
        self.path.write_text(json.dumps(row)+'\n'+json.dumps(changed)+'\n')
        result = observation_privacy.load_local(self.root)
        self.assertEqual(result['events'],[])
        self.assertIn('conflicting_replay',result['gaps'])

    def test_canonical_permission_revocation_invalidates_cut_and_hides_v4(self):
        row = self.row()
        canonical = self.publish_fixture(row)
        result = observation_privacy.load_local(self.root)
        canonical.chmod(0o644)
        self.assertFalse(observation_privacy.revalidate_local(self.root,result))
        self.assertEqual(observation_privacy.load_local(self.root)['events'],[])

    def test_new_canonical_capture_gap_invalidates_previous_read_cut(self):
        row = self.row()
        canonical = self.publish_fixture(row)
        result = observation_privacy.load_local(self.root)
        route = json.loads(canonical.read_bytes())
        route['observation_publication']['dropped'] = 1
        canonical.write_text(json.dumps(route))
        self.assertFalse(observation_privacy.revalidate_local(self.root,result))

    def test_existing_append_admits_closed_v4_but_append_alone_is_not_coverage(self):
        from getzilla.sprint_lifecycle import append_batch
        row = self.row()
        with native_root(self.root) as anchor:
            delivered = append_batch(self.root,[row],anchor=anchor,deadline=time.monotonic()+1)
        self.assertIsNotNone(delivered)
        self.assertEqual(delivered.digests,{row['event_id']:digest(row)})
        self.assertIn(row['event_id'],self.path.read_text())
        self.assertNotIn(row,observation_privacy.load_local(self.root)['events'])

    def test_existing_append_rejects_raw_fields_before_persisting(self):
        from getzilla.sprint_lifecycle import append_batch
        row = self.row()
        row['payload']['raw_prompt'] = 'PRIVATE_SENTINEL'
        before = self.path.read_bytes()
        with native_root(self.root) as anchor:
            self.assertIsNone(append_batch(self.root,[row],anchor=anchor,deadline=time.monotonic()+1))
        self.assertEqual(self.path.read_bytes(),before)
