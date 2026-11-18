"""Source provider costs come from saved bytes and bound source inventory."""
import copy
from datetime import timedelta
import unittest

from tests import test_security_action_inputs as owned
from getzilla import security_action_inputs as actions
from getzilla.security_inventory import canonical_digest


class SourceFactsTests(unittest.TestCase):
    setUp = owned.ActionInputsTests.setUp
    adapter = owned.ActionInputsTests.adapter
    world = owned.ActionInputsTests.world

    def report(self, uses=3, qualified=False, partial=False):
        module, inventory, descriptor, proof, fetch, calls = self.world(uses)
        inventory['digest'] = canonical_digest({k: v for k, v in inventory.items() if k != 'digest'})
        if partial:
            original = fetch
            def fetch(url, *, maximum):
                if '/git/trees/' in url:
                    raise owned.artifacts.ArtifactError('artifact-action-transport', 'API unavailable')
                return original(url, maximum=maximum)
        report = actions.prepare_actions(inventory, self.root, now=owned.NOW, fetch=fetch,
                                         component_maps={owned.REFERENCE: descriptor} if qualified else None)
        return inventory, report

    def validate(self, inventory, report, records=None):
        self.assertTrue(hasattr(actions, 'validate_source_facts'), 'missing byte-bound source facts validator')
        return actions.validate_source_facts(self.root, report, now=owned.NOW,
                                             inventory_digest=inventory['digest'], records=records)

    def test_totals_and_gap_labels_never_control_actual_logical_cost(self):
        inventory, report = self.report()
        actual = sum(x['bytes'] for x in report['source_facts'][0]['responses']) * 3
        report['bound_bytes'] = report['record_bytes'] = report['source_facts'][0]['bound_bytes'] = 0
        for gap in report['gaps']:
            gap['code'] = 'invented-pass'
        checked = self.validate(inventory, report)
        self.assertEqual(checked['bound_bytes'], actual)
        self.assertEqual(checked['records'], [])

    def test_verified_qualified_records_already_own_their_source_cost(self):
        inventory, report = self.report(qualified=True)
        checked = self.validate(inventory, report, report['records'])
        self.assertEqual(checked['gaps'], [], checked)
        self.assertEqual(checked['bound_bytes'], 0)
        self.assertEqual(checked['records'], report['records'])

    def test_partial_received_commit_keeps_cost_and_unavailable_source_gap(self):
        inventory, report = self.report(partial=True)
        actual = report['source_facts'][0]['responses'][0]['bytes'] * 3
        checked = self.validate(inventory, report)
        self.assertEqual(checked['bound_bytes'], actual)
        self.assertTrue(checked['gaps'])

    def test_replaced_origin_bytes_clock_or_omitted_subject_cannot_restore_credit(self):
        inventory, report = self.report()
        for mutation in ('hash', 'url', 'clock', 'subject', 'inventory'):
            changed = copy.deepcopy(report)
            if mutation == 'hash':
                changed['source_facts'][0]['responses'][0]['sha256'] = '0' * 64
            elif mutation == 'url':
                changed['source_facts'][0]['responses'][0]['url'] = 'https://evil.invalid/commit'
            elif mutation == 'clock':
                changed['source_facts'][0]['acquired_at'] = (owned.NOW - timedelta(hours=73)).isoformat()
            elif mutation == 'subject':
                changed['gaps'].pop()
            else:
                changed['source_inventory']['tools'].pop()
            with self.subTest(mutation=mutation):
                self.assertTrue(self.validate(inventory, changed)['gaps'])
