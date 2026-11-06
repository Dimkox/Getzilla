"""Public metadata fixtures for independent accounting row and read-set bounds."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import change, package_status, state
from getzilla.review_plan import reconcile_route
from tests import test_reconcile_accounting as fixtures


def public_rows(count):
    return [{'id': f'public-run-{i}', 'kind': 'run', 'status': 'not_run',
             'reason': 'Public metadata only; no execution claimed.'} for i in range(count)]


class AccountingRowCapacityTests(unittest.TestCase):
    def test_finite_row_boundary_preserves_each_row_and_status(self):
        self.assertEqual(package_status.MAX_ACCOUNTING_ROWS, 128)
        for count in (64, 65, 77, 96, 128):
            with self.subTest(count=count):
                accounting = {'schema_version': 1, 'obligations': public_rows(count)}
                before = copy.deepcopy(accounting)
                rows = package_status.accounting_rows(accounting)
                ids, kinds = set(), set()
                for row in rows:
                    self.assertIsNone(package_status.obligation_reference(row, ids, kinds))
                self.assertEqual(len(ids), count)
                self.assertIs(rows, accounting['obligations'])
                self.assertEqual(accounting, before)
        with self.assertRaises(package_status.InspectionError):
            package_status.accounting_rows({'schema_version': 1, 'obligations': public_rows(129)})

    def test_row_capacity_does_not_expand_file_or_aggregate_read_bounds(self):
        self.assertEqual((package_status.MAX_FILES, package_status.MAX_FILE_BYTES,
                          package_status.MAX_TOTAL_BYTES), (64, 262144, 1048576))
        findings = []
        closure = package_status._PackageReadClosure(ROOT, 'public-fixture',
                                                     lambda *args: findings.append(args))
        with patch.object(package_status, 'read_package_file', return_value=b'x') as reader:
            for i in range(64):
                self.assertEqual(closure.read(f'public-{i}.md'), b'x')
            self.assertEqual(closure.read('public-0.md'), b'x')
            self.assertIsNone(closure.read('public-64.md'))
            self.assertEqual(reader.call_count, 64)
        self.assertEqual(findings[0][0], 'inspection_limit')
        findings.clear()
        closure = package_status._PackageReadClosure(ROOT, 'public-fixture',
                                                     lambda *args: findings.append(args))
        with patch.object(package_status, 'read_package_file', return_value=b'x' * 262144) as reader:
            for i in range(4):
                self.assertIsNotNone(closure.read(f'public-{i}.md'))
            self.assertIsNone(closure.read('public-next.md'))
            self.assertEqual(reader.call_count, 4)
        self.assertEqual(findings[0][0], 'inspection_limit')


class AccountingRowConsumerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ReconcileAccountingTests(
            'test_prospective_whole_package_growth_refuses_before_both_publications')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.package = self.fixture.root, self.fixture.package
        self.path = self.package / 'state.json'

    def write_rows(self, count, reason=None):
        document = json.loads(self.path.read_text(encoding='utf-8'))
        rows = document['evidence_accounting']['obligations']
        rows[2:] = public_rows(count - 2)
        if reason is not None:
            for row in rows:
                row['reason'] = reason
        self.path.write_text(json.dumps(document), encoding='utf-8', newline='\n')
        return copy.deepcopy(rows)

    def test_inspector_and_synchronizer_accept_77_and_128_without_outcome_claims(self):
        for count in (77, 128):
            with self.subTest(count=count):
                before = self.write_rows(count)
                raw = self.path.read_bytes()
                route = state.get_active_route(self.root)
                change.synchronize_accounting(self.root, route, route['required_evidence'])
                self.assertEqual(self.path.read_bytes(), raw)
                inspected = package_status.inspect_package(self.root, route, state.get_active_change(self.root))
                self.assertEqual(inspected['findings'], [])
                self.assertEqual(json.loads(raw)['evidence_accounting']['obligations'], before)
                self.assertTrue(all(row['status'] == 'not_run' for row in before))

    def test_expansion_to_128_is_append_only_idempotent_and_cas_retry_safe(self):
        before = self.write_rows(125)
        self.fixture.expanded_source()
        route = state.get_active_route(self.root)
        with patch.object(state, 'update_route', side_effect=ValueError('public fixture CAS cut')):
            with self.assertRaisesRegex(ValueError, 'CAS cut'):
                reconcile_route(self.root)
        self.assertEqual(state.get_active_route(self.root), route)
        after = json.loads(self.path.read_bytes())['evidence_accounting']['obligations']
        self.assertEqual(after[:125], before)
        self.assertEqual(len(after), 128)
        self.assertTrue(all(row['status'] == 'not_run' for row in after))
        settled = self.path.read_bytes()
        reconcile_route(self.root)
        reconcile_route(self.root)
        self.assertEqual(self.path.read_bytes(), settled)
        self.assertFalse((self.root / '.getzilla/runtime/receipts').exists())

    def test_expansion_beyond_128_refuses_before_either_publication(self):
        self.write_rows(126)
        self.fixture.expanded_source()
        before, route = self.path.read_bytes(), state.get_active_route(self.root)
        with self.assertRaisesRegex(ValueError, 'bounded version 1'):
            reconcile_route(self.root)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(state.get_active_route(self.root), route)

    def test_concurrent_serialized_expansions_preserve_both_new_obligations(self):
        before = self.write_rows(125)
        route = state.get_active_route(self.root)
        ready = threading.Barrier(2)

        def expand(kind):
            state.bind_session(route['session_id'])
            ready.wait(timeout=10)
            change.synchronize_accounting(self.root, route, route['required_evidence'] + [kind])

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(expand, kind) for kind in ('data_review', 'security_review')]
            for future in futures:
                future.result(timeout=10)
        after = json.loads(self.path.read_bytes())['evidence_accounting']['obligations']
        self.assertEqual(after[:125], before)
        self.assertEqual({row['receipt_kind'] for row in after[125:]}, {'data_review', 'security_review'})
        self.assertEqual(len(after), 127)
        settled = self.path.read_bytes()
        change.synchronize_accounting(self.root, route, route['required_evidence'] + ['data_review', 'security_review'])
        self.assertEqual(self.path.read_bytes(), settled)

    def test_77_row_malformed_and_duplicate_inputs_refuse_without_rewrite(self):
        self.write_rows(77)
        original = json.loads(self.path.read_bytes())
        variants = []
        duplicate = copy.deepcopy(original)
        duplicate['evidence_accounting']['obligations'][-1] = copy.deepcopy(
            duplicate['evidence_accounting']['obligations'][0])
        variants.append(duplicate)
        malformed = copy.deepcopy(original)
        malformed['evidence_accounting']['obligations'][-1]['reason'] = ''
        variants.append(malformed)
        unknown = copy.deepcopy(original)
        unknown['evidence_accounting']['obligations'][-1]['status'] = 'unknown'
        variants.append(unknown)
        non_object = copy.deepcopy(original)
        non_object['evidence_accounting']['obligations'][-1] = None
        variants.append(non_object)
        self.fixture.expanded_source()
        for document in variants:
            with self.subTest(document=document['evidence_accounting']['obligations'][-1]):
                self.path.write_text(json.dumps(document), encoding='utf-8', newline='\n')
                before, route = self.path.read_bytes(), state.get_active_route(self.root)
                with self.assertRaises(ValueError):
                    reconcile_route(self.root)
                self.assertEqual(self.path.read_bytes(), before)
                self.assertEqual(state.get_active_route(self.root), route)
                inspected = package_status.inspect_package(self.root, route, state.get_active_change(self.root))
                self.assertIn('obligation_invalid', {row['code'] for row in inspected['findings']})

    def test_128_large_valid_rows_still_refuse_the_unchanged_file_byte_bound(self):
        self.write_rows(128, reason='x' * 3000)
        self.assertGreater(self.path.stat().st_size, 262144)
        before, route = self.path.read_bytes(), state.get_active_route(self.root)
        with self.assertRaises(ValueError):
            change.synchronize_accounting(self.root, route, route['required_evidence'])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(state.get_active_route(self.root), route)


if __name__ == '__main__':
    unittest.main()
