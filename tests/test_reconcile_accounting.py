"""Ordinary public package metadata; no gate or receipt authority is created."""
from __future__ import annotations

import copy
import json
import inspect as introspect
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import state
from getzilla.change import start_change
from getzilla.package_status import inspect_package
from getzilla.review_plan import reconcile_route
from getzilla import change
from getzilla import package_status
from tests import test_review_plan as fixtures
from tests._support import synchronize_fixture_scope


class ReconcileAccountingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ReviewPlanTests('test_exact_diff_plan_is_invariant_under_prompt_language_and_risk_words')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        shutil.copytree(ROOT / '.getzilla/templates/change', self.root / '.getzilla/templates/change')
        self.fixture.write('schemas/change-spec.schema.json', (ROOT / 'schemas/change-spec.schema.json').read_text())
        self.fixture.commit()
        self.fixture.base = fixtures.git(self.root, 'rev-parse', 'HEAD')
        fixtures.git(self.root, 'update-ref', 'refs/remotes/origin/main', self.fixture.base)
        route = self.fixture.route()
        self.assertEqual(route['required_evidence'], ['verification', 'code_review'])
        start_change(self.root)
        synchronize_fixture_scope(self.root)
        self.active = state.get_active_change(self.root)
        self.package = self.root / self.active['path']

    def expanded_source(self):
        for path in ('auth/public.py', 'schemas/public.json', '.github/workflows/public.yml'):
            self.fixture.write(path, 'ordinary public classifier fixture\n')
        self.fixture.commit()

    def aggregate_package(self, headroom, *, markdown_reference=False, empty_last=False):
        """Reuse the reviewer's exact public64/4096-headroom consumer probe."""
        path = self.package / 'state.json'
        document = json.loads(path.read_text())
        rows = document['evidence_accounting']['obligations']
        for i in range(2):
            rows.append({'id': f'public-run-{i}', 'kind': 'run'})
        for i, row in enumerate(rows):
            row.update(status='recorded', outcome='fail', recorded_at='2026-01-01T00:00:00Z',
                       reference='evidence/README.md' if markdown_reference and i == 0 else f'evidence/public-report-{i}.md')
            row.pop('reason', None)
            if row['kind'] == 'run':
                row['command'] = ['public-fixture-command']
            (self.package / row['reference']).write_text('x')
        if empty_last:
            (self.package / 'evidence/README.md').write_bytes(b'')
        path.write_bytes((json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode())
        _, total = self.inspect_bytes()
        target = package_status.MAX_TOTAL_BYTES - headroom
        extra = target - total
        for i, row in enumerate(rows):
            size = extra // len(rows) + (1 if i < extra % len(rows) else 0) + 1
            self.assertLessEqual(size, package_status.MAX_FILE_BYTES)
            (self.package / row['reference']).write_text('x' * size)
        inspected, total = self.inspect_bytes()
        self.assertEqual(total, target)
        self.assertEqual(inspected['findings'], [])
        return path, copy.deepcopy(document)

    def inspect_bytes(self):
        sizes = {}
        reader = package_status.read_package_file
        def observe(root, relative, *args, **kwargs):
            raw = reader(root, relative, *args, **kwargs)
            if any(frame.function == 'read' and frame.filename.endswith('/package_status.py')
                   for frame in introspect.stack()[:8]):
                sizes[relative] = len(raw)
            return raw
        with patch.object(package_status, 'read_package_file', side_effect=observe):
            result = inspect_package(self.root, state.get_active_route(self.root), state.get_active_change(self.root))
        return result, sum(sizes.values())

    def test_prospective_whole_package_growth_refuses_before_both_publications(self):
        path, _ = self.aggregate_package(64)
        before = path.read_bytes()
        route = state.get_active_route(self.root)
        self.expanded_source()
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            reconcile_route(self.root)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(state.get_active_route(self.root), route)
        inspected, total = self.inspect_bytes()
        self.assertEqual(inspected['findings'], [])
        self.assertEqual(total, 1048512)

    def test_prospective_whole_package_headroom_preserves_readable_expansion(self):
        path, before = self.aggregate_package(4096)
        self.expanded_source()
        route = reconcile_route(self.root)
        inspected, total = self.inspect_bytes()
        self.assertEqual(inspected['findings'], [])
        self.assertEqual(total, 1045166)
        after = json.loads(path.read_text())
        self.assertEqual(after['evidence_accounting']['obligations'][:4], before['evidence_accounting']['obligations'])
        self.assertTrue(all(row['status'] == 'not_run' for row in after['evidence_accounting']['obligations'][4:]))
        self.assertEqual(len(route['required_evidence']), 5)

    def test_exact_aggregate_boundary_and_markdown_reference_count_once(self):
        path, _ = self.aggregate_package(686, markdown_reference=True)
        self.expanded_source()
        reconcile_route(self.root)
        inspected, total = self.inspect_bytes()
        self.assertEqual(inspected['findings'], [])
        self.assertEqual(total, package_status.MAX_TOTAL_BYTES)
        self.assertEqual(len(json.loads(path.read_text())['evidence_accounting']['obligations']), 7)

    def test_exact_aggregate_before_unread_empty_member_still_refuses(self):
        path, _ = self.aggregate_package(686, empty_last=True)
        before = path.read_bytes()
        route = state.get_active_route(self.root)
        self.expanded_source()
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            reconcile_route(self.root)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(state.get_active_route(self.root), route)

    def test_reconcile_expansion_adds_only_missing_package_obligations(self):
        path = self.package / 'state.json'
        document = json.loads(path.read_text())
        for row, outcome in zip(document['evidence_accounting']['obligations'], ('fail', 'pass')):
            reference = 'evidence/public-' + row['id'] + '.md'
            (self.package / reference).write_text('Historical public accounting fixture; not a receipt.\n')
            row.update(status='recorded', outcome=outcome, recorded_at='2026-01-01T00:00:00Z', reference=reference)
            row.pop('reason')
        document['evidence_accounting']['obligations'].append(
            {'id': 'ordinary-run', 'kind': 'run', 'status': 'not_run', 'reason': 'Not executed.'})
        path.write_text(json.dumps(document))
        before = copy.deepcopy(document)
        self.expanded_source()
        route = reconcile_route(self.root)
        self.assertEqual(set(route['required_evidence']),
                         {'verification', 'code_review', 'data_review', 'security_review', 'release_review'})
        inspected = inspect_package(self.root, route, state.get_active_change(self.root))
        self.assertNotIn('obligation_missing', {row['code'] for row in inspected['findings']})
        after = json.loads(path.read_text())
        self.assertEqual(after['evidence_accounting']['obligations'][:3], before['evidence_accounting']['obligations'])
        added = after['evidence_accounting']['obligations'][3:]
        self.assertEqual({row['receipt_kind'] for row in added}, {'data_review', 'security_review', 'release_review'})
        self.assertTrue(all(row['status'] == 'not_run' and row['reason'] for row in added))
        self.assertEqual({k: v for k, v in after.items() if k != 'evidence_accounting'},
                         {k: v for k, v in before.items() if k != 'evidence_accounting'})
        settled = path.read_bytes()
        reconcile_route(self.root)
        self.assertEqual(path.read_bytes(), settled)
        self.assertFalse((self.root / '.getzilla/runtime/receipts').exists())

    def test_malformed_legacy_duplicate_and_identity_collision_refuse_unchanged(self):
        self.expanded_source()
        path = self.package / 'state.json'
        original = json.loads(path.read_text())
        variants = []
        missing = copy.deepcopy(original)
        missing.pop('evidence_accounting')
        variants.append(missing)
        for mutate in ('version', 'duplicate', 'reason', 'id-collision'):
            value = copy.deepcopy(original)
            accounting = value['evidence_accounting']
            if mutate == 'version':
                accounting['schema_version'] = 2
            elif mutate == 'duplicate':
                accounting['obligations'].append(copy.deepcopy(accounting['obligations'][0]))
            elif mutate == 'reason':
                accounting['obligations'][0]['reason'] = ''
            else:
                accounting['obligations'].append({'id': 'data_review', 'kind': 'run', 'status': 'not_run', 'reason': 'Ordinary unrun metadata.'})
            variants.append(value)
        for value in variants:
            with self.subTest(accounting=value.get('evidence_accounting')):
                path.write_text(json.dumps(value))
                before = path.read_bytes()
                route = state.get_active_route(self.root)
                with self.assertRaises(ValueError):
                    reconcile_route(self.root)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(state.get_active_route(self.root), route)

    def test_owner_foreign_and_closed_selected_packages_refuse(self):
        self.expanded_source()
        path = self.package / 'state.json'
        before = path.read_bytes()
        route = state.get_active_route(self.root)
        state.bind_session('different-fixture-workflow-owner')
        try:
            with self.assertRaises(ValueError):
                reconcile_route(self.root)
        finally:
            state.bind_session(route['session_id'])
        self.assertEqual(path.read_bytes(), before)
        for field, value in (('route_id', 'other-fixture-route'), ('status', 'archived')):
            document = json.loads(before)
            document[field] = value
            path.write_text(json.dumps(document))
            altered = path.read_bytes()
            with self.subTest(field=field), self.assertRaises(ValueError):
                reconcile_route(self.root)
            self.assertEqual(path.read_bytes(), altered)
            self.assertEqual(state.get_active_route(self.root), route)

    def test_row_and_utf8_output_bounds_refuse_before_any_publication(self):
        self.expanded_source()
        path = self.package / 'state.json'
        original = json.loads(path.read_text())
        full = copy.deepcopy(original)
        full['evidence_accounting']['obligations'].extend(
            {'id': f'ordinary-{i}', 'kind': 'run', 'status': 'not_run', 'reason': 'Not run.'}
            for i in range(package_status.MAX_ACCOUNTING_ROWS - 2))
        padded = copy.deepcopy(original)
        padded['ordinary_padding'] = ['x' * 60000] * 4 + ['']
        def encode(value):
            return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
        difference = 262000 - len(encode(padded))
        self.assertGreater(difference, 0)
        padded['ordinary_padding'][-1] = 'é' * (difference // 2)
        self.assertLessEqual(len(encode(padded)), 262000)
        self.assertGreater(len(encode(padded)), 261900)
        for value in (full, padded):
            path.write_bytes(encode(value))
            before = path.read_bytes()
            route = state.get_active_route(self.root)
            with self.assertRaises(ValueError):
                reconcile_route(self.root)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(state.get_active_route(self.root), route)

    def test_package_write_failure_cannot_publish_expanded_route(self):
        self.expanded_source()
        path = self.package / 'state.json'
        before = path.read_bytes()
        route = state.get_active_route(self.root)
        with patch.object(change, 'durable_json', side_effect=OSError('ordinary fixture publication failure')):
            with self.assertRaises(OSError):
                reconcile_route(self.root)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(state.get_active_route(self.root), route)

    def test_route_cas_cut_leaves_only_conservative_rows_and_retry_is_idempotent(self):
        self.expanded_source()
        path = self.package / 'state.json'
        before = json.loads(path.read_text())
        route = state.get_active_route(self.root)
        with patch.object(state, 'update_route', side_effect=ValueError('ordinary fixture CAS cut')):
            with self.assertRaisesRegex(ValueError, 'CAS cut'):
                reconcile_route(self.root)
        self.assertEqual(state.get_active_route(self.root), route)
        after = json.loads(path.read_text())
        self.assertEqual(after['evidence_accounting']['obligations'][:2], before['evidence_accounting']['obligations'])
        self.assertEqual(len(after['evidence_accounting']['obligations']), 5)
        self.assertTrue(all(row['status'] == 'not_run' for row in after['evidence_accounting']['obligations']))
        settled = path.read_bytes()
        reconcile_route(self.root)
        self.assertEqual(path.read_bytes(), settled)

    def test_source_change_after_accounting_publication_refuses_expanded_route(self):
        self.expanded_source()
        route = state.get_active_route(self.root)
        publish = change.durable_json
        def changed_source(root, path, value):
            publish(root, path, value)
            (root / 'app.py').write_text('ordinary concurrent fixture edit\n')
        with patch.object(change, 'durable_json', changed_source):
            with self.assertRaisesRegex(ValueError, 'source changed'):
                reconcile_route(self.root)
        self.assertEqual(state.get_active_route(self.root), route)

    def test_unsafe_active_path_and_linked_state_are_not_rewritten(self):
        self.expanded_source()
        route = state.get_active_route(self.root)
        path = self.package / 'state.json'
        before = path.read_bytes()
        active_path = state.active_change_path(self.root)
        active_bytes = active_path.read_bytes()
        state.durable_json(self.root, active_path, dict(self.active, path='ordinary-outside/state.json'))
        with patch.object(change, 'read_package_file', side_effect=AssertionError('unsafe target must not be opened')):
            with self.assertRaises(ValueError):
                reconcile_route(self.root)
        state.durable_bytes(self.root, active_path, active_bytes)
        self.assertEqual(path.read_bytes(), before)
        if os.name != 'nt':
            target = self.package / 'ordinary-public-state.json'
            target.write_bytes(before)
            path.unlink()
            path.symlink_to(target)
            try:
                with self.assertRaises(ValueError):
                    reconcile_route(self.root)
                self.assertTrue(path.is_symlink())
                self.assertEqual(target.read_bytes(), before)
            finally:
                path.unlink()
                path.write_bytes(before)
        self.assertEqual(state.get_active_route(self.root), route)

    def test_exact_consumer_output_cap_accepts_and_next_byte_refuses(self):
        self.expanded_source()
        path = self.package / 'state.json'
        original = json.loads(path.read_text())
        original['ordinary_padding'] = ['x' * 60000] * 4 + ['']
        expected = copy.deepcopy(original)
        for kind in ('data_review', 'release_review', 'security_review'):
            expected['evidence_accounting']['obligations'].append({
                'id': kind, 'kind': 'receipt', 'receipt_kind': kind, 'status': 'not_run',
                'reason': 'Selected by reconciled review plan; evidence not yet recorded.',
            })
        def encode(value):
            return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
        needed = 262144 - len(encode(expected))
        self.assertGreater(needed, 0)
        original['ordinary_padding'][-1] = 'é' * (needed // 2) + 'x' * (needed % 2)
        excessive = copy.deepcopy(original)
        excessive['ordinary_padding'][-1] += 'x'
        path.write_bytes(encode(excessive))
        before = path.read_bytes()
        route = state.get_active_route(self.root)
        with self.assertRaisesRegex(ValueError, 'consumer byte bound'):
            reconcile_route(self.root)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(state.get_active_route(self.root), route)
        path.write_bytes(encode(original))
        reconcile_route(self.root)
        self.assertEqual(len(path.read_bytes()), 262144)


if __name__ == '__main__':
    unittest.main()
